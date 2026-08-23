#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int p0(uint64_t v) {
  return v >= 0xffffff8000000000ULL && v < 0xffffff8000000000ULL + 0x400000000ULL;
}

static int run_one(const char *tag, int type, uint64_t config, int pid,
                   int exclude_user) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)type;
  pe.config = config;
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 33) - 1;
  pe.disabled = 1;
  pe.exclude_user = exclude_user ? 1 : 0;
  pe.exclude_hv = 1;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, (long)pid, -1, -1, 0);
  printf("%s type=%d cfg=0x%llx pid=%d xu=%d fd=%d errno=%d\n", tag, type,
         (unsigned long long)config, pid, exclude_user, fd, errno);
  if (fd < 0)
    return -1;
  size_t msz = 4096 * 33;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    printf("mmap errno=%d\n", errno);
    close(fd);
    return -1;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  struct timespec ts = {0, 2000000L};
  for (int i = 0; i < 300; i++)
    nanosleep(&ts, NULL);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t getpid_lo = 0xffffffc008165d20ULL;
  uint64_t getpid_hi = getpid_lo + 0xC0ULL;
  uint64_t svc_lo = 0xffffffc008096728ULL;
  uint64_t svc_hi = svc_lo + 0x270ULL;
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  int ns = 0, nget = 0, nsvc = 0, nx0p0 = 0;
  while (pos < head && ns < 80) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8;
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      int ing = (ip >= getpid_lo && ip < getpid_hi);
      int ins = (ip >= svc_lo && ip < svc_hi);
      if (ing)
        nget++;
      if (ins)
        nsvc++;
      uint64_t x0 = 0, x8 = 0;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        x0 = regs[0];
        x8 = regs[8];
        if (p0(x0))
          nx0p0++;
      }
      if (ns < 4 && (abi == 1 || abi == 2)) {
        uint64_t *regs = (uint64_t *)p;
        printf("  ip=%016llx\n", (unsigned long long)ip);
        for (int r = 0; r < 33; r++) {
          uint64_t v = regs[r];
          if (v > 0xffffff8000000000ULL)
            printf("    x%-2d %016llx p0=%d\n", r, (unsigned long long)v, p0(v));
        }
      } else if (ns < 10)
        printf("  ip=%016llx getpid=%d svc=%d x0=%016llx p0=%d x8=%llx\n",
               (unsigned long long)ip, ing, ins, (unsigned long long)x0, p0(x0),
               (unsigned long long)x8);
      ns++;
    }
    pos += ev->size;
  }
  printf("%s nsamp=%d ngetpid=%d nsvc=%d x0p0=%d data_head=%llu\n", tag, ns,
         nget, nsvc, nx0p0, (unsigned long long)head);
  munmap(buf, msz);
  close(fd);
  return 0;
}

static void hist_x28(const char *tag, int pid) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = 8;
  pe.config = 0x8;
  pe.sample_period = 2000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 33) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  int fd = (int)syscall(__NR_perf_event_open, &pe, (long)pid, -1, -1, 0);
  printf("hist %s pid=%d fd=%d errno=%d\n", tag, pid, fd, errno);
  if (fd < 0)
    return;
  size_t msz = 4096 * 33;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    close(fd);
    return;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  if (pid > 0) {
    struct timespec ts = {0, 2000000L};
    for (int i = 0; i < 250; i++)
      nanosleep(&ts, NULL);
  } else {
    for (volatile int i = 0; i < 400000; i++)
      syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uint64_t c28[64];
  int n28 = 0;
  while (pos < head && n28 < 64) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8;
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        uint64_t v = regs[28];
        if (v > 0xffffff8000000000ULL)
          c28[n28++] = v;
      }
    }
    pos += ev->size;
  }
  uint64_t best = 0;
  int bc = 0;
  for (int i = 0; i < n28; i++) {
    int c = 0;
    for (int j = 0; j < n28; j++)
      if (c28[j] == c28[i])
        c++;
    if (c > bc) {
      bc = c;
      best = c28[i];
    }
  }
  printf("hist %s x28_best=%016llx n=%d/%d al64=%d\n", tag,
         (unsigned long long)best, bc, n28, (best & 0x3f) == 0);
  munmap(buf, msz);
  close(fd);
}

int main(void) {
  int pr[2];
  if (pipe(pr) < 0)
    return 1;
  pid_t c = fork();
  if (c == 0) {
    close(pr[0]);
    write(pr[1], "r", 1);
    close(pr[1]);
    for (;;)
      syscall(__NR_getpid);
  }
  close(pr[1]);
  char b;
  read(pr[0], &b, 1);
  printf("child=%d parent=%d\n", (int)c, (int)getpid());
  hist_x28("child", c);
  hist_x28("parent", 0);
  kill(c, 9);
  waitpid(c, NULL, 0);
  return 0;
}
