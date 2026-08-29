#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int taskish(uint64_t v) {
  return ((v & 0x3f) == 0) && v >= 0xffffff8000000000ULL &&
         v < 0xffffffc000000000ULL;
}

int main(int argc, char **argv) {
  int pid = argc > 1 ? atoi(argv[1]) : 0;
  int pmu = 8;
  FILE *tf = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (tf) {
    fscanf(tf, "%d", &pmu);
    fclose(tf);
  }
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)pmu;
  pe.config = 0x8;
  pe.sample_period = 800;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 33) - 1;
  pe.disabled = 1;
  pe.exclude_user = 0;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, (long)pid, -1, -1, 0);
  printf("open pid=%d fd=%d errno=%d\n", pid, fd, errno);
  if (fd < 0)
    return 1;
  size_t msz = 4096 * 65;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    printf("mmap errno=%d\n", errno);
    return 1;
  }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 800000; i++)
    syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 64;
  uint64_t pos = hdr->data_tail;
  int ns = 0, nker = 0;
  uint64_t best_x28 = 0;
  int best_cnt = 0;
  uint64_t cand[16];
  int cc[16];
  int ncand = 0;
  memset(cand, 0, sizeof(cand));
  memset(cc, 0, sizeof(cc));

  while (pos < head && ns < 80) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0 || ev->size > 2048)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8;
      uint32_t pidv = *(uint32_t *)p;
      uint32_t tid = *(uint32_t *)(p + 4);
      p += 8;
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      int ker = (ip >= 0xffffffc000000000ULL);
      if (ker)
        nker++;
      uint64_t x28 = 0, sp = 0, pc = 0;
      if (abi == 1 || abi == 2) {
        uint64_t *r = (uint64_t *)p;
        x28 = r[28];
        sp = r[31];
        pc = r[32];
      }
      if (ns < 12)
        printf("S ip=%016llx ker=%d abi=%llu x28=%016llx sp=%016llx pc=%016llx "
               "pid=%u\n",
               (unsigned long long)ip, ker, (unsigned long long)abi,
               (unsigned long long)x28, (unsigned long long)sp,
               (unsigned long long)pc, pidv);
      if (taskish(x28)) {
        int f = -1, u;
        for (u = 0; u < ncand; u++)
          if (cand[u] == x28)
            f = u;
        if (f >= 0)
          cc[f]++;
        else if (ncand < 16) {
          cand[ncand] = x28;
          cc[ncand] = 1;
          ncand++;
        }
      }
      ns++;
      (void)tid;
    }
    pos += ev->size;
  }
  int u;
  for (u = 0; u < ncand; u++) {
    printf("CAND x28=%016llx n=%d\n", (unsigned long long)cand[u], cc[u]);
    if (cc[u] > best_cnt) {
      best_cnt = cc[u];
      best_x28 = cand[u];
    }
  }
  printf("nsamp=%d nker_ip=%d best_x28=%016llx cnt=%d\n", ns, nker,
         (unsigned long long)best_x28, best_cnt);
  if (best_x28)
    printf("TASK %016llx\n", (unsigned long long)best_x28);
  return 0;
}
