#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int p0k(uint64_t v) {
  return v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL;
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
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                   PERF_SAMPLE_REGS_USER;
  pe.sample_regs_user = (1ULL << 31) - 1;
  pe.disabled = 1;
  pe.exclude_user = 0;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  pe.exclude_callchain_kernel = 0;
  pe.exclude_callchain_user = 0;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, (long)pid, -1, -1, 0);
  printf("open pid=%d fd=%d errno=%d pmu=%d\n", pid, fd, errno, pmu);
  if (fd < 0)
    return 1;
  size_t msz = 4096 * 33;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    printf("mmap errno=%d\n", errno);
    return 1;
  }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 400000; i++)
    syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  int ns = 0, nk = 0;
  printf("head=%llu\n", (unsigned long long)head);
  while (pos < head && ns < 40) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0 || ev->size > 4096)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8;
      uint32_t pidv = *(uint32_t *)p;
      uint32_t tid = *(uint32_t *)(p + 4);
      p += 8;
      uint64_t nr = *(uint64_t *)p;
      p += 8;
      printf("S ip=%016llx pid=%u tid=%u nr=%llu", (unsigned long long)ip, pidv,
             tid, (unsigned long long)nr);
      if (p0k(ip))
        nk++;
      uint64_t i;
      for (i = 0; i < nr && i < 32; i++) {
        uint64_t c = *(uint64_t *)p;
        p += 8;
        if (p0k(c) || (c >= 0xffffffc000000000ULL && c < 0xfffffff000000000ULL)) {
          printf(" C[%llu]=%016llx", (unsigned long long)i, (unsigned long long)c);
          nk++;
        }
      }
      printf("\n");
      ns++;
    }
    pos += ev->size;
  }
  printf("nsamp=%d nkernelish=%d\n", ns, nk);
  return 0;
}
