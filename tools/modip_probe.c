#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  int pmu = 8;
  FILE *f = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (f) {
    if (fscanf(f, "%d", &pmu) != 1)
      pmu = 8;
    fclose(f);
  }
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
  printf("pmu=%d fd=%d errno=%d\n", pmu, fd, errno);
  if (fd < 0)
    return 1;
  size_t msz = 4096 * 65;
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    printf("mmap errno=%d\n", errno);
    return 1;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  {
    volatile int i;
    for (i = 0; i < 4000000; i++)
      syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 64;
  uint64_t pos = hdr->data_tail;
  uint64_t pages[64];
  int pc[64];
  int np = 0, ns = 0, nout = 0;
  while (pos < head && ns < 20000) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
      uint64_t pg = ip & ~0xfffULL;
      int i, found = -1;
      ns++;
      if (ip < 0xffffffc008000000ULL || ip >= 0xffffffc00ac00000ULL)
        nout++;
      for (i = 0; i < np; i++)
        if (pages[i] == pg) {
          found = i;
          break;
        }
      if (found >= 0)
        pc[found]++;
      else if (np < 64) {
        pages[np] = pg;
        pc[np] = 1;
        np++;
      }
    }
    pos += ev->size;
  }
  printf("nsamp=%d nout_vmlinux=%d npage=%d head=%llu\n", ns, nout, np,
         (unsigned long long)head);
  {
    int i;
    for (i = 0; i < np; i++)
      printf("PAGE %016llx n=%d\n", (unsigned long long)pages[i], pc[i]);
  }
  /* second pass: print full IPs on outlier pages */
  pos = hdr->data_tail;
  {
    int shown = 0;
    uint64_t pos2 = hdr->data_tail;
    while (pos2 < head && shown < 80) {
      struct perf_event_header *ev = (void *)(base + (pos2 % dsz));
      if (ev->size == 0)
        break;
      if (ev->type == PERF_RECORD_SAMPLE) {
        uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
        uint64_t pg = ip & ~0xfffULL;
        int hot = (pg >= 0xffffffe468800000ULL && pg < 0xffffffe468c00000ULL);
        int user = (ip < 0xffff000000000000ULL);
        if (!hot && !user) {
          printf("OUT ip=%016llx off=%03llx\n", (unsigned long long)ip,
                 (unsigned long long)(ip & 0xfffULL));
          shown++;
        }
      }
      pos2 += ev->size;
    }
  }
  munmap(buf, msz);
  close(fd);
  return 0;
}
