#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
#endif

static int try_bp(const char *tag, uint64_t addr, uint32_t bptype, uint64_t bplen,
                  uint32_t sz) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_BREAKPOINT;
  pe.size = sz;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.bp_type = bptype;
  pe.bp_addr = addr;
  pe.bp_len = bplen;
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0L, -1, -1, 0);
  printf("%s addr=%016llx type=%u len=%llu sz=%u fd=%d errno=%d\n", tag,
         (unsigned long long)addr, bptype, (unsigned long long)bplen, sz, fd,
         errno);
  if (fd >= 0)
    close(fd);
  return fd;
}

int main(int argc, char **argv) {
  uint64_t va = 0xffffffedf8041000ULL;
  if (argc > 1)
    va = strtoull(argv[1], NULL, 0);
  uint32_t sz = (uint32_t)sizeof(struct perf_event_attr);
  printf("sizeof(attr)=%u va=%016llx\n", sz, (unsigned long long)va);
  try_bp("modR1", va, 1, 1, sz);
  try_bp("modR4", va, 1, 4, sz);
  try_bp("modR8", va, 1, 8, sz);
  try_bp("modRW8", va, 3, 8, sz);
  try_bp("modX4", va, 4, 4, sz);
  try_bp("p0kptrR8", 0xffffff802a7bcf68ULL, 1, 8, sz);
  try_bp("p0kptrR4", 0xffffff802a7bcf68ULL, 1, 4, sz);
  try_bp("p0bssR8", 0xffffff802abb0000ULL, 1, 8, sz);
  try_bp("sz112", va, 1, 8, 112);
  try_bp("sz120", va, 1, 8, 120);
  try_bp("inc_user", va, 1, 8, sz);
  return 0;
}
