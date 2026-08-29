#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int perf_try(const char *tag, int type, uint64_t config, int pid, int cpu,
                    int exclude_user, int exclude_kernel, uint64_t bp_addr) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = (uint32_t)type;
  pe.config = config;
  pe.sample_period = 10000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 33) - 1;
  pe.disabled = 1;
  pe.exclude_user = exclude_user;
  pe.exclude_kernel = exclude_kernel;
  pe.exclude_hv = 1;
  if (type == PERF_TYPE_BREAKPOINT) {
    pe.bp_addr = bp_addr;
    pe.bp_len = HW_BREAKPOINT_LEN_8;
    pe.bp_type = HW_BREAKPOINT_RW;
    pe.sample_period = 1;
  }
  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, (long)pid, cpu, -1, 0);
  printf("PERF %s type=%d cfg=0x%llx pid=%d cpu=%d xu=%d xk=%d fd=%d errno=%d\n",
         tag, type, (unsigned long long)config, pid, cpu, exclude_user,
         exclude_kernel, fd, errno);
  if (fd >= 0)
    close(fd);
  return fd;
}

int main(int argc, char **argv) {
  volatile uint64_t probe = 0x1122334455667788ULL;
  int target = 0;
  if (argc > 1)
    target = atoi(argv[1]);
  printf("pid=%d uid=%d target=%d probe=%p\n", getpid(), getuid(), target,
         (void *)&probe);

  int pmu = 8;
  FILE *tf = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (tf) {
    if (fscanf(tf, "%d", &pmu) != 1)
      pmu = 8;
    fclose(tf);
  }
  printf("pmu_type=%d\n", pmu);

  perf_try("pmu_k", pmu, 0x8, 0, -1, 1, 0, 0);
  perf_try("pmu_u", pmu, 0x8, 0, -1, 0, 1, 0);
  perf_try("pmu_both", pmu, 0x8, 0, -1, 0, 0, 0);
  perf_try("pmu_cpu0_k", pmu, 0x8, -1, 0, 1, 0, 0);
  perf_try("sw_cpu", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 0, -1, 0, 1, 0);
  perf_try("sw_task", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, 0, -1, 0, 1, 0);
  perf_try("hw_cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0, -1, 0, 1,
           0);
  perf_try("bp_user", PERF_TYPE_BREAKPOINT, 0, 0, -1, 0, 1, (uint64_t)&probe);
  perf_try("bp_uk", PERF_TYPE_BREAKPOINT, 0, 0, -1, 0, 0, (uint64_t)&probe);

  errno = 0;
  int kc = open("/proc/kcore", O_RDONLY);
  printf("kcore fd=%d errno=%d\n", kc, errno);
  if (kc >= 0)
    close(kc);
  errno = 0;
  int km = open("/dev/kmem", O_RDONLY);
  printf("kmem fd=%d errno=%d\n", km, errno);
  if (km >= 0)
    close(km);

  if (target > 1) {
    errno = 0;
    long r = ptrace(PTRACE_ATTACH, target, 0, 0);
    printf("PTRACE_ATTACH pid=%d ret=%ld errno=%d\n", target, r, errno);
    if (r == 0) {
      int st = 0;
      waitpid(target, &st, 0);
      printf("wait status=%d\n", st);
      ptrace(PTRACE_DETACH, target, 0, 0);
    }
  }

  char path[64], buf[256] = {0};
  snprintf(path, sizeof(path), "/proc/%d/syscall", target > 1 ? target : getpid());
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    printf("syscall[%s] n=%zd %s\n", path, n, buf);
  } else
    printf("syscall[%s] errno=%d\n", path, errno);

  snprintf(path, sizeof(path), "/proc/%d/stack", target > 1 ? target : getpid());
  fd = open(path, O_RDONLY);
  printf("stack[%s] fd=%d errno=%d\n", path, fd, errno);
  if (fd >= 0) {
    char s[400] = {0};
    read(fd, s, sizeof(s) - 1);
    close(fd);
    printf("stack: %.300s\n", s);
  }
  return 0;
}
