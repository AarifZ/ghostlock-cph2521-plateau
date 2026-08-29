#define _GNU_SOURCE
#include <errno.h>
#include <linux/elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

int main(int argc, char **argv) {
  pid_t pid = (pid_t)atoi(argv[1]);
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
    printf("ATTACH errno=%d\n", errno);
    return 1;
  }
  int st = 0;
  waitpid(pid, &st, 0);
  ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);
  int i;
  for (i = 0; i < 8; i++) {
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, &st, 0);
    struct user_pt_regs r;
    memset(&r, 0, sizeof(r));
    struct iovec iov = {.iov_base = &r, .iov_len = sizeof(r)};
    ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
    printf("sys i=%d x8=%llu x0=%llu pc=%016llx\n", i,
           (unsigned long long)r.regs[8], (unsigned long long)r.regs[0],
           (unsigned long long)r.pc);
    if (r.regs[8] == 172 /* getpid */ || r.regs[8] == 260 /* wait4 */ ||
        r.regs[8] == 101 /* nanosleep */ || r.regs[8] == 128 /* clock_nanosleep */) {
      r.regs[8] = 174; /* getuid */
      iov.iov_len = sizeof(r);
      errno = 0;
      long sr = ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
      printf("SETREGSET ret=%ld errno=%d\n", sr, errno);
#ifdef PTRACE_SET_SYSCALL
      errno = 0;
      long ss = ptrace(PTRACE_SET_SYSCALL, pid, 0, (void *)(long)174);
      printf("SET_SYSCALL ret=%ld errno=%d\n", ss, errno);
#endif
      int nr = 174;
      struct iovec i2 = {.iov_base = &nr, .iov_len = sizeof(nr)};
      errno = 0;
      long ns = ptrace(PTRACE_SETREGSET, pid, (void *)(long)0x404, &i2);
      printf("NT_ARM_SYSTEM_CALL ret=%ld errno=%d\n", ns, errno);
      ptrace(PTRACE_SYSCALL, pid, 0, 0);
      waitpid(pid, &st, 0);
      iov.iov_len = sizeof(r);
      ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
      printf("EXIT x8=%llu x0=%llu\n", (unsigned long long)r.regs[8],
             (unsigned long long)r.regs[0]);
      ptrace(PTRACE_DETACH, pid, 0, 0);
      return 0;
    }
  }
  ptrace(PTRACE_DETACH, pid, 0, 0);
  printf("no getpid seen\n");
  return 1;
}
