#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

static int poke64(pid_t pid, uint64_t addr, uint64_t val) {
  errno = 0;
  long r = ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)val);
  return (r == -1 && errno) ? -1 : 0;
}

int main(int argc, char **argv) {
  pid_t pid = (pid_t)atoi(argv[1]);
  const char *msg = "UID0_GETUID_0\n";
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
    printf("ATTACH errno=%d\n", errno);
    return 1;
  }
  int st = 0;
  waitpid(pid, &st, 0);
  struct user_pt_regs r;
  memset(&r, 0, sizeof(r));
  struct iovec iov = {.iov_base = &r, .iov_len = sizeof(r)};
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  uint64_t dst = (r.sp - 0x100) & ~0xfULL;
  uint64_t words[3] = {0};
  memcpy(words, msg, strlen(msg));
  poke64(pid, dst, words[0]);
  poke64(pid, dst + 8, words[1]);
  printf("sp=%016llx dst=%016llx\n", (unsigned long long)r.sp,
         (unsigned long long)dst);
  ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  iov.iov_len = sizeof(r);
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  r.regs[0] = 1; /* fd stdout */
  r.regs[1] = dst;
  r.regs[2] = strlen(msg);
  r.regs[8] = 64; /* write */
  iov.iov_len = sizeof(r);
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  int nr = 64;
  struct iovec i2 = {.iov_base = &nr, .iov_len = sizeof(nr)};
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)0x404, &i2);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  iov.iov_len = sizeof(r);
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  printf("write x0=%lld x8=%llu\n", (long long)r.regs[0],
         (unsigned long long)r.regs[8]);
  ptrace(PTRACE_DETACH, pid, 0, 0);
  return 0;
}
