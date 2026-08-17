# Walk determinism master plan — CPH2521 GhostLock (2026-08-17)

**Source basis:** oppo-source/android_kernel_oppo_sm8475 @
`oppo/sm8475_b_16.0.0_reno10_pro_plus` — **VERSION 5.10.236, exact match with
the running kernel** (`Makefile` SUBLEVEL=236). All quotes below are from the
device's own tree (extracted to `../ksrc/`).

---

## 1. The bug, verbatim from the device source

`kernel/locking/rtmutex.c:1071` (remove_waiter):

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;      // ← 'current', NOT waiter->task
```

Full trigger chain (source-proven):

1. Waiter thread: `FUTEX_LOCK_PI(f_pi_chain)` (owns it) →
   `FUTEX_WAIT_REQUEUE_PI(f_wait → f_pi_target)`. `futex_wait_requeue_pi`
   sets `q.rt_waiter = &rt_waiter` — **on the WAITER's own kernel stack**.
2. Owner: `FUTEX_LOCK_PI(f_pi_target)` → blocks on `FUTEX_LOCK_PI(f_pi_chain)`.
3. Main: `FUTEX_CMP_REQUEUE_PI(f_wait, f_pi_target)` → `futex_requeue()` →
   `rt_mutex_start_proxy_lock(pi_mutex, this->rt_waiter, this->task)`.
4. `task_blocks_on_rt_mutex()`: enqueues the WAITER-STACK node, sets
   `waiter_task->pi_blocked_on = &waiter_stack_rt_waiter`, chain walk detects
   the cycle → **-EDEADLK**. Note: task_blocks has **no undo** on EDEADLK.
5. `rt_mutex_start_proxy_lock`: `remove_waiter()` → dequeues the node, clears
   **current(main)->pi_blocked_on** (no-op) — the waiter's stays dangling.
6. `futex_requeue` error path: `this->pi_state = NULL; break;` —
   **`requeue_futex()` (the q.key switch) is never reached**.
7. Waiter times out on f_wait → `handle_early_requeue_pi_wakeup`:
   `q.key != key2` → `-ETIMEDOUT` → `goto out` — **the proxy-lock/cleanup
   else-branch is skipped entirely**.
8. Waiter returns to userspace with `pi_blocked_on` dangling at its own
   (now-freed) stack frame = `SP_DIV-0x210`, `rt_waiter @ +0x90`.

## 2. The walk, condition by condition (what is deterministic)

`rt_mutex_adjust_pi` → `adjust_prio_chain` guards, in source order:

| # | Condition | Requirement on the overlay | Status |
|---|-----------|---------------------------|--------|
| C1 | dangling exists | EDEADLK path (above) | **DETERMINISTIC** (every fire primes; EDEADLK 35 always) |
| C2 | `!waiter` guard | pi_blocked_on non-NULL at consumer time | DETERMINISTIC (nothing clears it; the walk itself doesn't) |
| C3 | `next_lock == waiter->lock` | adjust_pi reads the same word it passes | DETERMINISTIC |
| C4 | `waiter_equal` false | prio word (3) ≠ task prio (139) | DETERMINISTIC |
| C5 | `[5] trylock lock->wait_lock` | lock word must be a lockable (zero) spinlock | depends on WHERE lock points |
| C6 | rb_erase Case-2 write `*left = parent_color` | single store; change_child only COMPARES parent+8/+0x10 (no store, no deref as function) | DETERMINISTIC given C5 and a mapped parent |
| C7 | re-enqueue + owner exit | tree/owner readable, empty tree → clean exit; `waiter->task` **is never guard-checked** in 5.10 (INIT_TASK stamp fine; only read on the wake path, and wake_up_process(INIT_TASK) is safe) | depends on lock slot |
| C8 | **fdset stamp present at the frame at walk time** | see §3 | DETERMINISTIC |
| C9 | **spray page reclaimed and holding our payload** | see §4 | **THE RACE** |

Also source-proven: `select.c core_sys_select` — `stack_fds[256]`, six 40-byte
regions `in/out/ex/res_in/res_out/res_ex`; our waiter words (global 0-10)
live in `in/out/ex` which are **never written after copy-in** (results go to
`res_*` at +120..240). The route blocks on an **unarmed timerfd** (never
readable) with the consumer armed +50 ms — the stamp sits stable in the
blocked frame. Even after select returns it persists until the thread's next
*deep* syscall (shallow gettid/clock frames don't reach SP-0x210).

## 3. Conclusion: the "walk race" is not the walk — it's the heap reclaim

`prepare_kernel_page` (util.c):

```c
uintptr_t base = leaked & ~(ORDER3_SIZE - 1);   // leaked mm's 16K page
prepare_skb_payload(base, ...);                  // fill skb_buf
sendmsg × SKB_RECLAIM_SENDS;                     // spray
return base;                                      // ← NO VERIFICATION
```

**Nothing checks that the skb spray actually claimed the freed mm slab page.**
"prepare_kernel_page ok attempt=N" only means KernelSnitch found the
mm_struct. When the reclaim loses (buddy allocator noise — worse at high
uptime, matches every "good session / bad session" observation), `fake_lock`,
`fake_w0`, `fake_fops` point at foreign-but-mapped heap memory:

- walk derefs foreign lock fields → wild tree walk → **crash at pre_setattr**
  (12/13 tonight); occasionally benign → ALIVE no-write.
- reclaim won → clean walk (T1c, T2f, afternoon 2/2).

CPU affinity is already correct (children + spray on CORE, consumer CORE+1 —
SLUB per-CPU consistency). Uptime is the only environmental lever in the
current design.

## 4. The fix implemented: reclaim-independent walk + crash-free verify loop

Two changes, both opt-in, built into `ghostlock-cph2521` (150848 B):

### 4.1 `MODE4_BSS_LOCK=1` (default ON inside VERIFY_SWAP) — walk without spray memory

`stack_lock` points at a **static all-zero .data slot** instead of the sprayed
page: `nfulnl_loggers + 0x40` (phase 1) / `+0x60` (phase 2) — VA
`0xffffffc00a7c1430`/`0x1450`, P0 `0xffffff802a7c1430`/`0x1450`.
Image-verified all-zero; runtime-writable (logger registration array);
**proven inert+writable by the slide proofs** that already write the
neighboring `nfulnl_logger` fields. For the walk this gives:
`wait_lock=0` (trylock ok) · `waiters.rb_node=NULL` (empty tree) ·
`rb_leftmost=NULL` · `owner=0` (clean no-owner exit). **No sprayed structure
is ever dereferenced by the walk.** The only spray dependency left is the
VALUE written (`fake_fops`), whose target page is always mapped, so
`change_child`'s compare-only reads are safe even when the reclaim lost.

One walk per slot: phase 2 uses a fresh slot because erasing a node from a
tree that already links it (leftmost==node) triggers `rb_next` → leftmost
update → reads `fake_fops+8/+0x30` as waiter fields → wake hazard. Fresh
slot → leftmost=0 ≠ node → path never taken.

### 4.2 `MODE4_VERIFY_SWAP=1` — phased route with abort-ALIVE gate

```
phase 1 (oracle):  stamp = { pc=fake_fops+0x80, right=0, left=fake_fops+0x90,
                              lock=BSS slot1, prio=3 }
                   walk writes the marker INTO our own sprayed table,
                   then wproof_spray_verify() peeks (MSG_PEEK, pages stay
                   pinned) the reclaim socket stream:
                     marker at table+0x90  → RECLAIM VERIFIED → phase 2
                     marker elsewhere/absent → MISMATCH (Y measured) → ABORT ALIVE
                     table not in stream    → NOTABLE → ABORT ALIVE
phase 2 (swap):    stamp = { pc=fake_fops, right=0, left=&ashmem_misc.fops,
                              lock=BSS slot2, prio=3 }   (same sprayed page)
                   walk executes  *ashmem_misc.fops = fake_fops  with the
                   CLONE_CFG table (verified page!), cfi probe (MODE4_PROOF)
                   → expect errno≠22 / cfi_write_ret>0 = plateau broken.
```

Failure budget per fire: worst case one stray qword at `page+FOPS_OFF+0x90`
into a foreign page (marker write when reclaim lost) — strictly cheaper than
today's foreign-lock CAS + tree walk. Phase-1 abort keeps the box alive to
retry the reclaim on the next fire.

**Fire command (next session, fresh boot, uptime ≤ 60 s):**

```
MODE4_WRITE_PROOF=1 WRITE_PROOF_TARGET=fops MODE4_VERIFY_SWAP=1 \
MODE4_CLONE_CFG=1 MODE4_PROOF=1 FOPS_MAX_ATTEMPTS=4
```

(`MODE4_WRITE_PROOF` selects the mode-4 route; the VERIFY_SWAP stamps
override the target selection internally.)

## 5. Alternative methods (ranked, from everything now proven)

1. **VERIFY_SWAP + CLONE_CFG** (above) — primary. Walk is reclaim-blind,
   swap is reclaim-gated, probe is the oracle.
2. **Direct cred-pointer swap (plan B, no fops/CFI at all):** AAW writes
   `*(task+0x780) = sprayed_page_addr` (task from mm->owner via KernelSnitch;
   offsets known: real_cred 0x778 / cred 0x780). Needs a forged cred in the
   sprayed page — requires knowing a valid `cred->security` blob pointer for
   SELinux (cannot read yet). Two adjacent writes would be needed (0x778+0x780).
   Viable AFTER the configfs write primitive exists (read then clone cred).
3. **selinux_enforcing = 0 via root-erase shape** (`*waiters = right` with
   right=0, lock=enforcing-8): needs wait_lock@enforcing-8 zero — verify in
   Image before attempting; only disables SELinux (still need uid0).
4. **WION/ION family** — obsoleted: the only-left MISC walk is proven safe
   (T2f) and BSS-lock removes the last geometric concern.
5. **SIGALRM/EINTR trigger** — not needed: the EDEADLK path is
   source-proven deterministic (§1); the historical flakiness was the reclaim.

## 6. Open items

- af_unix.c skb geometry (SKB_DATA_DELTA=-0xe80): empirically correct when
  reclaim wins; no action unless the oracle reports MISMATCH with a stable Y.
- The T2f open-crash: expected to be explained by phase-1 of VERIFY_SWAP
  (if MISMATCH dominates, delta/page-lifetime was the killer; if VERIFIED
  and phase 2 still dies at open, it is the probe path itself — then gate
  the probe off and use llseek-vs-read oracles first).
- `/sys/fs/pstore` still denied (uid 2000) — classification stays
  differential; the O_SYNC proof log ordering (pre_setattr before
  sched_setattr) remains the in-walk crash boundary.

---

## SESSION RESULT (2026-08-17 00:30-01:10, 5-fire budget)

| Fire | Config | Result |
|------|--------|--------|
| F1 | VERIFY_SWAP v1 (loggers+0x40 BSS lock) | SOFTBOOT @ pre_setattr → **runtime-nonzero loggers slot** (Image-rest zeros ≠ runtime) — fixed |
| F2 | v2 lock = init_task+0x878 | **ALIVE, walk clean (post_setattr), cfi probe safe, gate MISMATCH-abort** — first non-fatal reclaim-loss ever |
| F3 | + in-process retry loop | ALIVE, 3 fresh leaks, all MISMATCH, clean exit |
| F4 | + delta sweep (0x100/0xF80/−0x80/−0x1080) | ALIVE, 4 candidates, all MISMATCH, EXIT=1 |
| F5 | sweep restart + PREPARE_SLABS=64 | walk clean + probe safe, died post-probe pre-peek (churn-64 collateral; candidate 0x100@churn64 UNTESTED) |

**Proven this session:**
1. The walk is now fully crash-free and reclaim-blind (BSS lock init_task+0x878:
   wait_lock in never-written padding, tree = pi_waiters, owner = pi_top_task —
   all semantically dead for swapper, Image-verified zeros). post_setattr on
   every fire.
2. The non-fatal verify gate works end-to-end: table ALWAYS found in the peek
   stream at 0xF80 (= FOPS_OFF exactly — payload stream placement is perfect),
   marker NEVER found → the AAW executes but the sprayed payload never
   occupies the leaked mm page.
3. The blocker is now 100% isolated to the last mile: **the skb spray does not
   reclaim the leaked mm_struct slab page on this device** (10+ verified
   negative marker tests across 4 candidate deltas and 2 churn levels).

**Next session (ordered):**
1. Re-run F5 config (churn64 + candidate 0x100) — the death preempted its peek.
2. If still negative: the SLUB hypothesis — the freed mm slab page never leaves
   the percpu partial list. Options: (a) verify via /proc/slabinfo-style
   reasoning (mm_struct slab activity), (b) raise MM_PARTIALS/PREPARE_SLABS
   beyond 64 (rebuild), (c) study whether the skb allocation path on this
   kernel even draws from the buddy at the right order (af_unix SOCK_STREAM
   sends — check sock_alloc_send_pskb/data_len split on 5.10.236 with the
   actual SKB_RECLAIM_SENDS iovec), (d) spray a different reclaim vehicle
   (pipe buffers / sendmsg on a socket with page-frag allocs of matching order).
3. Once ANY marker verifies, phase 2 auto-fires the CLONE_CFG swap + cfi probe.

---

## SESSION 2 RESULT (2026-08-17 01:00-03:10, fires F7-F23 — full-access uid0 push)

### The static-chain design (MODE4_STATIC_CHAIN) — built and mechanically PROVEN:
- 7 deterministic walks, no spray: build fops table in kernel image tail
  (KIMAGE VA 0xffffffc00abb9d00; Image-file zeros verified; image_size covers
  it), then *ashmem_misc.fops swap. Per-phase nice (19..13) so every walk
  really runs (same-nice = silent no-op — found and fixed).
- TRAP experiments PROVED the walk machinery executes with our stamps:
  lock=text-addr (CAS on RO) → softboot; right=text (successor path) →
  softboot. Walks reach [5] trylock AND the rb_erase with our words.
- /dev/ashmem verified misc(10,127) — swap target correct.
- F10: all 7 phases + swap completed ALIVE (ioctl-first order).

### THE REMAINING BLOCKER (sharpened to a point):
The walks run with our stamps — but the erase's store (*left = pc) never
shows in any visible target (bootid readback per phase — F13/F15/F18/F19;
modprobe oracle is root-unreadable). Evidence table:
- shift -2: silent no-op (store invisible) — same shift T1c-era landed with
  spray-address stamps.
- shift -1: silent no-op. shift 0: DETERMINISTIC softboot. shift +1: softboot.
  shift -3: softboot at first walk.
- F14 (exact T1c stamps incl. spray lock, my binary) died at trylock —
  the walk READ our word9 → overlay contact at -2 CONFIRMED — but the spray
  page was foreign that boot (reclaim lost), i.e. F14 ≈ T1c-on-a-bad-boot.
⟹ Contradiction to resolve next session: overlay contact at -2 + erase runs
  (traps) + correct stamp structure ⇒ the store must land — yet readbacks say
  no. Candidates left: (a) the erase Case taken isn't !child (frame word3
  nonzero in the kernel copy — verify by making word3 a valid sprAY-safe addr
  and observing), (b) the store lands and something restores/aliases the
  targets (test by writing TWO DIFFERENT targets in consecutive phases and
  reading both), (c) per-boot phys aliasing (P0 vs KIMAGE diverge — try
  writing the SAME phase target via both alias forms).

### Next-session fire plan (in order):
1. F14-exact with spray on a reclaim-WINNING boot (retry a few times) — if it
   lands, diff stamp-by-stamp vs static (binary-search the pc/lock source).
2. word3 (tree_right) = a valid writable addr (tail+0x300) test — forces
   Case ambiguity resolution.
3. Dual-target dual-alias write test.
4. Resume only after the store-visibility question closes; the 7-phase chain
   then completes to cfi≠22 → configfs R/W → cred → uid0.

### Ops log: device healthy; ~23 fires total tonight; boot_id never left
corrupted state (readbacks clean); no overheating observed.

---

## SESSION 3 RESULT (2026-08-17 ~09:00-10:00 — reference mining + decisive diagnostics)

### Reference mining (user-supplied)
- **IonStackQuest3 (5.10 Quest3, lineage ancestor)**: exp32 uses a THIRD stamp
  mechanism — waiter spins 10M× setsockopt(MCAST_JOIN_SOURCE_GROUP) self-
  stamping its own stack while consumer fires ONCE mid-loop. No arm delay.
- **K40 4.19**: identical pselect architecture to ours (our codebase's parent)
  — pselect design is sound on that lineage.
- **Samsung PR196 (5.15)**: "rt_sigreturn/FPSIMD fake waiter writer" (3rd
  stamp variant); their FZG1 panic = "stale waiter's lock pointer was NULL"
  in adjust_prio_chain = walk reading UNSTAMPED residue (benign no-op class).
- **aristotle disasm**: already absorbed (shift -2 derivation, EINVAL analysis).

### DECODED THIS SESSION (fires F24-F30):
1. **F26 TRAP3 SOFTBOOT: the rb_erase store path EXECUTES.** parent=text|1
   → change_child RO-write → softboot. Walk has NO unproven segments left:
   trigger→dangling→stamp→[5] trylock→[6]→[7]→erase→store→change_child.
2. **F27: P0-FORM STORE LANDED VISIBLE.** bootid readback = literal bytes of
   tail+8 (0xffffff802abb9d08 → "089dbb2a-80ff-ffff-b"). THE PRIMITIVE IS
   FULLY PROVEN. All earlier silent fires = wrong address FORM.
3. **KASLR slide ≠ 0** (CONFIG_RANDOMIZE_BASE=y in IKCFG; KIMAGE-form writes
   vanish, P0-form lands). ALL text pointers (fops JT values) need +S.
   CONFIG_STATIC_USERMODEHELPER=y(") kills modprobe_path/core_pattern UMH.
4. **Live-vs-dead dangling is a per-fire coin flip** (~40-50%): dead boots =
   walk reads stale residue (lock=real pi_mutex, RB_CLEAR'd) → every path
   benign → silent ret=0 no-ops. F30 ph4 bootid-oracle catches this in-fire.
5. **Live-boot crash cause found: wake_up_process(word8=init_task) wakes the
   idle task** (F27 survived, L1 crashed — same shape). FIX BUILT (untested):
   word8 = tail+0x800 → ttwu reads state=0 → early return. Binary 156384 B.
6. **UMASK strategy** (MODE4_SC_UMASK, 4 phases): dmesg_restrict=0,
   kptr_restrict=0, selinux_state qword=0 (enforcing is byte +1 — offset
   0x02A793C8 = &selinux_state per kallsyms), ph4 bootid oracle. SELinux
   denies kallsyms/dmesg/sysctl-reads for shell — permissive should open
   them (to be confirmed on a live boot).

### RESUME HERE (device disconnected mid-loop):
Binary ghostlock-cph2521 (156384 B) has the SAFE-WAKE fix + UMASK4 + oracle.
1. Loop UMASK4 fires (fresh boot ≤60s uptime each) until: CLASS=ALIVE **and**
   post-bootid ≠ pre (oracle = live landing). ~2-4 attempts expected.
2. On the live boot: `dmesg | grep -A6 "Virtual kernel memory layout"` or
   `head /proc/kallsyms` → runtime _text VA → slide S = VA − 0xffffffc008000000.
   (If still denied in permissive: try /proc/net/packet %pK with restrict=0,
   or tracefs.)
3. Then: slide-adjust the 7-phase STATIC_CHAIN table values (tab[].val += S)
   — one-line change (fops_runtime_text already single-point) — fire until
   live boot → table built → ph7 swap → cfi probe: **errno≠22 = plateau
   broken** → configfs R/W → cred (task->cred/real_cred ← init_cred+S, or
   build fake cred in tail) → **uid 0**.
4. Fallback if wake-fix misbehaves: word8=0 crashes (NULL deref) — keep
   tail+0x800. If UMASK lands but reads still denied: kallsyms via
   /sys/kernel/tracing after enabling trace_clock... (tracefs listable).
