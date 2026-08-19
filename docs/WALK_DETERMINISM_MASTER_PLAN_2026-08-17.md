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

---

## SESSION 4 (2026-08-17 night → 08-18 morning) — Quest3 restructure + ground truth

### Implemented (all in ghostlock-cph2521 159280 B):
1. **MODE4_SELFSTAMP** — full Quest3 architecture: fd prestage BEFORE WRPI,
   zero-gap self-stamp spin after timeout, deterministic handoff, final
   stamp = long BLOCKING select (F27's stable shape).
2. Chain-unlock placement studied: before-stamp (unlock's deboost walk reads
   RAW residue → crash), mid-stamp (walk reads stamped words — still
   crashed), nounlock (dangling dies → dead boots dominate).
3. **ph6 hostname oracle**: store "PWNED\0" into init_uts_ns.nodename
   (0x027CBDA8+8+65) — shell-readable, harmless, persistent. The clean
   live/dead ground truth with zero side effects.
4. ph5 equal-prio [3]-exit probe, dying-box harvester (in-process kallsyms
   dump with per-chunk fsync to /data/local/tmp).

### GROUND TRUTH (hostname campaign, 8 fires): 0 landings.
- Dead boots (write_proof_miss): ~50-60%
- Live boots: crash in-walk (pre_setattr last), post-walk, or at unlock
- F27 remains the ONLY clean live landing in ~60 fires

### The eliminination table (live-boot crash):
- NOT the erase shape (zero-write + plain-store both crash; P5 [3]-exit
  crashed under unlock-before → unlock's own deboost walk implicated there)
- NOT wake(init_task) alone (P5-nounlock crashed once with no wake possible)
- NOT tearing (blocking final stamp didn't fix)
- NOT fd policy / stamp content (audited correct every time)
- UNRESOLVED without a kernel fault dump (pstore SELinux-denied)

### NEXT SESSION — strongest moves, in order:
1. **QEMU replay** (aristotle repo has qemu/ for this kernel class): boot OUR
   Image with our exact stamps, fire the same flow, read the panic PC + stack
   directly. Zero device risk, definitive answer to the live-walk crash.
2. wps=1/n≤64 residue experiment: word8/word9 unstamped = REAL waiter-task
   pointer + stale lock from the EDEADLK residue (wake-the-runnable-task is
   provably safe; stale-lock risk).
3. pstore via engineering path (EX01 lab image may expose ramoops elsewhere).

---

## SESSION 5 (2026-08-18) — QEMU deep-dive: crash chain DECODED

### Harness (qemu_cph/): real CPH2521 Image boots on qemu virt (nokaslr),
launcher forks exploit + polls /proc/<tid>/syscall, python cpio/probe/sweep,
30+ panics captured with full PC/registers.

### DECODED (from panic PC + register analysis + instruction decode):
1. +0x3f0 = `ldr x9,[x8,#0x38]` — load waiter->lock; garbage x8 = the
   dangling pi_blocked_on pointing at OVERWRITTEN stack content.
2. +0x188 = qspinlock `ldaxr` — walk read waiter->lock=0 (stamp misaligned
   by a word at that shift) → trylock(NULL) fault.
3. +0x1788 = brk (BUG/UBSAN-class) deep in walk epilogue — the walk gets
   PAST erase/store when the stamp is aligned.
4. Wedge/RCU-stall runs = trylock on mapped-but-never-freed lock values
   (retry loop) OR QEMU-TCG starvation (per-iteration sched_yield in the
   stamp spin REGRESSES — removed).
5. **Kernel has NO vmap stacks** — thread stacks live in the linear map;
   source confirms rt_waiter is a STACK local (the "slab-looking" waiter
   addresses in panics are linear-map stacks).
6. Long BLOCKING select lets kernel entries (IRQ) clobber the frozen stamp
   → walk reads FPSIMD junk. Spin-through-punch keeps it fresh.
7. Stamp alignment classes change per shift (sweep2.py): -4/-2/-1/+1 =
   mapped-lock behavior (stamp landing), others = garbage faults.
8. Waiter/consumer tids land ~500+ (slab_drain clones) — launcher probe
   range widened; /proc/<tid>/syscall exposes blocked syscalls.

### INSTRUMENT READY, ONE EXPERIMENT PENDING (exact resume point):
MODE4_QEMU_MAP (built, in qemu exploit): tags every stamp word
0xDEAD0000_000000C0+ii; the walk's trylock fault address names the word
index truly at waiter->lock(+0x38) = exact fdset-waiter alignment in ONE
panic. Last run went quiet (dead-boot class) — just re-run probe.py a few
times (each ~30s); on a panic, read the tag from "Unable to handle ... 0x…DEAD…C?".
With the true alignment: set PSELECT_SHIFT accordingly, restore ph6
safe-store shape, confirm hostname landing in QEMU, then port to device.

### Known QEMU quirks to respect: main thread can hang inside CMP_REQUEUE_PI
under TCG (its prints stop — use launcher/panic output for truth); keep
-smp 2; no sched_yield in stamp spin; panic=-1 halts (no auto-exit) —
probe.py kills QEMU after its window.

### SESSION 5 FINAL STATE (resume here):
- devtmpfs mount removed (request_module deadlock w/ STATIC_USERMODEHELPER="")
  → runs now complete cleanly end-to-end (launcher reaps exploit).
- MAP-tag runs: 5/5 quiet completes — no panic, no stall → the consumer's
  walk never read the tags. Next: verify the punch fires in QEMU at all
  (consumer sched_setattr path / EDEADLK priming under TCG — check the
  WRPI/CMP prints from launcher-class output, or make the consumer's
  sched_setattr return value visible via a file the launcher cats).
  If punch fires but walks exit instantly: QEMU dangling is DEAD-class
  (timeout cleanup clears pi_blocked_on) → mirror Quest3 trigger tweaks
  (WRPI timeout vs CMP timing) until live-class walks appear, then the
  MAP panic gives the alignment and everything downstream is ready.

---

## SESSION 6b (2026-08-19 morning) — exit-flow fix + bootid oracle campaign

### Device recovered (user reboot; battery 97%, 37C). Findings:
1. **hostname oracle is BLIND on device** — SELinux denies reading
   /proc/sys/kernel/hostname even for shell (harvester wrote "unreadable").
   The bootid oracle (ph3, F27 shape, in-process readback) is the visible
   device oracle; hostname stays for QEMU (no SELinux there).
2. **Exit-flow fixed properly**: owner timeout REVERTED (liveness suspect —
   7/7 dead boots under it), waiter no longer waits for owner_chain_done;
   process exit kills all threads (futex exit cleanup releases the blocked
   owner) and the dangling dies with the waiter task. No tail unlock needed.
3. Durable WP_BOOTAFTER logging added (console truncates at ~21 lines —
   boot_after was invisible before).
4. 7 clean-burn ALIVE fires with full readback — ALL dead-dangling boots
   (clean UUIDs, walks no-op'd). Liveness did not return post-timeout-revert
   (0 more samples before device dropped).
5. **DEVICE OFFLINE PATTERN (2nd occurrence)**: after ~8-10 reboot+fire
   cycles the box drops off WiFi/ADB until physically revived (both times
   the LAST fires completed ALIVE — suggests reboot-cycling wedges
   connectivity (modem/WiFi state), not our writes). Recovery = user reboot.

### NEXT (device online again):
1. Fire run_p3.sh (bootid oracle, current build) — need live-boot samples
   with the corrected exit flow; landing check = WP_BOOTAFTER shows
   tail-bytes ("80ff-ffff" pattern).
2. On landing: SELFSTAMP_SINGLE=1 (selinux zero) + harvester → kallsyms
   dump to /data/local/tmp/harvest_0.txt → slide S.
3. KASLR_SLIDE=S + 7-phase STATIC_CHAIN → hostname/bootid visible stores
   → *MISC swap → cfi != 22 → configfs R/W → cred → uid0 → [MP3].

---

## SESSION 7 (2026-08-19, QEMU + lldb) — THE ALIGNMENT + TARGET MYSTERIES SOLVED

### Instrument: QEMU gdbstub + NDK lldb (lldb.cmd with PATH to its dir; batch
### scripts dumpN.gdb in qemu_cph/). Conditional breakpoints work.

### FINDINGS (device-grade significance):
1. **CONFIG_VMAP_STACK=y confirmed** (IKCFG): kernel stacks are vmalloc'd at
   0xffffffc00bxxxxxx. Task structs are slab (linear map). Earlier
   "no-vmap-stack" conclusion reversed — both observations were correct.
2. **The walk's crash at +0x188 (lock=NULL trylock) is a task whose dangling
   pi_blocked_on points at ANOTHER thread's stack** — a slab_drain clone (comm
   "exploit") self-walking its stale dangling via its own setpriority. It is
   NOT our consumer's punch. Boot-noise walks dominated all our QEMU traces.
3. **The dangling DOES point at our waiter-thread's stack with the stamp**:
   dump7 caught dangling=0xffffffc00b013c30 with MAP tags (0xdead...c5/c7) at
   0xb0138b0/d8 — same 16K vmap stack, **920 bytes (115 words) BELOW the
   waiter**. The fdset lands at stack_fds=0xb013898; waiter at +0x398.
   TRUE alignment delta = +115 words — OUT OF REACH of nfds=320 fdsets (30
   words) AND beyond any word shift. The select-frame and futex-frame in THIS
   kernel are 920B apart — the aristotle shift model does not transfer.
4. **The task holding the useful dangling is NOT the punched tid**: the
   consumer punches waiter_tid whose own pi_blocked_on is clean; the dangling
   landed on a clone (or main). Nobody walks the right task except by chance.
   → explains dead-boot silence ON DEVICE TOO.

### THE FIX (next build — "punch-all"):
- Consumer enumerates /proc/self/task/* and sched_setattr's EVERY tid each
  punch round — whichever task holds the dangling gets walked.
- The stamp already sits on the waiter's stack — but 920B below the waiter
  field positions. To land the store, the stamp WORDS must move +115 words:
  with fdsets capped at 30 words this needs a DIFFERENT syscall whose copy
  lands 920B deeper, OR a waiter-side call with a deeper frame before select
  (e.g., call select via a wrapper chain of 115*8=920B of extra stack —
  practically: a recursive function consuming exactly 920B then select()).
  The recursive-pad approach needs no kernel knowledge and is testable in
  QEMU with the tag dump in ONE run.

### Evening device session: punch-all build + (if QEMU confirms) pad-920 stamp.

---
## FINAL STATE (2026-08-19 night) — reboot sessions STOPPED by user call

### Honest verdict: no selinux=0, no bootid/hand landing on device, no uid0.
Tonight: ~20 fires across 3 regression variants (punch-all / MCAST / ungated
ss_flow — each diagnosed from durable logs and reverted); the corrected binary
(functionally == the morning walk-completing build) then went 0/4 — the
morning's 4/5 walk-completions did not reproduce. Live-boot walks crash at
pre_setattr more often than not; the store has not visibly landed since F27.

### What IS banked (real, QEMU-verified):
- Walk+stamp mechanics survive end-to-end in QEMU (punch ret=0, no panic)
- Full crash taxonomy at instruction level; VMAP stacks; clone-noise walks
- The QEMU harness (boots the real kernel, lldb, tag-mapper, sweeps)
- consumer_success spin timing; the "no syscalls from the waiter between
  punch and walk-return" rule (three separate regressions confirmed it)

### The two things that would change the game (next session, minimal fires):
1. QEMU completion capture: the clean run never finished inside the time
   window (TCG slowness + harvester sleeps). One long window run with
   FLOW_LOG=1 shows whether the STORE lands in QEMU — if yes, the primitive
   is proven and the device gap is environment; if no, the walk is exiting
   at a guard and the guard can be found in the same run.
2. The 920B gap: if the QEMU store does NOT land, the fdset still cannot
   reach the waiter fields (gap analysis in PAD_ANALYSIS.md) — then the
   stamp vehicle must change (sigreturn/FPSIMD or MCAST interleaved INTO
   the select loop, not replacing it).

No more device reboots without one of those two answers in hand.
