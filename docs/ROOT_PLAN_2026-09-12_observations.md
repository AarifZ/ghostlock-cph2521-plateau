# FLIP session observations (final)

FLIP 1/2 (child_piped + UID0_EZP=1 + 0x780): W1 survived both,
self-leak worked both (8 and 256 votes), punch fired at child+0x780
both, flow EXIT=0 both, stores reported MISS both. BUT critical
instrumentation gap: no "uid query attempt=N" lines printed in either
fire, and child_uid.txt beacon stayed EMPTY both times. The
landing-check may not be running (cred_mode false? loop break before
the check?), and the beacon may be victim of the active /data rollback.

OPEN QUESTIONS FOR NEXT SESSION (in priority order):
1. Why do the uid-query lines never print in child_piped fires?
   - grep do_pselect_fake_lock_route for the cred_mode branch —
     trace why "attempt=N -> 2000" lines are absent. If the check
     isn't running, a landed store would be INVISIBLE (the CHILDSELF
     fire's empty beacon may have been a silent WIN).
2. Beacon reliability: child writes uid every spin iteration — empty
   file means open failed or /data rollback emptied it. Test by
   checking the beacon immediately after flow EXIT (before reboot
   window) in the same shell command.
3. Compare landing with vs without UID0_EZP: the Z33 win (08-24) had
   NO ezp (bss_tail lock). The ezp lock (empty_zero_page) may change
   walk dynamics. Fire one roll without ezp + with fixed query
   instrumentation.

## SIGPIPE ROOT CAUSE FOUND + FIXED (the "vanishing execution")

QUERY-BRACKET proved it: the process died INSIDE uid0_child_getuid_query
— the write('C') to the dead child's pipe = SIGPIPE = instant process
death. The child dies AT the punch (zero-page corruption from ezp kills
it, or the cred swap cripples it) — which means **the punch was very
likely LANDING all along** and the SIGPIPE suicide destroyed the proof.

FIXES (all committed):
1. signal(SIGPIPE, SIG_IGN) in the query — EPIPE, not death
2. uid0_child_status_uid(): /proc/<pid>/status Uid read — the PROVEN
   real_cred landing signal, works even when the child is dead (9991 =
   dead child = treated as LANDED)
3. status check prints "child /proc status Uid=N" per attempt

LAST ROLL (SPRAYFLIP): trigger coin lost (sched_setattr success=0 —
consumer failed; clean exit, no query ran). Not a regression.

CURRENT FIRE COIN STRUCTURE (all survivable, all observable):
W1 flip (~50%) × trigger flip (sched_setattr ~90%) × landing flip (?% —
may be near 100% given the SIGPIPE evidence) — roll the SPRAYFLIP config
until all three align; the status-Uid line will say 0 or 9991 on a win,
then G+payload fires → ROOTED.

## FLIP GRIND LOG (context-exhausted mid-grind)

- HONEST 2: 3 honest attempts, 3 misses (child alive, status Uid 2000) —
  landing rate is the old lottery, NOT near-100% (the SIGPIPE deaths were
  the zero-page ezp killing the child, not proof of landing)
- FL3: W1 walk crash (coin lost)
- FL4: fired; device dropped post-fire (Shizuku dead after reboot) —
  RESULT UNREAD, on /data/local/tmp/hkc.txt when device returns
GRIND STATE: 2 honest misses + 2 unknowns. Next session: read FL4,
keep rolling the SPRAYLOCK config. Each roll ~8min (fire+reboot+settle).

## FLIP GRIND COMPLETE LOG (both configs)

SPRAY_LOCK config (init_task+0x878 lock): FL5 = 3 honest misses, DEVICE
SURVIVED whole fire (disarm working — same-boot re-roll proven possible).
Z33-geometry config (bss_tail default overlay): FL7 = W1 crash.
Full tally: FL3 W1✗, FL4 punch-walk✗, FL5 3-miss SURVIVE, FL6 W1✗,
FL7 W1✗. Landing: 0/12 honest attempts (both configs). W1 running cold
(1/5 this stretch vs ~50% historical).

NOTE: Z33's single historical win used bss_tail + 08-24-era binary.
0/12 honest now — either genuinely cold dice (P≈0.25^12≈tiny... more
likely landing rate <25% per attempt in current binary) or the current
SLIDE_CRED stamp differs subtly from the 08-24 one that won. NEXT
SESSION diff the Z33-era stamp (git log src/core/fops.c Aug 24) vs
current — the winning geometry is in git history.

## 09-13 SESSION: PRIO-WORD REGRESSION FOUND + FIXED (the history diff paid off)

Git diff 37b9bea (Z33 win, 08-24 01:14) vs current found the ONE effective
stamp difference: the Z33-era words writer HARDCODED word8 (waiter prio) = 0.
93473c5 (08-29 17:29) changed it to emit stack_prio(=3) — every walk since
ran prio=3; ALL Z-era walks (Z25-Z33, incl. the win) ran prio=0. Confirmed
on-device: park2.txt 09-12 shows "pselect place ... prio=0000000000000003".
FIX: stack_prio 3→0 in SLIDE_CRED + both SLIDE_ZERO branches (committed).

BUILD DEFINES RECOVERED (were lost): the committed binary was built with
  -DGHOSTLOCK_KERNEL_5_10 -DKIMAGE_TEXT_BASE=0xffffffc008000000
(target.h defaults are wrong alone → 214896-byte binary missing whole 5.10
stamp paths; correct build = 232168 bytes, string parity verified).
Full build line is in Makefile comments now.

FIRES TODAY:
- PARKW1 (prio=3, park-first): park walk KP (boot died after consumer punch).
- prio0 park-first (hk49290): prio=0 CONFIRMED on device ("prio=...0000") —
  park walk STILL KP'd (died after "consumer punch tid sched_ret=0"). Park
  walk now ~6 straight KP regardless of prio.
- Z33_logcat.txt re-read: the winning run ran UNDER PERMISSIVE (avc
  permissive=1 from gl_uid0 doing syslog_read at 01:48:29, alive past
  01:49:47; child pid 22522). Console log of the winning walk is lost.
- DIRECT punch fired (hq49860): UID0_DIRECT=1 + INITTASK=1 + prio=0, first
  walk = cred punch (no park). RESULT UNREAD — device rebooted during/after
  the fire, adbd tcpip did not survive reboot (WiFi up, 5555 refused).
  Read /data/local/tmp/hq49860.txt when USB bootstrap restores adb.

NEXT: user plugs USB briefly → adb tcpip 5555 → read hq49860.txt. If
LANDED/ROOTED → done. If punch-walk KP → direct walks are cold too, rethink
ghost state (park-first may be load-bearing for punch geometry). If honest
miss → prio was not the (only) gap; next diff = fdset rebuild/attempt
machinery vs Z33 era.

## 09-13 UPTIME CORRELATION (stop firing on fresh boots)

All KPs today were on boots < ~10 min old. The ONE surviving walk+store
attempt (lived, missed, DISARMed, exited) was on a 5h-settled boot.
FL5 yesterday (3 misses, device survived whole fire) was also settled.
Theory: fresh boot = heavy futex/PI traffic from init/services pollutes
the ghost's stale tree -> erase rebalances through foreign nodes -> KP.
Settled boot = quiet PI state -> clean walk. Flip loop was firing at
uptime 140s (self-feeding KP loop) — RAISED to 600s minimum settle.

## 09-13 *** FIRST CHILD CRED LANDING OF THE EZP FLOW *** (hu76494)

Park-first + ONE-SHOT EZP + child_piped + UID0_SLOT=0x778 + prio=0:
- Park W1 LIVED (enforce=0 written — first park survival today, 2/8)
- ONE-SHOT EZP override: lock=ezp+0x100 task=ezp+0x800 tree=child+0x778
- **CRED LANDED attempt=1/1**: child Uid=[0 0 4294967176 0]
  CapEff=000001ffffffffff (FULL CAPS) — suid field holds pointer bits
  (the change_child second store into init_cred+8 region, Z33 signature)
- UID0 WIN stage reached; G written to uid0_go + piped to child
- **BLOCKER: child unresponsive (query 9999) — dead/zombie from zero-page
  poison seconds after landing; status Uid=0 persists as corpse. The ezp
  lock's wait_lock manipulation writes poison the zero page EVEN ON A
  HIT.** Box rebooted ~2min after (known ezp cost).
- Slot matrix today: 0x778 ezp = LANDS (child dies of poison);
  0x780 ezp = clean miss (ht75756, child responsive 2000);
  0x780 direct-bss = 3 clean misses; Z33 0x780 bss-after-park = the only
  LIVING uid-0 child ever (beacon wrote uid 0 for ~2min, no zero-page).
CONCLUSION: the payload needs a LIVE uid-0 child → the bss punch after a
living park (Z33 replay) is the winning configuration. Park coin ~25-40%
per fire; re-roll until it lives, then the punch is walk-2 Z33 geometry.

## 09-13 EVENING — QUIET CHILD SOLVED THE WEDGE; DIRECT DOUBLE-PUNCH ERA

1. UID0_QUIET_CHILD: child spins getuid+usleep ONLY (cred-inert) after
   perf self-leak (fd closed). RESULT: 0x778 landing SURVIVED by the
   child — it auto-payloaded (status-0 auto-G), wrote ROOTED
   ("uid=2000 euid=2000 status=0") and ran the full `id` as uid 2000.
   THE MID-SYSCALL WEDGE IS SOLVED. Beacon/pwrite(O_SYNC)/poll were the
   killers; Z33's child had none.
2. DIRECT walk-1 0x778 LANDS (fl82382) — NO PARK NEEDED for the store.
3. UID0_DOUBLE_PUNCH: stage1 0x778 (alive-checked) then stage2 0x780 on
   the same child (stage2 IS walk-2 = Z33's winning walk position).
   Roll1: stage1 landed, child payload ran, stage2 walk KP'd the boot
   after (F13 double-walk pattern persists despite DISARM1).
4. ROOTED-file semantics fixed: status-only wins write ROOTED with
   uid=2000 — the loop now clears proof files per fire and stops only
   on ROOTED_ID (subjective root). 
5. Remaining gap: 0x780 subjective store 0/17 lifetime vs 0x778 4/4.
   Every double-punch roll = stage1 (~certain) + stage2 (KP risk, then
   the 0x780 coin). If stage-2 keeps KP'ing: add inter-stage settle or
   route the second punch through a fresh process targeting the same
   child (needs leak-by-pid).

## 09-13 NIGHT — THE 0x780 VERDICT + DUALWRITE ENDGAME

**CANARY DISCRIMINATOR (fl89650):** stage-2 walk aimed at comm (+0x790)
with rotated lock: comm_landed=1, child alive, no reboot. With 0x778 at
5/5 and 0x790 landing in both walk-1 and walk-2 positions: **task->cred
(0x780) is SPECIFICALLY vendor-protected — direct stores never land
(0/20 all-time; Z33's historical "win" was itself a real_cred/status
landing, per the in-code Z33 comment).**

**DUALWRITE GEOMETRY (the way around it):** the erase does TWO stores.
Store-1: *tree_l = pc. Store-2 (__rb_change_child): writes tree_l into
*(pc+8) — ALWAYS lands (the historical suid pointer-bits WERE store-2).
Invert the stamp: tree_pc = task+0x778|red, tree_l = init_cred:
- store-1: *init_cred = task+0x778  (usage→huge=never freed; uid garbage
  — CAPS SURVIVE FULL)
- store-2: *(task+0x778+8) = init_cred  → **task->cred = init_cred via
  the unblocked path**
Then the pur-spin child wakes, setuid(0) (CAP_SETUID from the full cap
set) mints a CLEAN root cred, payload runs → ROOTED_ID + KSU.
Confirmed live on device (i390054 stamp print: pc=slot|1, l=init_cred).
Flow hardened: flag-flip grace (3s) + uid0_payload_fired() in WIN so
the miss-path doesn't kill the child mid-setuid.

Remaining coin: the post-store waiter wedge (~50%/fire, intrinsic — the
overlay corrupts select's own stack state; 2.5s bound + DISARM contain
it). Loop is grinding DUALWRITE; stop condition ROOTED_ID.

## 09-13 CLOSE-OF-DAY HANDOFF (the definitive state)

### WHAT IS PROVEN (device-verified today)
1. **0x780 (task->cred) is a FORTRESS**: direct stores 0/20 all eras; the
   DUALWRITE geometry (pc=slot|red, l=init_cred) executed BOTH erase stores —
   status=0xFFFFFF88 proved store-1 corrupted init_cred.uid through
   real_cred=init_cred — yet child_wake.txt showed `setuid=-1 errno=1` with
   getuid=2000: the cred POINTER is actively restored by the vendor kernel.
   Z33's historical "win" was a real_cred landing all along.
2. **0x778 (real_cred) + 0x790 (comm) stores land reliably** in every
   geometry (5/5, both walk-1 and walk-2, ezp/bss/direct).
3. **Quiet child (UID0_QUIET_CHILD/UID0_PUR_SPIN)** survives landings: zero
   syscalls during punch (shared-page flag; getuid+nanosleep fallback). The
   mid-syscall wedge that killed every landed child is SOLVED.
4. **ORACLE-CAPS pipeline works end-to-end** (a408971): walk-1 SLIDE-oracle
   (MODE4_ORACLE_TGT=child_task+0x778 via boot_id redirect) survived,
   readback executed, parse ran, plausibility gate correctly refused walk-2
   when the store missed. Overlay now uses bss_tail+prio0 (proven class).
   NOTE: the stamp's print text still says "lock=init_task+0x878" — stale
   message only; the placed word is bss_tail (see "pselect place" line).

### THE ENDGAME DESIGN (UID0_ORACLE_CAPS=1, built and firing)
- walk-1: boot_id ctl_table.data := child_task+0x778 → read
  /proc/sys/kernel/random/boot_id → 16 bytes = [real_cred, cred].
- parse + plausibility (P0-range, 8-aligned, ≠task) — gate works.
- walk-2: PLAIN store: *(&child->cred->cap_effective at subj_cred+0x30) =
  init_cred pointer VALUE — the pointer bits are a giant capability mask
  (CAP_SETUID bit7, CAP_SYS_ADMIN bit21, CAP_MAC_ADMIN…). The cred pointer
  is untouched => nothing for the reverter to undo.
- flag flip → child wakes → setuid(0) succeeds (CAP_SETUID) → clean root
  cred → payload → ROOTED_ID + ksud late-load (KernelSU).
- Remaining coins only: walk survive (~50%) × store land (~50%) ×2 walks.
  3 oracle fires so far: 1 walk-survived (store missed), 2 walk-died.
  THE LOOP (fastflip.sh, oracle config) grinds this — stop condition
  ROOTED_ID.

### OPERATIONAL LESSONS (all fixed in-tree)
- pkill -f gl_uid0_child SIGTERMs its own shell (cmdline match) → pkill -x.
- live_sync O_SYNC FUSE writes stalled flows for minutes → UID0_NO_SYNCLOG.
- route_done join hang → 2.5s bound + detach all threads (wedge ~50% is
  intrinsic: the overlay corrupts select's own stack).
- /data rollback eats logs within ~75s → logs to /sdcard/Download/.
- Two concurrent loops double-fire (ghost residue) → /tmp/fastflip.lock.
- Hard-freeze (glowing screen): recover with power+volup+voldown held ~1-2min.
- Stale-beacon false "misses": 0x780 landings are invisible to status; only
  the child getuid/beacon or payload files are honest signals.

### NEXT SESSION (in order)
1. Check /data/local/tmp/ROOTED_ID + /sdcard/Download/a5*.txt / r*.txt tails
   (the loop may have landed while unattended).
2. If not: re-run ./fastflip.sh (oracle config already set) and let it grind;
   each roll ~2-4min. Watch "ORACLE-CAPS parsed:" lines — a plausible
   subj_cred (0xffffff80xxxxxxxx) followed by "child_capstore" and
   child_wake.txt "setuid=0" = WIN.
3. If walk-1 stores keep missing (bootid readback stays the stale
   e0a8-8d2a80ffffff pattern): try prio/word variants on the SLIDE stamp,
   or aim the oracle at a heap address the cred-class stamp has already
   successfully written (task+0x778 itself) to isolate stamp-vs-target.
4. Alternative if cap_effective offset differs: dump 0x30/0x38 both via two
   oracle reads at subj_cred+0x20..0x40 first (the oracle can read ANY
   kernel address now — use it to verify offsets before storing).

## 09-13 STRATEGY RESET (user directive) — single-fire discipline, ashmem path

BANS IN EFFECT: no automated loops, 1 fire per run, no re-fire after a KP
without a geometry fix, oracle-caps/dualwrite chains abandoned, no direct
task->cred / cred+N stores.

### WALK-1 PANIC ANALYSIS (deterministic, from kallsyms_fresh.txt)
The PI walk writes the fake lock's rt_mutex fields: wait_lock spinlock
(+0x0), waiters root (+0x8), leftmost (+0x10), owner (+0x18).
- fake_lock = init_task+0x878 (park/oracle overlay): those writes land in
  LIVE init_task fields => deterministic corruption => the park/oracle KP
  cluster. DO NOT USE THIS LOCK.
- fake_lock = bss_tail 0x02BB9D00: PAST __bss_stop (0xabb9bcc) — dead
  linker padding to init_pg_dir => writes mostly harmless => cred walks
  survived more. Still not guaranteed-zero; superseded by the sprayed page.
- fake_lock = SPRAYED page +0xE80 (SLIDE_SWAP geometry): our own zeroed
  page; LOCK_EMPTY mode zeroes +0/+8/+10/+18; fake_task at +0x1280 zeroed
  (dead-end); table at +0x0..0x100. NO overlaps. This is the safe class
  (08-30 SPRAY_LOCK canary: landed + survived 1425s).
FIX APPLIED: SLIDE_SWAP stamp stack_prio 3 -> 0 (all-day evidence: prio-0
walks survived, prio-3 KP'd). Clone precedence: explicit MODE4_CLONE_FOPS
now yields the pure replica (no armed .write).

### THE SINGLE TEST FIRE (built, NOT fired — awaiting user confirmation)
env: MODE4_ONLY=1 MODE4_SLIDE_SWAP=1 MODE4_CLONE_FOPS=1 MODE4_LOCK_EMPTY=1
     UID0_NO_SYNCLOG=1 KPHYS=0xa8000000 CORE_SEL=7
action: one walk -> *(&ashmem_misc.fops) = fake_fops where fake_fops is a
     bit-exact replica of the real ashmem_fops (real .cfi_jt stubs from
     offsets.h: open 0x01831488, ioctl 0x01837928, compat 0x01837930,
     splice_read 0x01822B58, llseek/read_iter etc.).
semantics: NO-OP swap — if the box stays healthy and ashmem traffic works,
     this PROVES (a) walk-1 stability on the sprayed geometry, (b) the
     fops pointer swap lands, (c) CFI accepts our table through .cfi_jt.
next (separate approved fire only): CLONE_CFG table (clone + .write =
     configfs_write JT) -> kernel_write_data -> splice/physrw or UMH.

## 09-13 LATE — MECHANISM WIN + ESCALATION RESEARCH STATE

### FIRE 6 = THE WIN (t616616, commit b6b75e0)
pi-only clean swap: WALK STABLE, SWAP HELD (aligned ptr), probe-open
survived, pwrite REACHED configfs_write through OUR table's .write JT
(errno=22 = configfs' own foreign-fd rejection = CFI ACCEPTED the call).
Kernel R/W mechanism is live: *target = <controlled table ptr> + full
fops table control with JT-only slots.

### TODAY'S CRASH-ROOT-CAUSE LEDGER (all fixed, all deterministic)
1. park/oracle lock init_task+0x878 -> spinlock writes in live task fields
2. prio=3 walks -> prio=0
3. black-parent rebalance -> red / all-zero main tree
4. color bit |1 leaking into stored pointer -> pi-tree clean store
5. FDSET WRITER BUG: words 3/4/5 hardcoded pi words to 0 — pi stamps
   never reached the waiter (fire-5 zeroed misc.fops via NULL-parent
   pi erase). THIS likely also invalidated every pi-erase-based fire
   ever run (old "settle breaks writes" findings suspect).

### ESCALATION RESEARCH (offline, Image extracted: kernel_Image.bin)
- Image: PE/COFF arm64, .text VMA==file offset (base+0x10000 section);
  disasm: NDK llvm-objdump.
- __arm64_sys_getuid @0x1641c0: PLAIN task->cred(0x780)->uid read, NO
  validation. Fallback global = overflowuid @0x27dfee0 (standard).
- No vendor cred-guard/validate symbols in kallsyms; commit_creds tail
  = standard put_cred. "Fortress" may partly be an artifact of the
  pi-words bug (pi erases never executed in those fires).
- CFI JT section at ~0x1820000+: JTs exist only for address-taken
  functions; deltas non-uniform (getuid 0x16c10a0, getuid16 0x1583cc4)
  -> build the JT map by pairing sorted *.cfi_jt symbols with their
  functions from kallsyms (both orders match).

### NEXT (research, then single approved fires)
1. JT-map tool (kallsyms-paired) -> gadget menu for
   .write(file,buf,count,pos) / .llseek(file,offset,whence) arg shapes.
2. RE-TEST the 0x778+0x780 punch under the FIXED fdset writer — the
   historical 0/20 may be pi-words-tainted; a verified child getuid
   (not stale beacons) is the honest detector.
3. Groomed x0 gadget hunt for commit_creds-shaped calls.

## 09-13 FINAL STATE (context-exhausted — precise resume point)

### THE PI CHANNEL NOW WORKS END-TO-END (first time ever)
Root cause chain found and fixed live tonight: (1) fdset words 3/4/5
hardcoded pi=0; (2) my CRED_PI branch was anchored into the RESURGE
stage-2 block = DEAD CODE (never ran). After moving it into the live
stage-0 chain, the debug fire r219140 showed the full chain:
  stack CRED_PI: pi *slot = cred_copy
  LAYOUT=COMPACT emit pi_parent=<cc> pi_left=<slot>
  pselect place tree=0 pi=<cc> prio=0
ALL historical pi-erase conclusions are INVALID (both bugs predate).

### CRED_PI RESULT MATRIX (both fired, both analyzed)
- LEFT-child pi (pi_left=slot): WALK CLEAN (no crash, full flow) but
  child_wake getuid=2000 — store did not take. NOTE that fire ran with
  prio=1 (branch forgot stack_prio=0).
- RIGHT-child pi (pi_right=slot, prio=0, NULL-sibling design): the
  WALK ITSELF crashed (r319322, pre-select, reboot).
=> next analysis: why right-child pi erase crashes while left survives
   (successor-path/augment difference?), and whether the left-form miss
   was the prio=1 or the pi-dequeue never executing store-1. Consider:
   instrument LEFT form at prio=0 FIRST (one fire, walk-proven class).

### Resume checklist
1. Left-pi + prio=0 single fire (the untested combination).
2. If still no store: the pi dequeue path may not run store-1 for our
   ghost at all — audit rt_mutex_dequeue/dequeue_pi call order in the
   Image (which erase runs for a stale-hb-tree waiter).
3. JT map + gadget route remains the fallback (misc.fops swap chain is
   mechanically proven through fdset+walk; only the VALUE slot was
   never honestly verified — see fire-6 caveat).

## 09-13 L0 MEASUREMENT (m120688): NULL RESULT
Left-pi + prio=0: the flow STALLED pre-walk (log stops at 49 lines after
the cred_copy spray print; killed by the 90s timeout; device healthy
throughout — no KP, no reboot, no wake). No walk ran => no data for this
matrix cell. A retry would likely reach the walk (transient stall, probably
perf/leak phase on this boot). MATRIX STANDS:
- left-pi  @ prio=1: clean walk, NO store (child_wake getuid=2000)
- right-pi @ prio=0: walk crash
- left-pi  @ prio=0: no data (stall)
Per agreement: no more fires without external input. Repo clean at 63e7358.

## 09-14 (early): JoinChang repo read + JC2 build (commit 1c2120c)

**Upstream (github.com/JoinChang/ghostlock-oneplus) findings — the "word"
suggestion the user flagged:**
- CPH2521 in their device table = "Offsets Extracted (pending device test)"
  — they never fired on our device either; we are the testers.
- 5.10 OPLUS: waiter word=0, SHIFT=0 (their table) — matches our verified
  compact map. (Our device-measured shift=-2 placement = words 2-9 land at
  global 0-7; their words_compact stamps exactly words 2-9, consistent.)
- **Their mode-2 (cred write) NEVER puts write geometry on the ghost stack
  stamp.** words_compact = {2:0, 3:0, 4:0, 5:0, 6:fake_task, 7:fake_lock,
  8:0, 9:0} — pure carrier. Words 0/1 keep the original sole-waiter 0/0.
- Write geometry on the SPRAYED W0 heap waiter: W0.pi = {pc=target-8,
  right=REAL init_cred (data_addr), left=0}; W0.tree = {1,0,0} inert root
  of fake_lock->waiters; fake_task->pi_waiters = NULL for mode!=4.
- Trigger decoded: unlock's mark_wakeup_next_waiter takes W0 as top waiter
  (leftmost forced) -> rt_mutex_dequeue_pi(current, W0) -> rb_erase(W0.pi)
  Case 1a: store-1 *(init_cred+0)=pc (usage = huge refcount — harmless,
  their comment confirms), store-2 __rb_change_child at parent+8:
  ***(child_task+0x780) = init_cred**. No rebalance (child-present case).
- Their W2 targets a fork()'d child blocked in read(); child verifies with
  plain getuid() — NO setuid() dependency. Task leak via perf register
  sampling (SP_EL0=current on arm64) — we keep our proven x28/child_self
  leak instead (perf EACCES from shell on CPH).

**Why our fork could never fire mode 2 before:** pselect_custom_write==2
fell into a LEGACY-word-map stamp fallback (task@8/lock@9) — wrong layout
for our compact waiter (task@6/lock@7). Fixed: MODE4_JC2 benign-carrier
compact branch (fops.c) + UID0_JC2 punch driver (main.c).

**Differs from all 22+ failed +0x780 attempts:**
- store-2 (__rb_change_child parent+8) instead of store-1 (child pc store)
- geometry on our sprayed heap page, not the ghost stack (augmented-callback
  inputs fully controlled — addresses the 3-model concern)
- value = REAL init_cred (usage corruption tolerable), not the Image copy
- child getuid detector, no setuid-before-read race

**Build:** ghostlock-cph2521-jc2 (240696 B, md5 06b0e72d6d07ba465b02207520b10efc)
pushed to /data/local/tmp/gl_jc2. Device healthy (up ~1h51m at push).
**Awaiting user fire approval** — single fire, env:
UID0_DIRECT=1 UID0_JC2=1 UID0_QUIET_CHILD=1 UID0_PUR_SPIN=1
UID0_NO_SYNCLOG=1 KPHYS=0xa8000000 CORE_SEL=7

## 09-14: JC2 fire-2 (fl010034) — store-2 form DISPROVEN on this kernel (5/5 KP)

Both fire-1 fixes confirmed working in the log: `shift=-2` printed, mode-2 armed
before spray (no mode4 inert line), spray geometry correct
(`JC2 spray base=... w0=...`, punch pc=child+0x778 right=init_cred).
Device REBOOTED at the walk (~60-90s in), bootreason "reboot".

The `pselect LOCK/TASK MISPLACE` warnings are FALSE ALARMS: the audit
(fops.c ~2195) reads out[1]/out[2] = the LEGACY word map (task@w8/lock@w9);
compact stamps (task@w6/lock@w7, all recent fires) legitimately read prio/
deadline = 0 there. Placement matches the proven CRED_PI-L0 layout.

**Verdict — connection to chains V-Y (08-31):** our own code comment
("GLM 08-31 only-right (parent=slot-8, right=init_cred) KPd 4/4 — one-child
erase rebalances through task_struct") is the SAME geometry JoinChang mode-2
uses. Fire-2 ran it via the heap-W0 carrier instead of the ghost-pi words:
same KP. **The store-2/__rb_change_child form at task_struct targets
deterministically panics this kernel — 5/5 across two carriers.** This is
why JoinChang's table marks CPH2521 "pending device test": the mode-2 form
does not transfer to this 5.10 vendor build. Upstream mode-2 is closed.

**Matrix after fire-2 (pi-erase write family, ghost carrier):**
- left-pi (store-1, child=target) @ prio=1: clean walk, no store
- right-pi (store-2, parent=target-8) @ prio=0: WALK CRASH (V-Y + fire-2: KP 5/5)
- left-pi @ prio=0: STALLED pre-walk — never got a clean result (open cell)
- store-1 with parent-on-our-page (fire-6 shape): SURVIVES + LANDS (misc.fops,
  real_cred+0x778 ~100%) — the only proven write family on this device

Remaining viable endgames:
1. CRED_PI-L0 retry (left-pi prio=0) with the pre-walk stall diagnosed
   (fire-1's WRITE_PROOF-poisoning could also explain the old stall — the
   old CRED_PI binary predates the stale-env/ordering fixes)
2. ORACLE_CAPS (never touches +0x780: mutate ORIGINAL cred capability words)
