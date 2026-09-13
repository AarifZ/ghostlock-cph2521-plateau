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
