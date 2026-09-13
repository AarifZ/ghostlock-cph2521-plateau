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
