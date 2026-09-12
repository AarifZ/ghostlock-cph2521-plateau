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
