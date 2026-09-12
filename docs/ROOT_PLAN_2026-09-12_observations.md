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
