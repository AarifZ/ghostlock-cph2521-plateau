# EXP M — E2 + OPEN_ALL on clean boot — SOFTBOOT (final reject)

**Boot:** `d7201f77-…` uptime ~29s (clean adb reboot)  
**Env:** `MODE4_EXP_E2=1 MODE4_OPEN_ALL_FDS=1` delay=100ms  

| Check | Result |
|-------|--------|
| EDEADLK | errno=**35** |
| Stamp | parent=fake_fops right=MISC lock=fake_lock |
| Survive | **SOFTBOOT** after place, before post-select |
| USB thrash | **none** (server restart only; manual replug if needed) |

**Conclusion:** Main only-right with MISC as `right` softboots even on clean boot + OPEN_ALL.  
Do **not** re-fire E2 / classic A / dual MISC-main.
