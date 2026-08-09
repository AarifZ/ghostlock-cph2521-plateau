# EXP O2 — CLASSIC + consumer + CFI_ON_PUNCH — SOFTBOOT

**Boot pre:** `abc84b01-…` (same as EXP_O survive) uptime ~123s  
**Env:** `MODE4_CLASSIC_MAPPED=1 MODE4_CFI_ON_PUNCH=1` (consumer on) delay=100ms  

## Result

| Check | Result |
|-------|--------|
| EDEADLK | 35 |
| Spray | ok |
| place | parent=MISC-8 right=fake_fops |
| Survive | **SOFTBOOT** (ADB gone; no consumer/CFI log) |

## Matrix

| Exp | Stamp | Consumer | Result |
|-----|-------|----------|--------|
| O | classic MISC-8 | **off** | **ALIVE** post-select |
| O2 / I4 | classic MISC-8 | **on** | **SOFTBOOT** |

**Conclusion confirmed:** select alone OK with classic; punch/erase path kills.  
CFI_ON_PUNCH did not log before death (softboot during/just after setprio before probe completes, or before punch log flush).

## Recovery

Manual replug if needed; adb server only.
