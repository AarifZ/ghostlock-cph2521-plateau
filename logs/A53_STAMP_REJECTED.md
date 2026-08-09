# MODE4_A53_STAMP — REJECTED (on-device)

**Date:** 2026-08-09  
**Device:** CPH2521 clean reboot, uptime ~27s  
**Binary:** ghostlock-cph2521 with A53 stamp env  

## What ran

```text
MODE4_ONLY=1 MODE4_A53_STAMP=1 KPHYS=0xa8000000 FOPS_MAX_ATTEMPTS=12
```

Samsung-style stamp (no waiter shift):

- `write_set[1]` / `out[1]` = MISC-8  
- `write_set[2]` / `out[2]` = fake_fops  
- `except[2]` = init_task  
- `except[3]` = fake_lock  
- W0 prio=100  

## Result

```text
stack mode4 A53_STAMP write[1]=MISC-8 write[2]=fake_fops ...
pselect pre-select +5ms
→ SOFTBOOT (ADB gone)
```

KS attempt=3 (late spray) — still dies at select entry with MISC on overlay.

## Verdict

**No progress.** Same class as GLM MAIN-GADGET: classic MISC-8 on the pselect stamp softboots on CPH2521 under our route.

**Do not merge to plateau.** Default remains:

`success=1 + cfi errno=22 + ALIVE` without A53 stamp.

Log: `logs/a53_stamp.txt`
