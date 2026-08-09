# EXP O — CLASSIC_MAPPED + NO_CONSUMER — ALIVE

**Date:** 2026-08-09  
**Binary:** 128712  
**Boot:** `abc84b01-…` uptime ~33s clean hard reboot  
**Env:** `FOPS_MAX_ATTEMPTS=4 MODE4_ONLY=1 MODE4_CLASSIC_MAPPED=1 MODE4_NO_CONSUMER=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000`

## Result

| Check | Result |
|-------|--------|
| KS spray | ok attempt=1 (~13s) |
| EDEADLK | **35** |
| Stamp | main parent=**MISC-8** right=fake_fops left=0 lock=fake |
| Select | **ALIVE** post-select ret=0 (stage.txt) |
| boot_id | **same** after route |
| success | 0 (no consumer — expected) |

```text
CLASSIC_MAPPED(A) main parent=MISC-8 right=fake_fops
pselect place tree=ffffff802a91a8e0 lock=fake
stage: pselect_pre_select → post_select ret=0 → route_threads_returned
POST boot_id=abc84b01… uptime 58s (same boot)
```

## Interpretation

| Prior | Consumer? | Result |
|-------|-----------|--------|
| I4 classic + punch | yes | SOFTBOOT |
| **O classic + NO_CONSUMER** | **no** | **ALIVE** |

**MISC-8 parent is not toxic for select/open alone.** Softboot class for classic is **consumer punch / erase path**, not overlay packing.

Next: classic + consumer with **early CFI probe from consumer** after setprio (catch write before late softboot), or harden erase post-write walk.
