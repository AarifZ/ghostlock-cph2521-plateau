# EXP_F + consumer with select timeout ≥ delay — SOFTBOOT (rejected)

**Date:** 2026-08-09  
**Binary:** `ghostlock-cph2521` 124488 bytes  
**Change:** `PSELECT_TIMEOUT_SEC=1` + `USEC=500000` (1.5s overlay; was 200ms)

## Hypothesis

Prior F+consumer delay=500ms survived with `success=0` because select returned at ~203ms **before** the consumer punch. Raising select timeout should let sched_setattr fire during UAF overlay.

## Run: `expF_timeout1p5_delay100_r1`

| Field | Value |
|-------|--------|
| Env | `MODE4_ONLY=1 MODE4_EXP_F=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000 FOPS_MAX_ATTEMPTS=12` |
| BEFORE boot | `0598e8e8-a178-45eb-9726-680d4c3c1806` uptime≈38s (clean adb reboot) |
| AFTER boot | `0d8ca3e4-9ce2-4e1f-9c82-9a5eeec7cdc2` uptime≈32s (**new boot_id = kernel softboot**) |
| Last console | `pselect pre-select +1ms` then ADB drop |
| Last stage | `pselect_pre_select` (no `pselect_post_select`) |
| Stamp | main only-right inverted parent=fake_fops right=MISC prio=90 deadline=0x1000 |

## Conclusion

| Config | Consumer punch during overlay? | Result |
|--------|--------------------------------|--------|
| F + NO_CONSUMER | no | ALIVE, success=0 |
| F + delay=500, select=200ms | no (timeout first) | ALIVE, success=0 |
| F + delay=100, select=1.5s | **yes** | **SOFTBOOT** |

**EXP_F MISC-as-right + consumer punch is softboot-class.** Timeout fix worked (punch window real); the write path still panics when erase/adjust touches that stamp with live consumer.

Do **not** re-fire A/E2/F+consumer without a new theory (e.g. different parent/right identity, PI-only erase, or lock match for adjust without MISC child).

## Code kept

Longer select timeout remains useful for any future consumer-during-overlay experiments (delay must stay &lt; 1.5s). Plateau reconfirm required after this build change.
