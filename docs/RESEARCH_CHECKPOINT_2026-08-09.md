# Research checkpoint — CPH2521 write path (2026-08-09)

**Branch:** `research/cph2521-zero-name-write-path-2026-08-09`  
**Does not change default plateau behavior** — plateau remains: inert stamp / delay, `success=1`, `cfi errno=22`, ALIVE.

## Best so far (facts)

| Item | Status |
|------|--------|
| UAF prime | `CMP_REQUEUE_PI` errno **35** (EDEADLK) reliable |
| Plateau | ALIVE, cfi **22**, no fops redirect, no uid0 |
| Classic parent=MISC−8 + erase | **softboot** (dies in `sched_setattr`, last PROOF=`pre_setattr`) |
| Classic + no erase (NO_CONSUMER / PRIO_MATCH) | **ALIVE** |
| **`MODE4_ZERO_NAME`** | **ALIVE** after setprio; `post_setattr ret=0`; cfi22 expected |
| ION_SAFE after zero | still softboot at `pre_setattr` |

## Source insight (Linux 5.10 `rtmutex.c`)

```
adjust_prio_chain: dequeue(rb_erase) → update prio → enqueue(walk tree)
```

- Root write of `fake_fops` into waiters root → re-enqueue walks fops as rb node → die  
- Classic parent=MISC−8 writes `*MISC` without replacing waiters root, but setprio still dies  
- ZERO_NAME uses parent=MISC−16 (name slot), survives  

## Key env flags (opt-in only)

| Flag | Purpose |
|------|---------|
| `MODE4_ZERO_NAME=1` | Survive erase; `*name=0` for ION wait_lock |
| `MODE4_ION_SAFE=1` | Root `*MISC=fake_fops` + rb-leaf fops head |
| `MODE4_LOCK_OWNER0=1` | owner=0, avoid setprio(fake_task) |
| `MODE4_PROOF=1` / `MODE4_CFI_ON_PUNCH=1` | Durable stage PROOF markers |
| Default (no flags) | **Unchanged plateau** |

## Binary

`ghostlock-cph2521` (~132k) includes zeroed fake_fops table + research env paths.

## Recovery

`post_softboot_hardboot.ps1` — `adb reboot` only, requires new `boot_id`. No USB thrash.
