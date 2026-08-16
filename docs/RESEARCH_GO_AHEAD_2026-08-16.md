# Research go-ahead results (2026-08-16 evening)

## pstore / last_kmsg

| Path | Access as shell uid 2000 |
|------|---------------------------|
| `/sys/fs/pstore` | **Permission denied** |
| `/proc/last_kmsg` | missing |
| `dmesg` | denied (`dmesg_restrict`) |

No fault PC without root / eng build. Live_sync remains the panic breadcrumb.

## Fires

| Tag | Config | Result | Last live_sync |
|-----|--------|--------|----------------|
| `gate_bootid_*` | only-left bootid (re-gate) | **SOFTBOOT** | `pre_setattr` |
| `misc_noconsumer_*` | only-left P0 MISC, **NO_CONSUMER** | **ALIVE** same boot | full route return, EXIT=1 |
| `misc_kimage_*` | only-left **kimage** MISC VA | **SOFTBOOT** | `pre_setattr` |

## Interpretation

1. **Overlay with `left=MISC` is OK in select** (NO_CONSUMER lives). Death is **not** “select can’t hold MISC bits.”
2. **Death is in consumer `sched_setattr` → `adjust_prio_chain` / `rb_erase`** when `left=MISC` (P0 or kimage).
3. **kimage vs P0 does not save us** — same softboot class.
4. **Bootid AAW is flaky under load/uptime** this run (softboot once). Prior 2× positive still stand; re-gate should be low-uptime only.

## Sharper model

```
idle overlay left=MISC     → ALIVE (NO_CONSUMER)
walk+erase left=MISC       → SOFTBOOT
walk+erase left=bootid     → usually ALIVE + store (2× proven earlier)
ION lock=MISC-8 no zero    → ALIVE, no erase, cfi22
```

So the problem is **erase/rebalance with a toxic `left` target**, not the UAF reclaim itself.

## Plateau

Still **no fops land / no cfi≠22 / no uid0**.  
Research: isolated crash phase to **setprio erase**, not select; ruled out kimage-only fix; pstore unavailable.

## Next (when ready)

1. Bootid re-gate only on **fresh boot uptime ≲60s**.
2. Shape that writes `*MISC` **without** `left=MISC` (root erase needs wait_lock=0 without toxic name zero).
3. Or RE with root/eng for ramoops.
