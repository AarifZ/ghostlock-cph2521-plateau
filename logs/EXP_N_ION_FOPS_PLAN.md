# Experiment N — non-MISC write (ION_FOPS / EXP_N)

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 ≥128712  
**Why:** A/E2 softboot (MISC in tree); ION_ROOT survives but wait_lock at MISC−8 = ashmem **name** ≠ 0 → no erase (cfi22).

## Theory (Ghidra `rt_mutex_adjust_prio_chain`)

1. Erase needs `waiter->lock` wait_lock trylock (`*(u32*)lock == 0`).  
2. Root only-right: `*(lock+8) = right`.  
3. Classic only-right unlinked: always takes `parent->rb_right = child`.

### N1 — `MODE4_ION_FOPS=1` (first fire)

| Field | Value |
|-------|--------|
| lock | `ashmem_fops + 0x10` (`.read` slot, static **0**) |
| parent | 1 (null) |
| right | configfs_bin_write CFI JT |
| left | 0 |
| task | init_task P0 |

→ if erase: `*(ashmem_fops + 0x18) = write JT` (`.write` was 0).  
Risk: fops table **RO** → fault/softboot on store. Survives+cfi22 → no erase still.

### N2 — `MODE4_EXP_N=1` (if N1 softboots RO)

| Field | Value |
|-------|--------|
| lock | fake_lock |
| parent | `ashmem_fops + 0x10` |
| right | write JT |
| left | 0 |

Same store target via classic parent; no MISC in tree.

## Fire (MODE4_ONLY, EDEADLK required)

```text
MODE4_ONLY=1 MODE4_ION_FOPS=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000
```

Reject re-fire: A, E2, F+consumer, dual REF_LEFT, E2 OPEN_ALL.

## Success

- ALIVE + cfi errno **≠ 22** → write path alive (even if not full fake_fops redirect).  
- Softboot → document RO vs walk; try N2 or next theory.  
- cfi22 + ALIVE → erase still skipped (lock identity / pi_blocked_on).
