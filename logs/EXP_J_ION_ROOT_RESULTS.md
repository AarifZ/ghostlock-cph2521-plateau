# Experiment J — MODE4_ION_ROOT (IonStack lock=MISC-8 root write)

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 127432  
**Env:** `MODE4_ONLY=1 MODE4_ION_ROOT=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000`

## Stamp

| Field | Value |
|-------|--------|
| `waiter->lock` | **MISC−8** (`ashmem` fops − 8) so `waiters` root @ +8 = fops slot |
| main `parent_color` | 1 (null parent / black root) |
| main `right` | `fake_fops` |
| main `left` | 0 |
| task | init_task P0 |
| prio / deadline | 90 / 0x1000 (≠ task for adjust) |

Theory (IonStack + Image): only-right root erase → `*(lock+8) = right` → `*MISC = fake_fops`.

## Results

| Run | EDEADLK | Survived? | setprio | cfi |
|-----|---------|-----------|---------|-----|
| r1 delay=150 | **errno=35** | **ALIVE** | success=0 (race) | step=33 no probe |
| r2 delay=100 | **errno=35** | **ALIVE** | **success=1** | **errno=22** |

```text
CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK/UAF-primed)
consumer punch tid=… sched_ret=0 errno=0
cfi write ret=-1 errno=22
```

## Interpretation

1. **ION_ROOT does not softboot** (unlike E2 / classic A with MISC in tree fields).  
2. UAF still primed (same -35 as us + pubglite55).  
3. Write still **not** landing → most likely `raw_spin_trylock(MISC-8)` fails:  
   IonStack needs `*(u32 *)(target-8) == 0` (unlocked wait_lock).  
   At `ashmem_misc+0x08` lives **name** (kernel pointer) → low 32 bits ≠ 0 → chain exits before `rb_erase`.  
4. That matches “success=1 + cfi22”: setprio runs, adjust early-outs on lock.

## Next (if continuing)

- Pick a write target where **target−8** is a zeroed spinlock-shaped qword, **or**  
- Keep `lock=fake_lock` (wait_lock=0 in spray) and find a root/child shape that still hits MISC without softboot  
- Or owner-side setprio (pubglite poll-stamp analysis) once main stamp is safe  

Default remains plateau. `MODE4_ION_ROOT` env-only.
