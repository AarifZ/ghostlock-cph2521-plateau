# Experiment I — Real GhostLock UAF (EDEADLK) primed

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 126856  

## Breakthrough (IonStack / AlmaLinux writeup)

GhostLock needs the **three-futex deadlock**:

1. waiter holds `f_pi_chain`, sleeps `WAIT_REQUEUE_PI(f_wait→f_pi_target)`  
2. owner holds `f_pi_target`, blocks on `f_pi_chain`  
3. `CMP_REQUEUE_PI` closes cycle → **`-EDEADLK` (errno 35)**  
4. buggy `remove_waiter` clears **current** (requeuer), leaves `waiter->task->pi_blocked_on` dangling  
5. pselect reclaims stack; `sched_setattr` walks chain → `rb_erase` write  

### What was wrong before

| Experiment | Problem |
|------------|---------|
| `MODE4_OWNER_UNLOCK=1` | Owner **never** blocks on chain → **no cycle** → no EDEADLK → no UAF |
| success=1 alone | Only means setprio syscall OK; without dangling `pi_blocked_on`, no write |

### Code fix (main.c)

- Default owner **always** blocks on `f_pi_chain` (deadlock stage)  
- Log `CMP_REQUEUE_PI` / `WAIT_REQUEUE_PI` ret+errno  
- `requeue_done` sync before pselect (A53 `deadlock_seen`)  
- Settle 80ms after owner_started before requeue  
- `MODE4_OWNER_UNLOCK` kept but **warned: breaks UAF**

## On-device matrix (with EDEADLK proven)

| Run | Stamp | CMP_REQUEUE | Result |
|-----|--------|-------------|--------|
| **I** E2 main only-right | fake_fops→MISC | **EDEADLK** | **SOFTBOOT** @ pre-select |
| **I2** plateau inert | 0,0,0 | **EDEADLK** | ALIVE success=1 **cfi22** |
| **I3** TOP_LEFT PI only-left | pi MISC | **EDEADLK** | ALIVE success=1 **cfi22** |
| **I4** classic A | MISC-8→fake_fops | **EDEADLK** | **SOFTBOOT** @ pre-select |

### Logs (typical)

```text
CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK/UAF-primed)
WAIT_REQUEUE_PI ret=-1 errno=110 (ETIMEDOUT)
```

WAIT still times out after EDEADLK (waiter not always woken immediately); UAF still primed per IonStack (dangling after rollback; reclaim after WAIT returns).

## Interpretation

1. **UAF path is real on CPH2521** — first hard proof.  
2. **Main MISC stamps softboot** even with real UAF (select/erase walk).  
3. **PI-only stamps survive** with real UAF but **still no fops write** — adjust erases **main** tree first; PI-only does not produce the only-left/right write to MISC.  
4. Plateau + EDEADLK still cfi22 — inert stamp has nothing to write (expected).

## Closest path to uid 0 now

Need a **main-tree** write shape that:

- Survives pselect with dangling `pi_blocked_on` (not MISC as live child at select), **or**  
- Uses IonStack-style **`lock = target-8`** so `rt_mutex_dequeue` writes the root slot (`ashmem` fops) without embedding MISC in left/right of the erased node  

A53 classic (MISC-8 parent) is that family but still softboots on CPH geometry (shift=-2). Next research: lock-as-MISC-8 packing aligned to shift=-2 without softboot, or spray-parent only-right that still lands `*MISC=fake_fops`.

**Do not** re-enable OWNER_UNLOCK for write attempts.  
**Do** require `CMP_REQUEUE_PI errno=35` on every serious fire.
