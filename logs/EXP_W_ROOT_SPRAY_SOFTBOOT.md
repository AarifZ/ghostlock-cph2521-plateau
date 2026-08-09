# EXP W — ROOT_SPRAY — SOFTBOOT (still plateau)

**Honest status:** we have **not** crossed the plateau (no `cfi write` success, no uid0).

## Fire

`MODE4_ROOT_SPRAY=1 MODE4_LOCK_OWNER0=1` — root only-right into **fake_lock.waiters**, not MISC.

```text
EDEADLK=35
pre-select logged
SOFTBOOT during select/punch
```

## Why (5.10 source)

```c
rt_mutex_dequeue → rb_erase: *lock->waiters = right  // right=fake_fops
rt_mutex_enqueue: walks *lock->waiters as rb tree
```

`fake_fops` is a **file_operations table**, not a valid waiter rb node → enqueue walks JTs as left/right → softboot.

Same failure mode would hit **ION_ROOT** if wait_lock ever succeeded: `lock=MISC-8` ⇒ waiters root is MISC ⇒ `*MISC=fake_fops` then enqueue walks fake_fops.

## Plateau scorecard

| Achievement | Status |
|-------------|--------|
| EDEADLK UAF prime | yes |
| Survive select (inert / PRIO_MATCH) | yes |
| setprio success=1 | yes (when no lethal stamp) |
| **fops redirect (cfi ≠ 22)** | **NO — still plateau** |
| uid 0 | **NO** |

Progress is **diagnosis**, not privilege.

## Recovery

CLEAN `b0ffc570-…` after hardboot.
