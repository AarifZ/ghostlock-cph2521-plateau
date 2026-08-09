# Linux 5.10 `rtmutex.c` — write path vs CPH softboot (2026-08-09)

Source: `torvalds/linux` tag **v5.10** `kernel/locking/rtmutex.c`.

## Consumer path (what we fire)

`sched_setattr` → `rt_mutex_setprio` → `rt_mutex_adjust_pi` → **`rt_mutex_adjust_prio_chain`**.

```c
// rt_mutex_adjust_pi (setscheduler path)
waiter = task->pi_blocked_on;
if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task)))
  return;  // EXP_P PRIO_MATCH exits here — ALIVE
next_lock = waiter->lock;
rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
                           next_lock, NULL, task);
```

## Chain walk step that writes (requeue)

```c
// [7] inside adjust_prio_chain when requeue==true
prerequeue_top_waiter = rt_mutex_top_waiter(lock);
rt_mutex_dequeue(lock, waiter);   // === rb_erase(waiter, &lock->waiters) ===
waiter->prio = task->prio;
waiter->deadline = task->dl.deadline;
rt_mutex_enqueue(lock, waiter);   // re-link clean node
```

`rt_mutex_dequeue`:
```c
if (RB_EMPTY_NODE(&waiter->tree_entry)) return;
rb_erase_cached(&waiter->tree_entry, &lock->waiters);
RB_CLEAR_NODE(&waiter->tree_entry);
```

**Write primitive** = `rb_erase` only-right/leaf change_child on forged `tree_entry`.

## Post-dequeue softboot sources (source logic)

After enqueue, if **owner == NULL**:
```c
if (!rt_mutex_owner(lock)) {
  if (prerequeue_top_waiter != rt_mutex_top_waiter(lock))
    wake_up_process(rt_mutex_top_waiter(lock)->task);  // task field!
  return;
}
```

We stamp **`task = init_task`**. If stack becomes **top** after enqueue → **`wake_up_process(init_task)`** → softboot.

If **owner = fake_task|1** and stack becomes top:
```c
rt_mutex_dequeue_pi(owner, prerequeue);
rt_mutex_enqueue_pi(owner, waiter);
rt_mutex_adjust_prio(owner);  // setprio(fake_task spray) → softboot
```

### EXP_V attempted fix (still softboot)

| Knob | Intent |
|------|--------|
| `MODE4_LOCK_OWNER0` | `owner=0` → skip setprio(fake_task) |
| stack `prio=200`, W0 `prio=100` | stack never top → no wake(init) |
| still classic parent=MISC-8 right=fake_fops | write should run |

**Result: still SOFTBOOT** → death is almost certainly **inside `rb_erase` / MISC parent access**, not post-wake/setprio.

## Why PRIO_MATCH / NO_CONSUMER live

- No `rt_mutex_dequeue` → no MISC parent walk/store.
- Matches device matrix (O, P ALIVE; R/S/T/U/V softboot).

## remove_waiter (better API, hard to hit)

```c
// dequeue only — NO re-enqueue of same waiter
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;
// optional PI deboost on owner
```

Called with **`lock->wait_lock` held** from unlock/proxy fail. Overlay is **not** on the real futex lock tree after UAF reclaim, so unlock of `f_pi_target` does not erase our stamp.

## Implications for uid0

1. **Do not** re-fire classic MISC-8 erase until there is a theory for **why `rb_erase` with parent at `ashmem_misc+8` panics** (list/name walk, concurrent fops use, etc.).
2. Prefer write shapes that **never treat MISC-8 as an `rb_node` parent**:
   - root-only (`parent==0`) with `lock+8 == MISC` and **wait_lock==0** (ION blocked: name≠0)
   - or non-MISC target with zero wait_lock (ION_FOPS softbooted — likely RO)
3. Optional RE: dump exact fault PC after softboot (pstore/last_kmsg) if device exposes it.
4. `remove_waiter`-shaped erase needs the forged node **linked under a lock we unlock** while holding wait_lock — new route design.

## Env flags added

- `MODE4_LOCK_OWNER0=1` — waiters=W0, owner=0  
- `MODE4_CLASSIC_SAFE=1` — stack prio=200 with classic MISC stamp  
- `MODE4_CLASSIC_LEAF=1` — *MISC=0 probe (softboot)
