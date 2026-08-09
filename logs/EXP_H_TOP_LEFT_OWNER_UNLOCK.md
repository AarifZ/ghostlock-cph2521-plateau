# Experiment H — TOP_LEFT + OWNER_UNLOCK (uid0 path)

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 126184  
**RE driver:** sm8475 `remove_waiter` / `mark_wakeup_next_waiter` need top + PI dequeue; adjust needs main dequeue for write. Owner never unlocked `f_pi_target` during overlay (blocked on chain).

## Code added

| Env | Effect |
|-----|--------|
| `MODE4_TOP_LEFT=1` | PI only-left, stack prio=0, deadline≠0, W0 prio=250 |
| `MODE4_OWNER_UNLOCK=1` | Owner holds target, does **not** take chain until unlock_req; consumer after setprio sets unlock_req → `FUTEX_UNLOCK_PI(f_pi_target)` |

## H — TOP_LEFT + OWNER_UNLOCK

| | |
|--|--|
| Boot | `aba35e93-fa28-4e03-abed-1ac918769eb8` ~30s |
| Owner | `UNLOCK f_pi_target ret=0` **worked** |
| Route | success=1, owner_unlock_done=1, post-select +1509ms ret=0 |
| CFI | **errno=22** |
| AFTER | same boot **ALIVE** |

## H2 — EXP_E2 (main only-right) + OWNER_UNLOCK

| | |
|--|--|
| Boot | same `aba35e93…` ~92s |
| Stamp | main parent=fake_fops right=MISC left=0 |
| Owner | UNLOCK ret=0 |
| Route | success=1, ALIVE |
| CFI | **errno=22** |

### Softboot note (important)

Earlier **E2 alone softbooted**. With `MODE4_OWNER_UNLOCK=1` (owner not blocked on chain during select), **E2 survived**.  
Hypothesis: prior E2 softboots mixed **owner/chain lock state** with MISC-main, not only “MISC is poison.” Main only-right inverted is **conditionally survivable** under OWNER_UNLOCK.

Still **no fops write** → erase of stamped node still not committing (or `pi_blocked_on` null so adjust no-ops; unlock top waiter ≠ our UAF).

## Closest to uid 0 now

1. Plateau / PI-only / TOP_LEFT: alive cfi22  
2. **E2 + OWNER_UNLOCK: alive cfi22 with main MISC stamp** ← new survivable write geometry  
3. Need: prove `WAIT_REQUEUE_PI` leaves dangling `pi_blocked_on` and force **main** `rb_erase` on that node (adjust requeue) without reinsert softboot  

Next code: log `WAIT_REQUEUE_PI` ret; optional `MODE4_LOCK_IDENTITY` research; keep OWNER_UNLOCK default-off.
