# High-ROI RE (Ghidra + firmware policy) — 2026-08-09

## Firmware download decision

| Candidate | Size / notes | ROI for **write land** |
|-----------|--------------|-------------------------|
| Current `CPH2521_16.0.5.1002_EX01_boot.img` + Image + kallsyms | already analyzed | **High** (have it) |
| oppostockrom PHU110 domestic 9.25 GB full package | wrong region SKU packaging; multi‑GB | **Low** for GhostLock write |
| Random XBL / full OFP | boot chain | **None** for rtmutex UAF |

**Policy:** do **not** download multi‑GB full ROMs unless we need a **different kernel build** (new uname) after an OTA. Diffing the same-family kernel is done offline on Image; XBL does not change `remove_waiter`.

Phone ADB was down during this pass; RE is offline-complete.

---

## Critical Ghidra path: `rt_mutex_adjust_prio_chain` @ `001ed8ec`

Consumer `sched_setattr` → `rt_mutex_setprio` → may enter **adjust_prio_chain**.  
Asm (high signal):

```text
001ed9c4  ldr  x28, [x19, #0x898]     ; waiter = task->pi_blocked_on
001ed9c8  cbz  x28, exit
001ed9e0  ldr  x8,  [x28, #0x38]     ; waiter->lock
001ed9e4  cmp  x24, x8               ; must match chain's expected lock
001ed9e8  b.ne exit                  ; else NO erase / NO write
...
001eddd4  add  x1, x27, #0x8         ; &lock->waiters
001eddd8  mov  x0, x28               ; waiter
001edddc  bl   rb_erase              ; MAIN erase of pi_blocked_on waiter
001eddf0  str  x28, [x28]            ; mark dequeued (*waiter = waiter)
001eddfc  str  w8,  [x28, #0x40]     ; REWRITE prio from task
001ede00  str  x10, [x28, #0x48]     ; REWRITE deadline
... re-walk lock waiters, rb_insert_color(waiter)
```

Also (later in function) PI tree erase:

```text
rb_erase(waiter+0x18, owner+0x880)   ; when top-of-pi conditions hold
```

### What this means for CPH stamps

| Requirement for late write via adjust | Our plateau overlay |
|--------------------------------------|---------------------|
| `task->pi_blocked_on` still points at UAF stack | GhostLock bug leaves **real waiter**’s `pi_blocked_on` dangling — good if consumer punches **that** tid |
| `waiter->lock` equals lock adjust expects | We set `lock=fake_lock` (spray). If chain holds **real** futex PI lock ≠ fake_lock → **early exit, no rb_erase** |
| Node looks still linked (`*waiter ≠ waiter`) | Classic stamps set parent ≠ self → OK |
| only-right shape for fops | Need parent/right/left as designed **at erase time** |

**Hypothesis (high ROI):**  
`success=1` means setprio/sched path ran, but **adjust often exits before `rb_erase`** because:

1. `pi_blocked_on` is NULL / wrong task, or  
2. **`waiter->lock` (fake_lock) ≠ lock used in the PI chain**, or  
3. First `remove_waiter` already dequeued; tree no longer contains UAF pointer and chain skips.

That explains **B/C survive + cfi22** better than “missing offsets.”

MISC-on-main (A/E2) softboots because **select-time walk** treats MISC as rb child/parent — orthogonal to adjust.

---

## Experiment matrix (updated)

| Exp | Result | Keep? |
|-----|--------|-------|
| A main MISC-8→fops | softboot | reject |
| E2 main fops→MISC | softboot | reject |
| E spray parent→fops | alive, cfi22 | geometry OK, no redirect |
| B/C PI MISC | alive, cfi22 | no write; prio games insufficient |
| baseline | alive, cfi22 | plateau |

---

## Next high-ROI tests (ordered)

### T1 — Lock identity (code + one fire)

**Idea:** On mode4 overlay, set `waiter->lock` to something the chain will accept.

Options to try (env-gated, one at a time):

1. **`MODE4_LOCK_FROM_OWNER`** research: whether punch path uses `fake_lock` as the rt_mutex (it should for pselect fake lock route — verify in fops route that owner/waiter use same `fake_lock`).  
2. Ensure **fake_lock.waiters** can contain the UAF node after overlay (hard: need stack VA).  
3. Log whether adjust would see lock match: static only for now.

Code audit (already): pselect uses `fake_lock` for lock word; consumer punches **waiter tid** (the thread in select). That waiter’s `pi_blocked_on` should be the UAF if GhostLock left it. The **lock** field in overlay is `fake_lock`. Chain after requeue: the waiter was on the **requeue PI mutex**, not necessarily `fake_lock`.

**Key question:** Is `fake_lock` the same object as the futex PI lock after requeue, or only a pselect-side fake?

From exploit design: requeue sets up real futex PI; pselect overlays waiter with `lock=fake_lock` so **later** paths walk fake_lock. The write target for erase is `rb_erase(waiter, &fake_lock.waiters)`. For only-right write, **tree membership is secondary** to node fields — but broken rb_erase on non-member can softboot or no-op.

### T2 — Prove adjust sees linked node (instrumentation)

Add durable log around consumer success counting already present (`success=1`). Optional: **read** nothing in kernel; userspace cannot see pi_blocked_on.

Static: confirm waiter_thread is the one with UAF stack + same tid as punch.

### T3 — Non-MISC write that still hits MISC (hard)

Only-right first store `*right = parent_color` needs `right == MISC` → E2 softboot.  
change_child with `parent == MISC-8` → A softboot.  

So **any direct MISC stamp on main softboots at select**. Late path must apply stamp **without** select walking MISC, or walk must not follow those pointers (tree empty / not linked at select enter).

**Idea T3a:** Main stamp only-right with MISC **after** select entered? Not possible with single pselect overlay.

**Idea T3b:** Rely on **adjust’s rb_erase** only; keep main **zero** at select (survive); somehow fill stamp later — needs second reclaim (not available).

**Idea T3c:** PI-only stamp (B/C) + force adjust to take PI erase branch (top of owner pi_waiters). Still cfi22 so far.

### T4 — Firmware version (only if OTA)

If device gets new `uname`, re-extract **that** boot.img (from phone `dd` or OTA payload), re-kallsyms, re-offset. Do not download 9 GB domestic PHU110 blindly.

---

## Concrete next code experiment (recommend)

### `MODE4_FAKELOCK_OWNER_INIT` hygiene (low risk)

Ensure `fake_lock.owner` / waiters match what adjust expects when `waiter->lock == fake_lock`:

- Already: waiters root = W0, owner = fake_task|1  
- Stack: task=init_task (not fake_task), lock=fake_lock  

**Mismatch:** adjust compares waiter prio to task prio; rewrites from **task** at +0x898’s owner task (`x19`), not overlay task field only.

When adjust runs on **waiter task** (consumer punch tid):  
`x19 = waiter task`, `pi_blocked_on = UAF`, `waiter->lock` must equal lock in chain.

If punch only changes nice and never enters adjust with `pi_blocked_on` set, **no erase**.

**Check:** Does `sched_setattr` → `rt_mutex_setprio` always call `adjust_prio_chain` when `pi_blocked_on != NULL`?

From setprio decomp: if prio changes and task has pi state, calls helper `func_0x001a66a4` / chain — need confirm path with blocked-on waiter.

### Recommended fire after RE (single variable)

Do **not** re-fire E2/A.

Optional **same-boot** baseline reconfirm only.

**Next real experiment (design, then implement):**  
Document + implement **MODE4_TASK_WAITER** (if not already): overlay `task` field = **real waiter task** P0 alias if we can leak it — we usually cannot.

Without leak, force path where **current** holds the dangling `pi_blocked_on` (GhostLock wrong-current): then setprio on **current** would walk overlay. Consumer punches **waiter tid**, not current.

**Research experiment (no phone):** map exact call chain  
`sched_setattr_tid(waiter)` → … → `adjust_prio_chain` args when `pi_blocked_on` set.

---

## Summary

| Question | Answer |
|----------|--------|
| Download other full firmware now? | **No** (9 GB, wrong ROI; keep current Image) |
| High-ROI RE result? | **adjust_prio_chain erases `pi_blocked_on` main node** if lock matches |
| Why cfi22 with success=1? | Likely **no rb_erase** (lock mismatch / no pi_blocked_on / skip) or erase without only-right gadget |
| Next? | Static: setprio→adjust when blocked; design stamp so **lock match + linked look** without MISC-on-main at select |

## Env flags available (no change to default)

```text
MODE4_EXP_E=1      # survive, non-MISC main
MODE4_EXP_E2=1     # REJECT softboot
MODE4_TOP_PI=1     # survive, cfi22
MODE4_PI_CLASSIC=1 # survive, cfi22
```
