# CPH2521 Ghidra walk — remove_waiter + UAF path (2026-08-09)

Project: `C:\Users\LENOVO\cph_ghidra_lab\CPH_kernel_lab` / program `kernel`  
Image base 0; addresses = kallsyms VA − `0xffffffc008000000`.

## 1. Exact stamp that gets erased

### Call site (GhostLock)

Only **one** xref to `remove_waiter`:

```
rt_mutex_start_proxy_lock @ 001ef8dc
  → remove_waiter(lock, waiter) @ 001ef968
```

`rt_mutex_start_proxy_lock` is called from `futex_requeue` (PI requeue path).

```c
// rt_mutex_start_proxy_lock(lock, waiter, task)
try_take = try_to_take_rt_mutex(...);
if (try_take == 0) {
  ret = task_blocks_on_rt_mutex(lock, waiter, task, /*detect_deadlock=*/1);
  if (ret == 0) goto unlock_out;
  if (lock->owner_raw < 2) { ret = 0; goto unlock_out; }  // edge
}
else ret = 1;
remove_waiter(lock, waiter);   // DEADLOCK / fail unwind
```

On **−EDEADLK** (or non-zero from `task_blocks_on_rt_mutex` while owner still held), the kernel **unlinks the same stack `waiter`** that was just linked.

### `remove_waiter(lock=x0, waiter=x1)` — two erase targets

| Phase | Condition | Call | Node erased |
|-------|-----------|------|-------------|
| **A. Main tree** | waiter still in waiters tree (`*waiter != waiter` sentinel) | `rb_erase(waiter, lock+8)` | **waiter main rb_node @ +0** |
| **B. PI tree** | `top_waiter == this waiter` AND owner non-null | `rb_erase(waiter+0x18, owner+0x880)` | **waiter.pi_tree @ +0x18** |

Asm (main erase):

```
001ed304: add x1, x19, #0x8     ; lock+8 = waiters root
001ed308: mov x0, x23           ; waiter
001ed30c: bl  rb_erase
001ed310: str x23, [x23]        ; mark dequeued
```

Asm (PI erase, only if was top):

```
001ed38c: ldr x8, [x24, #0x18]! ; node = &waiter->pi_tree
...
001ed3bc: add x1, x21, #0x880   ; owner->pi_waiters
001ed3c0: mov x0, x24
001ed3c4: bl  rb_erase
```

### GhostLock “wrong task” detail (confirmed)

Early in `remove_waiter`:

- `mrs x20, sp_el0` → **current**
- take **`current + 0x86c`** (`pi_lock`)
- clear **`current + 0x898`** (`pi_blocked_on`) after main erase

The **real waiter task** is only used later if top-waiter path needs **owner**’s pi tree (`owner` from `lock->owner`).  
So: main erase always uses the **waiter pointer** (stack UAF). PI bookkeeping on first unlock uses **current**, not `waiter->task` — classic GhostLock.

### What is **not** erased

| Object | Erased by remove_waiter? |
|--------|---------------------------|
| Stack pselect overlay = forged waiter | **YES** (this is the pointer) |
| Heap spray W0 (unless pointer equals W0) | **NO** |
| `fake_task.pi_waiters` root alone | **NO** (unless someone walks it) |
| Nodes only linked under fake_task | Softboot risk; not the default erase |

**Write primitive requires the stamp on the stack waiter node that is actually passed to `rb_erase`.**

### Classic write shape (only-right `rb_erase`)

From `rb_erase` decompile (left=0, right≠0):

```c
// param_1 = node, param_2 = root
left  = node[1];   // +0x08
right = node[2];   // +0x10
if (right != 0 && left == 0) {
  *right = *node;                    // right->__rb_parent_color = parent_color
  parent = *node & ~3;
  if (parent->rb_right == node)
    parent->rb_right = right;        // parent+0x10
  else
    parent->rb_left  = right;        // parent+0x08
}
```

For fops redirect:

| Field on **erased node** | Value |
|--------------------------|--------|
| `__rb_parent_color` (+0) | `MISC_FOPS - 8` (so parent = MISC−8) |
| `rb_right` (+8) | `fake_fops` |
| `rb_left` (+16) | `0` (only-right) |

Then `*(MISC) = fake_fops` if node was **left** child of fake parent (parent+8 = MISC fops slot).  
`ashmem_misc+0x10` = fops → parent at `ashmem_misc+0x08` = MISC−8 when treating as rb_node starting at MISC−8 with rb_left @ +8.

### Main tree vs PI tree stamp

| Stamp location | When erased | CPH softboot history |
|----------------|-------------|----------------------|
| Stack main tree (words 0/1/2 of waiter) | **Always** (if still linked) | MISC on main → softboot at select (tree walk / overlay) |
| Stack pi_tree (+0x18) | Only if top waiter | STACK_PI survived but cfi22 (not top / not erased) |
| Heap W0 main or pi | Never (wrong pointer) | inert → cfi22 |

**Conclusion for plateau→write:** must get **classic main-tree gadget on the stack waiter** that survives until `remove_waiter`, **or** ensure stack waiter is **top** and put classic on **pi_tree @ +0x18**. Heap W0 alone cannot complete the write.

---

## 2. Waiter layout from `task_blocks_on_rt_mutex`

Signature (decomp):  
`task_blocks_on_rt_mutex(lock, waiter, task, detect_deadlock)`

Asm proof:

```
001ecb78: stp x20, x19, [x22, #0x30]   ; task, lock
001ecb84: str w8, [x22, #0x40]         ; prio
001ecb8c: str x8, [x22, #0x48]         ; deadline
001ecc50: str x22, [x20, #0x898]       ; task->pi_blocked_on = waiter
```

| Offset | Field | Source |
|--------|-------|--------|
| +0x00 | main `__rb_parent_color` | linked against tree |
| +0x08 | main `rb_right` | 0 at insert then tree ops |
| +0x10 | main `rb_left` | 0 at insert |
| +0x18 | pi_tree parent | PI tree under owner |
| +0x20 | pi_tree right | |
| +0x28 | pi_tree left | |
| +0x30 | **task** | `param_3` |
| +0x38 | **lock** | `param_1` |
| +0x40 | **prio** | `task->prio` @ +0x84 |
| +0x48 | **deadline** | `task+0x360` (this build) |

Insert:

1. Walk `lock->waiters` (root @ lock+8) by prio/deadline  
2. `rb_insert_color(waiter)` on **main** node  
3. `task->pi_blocked_on = waiter`  
4. If top: also link `waiter.pi_tree` into `owner->pi_waiters` (+0x880)

Prio compare on **main** tree uses `waiter+0x40` / `+0x48`.  
PI tree walk uses prio at **pi_node+0x28** (= waiter+0x40) — same prio field relative to pi entry.

---

## 3. UAF chain: `futex_requeue` → proxy → free stack

```
futex_requeue (FUTEX_CMP_REQUEUE_PI)
  → rt_mutex_start_proxy_lock(pi_mutex, &waiter_on_stack, task)
       → task_blocks_on_rt_mutex(...)   // links stack waiter
       → on deadlock/fail: remove_waiter(lock, &waiter_on_stack)
  // waiter was on requeue thread stack
  // GhostLock: pi_blocked_on / cleanup uses wrong task → dangling ref
  // Attacker reclaims stack with pselect fdset overlay = forged waiter
  // Later remove_waiter / adjust path erases forged node → write
```

CPH route (mode4): requeue success + pselect overlay with `shift=-2` so:

| Waiter field | Logical word | After shift −2 (wps=5) lands at |
|--------------|--------------|----------------------------------|
| tree parent/right/left | 2,3,4 | in[0], in[1], in[2] (approx) |
| pi parent/right/left | 5,6,7 | … |
| task / lock | 8, 9 | **out[1], out[2]** |
| prio | 10 | out[3] |

A53 stamp `write_set[1]=MISC-8, write_set[2]=value` without shift collides with **task/lock** on CPH → softboot (rejected).

---

## 4. Implications (actionable)

1. **Erased stamp = stack waiter main rb @ +0** (primary) or **pi @ +0x18** if top.  
2. **Heap W0** is spray/fake_lock material only until proven otherwise — not the erase target.  
3. To beat cfi22 without softboot:  
   - Keep plateau task/lock placement (`init_task` P0, `fake_lock`).  
   - Put classic **only** in main tree slots under shift=−2 **after** link / without early walk treating MISC as live node — still open research (timing / prio so not walked badly).  
   - Or force **top-waiter** + classic on **pi_tree** only (STACK_PI survived but no write — likely not top).  
4. `fake_task.pi_waiters` linking remains **hard-negative** (softboot).  
5. Consumer delay ≥150 ms reduces race softboot; orthogonal to stamp geometry.

---

## 5. Symbols / addresses (lab project)

| Name | Ghidra | Kallsyms VA |
|------|--------|-------------|
| `remove_waiter` | `001ed254` | `ffffffc0081ed254` |
| `task_blocks_on_rt_mutex` | `001ecaf0` | `ffffffc0081ecaf0` |
| `rt_mutex_start_proxy_lock` | `001ef8dc` | `ffffffc0081ef8dc` |
| `futex_requeue` | `002943bc` | `ffffffc0082943bc` |
| `rb_erase` | `00ab7590` | `ffffffc008ab7590` |
| `rb_insert_color` | `00ab73c0` | `ffffffc008ab73c0` |
| `rt_mutex_setprio` | `001a5d60` | `ffffffc0081a5d60` |
| `ashmem_misc` | `0291a8d8` | `ffffffc00a91a8d8` |
| `ashmem_fops` | `022bfdc8` | `ffffffc00a2bfdc8` |
