# Experiments E2 + C + RE notes (2026-08-09)

## E2 — MODE4_EXP_E2 — REJECTED (softboot)

**Stamp:** main only-right inverted  
`parent_color = fake_fops`, `right = MISC`, `left = 0`  
→ if erase: `*MISC = fake_fops` (first only-right store)

**Result:**  
- Log reaches `EXP_E2` + `pselect pre-select` then dies  
- `boot_id` changed → **true kernel reboot/softboot**  
- Same class as DIG / STACK_PI inverted (MISC as walkable right child)

**Verdict:** do not re-fire without new theory. Env-only.

---

## C — MODE4_TOP_PI — ALIVE, no write

**Stamp:** PI classic like B + stronger top preference  
- stack prio=**0**, W0 prio=**250**, pi parent=MISC-8, right=fake_fops, main=0  

**Result (clean-ish boot ~29s):**  
```text
TOP_PI(C) prio=0
success=1 delay=150000
cfi write errno=22
ALIVE same boot_id
```

**Verdict:** same plateau as B. Prio games alone do **not** make PI erase commit fops write. Not a merge.

---

## RE (Ghidra) — after E2/C

### Write sites still only rb_erase shapes
- `remove_waiter`: main erase always (if linked); PI erase if was top  
- `rt_mutex_adjust_prio_chain` called from remove_waiter / task_blocks  
- `rt_mutex_setprio` (consumer `sched_setattr` path): **no direct rb_erase** — scheduler/rtmutex bookkeeping; `success=1` ≠ fops write  

### Matrix so far

| Exp | Stamp | Softboot? | cfi22? |
|-----|--------|-----------|--------|
| A main MISC-8→fake_fops | softboot | — |
| E2 main fake_fops→MISC | **softboot** | — |
| E spray parent→fake_fops | alive | yes (expected) |
| B/C PI MISC-8→fake_fops | alive | **yes** |
| baseline inert | alive | yes |

### Implication
Any stamp that puts **MISC in main tree fields** (as parent or right) softboots at select.  
PI MISC stamp survives but **does not produce write** under current route (erase not firing on that node, or wrong only-right shape for PI subtree, or consumer path never re-erases UAF).

### Next RE focus (no thrash)
1. Whether UAF node is still **linked** when consumer runs (or only dangling pi_blocked_on).  
2. Exact fields `adjust_prio_chain` loads from waiter (task@0x30, lock@0x38, pi@0x18).  
3. Non-MISC write destinations that still alias `ashmem_misc+0x10` (unlikely without MISC in stamp).  
4. Timing: stamp must match **which** erase runs (first remove_waiter vs late chain).

**Do not default** E2 or C. Plateau remains inert + delay 150ms.
