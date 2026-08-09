# EXP U — CLASSIC_LEAF (erase *MISC=0) — SOFTBOOT

**Env:** `MODE4_CLASSIC_LEAF=1` parent=MISC-8 right=0 left=0 prio=90 consumer on  
**Ghidra rb_erase:** only-right/leaf writes parent slot; red leaf skips rebalance early.

## Result

| Check | Result |
|-------|--------|
| EDEADLK | 35 |
| Stamp | parent=MISC-8, **right=0 left=0** |
| Survive | **SOFTBOOT** |

## Interpretation

| Erase value into MISC | Result |
|----------------------|--------|
| fake_fops (classic) | softboot |
| **0 (leaf)** | **softboot** |
| erase skipped (PRIO_MATCH) | ALIVE |

Softboot is **not** “bad fake_fops table”. Any **rb_erase with parent=MISC-8** (or post-erase adjust re-insert / concurrent fops use) kills.

Ghidra note: only-right with child early-returns after `*child=parent_color`; leaf may rebalance if black. Our parent_color is RED (…e0). Softboot still happens → focus next on **adjust re-insert after erase** or **remove_waiter path** (no re-enqueue).

## Recovery

hardboot OK → `2eb628df` then user boot; latest CLEAN `2eb628df` / after U: `2eb628df` wait log said `2eb628df` then AFTER `2eb628df` - actually AFTER `2eb628df-01bd...` no `2eb628df` from earlier and U recovery `2eb628df` → `2eb628df` 

From log: AFTER boot_id=2eb628df-01bd-4fd6-8c2f-20461693814e
