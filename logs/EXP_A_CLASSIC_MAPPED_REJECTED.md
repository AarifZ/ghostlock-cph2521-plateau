# Experiment A — MODE4_CLASSIC_MAPPED — REJECTED

**Date:** 2026-08-09  
**Device:** CPH2521 clean boot, delay=150ms  
**Binary:** ghostlock-cph2521 (123080)

## Stamp (RE-backed erase target A)

Stack main rb_node under `PSELECT_SHIFT=-2`:

- `parent_color = MISC-8`
- `right = fake_fops`
- `left = 0`
- `pi = 0`
- **task/lock preserved** (`init_task` P0, `fake_lock`)
- W0 prio=100

## Results

| Run | Result |
|-----|--------|
| r1 clean (~23s) | **softboot** at `pselect pre-select` |
| r2 clean (~39s) | **softboot** at select |

r1 log (partial): placement showed  
`tree=MISC-8 pi=0 task=init_task lock=fake_lock prio=1` — geometry correct, still dies.

## Verdict

**Reject.** Stack main classic with MISC softboots on CPH even when task/lock slots are correct.  
Matches historical MAIN-GADGET / A53-mapped class. Do not merge.

Env remains opt-in only: `MODE4_CLASSIC_MAPPED=1`.
