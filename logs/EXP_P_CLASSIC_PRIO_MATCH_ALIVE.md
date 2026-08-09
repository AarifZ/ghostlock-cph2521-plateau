# EXP P — CLASSIC + consumer + PRIO_MATCH — ALIVE

**Boot:** `82da8ffa-…`  
**Env:** `MODE4_CLASSIC_MAPPED=1 MODE4_CLASSIC_PRIO_MATCH=1` (prio=120) consumer on, delay=100ms  

## Result

| Check | Result |
|-------|--------|
| EDEADLK | 35 |
| Stamp | parent=MISC-8 right=fake_fops **prio=120** |
| Consumer | on (setprio) |
| Survive | **ALIVE** same boot_id, stage full return |

## Matrix (classic MISC-8 parent)

| Exp | Consumer | prio | Erase? | Result |
|-----|----------|------|--------|--------|
| O | off | 1 | n/a | ALIVE |
| P | on | **120 match** | **skipped** | **ALIVE** |
| O2 / I4 | on | 1 mismatch | **yes** | SOFTBOOT |

**Conclusion:** setprio + classic stamp is fine if adjust **early-outs**. Softboot is **`rb_erase` / post-erase** on the MISC-8 parent stamp, not select and not setprio alone.
