# Experiment E — MODE4_EXP_E — RESULT

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 (123592)  
**Env:** `MODE4_ONLY=1 MODE4_EXP_E=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=150000`  
**Boot:** same session, no reboot (uptime ~1431→1468)

## Stamp

Stack main only-right, **parent = spray SCRATCH** (not MISC):

- `parent_color = page+SCRATCH` (inert black rb_node primed in util)
- `right = fake_fops`
- `left = 0`
- pi = 0, task/lock preserved
- W0 prio=100

## Result r1

```text
EXP_E SCRATCH inert parent
EXP_E main parent=spray_SCRATCH=…380 right=fake_fops
place tree=spray pi=0 task=init lock=fake prio=1
post-select ret=12 success=1 delay=150000
cfi write errno=22
EXIT, ALIVE, same boot_id
```

| Metric | Outcome |
|--------|---------|
| Softboot | **No** |
| ADB | **stable** |
| Route | success=1 |
| fops redirect | **No** (expected — parent≠MISC-8) |

## Verdict

**E survives** where A (MISC parent) softboots. Main-tree classic geometry is viable if parent stays in controlled spray.

**Not a plateau upgrade** (still errno 22). Next step if continuing this line: **E2** — only-right with `parent_color=fake_fops`, `right=MISC` (inverted write `*MISC=fake_fops`) env-gated, or chain spray parent so a child slot aliases MISC (hard).

Env: `MODE4_EXP_E=1` opt-in only.
