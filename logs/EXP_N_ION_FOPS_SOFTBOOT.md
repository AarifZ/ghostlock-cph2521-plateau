# EXP N1 — MODE4_ION_FOPS — SOFTBOOT

**Date:** 2026-08-09  
**Binary:** ghostlock-cph2521 128712  
**Env:** `MODE4_ONLY=1 MODE4_ION_FOPS=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000`  
**Boot pre:** `3e2b6acd-…` uptime ~1615s  

## Result

| Check | Result |
|-------|--------|
| EDEADLK | **errno=35** |
| Stamp | lock=`ashmem_fops+0x10`, parent=1, right=**write_jt** `ffffffc009830218` |
| Survive | **SOFTBOOT** after place / pre-select (no post-select) |
| USB thrash | none |

```text
CMP_REQUEUE_PI ret=-1 errno=35
stack mode4 ION_FOPS(N1) lock=ashmem_fops+0x10=ffffff802a2bfdd8
  parent=1 right=write_jt=ffffffc009830218
pselect place tree=1 … lock=ffffff802a2bfdd8
pselect pre-select  (log ends — softboot)
```

## Root cause (design bug, not “unknown”)

`rb_erase` only-right does:

1. `*root = child` (or `parent->rb_right = child`) — value store OK  
2. **`rb_set_parent_color(child, …)`** — **stores into `*child`**

So **`right` must be a writable object** (spray `fake_fops`), never a CFI JT in **.text**.  
ION_ROOT used `right=fake_fops` and survived; N1 used `right=write_jt` → write to text → softboot.

Do **not** fire N2 with `right=write_jt` (same bug).

## Next (after manual replug)

1. **N1b** `MODE4_ION_FOPS=1` but **right=fake_fops** (probe: erase + table writable?)  
   - Target still `ashmem_fops.write` ← table addr (wrong for CFI) but proves lock/wait_lock + RO vs RW.  
2. Or abandon slot-write; stay on **MISC ← fake_fops** with lock that has wait_lock=0 (open).

## Policy

- Reject N1 as fired (write_jt).  
- Softboot recovery: **adb server only**; **manual replug**.
