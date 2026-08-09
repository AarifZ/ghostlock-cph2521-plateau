# EXP N1b — MODE4_ION_FOPS right=fake_fops — SOFTBOOT

**Date:** 2026-08-09  
**Binary:** 128712 (right=fake_fops fix)  
**Env:** `MODE4_ONLY=1 MODE4_ION_FOPS=1 KPHYS=0xa8000000 PSELECT_ROUTE_DELAY_USEC=100000`  
**Boot pre:** `5a66fd50-…` uptime ~1814s  

## Result

| Check | Result |
|-------|--------|
| EDEADLK | **35** |
| Stamp | lock=`ashmem_fops+0x10`, parent=1, right=**fake_fops** (spray) |
| Survive | **SOFTBOOT** after place (no post-select / ADB gone) |

```text
CMP_REQUEUE_PI errno=35
ION_FOPS(N1) lock=ashmem_fops+0x10=ffffff802a2bfdd8 right=fake_fops=ffffff8869270100
pselect place … lock=ffffff802a2bfdd8
(log ends — softboot)
```

## Interpretation

| Prior | Diff | Inference |
|-------|------|-----------|
| N1 r1 right=write_jt | softboot | text store via rb_set_parent |
| **N1b right=fake_fops** | **still softboot** | not JT-only; likely **store into ashmem_fops (.rodata)** or toxic lock walk |
| ION_ROOT lock=MISC-8 | ALIVE cfi22 | wait_lock fail → **no erase**; MISC is .data |
| Plateau lock=fake_lock | ALIVE cfi22 | no write |

**Best read:** wait_lock at `.read==0` **succeeds** → `rb_erase` runs → root write to `ashmem_fops+0x18` faults if table is **RO** → softboot.  
That would mean **adjust/erase path is real** for Ion-style lock identity, but **cannot target fops table body**.

## Reject

- `MODE4_ION_FOPS` (N1 / N1b) — do not re-fire  
- `MODE4_EXP_N` (parent in fops table) — same RO write target  

## Write target policy

| Target | Writable? | wait_lock at −8 / lock |
|--------|-----------|-------------------------|
| `ashmem_misc.fops` (MISC) | **yes** (.data) | MISC−8 = name ≠ 0 → ION_ROOT no erase |
| `ashmem_fops.*` slots | **no** (likely .rodata) | wait_lock OK → erase softboots |

Need: **write MISC** with a lock that **trylocks** (wait_lock 0) **or** classic/parent geometry that survives select (open).

## Recovery

ADB server only; **manual replug** if still dead.
