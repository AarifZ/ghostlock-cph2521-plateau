# Experiment G — REF only-left (oppo-ghostlock-ref shape)

**Date:** 2026-08-09  
**Binary:** `ghostlock-cph2521` 125256 bytes  
**RE:** Ghidra `rb_erase` only-left branch + sm8475 `rtmutex.c` + `oppo-ghostlock-ref` default packing

## Shape

`parent=fake_fops`, `right=0`, `left=MISC` → `*MISC = parent_color` (only-left).

| Env | Stack | Heap W0.pi | Result |
|-----|-------|------------|--------|
| `MODE4_REF_LEFT=1` | main+pi only-left | only-left | **SOFTBOOT** at `pselect pre-select` |
| `MODE4_REF_LEFT_PI=1` | main=0, pi only-left | only-left | **ALIVE success=1 cfi errno=22** |

### G dual softboot
- BEFORE `1e95d5f8…` ~30s  
- AFTER (USB recover) `9de24652…` new boot_id  
- Last log: stamp placed, `pre-select`  
- Recover: `adb kill-server` + USB PnP cycle → worked (`adb_usb_recover.ps1`)

### G-pi survive (no write)
- boot `a1fdfe2f-40c0-44a2-a202-1800a0565c4c`  
- post-select +1511ms ret=5 calls=1 **success=1**  
- cfi write ret=-1 **errno=22**  
- same boot_id AFTER **ALIVE**

## Interpretation (Ghidra + source)

1. **MISC on main tree (left or right)** → CPH softboot class at select (dual REF_LEFT; A; E2; F when punch races).  
2. **MISC only on PI** → survive + route signal, **no fops write** (same as B/C).  
3. Consumer `sched_setattr` → `rt_mutex_adjust_pi` primarily **`rt_mutex_dequeue` on main `tree_entry`**, not PI; PI requeue only if top-waiter conditions.  
4. Plateau success=1 does **not** mean erase committed; only that setprio syscall returned 0.  
5. Ref dual only-left works on Find N2 / Xiaomi-13-pro; **not safe as dual on CPH2521**.

## Closest path to uid 0 still open

| Approach | Status |
|----------|--------|
| Main only-left/right with MISC | softboot on CPH |
| PI only-* with MISC | alive, write not landing |
| Plateau | alive cfi22 (hold) |
| **Need** | Late **main** erase with only-right inverted *without* select walking MISC, **or** proven top-waiter **PI** erase of only-left node, **or** lock identity so adjust dequeues UAF main with safe parent rewiring |

Do not re-fire dual REF_LEFT / A / E2 / F+consumer without new theory.

## USB recovery (user request)

```powershell
.\adb_usb_recover.ps1
# or: adb kill-server; adb start-server; cycle USB Composite / ADB PnP
```

## Code kept (env-only)

- `MODE4_REF_LEFT` / `MODE4_REF_LEFT_PI` in `fops.c` + heap in `util.c`  
- Default remains plateau inert  
