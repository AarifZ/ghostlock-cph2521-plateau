# ASHMEM_MISC_FOPS re-check (high ROI) — 2026-08-16

## Boot-id write-proof reconfirm

| Run | Tag | Result |
|-----|-----|--------|
| 1 | `wproof2_20260816_154451` | landed=1 ALIVE |
| 2 | `bootid_reconfirm_20260816_160618` | **landed=1 ALIVE EXIT=0** |

```
before: e208041c-a085-484f-8c66-c67d3a7885c3
after:  00819100-88ff-ffff-8c66-c67d3a7885c3
fake_fops: ffffff8800918100  (LE matches after string)
```

**Not a fluke.** only-left + parent=`fake_fops` + owner=1 + shift=-2 **reliably stores** into kernel P0 data.

---

## kallsyms (Desktop\Oppo\kallsyms.txt)

| Symbol | VA | OFF from `0xffffffc008000000` |
|--------|-----|-------------------------------|
| `ashmem_fops` | `ffffffc00a2bfdc8` | `0x022BFDC8` |
| `ashmem_misc` | `ffffffc00a91a8d8` | `0x0291A8D8` |
| **`ashmem_misc+0x10` (fops)** | `ffffffc00a91a8e8` | **`0x0291A8E8`** |
| `sysctl_bootid` | `ffffffc00ab99b6d` | `0x02B99B6D` |
| `ashmem_mutex` | `ffffffc00a91a840` | near misc |

### Match vs `src/devices/cph2521/offsets.h`

| Field | Claimed | kallsyms | Match? |
|-------|---------|----------|--------|
| `off_ashmem_misc_fops` | `0x0291A8E8` | `ashmem_misc+0x10` | **YES** |
| `off_ashmem_fops` | `0x022BFDC8` | `ashmem_fops` | **YES** |
| `off_slide_boot_id` | `0x02B99B6D` | `sysctl_bootid` | **YES** |

Runtime P0 for MISC: `ffffff802a91a8e8` (= same OFF via phys load delta).  
Runtime P0 for bootid: `ffffff802ab99b6d` (proven writable by write-proof).

**Offset is not wrong.** Softboot on MISC is not “we aimed at the wrong symbol.”

---

## Why bootid survives but MISC softboots

### only-left erase (working geometry)

```
parent_color = fake_fops
right = 0
left  = target
→ *target = fake_fops
→ __rb_change_child attaches target under fake_fops as a child
```

After that, **`target` is treated as an `rb_node` in the tree** for rebalance / further walks:

| target | As rb_node after store | Risk |
|--------|------------------------|------|
| `sysctl_bootid` (16-byte uuid BSS) | +0 parent=fake_fops; +8/+16 ≈ uuid/adjacent BSS often quiet | **survives** |
| `ashmem_misc.fops` (.data) | +0 = fake_fops; **+8/+16 = following miscdevice fields (list/name-ish)** | **walks live kernel ptrs → softboot** |

Classic only-right with parent=`MISC-8` walks **`name` / miscdevice mid-struct as parent rb_node** → same class of softboot (historical + reconfirmed).

So: **store primitive OK; tree-role of MISC is toxic.**

---

## Implications (direction)

1. Do **not** use MISC as `left` (only-left child) or as classic `parent` (MISC-8) without a plan to **not leave miscdevice fields as tree nodes**.
2. Prefer **root-slot write** into the waiters pointer:
   - `lock` identity at `MISC-8` with `wait_lock==0` (ZERO_NAME zeros `*name` @ MISC-8)
   - `parent=1`, `right=fake_fops` (rb-leaf), `owner=1`
   - Root erase: `*waiters` / `*MISC = fake_fops` **without** promoting MISC as a child node with list children
3. Keep bootid proof as **regression gate** after packing changes.

---

## Next fire (when authorized)

```
MODE4_CHAIN or staged:
  phase1 ZERO_NAME (survived historically)
  phase2 ION_SAFE: lock=MISC-8, parent=1, right=fake_fops rb-leaf, owner=1
  MODE4_ONLY / no W1
```

Not fired in this session after reconfirm + RE.
