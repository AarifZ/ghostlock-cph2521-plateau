# Deep dig: mode-4 fops redirect not landing (CPH2521)

## Executive summary

`PSELECT_SHIFT=-2` correctly overlays the UAF waiter. Route signal fires.
`cfi write errno=22` means `ashmem_misc.fops` still points at real ashmem
(no `.write`). The write-what-where never committed.

**Root cause (from Image disasm of `remove_waiter` / `rb_erase`):**

The PI write primitive is `rb_erase` on a waiter **pi_tree** node with:
- `rb_left = 0`
- `rb_right = MISC_FOPS` (address to overwrite)
- `__rb_parent_color = fake_fops` (value written)

`rb_erase` only-right-child path does: `*right = parent_color` → `*MISC = fake_fops`.

That erase is invoked on the **stack UAF waiter**'s `pi_tree` (`waiter+0x18`),
not on the heap `W0` node alone. Our stack overlay zeroed pi fields (words 5–7)
and only packed the gadget on heap W0 → erase ran on empty stack pi_tree →
no write; CFI still sees real ashmem.

## Evidence chain

### Device
- shift=-2: survives select, success=1, cfi open OK, pwrite EINVAL
- left=MISC on heap: softboot (bad shape for this path)
- waiter_task=fake_task on heap W0: softboot

### Image (remove_waiter @ 0xffffffc0081ed254)
- Erases waiter from lock waiters via `rb_erase(waiter, lock+8)`
- If waiter is top / owner path: `rb_erase(&waiter->pi_tree, owner+0x880)`
- Waiter `lock` field @ +0x38, `pi_tree` @ +0x18, `task` @ +0x30 — matches us

### Image (rb_erase @ 0xffffffc008ab7590)
- `ldp left,right,[node,#8]`
- If left==0 && right!=0: `str parent_color, [right]`  ← write primitive

### Code bug (pre-fix)
`prepare_pselect_fdsets` 5.10 words 5–7 always 0; gadget only in util.c heap W0.

## Fix applied (this dig)

In `fops.c` for `GHOSTLOCK_KERNEL_5_10` + mode 4:
- stack word 5 = fake_fops (pi_parent / value)
- stack word 6 = data_addr(MISC_FOPS) (pi_right / address)
- stack word 7 = 0 (pi_left)

Rebuild: ghostlock-cph2521 ~116408 bytes.

## What we still might need from other images

**Not required for next single-device test** of this fix.

Optional later (only if stack gadget still fails or post-redirect breaks):

| Image | Why |
|-------|-----|
| **vendor_boot.img** | Confirm PHYS_OFFSET / DT memory base if KPHYS ever looks wrong (currently 0xa8000000 works for aliases) |
| **dtbo / dtb** | Same, SoC memory map |
| **super / system** | Not needed for kernel exploit |
| **recovery** | Not needed |
| **vbmeta** | Not needed for this bug |
| Samsung payloads | Method only; do not copy offsets |

Boot.img we have is sufficient for structure digs.

## Samsung A155N 5.10 (KB) alignment

Their waiter 0x50 layout and task pi 0x86c/0x880 match CPH. Their claimed
PSELECT shift 0 is **not** ours (−2). Their P0 phys 0x40000000 is MTK — ignore.

## Frozen packing table (research plan 2026-08-02)

**Write primitive (Image rb_erase only-right):** `*rb_right = __rb_parent_color`

| Location | parent_color | right | left | Role |
|----------|--------------|-------|------|------|
| **Stack PI** words 5–7 | `fake_fops` (RED) | `MISC` P0 | `0` | Primary if pi erase |
| **Stack main** words 2–4 | `0` | `0` | `0` | Proven survive (not `1`) |
| **Heap W0 PI** | same as stack PI | same | `0` | Spray-backed value page |
| **Heap W0 main** | `1` | `0` | `0` | Never MISC on main |
| **pi_waiters** | `0` | | | Wiring softbooted on-device |
| **stack task/lock** | `init_task` P0 / `fake_lock` | | | Proven safer than fake_task |

**Do not use as default:** classic (MISC-8, right=fake_fops), MAIN_TREE+MISC, left=MISC,
fake_task waiter, G06 perf-first (shell EACCES on CPH).

**Success only:** `cfi write ret≥0 errno=0` (not route success=1).

## Next validation

T0: `MODE4_ONLY=1 MODE4_NO_GADGET=1` — must survive select.  
T1: `MODE4_ONLY=1` dig default (stack+heap inverted PI) — need cfi write ≠ 22 or softboot then offline-only fix.

If still errno 22 with dig packing: re-disasm which node remove_waiter erases; do not invent shapes.
