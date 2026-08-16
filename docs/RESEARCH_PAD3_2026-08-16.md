# MODE4_PAD3 — pad toxic neighbors then *MISC (2026-08-16)

## Why this is next

| Fact | Evidence |
|------|----------|
| AAW is real | boot_id write-proof POSITIVE ×3+ (only-left `*tgt=fake_fops`) |
| MISC offset correct | kallsyms `ashmem_misc+0x10` = `0x0291A8E8` |
| `left=MISC` overlay idle | NO_CONSUMER ALIVE |
| `left=MISC` + erase | SOFTBOOT in setprio / `rb_erase` |
| ION alone | ALIVE, cfi22 (no wait_lock=0 → no land) |
| ZION name-zero | softboot (name region toxic as left) |

**Hypothesis:** only-left treats `left` as an `rb_node`. Erase walks `left->rb_right` (`+8`) and `left->rb_left` (`+16`). For `left=MISC` those are live kernel fields → softboot. Zero them first (same only-left AAW that worked on boot_id), then write `*MISC=fake_fops`.

## Geometry (stack stamp per phase)

```
MISC     = ashmem_misc + 0x10   # fops pointer slot
MISC+8   = "rb_right" of that node
MISC+16  = "rb_left"  of that node

phase1: parent_color=0, left=MISC+16  → * (MISC+16) = 0
phase2: parent_color=0, left=MISC+8   → * (MISC+8)  = 0
phase3: parent=fake_fops, left=MISC   → * MISC = fake_fops
```

Packing: **owner=1** (proven clean exit after erase on boot_id).  
`MODE4_ONLY` / stop_no_w1. live_sync phase markers.

## Fire

```text
MODE4_PAD3=1 MODE4_ONLY=1
# optional: MODE4_NO_CONSUMER=0 (need consumer erase for store)
```

Fresh boot, uptime ≲ 60s, network ADB, pull console + `live_sync.log`.

## Risk

Phase1/2 still use `left` in the MISC *region*. If `MISC+24`/`MISC+32` (children of pad nodes) are toxic, phase1 may softboot. That still isolates: which neighbor is quiet.

## Success criteria

| Outcome | Meaning |
|---------|---------|
| phase1 softboot | pad target toxic; need quieter pad or different order |
| phase1–2 ALIVE, phase3 softboot | pads not enough / rebalance still toxic |
| phase3 ALIVE cfi≠22 or wr>0 | **fops land** — past product plateau |
| all ALIVE cfi22 | erase not linking (wait_lock / geometry) |

## boot_id side effect (user note)

Confirmed: after write-proof, `/proc/.../boot_id` becomes `0001a37e-89ff-...` and Android ashmem path is `/dev/ashmem{boot_id}`. Apps that were **not already open** cannot open ashmem → fail to launch. **Reboot restores** real uuid. Policy: boot_id proof = diagnostic only; reboot after gate.

## Closer?

- **Research:** yes — AAW proven; crash phase isolated; PAD3 is the direct fix for toxic-left erase.
- **Product (uid0):** only if phase3 lands `*MISC=fake_fops` ALIVE. Not there yet until this (or successor) fires green.
