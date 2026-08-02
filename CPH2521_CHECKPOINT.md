# CPH2521 GhostLock checkpoint — freeze before mode-4 root fixes

**Date:** 2026-08-01  
**Device:** OPPO Reno 10 Pro Plus (CPH2521)  
**Build:** CPH2521_16.0.5.1002(EX01)  
**Kernel:** `5.10.236-android12-9-o-g74d132f4467a`  
**Repo:** `ghostlock-oneplus` (JoinChang / local CPH2521 port)  
**CVE:** GhostLock CVE-2026-43499 (futex PI UAF + pselect stack reclaim)

This checkpoint freezes **what is proven on-device** and **what is still open**
before further structural work on the mode-4 fops redirect / root path.

---

## 1. Proven on-device (do not re-open without new evidence)

| Item | Value / status |
|------|----------------|
| Offsets table match | uname → `cph2521/offsets.h` |
| KIMAGE `_text` | `0xffffffc008000000` |
| KPHYS (Qualcomm) | `0xa8000000` (P0 delta `0x28000000`) |
| `mm_struct` | size **0x3c0**, SLUB **order-2** (from Image) |
| Waiter (disasm) | task@**0x30**, lock@**0x38**, pi_tree@**0x18**, prio@**0x40**, deadline@**0x48** |
| `task_pi_lock` / `pi_waiters` | **0x86c** / **0x880** |
| CFI | fops use **`.cfi_jt`**, not raw funcs |
| fops layout | Android 5.10 + `mmap_supported_flags` → open@**0x70** |
| `ashmem_misc+0x10` | → `ashmem_fops` (Image dump) |
| **PSELECT_SHIFT** | **`-2`** survives pselect; `0` softboots at overlay |
| Mode-4 shape (working-ish) | `write_pc=fake_fops`, **`right=MISC`**, `left=0`, heap `waiter_task=init_task` |
| Mode-4 shapes that softboot | `left=MISC`; heap `waiter_task=fake_task` |
| Clean-boot KS | attempt=1 when uptime ≲ 45s |
| Route signal | often `calls=1 success=1` with shift=-2 |
| **CFI write** | **always `ret=-1 errno=22`** after open OK |

### Interpretation of errno 22

Real `ashmem_fops` has **`.write == NULL`** (uses `read_iter` only).  
Successful `open(/dev/ashmem*)` + failed `pwrite` with EINVAL means:

> **`ashmem_misc.fops` was not replaced** by `fake_fops`.  
> Route “success” is **not** proof the PI write-what-where landed.

---

## 2. Binary / build freeze

| File | Notes |
|------|--------|
| `ghostlock-cph2521` | Checkpoint copy in this dir (~116208 bytes) |
| `build_cph2521.ps1` | `-DGHOSTLOCK_KERNEL_5_10=1`, `-DPSELECT_WAITER_WORD_SHIFT=(-2)`, mm 0x3c0 order 2, SKB default -0xe80 |
| Durable logs | `stage.txt` fsync markers + `fflush` on `pr_*` |

**Runtime env for one-shot tests:**

```text
KPHYS=0xa8000000
PSELECT_SHIFT=-2
SKB_DATA_DELTA=-0xe80
SKIP_DRAIN=1
LIGHT_DRAIN=1
```

(SHIFT is also baked into the build default.)

---

## 3. Best clean-boot log snapshot

Copied under `logs/` from `mode4_go` (right=MISC, init_task, shift=-2):

- Survives multiple pselect routes  
- Mode-4 + Write1×2: each ends `cfi write ret=-1 errno=22`  
- Softboot later on Write1 attempt 3 during spray (heap stress / KS fail)

Key shape line:

```text
mode4 write shape parent=<fake_fops> right=<misc_p0> left=0 waiter_task=init_task
```

---

## 4. Open problems (next phase — “root fixes”)

Priority order (structure, not reboot matrix):

1. **Mode-4 PI write actually commits to `*ASHMEM_MISC_FOPS`**
   - Compare pi_tree erase / rb_set_parent shape carefully to working ports  
   - Confirm spray page reclaim + lock waiters list walk on 5.10  
   - Optional: probe whether write lands elsewhere (wrong address alias)
2. **KASLR / CFI JT runtime VAs**  
   - Fake fops currently use link-time `KIMAGE+off` with `kaslr_done=1 slide=0`  
   - If fops *did* redirect with wrong JT, open would CFI-fail; today open works ⇒ still no redirect  
   - Still need correct JT once redirect works
3. **SKB_DATA_DELTA** fine-tune only if write lands off-object  
4. **Post-redirect:** configfs bin private_data / CFG_* offsets for physrw  
5. **UMH / KSU** only after stable 1-byte SELinux or pipe physrw  

**Stop doing:** blind PSELECT_SHIFT reboot matrices; uptime-only thrashing.

---

## 5. External KB: Root-My-Galaxy PORTING.md (read carefully)

Source (not universal; many open issues; **device-untested profiles** in places):

- https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/main/docs/PORTING.md  
- 5.10 no-BTF sibling: `docs/SM-A155N-A155NKSS6BYH1.md`  
- Main PORTING example is **S24 FE 6.1**, not Oppo.

### Use as methodology, not numbers

**Good practices to mirror:**

- Exact firmware identity + kernel SHA before any offset table  
- Recover symbols (vmlinux-to-elf / kallsyms); BTF when present  
- **Never copy** `P0_KERNEL_PHYS_LOAD`, waiter layout, or fops field offsets across SoCs  
- `ASHMEM_MISC_FOPS = ashmem_misc + 0x10` (same as us)  
- PSELECT word shift = **qword count** in read/write/except logical array; **not portable default 0**  
- Slide/oracle (nfulnl_logger name ptr, boot_id sysctl slot) as separate macros  
- 5.10 may need **legacy 0x50-byte waiter** (A155N) vs 6.x 0x70  

**A155N 5.10 layout (Samsung) — compares well to CPH2521 disasm:**

| Field | A155N (doc) | CPH2521 (ours) |
|-------|-------------|----------------|
| waiter pi_tree | 0x18 | 0x18 ✓ |
| waiter task/lock | 0x30 / 0x38 | 0x30 / 0x38 ✓ |
| waiter prio/deadline | 0x40 / 0x48 | 0x40 / 0x48 ✓ |
| sizeof waiter | 0x50 | assumed 5.10 ✓ |
| task pi_lock / pi_waiters | 0x86c / 0x880 | 0x86c / 0x880 ✓ |
| mm_struct size | 0x3c0 | 0x3c0 ✓ |
| mm slab order | **3** | **2** (our packing choice) |
| PSELECT shift | **0** (their claim) | **−2** (device-measured) |
| P0_KERNEL_PHYS_LOAD | 0x40000000 (MTK) | **0xa8000000** (QC) |
| configfs read symbol | `configfs_read_file` | `configfs_read_bin_file` JT |

**Do not copy from Galaxy:**

- Any numeric offset table, event IDs, P0 fingerprint rows  
- Phys load from sboot/LK of another OEM  
- Assume BTF exists (CPH2521: no usable BTF; we used disasm)  
- Their “hardware execution remains unverified” profiles as proof of life  

Local notes: `EXTERNAL_KB_Root-My-Galaxy.md` (summary only).

---

## 6. Artifact index (this folder)

```text
CHECKPOINT.md                 — this file
EXTERNAL_KB_Root-My-Galaxy.md — Samsung guide takeaways
STRUCTURAL_FINDINGS.md        — earlier offline analysis
ghostlock-cph2521             — binary freeze
build_cph2521.ps1
util.c / fops.c / cph2521_offsets.h
logs/exploit_plain.txt, stage.txt, exploit_raw.txt
```

Repo git checkpoint: see `git log` message `checkpoint: CPH2521 shift=-2 ...` if committed.

---

## 7. Resume checklist

1. Read this file + best log in `logs/`  
2. Diff mode-4 pi_tree packing vs JoinChang Ace / CyberMeowfia tokay **with 5.10 waiter size 0x50**  
3. One-shot test only after a structural change; catch uptime ≤ 50s  
4. ADB: never `pull` whole `ghostlock_logs` (200MB traces); pull named small files only  
5. Spawn: avoid hanging `adb shell '… &'` without detaching properly  

**Checkpoint status: FROZEN — safe to explore mode-4 / root fixes from here.**
