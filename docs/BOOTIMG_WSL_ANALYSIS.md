# CPH2521 boot.img analysis & WSL lab plan

**Image:** `CPH2521_16.0.5.1002_EX01_boot.img` (~192 MB)  
**Goal:** offline control (disasm, offsets, reclaim geometry) — not a full phone emulator root lab.

## Can we “boot” this image somewhere with full control?

| Approach | Realistic? | Notes |
|----------|------------|--------|
| **QEMU full Android boot** of this `boot.img` | **Poor / high effort** | Qualcomm SoC + vendor blobs; no public machine model for Reno 10 Pro+. Kernel alone may panic without device tree / firmware. |
| **QEMU aarch64 “kernel only”** (`Image` + initramfs) | **Limited** | Can sometimes start until first hardware probe; rarely useful for GhostLock (needs futex/ashmem/mm SLUB like the phone). |
| **Static analysis (vmlinux / Image)** | **Best ROI** | Extract `Image`/`vmlinux`, disasm `rb_erase` / `remove_waiter` / fops, re-check offsets. No softboot risk. |
| **Device (real phone)** | **Only full end-to-end** | Plateau + experiments still need clean boots on hardware. |
| **Cloud Android farms** | **Usually no** | No raw boot.img replace on locked BL; no kernel debug. |

**Recommendation:** treat boot.img as a **symbol/disasm oracle**, not a substitute for the phone. Full-control “find root offline” for this vendor kernel is not practical without a matching virtual platform (we do not have one).

## What *is* worth doing in WSL Ubuntu

1. Unpack `boot.img` → kernel `Image` / ramdisk  
2. Extract `vmlinux` if compressed  
3. `llvm-nm` / `llvm-objdump` / Ghidra / IDA on `remove_waiter`, `rb_erase`, ashmem fops  
4. Optional: BTF/`pahole` if present (CPH often has little BTF)  
5. Keep phone for one-shot runtime tests only  

## Disk space (WSL / spare drive)

| Item | Space |
|------|--------|
| boot.img | ~0.2 GB |
| Unpacked Image + ramdisk | ~0.1–0.3 GB |
| vmlinux (if extracted) | ~0.05–0.2 GB |
| Android NDK (if building in WSL) | ~3–5 GB |
| LLVM/clang tools | ~1–2 GB |
| Ghidra (optional) | ~1 GB + project DB ~0.5–2 GB |
| aarch64 cross binutils | ~0.5 GB |
| Working room / logs | ~2 GB |
| **Comfortable total** | **~12–15 GB free** |
| **Minimum (static only, no NDK)** | **~4–6 GB free** |

Copy to a drive with **≥20 GB free** if you also want NDK + Ghidra.

## Tools to install (Ubuntu WSL)

```bash
sudo apt update
sudo apt install -y \
  build-essential git python3 python3-pip \
  binutils-aarch64-linux-gnu \
  lz4 gzip bzip2 xz-utils cpio \
  device-tree-compiler \
  file binwalk \
  curl wget

# unpack helpers (pick one pipeline you like)
pip3 install --user unpackbootimg  # or use magiskboot / abootimg if preferred

# optional reverse engineering
# Ghidra: download from NSA/GitHub releases (needs Java)
sudo apt install -y default-jre-headless
```

Useful binaries often copied from Android tree or releases:

- `magiskboot` (unpack/repack boot)  
- `extract-vmlinux` / `vmlinux-to-elf`  
- `llvm-objdump` / `llvm-nm` (from NDK or `apt install llvm`)  

## Suggested layout on spare drive

```text
D:\cph-lab\   or  /mnt/d/cph-lab/
  boot.img                    # copy of CPH2521_..._boot.img
  work/                       # unpack here
  tools/                      # magiskboot, extract-vmlinux
  ghidra_projects/            # optional
```

## Analysis checklist (offline)

1. `magiskboot unpack boot.img` → `kernel`  
2. Identify compression; extract vmlinux if needed  
3. Disasm (kallsyms + Image):
   - `rt_mutex_remove_waiter` / `remove_waiter`  
   - `rb_erase` / `rb_erase_cached`  
   - `ashmem_misc` / fops table slots (CFI JT)  
4. Confirm CPH waiter: task@0x30 lock@0x38 pi@0x18  
5. Diff conclusions against `CPH2521_CLOSEST_CHECKPOINT.md`  

## Runtime experiment policy (phone)

- Plateau default: **do not break** (`success=1`, `cfi errno=22`, ALIVE).  
- New shapes: **env-gated**, branch/exp binary, one clean boot, softboot = reject.  
- Merge to plateau/upstream **only** if: no softboot + better than errno 22 + retest.

### Env flags added for Samsung mapping

| Env | Meaning |
|-----|---------|
| (default) | Plateau baseline |
| `MODE4_A53_STAMP=1` | Exact A53 `write_set[1/2]` + `except[2/3]` layout |
| `MODE4_CLASSIC_MAPPED=1` | Classic via our shift=-2 waiter words (known softboot risk) |

## Bottom line

- **Full control boot of this boot.img:** not realistic as a root-dev VM.  
- **Full control analysis of the kernel image:** yes, WSL is enough.  
- **Proof of root:** still the physical CPH2521.  
