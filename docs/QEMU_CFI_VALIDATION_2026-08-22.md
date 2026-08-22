# QEMU CFI validation + 5.10 slot ground truth — 2026-08-22

## What was proven (QEMU, real CPH2521 kernel Image, nokaslr)

Manual-swap harness (`qemu_cph/cfitest.py` + `rsp.py` RSP client):
spray → RSP pokes `ashmem_misc.fops = <real sprayed table>` → guest runs
`try_cfi_stage` (CFI_TEST mode). Result:

```
cfi write ret=35          ← configfs_write_bin_file copied 35 bytes to
                             binwrite_target — ARBITRARY WRITE WORKS
file: f_op=<real table> f_mode CAN_WRITE=1 CAN_READ=1
private_data blob at name+0xb exactly as designed (bin_buffer+size visible)
```

- kCFI passes with genuine `.cfi_jt` pointers in every slot. **CFI is not
  a blocker.**
- errno 22 root-caused at instruction level: `vfs_write+0x30` loads
  `file->f_mode` (+0x44): bit1=FMODE_WRITE else -EBADF, **bit18=
  FMODE_CAN_WRITE else -EINVAL**. Stamped in do_dentry_open AFTER ->open
  from `f_op->write || f_op->write_iter`. ⇒ errno22 with a fresh O_RDWR fd
  means the swap did NOT land (or table slots empty) — it never meant
  "CFI blocked".

## 5.10 ground truth (Image disassembly / dumps)

- Real `configfs_bin_file_operations`: `.read=configfs_read_bin_file.cfi_jt`
  @+0x10, `.write=configfs_write_bin_file.cfi_jt` @+0x18, everything else 0.
  **On 5.10 the configfs bin fns are `.read`/`.write` style (never converted
  to `_iter`). Putting them in iter slots = kCFI panic** (QEMU-verified:
  "CFI failure (target: configfs_write_bin_file.cfi_jt)").
  JoinChang's `write_iter` arrangement is 6.x-only. Our offsets already
  pointed at these JTs (kallsyms names).
- `configfs_buffer`: private_data@file+0xd8, page+0x10, mutex 0x20..0x50,
  needs_read_fill+0x50, read_in_progress+0x54 (must be 0), write_in_progress
  +0x55, bin_buffer+0x58, bin_buffer_size+0x60 (32-bit, bounds the copy),
  cb_max_size+0x64 (only read on the vmalloc growth path — skipped when
  size ≥ pos+len).
- `ashmem_area.name` @ +0xb (SET_NAME memcpy dest `add x0, x19, #0xb`)
  ⇒ ASHMEM_NAME_PREFIX_LEN=11 confirmed. Default name "dev/ashmem/".
- Read primitive on 5.10 must use a SMALL pos (JoinChang's huge
  ASHMEM_PREFIX_COUNT-derived pos fails the 32-bit size bound) —
  `configfs_read_once` now uses pos=0x1000, bin_buffer=target-pos.

## Code changes

- `put_fake_fops_table`: 5.10 = configfs JTs in `.read/.write` (+0x10/+0x18),
  iters zero; rb_leaf shell keeps +0x10 = 0 (guard added); CLONE_CFG same.
- `MODE4_JOINCHANG=1`: arms W0.pi write shape {parent=fake_fops,
  right=MISC_P0, left=0} + fake_task.pi_waiters→&W0.pi (compact 5.10 offsets
  pi_tree@0x18 from build defines). rb_erase right-child-only path writes
  `child->__rb_parent_color = pc` → `*MISC_FOPS = fake_fops`, red ⇒ no
  rebalance.
- `do_one_write` mode4: post-walk `try_cfi_stage` now unconditional
  (verifies + restores ashmem_misc.fops).
- `CFI_TEST` QEMU mode + `QEMU_INIT` mknod/KPHYS auto-setup +
  `RECLAIM_DELAY_MS` knob.

## Device fires today (3, all softboot — stopped per policy)

| Tag | Env | Signature |
|-----|-----|-----------|
| JC1 | MODE4_JOINCHANG=1 | walk clean, NO cfi markers (gated off), softboot AFTER process exit |
| JC2 | MODE4_JOINCHANG=1 + unconditional cfi | cfi_open_ok → pwrite errno22 (swap NOT landed at open) → softboot after exit |
| WPS1 | WRITE_PROOF+WPROOF_SPRAY | softboot DURING pselect (before walk output) |

## Open problem (sharply defined)

**Heap placement**: in QEMU the reclaim frag lands ~0x31bf00 BELOW the
leaked base (wide-scan verified; base page = live mm slab, never freed).
JC2 errno22 + WPS1 mid-walk crash are consistent with the same miss on
device (fake_fops → uncontrolled page). The WPROOF_SPRAY MSG_PEEK oracle
exists but its fire softbooted — needs QEMU-grade analysis of the
KernelSnitch free/reclaim choreography (per-cpu partial lists, RCU-delayed
mmdrop) before more device cycles.

## QEMU harness notes

- `qemu_cph/cfitest.py`: boots, waits for "CFI_TEST armed", RSP-pokes
  MISC.fops (wide-scans for the ioctl-JT anchor and repokes at the REAL
  table if the reclaim missed), breakpoints write_bin JT, inspects the
  file struct, resumes.
- lldb.exe on this host is broken (0xC0000135) — use `rsp.py` (raw GDB
  RSP: read/write mem, Z0 breakpoints, p-reg reads).
- Static guest build: `build_qemu_static.ps1` (-static -ldl; dynamic binary
  can't exec in the initramfs).
