#!/usr/bin/env python3
"""Structural checks for CPH2521 GhostLock (boot.img-derived 5.10 port)."""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OFFSETS = ROOT / "src" / "devices" / "cph2521" / "offsets.h"
BUILD = ROOT / "build_cph2521.ps1"
BINARY = ROOT / "ghostlock-cph2521"
UNAME = "5.10.236-android12-9-o-g74d132f4467a"
EXPECTED = {
    "off_init_cred": 0x027E0BE0,
    "off_init_task": 0x027CC000,
    "off_ashmem_misc_fops": 0x0291A8E8,
    "off_selinux_enforcing": 0x02A793C8,
    # CFI jump tables (real ashmem_fops / configfs_bin_file_operations)
    "off_ashmem_ioctl": 0x01837928,
    "off_ashmem_open": 0x01831488,
    "off_configfs_bin_write_iter": 0x01830218,
    "off_noop_llseek": 0x0181FE48,
    "off_call_usermodehelper_exec_work": 0x0183E200,
}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"OK: {msg}")


def main() -> None:
    print(f"ROOT={ROOT}")
    text = OFFSETS.read_text(encoding="utf-8", errors="replace")
    if UNAME not in text:
        fail(f"offsets.h missing uname {UNAME}")
    ok(f"offsets.h contains uname {UNAME}")
    for name, val in EXPECTED.items():
        m = re.search(rf"\.{name}=0x([0-9A-Fa-f]+)", text)
        if not m:
            fail(f"missing {name}")
        got = int(m.group(1), 16)
        if got != val:
            fail(f"{name}: expected 0x{val:08X}, got 0x{got:08X}")
        ok(f"{name}=0x{got:08X}")

    b = BUILD.read_text(encoding="utf-8", errors="replace")
    for needle in (
        "GHOSTLOCK_KERNEL_5_10",
        "MM_STRUCT_SZ=0x3c0",
        "MM_ORDER=2",
        "WAITER_TASK_OFF=0x30",
        "KIMAGE_TEXT_BASE=0xffffffc008000000",
        "KMALLOC_CACHE_TYPES=3",
    ):
        if needle not in b:
            fail(f"build_cph2521.ps1 missing {needle}")
    ok("build_cph2521.ps1 boot.img-derived defines")

    fops = (ROOT / "src" / "core" / "fops.c").read_text(encoding="utf-8", errors="replace")
    util = (ROOT / "src" / "core" / "util.c").read_text(encoding="utf-8", errors="replace")
    target = (ROOT / "src" / "core" / "target.h").read_text(encoding="utf-8", errors="replace")
    if "GHOSTLOCK_KERNEL_5_10" not in fops or "active_offsets" not in util:
        fail("fops/util missing 5.10 / active_offsets paths")
    ok("fops.c/util.c have 5.10 + runtime offset paths")
    if "FOPS_OPEN_OFF         0x70" not in target and "FOPS_OPEN_OFF 0x70" not in target:
        # allow spacing variants
        if not re.search(r"FOPS_OPEN_OFF\s+0x70", target):
            fail("target.h missing 5.10 FOPS_OPEN_OFF 0x70 (mmap_supported_flags layout)")
    ok("target.h has Android 5.10 fops layout (open@0x70)")

    if not BINARY.is_file():
        fail(f"missing binary {BINARY}")
    data = BINARY.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or struct.unpack_from("<H", data, 18)[0] != 0xB7:
        fail("binary not ELF aarch64")
    ok(f"binary ELF aarch64 size={len(data)}")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
