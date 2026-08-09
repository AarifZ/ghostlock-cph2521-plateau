#!/usr/bin/env python3
"""Structural + log-evidence checks for CPH2521 GhostLock port.

Drives real project files (offsets.h, build script, binary, optional run logs).
Exit 0 only if hard requirements pass.
"""
from __future__ import annotations

import os
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
}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"OK: {msg}")


def test_offsets_header() -> None:
    text = OFFSETS.read_text(encoding="utf-8", errors="replace")
    if f'OFFSETS_ENTRY("{UNAME}"' not in text and f"OFFSETS_ENTRY(\"{UNAME}\"" not in text:
        # allow either quote style
        if f'OFFSETS_ENTRY("{UNAME}"' not in text:
            if UNAME not in text:
                fail(f"offsets.h missing uname {UNAME}")
    if UNAME not in text:
        fail(f"offsets.h missing uname string {UNAME}")
    ok(f"offsets.h contains uname {UNAME}")

    for name, val in EXPECTED.items():
        # match .off_init_cred=0x027E0BE0 or similar
        pat = rf"\.{name}=0x([0-9A-Fa-f]+)"
        m = re.search(pat, text)
        if not m:
            fail(f"offsets.h missing field {name}")
        got = int(m.group(1), 16)
        if got != val:
            fail(f"{name}: expected 0x{val:08X}, got 0x{got:08X}")
        ok(f"{name}=0x{got:08X}")


def test_build_script() -> None:
    text = BUILD.read_text(encoding="utf-8", errors="replace")
    if "MM_STRUCT_SZ=0x3c0" not in text and "MM_STRUCT_SZ=0x3C0" not in text:
        fail("build_cph2521.ps1 missing MM_STRUCT_SZ=0x3c0")
    if "KIMAGE_TEXT_BASE=0xffffffc008000000" not in text:
        fail("build_cph2521.ps1 missing CPH2521 KIMAGE_TEXT_BASE")
    ok("build_cph2521.ps1 has CPH2521 defines")


def test_binary_elf() -> None:
    if not BINARY.is_file():
        fail(f"missing binary {BINARY}")
    data = BINARY.read_bytes()
    if data[:4] != b"\x7fELF":
        fail("binary is not ELF")
    # EI_CLASS=2 (64-bit), EI_DATA=1 (LE), e_machine at 18 = EM_AARCH64 (0xB7)
    if data[4] != 2 or data[5] != 1:
        fail(f"ELF class/data unexpected: class={data[4]} data={data[5]}")
    e_machine = struct.unpack_from("<H", data, 18)[0]
    if e_machine != 0xB7:
        fail(f"e_machine=0x{e_machine:x}, expected EM_AARCH64")
    ok(f"binary ELF aarch64 size={len(data)}")


def test_run_log_if_present() -> None:
    """If SCRATCH or env GHOSTLOCK_RUN_LOG points at a run log, assert key lines."""
    candidates = []
    env = os.environ.get("GHOSTLOCK_RUN_LOG")
    if env:
        candidates.append(Path(env))
    scratch = os.environ.get("GHOSTLOCK_SCRATCH")
    if scratch:
        candidates.append(Path(scratch) / "cph2521_boot_run.log")
        candidates.append(Path(scratch) / "cph2521_boot_run_terminal.log")
    # default implementer scratch used by goal harness
    default_scratch = Path(
        r"C:\Users\LENOVO\AppData\Local\Temp\grok-goal-eca8d48cf307\implementer"
    )
    candidates.append(default_scratch / "cph2521_boot_run.log")
    candidates.append(default_scratch / "cph2521_boot_run_terminal.log")

    log_path = next((p for p in candidates if p.is_file() and p.stat().st_size > 0), None)
    if not log_path:
        print("SKIP: no run log present (set GHOSTLOCK_RUN_LOG to require it)")
        return

    text = log_path.read_text(encoding="utf-8", errors="replace")
    # strip ANSI
    plain = re.sub(r"\x1b\[[0-9;]*m", "", text)
    if "offsets matched" not in plain and UNAME not in plain:
        fail(f"run log {log_path} missing offset match")
    if f"offsets matched: {UNAME}" not in plain and "offsets matched" not in plain:
        fail(f"run log missing offsets matched line")
    ok(f"run log {log_path.name}: offsets matched")

    progressed = (
        "prepare_kernel_page ok" in plain
        or "mm_struct found" in plain
        or "heap spray done" in plain
    )
    failed_ks = "mm_struct leak failed" in plain or "KernelSnitch" in plain
    if progressed:
        ok("run log: progressed past KernelSnitch failure (prepare_kernel_page ok / spray done)")
    elif failed_ks:
        ok("run log: KernelSnitch failed explicitly (criterion 3b path)")
    else:
        fail("run log has neither prepare_kernel_page ok nor KernelSnitch failure")


def main() -> None:
    print(f"ROOT={ROOT}")
    test_offsets_header()
    test_build_script()
    test_binary_elf()
    test_run_log_if_present()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
