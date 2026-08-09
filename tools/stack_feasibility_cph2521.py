#!/usr/bin/env python3
"""Static stack overlay estimate for CPH2521 from kallsyms + Image.

Uses real VAs (not string-search). Frame sizes from prologues; waiter/stack_fds
from add-sp / zero-store patterns. PSELECT_SHIFT cannot be proven static-only
(compiler/PGO) but this prints a best estimate and a safe try order.
"""
from __future__ import annotations

import struct
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    raise SystemExit("pip install capstone")

ROOT = Path(r"C:\Users\LENOVO\Desktop\HILY installer\Oppo")
KERNEL = ROOT / "kernel"
KALL = ROOT / "kallsyms.txt"
KBASE = 0xFFFFFFC008000000


def load_syms() -> dict[str, int]:
    out = {}
    for line in KALL.read_text(encoding="utf-8", errors="replace").splitlines():
        p = line.split()
        if len(p) >= 3:
            try:
                out[p[2]] = int(p[0], 16)
            except ValueError:
                pass
    return out


def analyze_func(data: bytes, va: int, size: int = 0x400) -> dict:
    off = va - KBASE
    code = data[off : off + size]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    frame = 0
    zero_sp = []
    add_sp = []
    for insn in md.disasm(code, va):
        op = insn.op_str
        if insn.mnemonic == "sub" and op.startswith("sp, sp, #"):
            try:
                frame += int(op.split("#")[-1], 0)
            except ValueError:
                pass
        if insn.mnemonic == "stp" and "sp" in op and "#-" in op and "x29" in op:
            try:
                frame += int(op.split("#-")[-1].rstrip("]!"), 0)
            except ValueError:
                pass
        if insn.mnemonic in ("str", "stp") and "xzr" in op and "sp" in op and "#" in op:
            try:
                val = int(op.split("#")[-1].rstrip("]!"), 0)
                zero_sp.append(val)
            except ValueError:
                pass
        if insn.mnemonic == "add" and ", sp, #" in op:
            try:
                val = int(op.split("#")[-1], 0)
                add_sp.append(val)
            except ValueError:
                pass
        # stop after a while for large funcs
        if insn.address > va + 0x180 and frame and (zero_sp or add_sp):
            # keep scanning a bit more for futex waiter
            if insn.address > va + size:
                break
    return {
        "frame": frame,
        "zero_sp": sorted(set(zero_sp)),
        "add_sp": sorted(set(add_sp)),
    }


def main() -> None:
    data = KERNEL.read_bytes()
    syms = load_syms()
    print(f"kernel={KERNEL} size={len(data)} syms={len(syms)}")

    funcs = [
        "futex_wait_requeue_pi",
        "core_sys_select",
        "__arm64_sys_pselect6",
        "__arm64_sys_select",
        "do_select",
        "task_blocks_on_rt_mutex",
    ]
    info = {}
    for name in funcs:
        va = syms.get(name)
        if not va:
            print(f"MISSING {name}")
            continue
        info[name] = analyze_func(data, va)
        print(f"\n{name} @ 0x{va:x}")
        print(f"  frame≈0x{info[name]['frame']:x} ({info[name]['frame']})")
        print(f"  add sp offsets (first 12): { [hex(x) for x in info[name]['add_sp'][:12]] }")
        zs = info[name]["zero_sp"]
        if zs:
            print(f"  zero-stores sp range: 0x{min(zs):x}..0x{max(zs):x} count={len(zs)}")

    # Heuristic from GhostLock docs / Ace 6T class
    futex = info.get("futex_wait_requeue_pi", {})
    sel = info.get("core_sys_select", {})
    psel = info.get("__arm64_sys_pselect6", {})
    ssel = info.get("__arm64_sys_select", {})

    # Waiter local often at add sp,#0x70 on this Image (prior disasm)
    waiter_off = 0x70
    if 0x70 in futex.get("add_sp", []):
        waiter_off = 0x70
    elif futex.get("add_sp"):
        # pick mid-range add
        cands = [x for x in futex["add_sp"] if 0x40 <= x <= 0x120]
        if cands:
            waiter_off = cands[0]

    # stack_fds: largest contiguous zero-store cluster in core_sys_select lower frame
    stack_fds = 0x50
    zs = sel.get("zero_sp", [])
    if zs:
        # cluster around 256-byte SELECT_STACK_ALLOC
        for base in sorted(zs):
            span = sum(1 for z in zs if base <= z < base + 0x100)
            if span >= 20:
                stack_fds = base
                break

    print("\n===== ESTIMATE =====")
    print(f"futex frame≈0x{futex.get('frame', 0):x} waiter_local≈sp+0x{waiter_off:x}")
    print(f"core_sys_select frame≈0x{sel.get('frame', 0):x} stack_fds≈sp+0x{stack_fds:x}")
    print(f"pselect6 frame≈0x{psel.get('frame', 0):x} select frame≈0x{ssel.get('frame', 0):x}")

    # Rough SP at stack_fds vs waiter when same kernel stack page reused:
    # Not reliable static-only; report Ace-class try matrix.
    # GhostLock: estimated_waiter_word = (sp_diff/8) + base_word
    # With default layout base waiter word 2 for task@0x30 on 5.10 (word 8 = 2+6).
    print(
        """
5.10 waiter fields in pselect words (shift=0, Ace layout base word 2):
  task  @ waiter+0x30 → global word 8
  lock  @ waiter+0x38 → global word 9
Feasible if task/lock land in controllable fd_set words 0..14.

Recommended PSELECT_SHIFT try order (each wrong guess can soft-reboot):
  0, -2, 2, -4, 1, -1, 4, -6
Start at 0 on fresh boot (<30s uptime), KPHYS=0xa8000000.
"""
    )
    print("Static analysis CANNOT prove feasibility (PGO/LTO). Device trial required.")


if __name__ == "__main__":
    main()
