#!/usr/bin/env python3
"""Deep analysis of CPH2521 boot.img kernel for GhostLock porting."""
import struct
import sys
from pathlib import Path

KERNEL = Path(r"C:\Users\LENOVO\Desktop\HILY installer\Oppo\kernel")
KALLSYMS = Path(r"C:\Users\LENOVO\Desktop\HILY installer\Oppo\kallsyms.txt")
KBASE = 0xFFFFFFC008000000
data = KERNEL.read_bytes()


def va_to_off(va: int) -> int:
    return va - KBASE


def read_u32(off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_u64(off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def load_syms() -> dict[str, int]:
    out = {}
    for line in KALLSYMS.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                out[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    return out


def disasm_range(va: int, size: int, label: str = "", max_lines: int = 80) -> list[str]:
    lines = []
    off = va_to_off(va)
    lines.append(f"\n===== {label} @ 0x{va:x} (file+0x{off:x}) =====")
    n = 0
    for i in range(0, size, 4):
        if n >= max_lines:
            lines.append("  ...")
            break
        insn = read_u32(off + i)
        pc = va + i
        # ADRP
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            page = (pc & ~0xFFF) + (imm << 12)
            lines.append(f"  {pc:x}: adrp x{rd}, 0x{page:x}")
            n += 1
            continue
        # ADD imm
        if (insn & 0x7F800000) in (0x11000000, 0x91000000):
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 1
            imm = imm12 << (12 if sh else 0)
            sf = "x" if (insn >> 31) & 1 else "w"
            lines.append(f"  {pc:x}: add {sf}{rd}, {sf}{rn}, #0x{imm:x}")
            n += 1
            continue
        # SUB imm
        if (insn & 0x7F800000) in (0x51000000, 0xD1000000):
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 1
            imm = imm12 << (12 if sh else 0)
            sf = "x" if (insn >> 31) & 1 else "w"
            lines.append(f"  {pc:x}: sub {sf}{rd}, {sf}{rn}, #0x{imm:x}")
            n += 1
            continue
        # MOVZ/MOVK/MOVN
        if (insn & 0x1F800000) == 0x12800000 or (insn & 0x1F800000) == 0x52800000:
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 3
            opc = (insn >> 29) & 3
            names = {0: "movn", 2: "movz", 3: "movk"}
            sf = "x" if (insn >> 31) else "w"
            lines.append(f"  {pc:x}: {names.get(opc, 'mov?')} {sf}{rd}, #0x{imm16:x}, LSL #{hw * 16}")
            n += 1
            continue
        # STP/LDP (signed offset / pre / post simplified)
        if (insn & 0xFE000000) == 0xA8000000 or (insn & 0xFE000000) == 0xA9000000:
            imm7 = (insn >> 15) & 0x7F
            if imm7 >= 64:
                imm7 -= 128
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            off8 = imm7 * 8
            L = (insn >> 22) & 1
            kind = "ldp" if L else "stp"
            lines.append(f"  {pc:x}: {kind} x{rt}, x{rt2}, [x{rn}, #{off8:#x}]")
            n += 1
            continue
        # STR/LDR unsigned offset 64
        if (insn & 0xFFC00000) in (0xF9000000, 0xF9400000):
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            kind = "ldr" if (insn >> 22) & 1 else "str"
            lines.append(f"  {pc:x}: {kind} x{rt}, [x{rn}, #{imm12 * 8:#x}]")
            n += 1
            continue
        # LDR/STR 32-bit
        if (insn & 0xFFC00000) in (0xB9000000, 0xB9400000):
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            kind = "ldr" if (insn >> 22) & 1 else "str"
            lines.append(f"  {pc:x}: {kind} w{rt}, [x{rn}, #{imm12 * 4:#x}]")
            n += 1
            continue
        # BL
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            target = pc + imm26 * 4
            lines.append(f"  {pc:x}: bl 0x{target:x}")
            n += 1
            continue
        # RET
        if insn == 0xD65F03C0:
            lines.append(f"  {pc:x}: ret")
            n += 1
            continue
        # MOV Xd, Xm
        if (insn & 0xFFE0FFE0) == 0xAA0003E0:
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            lines.append(f"  {pc:x}: mov x{rd}, x{rm}")
            n += 1
            continue
        # CBZ/CBNZ
        if (insn & 0x7E000000) == 0x34000000:
            rt = insn & 0x1F
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target = pc + imm19 * 4
            kind = "cbnz" if (insn >> 24) & 1 else "cbz"
            sf = "x" if (insn >> 31) else "w"
            lines.append(f"  {pc:x}: {kind} {sf}{rt}, 0x{target:x}")
            n += 1
            continue
        lines.append(f"  {pc:x}: .inst 0x{insn:08x}")
        n += 1
    return lines


def find_imm_in_func(va: int, size: int) -> list[tuple[int, str, int]]:
    """Collect interesting immediates (likely sizes/offsets)."""
    hits = []
    off = va_to_off(va)
    for i in range(0, size, 4):
        insn = read_u32(off + i)
        pc = va + i
        if (insn & 0x7F800000) in (0x11000000, 0x91000000, 0x51000000, 0xD1000000):
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 1
            imm = imm12 << (12 if sh else 0)
            op = "sub" if (insn >> 30) & 1 else "add"
            if imm in (0x3B0, 0x3C0, 0x400, 0x3A0, 0x380, 0x360, 0x1A0, 0x1C0, 0x70, 0xD8,
                       0x30, 0x38, 0x40, 0x48, 0x18, 0x50, 0x58, 0x86C, 0x880, 0x890, 0x898,
                       0x778, 0x780, 0x790, 0x5C8, 0x310, 0x84, 0x8C):
                hits.append((pc, op, imm))
        # MOVZ small
        if (insn & 0xFF800000) in (0xD2800000, 0x52800000):
            imm16 = (insn >> 5) & 0xFFFF
            if imm16 in (0x3B0, 0x3C0, 0x400, 0x3A0, 0x70, 0x1A0, 0x1C0):
                hits.append((pc, "movz", imm16))
    return hits


def dump_ashmem_fops(syms: dict) -> list[str]:
    lines = []
    fops = syms.get("ashmem_fops")
    if not fops:
        return ["ashmem_fops missing"]
    off = va_to_off(fops)
    lines.append(f"\n===== ashmem_fops @ 0x{fops:x} =====")
    # file_operations layout varies; dump 32 qwords and match known symbols
    rev = {v: k for k, v in syms.items()}
    for i in range(32):
        val = read_u64(off + i * 8)
        name = rev.get(val, "")
        # also try without KASLR - values are absolute in image
        lines.append(f"  +0x{i*8:02x}: 0x{val:016x}  {name}")
    misc = syms.get("ashmem_misc")
    if misc:
        lines.append(f"\n===== ashmem_misc @ 0x{misc:x} =====")
        moff = va_to_off(misc)
        for i in range(8):
            val = read_u64(moff + i * 8)
            name = rev.get(val, "")
            lines.append(f"  +0x{i*8:02x}: 0x{val:016x}  {name}")
        # fops pointer typically at +0x10 for miscdevice
        fops_ptr = read_u64(moff + 0x10)
        lines.append(f"  misc+0x10 fops_ptr = 0x{fops_ptr:x} expected ashmem_fops=0x{fops:x} match={fops_ptr==fops}")
    return lines


def analyze_mm(syms: dict) -> list[str]:
    lines = []
    # mm_cache_init - look for size argument to kmem_cache_create
    mm_ci = syms["mm_cache_init"]
    lines.extend(disasm_range(mm_ci, 0xC0, "mm_cache_init", 60))
    hits = find_imm_in_func(mm_ci, 0xC0)
    lines.append(f"  interesting imms: {hits}")

    mm_alloc = syms["mm_alloc"]
    lines.extend(disasm_range(mm_alloc, 0x80, "mm_alloc", 40))
    hits = find_imm_in_func(mm_alloc, 0x100)
    lines.append(f"  interesting imms: {hits}")

    mmdrop = syms["__mmdrop"]
    lines.extend(disasm_range(mmdrop, 0xA0, "__mmdrop", 40))
    hits = find_imm_in_func(mmdrop, 0x120)
    lines.append(f"  interesting imms: {hits}")
    return lines


def analyze_waiter(syms: dict) -> list[str]:
    lines = []
    tb = syms["task_blocks_on_rt_mutex"]
    lines.extend(disasm_range(tb, 0x180, "task_blocks_on_rt_mutex", 90))
    hits = find_imm_in_func(tb, 0x200)
    lines.append(f"  interesting imms: {[(hex(p), o, hex(i)) for p,o,i in hits]}")

    # Also scan for stp of task/lock into waiter
    off = va_to_off(tb)
    lines.append("  STP/STR into xN (waiter candidate):")
    for i in range(0, 0x200, 4):
        insn = read_u32(off + i)
        pc = tb + i
        # STP with positive small offset
        if (insn & 0xFFC00000) == 0xA9000000:
            imm7 = (insn >> 15) & 0x7F
            if imm7 >= 64:
                imm7 -= 128
            off8 = imm7 * 8
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            if 0 <= off8 <= 0x60:
                lines.append(f"    {pc:x}: stp x{rt}, x{rt2}, [x{rn}, #{off8:#x}]")
        if (insn & 0xFFC00000) == 0xF9000000:
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            o = imm12 * 8
            if o in (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58):
                lines.append(f"    {pc:x}: str x{rt}, [x{rn}, #{o:#x}]")
        if (insn & 0xFFC00000) == 0xB9000000:
            imm12 = (insn >> 10) & 0xFFF
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            o = imm12 * 4
            if o in (0x40, 0x44, 0x48, 0x4C):
                lines.append(f"    {pc:x}: str w{rt}, [x{rn}, #{o:#x}]")
    return lines


def analyze_stack_frames(syms: dict) -> list[str]:
    lines = []
    for name in ("futex_wait_requeue_pi", "core_sys_select", "__arm64_sys_pselect6",
                 "do_select", "__arm64_sys_select"):
        va = syms.get(name)
        if not va:
            lines.append(f"MISSING {name}")
            continue
        # first 0x40 bytes for frame alloc (sub sp)
        chunk = disasm_range(va, 0x80, f"{name} prologue", 30)
        lines.extend(chunk)
        hits = find_imm_in_func(va, 0x40)
        lines.append(f"  prologue imms: {[(hex(p), o, hex(i)) for p,o,i in hits]}")
        # look for first sub sp
        off = va_to_off(va)
        for i in range(0, 0x40, 4):
            insn = read_u32(off + i)
            if (insn & 0xFF0003FF) == 0xD10003FF or (insn & 0xFF8003FF) == 0xD10003FF:
                imm12 = (insn >> 10) & 0xFFF
                sh = (insn >> 22) & 1
                imm = imm12 << (12 if sh else 0)
                lines.append(f"  FRAME sub sp, sp, #0x{imm:x}")
            # stp x29, x30, [sp, #-imm]!
            if (insn & 0xFFC003E0) == 0xA98003E0 or (insn & 0xFFC07FFF) == 0xA9BF7BFD:
                imm7 = (insn >> 15) & 0x7F
                if imm7 >= 64:
                    imm7 -= 128
                lines.append(f"  FRAME stp fp,lr [sp, #{imm7*8:#x}]!")
    return lines


def analyze_task_offsets(syms: dict) -> list[str]:
    lines = []
    for name in ("commit_creds", "get_task_cred", "rt_mutex_setprio",
                 "mark_wakeup_next_waiter", "remove_waiter", "wake_up_new_task"):
        va = syms.get(name)
        if not va:
            continue
        hits = find_imm_in_func(va, 0x300)
        if hits:
            lines.append(f"{name}: {[(hex(p), o, hex(i)) for p,o,i in hits[:20]]}")
    return lines


def slub_pack(size: int) -> list[str]:
    lines = [f"\n===== SLUB packing for obj size 0x{size:x} ({size}) ====="]
    for order in range(0, 5):
        page = 4096 << order
        n = page // size
        if n == 0:
            continue
        waste = page - n * size
        pct = 100.0 * waste / page
        lines.append(f"  order={order} page=0x{page:x} objs={n} waste={waste} ({pct:.1f}%)")
    return lines


def verify_offsets(syms: dict) -> list[str]:
    """Verify offsets.h values against kallsyms."""
    expected = {
        "init_task": 0x027CC000,
        "init_cred": 0x027E0BE0,
        "init_uts_ns": 0x027CBDA8,
        "empty_zero_page": 0x029C3000,
        "root_task_group": 0x029C8040,
        "selinux_state": 0x02A793C8,
        "kptr_restrict": 0x027BCF68,
        "selinux_blob_sizes": 0x02302940,
        "security_hook_heads": 0x023022A8,
        "kmalloc_caches": 0x02301DE0,
        "anon_pipe_buf_ops": 0x0216A7E8,
        "ashmem_fops": 0x022BFDC8,
        "ashmem_ioctl": 0x011EE7D0,
        "compat_ashmem_ioctl": 0x011EF2E0,
        "ashmem_mmap": 0x011EF340,
        "ashmem_open": 0x011EF580,
        "ashmem_release": 0x011EF620,
        "ashmem_show_fdinfo": 0x011EF744,
        "configfs_read_bin_file": 0x006B0D0C,
        "configfs_write_bin_file": 0x006B0F84,
        "generic_file_splice_read": 0x005E6C68,
        "noop_llseek": 0x0056CF68,
        "nfulnl_logger": 0x027C14B8,
        "sysctl_bootid": 0x02B99B6D,
        "system_unbound_wq": 0x027B9E88,
        "call_usermodehelper_exec_work": 0x001672AC,
    }
    lines = ["\n===== offsets.h vs kallsyms (_text-relative) ====="]
    text = syms.get("_text", KBASE)
    ok = 0
    bad = 0
    for name, exp in expected.items():
        va = syms.get(name)
        if va is None:
            lines.append(f"  MISS {name}")
            bad += 1
            continue
        got = va - text
        status = "OK" if got == exp else "MISMATCH"
        if status == "OK":
            ok += 1
        else:
            bad += 1
        lines.append(f"  {status}: {name} got=0x{got:08X} exp=0x{exp:08X}")
    # ashmem_misc + 0x10
    misc = syms.get("ashmem_misc")
    if misc:
        got = (misc - text) + 0x10
        exp = 0x0291A8E8
        status = "OK" if got == exp else "MISMATCH"
        lines.append(f"  {status}: ashmem_misc+0x10 got=0x{got:08X} exp=0x{exp:08X}")
        if status == "OK":
            ok += 1
        else:
            bad += 1
    # loggers+0x10
    loggers = syms.get("loggers")
    if loggers:
        got = (loggers - text) + 0x10
        exp = 0x027C13F0
        status = "OK" if got == exp else "MISMATCH"
        lines.append(f"  {status}: loggers+0x10 got=0x{got:08X} exp=0x{exp:08X}")
        if status == "OK":
            ok += 1
        else:
            bad += 1
    lines.append(f"  SUMMARY: {ok} OK, {bad} bad")
    return lines


def main():
    syms = load_syms()
    print(f"kernel size={len(data)} symbols={len(syms)}")
    print(f"_text=0x{syms.get('_text',0):x} _stext=0x{syms.get('_stext',0):x}")

    out = []
    out.extend(verify_offsets(syms))
    out.extend(analyze_mm(syms))
    out.extend(slub_pack(0x3C0))
    out.extend(slub_pack(0x400))
    out.extend(analyze_waiter(syms))
    out.extend(analyze_stack_frames(syms))
    out.extend(analyze_task_offsets(syms))
    out.extend(dump_ashmem_fops(syms))

    # kmalloc-cg check
    out.append(f"\nkmalloc-cg in image: {data.find(b'kmalloc-cg') >= 0}")
    out.append(f"kmalloc-8 in image: {data.find(b'kmalloc-8') >= 0}")

    text = "\n".join(out)
    print(text)
    out_path = Path(r"C:\Users\LENOVO\Desktop\HILY installer\Oppo\CPH2521_DEEP_KERNEL_ANALYSIS.txt")
    out_path.write_text(text, encoding="utf-8")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
