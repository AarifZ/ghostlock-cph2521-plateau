#!/usr/bin/env python3
"""Map file_operations field offsets from CPH2521 kernel Image."""
import struct
from pathlib import Path

KBASE = 0xFFFFFFC008000000
ROOT = Path(r"C:\Users\LENOVO\Desktop\HILY installer\Oppo")
data = (ROOT / "kernel").read_bytes()
syms = {}
for line in (ROOT / "kallsyms.txt").read_text(encoding="utf-8", errors="replace").splitlines():
    p = line.split()
    if len(p) >= 3:
        try:
            syms[p[2]] = int(p[0], 16)
        except ValueError:
            pass
rev = {v: k for k, v in syms.items()}


def dump(name: str, n: int = 40) -> None:
    va = syms[name]
    off = va - KBASE
    print(f"\n=== {name} @ 0x{va:x} off=0x{va - KBASE:08X} ===")
    for i in range(n):
        val = struct.unpack_from("<Q", data, off + i * 8)[0]
        nm = rev.get(val, "")
        print(f"  +0x{i * 8:02x}: 0x{val:016x}  {nm}")


def show_layout(name: str, slots: dict) -> None:
    va = syms[name]
    off = va - KBASE
    print(f"\n--- {name} mapped ---")
    for n, o in slots.items():
        val = struct.unpack_from("<Q", data, off + o)[0]
        print(f"  {n:24s} +0x{o:02x}: {rev.get(val, hex(val))}")


dump("ashmem_fops", 36)
dump("configfs_bin_file_operations", 36)
dump("configfs_file_operations", 36)

# Layout A: classic without mmap_supported_flags (matches target.h partially)
slots_classic = {
    "owner": 0x00,
    "llseek": 0x08,
    "read": 0x10,
    "write": 0x18,
    "read_iter": 0x20,
    "write_iter": 0x28,
    "iopoll": 0x30,
    "iterate": 0x38,
    "iterate_shared": 0x40,
    "poll": 0x48,
    "unlocked_ioctl": 0x50,
    "compat_ioctl": 0x58,
    "mmap": 0x60,
    "open": 0x68,
    "flush": 0x70,
    "release": 0x78,
    "fsync": 0x80,
    "fasync": 0x88,
    "lock": 0x90,
    "sendpage": 0x98,
    "get_unmapped_area": 0xA0,
    "check_flags": 0xA8,
    "flock": 0xB0,
    "splice_write": 0xB8,
    "splice_read": 0xC0,
    "setlease": 0xC8,
    "fallocate": 0xD0,
    "show_fdinfo": 0xD8,
    "copy_file_range": 0xE0,
    "remap_file_range": 0xE8,
    "fadvise": 0xF0,
}

# Layout B: with mmap_supported_flags after mmap (common on Android)
slots_android = {
    "owner": 0x00,
    "llseek": 0x08,
    "read": 0x10,
    "write": 0x18,
    "read_iter": 0x20,
    "write_iter": 0x28,
    "iopoll": 0x30,
    "iterate": 0x38,
    "iterate_shared": 0x40,
    "poll": 0x48,
    "unlocked_ioctl": 0x50,
    "compat_ioctl": 0x58,
    "mmap": 0x60,
    "mmap_supported_flags": 0x68,
    "open": 0x70,
    "flush": 0x78,
    "release": 0x80,
    "fsync": 0x88,
    "fasync": 0x90,
    "lock": 0x98,
    "sendpage": 0xA0,
    "get_unmapped_area": 0xA8,
    "check_flags": 0xB0,
    "flock": 0xB8,
    "splice_write": 0xC0,
    "splice_read": 0xC8,
    "setlease": 0xD0,
    "fallocate": 0xD8,
    "show_fdinfo": 0xE0,
    "copy_file_range": 0xE8,
    "remap_file_range": 0xF0,
    "fadvise": 0xF8,
}

# Layout C: target.h (llseek at 0x10 - implies something before?)
slots_target = {
    "owner": 0x00,
    "??": 0x08,
    "llseek": 0x10,
    "read": 0x18,
    "write": 0x20,
    "read_iter": 0x28,
    "write_iter": 0x30,
    "unlocked_ioctl": 0x50,
    "compat_ioctl": 0x58,
    "mmap": 0x60,
    "open": 0x68,
    "release": 0x78,
    "splice_read": 0xB8,
    "show_fdinfo": 0xD8,
}

print("\n================ SCORE LAYOUTS ================")
for label, slots in [
    ("classic", slots_classic),
    ("android+mmap_flags", slots_android),
    ("target.h", slots_target),
]:
    print(f"\n### {label}")
    show_layout("ashmem_fops", slots)
    show_layout("configfs_bin_file_operations", slots)

# Score: how many known ashmem symbols land on expected fields
expect_ashmem = {
    "llseek": "ashmem_llseek.cfi_jt",
    "read_iter": "ashmem_read_iter.cfi_jt",
    "unlocked_ioctl": "ashmem_ioctl.cfi_jt",
    "compat_ioctl": "compat_ashmem_ioctl.cfi_jt",
    "mmap": "ashmem_mmap.cfi_jt",
    "open": "ashmem_open.cfi_jt",
    "release": "ashmem_release.cfi_jt",
    "show_fdinfo": "ashmem_show_fdinfo.cfi_jt",
}
expect_cfg = {
    "read": "configfs_read_bin_file.cfi_jt",
    "write": "configfs_write_bin_file.cfi_jt",
    "llseek": None,  # may be generic
    "open": "configfs_open_bin_file.cfi_jt",
    "release": "configfs_release_bin_file.cfi_jt",
}


def score(name: str, slots: dict, expect: dict) -> int:
    va = syms[name]
    off = va - KBASE
    sc = 0
    for field, want in expect.items():
        if field not in slots or want is None:
            continue
        val = struct.unpack_from("<Q", data, off + slots[field])[0]
        got = rev.get(val, "")
        if got == want:
            sc += 1
        else:
            print(f"  miss {name}.{field}: want {want} got {got or hex(val)}")
    return sc


print("\n================ SCORES ================")
for label, slots in [
    ("classic", slots_classic),
    ("android+mmap_flags", slots_android),
    ("target.h", slots_target),
]:
    sa = score("ashmem_fops", slots, expect_ashmem)
    sc = score("configfs_bin_file_operations", slots, expect_cfg)
    print(f"{label}: ashmem={sa}/{len(expect_ashmem)} configfs_bin={sc}/{len([v for v in expect_cfg.values() if v])}")
