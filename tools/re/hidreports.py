#!/usr/bin/env python3
"""Parse HID report descriptors and print report sizes per type/id.

Usage: hidreports.py <descriptor.bin | /sys/class/hidraw/hidrawN/device/report_descriptor>
"""
import sys


def parse(desc: bytes):
    """Yield (type, report_id, size_bits) for each Input/Output/Feature."""
    size = count = 1
    rid = 0
    i = 0
    n = len(desc)
    while i < n:
        b = desc[i]
        bsize = (b & 0x03)
        if bsize == 3:
            bsize = 4
        tag = b & 0xFC
        val = int.from_bytes(desc[i + 1:i + 1 + bsize], "little") if bsize else 0
        if tag == 0xFE:  # Long item: b0 size is the whole item size
            i += b[1] + 1 if n > 1 else 1
            continue
        if tag == 0x74:  # Global
            item = (b >> 2) & 0x0F
            if item == 0x06:    size = val
            elif item == 0x07:  count = val
            elif item == 0x08:  rid = val
        elif tag in (0x80, 0x90, 0xA0):  # Input / Output / Feature
            typ = {0x80: "In", 0x90: "Out", 0xA0: "Feat"}[tag]
            yield (typ, rid, size * count)
        i += 1 + bsize


def main():
    data = open(sys.argv[1], "rb").read()
    reports = {}
    for typ, rid, bits in parse(data):
        reports.setdefault((typ, rid), []).append(bits)
    for (typ, rid), sizes in sorted(reports.items()):
        total = sum(sizes) // 8
        print(f"{typ:4} id={rid:#04x} bits={sizes} -> {total} bytes")


if __name__ == "__main__":
    main()
