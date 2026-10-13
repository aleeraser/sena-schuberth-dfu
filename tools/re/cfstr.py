#!/usr/bin/env python3
"""Resolve CFStrings in the SCHUBERTH macOS binary (handles chained fixups).

Usage: cfstr.py <binary> <addr_hex> [addr_hex ...]
"""
import struct, sys

def load(path):
    data = open(path, 'rb').read()
    # fat: find x86_64 slice
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        n = struct.unpack('>I', data[4:8])[0]
        soff = None
        for i in range(n):
            ct, cpusub, offset, size, align = struct.unpack('>5I', data[8+i*20:28+i*20])
            if ct == 0x01000007:
                soff = offset
                break
    else:
        soff = 0
    magic = struct.unpack('<I', data[soff:soff+4])[0]
    hdr_off = soff + (32 if magic in (0xfeedfacf,) else 28)
    ncmds = struct.unpack('<I', data[soff+16:soff+20])[0]
    segs = []
    off = hdr_off
    for _ in range(ncmds):
        cmd, size = struct.unpack('<2I', data[off:off+8])
        if cmd == 0x19:
            name = data[off+8:off+24].split(b'\0')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack('<4Q', data[off+24:off+56])
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += size
    return data, soff, segs

def make_a2o(soff, segs):
    def a2o(a):
        for name, vmaddr, vmsize, fileoff, filesize in segs:
            if vmaddr <= a < vmaddr + vmsize:
                return soff + fileoff + (a - vmaddr)
        raise KeyError(hex(a))
    return a2o

def deref(data, a2o, val):
    """Resolve a possibly-chained-fixup 64-bit pointer value."""
    if val >> 63 and not (val >> 50) & 1:      # chained rebase (dyld_chained_ptr_64_rebase)
        target = val & 0xFFFFFFFFFF            # 40-bit offset
        high = (val >> 40) & 0xFF
        return 0x100000000 + (high << 40) + target
    return val

def cfstr(data, a2o, addr):
    ptr, ln = struct.unpack('<QQ', data[a2o(addr)+16:a2o(addr)+32])
    ptr = deref(data, a2o, ptr)
    return data[a2o(ptr):a2o(ptr)+ln].decode('utf-8', 'replace')

if __name__ == '__main__':
    path = sys.argv[1]
    data, soff, segs = load(path)
    a2o = make_a2o(soff, segs)
    for a in sys.argv[2:]:
        print(hex(int(a, 16)), repr(cfstr(data, a2o, int(a, 16))))
