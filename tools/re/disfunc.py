#!/usr/bin/env python3
"""Disassemble a Mach-O x86_64 function range locally with capstone,
annotating rip-relative string refs and call targets.

Usage: disfunc.py <binary> <start_hex> <end_hex> [--out listing.txt]
"""
import sys, struct, argparse
from capstone import *

def find_slice(data):
    magic = data[:4]
    if magic in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        n = struct.unpack('>I', data[4:8])[0]
        for i in range(n):
            off = 8 + i*20
            cputype, cpusub, offset, size, align = struct.unpack('>5I', data[off:off+20])
            if cputype == 0x01000007:  # x86_64
                return offset, size
        raise SystemExit('no x86_64 slice')
    return 0, len(data)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary'); ap.add_argument('start'); ap.add_argument('end')
    ap.add_argument('--out')
    a = ap.parse_args()
    data = open(a.binary,'rb').read()
    soff, ssize = find_slice(data)
    start = int(a.start,16); end = int(a.end,16)
    # assume __TEXT vmaddr 0x100000000 mapped at slice offset 0 (typical PIE macОС)
    def addr2off(addr): return soff + (addr - 0x100000000)
    code = data[addr2off(start):addr2off(end)]

    def cstr(addr):
        o = addr2off(addr)
        if o < 0 or o >= len(data): return None
        s = b''
        while o < len(data) and data[o] != 0 and len(s) < 200:
            s += bytes([data[o]]); o += 1
        try: return s.decode('utf-8')
        except: return repr(s)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    lines = []
    calls = {}
    for ins in md.disasm(code, start):
        ann = ''
        if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
            tgt = None
            import re
            mm = re.search(r'\[rip ([-+]) (0x[0-9a-f]+)\]', ins.op_str)
            if mm:
                tgt = ins.address + ins.size + int(mm.group(2),16) * (-1 if mm.group(1)=='-' else 1)
            if tgt:
                s = cstr(tgt)
                ann = f'  ; -> 0x{tgt:x}' + (f'  "{s}"' if s and s.isprintable() and len(s)>1 else '')
        if ins.mnemonic in ('call','jmp') and 'rip' not in ins.op_str:
            try:
                tgt = int(ins.op_str,16)
                calls[tgt] = calls.get(tgt,0)+1
                ann = f'  ; call 0x{tgt:x}'
            except: pass
        lines.append(f'0x{ins.address:x}: {ins.bytes.hex():<12} {ins.mnemonic} {ins.op_str}{ann}')
    txt = '\n'.join(lines)
    if a.out:
        open(a.out,'w').write(txt)
        print(f'wrote {a.out}: {len(lines)} insns, {len(calls)} call targets')
    else:
        print(txt)
    if a.out:
        print('call targets (count):')
        for t,c in sorted(calls.items()):
            print(f'  0x{t:x} x{c}')

if __name__ == '__main__':
    main()
