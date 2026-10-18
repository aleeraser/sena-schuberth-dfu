#!/usr/bin/env python3
"""Does 0x5B (block-CRC close) re-open staging for the next block?

update12 proved: staging block 0 then starting block 1 in the same
session -> 0x06 status 2, with or without 0x07/0x08 closes. update8
saw 0x5B itself rejected, but that run's 0x0F session cmd failed
(status 2); later runs show 0x0F succeeding. This probe, with a clean
session: stage 64 real chunks of SC2.img, send 0x5B with the running
CRC, then try a fresh 0x05 + 8 chunks. NO 0x07/0x08 -> nothing is
committed; replug afterwards clears the staging area.
"""
import sys
from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.crc import crc16_ccitt
from schuberth_dfu.rawusb import RawHandle
from schuberth_dfu.airodfu import Link, AirohaError
from schuberth_dfu.sc2flow import MeshLink, Sc2Error, CMD_START

IMG = "/tmp/opencode/sc2v2-dl.img"
CHUNK = 58

def main():
    data = open(IMG, "rb").read()
    c = parse_sena_container(data)
    blob = c.images[0].blob(data)[:CHUNK * 64]

    main_h = RawHandle(0x3217)
    link = MeshLink(main_h)
    ver = None
    for attempt in range(4):          # first reads may return stale pushes
        try:
            ver = __import__("schuberth_dfu.sc2flow",
                             fromlist=["read_version"]).read_version(link)
            break
        except Sc2Error as exc:
            print(f"B version attempt {attempt + 1}: {exc}")
    print("B version:", ".".join(map(str, ver)) if ver else "?")
    try:
        link.bulk(CMD_START)
        print("B 0x0F: status 0")
    except Sc2Error as exc:
        print("B 0x0F:", exc)

    mesh = RawHandle(0x3220)
    alink = Link(mesh, timeout=20.0)
    print("mesh 0x01(0):", alink.block_version(0).hex())
    alink.start_block()
    print("0x05 start: ok")
    running = 0
    for i in range(64):
        ch = blob[i * CHUNK:(i + 1) * CHUNK]
        dev_crc = alink.write_chunk(ch)
        our = crc16_ccitt(ch)
        if dev_crc != our:
            print(f"chunk {i}: CRC mismatch dev {dev_crc:#04x} our {our:#04x}")
            return 1
        running = crc16_ccitt(ch, running)
    print("64 chunks ok, running crc", hex(running))
    try:
        alink.block_crc(running)
        print("0x5B: ACK status 0")
    except AirohaError as exc:
        print("0x5B:", exc)
    # second staging round in the same session
    try:
        print("mesh 0x01(1):", alink.block_version(1).hex())
        alink.start_block()
        print("0x05 #2: ok")
        for i in range(8):
            ch = blob[i * CHUNK:(i + 1) * CHUNK]
            dev_crc = alink.write_chunk(ch)
            if dev_crc != crc16_ccitt(ch):
                print(f"chunk {i} (round 2): CRC mismatch")
                return 1
        print("8 chunks round 2: ACCEPTED  <-- 0x5B re-opens staging")
    except AirohaError as exc:
        print("round 2:", exc)
    print("(no 0x07/0x08 sent: nothing committed; replug to clear staging)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
