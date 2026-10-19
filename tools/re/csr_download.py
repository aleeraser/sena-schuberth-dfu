#!/usr/bin/env python3
"""Full CSR-download over transport B (vendor QCC-BT phase @0x10004cb34):
0x50 arm -> 0x05 start -> 0x06 chunks [01 06 lenBE16 data(<=1019)]* ->
0x0E last -> 0x07 commit -> 0x08 reboot. Per-chunk ack per vendor primitive
100108a72 (retry while status==1). Stages the COMPLETE SC2.img; the device
validates at commit. Checks version afterwards (draining stale replies)."""
import sys, time
from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.rawusb import RawHandle, RawUsbError

IMG = "/home/alessandro/git/reverse-engineer/schuberth-firmware-updater/firmware/sc2v2-2.4.0.0.img"
CHUNK = 1019

def main():
    data = open(IMG, "rb").read()
    c = parse_sena_container(data)
    img = c.images[0]
    blob = img.blob(data)
    print(f"staging {img.name} {len(blob)} B in {-(-len(blob)//CHUNK)} chunks")

    h = RawHandle(0x3217)

    def drain():
        while h.read_bulk(timeout_ms=200):
            pass

    def cmd(cmd, body=b"", label="", wait=True):
        try:
            h.write_bulk(cmd, body)
        except RawUsbError as e:
            print(f"B {cmd:#02x} {label}: write err {e}")
            return b""
        if not wait:
            return b""
        rep = b""
        for _ in range(8):
            rep = h.read_bulk(timeout_ms=600)
            if rep:
                break
        print(f"B {cmd:#02x} {label}: {rep[:8].hex() if rep else 'NO REPLY'}")
        return rep

    drain()
    # c1b sends frames EXACTLY as built: [01 cmd 00 00...] (the FF was only a
    # sentinel in the reply buffer; see sub_100108c1b disasm)
    cmd(0x01, b"", "ver")
    cmd(0x50, b"", "arm")
    cmd(0x05, b"", "start")

    off = 0
    t0 = time.monotonic()
    nchunk = 0
    while off < len(blob):
        ch = blob[off:off + CHUNK]
        last = off + CHUNK >= len(blob)
        ccode = 0x0E if last else 0x06
        # vendor frame: [01 cmd lenBE16 data...]  (length at [2..3], data at [4:])
        body = len(ch).to_bytes(2, "big") + ch
        try:
            h.write_bulk(ccode, body)
        except RawUsbError as e:
            print(f"chunk at {off}: write err {e}")
            return 1
        # vendor ack primitive 100108a72: success unless device says busy ([2]==1);
        # a read error also just continues the loop (vendor falls through too)
        status = None
        for _ in range(20):
            rep = h.read_bulk(timeout_ms=1000)
            if not rep:
                continue
            if all(x == 0 for x in rep):
                continue  # idle zero report
            if len(rep) > 2 and rep[1] == ccode:
                status = rep[2]
                if status != 1:
                    break
        if status == 2 and nchunk < 3:
            print(f"chunk at {off}: status 2 early — aborting to inspect")
            return 1
        off += len(ch)
        nchunk += 1
        if nchunk % 200 == 0:
            print(f"  staged {off}/{len(blob)} ({time.monotonic()-t0:.0f}s)", flush=True)
    print(f"all {nchunk} chunks done in {time.monotonic()-t0:.0f}s")

    cmd(0x07, b"", "COMMIT [01 07 00]")
    time.sleep(2)
    cmd(0x08, b"", "reboot [01 08 00]", wait=False)
    print("waiting 12s for device to come back...")
    time.sleep(12)
    try:
        h2 = RawHandle(0x3217)
        # drain stale pushes first, then query and wait for the 0x01 echo
        while h2.read_bulk(timeout_ms=300):
            pass
        h2.write_bulk(0x01, b"\xff")
        rep = b""
        for _ in range(10):
            rep = h2.read_bulk(timeout_ms=800)
            if rep and rep[1] == 0x01:
                break
        if rep and len(rep) > 6 and rep[1] == 0x01 and rep[2] == 0:
            print("version now:", ".".join(str(x) for x in rep[3:7]))
        else:
            print("version query:", rep[:8].hex() if rep else "NO REPLY (may need replug)")
    except RawUsbError as e:
        print("reopen failed:", e, "(may need replug)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
