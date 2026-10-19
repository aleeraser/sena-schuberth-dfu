#!/usr/bin/env python3
"""Vendor-exact SC2V2 main update on transport B (0x3217), reconstructed
from -[UpdateViewController threadMethodUpdate:] default path for 0x3217
(QCC-BT phase 0x10004b900-0x10004d600):

  0x0A result peek -> 0x01 ver -> 0x20 session start -> 0x22 x25 poll
  -> 0x21 confirm (vendor logs 'UPDATE START MESH HANDLE FIND' while retrying)
  -> 0x21 -> 0x20 -> 0x05 start -> 0x06 chunks [01 06 lenBE16 data<=1019]*
  -> 0x0E last -> 0x07 commit [01 07 00] -> 0x08 reboot [01 08 00].

All frames are [01 cmd 00 ...] zero-padded (c1b never touches the frame;
its FF is a reply-buffer sentinel). Chunk ack primitive 100108a72: retry
while device says busy [2]==1, otherwise continue regardless.

Requires the headset main system powered on (0x20/0x22/0x21 answer status 2
in USB charge mode). Aborts before touching flash if the handshake fails.
"""
import sys, time
from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.rawusb import RawHandle, RawUsbError

IMG = "/home/alessandro/git/reverse-engineer/schuberth-firmware-updater/firmware/sc2v2-2.4.0.0.img"
CHUNK = 1019

def main():
    data = open(IMG, "rb").read()
    container = parse_sena_container(data)
    img = container.images[0]
    blob = img.blob(data)
    print(f"image {img.name} {len(blob)} B, {-(-len(blob)//CHUNK)} chunks")

    h = RawHandle(0x3217)

    def drain():
        while h.read_bulk(timeout_ms=200):
            pass

    def send(cmd, tries=1, label=""):
        """vendor c1b: build [01 cmd 00 ...], write 1023 B, read reply
        (67 B semantics: first pushed 16-B packet carries echo+status).
        success = reply[1]==cmd and reply[2]==0."""
        for t in range(tries):
            try:
                h.write_bulk(cmd, b"")
            except RawUsbError as e:
                print(f"B {cmd:#02x} {label} try{t}: write err {e}")
                return None
            rep = b""
            for _ in range(5):
                rep = h.read_bulk(timeout_ms=800)
                if rep and len(rep) > 2 and rep[1] == cmd:
                    break
            ok = len(rep) > 2 and rep[1] == cmd and rep[2] == 0
            if t or not ok:
                print(f"B {cmd:#02x} {label} try{t}: "
                      f"{rep[:8].hex() if rep else 'NO REPLY'}")
            if ok:
                return rep
            time.sleep(0.001)  # vendor usleep(1ms) in retry loops
        return None

    drain()
    send(0x0A, 1, "dfu-result peek")
    rep = send(0x01, 1, "ver")
    if rep:
        print("current version:", ".".join(str(x) for x in rep[3:7]))

    # --- vendor session handshake (needs powered-on main system) ---
    if send(0x20, 2, "session start") is None:
        print("0x20 refused: device answers status 2 -- main system must be "
              "powered on (charge mode blocks the session). Aborting before "
              "any flash-touching step.")
        return 2
    ok22 = False
    for i in range(25):  # vendor retry loop, 25 tries
        rep = send(0x22, 1, f"poll {i}")
        if rep is not None:
            ok22 = True
            if rep[3] == 1:
                print("0x22 ready flag set")
            break
    if not ok22:
        print("0x22 poll loop exhausted -- aborting")
        return 2
    if send(0x21, 2, "confirm") is None:
        print("0x21 refused -- aborting")
        return 2
    send(0x21, 1, "confirm#2")
    send(0x20, 1, "start#2")

    # --- CSR download ---
    if send(0x05, 1, "dl start") is None:
        print("0x05 refused -- aborting")
        return 2
    off, t0, nchunk = 0, time.monotonic(), 0
    while off < len(blob):
        ch = blob[off:off + CHUNK]
        ccode = 0x0E if off + CHUNK >= len(blob) else 0x06
        try:
            h.write_bulk(ccode, len(ch).to_bytes(2, "big") + ch)
        except RawUsbError as e:
            print(f"chunk at {off}: write err {e}")
            return 1
        for _ in range(20):  # ack: retry while status==1
            rep = h.read_bulk(timeout_ms=1000)
            if not rep or all(x == 0 for x in rep):
                continue
            if len(rep) > 2 and rep[1] == ccode:
                if rep[2] != 1:
                    if rep[2] != 0 and nchunk < 3:
                        print(f"chunk at {off}: status {rep[2]} -- aborting")
                        return 1
                    break
        off += len(ch)
        nchunk += 1
        if nchunk % 200 == 0:
            print(f"  staged {off}/{len(blob)} ({time.monotonic()-t0:.0f}s)",
                  flush=True)
    print(f"all {nchunk} chunks done in {time.monotonic()-t0:.0f}s")

    if send(0x07, 1, "COMMIT") is None:
        print("0x07 commit not acked")
    time.sleep(2)
    try:
        h.write_bulk(0x08, b"")  # reboot, no reply expected
    except RawUsbError as e:
        print(f"0x08 write err {e}")
    print("waiting 12s for device...")
    time.sleep(12)
    try:
        h2 = RawHandle(0x3217)
        while h2.read_bulk(timeout_ms=300):
            pass
        h2.write_bulk(0x01, b"")
        rep = b""
        for _ in range(10):
            rep = h2.read_bulk(timeout_ms=800)
            if rep and len(rep) > 6 and rep[1] == 0x01:
                break
        if rep and rep[1] == 0x01 and rep[2] == 0:
            print("version now:", ".".join(str(x) for x in rep[3:7]))
        else:
            print("version query:", rep[:8].hex() if rep else "NO REPLY")
    except RawUsbError as e:
        print("reopen failed:", e, "(may need replug)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
