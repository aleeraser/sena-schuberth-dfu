#!/usr/bin/env python3
"""Raw standalone driver of the LIVE-VERIFIED SC2V2 (0x3217) update
(2026-10-19: took a real unit from 2.3.2.1 to 2.4.0.0). Mirrors the
vendor image loop at threadMethodUpdate: 0x10005d2b0-0x10005f222:

  sleep(5)
  for each container image (ALL of them, incl. the submesh; B side only):
      0x05 start, frame[2] = container entry flag (Image.flag)
      0x06 chunks [01 06 lenBE16 data<=0x3FB], tight echo-matched ack
          loop (vendor sub_100108a72: no sleep, no bound, retry while
          reply[2]==1 busy)
      0x07 commit
  sleep(5)
  0x08 reboot [01 08 00]
  sleep(1), then wait for the device to re-enumerate itself and
  re-read 0x01.

No 0x20/0x22/0x21 session, no 0x0E last-chunk: those are PRISM-family
commands (PID gate 0x10004bb02-0x10004bb85 -> jne 0x10005d2b0). Run the
package instead (schuberth-dfu update); this file exists as the minimal
no-frills reference of the exact byte sequence.

Usage: pkexec python3 tools/re/sc2v2_live_update.py <container.img>
"""
import struct, sys, time
from schuberth_dfu.rawusb import RawHandle, RawUsbError


def main(img_path):
    data = open(img_path, "rb").read()
    dev, count = struct.unpack_from("<II", data, 0x1C)
    ents = [struct.unpack_from("<IIII", data, 0x24 + 0x20 * i)
            for i in range(count)]
    print(f"device={dev:#06x} entries(a,b,off,size)={ents}")
    h = RawHandle(0x3217)

    def drain():
        while h.read_bulk(timeout_ms=200):
            pass

    def cmd(cmd_id, payload=b""):
        # vendor c1b (sub_100108c1b): single write, then BLOCK until a
        # reply echoing cmd_id arrives. No timeout, no retry cap.
        h.write_bulk(cmd_id, payload)
        while True:
            r = h.read_bulk(timeout_ms=3000)
            if r and len(r) > 2 and r[1] == cmd_id:
                return r

    drain()
    print("sleep(5)"); time.sleep(5)
    for idx, (a, b, off, size) in enumerate(ents):
        blob = data[off:off + size]
        r = cmd(0x05, bytes([b]))
        if r[2] != 0:
            sys.exit(f"[{idx}] 05 refused status={r[2]}")
        p = 0
        t0 = time.monotonic()
        while p < size:
            chunk = blob[p:p + 1019]
            h.write_bulk(0x06, len(chunk).to_bytes(2, "big") + chunk)
            while True:  # vendor a72: tight ack busy-wait
                r = h.read_bulk(timeout_ms=3000)
                if r and len(r) > 2 and r[1] == 0x06:
                    if r[2] == 1:
                        continue
                    if r[2] != 0:
                        sys.exit(f"[{idx}] chunk @{p} status {r[2]}")
                    break
            p += len(chunk)
        print(f"[{idx}] type={a} b={b}: {size} B staged in "
              f"{time.monotonic() - t0:.1f}s")
        r = cmd(0x07)
        print(f"[{idx}] 07 commit: status={r[2]}")
    print("sleep(5) post-loop"); time.sleep(5)
    r = cmd(0x08, b"\x00")
    print("08:", r[:8].hex())
    print("sleep(1)"); time.sleep(1)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            h2 = RawHandle(0x3217)
            for _ in range(6):
                if not h2.read_bulk(timeout_ms=300):
                    break
            h2.write_bulk(0x01, b"")
            while True:
                rep = h2.read_bulk(timeout_ms=2000)
                if rep and len(rep) > 6 and rep[1] == 0x01:
                    print("VERSION:",
                          ".".join(str(x) for x in rep[3:7]))
                    return
        except Exception as exc:
            print("reopen:", exc)
            time.sleep(2)


if __name__ == "__main__":
    main(sys.argv[1])
