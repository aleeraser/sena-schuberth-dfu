"""Simulated headsets implementing the decoded DFU protocols.

Used by the test-suite and by `schuberth-dfu selftest` to exercise the
update flows end-to-end without hardware. The simulators respond to the
same report primitives as transport.Handle, so the real flow code runs
unmodified against them.
"""
import hashlib
import struct

from .container import SENA_MAGIC
from .crc import crc16_ccitt
from .airodfu import REPLY_PAYLOAD_LEN


def build_container(version=b"v9.9-build9", device_id=0x3170,
                    blobs=None, names=None, types=None):
    """Synthesize a container matching the layout in findings.md."""
    blobs = blobs or [b"main-fw" * 10, b"voice-prompts" * 5]
    names = names or [b"TEST_MAIN.bin", b"TEST_VP.bin"]
    types = types or list(range(len(blobs)))
    count = len(blobs)
    table_end = 0x24 + count * 0x20
    header_size = table_end + 0x100 * max(len(names), 1)
    offsets, off = [], header_size
    for b in blobs:
        offsets.append(off)
        off += len(b)
    hdr = bytearray(header_size)
    hdr[0x00:0x18] = version.ljust(0x18, b"\x00")
    hdr[0x18:0x1C] = SENA_MAGIC
    struct.pack_into("<II", hdr, 0x1C, device_id, count)
    for i, (b, o) in enumerate(zip(blobs, offsets)):
        e = 0x24 + i * 0x20
        struct.pack_into("<4I", hdr, e, types[i], 1, o, len(b))
        hdr[e + 16:e + 32] = hashlib.md5(b).digest()
    pos = table_end
    for n in names:
        hdr[pos:pos + len(n)] = n
        pos += 0x100  # scattered name records
    return bytes(hdr) + b"".join(blobs)


class FakeAiroha:
    """Transport A: 62-byte output report in, feature reply out."""

    def __init__(self, corrupt_crc=False, version=(2, 5, 3, 0, 0)):
        self.corrupt_crc = corrupt_crc
        self.version = version
        self.written = bytearray()
        self.cmds = []
        self._reply = b""

    def write_report(self, data):
        assert data[0] == 0x01 and data[1] == 0x3C, "bad transport-A header"
        cmd = data[2]
        params = data[3:]
        self.cmds.append(cmd)
        rep = bytearray(62)
        rep[1] = 2 + REPLY_PAYLOAD_LEN.get(cmd, 0)   # length byte (ready signal)
        rep[2] = cmd
        rep[3] = 0
        if cmd == 0x06:
            length = params[0]
            chunk = bytes(params[1:1 + length])
            assert length <= 0x3A
            self.written += chunk
            crc = crc16_ccitt(chunk)
            if self.corrupt_crc:
                crc ^= 0xFFFF
            rep[4] = crc & 0xFF
            rep[5] = crc >> 8
        elif cmd == 0x0A:
            rep[4] = 0
        elif cmd == 0x01:
            rep[4:9] = bytes(list(self.version))
        self._reply = bytes(rep)

    def feature_get(self):
        return self._reply

    def close(self):
        pass


class FakeSc2:
    """Transports B (1023/67) + C (65/65) with busy-retry replies."""

    def __init__(self, busy_once=False):
        self.busy_once = busy_once
        self._busy_pending = False
        self.cmds = []
        self.chunks = bytearray()
        self._pending = None
        self.closed = False

    def close(self):
        self.closed = True

    def write_bulk(self, cmd, params=b""):
        self.cmds.append(("B", cmd))
        rep = bytearray(67)
        rep[1] = 0
        rep[2] = 0
        if cmd == 0x01:
            rep[3:7] = [1, 0, 2, 3]
        self._pending = bytes(rep)

    def read_bulk(self, timeout_ms=2000):
        return self._pending

    def write_mesh(self, cmd, params=b""):
        self.cmds.append(("C", cmd))
        rep = bytearray(65)
        rep[1] = 0
        rep[2] = 0
        if cmd == 0x06:
            assert params[0] == 0
            length = params[1]
            assert length <= 0x3D
            self.chunks += params[2:2 + length]
        if self.busy_once:
            self._busy_pending = True
            self.busy_once = False
        self._pending = bytes(rep)

    def read_mesh(self, timeout_ms=2000):
        if self._busy_pending:
            self._busy_pending = False
            busy = bytearray(self._pending)
            busy[2] = 1
            return bytes(busy)
        return self._pending


class FakeSc2V2:
    """0x3217 raw-USB model per vendor-static analysis + live probing
    (2026-10-19): pushed EP1 replies [0x02, echo cmd, status, payload...];
    frames are [01 cmd 00 ...] zero-padded. Session commands 0x20/0x21/0x22
    answer status 2 unless `powered_on` (live charge-mode device with a
    dead battery answers 2). CSR chunks [01 06 lenBE16 data] stage into
    .staging; 0x07 commits the staged image into .applied; 0x08 answers
    nothing (device restarts)."""

    def __init__(self, version=(2, 3, 2, 1), powered_on=True):
        self.version = version
        self.powered_on = powered_on
        self.cmds = []
        self.staging = bytearray()
        self.applied = []          # one entry per committed image
        self.reboots = 0
        self._pending = None

    def close(self):
        pass

    def write_bulk(self, cmd, params=b""):
        self.cmds.append(cmd)
        if cmd == 0x08:
            self._pending = None            # no reply: device restarts
            self.reboots += 1
            return
        rep = bytearray(16)
        rep[0] = 0x02
        rep[1] = cmd
        rep[2] = 0
        if cmd == 0x01:
            rep[3:7] = bytes(list(self.version))
        elif cmd in (0x20, 0x21, 0x22, 0x0F, 0x10, 0x12):
            if not self.powered_on:
                rep[2] = 2                  # live: charge-mode refusal
        elif cmd == 0x05:
            self.staging = bytearray()
        elif cmd in (0x06, 0x0E):
            length = struct.unpack(">H", params[:2])[0]
            self.staging += params[2:2 + length]
        elif cmd == 0x07:
            self.applied.append(bytes(self.staging))
            self.staging = bytearray()
        self._pending = bytes(rep)

    def read_bulk(self, timeout_ms=3000):
        return self._pending or b""
