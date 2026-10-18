"""Airoha BT DFU command layer + block-update loop (tickets 04/05).

Transport A ("feature"): commands go out as 62-byte output reports
[0]=0x01, [1]=0x3C, [2]=cmd, [3..]=params; replies are polled from the
62-byte feature report (ID 2): [2]=echo cmd, [3]=status, [4..]=payload.
Per-command reply payload lengths come from the 27-entry table at
0x10024c620 (findings.md "Airoha BT DFU command protocol").

NOTE: never exercised against real hardware yet; every constant is from
the macOS binary, but report-id behaviour on Linux hidraw needs a first
live validation (ticket 06).
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from .container import Image
from .crc import crc16_ccitt

# Command numbers (feature path usage observed in threadMethodUpdate:).
CMD_NOP = 0x00
CMD_VERSION = 0x01            # reply payload 5 or 8 bytes; + [block idx]
                              # param = per-block version check (vendor
                              # "BLOCK %d VERSION CHECK"; live SC2V2
                              # answers the same 5 bytes for any param)
CMD_BLOCK_START = 0x05        # bare: open block transfer ("UPDATE START";
                              # live: slow, ~4 s — flash prep)
CMD_WRITE = 0x06              # [3]=len(<=0x3A), [4..]=data; reply[4..5]=CRC16 LE
CMD_VERIFY = 0x08
CMD_GET_DFU_RESULT = 0x0A     # reply[4] = result byte (informational)
CMD_CHUNK_CRC = 0x5A          # [3]=2, [4..5]=chunk CRC16 LE (bulk mesh path)
CMD_BLOCK_CRC = 0x5B          # [3]=2, [4..5]=running block CRC16 LE:
                              # closes the block; device checks it at VERIFY

CHUNK_LEN = 0x3A              # 58 bytes per write (findings.md)

# Expected reply payload lengths from the 0x10024c620 table (cmd: extra).
REPLY_PAYLOAD_LEN = {
    0x00: 0, 0x01: 5, 0x02: 6, 0x03: 58, 0x04: 0, 0x05: 0, 0x06: 2,
    0x07: 0, 0x08: 0, 0x09: 0, 0x0A: 1, 0x0B: 0, 0x0C: 0, 0x0D: 0,
}
for _c in range(0x50, 0x5C):
    REPLY_PAYLOAD_LEN[_c] = 0


class AirohaError(Exception):
    pass


class AirohaResetError(AirohaError):
    """Link died at/after VERIFY: the device applied the block and
    re-enumerated (observed live on SC2V2 at verify of block 0). The
    block itself was fully streamed and committed by the device."""


class Link:
    """Transport A command layer over a transport.Handle (or fake)."""

    def __init__(self, handle, *, poll_interval: float = 0.002,
                 timeout: float = 5.0):
        self.h = handle
        self.poll_interval = poll_interval
        self.timeout = timeout

    def command(self, cmd: int, params: bytes = b"") -> bytes:
        """Send one command, poll for the matching feature reply.

        Ready signal per the vendor poll loop (sub_100108d34): the reply
        length byte [1] must be non-zero AND [2] must echo the command;
        a zeroed/partial buffer (device still processing) is not ready.
        Returns the full 62-byte reply; payload starts at offset 4.
        Raises AirohaError on timeout or non-zero status.
        """
        buf = bytearray(62)
        buf[0] = 0x01
        buf[1] = 0x3C
        buf[2] = cmd
        buf[3:3 + len(params)] = params
        self.h.write_report(bytes(buf))

        deadline = time.monotonic() + self.timeout
        while True:
            rep = self.h.feature_get()
            if len(rep) >= 3 and rep[1] != 0 and rep[2] == cmd:
                break
            if time.monotonic() >= deadline:
                raise AirohaError(f"no echo for cmd {cmd:#02x} "
                                  f"(last reply {rep[:4].hex() if rep else '-'})")
            time.sleep(self.poll_interval)
        if len(rep) < 4 or rep[3] != 0:
            raise AirohaError(f"cmd {cmd:#02x} status={rep[3] if len(rep) > 3 else '?'}")
        return rep

    # --- primitives ------------------------------------------------------

    def version(self) -> bytes:
        rep = self.command(CMD_VERSION)
        return rep[4:9]                      # 5 version bytes (extra=5)

    def block_version(self, block_idx: int) -> bytes:
        """Vendor 'BLOCK %d VERSION CHECK': cmd 0x01 with the block idx
        as param; 5-byte version payload (live SC2V2: same bytes for
        every param)."""
        rep = self.command(CMD_VERSION, bytes([block_idx]))
        return rep[4:9]

    def start_block(self) -> None:
        """Vendor 'BLOCK %d UPDATE START': bare cmd 0x05. Slow on live
        devices (~4 s, flash prep)."""
        self.command(CMD_BLOCK_START)

    def block_crc(self, crc: int) -> None:
        """Close the block transfer: cmd 0x5B, params [2, crc_lo, crc_hi]
        (running CRC-16/CCITT over the whole block). The device checks
        it during VERIFY."""
        self.command(CMD_BLOCK_CRC,
                     bytes([2, crc & 0xFF, (crc >> 8) & 0xFF]))

    def write_chunk(self, data: bytes) -> int:
        """Write one <=58-byte chunk; return the device's CRC-16 for it."""
        if len(data) > CHUNK_LEN:
            raise AirohaError(f"chunk too long: {len(data)}")
        rep = self.command(CMD_WRITE, bytes([len(data)]) + data)
        return rep[4] | (rep[5] << 8)

    def verify(self) -> None:
        self.command(CMD_VERIFY)

    def get_dfu_result(self) -> int:
        return self.command(CMD_GET_DFU_RESULT)[4]


def update_image(link: Link, data: bytes, image: Image,
                 progress: Optional[Callable[[int, int], None]] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
    """Stream one container image through the Airoha block-update loop.

    Per chunk: write (cmd 6) and compare the device CRC-16 against ours;
    keep a running CRC over the whole image. Then VERIFY (cmd 8) and
    GET_DFU_RESULT (cmd 0x0A).
    """
    blob = image.blob(data)
    running = 0
    sent = 0
    for off in range(0, len(blob), CHUNK_LEN):
        chunk = blob[off:off + CHUNK_LEN]
        our_crc = crc16_ccitt(chunk)
        for attempt in range(3):
            dev_crc = link.write_chunk(chunk)
            if dev_crc == our_crc:
                break
            # live devices occasionally answer before filling the CRC
            # field; re-send (vendor re-writes on bad acks too).
            if attempt < 2:
                continue
            raise AirohaError(
                f"CRC mismatch at {off:#x}: device {dev_crc:#04x} != ours {our_crc:#04x}")
        running = crc16_ccitt(chunk, running)
        sent += len(chunk)
        if progress:
            progress(sent, len(blob))
    if log:
        log(f"block crc = {running:#06x}")
    link.block_crc(running)
    from .rawusb import RawUsbError
    try:
        link.verify()
        result = link.get_dfu_result()
    except (RawUsbError, OSError) as exc:
        # every chunk landed with a matching CRC; if the link dies now
        # the device is applying the block (apply-reset), not rejecting
        # it — the flow treats this as "block done, interface gone".
        raise AirohaResetError(f"link died at verify/result: {exc}") from exc
    # Vendor logs "GET_DFU_RESULT value[%d]" then "BLOCK %d UPDATE OK"
    # without gating on the value; live SC2V2 answers 1 after applying
    # a block. Informational only.
    if log:
        log(f"DFU result = {result}")
