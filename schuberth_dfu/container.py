"""Firmware container parsers.

SENA ships one generic multi-image container for most products (Airoha and
CSR devices alike), plus a legacy simple format for PRISM. Layout recovered
from live .img files + the macOS loaders (findings.md "Firmware container").

SENA multi-image container:

    0x000 char[24]  version string, e.g. b"v2.5.3-build0"
    0x018 u8[4]     magic 19 28 C5 E6
    0x01C u32       target device id (equals USB PID for CSR devices)
    0x020 u32       image count
    0x024 image[i]  {u32 a, u32 b, u32 file_offset, u32 size, u8 md5[16]}
                    (stride 0x20; `a` is an image-type index: 0 main FW,
                     1 voice prompts, 3 mesh loader, 4 config/keys)
    0x10C..         NUL-padded image name records, e.g. b"SPIDER_ST1_VP.bin"
    (header ends where the first image blob starts, typically 0x2d4/0x584)

PRISM container (parser sub_10010f6ab): product name string at file offset
0x10, CRC-32 footer = last 4 bytes covering everything before them.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, replace
from typing import Callable, List, Optional

SENA_MAGIC = b"\x19\x28\xc5\xe6"
QCC_MAGIC = b"APPUHDR5"

IMAGE_TYPE_MAIN = 0
IMAGE_TYPE_VOICE = 1
IMAGE_TYPE_MESH = 3
IMAGE_TYPE_CONFIG = 4


class ContainerError(Exception):
    pass


@dataclass(frozen=True)
class Image:
    type: int
    flag: int
    offset: int
    size: int
    md5: bytes
    name: Optional[str] = None

    def blob(self, data: bytes) -> bytes:
        return data[self.offset:self.offset + self.size]

    def verify(self, data: bytes) -> bool:
        return hashlib.md5(self.blob(data)).digest() == self.md5


@dataclass(frozen=True)
class SENAContainer:
    version: str
    device_id: int
    images: List[Image]
    names: List[str]

    def verify_all(self, data: bytes) -> bool:
        return all(img.verify(data) for img in self.images)


def parse_sena_container(data: bytes) -> SENAContainer:
    """Parse the multi-image container; raises ContainerError if not one."""
    if len(data) < 0x44:
        raise ContainerError("file too small")
    if data[0x18:0x1C] != SENA_MAGIC:
        raise ContainerError(
            f"bad magic {data[0x18:0x1C].hex()!r}, expected {SENA_MAGIC.hex()!r}")
    version = data[0x00:0x18].split(b"\x00")[0].decode("utf-8", "replace")
    device_id, count = struct.unpack_from("<II", data, 0x1C)
    if not 1 <= count <= 16:
        raise ContainerError(f"implausible image count {count}")
    images: List[Image] = []
    for i in range(count):
        off = 0x24 + i * 0x20
        a, b, blob_off, blob_size = struct.unpack_from("<4I", data, off)
        md5 = data[off + 16:off + 32]
        if blob_off + blob_size > len(data):
            raise ContainerError(
                f"image[{i}] {blob_off:#x}+{blob_size:#x} past EOF {len(data):#x}")
        images.append(Image(type=a, flag=b, offset=blob_off, size=blob_size, md5=md5))
    # Name records live between the table and the first blob and correspond
    # to the images positionally (verified: SC2 -> SC2.img/vp.bin/MESH3.0.ldr/
    # HeySiri config; ST1 -> VP then main).
    table_end = 0x24 + count * 0x20
    first_blob = min(img.offset for img in images)
    names = [n.decode("ascii")
             for n in data[table_end:first_blob].split(b"\x00")
             if n.strip() and len(n) >= 4
             and all(32 <= c < 127 for c in n)]
    images = [replace(img, name=names[i]) if i < len(names) else img
              for i, img in enumerate(images)]
    return SENAContainer(version=version, device_id=device_id, images=images,
                         names=names)


def is_qcc_appu(data: bytes) -> bool:
    """True for the Qualcomm APPUHDRV5 partition container (unsupported)."""
    return QCC_MAGIC in data[:0x200]


def assert_matches_device(container: "SENAContainer", product_id: int) -> None:
    """Refuse to flash an image built for a different device.

    The container's device_id is the USB PID the vendor pairs it with
    (verified: SC2-v1.5 -> 0x3170, SC2-v2.4/SC2V2 -> 0x3217, SC1A ->
    0x5622, SC1M -> 0x6400, UCOM3 -> 0x3340). Callers must treat a
    mismatch as fatal before touching the device.
    """
    if container.device_id != product_id:
        raise ContainerError(
            f"refusing to flash: firmware image is for device "
            f"{container.device_id:#06x} but the connected device is "
            f"{product_id:#06x}")


QCC_RECORD_MAGIC = b"PARTDATA"
QCC_FOOTER_MAGIC = b"APPUPFTR"


@dataclass(frozen=True)
class QccRecord:
    kind: int                 # 0 = key block, 1 = "Image" descriptor, 9 = data
    payload: bytes            # record bytes after the 16-byte header


@dataclass(frozen=True)
class QccPartitions:
    """APPUHDR5 partition image (decoded live from ucom3/ucom6r containers,
    ticket 09): fixed header, big-endian PARTDATA records, APPUPFTR hash
    table. The vendor host forwards the whole blob to the device untouched
    (device-side validates it); we parse it for reporting and sanity checks.
    """
    chip: str                 # e.g. "QCC512Xx"
    records: List[QccRecord]
    footer_hashes: List[bytes]  # 16 x 16-byte entries, algorithm keyed/n.i.

    @property
    def data_blob(self) -> Optional[bytes]:
        for r in self.records:
            if r.kind == 9:
                return r.payload
        return None


def parse_qcc_partitions(blob: bytes) -> QccPartitions:
    """Parse one APPUHDR5 image (a SENADRIVER container image() blob)."""
    if blob[:8] != QCC_MAGIC:
        raise ContainerError(f"not an APPUHDRV5 image (magic {blob[:8]!r})")
    chip = blob[0x0C:0x18].split(b"\x00")[0].decode("ascii", "replace")
    x = 0x3C
    records: List[QccRecord] = []
    while blob[x:x + 8] == QCC_RECORD_MAGIC:
        total, kind = struct.unpack_from(">II", blob, x + 8)
        if total < 4 or x + 12 + total > len(blob):
            raise ContainerError(f"bad PARTDATA record at {x:#x}")
        records.append(QccRecord(kind=kind, payload=blob[x + 16:x + 12 + total]))
        x += 12 + total
    if blob[x:x + 8] != QCC_FOOTER_MAGIC:
        raise ContainerError(f"expected APPUPFTR footer at {x:#x}")
    table_len, = struct.unpack_from(">I", blob, x + 8)
    hashes = [blob[x + 12 + 16 * i:x + 28 + 16 * i]
              for i in range(table_len // 16)]
    return QccPartitions(chip=chip, records=records, footer_hashes=hashes)


def parse_prism_container(data: bytes, expected_name: str,
                          crc32: Callable[[bytes], int]) -> bytes:
    """Validate the PRISM simple container and return the payload.

    `crc32` is a callable bytes -> int (see schuberth_dfu.crc.crc32).
    Product name string must match `expected_name` at file offset 0x10.
    """
    if len(data) < 0x14:
        raise ContainerError("file too small")
    name = data[0x10:].split(b"\x00")[0].decode("utf-8", "replace")
    if not name.startswith(expected_name):
        raise ContainerError(f"firmware is for {name!r}, not {expected_name!r}")
    stored = struct.unpack_from("<I", data, len(data) - 4)[0]
    if crc32(data[:-4]) != stored:
        raise ContainerError("CRC-32 footer mismatch")
    return data[:len(data) - 4]


@dataclass(frozen=True)
class PrismUpdateImage:
    """PRISM-v1.0.0.0.img wrapper (ticket 10, decoded live from the server
    sample): PRISM updates are NOT a packet protocol — the app copies
    drop-files (`__prism_dfu_bluetooth__.img`, `__prism_firmware__.bin`)
    onto the device's USB mass-storage volume (strings:
    getPrismDiskPathWithDevice:, checkPrismUpdateComplete, endPrismUpdate,
    MISC/version.conf; dialog: "Disconnect the USB cable from the PRISM /
    Wait until the PRISM completes update and powers off / Connect USB
    cable ... and then power on it"). This wrapper is the download
    artifact the drop-files are derived from.

    Decoded header (u32 LE unless noted):
      0x00  version string "v0.0.0.0" (28 B)
      0x1C  pid (0x3020)
      0x20  component count (2)
      0x30  component 0 size (0x131eb0) ; 0x4C/0x50: main component
            offset+size (they tile the file exactly)
      0x64  sub-header magic "CSR-dfu2" (Bluetooth-module DFU image —
            the "__prism_dfu_bluetooth__" component), 0x6E size u32,
            0x74 72-B space-padded name "PRISM#3020"
    Payload layout beyond the header and the wrapper->drop-file
    derivation are UNRESOLVED (needs PRISM hardware to observe what the
    app writes to the disk volume) — reader only; do not auto-flash.
    """
    version: str
    pid: int
    count: int
    comp0_size: int
    bt_size: int
    bt_name: str
    main_offset: int           # second (camera) component start
    main_size: int


def parse_prism_update_image(data: bytes) -> PrismUpdateImage:
    """Read the PRISM download wrapper header (see PrismUpdateImage)."""
    version = data[:0x1C].split(b"\x00")[0].decode("ascii", "replace")
    pid, count = struct.unpack_from("<II", data, 0x1C)
    if pid != 0x3020:
        raise ContainerError(f"not a PRISM image (pid {pid:#06x})")
    if data[0x64:0x6C] != b"CSR-dfu2":
        raise ContainerError(f"missing CSR-dfu2 sub-header at 0x64 "
                             f"({data[0x64:0x6C]!r})")
    comp0_size, = struct.unpack_from("<I", data, 0x30)
    bt_size, = struct.unpack_from("<I", data, 0x6E)
    name = data[0x74:0x74 + 72].decode("ascii", "replace").strip(" \x00")
    main_offset, main_size = struct.unpack_from("<II", data, 0x4C)
    if main_offset + main_size > len(data):
        raise ContainerError("component table exceeds file")
    return PrismUpdateImage(version=version, pid=pid, count=count,
                            comp0_size=comp0_size, bt_size=bt_size,
                            bt_name=name, main_offset=main_offset,
                            main_size=main_size)
