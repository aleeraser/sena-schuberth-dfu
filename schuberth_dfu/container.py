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
