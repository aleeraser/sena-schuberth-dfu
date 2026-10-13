"""CRC helpers used by the update protocols.

CRC-16/CCITT: table at 0x10016a980 in the macOS binary is the MSB-first
polynomial 0x1021 table; the update loop initialises both the per-chunk and
the running block CRC to 0 (findings.md "Airoha BT DFU command protocol").
"""
from __future__ import annotations

import zlib

_POLY = 0x1021


def _crc16_table():
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            crc = ((crc << 1) ^ _POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        table.append(crc)
    return table


CRC16_TABLE = tuple(_crc16_table())


def crc16_ccitt(data: bytes, crc: int = 0) -> int:
    """CRC-16/CCITT-FALSE-style with MSB-first table, configurable init."""
    for byte in data:
        crc = ((crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ byte) & 0xFF]) & 0xFFFF
    return crc


def crc32(data: bytes) -> int:
    """Standard reflected CRC-32 (matches the PRISM footer, table 0x10016ad20)."""
    return zlib.crc32(data) & 0xFFFFFFFF
