"""HID transport over hidapi.

The macOS app statically links a libusb-compat shim implemented on top of
IOHID, so every "bulk" transfer is really a HID report (findings.md "macOS
transport"). On Linux the equivalent is hidraw via hidapi.

Report geometry (observed in the macOS binary):
  - output (host->device) reports: up to 0x3FF = 1023 bytes payload
  - input (device->host) replies: 0x43 = 67 bytes
  - feature reports: 0x3E = 62 bytes, report id 0x02
"""
from __future__ import annotations

from typing import List, NamedTuple

from . import USB_VID
from .catalog import catalog

REPORT_MAX_OUTPUT = 0x3FF   # 1023 bytes
REPLY_LEN = 0x43            # 67 bytes
FEATURE_LEN = 0x3E          # 62 bytes
FEATURE_REPORT_ID = 0x02
MESH_REPORT_LEN = 0x41      # 65 bytes (mesh-DFU interface, transport C)


class Device(NamedTuple):
    path: bytes
    vendor_id: int
    product_id: int
    product_name: str        # internal product name from the catalog
    serial_number: str


class TransportError(Exception):
    pass


def _hid():
    try:
        import hid  # python3-hidapi (pip "hidapi")
    except ImportError as exc:  # pragma: no cover - hardware path only
        raise TransportError(
            "python hidapi is required for device access "
            "(pip install hidapi)") from exc
    return hid


def scan() -> List[Device]:
    """Enumerate supported headsets currently plugged in."""
    hid = _hid()
    known = catalog()
    found = []
    for info in hid.enumerate(USB_VID, 0):
        pid = info["product_id"]
        if pid not in known:
            continue
        found.append(Device(
            path=info["path"],
            vendor_id=info["vendor_id"],
            product_id=pid,
            product_name=known[pid],
            serial_number=info.get("serial_number") or "",
        ))
    return found


class Handle:
    """Open device with the report primitives the DFU flows need."""

    def __init__(self, dev: Device):
        hid = _hid()
        self.dev = dev
        self._h = hid.device()
        self._h.open_path(dev.path)
        self._h.set_nonblocking(False)

    def close(self) -> None:
        self._h.close()

    def __enter__(self) -> "Handle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def write_report(self, data: bytes) -> None:
        """Output report; leading 0 = report id 0 (as the macOS shim does)."""
        if len(data) > REPORT_MAX_OUTPUT:
            raise TransportError(f"report too long: {len(data)}")
        if self._h.write_output_report(b"\x00" + data) < 0:
            raise TransportError("write_output_report failed")

    def read_reply(self, timeout_ms: int = 1000) -> bytes:
        """Input report, expected 67 bytes (REPLY_LEN)."""
        data = self._h.read(REPLY_LEN, timeout_ms)
        return bytes(data)

    # --- transport B "bulk" (normal-mode CSR/mesh devices) --------------
    # request: 1023-byte output report [0]=0x01,[1]=cmd,[2..]=params
    # reply:   67-byte input report  [1]=status,[2]=result(0 OK/1 busy)

    def write_bulk(self, cmd: int, params: bytes = b"") -> None:
        buf = bytearray(REPORT_MAX_OUTPUT)
        buf[0] = 0x01
        buf[1] = cmd
        buf[2:2 + len(params)] = params
        if self._h.write_output_report(b"\x00" + bytes(buf)) < 0:
            raise TransportError("bulk write failed")

    def read_bulk(self, timeout_ms: int = 2000) -> bytes:
        return bytes(self._h.read(REPLY_LEN, timeout_ms))

    # --- transport C "mesh DFU" (65-byte reports) -----------------------

    def write_mesh(self, cmd: int, params: bytes = b"") -> None:
        buf = bytearray(MESH_REPORT_LEN)
        buf[0] = 0x01
        buf[1] = cmd
        buf[2:2 + len(params)] = params
        if self._h.write_output_report(b"\x00" + bytes(buf)) < 0:
            raise TransportError("mesh write failed")

    def read_mesh(self, timeout_ms: int = 2000) -> bytes:
        return bytes(self._h.read(MESH_REPORT_LEN, timeout_ms))

    def feature_get(self, report_id: int = FEATURE_REPORT_ID,
                    length: int = FEATURE_LEN) -> bytes:
        return bytes(self._h.get_report_feature(report_id, length))

    def feature_set(self, data: bytes, report_id: int = FEATURE_REPORT_ID) -> None:
        self._h.send_feature_report(bytes([report_id]) + data)
