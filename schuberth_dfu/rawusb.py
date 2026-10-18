"""Raw USB (pyusb) transport for the SC2V2 family (092b:3217 / 092b:3220).

These two interfaces cannot be driven through the kernel HID stack:
0x3217's report descriptor has a vendor typo (`96 FE 03` where
`76 FE 03` = Report Count 1022 was meant) so Linux sizes its output
report at 1 byte and truncates every write, and GET_REPORT ioctls are
refused for lack of control-transfer quirks; 0x3220 has no OUT endpoint
at all. The macOS app sidesteps all of it via IOHID, which sends plain
SET_REPORT/GET_REPORT control transfers and raw interrupt transfers —
this module replicates exactly that (findings.md "Live SC2V2 USB
topology + report-ID convention").

Detaching hid-generic requires root: run the update via sudo.

Handle primitives match transport.Handle / the flow classes:
  - transport B (0x3217): write_bulk/read_bulk over interrupt EPs.
    Wire frame: 1023 B [0x01, cmd, params...], NO report-id prefix on
    the wire; replies are pushed on EP IN as [0x02, echo, status, ...].
  - transport A (0x3220): write_report/feature_get over control
    transfers. The vendor duplicates the report ID inside the payload:
    SET_REPORT(OUTPUT, id1) with 62 B [0x01, 0x3C, cmd, ...];
    GET_REPORT(FEATURE, id2) replies [0x02, len, echo, status, ...].
"""
from __future__ import annotations

import time
from typing import List, Tuple

from . import USB_VID

BULK_REPORT_LEN = 0x3FF          # transport B frame size
AIRO_FRAME_LEN = 0x3E            # transport A frame, incl. duplicated id
AIRO_OUT_RID = 0x01
AIRO_IN_RID = 0x02
RT_OUTPUT = 0x02
RT_FEATURE = 0x03

# PIDs that need this backend (confirmed live, findings.md 2026-10-18)
RAW_PIDS = frozenset({0x3217, 0x3220})


class RawUsbError(Exception):
    pass


def _usb():
    try:
        import usb.core
        import usb.util
    except ImportError as exc:  # pragma: no cover - hardware path only
        raise RawUsbError(
            "pyusb is required for raw USB access (pip install pyusb)") from exc
    return usb.core, usb.util


def scan_raw() -> List[Tuple[int, int, int]]:
    """(product_id, bus, address) for every present 092b raw-mode PID."""
    core, _ = _usb()
    return [(d.idProduct, d.bus, d.address)
            for d in core.find(idVendor=USB_VID, find_all=True)
            if d.idProduct in RAW_PIDS]


class RawHandle:
    """One 092b interface via pyusb; detaches hid-generic (needs root)."""

    def __init__(self, product_id: int):
        core, util = _usb()
        dev = core.find(idVendor=USB_VID, idProduct=product_id)
        if dev is None:
            raise RawUsbError(f"PID {product_id:#06x} not present")
        try:
            cfg = dev.get_active_configuration()
        except core.USBError as exc:
            raise RawUsbError(
                f"cannot read config: {exc} — run with sudo "
                "(raw USB needs hid-generic detach)") from exc
        intf = cfg[(0, 0)]
        self.product_id = product_id
        self.iface = intf.bInterfaceNumber
        try:
            if dev.is_kernel_driver_active(self.iface):
                dev.detach_kernel_driver(self.iface)
        except (NotImplementedError, core.USBError) as exc:
            if getattr(exc, "errno", None) in (1, 13):
                raise RawUsbError(
                    "raw USB needs root (hid-generic detach); run with sudo"
                ) from exc
        self._core, self._util = core, util
        self._dev = dev
        in_ep = util.find_descriptor(
            intf, custom_match=lambda e:
            util.endpoint_direction(e.bEndpointAddress) == util.ENDPOINT_IN)
        out_ep = util.find_descriptor(
            intf, custom_match=lambda e:
            util.endpoint_direction(e.bEndpointAddress) == util.ENDPOINT_OUT)
        self._ep_in = in_ep.bEndpointAddress if in_ep else None
        self._ep_out = out_ep.bEndpointAddress if out_ep else None
        self._in_size = in_ep.wMaxPacketSize if in_ep else 0

    def close(self) -> None:
        self._util.dispose_resources(self._dev)

    def __enter__(self) -> "RawHandle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- transport B "bulk" (0x3217): interrupt endpoints ----------------

    def write_bulk(self, cmd: int, params: bytes = b"") -> None:
        if self._ep_out is None:
            raise RawUsbError("no interrupt OUT endpoint on this interface")
        buf = bytearray(BULK_REPORT_LEN)
        buf[0] = 0x01
        buf[1] = cmd
        buf[2:2 + len(params)] = params
        self._dev.write(self._ep_out, bytes(buf), 5000)

    def read_bulk(self, timeout_ms: int = 3000) -> bytes:
        """Next meaningful pushed report [0x02, echo, status, payload...].

        The device pads with all-zero reports after each reply; those are
        skipped. Returns b"" on timeout.
        """
        if self._ep_in is None:
            raise RawUsbError("no interrupt IN endpoint on this interface")
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            try:
                rep = bytes(self._dev.read(self._ep_in, self._in_size, 500))
            except self._core.USBError as exc:
                if getattr(exc, "errno", None) in (110, 60):   # ETIMEDOUT
                    continue
                raise RawUsbError(f"interrupt IN read failed: {exc}") from exc
            if any(rep[1:]):
                return rep
        return b""

    # --- transport A "feature" (0x3220): control transfers only ----------

    def write_report(self, data: bytes) -> None:
        """SET_REPORT(OUTPUT, id1); `data` is the 62-B frame whose first
        byte duplicates the report ID (vendor convention)."""
        self._dev.ctrl_transfer(0x21, 0x09,
                                (RT_OUTPUT << 8) | AIRO_OUT_RID,
                                self.iface, bytes(data), 5000)

    def feature_get(self, report_id: int = AIRO_IN_RID,
                    length: int = AIRO_FRAME_LEN) -> bytes:
        """GET_REPORT(FEATURE, id2) poll; device echoes id as byte 0."""
        return bytes(self._dev.ctrl_transfer(
            0xA1, 0x01, (RT_FEATURE << 8) | report_id,
            self.iface, length, 2000))
