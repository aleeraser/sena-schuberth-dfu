#!/usr/bin/env python3
"""Probe 0x3217 for QCC download mode after a run-loader.

update9 left 0x3217 deaf to transport-B framing until replug; the
vendor's post-0x08 state is "Find Mesh" (sub_100108466), so the CSR
side may switch the SAME interface to transport-C framing: 65-byte
[01 cmd ...] reports on the interrupt endpoints (EP2 OUT / EP1 IN).
Run this right after an update attempt ends, BEFORE replugging.

Read-only: version (0x01) + NOP (0x00) queries in both framings.
"""
import time
import usb.core
import usb.util

VID, PID = 0x092B, 0x3217


def drain(ep_in, size, secs=1.0):
    end = time.monotonic() + secs
    seen = []
    while time.monotonic() < end:
        try:
            rep = bytes(ep_in.read(size, 300))
            if any(rep):
                seen.append(rep[:16].hex())
        except usb.core.USBError:
            pass
    return seen


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("0x3217 not present")
        return 1
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
    dev.set_configuration()
    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    ep_in = usb.util.find_descriptor(
        intf, custom_match=lambda e:
        usb.util.endpoint_direction(e.bEndpointAddress) ==
        usb.util.ENDPOINT_IN)
    ep_out = usb.util.find_descriptor(
        intf, custom_match=lambda e:
        usb.util.endpoint_direction(e.bEndpointAddress) ==
        usb.util.ENDPOINT_OUT)
    print(f"EPs: IN {ep_in.bEndpointAddress:#04x} max {ep_in.wMaxPacketSize}, "
          f"OUT {ep_out.bEndpointAddress:#04x} max {ep_out.wMaxPacketSize}")
    print("drain:", drain(ep_in))

    def try_c(cmd):
        frame = bytearray(65)          # transport C: [01 cmd FF ...]
        frame[0], frame[1], frame[2] = 1, cmd, 0xFF
        try:
            dev.write(ep_out, bytes(frame), 1500)
            return drain(ep_in, 65, 1.5)
        except usb.core.USBError as e:
            return f"write err: {e}"

    def try_b(cmd):
        frame = bytearray(1023)        # transport B: [01 cmd ...]
        frame[0], frame[1] = 1, cmd
        try:
            dev.write(ep_out, bytes(frame), 1500)
            return drain(ep_in, 16, 1.5)
        except usb.core.USBError as e:
            return f"write err: {e}"

    for label, fn in (("C65 ver", lambda: try_c(0x01)),
                      ("C65 nop", lambda: try_c(0x00)),
                      ("B1023 ver", lambda: try_b(0x01)),
                      ("C65 ver again", lambda: try_c(0x01))):
        print(f"{label}: {fn()}")

    # control-transfer report access, in case DFU mode moved to reports
    for (rt, rid) in ((0x01, 1), (0x03, 2), (0x01, 2)):
        try:
            rep = bytes(dev.ctrl_transfer(0xA1, 0x01, (rt << 8) | rid, 0,
                                          65, 500))
            if any(rep):
                print(f"GET rt{rt} id{rid}: {rep[:12].hex()}")
        except usb.core.USBError:
            pass
    usb.util.dispose_resources(dev)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
