#!/usr/bin/env python3
"""Raw-USB probe for the SC2V2 (092b:3217) and its mesh interface (092b:3220).

The vendor HID report descriptors are malformed (0x3217: `96 FE 03` where
`76 FE 03` = Report Count 1022 was intended, so the Linux kernel sizes the
output report at 1 byte and truncates every write; 0x3220: no OUT endpoint,
kernel GET_REPORT ioctls refused). The macOS app talks to these devices
through IOHID: SET_REPORT/GET_REPORT control transfers plus raw interrupt
endpoint transfers. This script replicates that via pyusb.

Run with the headset POWERED ON:
    sudo /path/to/venv/bin/python3 tools/re/probe_sc2.py
"""
import sys
import time

import usb.core
import usb.util

VID = 0x092B
RT_FEATURE, RT_INPUT, RT_OUTPUT = 0x03, 0x01, 0x02


def set_report(dev, iface, rtype, rid, data):
    return dev.ctrl_transfer(0x21, 0x09, (rtype << 8) | rid, iface, data, 2000)


def get_report(dev, iface, rtype, rid, length):
    return dev.ctrl_transfer(0xA1, 0x01, (rtype << 8) | rid, iface, length, 2000)


def airo_frame(cmd, params=b"", length=62):
    """Transport A frame as passed to IOHIDDeviceSetReport (sub_100108d0d):
    buf[0]=0x01 (report id duplicated inside the payload!), [1]=0x3C (len),
    [2]=cmd, [3..]=params."""
    f = bytearray(length)
    f[0] = 0x01
    f[1] = 0x3C
    f[2] = cmd
    f[3:3 + len(params)] = params
    return bytes(f)


def bulk_frame(cmd, params=b"", length=1023):
    """Transport B frame: [0]=0x01 (id in payload), [1]=cmd, [2..]=params."""
    f = bytearray(length)
    f[0] = 0x01
    f[1] = cmd
    f[2:2 + len(params)] = params
    return bytes(f)


def poll_get(dev, iface, rid, length, expect, secs=1.5, types=(RT_FEATURE,)):
    """GET_REPORT poll loop (macOS polls FEATURE id2 until echo)."""
    end = time.time() + secs
    while time.time() < end:
        for rt in types:
            try:
                r = bytes(get_report(dev, iface, rt, rid, length))
            except usb.core.USBError as e:
                print(f"    GET rt{rt} id{rid}: {e}")
                return None
            if any(r[1:]):
                echo = " ECHO" if r[2] == expect else ""
                print(f"    GET rt{rt} id{rid}: {r[:16].hex()}{echo}")
                if r[2] == expect:
                    return r
        time.sleep(0.1)
    print("    (replies all zero)")
    return None


def drain_ep(dev, ep, size=64, secs=0.5):
    """Read pushed reports from an interrupt IN endpoint."""
    got = []
    end = time.time() + secs
    while time.time() < end:
        try:
            got.append(bytes(dev.read(ep, size, 300)))
        except usb.core.USBError:
            if got:
                break
    if got:
        print(f"    EP{ep:#04x} pushed: {[g[:12].hex() for g in got]}")
    return got


def probe_mesh(dev):
    """0x3220: no OUT endpoint -> SET_REPORT control; FEATURE id2 poll."""
    print("\n== 0x3220 mesh interface: SET_REPORT(OUT,id1,61B) + GET(FEATURE,id2) ==")
    drain_ep(dev, 0x83)
    for cmd in (0x01, 0x05):
        print(f"  -- cmd {cmd:#02x} --")
        try:
            set_report(dev, 0, RT_OUTPUT, 1, airo_frame(cmd))
        except usb.core.USBError as e:
            print(f"    SET failed: {e}")
            return
        if poll_get(dev, 0, 2, 62, cmd) is None:
            drain_ep(dev, 0x83)


def probe_normal(dev):
    """0x3217: has interrupt EPs (0x81 IN 16B, 0x02 OUT 64B). Control
    SET_REPORT STALLed, so try raw interrupt OUT writes."""
    print("\n== 0x3217 normal interface: interrupt OUT EP2 writes ==")
    variants = [
        ("1024B [id1,01,cmd]", 0x02, bytes([0x01]) + bulk_frame(0x01)),
        ("1023B [01,cmd]", 0x02, bulk_frame(0x01)),
        ("64B [id1,01,cmd]", 0x02, (bytes([0x01]) + bulk_frame(0x01))[:64]),
    ]
    for label, ep, data in variants:
        print(f"  -- write EP{ep:#04x} {label} --")
        try:
            n = dev.write(ep, data, 2000)
            print(f"    wrote {n}")
        except usb.core.USBError as e:
            print(f"    write failed: {e}")
            continue
        drain_ep(dev, 0x81, 16)
        poll_get(dev, 0, 2, 67, 0x01, secs=0.6,
                 types=(RT_INPUT, RT_FEATURE))


def main():
    for pid, probe in ((0x3220, probe_mesh), (0x3217, probe_normal)):
        dev = usb.core.find(idVendor=VID, idProduct=pid)
        if dev is None:
            print(f"{pid:#06x}: not present")
            continue
        print(f"== {pid:#06x} bus {dev.bus} addr {dev.address} ==")
        try:
            if dev.is_kernel_driver_active(0):
                dev.detach_kernel_driver(0)
                print("  detached kernel driver from iface 0")
        except (NotImplementedError, usb.core.USBError) as e:
            print(f"  detach: {e}")
        probe(dev)
        usb.util.dispose_resources(dev)

    print("\nDone. If replies stayed zero with the headset ON, the mesh cmd")
    print("set or entry sequence differs and we go back to the disassembly.")


if __name__ == "__main__":
    sys.exit(main())
