"""schuberth-dfu command line interface."""
from __future__ import annotations

import argparse
import sys
import urllib.request

from . import USB_VID
from .catalog import family_for_pid, product_for_pid
from .container import ContainerError, parse_sena_container, is_qcc_appu
from .manifest import (BASE_URL, FIRMWARE_MANIFEST, REVISIONS_MANIFEST,
                       download_url, fetch_manifest, latest)


def cmd_detect(args) -> int:
    from .transport import scan  # lazy: hidapi only needed for hardware
    devices = scan()
    if not devices:
        print(f"No supported headsets found (looking for VID {USB_VID:#06x}).")
        print("Note: DFU mode may require the device to be in its update "
              "state; see README.")
        return 1
    for d in devices:
        fam = family_for_pid(d.product_id) or "unsupported"
        print(f"{d.product_name:16} PID {d.product_id:#06x}  family={fam:8} "
              f"serial={d.serial_number or '-'}")
    return 0


def cmd_check(args) -> int:
    entries = fetch_manifest(FIRMWARE_MANIFEST)
    entry = latest(entries, args.product)
    if entry is None:
        print(f"No firmware for product {args.product!r} in the manifest.")
        print("Known products:",
              ", ".join(sorted({e.product for e in entries}))[:2000])
        return 1
    print(f"{entry.product}: latest {entry.version}")
    print(f"  file: {entry.filename}")
    print(f"  url:  {download_url(entry)}")
    if args.all_revisions:
        revs = fetch_manifest(REVISIONS_MANIFEST)
        for e in revs:
            if e.product == entry.product and e.language is None:
                print(f"  rev {e.version}: {e.filename}")
    return 0


def cmd_download(args) -> int:
    entries = fetch_manifest(FIRMWARE_MANIFEST)
    entry = latest(entries, args.product)
    if entry is None:
        print(f"No firmware for product {args.product!r}.")
        return 1
    url = download_url(entry)
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    out = args.output or entry.filename
    try:
        if is_qcc_appu(data):
            print("warning: Qualcomm APPUHDRV5 container, not supported yet")
        container = parse_sena_container(data)
    except ContainerError as exc:
        print(f"container parse failed: {exc}")
        return 1
    print(f"container {container.version} device_id={container.device_id:#06x} "
          f"images={len(container.images)} names={container.names}")
    for i, img in enumerate(container.images):
        ok = img.verify(data)
        print(f"  img[{i}] type={img.type} size={img.size:#08x} "
              f"md5={'OK' if ok else 'FAIL'} name={img.name or '-'}")
        if not ok:
            return 1
    with open(out, "wb") as fh:
        fh.write(data)
    print(f"saved {out} ({len(data)} bytes, all MD5s verified)")
    return 0


def cmd_version(args) -> int:
    from .rawusb import RawHandle, RawUsbError, scan_raw
    found = {p for p, _, _ in scan_raw()}
    if not found:
        print("no SC2V2-family interfaces present (092b:3217/092b:3220)")
        return 1
    try:
        if 0x3217 in found:
            from .sc2flow import MeshLink, read_version
            with RawHandle(0x3217) as h:
                print("main:   ", ".".join(map(str, read_version(MeshLink(h)))))
        if 0x3220 in found:
            from .airodfu import Link
            with RawHandle(0x3220) as h:
                print("submesh:", ".".join(map(str, Link(h).version())))
    except RawUsbError as exc:
        print(f"version read failed: {exc}")
        return 1
    return 0


def cmd_update(args) -> int:
    from .transport import Handle, scan  # lazy: hidapi only for hardware
    from .catalog import (FAMILY_AIROHA, FAMILY_CSR, FAMILY_SC1,
                          family_for_pid)

    devices = scan()
    if not devices:
        print("No supported headsets found.")
        return 1
    dev = devices[0]
    fam = family_for_pid(dev.product_id)
    print(f"device: {dev.product_name} PID {dev.product_id:#06x} family={fam}")

    if args.image:
        with open(args.image, "rb") as fh:
            data = fh.read()
    else:
        import urllib.request
        from .manifest import fetch_manifest, latest, download_url
        entry = latest(fetch_manifest(), dev.product_name)
        if entry is None:
            print(f"No manifest entry for {dev.product_name!r}; "
                  "pass --image.")
            return 1
        print(f"downloading {entry.filename}")
        with urllib.request.urlopen(download_url(entry), timeout=60) as resp:
            data = resp.read()

    from .container import parse_sena_container
    container = parse_sena_container(data)
    if not container.verify_all(data):
        print("container MD5 verification FAILED, refusing")
        return 1
    print(f"container {container.version}: "
          + ", ".join(f"{i.name or i.type}" for i in container.images))

    if fam not in (FAMILY_AIROHA, FAMILY_CSR, FAMILY_SC1):
        print(f"family {fam!r} update flow not implemented")
        return 2

    if not args.yes:
        print("Refusing to flash without --yes (flashing can brick the "
              "device; keep it plugged in throughout).")
        return 2

    def log(msg: str) -> None:
        print(msg, flush=True)

    if dev.product_id == 0x3217 or fam == FAMILY_SC1:
        # SC2V2/SC1: kernel HID path unusable (malformed descriptors) ->
        # raw USB control/interrupt transfers; needs the udev rule or root
        # (hid-generic detach). The whole update runs on the main
        # interface (companion PIDs like 0x3220 are not touched).
        from .rawusb import RawHandle, RawUsbError
        if dev.product_id == 0x3217:
            from .sc2flow import Sc2Error, update_sc2v2 as update_flow
        else:
            from .sc2flow import Sc2Error, update_sc1 as update_flow
            log("SC1 family: flow derived from the vendor binary "
                "(static model); not yet hardware-verified — report issues")
        try:
            update_flow(RawHandle(dev.product_id), container, data,
                        log=log, force=args.force,
                        reopen=lambda: RawHandle(dev.product_id))
        except (RawUsbError, Sc2Error) as exc:
            print(f"{fam.upper()} flow failed: {exc}")
            return 1
        log("update complete")
        return 0

    with Handle(dev) as handle:
        if fam == FAMILY_CSR:
            from .sc2flow import Sc2Error, update_sc2
            try:
                update_sc2(handle, container, data, log=log,
                           force=args.force)
            except Sc2Error as exc:
                print(f"SC2 flow failed: {exc}")
                return 1
        else:
            from .airodfu import AirohaError, Link, update_image
            link = Link(handle)
            try:
                for img in container.images:
                    log(f"writing {img.name or img.type} ({img.size} bytes)")
                    update_image(link, data, img,
                                 progress=lambda d, t: print(
                                     f"\r {d * 100 // t}%", end="", flush=True),
                                 log=log)
                print()
            except AirohaError as exc:
                print(f"\nAiroha flow failed: {exc}")
                return 1
    log("update complete")
    return 0


def cmd_selftest(args) -> int:
    """Exercise both update flows against simulated devices (no hardware)."""
    import os
    from .container import parse_sena_container
    from .sim import FakeAiroha, FakeSc2, build_container

    blobs = [os.urandom(4000), os.urandom(700)]
    data = build_container(blobs=blobs)
    container = parse_sena_container(data)
    assert container.verify_all(data)
    print(f"container: {len(container.images)} images, MD5s OK")

    print("airoha flow (transport A, 58B chunks + CRC16):")
    dev = FakeAiroha()
    from .airodfu import Link, update_image
    link = Link(dev, poll_interval=0, timeout=2)
    for img in container.images:
        update_image(link, data, img,
                     progress=lambda d, t: print(f"\r  {d*100//t}%",
                                                 end="", flush=True))
    print()
    assert bytes(dev.written) == b"".join(blobs), "airoha sim data mismatch"
    print("  OK: all bytes + CRCs verified, VERIFY/GET_DFU_RESULT sent")

    print("sc2 flow (transports B+C, 61B chunks, Find Mesh):")
    normal, mesh = FakeSc2(), FakeSc2(busy_once=True)
    from .sc2flow import update_sc2
    update_sc2(normal, container, data,
               log=lambda s: print(f"  [{s}]") if "Mesh" in s or "version" in s else None,
               mesh_opener=lambda: mesh)
    assert mesh.chunks == b"".join(blobs), "sc2 sim data mismatch"
    print("  OK: all bytes transferred, busy-retry handled")

    print("sc2v2 flow (live-verified: every image via transport B, "
          "0x05/0x06xN/0x07 per image, one final 0x08):")
    from .sc2flow import update_sc2v2
    from .sim import FakeSc2V2
    v2blobs = [os.urandom(4000), os.urandom(700), os.urandom(1300)]
    v2data = build_container(version=b"v2.4.0.0-build0", device_id=0x3217,
                             blobs=v2blobs,
                             names=[b"SC2.img", b"vp.bin",
                                    b"Submesh_v0.4b4.bin"],
                             types=[0, 1, 3])
    v2c = parse_sena_container(v2data)
    dev2 = FakeSc2V2(version=(2, 3, 2, 1), target=(2, 4, 0, 0))
    assert update_sc2v2(dev2, v2c, v2data, log=lambda s: None) is True
    assert dev2.applied == v2blobs, "sc2v2 image data mismatch"
    assert dev2.version == (2, 4, 0, 0) and dev2.reboots == 1
    print("  OK: 3 images staged+committed over B, reboot applied "
          "2.3.2.1 -> 2.4.0.0")
    print("selftest passed — protocol layers work; SC2V2 flow additionally "
          "verified end-to-end on real hardware (2.3.2.1 -> 2.4.0.0)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="schuberth-dfu",
                                 description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("detect", help="list connected supported headsets")

    p = sub.add_parser("check", help="show latest firmware for a product")
    p.add_argument("product", help="internal product name, e.g. SC2")
    p.add_argument("--all-revisions", action="store_true")

    p = sub.add_parser("download", help="download+verify latest firmware")
    p.add_argument("product")
    p.add_argument("-o", "--output")

    p = sub.add_parser("update", help="update a connected device")
    p.add_argument("--image", help="previously downloaded .img file")
    p.add_argument("--yes", action="store_true",
                   help="confirm flashing (required)")
    p.add_argument("--force", action="store_true",
                   help="flash even if versions match")

    sub.add_parser("version",
                   help="read live versions (SC2V2 raw USB, read-only)")

    sub.add_parser("selftest",
                   help="run the update flows against simulated devices")

    handlers = {"detect": cmd_detect, "check": cmd_check, "version": cmd_version,
                "download": cmd_download, "update": cmd_update,
                "selftest": cmd_selftest}
    args = ap.parse_args(argv)
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
