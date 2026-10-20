#!/usr/bin/env python3
"""Run the web UI against SIMULATED devices (no hardware needed).

Demo/documentation aid and dev convenience: serves the real UI on
localhost with one fake SC2V2 (current 2.3.2.1 -> latest 2.4.0.0) and a
fake UCOM3, wired to the fake-device flows. Nothing here touches USB.

Usage: python3 tools/ui_demo.py [--port 8791]
"""
import argparse

from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.sc2flow import update_sc2v2
from schuberth_dfu.sim import FakeSc2V2, build_container
from schuberth_dfu.ui import DeviceInfo, UIState, create_server

DEV = DeviceInfo(0x3217, "SC2V2", "csr")
FAKE = FakeSc2V2(version=(2, 3, 2, 1), target=(2, 4, 0, 0))
DEMO_IMAGE = "/tmp/demo-sc2v2-2.4.0.0.img"


def make_state():
    def devices():
        return [DEV, DeviceInfo(0x3220, "Airoha companion", None)]

    def versions(dev):
        if dev.product_id == 0x3217:
            return {"main": ".".join(map(str, FAKE.version)),
                    "submesh": "0.4.0.0.4"}
        return {}

    def updater(dev, image, force, log):
        data = open(image, "rb").read()
        container = parse_sena_container(data)
        if container.device_id != dev.product_id:
            return {"ok": False, "error": "image is for another device"}
        update_sc2v2(FAKE, container, data, log=log, force=force)
        return {"ok": True, "error": None}

    def checker(product):
        return ({"product": product, "version": "v2.4",
                 "filename": "demo-sc2v2-2.4.0.0.img"}
                if product == "SC2V2" else {"error": "demo: SC2V2 only"})

    def prepare(product):
        if product != "SC2V2":
            return {"error": "demo: SC2V2 only"}
        return {"path": DEMO_IMAGE, "version": "v2.4",
                "filename": "demo-sc2v2-2.4.0.0.img"}

    return UIState(devices=devices, versions=versions, updater=updater,
                   checker=checker, preparer=prepare)


def write_demo_image():
    import pathlib
    p = pathlib.Path(DEMO_IMAGE)
    if not p.exists():
        p.write_bytes(build_container(
            version=b"v2.4-build0", device_id=0x3217,
            blobs=[b"SC2 image demo bytes " * 200,
                   b"voice prompts demo bytes " * 120,
                   b"submesh demo bytes " * 80],
            names=[b"SC2.img", b"vp.bin", b"Submesh_v0.4b4.bin"],
            types=[0, 1, 3]))
    return str(p)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    write_demo_image()
    httpd = create_server(make_state(), a.host, a.port)
    print(f"UI DEMO (simulated devices): http://{a.host}:{a.port}/  Ctrl-C stops")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
