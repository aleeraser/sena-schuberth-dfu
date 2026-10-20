"""UI API tests: fake devices + fake updater, real HTTP round-trips."""
import json
import threading
import urllib.request

import pytest

from schuberth_dfu.ui import DeviceInfo, UIState, create_server


@pytest.fixture()
def server():
    devices = [DeviceInfo(0x3217, "SC2V2", "csr")]

    def versions(dev):
        return {"main": "2.3.2.1", "submesh": "0.4.0.0.4"}

    def updater(dev, image, force, log):
        log("staging image 0")
        log("image 0 committed (0x07)")
        return {"ok": True, "error": None}

    state = UIState(devices=lambda: devices, versions=versions,
                    updater=updater,
                    checker=lambda p: {"product": p, "version": "v2.4",
                                       "filename": "x.img"},
                    preparer=lambda p: {"path": "/tmp/x.img",
                                        "version": "v2.4",
                                        "filename": "x.img"})
    httpd = create_server(state, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return json.loads(r.read())


def post(base, path, body):
    req = urllib.request.Request(
        base + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def test_index_served(server):
    with urllib.request.urlopen(server + "/", timeout=5) as r:
        html = r.read().decode()
    assert "SCHUBERTH" in html and "Device recognition" in html


def test_state_lists_devices_with_versions(server):
    st = get(server, "/api/state")
    dev = st["devices"][0]
    assert dev["pid"] == "0x3217" and dev["supported"]
    assert dev["versions"]["main"] == "2.3.2.1"
    assert st["job"] is None


def test_check_and_prepare(server):
    assert get(server, "/api/check?product=SC2V2")["version"] == "v2.4"
    assert post(server, "/api/prepare", {"product": "SC2V2"})["path"] == "/tmp/x.img"


def test_update_job_lifecycle(server):
    r = post(server, "/api/update", {"pid": "0x3217", "image": "/tmp/x.img"})
    assert r.get("started")
    for _ in range(50):
        job = get(server, "/api/state")["job"]
        if job and job["status"] in ("done", "failed"):
            break
    assert job["status"] == "done"
    assert job["result"]["ok"] is True
    assert any("committed" in line for line in job["log"])


def test_update_rejects_unsupported_pid(server):
    r = post(server, "/api/update", {"pid": "0x9999", "image": "x"})
    assert "not connected" in r["error"]


def test_default_update_guard_refuses_wrong_device_image(tmp_path):
    """A 0x3170 image must be refused for a 0x3217 device before any
    USB access (device-id guard)."""
    from schuberth_dfu.sim import build_container
    from schuberth_dfu.ui import default_update
    img = tmp_path / "wrong.img"
    img.write_bytes(build_container(device_id=0x3170))
    res = default_update(DeviceInfo(0x3217, "SC2V2", "csr"), str(img),
                         False, lambda m: None)
    assert res["ok"] is False and "0x3170" in res["error"]
