import os

from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.sc2flow import (CMD_NOP, CMD_REBOOT, CMD_RV, CMD_RUNLOADER,
                                   CMD_START, CMD_VERSION, CMD_WRITE,
                                   MeshLink, parse_container_version,
                                   update_image, update_sc2)
from schuberth_dfu.sim import FakeSc2, build_container


def link_for(dev):
    return MeshLink(dev, busy_delay=0, busy_retries=10)


def test_bulk_and_mesh_command_sequence():
    dev = FakeSc2()
    link = link_for(dev)
    link.bulk(CMD_VERSION)
    link.mesh(CMD_NOP)
    assert dev.cmds == [("B", CMD_VERSION), ("C", CMD_NOP)]


def test_busy_reply_is_retried():
    dev = FakeSc2(busy_once=True)
    link = link_for(dev)
    link.mesh(0x05)  # first read busy, second OK
    assert dev.cmds == [("C", 0x05)]  # retried reads, not re-writes


def test_write_chunking_61_bytes():
    blob = os.urandom(200)

    class Img:
        def blob(self, data):
            return blob

    dev = FakeSc2()
    update_image(link_for(dev), None, Img())
    assert dev.chunks == blob
    assert dev.cmds.count(("C", CMD_WRITE)) == 4  # ceil(200/61)


def test_find_mesh_handle_accepts_dfu_pids(monkeypatch):
    from schuberth_dfu import sc2flow
    from schuberth_dfu.transport import Device

    seen = {}

    def fake_scan(extra_pids=frozenset()):
        seen["extra"] = extra_pids
        return [Device(path=b"x", vendor_id=0x092B, product_id=0x3160,
                       product_name="DFU-0x3160", serial_number="")]

    monkeypatch.setattr(sc2flow, "scan", fake_scan)
    marker = object()
    h = sc2flow.find_mesh_handle(retries=1, delay=0, opener=lambda d: marker)
    assert h is marker
    assert 0x3160 in seen["extra"]


def test_parse_container_version():
    assert parse_container_version("v1.5-build0") == (1, 5, 0, 0)
    assert parse_container_version("v2.5.3-build0") == (2, 5, 3, 0)


def test_update_sc2_skips_when_version_matches():
    # FakeSc2 reports version (1,0,2,3); match the container to it.
    data = build_container(version=b"v1.0.2.3-build0", blobs=[os.urandom(100)])
    c = parse_sena_container(data)
    normal, mesh = FakeSc2(), FakeSc2()
    assert update_sc2(normal, c, data, mesh_opener=lambda: mesh) is False
    assert normal.cmds == [("B", CMD_VERSION)]  # version query only
    assert mesh.cmds == []


def test_update_sc2_force_overrides_skip():
    data = build_container(version=b"v1.0.2.3-build0", blobs=[os.urandom(100)])
    c = parse_sena_container(data)
    normal, mesh = FakeSc2(), FakeSc2()
    assert update_sc2(normal, c, data, mesh_opener=lambda: mesh,
                      force=True) is True
    assert mesh.chunks  # data was written


def test_update_sc2_full_flow():
    blobs = [os.urandom(300), os.urandom(61)]
    data = build_container(blobs=blobs)
    c = parse_sena_container(data)
    normal = FakeSc2()
    mesh = FakeSc2()
    update_sc2(normal, c, data, log=lambda s: None,
               mesh_opener=lambda: mesh)
    kinds = [k for k in normal.cmds]
    assert kinds == [("B", CMD_VERSION), ("B", CMD_START)]
    assert mesh.cmds[0] == ("B", CMD_RV)
    assert mesh.cmds[1] == ("B", CMD_START)
    assert mesh.cmds[2:4] == [("C", CMD_NOP), ("C", 0x05)]
    assert mesh.chunks == blobs[0] + blobs[1]
    tail = [cmd for transport, cmd in mesh.cmds if transport == "C"]
    assert tail.count(CMD_WRITE) == 5 + 1  # ceil(300/61)=5 plus 1
    assert tail.count(CMD_RUNLOADER) == 2
    assert tail.count(CMD_REBOOT) == 2
