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


def sc2v2_container():
    main_blob, vp_blob, sub_blob = os.urandom(300), os.urandom(120), os.urandom(60)
    data = build_container(
        version=b"v2.4-build0", device_id=0x3217,
        blobs=[main_blob, vp_blob, sub_blob],
        names=[b"SC2.img", b"vp.bin", b"Submesh_v0.4b4.bin"],
        types=[0, 1, 3])
    return data, parse_sena_container(data), (main_blob, vp_blob, sub_blob)


def test_sc2v2_streams_all_blocks_through_airoha():
    from schuberth_dfu.sc2flow import update_sc2v2
    from schuberth_dfu.sim import FakeAiroha, FakeSc2V2
    data, container, (main_blob, vp_blob, sub_blob) = sc2v2_container()
    main, mesh = FakeSc2V2(version=(2, 3, 2, 1)), FakeAiroha(version=(0, 4, 0, 0, 4))
    assert update_sc2v2(main, mesh, container, data) is True
    assert main.chunks == b""                       # B is inert for writes
    assert mesh.written == main_blob + vp_blob      # blocks 0+1 via A
    assert 0x06 not in [c for c in main.cmds]
    assert main.cmds == [0x01, 0x0F, 0x08]          # version, start, reboot
    # submesh block skipped on version match: no 0x06 for its bytes
    assert sub_blob not in mesh.written


def test_sc2v2_skips_when_current():
    from schuberth_dfu.sc2flow import update_sc2v2
    from schuberth_dfu.sim import FakeAiroha, FakeSc2V2
    data, container, _ = sc2v2_container()
    main, mesh = FakeSc2V2(version=(2, 4, 0, 0)), FakeAiroha(version=(0, 4, 0, 0, 4))
    assert update_sc2v2(main, mesh, container, data) is False
    assert main.cmds == [0x01] and mesh.cmds == []


def test_parse_submesh_image_version():
    from schuberth_dfu.sc2flow import parse_submesh_image_version
    assert parse_submesh_image_version("Submesh_v0.4b4.bin") == (0, 4, 0, 0, 4)
    assert parse_submesh_image_version("vp.bin") is None


def test_airo_ready_retries_flaky_interface():
    from schuberth_dfu.airodfu import AirohaError, Link
    from schuberth_dfu.sc2flow import airo_ready
    from schuberth_dfu.sim import FakeAiroha

    class Flaky(Link):
        def __init__(self, h, fails):
            super().__init__(h, poll_interval=0, timeout=0.01)
            self.left = fails
        def version(self):
            if self.left:
                self.left -= 1
                raise AirohaError("silent")
            return super().version()

    link = Flaky(FakeAiroha(version=(0, 4, 0, 0, 4)), fails=3)
    assert airo_ready(link, retries=5, delay=0) == (0, 4, 0, 0, 4)


def test_sc2v2_death_at_block_start_reopens_and_resends():
    from schuberth_dfu.rawusb import RawUsbError
    from schuberth_dfu.sc2flow import update_sc2v2
    from schuberth_dfu.sim import FakeAiroha, FakeSc2V2
    data, container, (main_blob, vp_blob, _) = sc2v2_container()

    class ResettingAiroha(FakeAiroha):
        """Dies once, at the block-start cmd of block 0."""
        def write_report(self, d):
            if d[2] == 0x05 and not getattr(self, "done", False):
                self.done = True
                raise RawUsbError("I/O error")
            return super().write_report(d)

    main = FakeSc2V2(version=(2, 3, 2, 1))
    first = ResettingAiroha(version=(0, 4, 0, 0, 4))
    second = FakeAiroha(version=(0, 4, 0, 0, 4))
    assert update_sc2v2(main, first, container, data,
                        mesh_reopen=lambda: second) is True
    assert first.written == b""              # died before any chunk
    assert second.written == main_blob + vp_blob  # both blocks re-staged


def test_sc2v2_midblock_death_resends_the_block():
    from schuberth_dfu.rawusb import RawUsbError
    from schuberth_dfu.sc2flow import update_sc2v2
    from schuberth_dfu.sim import FakeAiroha, FakeSc2V2
    data, container, (main_blob, vp_blob, _) = sc2v2_container()

    class FlakyAiroha(FakeAiroha):
        """Dies mid-stream (second chunk), before anything is committed."""
        def write_report(self, d):
            if d[2] == 0x06 and len(self.written) == 58:
                raise RawUsbError("I/O error")
            return super().write_report(d)

    main = FakeSc2V2(version=(2, 3, 2, 1))
    first = FlakyAiroha(version=(0, 4, 0, 0, 4))
    second = FakeAiroha(version=(0, 4, 0, 0, 4))
    assert update_sc2v2(main, first, container, data,
                        mesh_reopen=lambda: second) is True
    assert first.written == main_blob[:58]     # died after 1 chunk
    assert second.written == main_blob + vp_blob  # block 0 re-sent whole
