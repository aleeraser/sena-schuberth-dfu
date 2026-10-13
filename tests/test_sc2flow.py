import os

from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.sc2flow import (CMD_NOP, CMD_REBOOT, CMD_RV, CMD_RUNLOADER,
                                   CMD_START, CMD_VERSION, CMD_WRITE,
                                   MeshLink, update_image, update_sc2)
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
