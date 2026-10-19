"""SC1 family flow (ticket 08): static vendor model, sim-tested.
Live validation pending SC1A/SC1S/SC10U hardware."""
import os

import pytest

from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.sc2flow import Sc2Error, update_sc1
from schuberth_dfu.sim import FakeSc1, build_container


def sc1_container(n_images=2):
    blobs = [os.urandom(1300), os.urandom(640)][:n_images]
    names = [b"SC1A.img", b"vp_en.bin"][:n_images]
    if n_images == 3:                       # cap test: unexpected extra
        blobs.append(os.urandom(100))
        names.append(b"Submesh_v0.1b1.bin")
    data = build_container(version=b"v2.1.1-build2", device_id=0x5622,
                           blobs=blobs, names=names,
                           types=[0] * len(blobs))
    return data, parse_sena_container(data), tuple(blobs)


def test_sc1_full_flow_command_order(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, blobs = sc1_container()
    dev = FakeSc1(version=(2, 0, 0, 0))
    assert update_sc1(dev, container, data) is True
    # 0x01 skip-check, 0x01 vendor pre-handshake read, session preamble
    # (0x21 0x50 best-effort / 0x21 0x20 hard), per image 05 06xN 07,
    # final 0x08 + post-reboot version re-read
    assert dev.cmds == [
        0x01, 0x01, 0x21, 0x50, 0x21, 0x20,
        0x05, 0x06, 0x06, 0x07,      # SC1A.img: 1300 B = 2 chunks
        0x05, 0x06, 0x07,            # vp_en.bin: 640 B = 1 chunk
        0x08, 0x01,
    ]
    assert dev.applied == list(blobs)
    assert dev.version == (2, 1, 1, 0)


def test_sc1_session_refusal_aborts_before_flash(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, _ = sc1_container()
    dev = FakeSc1(version=(2, 0, 0, 0), accept_session=False)
    with pytest.raises(Sc2Error, match="0x21 result=2"):
        update_sc1(dev, container, data)
    for untouched in (0x05, 0x06, 0x07, 0x08):   # nothing flash-touching
        assert untouched not in dev.cmds
    assert 0x20 not in dev.cmds                  # aborted at the hard 0x21
    assert dev.applied == []


def test_sc1_best_effort_arm_failure_still_downloads(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, blobs = sc1_container()

    class NoArm(FakeSc1):
        """Firmware that refuses only the 0x50 arm (best-effort step)."""
        def write_bulk(self, cmd, params=b""):
            super().write_bulk(cmd, params)
            if cmd == 0x50:
                rep = bytearray(self._pending)
                rep[2] = 2
                self._pending = bytes(rep)

    dev = NoArm(version=(2, 0, 0, 0))
    assert update_sc1(dev, container, data) is True
    assert dev.applied == list(blobs)


def test_sc1_two_image_cap(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, blobs = sc1_container(n_images=3)
    dev = FakeSc1(version=(2, 0, 0, 0))
    assert update_sc1(dev, container, data) is True
    assert dev.applied == list(blobs[:2])        # vendor loop cap (r12,2)
    assert dev.cmds.count(0x07) == 2


def test_sc1_skips_when_current(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, _ = sc1_container()
    dev = FakeSc1(version=(2, 1, 1, 0))
    assert update_sc1(dev, container, data) is False
    assert dev.cmds == [0x01]
    assert dev.applied == []
