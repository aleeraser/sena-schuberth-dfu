"""QCC family flow (ticket 09): static vendor model + APPUHDRV5 grammar.
Live validation pending UCOM hardware."""
import os
import pathlib

import pytest

from schuberth_dfu.container import parse_sena_container, parse_qcc_partitions
from schuberth_dfu.sc2flow import Sc2Error, update_qcc
from schuberth_dfu.sim import FakeQcc, build_container

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "firmware" / "ucom3-1.4.1.img"


def qcc_container():
    main_blob, vp_blob = os.urandom(2500), os.urandom(640)
    data = build_container(version=b"v1.4.1-build0", device_id=0x3340,
                           blobs=[main_blob, vp_blob],
                           names=[b"ucom3.bin", b"vp.bin"], types=[0, 1])
    return data, parse_sena_container(data), (main_blob, vp_blob)


def test_qcc_full_flow_command_order(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, blobs = qcc_container()
    dev = FakeQcc(version=(1, 3, 0, 0))
    assert update_qcc(dev, container, data) is True
    assert dev.cmds == [
        0x01,
        0x03, 0x13,                          # ENTER_DNLD_MODE + preflight
        0x05, 0x06, 0x06, 0x0E, 0x07,        # main: 2500 B, LAST = 0x0E
        0x05, 0x0E, 0x07,                    # vp: 640 B (single chunk=LAST)
        0x08, 0x0A, 0x01,
    ]
    assert dev.applied == list(blobs)
    assert dev.commits_without_eof == 0
    assert dev.version == (1, 4, 1, 0)


def test_qcc_enter_dnld_refused_aborts_before_flash(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, _ = qcc_container()
    dev = FakeQcc(version=(1, 3, 0, 0), refuse_enter_dnld=True)
    with pytest.raises(Sc2Error, match=r"cmd 0x0?3 result=2"):
        update_qcc(dev, container, data)
    for untouched in (0x05, 0x06, 0x07, 0x08, 0x0E):
        assert untouched not in dev.cmds
    assert dev.applied == []


def test_qcc_skips_when_current(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    data, container, _ = qcc_container()
    dev = FakeQcc(version=(1, 4, 1, 0))
    assert update_qcc(dev, container, data) is False
    assert dev.cmds == [0x01]


def test_qcc_real_ucom3_partition_grammar():
    if not SAMPLE.exists():
        pytest.skip("gitignored sample firmware/ucom3-1.4.1.img not present")
    data = SAMPLE.read_bytes()
    container = parse_sena_container(data)
    assert container.device_id == 0x3340
    blob = container.images[0].blob(data)
    parts = parse_qcc_partitions(blob)
    assert parts.chip == "QCC512Xx"
    assert [r.kind for r in parts.records] == [0, 1, 9]
    assert parts.data_blob and len(parts.data_blob) == 0xab468 - 4
    assert len(parts.footer_hashes) == 16
    # vp.bin is an APPUHDR5 voice image too: kind-7 partition instead of 9
    vp = parse_qcc_partitions(container.images[1].blob(data))
    assert [r.kind for r in vp.records] == [0, 1, 7]
