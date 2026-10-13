import os

import pytest

from schuberth_dfu.airodfu import AirohaError, Link, update_image
from schuberth_dfu.container import parse_sena_container
from schuberth_dfu.sim import FakeAiroha, build_container


def test_update_image_roundtrip():
    blobs = [os.urandom(1000), os.urandom(58 * 3)]
    data = build_container(blobs=blobs)
    c = parse_sena_container(data)
    dev = FakeAiroha()
    link = Link(dev, poll_interval=0, timeout=1)
    for img in c.images:
        update_image(link, data, img)
    assert bytes(dev.written) == blobs[0] + blobs[1]
    assert 0x08 in dev.cmds and 0x0A in dev.cmds


def test_update_image_crc_mismatch_aborts():
    data = build_container(blobs=[os.urandom(200)])
    c = parse_sena_container(data)
    dev = FakeAiroha(corrupt_crc=True)
    link = Link(dev, poll_interval=0, timeout=1)
    with pytest.raises(AirohaError, match="CRC mismatch"):
        update_image(link, data, c.images[0])


def test_chunking_respects_58_bytes():
    data = build_container(blobs=[os.urandom(120)])
    c = parse_sena_container(data)
    dev = FakeAiroha()
    link = Link(dev, poll_interval=0, timeout=1)
    update_image(link, data, c.images[0])
    assert len(dev.written) == 120  # fake asserts each chunk <= 0x3A
