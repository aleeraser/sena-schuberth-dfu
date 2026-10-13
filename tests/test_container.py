import os

import pytest

from schuberth_dfu.container import (ContainerError, SENA_MAGIC,
                                     is_qcc_appu, parse_sena_container)
from schuberth_dfu.sim import build_container


def test_roundtrip_and_md5():
    blobs = [os.urandom(1000), os.urandom(500)]
    data = build_container(blobs=blobs)
    c = parse_sena_container(data)
    assert c.version == "v9.9-build9"
    assert c.device_id == 0x3170
    assert len(c.images) == 2
    assert c.verify_all(data)
    for img, blob in zip(c.images, blobs):
        assert img.blob(data) == blob
    assert c.names == ["TEST_MAIN.bin", "TEST_VP.bin"]
    assert [img.name for img in c.images] == ["TEST_MAIN.bin", "TEST_VP.bin"]


def test_md5_tamper_detected():
    data = bytearray(build_container())
    c = parse_sena_container(bytes(data))
    data[c.images[0].offset + 10] ^= 0xFF  # flip a byte inside image 0
    c = parse_sena_container(bytes(data))
    assert not c.verify_all(bytes(data))


def test_bad_magic():
    data = bytearray(build_container())
    data[0x18:0x1C] = b"junk"
    with pytest.raises(ContainerError):
        parse_sena_container(bytes(data))


def test_qcc_sniff():
    data = b"\x00" * 0x180 + b"APPUHDR5" + b"\x00" * 0x100
    assert is_qcc_appu(data)
    assert not is_qcc_appu(build_container())


# Optional: run against real downloaded images when available.
REAL = [p for p in (os.environ.get("SCHUBERTH_TEST_IMGS", "").split(":")
                    if os.environ.get("SCHUBERTH_TEST_IMGS") else [])
        if os.path.exists(p)]


@pytest.mark.parametrize("path", REAL)
def test_real_images(path):
    data = open(path, "rb").read()
    c = parse_sena_container(data)
    assert c.verify_all(data), f"MD5 mismatch in {path}"
