"""PRISM download-wrapper reader (ticket 10). Flashing stays unwired:
the drop-file derivation needs PRISM hardware."""
import pathlib

import pytest

from schuberth_dfu.container import parse_prism_update_image

SAMPLE = (pathlib.Path(__file__).resolve().parent.parent
          / "firmware" / "prism-1.0.0.0.img")


def test_prism_update_image_sample():
    if not SAMPLE.exists():
        pytest.skip("gitignored sample firmware/prism-1.0.0.0.img absent")
    p = parse_prism_update_image(SAMPLE.read_bytes())
    assert (p.version, p.pid, p.count) == ("v0.0.0.0", 0x3020, 2)
    assert p.bt_name == "PRISM#3020"
    assert p.bt_size == 0x131EA0
    assert p.comp0_size == 0x131EB0
    # the two components tile the file exactly
    assert p.main_offset + p.main_size == SAMPLE.stat().st_size


def test_prism_reader_rejects_other_images():
    with pytest.raises(Exception):
        parse_prism_update_image(b"\x00" * 0x200)
