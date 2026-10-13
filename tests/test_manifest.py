import pathlib

from schuberth_dfu.manifest import (download_url, latest, parse_manifest)

FIXTURE = (pathlib.Path(__file__).parent / "fixtures" / "Firmware.txt").read_text()


def test_parse_fixture():
    entries = parse_manifest(FIXTURE)
    assert entries, "fixture produced no entries"
    products = {e.product for e in entries}
    assert {"SC2", "SC2V2", "AIROHAST1", "SRLMesh", "QCC5S"} <= products


def test_trailer_lines_ignored():
    entries = parse_manifest(FIXTURE)
    # "SC2:1" trailer must not become an entry
    assert all(not (e.product == "SC2" and e.version == "1") for e in entries)
    assert all(e.version.startswith("v") for e in entries)


def test_latest_sc2():
    entries = parse_manifest(FIXTURE)
    e = latest(entries, "SC2")
    assert e is not None
    assert e.version == "v1.5"
    assert e.filename == "SC2-v1.5-build0.img"
    assert download_url(e).endswith("/SC2-v1.5-build0.img")


def test_language_entries():
    entries = parse_manifest(FIXTURE)
    mesh = [e for e in entries if e.product == "SRLMesh"]
    assert {e.language for e in mesh} == {"English", "German"}
    # latest() prefers a language-less entry, falls back to first variant
    e = latest(entries, "SRLMesh")
    assert e is not None and e.language == "English"


def test_unknown_product():
    entries = parse_manifest(FIXTURE)
    assert latest(entries, "NOPE") is None
