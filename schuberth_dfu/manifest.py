"""Firmware manifest client.

The SENA/SCHUBERTH update server hosts two plain-text manifests under the
base URL:

    Firmware    - latest version per product
    Revisions   - every historical version (restore/downgrade)

Line format (verified live, findings.md "Update server protocol"):

    SENA                                  # vendor header line
    PRODUCT:version:filename.img          # latest entry
    PRODUCT:version:Language:filename.img # language-specific variant
    PRODUCT:<n>                           # per-product trailer line
"""
from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

BASE_URL = "https://firmware.sena.com/senabluetoothmanager/"
CHINA_BASE_URL = "https://firmware.senachina.com/senabluetoothmanager/"

FIRMWARE_MANIFEST = "Firmware"
REVISIONS_MANIFEST = "Revisions"

# A version token looks like v1.5 / v2.5.3; product keys are [A-Za-z0-9_]+.
_ENTRY = re.compile(r"^([A-Za-z0-9_]+):(v\d+(?:\.\d+)*)(?::([^:]+))?:?([^:]*)$")


@dataclass(frozen=True)
class Entry:
    product: str
    version: str
    filename: str
    language: Optional[str] = None


def parse_manifest(text: str) -> List[Entry]:
    """Parse manifest text into entries; trailer/`PRODUCT:<n>` lines ignored."""
    entries: List[Entry] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line == "SENA" or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue  # trailer line "PRODUCT:<n>"
        product, version = parts[0], parts[1]
        if not re.fullmatch(r"v\d+(?:\.\d+)*", version):
            continue  # trailer line with a bare count
        if len(parts) == 3:
            entries.append(Entry(product, version, parts[2]))
        elif len(parts) == 4:
            entries.append(Entry(product, version, parts[3], language=parts[2]))
    return entries


def fetch_manifest(name: str = FIRMWARE_MANIFEST, *, base_url: str = BASE_URL,
                   timeout: float = 30.0) -> List[Entry]:
    with urllib.request.urlopen(base_url + name, timeout=timeout) as resp:
        return parse_manifest(resp.read().decode("utf-8", "replace"))


def latest(entries: List[Entry], product: str) -> Optional[Entry]:
    """Latest entry for a product (manifest order is newest-first)."""
    for e in entries:
        if e.product == product and e.language is None:
            return e
    for e in entries:
        if e.product == product:
            return e
    return None


def download_url(entry: Entry, *, base_url: str = BASE_URL) -> str:
    return base_url + entry.filename
