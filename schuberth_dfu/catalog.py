"""PID -> product catalog.

Data recovered from +[SENABluetoothManagerAppController
sbdm_product_name:for_internal:] in the macOS binary (see
docs/analysis/findings.md "Device catalog"). The internal names match the
product keys used by the server manifests.
"""
import csv
import importlib.resources as resources
from typing import Dict, Optional

# PIDs whose firmware container/flow is understood well enough to attempt an
# update. Populated as flows are implemented.
FAMILY_AIROHA = "airoha"
FAMILY_CSR = "csr"
FAMILY_QCC_MESH = "qcc_mesh"
FAMILY_PRISM = "prism"
FAMILY_SC1 = "sc1"

# Device family per PID, from the update-flow dispatch in
# -[UpdateViewController threadMethodUpdate:] (findings.md).
_FAMILIES = {
    0x3170: FAMILY_CSR,       # SC2
    0x3217: FAMILY_CSR,       # SC2V2 (recovered from container model id)
    0x321B: FAMILY_QCC_MESH,  # QCC_SC2
    0x3020: FAMILY_PRISM,     # PRISM
    0x5622: FAMILY_SC1,       # SC1A  (ticket 08: static model, live test pending)
    0x5623: FAMILY_SC1,       # SC10U
    0x5624: FAMILY_SC1,       # SC1S
    0x6400: FAMILY_SC1,       # SC1M  (device_id from its v1.1 container;
                                #      same exclusion-chain continuation)
    0x6510: FAMILY_AIROHA,    # ST1
    0x6840: FAMILY_AIROHA,    # AIROHASURGE
}

# Airoha DFU-mode PIDs (sub_1001086ec table range, findings.md).
_AIROHA_DFU_RANGE = range(0x6800, 0x683B)


def family_for_pid(pid: int) -> Optional[str]:
    fam = _FAMILIES.get(pid)
    if fam is None and pid in _AIROHA_DFU_RANGE:
        return FAMILY_AIROHA
    return fam


def load_catalog() -> Dict[int, str]:
    """Return {pid: internal product name}."""
    ref = resources.files(__package__).joinpath("data/pid-catalog.csv")
    with ref.open("r", encoding="utf-8") as fh:
        return {int(row["pid"], 16): row["internal_name"]
                for row in csv.DictReader(fh)}


_CATALOG = None


def catalog() -> Dict[int, str]:
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = load_catalog()
    return _CATALOG


def product_for_pid(pid: int) -> Optional[str]:
    return catalog().get(pid)
