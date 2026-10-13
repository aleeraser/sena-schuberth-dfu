# schuberth-dfu

Linux firmware updater for SCHUBERTH (and SENA) motorcycle headsets, built
from reverse-engineering the vendor's Windows/macOS "Bluetooth Device
Manager" apps. Protocol evidence and analysis: `docs/analysis/findings.md`.

**Unofficial project.** Not affiliated with, endorsed by, or sponsored by
SCHUBERTH/HJC or SENA Technologies. All trademarks belong to their owners;
vendor firmware is not distributed here (installers are gitignored, with
their SHA-256s recorded in findings.md).

**Status: protocol-complete, hardware-untested.** Detection, manifest
lookup, firmware download + container verification, and both update flows
(Airoha feature-path, SC2 "Qcc Mesh" path) are implemented and unit-tested
against simulated devices. Nothing has run against a real headset yet —
the first live run needs validation of report ids/timings (ticket 06).

## Install (dev)

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e .[dev]
```

For device access: `pip install hidapi`, plus the udev rule:

```
sudo cp udev/99-schuberth-dfu.rules /etc/udev/rules.d/
# make sure your user is in the plugdev group
```

## Usage

```
schuberth-dfu detect                 # list connected supported headsets
schuberth-dfu check SC2              # latest firmware for product SC2
schuberth-dfu check SC2 --all-revisions
schuberth-dfu download SC2 -o sc2.img  # download + verify all MD5s
schuberth-dfu update --image sc2.img --yes   # flash connected device
schuberth-dfu selftest       # run both update flows against simulated devices
```

Product names are the internal catalog keys (see
`docs/analysis/pid-catalog.csv`), e.g. `SC2`, `SC2V2`, `ST1`, `PRISM`.

## Supported devices (plan)

| Product | PID | Family | Status |
|---|---|---|---|
| SC2 | 0x3170 | CSR | flow implemented (experimental, untested on hw) |
| SC2V2 | 0x3217 | CSR | flow implemented (experimental, untested on hw) |
| ST1/S1/M1 EVO/C30/… | various | Airoha | command+block loop implemented (untested on hw) |
| PRISM | 0x3020 | camera | later (ticket 10) |

## Tests

```
pytest
# against real firmware images you downloaded:
SCHUBERTH_TEST_IMGS=/path/st1.img:/path/sc2.img pytest
```

## Safety

Flashing firmware can brick a headset. This project is unofficial; only
proceed on your own risk. Never unplug power during an update.

## License

GPL-3.0-or-later. Deliberately copyleft: anyone (including the headset
vendors) may use and extend this work, but must keep distributed
derivatives open under the same license. Vendor firmware, installers and
their contents are not part of this work and not covered by this license.
