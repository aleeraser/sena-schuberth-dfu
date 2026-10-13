# Spec: Linux firmware updater for SCHUBERTH/SENA headsets (`schuberth-dfu`)

Status: draft
Related analysis: `docs/analysis/findings.md`, `docs/analysis/pid-catalog.csv`

## Problem

SCHUBERTH ships firmware updaters only for Windows and macOS. A Linux user
cannot update the firmware on SCHUBERTH motorcycle headsets (SC1, ST1, PRISM,
SRC/SRH family…). The macOS/Windows apps are white-label SENA Bluetooth Device
Managers talking to SENA's firmware servers and to the headsets over USB.

## What we know (see findings.md for evidence)

- Firmware index: plain-text manifests `Firmware` / `Revisions` under
  `https://firmware.sena.com/senabluetoothmanager/`, lines
  `PRODUCT:version[:Language]:filename.img`.
- Devices enumerate as USB HID, VID **0x092B** (Airoha), PID identifies the
  product (`docs/analysis/pid-catalog.csv`).
- Airoha-family update protocol: 62-byte HID reports, command byte at `[2]`
  (5=version, 6=write 58-byte chunk, 8=verify, 0x0A=result), replies echo the
  command and carry a **CRC-16/CCITT** the host must match; per-block running
  CRC; firmware `.img` container = 724-byte header (magic `19 28 C5 E6`) +
  two MD5-checked images (voice prompts + AB156x loader/FW blob).
- QCC-family devices use the Qualcomm `APPUHDR5`/`PARTDATA` container; PRISM
  uses a simple name@0x10 + CRC-32-footer container.

## Goal (v1)

A Python 3 CLI, `schuberth-dfu`, that on Linux:

1. **detect** — scan USB HID for VID 0x092B, map PID → product via the catalog,
   print product + current firmware version.
2. **check** — fetch the `Firmware` manifest, resolve the latest version +
   filename for the detected product.
3. **download** — fetch the `.img`, verify container MD5s.
4. **update** — run the device-family update loop with progress output.

**v1 primary target: SC2 / SC2V2 (PIDs 0x3170 / 0x3217, CSR-based)** — the
maintainer's device. Flow: CSR DFU over HID ("Qcc Mesh" flow in the macOS app,
see findings.md "SC2"). Airoha-BT family (ST1/S1/…) is the secondary target
(its command layer is already decoded, tickets 04/05).

## Non-goals (v1)

- PRISM camera flow (later ticket).
- Device settings / intercom pairing features.
- Windows-only CSR/FTDI cable path (old SC1 via DFUEngine BCSP transport).
- GUI.

## Design

- `hidapi` (python3-hidapi / hid) for transport; udev rules file shipped.
- Pure-python CRC-16/CCITT (poly 0x1021, init 0, MSB-first) and MD5 checks.
- Modules: `catalog`, `manifest`, `container`, `transport`, `airodfu`, `cli`.
- All protocol constants centralized from findings.md with evidence refs.

## Acceptance (v1)

- `schuberth-dfu detect` lists a plugged-in ST1/S1-class device with product
  name and version.
- `schuberth-dfu update` takes that device from current → latest firmware
  end-to-end, with per-block progress and safe abort on CRC mismatch.
- Dry-run mode (`--check-only`) never touches the device beyond version read.
