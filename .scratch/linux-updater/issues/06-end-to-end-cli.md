# 06 — End-to-end update CLI

Status: in-progress
Blocked by: 01, 02, 03, 04, 05

Wire everything into `schuberth-dfu update`:

- detect → resolve product → fetch manifest → download `.img` (with resume +
  sha256 pinning of the downloaded file for repeatability) → parse container →
  run block-update loop → reboot device → re-read version to confirm.
- `--check-only` dry-run path; `--from-file` for offline images.
- README: usage, udev setup, supported device list, safety warnings.

## Comments
- 2026-10-13: `schuberth-dfu update` wired: detect → family dispatch
  (airodfu / sc2flow) → manifest download or --image → MD5 gate → --yes
  confirmation. All paths exercised offline via fake devices; the live
  hardware leg (report ids, busy timing, Find Mesh re-enumeration) is the
  remaining work.
