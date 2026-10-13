# 03 — HID transport layer

Status: done

Implement `transport.py` over `hidapi`:

- Open VID 0x092B by PID; claim the HID interface with usage page 0xFF00 /
  usage 1 when multiple interfaces exist (airoha mesh case).
- Primitives mirroring the macOS shim (findings.md "Report geometry"):
  - `write_report(data)` — output report, ≤1023 bytes payload
  - `read_reply(timeout)` — input report, 67-byte replies
  - `feature_get(report_id=2)` / `feature_set` — 62-byte feature reports
- `detect` CLI subcommand: enumerate supported PIDs, print product name.
- Ship `udev/99-schuberth-dfu.rules` (MODE 0660, udev group) + README note.

## Comments

- 2026-10-13: implemented in `schuberth_dfu/transport.py` (hidapi) + udev rule
  + `detect` subcommand. No hardware on the dev box, so the open/report paths
  are untested against a device — first hardware session should validate
  report geometry assumptions.
