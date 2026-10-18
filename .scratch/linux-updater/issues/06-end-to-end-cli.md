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

## Hardware validation checklist (first run, SC2)

1. `sudo cp udev/99-schuberth-dfu.rules /etc/udev/rules.d/ && sudo udevadm control --reload`, replug
2. Terminal A: `dmesg -w`; terminal B: `watch -n1 lsusb -d 092b:`
3. `schuberth-dfu detect` → expect `SC2 PID 0x3170 family=csr`
4. `schuberth-dfu check SC2 && schuberth-dfu download SC2 -o sc2.img`
5. `schuberth-dfu update --image sc2.img --yes`
   - up-to-date device → expect `VERSION IS SAME ... UPDATE SKIP` (safe first run)
   - watch terminal B during the flow: confirms the DFU-mode PID guess
     (0x3160/0x3220/0x6501/0x6511)
6. Triage: detect empty → udev/permissions; version query timeout →
   report-id mismatch (probe with hidapitest/hidrd); Find Mesh timeout →
   lsusb shows the real DFU PID, update DFU_MESH_PIDS; write ack errors →
   chunk/CRC semantics
7. Record results here + findings.md
- 2026-10-18: live session on SC2V2 (0x3217 + 0x3220). hidapi/kernel path
  dead (vendor descriptor typos); raw pyusb backend added (`rawusb.py`,
  sudo). Both transports confirmed on hardware: main fw v2.3.2.1 (behind
  v2.4), submesh 0.4.0.0.4 (current -> skip). `update_sc2v2` flow +
  `version` subcommand implemented, sim-tested. Remaining: probe the
  0x06 bulk write-ack, then the real flash.
