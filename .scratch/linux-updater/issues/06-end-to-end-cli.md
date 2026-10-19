# 06 — End-to-end update CLI

Status: done
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
- 2026-10-19 (DONE): live SC2V2 (0x3217) updated **2.3.2.1 → 2.4.0.0**
  with the vendor-exact flow, then via the package after rewriting
  `update_sc2v2` to the verified model: sleep(5); per container image
  (ALL three incl. submesh, over 0x3217 only — 0x3220 untouched):
  `0x05 [2=Image.flag]` → `0x06` chunks `[lenBE16 data≤1019]` tight
  busy-ack → `0x07`; sleep(5); `0x08`; device self-reboots (~40 s),
  version re-read confirms. The earlier "session handshake / power gate"
  model was a PRISM-family misread (PID gate 0x10004bb7f, see
  findings.md). 36 tests + selftest green.

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
- 2026-10-19: first flash (transport-B model) ACKed everything but left
  fw at 2.3.2.1 -> B writes are inert on SC2V2. Vendor BBBBB branch
  decoded: images stream through the Airoha interface (0x3220, cmd
  0x05/0x06/0x08/0x0A, block idx = container image index). Second run
  exposed a poll race (reply read before CRC filled) -> vendor's
  length-byte ready gate + chunk retry fixed it. pkexec works for the
  root step (polkit GUI prompt).
- 2026-10-18 (later): Airoha-side run got block 0 fully streamed+CRC'd
  in ~80 s (2 ms poll fixed the 90 ms/chunk pacing). GET_DFU_RESULT=1
  is informational (vendor logs only); device re-enumerates 0x3220
  ~1 s after each applied block -> vendor-style per-block re-open
  added. Full-bundle run in progress.
- 2026-10-18 (evening): framing settled (0x3220 parses only [01 3C cmd];
  id6/7 pair + 65B C-framing dead). Block loop semantics from the shared
  region: per image NOP/0x05/0x06*/0x07/0x08, and every phase must be
  re-armed with 0x0F on B (without it the next image's 0x06 -> status 2).
  Attempt 11 runs that exact vendor sequence.
