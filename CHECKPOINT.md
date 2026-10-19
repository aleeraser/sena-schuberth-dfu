# CHECKPOINT — SC2V2 live-flashing session (2026-10-18/19)

Self-contained takeover state. If you read only one file, read this;
`docs/analysis/findings.md` is the curated RE knowledge base, this file
is the *working* state including dead ends and the live experiment log.

## 1. Goal & where we stand

Reverse-engineer the SCHUBERTH Bluetooth Device Manager (Windows NSIS
setup.exe + macOS .pkg, no Linux version) and build a Linux updater.
The Python package `schuberth_dfu` is complete and unit-tested (36 tests
pass offline). **Ticket 06 is DONE: the real SC2V2 was updated
2.3.2.1 → 2.4.0.0 on 2026-10-19 with the vendor-exact flow** (findings.md
"SC2V2 vendor flow — LIVE VERIFIED"). Note the earlier "power/battery
gate" and "session handshake" model was a misread — the 0x20/0x21/0x22/
0x0E commands belong to the PRISM family; 0x3217's real flow is a simple
per-image `0x05 [2=flag] / 0x06 chunks / 0x07` loop for ALL container
images over the 0x3217 interface, one `0x08` at the end (details §5/§6).
Remaining work: other device families — ticket 08
(SC1A/SC10U/SC1S/SC1M) is RE-searched and implemented (`update_sc1`,
sim-tested, **live hw validation pending**); tickets 09 (QCC/PARTDATA
container) and 10 (PRISM, BT transport) are open; 07 (Airoha block
table) is offline research.

## 2. Quickstart (fresh shell)

```bash
cd /home/alessandro/git/reverse-engineer/schuberth-firmware-updater
# venv (rebuild if gone): python3 -m venv /tmp/opencode/venv-schuberth
#   /tmp/opencode/venv-schuberth/bin/pip install -e .[dev]
# USB access: udev rule installed 2026-10-19 (see below) -> NO root needed
# on this machine. (On a fresh machine: sudo cp udev/99-schuberth-dfu.rules
# /etc/udev/rules.d/ && sudo udevadm control --reload, replug; or use
# pkexec for one-off root runs — absolute paths, cwd resets.)
/tmp/opencode/venv-schuberth/bin/schuberth-dfu version
/tmp/opencode/venv-schuberth/bin/schuberth-dfu update --image /home/alessandro/git/reverse-engineer/schuberth-firmware-updater/firmware/sc2v2-2.4.0.0.img --yes
```

udev rules are installed on this machine (`/etc/udev/rules.d/99-schuberth-dfu.rules`,
from `udev/99-schuberth-dfu.rules` — now covers **both** `usb` (raw usbfs
nodes for the SC2V2 RawHandle path incl. hid-generic detach) and `hidraw`,
MODE 0660 GROUP plugdev; user is in plugdev). Verified rootless:
detect/version/update all run without pkexec. The SC2V2 path still uses
**pyusb raw USB** (hidraw/hidapi are unusable there, see §5) — just not root.

Device must be plugged in: `lsusb -d 092b:` → expect `092b:3217` (SC2)
and `092b:3220` (Airoha Headset). If 0x3217 stops answering (status
timeouts/hangs), **unplug/replug USB** — required after several reboot
commands; the vendor app needs it too.

## 3. Device under test

- SC2V2, main CSR side PID **0x3217**, Airoha side PID **0x3220**, VID 0x092B.
- Versions before any successful update: **main 2.3.2.1, submesh 0.4.0.0.4**.
- Target container: `firmware/sc2v2-2.4.0.0.img` (gitignored; re-fetch with
  `schuberth-dfu download SC2V2 -o firmware/sc2v2-2.4.0.0.img`) — v2.4-build0,
  device_id 0x3217, 3 images: `SC2.img` (type 0, 1,075,012 B, magic
  "CSR-dfu2"), `vp.bin` (type 1, 5,817,184 B), `Submesh_v0.4b4.bin`
  (type 3, 1,224,847 B). Block idx = container image index (0,1,2).
- Device state at time of writing: **updated to main 2.4.0.0** (submesh
  0.4.0.0.4) on 2026-10-19 via the vendor-exact flow (csr11); responsive
  on both interfaces. The "won't power on with USB / status 2 to 0x2x"
  behaviour is the *normal, intended* update state for this family
  (vendor dialog: "SC2 ... Leave it powered off") — see correction below.

## 4. Vendor artifacts (gitignored; on disk under `extract/`)

- `SCHUBERTHBluetoothDeviceManagerForMAC-v1.6.pkg` sha256 `d3b3bb1e…6bbb72` (xar)
- `…ForWindows-v1.6-setup.exe` sha256 `0a068e61…5e9acd` (NSIS)
- Mac binary: `extract/mac/payload/SCHUBERTHBluetoothDeviceManager.app/Contents/MacOS/SCHUBERTHBluetoothDeviceManager`
  fat Mach-O, x86_64 slice at file offset 16384, vm base 0x100000000 →
  **file offset = 16384 + (addr − 0x100000000)**. sha256 `ea94b0bc…9aaefcb`.
- Windows `DFUEngine.dll` sha256 `efe2c341…02d706b` (untouched so far).
- Update server: `https://firmware.sena.com/senabluetoothmanager/`.
- Key function: `threadMethodUpdate:` 0x100032b60–0x100060e4a (189 KB!).
  **Never decompile it whole** (user killed Hopper over RAM); use local
  capstone (`tools/re/disfunc.py <bin> <start> <end>`) and awk slices of
  the pre-dumped listing `/tmp/opencode/threadMethodUpdate.asm`
  (regenerate: disfunc.py whole range into a file if missing).
  CFString refs: `tools/re/cfstr.py <bin> ADDR…`.
- It is NOT table-driven: `jmp 0x100038cf8` = function epilogue
  (check-cancel → return or continue at 0x10003a781). The code is
  straight-line with branches; read it linearly in slices.
- SC2V2 branch marker string: `'BBBBBBBBBBBBBBB'` at chain entry
  0x10003e54d (PID compares 0x3218/0x321c/0x3214/0x3217 precede it).

## 5. Wire protocol (live-confirmed on SC2V2)

**0x3217 (transport B)**: EP2 interrupt OUT, **1023-B frame, no ID
prefix on the wire**: `[01 cmd params…]`. Replies **pushed on EP1 IN**
as ~12-B reports: `[02 echo result payload…]` (result 0 = OK).
- 0x01 → version `02 03 02 01` = 2.3.2.1. 0x0F (session start) →
  **status 2 usually, sometimes 0** (after certain states; meaning of 2
  unknown, vendor tolerates). 0x06/0x07/0x08 ACK but are **inert** for
  flashing (update1 proved B-side writes don't apply anything).
- Kernel hidraw is broken for this device (descriptor typo `96 FE 03`
  where 0x3F6=1014… meant → kernel truncates writes to 1 byte;
  GET_REPORT refused) → **pyusb raw backend** `schuberth_dfu/rawusb.py`.

**0x3220 (transport A)**: no OUT endpoint; commands via
**SET_REPORT(OUTPUT, id1), 62-B payload whose first byte duplicates the
ID**: `[01 3C cmd params…]`. Reply polled via **GET_REPORT(FEATURE,
id2)** → `[02 len echo status payload…]`; ready signal = **len byte
[1] != 0** AND echo at [2] (vendor poll loop sub_100108d34 does the
same; polling at 50 ms was the pacing bottleneck — 2 ms gives ~4 ms
per chunk round-trip, 50 ms gives ~90 ms).
- Report descriptor: id1 OUT 61B, id2 IN 61B, **id6 OUT / id7 IN 61B
  pair exists but is dead** (device ignores it). 65-B writes (vendor
  transport-C shape) are **NAKed** on Linux. `[01 cmd …]` (no 0x3C)
  framing is **ignored** — 0x3220 only speaks the 0x3C framing.
- Cmds live: 0x01(+idx param, param ignored, always answers
  `00 04 00 00 04`) OK; 0x00 NOP **never echoes (unsupported)**; 0x05
  bare = block UPDATE START (slow ~4 s); 0x06 chunk write `[3]=len(≤58)
  [4..]=data`, reply `[4..5]`=CRC16 LE of chunk — all CRCs matched for
  full 1 MB streams; **0x5B rejected status 2 (device doesn't
  implement it)**; 0x07 run-loader ACKs; 0x08 ACKs then device
  re-enumerates 0x3220 (~1 s gone, ~5 s to return); 0x0A answers 1
  (informational — vendor logs `GET_DFU_RESULT value[%d]` then `BLOCK
  %d UPDATE OK`, never gates on it).
- CRC-16/CCITT poly 0x1021 MSB-first, init 0 (`schuberth_dfu/crc.py`).

**Vendor code map** (threadMethodUpdate.asm slices):
- 60S-style Airoha flow: 0x10003bd6c–0x10003c3e3: 0x01(idx) version
  check → 0x05 → 0x06 chunks → **0x5B** running-CRC close → 0x08 → 0x0A.
  (This is the flow 0x5B belongs to — NOT SC2V2.)
- SC2V2 main phase: 0x10003fe34 "Qcc Mesh Update start": c1b(0x0F on
  B, must return OK) → loop 20× sub_100108466 (QCC mesh open; matches
  PIDs **0x3160 and 0x3220** — on SC2V2 the "QCC mesh" IS 0x3220) → on
  open success falls into block-loop region; open fail → retry → return.
- SC2V2 block loop (shared region entered from several branches):
  0x10004139c: 9161(NOP) → 9161(0x05) → 90ac(0x06 chunks, write-only)
  → 9161(0x07 "QCC Runloader Start") → 9161(0x08) → log "Find Mesh" →
  sub_100108466 re-open (13×) → epilogue. 9161/90ac write 65-B
  `[01 cmd FF…]` via macOS shim sub_10012e461 (ID-dup convention);
  on our Linux device the equivalent accepted shape is the 62-B
  `[01 3C cmd …]` A framing. macOS-side length quirks unexplored.
- VP phase branch: 0x1000408ed "Qcc Mesh Update start VP" → 0x0F →
  sub_100108544 (airoha mesh open, also 0x3220) → same block loop.
- sub_100108c1b = transport B cmd (slot 0 = 0x3217, opened by
  sub_1001086ec); sub_100109206 = transport A cmd w/ table @0x10024c620
  (cmds 0x00–0x0D + 0x50–0x5B, reply lengths; our REPLY_PAYLOAD_LEN).

## 6. Live experiment log (logs in /tmp/opencode/csrN.log; /tmp/opencode was wiped 2026-10-19 ~21:30 — venv+image rebuilt, image now in `firmware/`)

| # | flow variant | result |
|---|---|---|
| 1-13 | mesh (0x3220) block-loop variants (older revision) | staged OK, commit never applied (wrong phase for main images anyway) |
| csr1 | B CSR download, wrong chunk framing (`[01 06 FF 00 lenBE data]`) | 1 MB "staged" 19 s, ACKs, reboot → still 2.3.2.1 (device parsed len 0xFF00, discarded data; ack `[02 06 00]` only appears with correct framing) |
| csr2 | `0x05 [01 05 00]` sent via EP2 with NO follow-up | device stalled EP reads → replug. (Later understood: fine frame; the stall was the half-open download state.) |
| csr3 | 0x50→0x05 FF→chunks `[01 06 lenBE data]`→0x0E→0x07 FF→0x08 | chunk acks seen; commit ACK; rebooted (transient 0.0.0.0 = stale queued reply artifact); still 2.3.2.1 |
| csr4 | + per-chunk ack lockstep (vendor 100108a72) | all 1055 chunks acked st0; **0x0E (writeLAST) → status 2**; commit inert |
| csr5 | + commit frame `[01 07 00]` | commit ACK; still 2.3.2.1 — because 0x0E finalization was refused (status 2): staging never completed on this unit |
| handshake probe | `0x0A,0x01,0x20,0x22,0x21` in vendor order | 0x20/0x22/0x21 all **status 2** (also 0x0F/0x10/0x12/0x13/0x21/0x40/0x5A/0x5B); OK: 0x01/0x02/0x03/0x05/0x06/0x07/0x08/0x0A/0x50/0x51/0x60 |
| csr7 | all-0x06 staging capacity probe | **all 1,075,012 B acked st=0** (no capacity limit); bare `[01 0E 00]` also status 2 |
| csr8 | all 0x06 (no 0x0E at all) -> 0x07 commit -> 0x0A x8 -> 0x08 | commit ACK st0, 0x0A [3]=2 constant, 0x08 re-enumerates, still 2.3.2.1 |
| meshfirst/meshcommit | A:0x05 dummy / full submesh stage+A:0x07+0x08 first, THEN B:0x20/0x22/0x21 | mesh phase runs fine (submesh re-staged+committed, same version), B handshake STILL status 2 — mesh-first does not unlock |
| arm combos | 0x50->0x51->0x60 -> handshake | no change; 0x02 payload `01 95 DC 35 8D` static across samples (device id/counter, not voltage) |
| **static breakthrough** | PID gate at 0x10004bb7f: `cmp eax,{0x5510,0x5580,0x5570,0x5576,0x3060}; jne 0x10005d2b0` | the whole 0x20/0x22/0x21+0x0E region is PRISM-family only; 0x3217's real path is 0x10005d2b0 (per-image 0x05[2=flag]/0x06/0x07 loop) — everything empirical up to here was chasing a phantom |
| csr9/csr10 | replay attempts w/ capped retries | stalled at image1 0x05 (device busy writing flash post-commit; capped pyusb retries misread it) — fix: block like vendor c1b |
| **csr11 — UPDATE SUCCEEDED** | vendor-exact: sleep5, (0x05[b], 0x06xN tight-ack, 0x07)x3, sleep5, 0x08 | staged 1.07/5.82/1.22 MB in 41/156/113 s, all acks+commits status 0; after 0x08 device re-enumerated ~40 s; **version 2.4.0.0**, submesh 0.4.0.0.4. Ticket 06 closed |

### THE "GATE" WAS A PHANTOM (corrected later on 2026-10-19 — device now updated to 2.4.0.0)
The earlier conclusion ("session handshake 0x20→0x22→0x21 required; our
unit refuses due to dead battery") was a **dispatch misread**: that whole
handshake block (0x10004bb8c+) is gated at 0x10004bb02–0x10004bb85 to the
PRISM-family PIDs {0x5510,0x5580,0x5570,0x5576,0x3060}; every other PID —
0x3217 included — takes `jne 0x10005d2b0` and never sends 0x2x/0x0E.
Status 2 to those commands is "not implemented on this product", not a
power gate. The real 0x3217 flow (0x10005d2b0) worked on the first
vendor-exact replay with the headset in its normal USB/powered-off state:
sleep(5) → per image (ALL three, incl. submesh, over 0x3217 only):
0x05 [2=Image.flag] → 0x06 chunks (tight busy-ack, no sleeps) → 0x07 →
sleep(5) → 0x08 [01 08 00] → device self-reboots (~40 s) → 2.4.0.0.
The dead-battery story started from the user's unit powering off when
USB is plugged — that is simply how this family enters update mode.

### Corrected protocol facts (supersede older claims in §5 where they conflict)
- `sub_100108c1b` (c1b) puts the FF sentinel in the **reply buffer**, not the
  frame. All vendor frames are `[01 cmd 00 00 ...]` zero-padded 1023 B.
  (Our `[01 cmd FF]` probes worked for queries; commit needs `[01 07 00]`.)
- CSR download on 0x3217: `0x05` start **[2=Image.flag]**; chunks
  `[01 06 lenBE16 data≤1019]` (length at [2..3], data at [4]); NO 0x0E
  last-chunk on this PID — 0x0E/0x20/0x21/0x22 are PRISM-family commands.
  Per-chunk ack read (sub_100108a72: tight loop, retry while `[2]==1`,
  no sleep, no timeout).
- Live EP1 pushes lag one write behind: always echo-match `reply[1]==cmd`
  when reading acks (bulk(echo=True) in sc2flow).
- 0x3220 report sizes are 61 B OUT/IN; 1023 B SET_REPORT to it times out.
  For SC2V2 the 0x3220 interface carries **no vendor update traffic at
  all** — even the submesh image stages via 0x3217.
- Shim: `sub_10012e44c` write = HID output report id1 len 1023;
  `sub_10012e68e` read = 67 B input report. Handle obj: {+0x00 IOHIDDevice,
  +0x10 error, +0x40 buffered file, +0x90 timeout}. `0x10013c855` =
  sleep(edi seconds).

### Phase map for deviceTarget 0x3217 (verified 2026-10-19, live-verified)
`0x10003e3dc` PID chain (0x3210–0x321C all → 0x10003e54d "BBBBB") →
fallthrough chains → PID gate at 0x10004bb02 (PRISM handshake region
skipped: `jne 0x10005d2b0`) → **image loop 0x10005d2b0–0x10005d4cf**
(sleep 5; per image 0x05[2=flag]/0x06xN/0x07) → 0x10005e900 (sleep 5) →
PID chains → 0x10005f1e2 (0x08 [01 08 00] if did_any; sleep 1) →
0x100060274 final (reopen handles, re-read versions).

## 7. Working-tree state at checkpoint time

Committed with this update: rewritten `schuberth_dfu/sc2flow.py` SC2V2 flow
(session handshake + B-side CSR download for types 0/1, mesh loop now only
for type-3 submesh), updated `sim.FakeSc2V2` (staging/commit/power gate),
rewritten sc2v2 tests (35 pass + selftest), `tools/re/csr_download.py`
(chunked staging driver), `tools/re/csr_full.py` (vendor-exact sequence,
aborts safely before flash when the session is refused), `firmware/`
gitignored, image re-downloaded to `firmware/sc2v2-2.4.0.0.img`.

Live CLI on our unit now prints exactly:
`SC2V2 flow failed: device refused the update session (cmd 0x20). The
headset's main system must be powered on with a working battery…`

### Next steps (in order)
1. Optional regression: re-run `…/schuberth-dfu update --image
   …/firmware/sc2v2-2.4.0.0.img --yes` on the now-2.4.0.0 unit (same
   version → should print SKIP; with --force it should re-flash cleanly).
   Nothing else stands between us and "SC2V2 supported" — the CLI flow
   code is what csr11 proved on hardware.
2. SC1 hardware whenever available (0x5622/0x5623/0x5624 or SC1M
   0x6400): `schuberth-dfu update --image firmware/sc1a-2.1.1.img --yes`
   — the flow is the ticket-08 static model (`update_sc1`); watch for
   0x21/0x50/0x20 replies (status 0 expected; abort is vendor-exact
   behavior on refusal). Closes the last SC1 unknown.
3. Offline (unblocked): ticket 09 PARTDATA grammar, 10 PRISM (its
   handshake region 0x10004bb8c–0x10005f1e2 + BT transport angle),
   07 block-table research.

## 8. Code map (`schuberth_dfu/`)

- `catalog.py`/`manifest.py`: server catalog fetch, signed manifest.
- `container.py`: SENa container parse (`parse_sena_container`,
  `Image.blob(data)`, `is_qcc_appu`).
- `crc.py`: `crc16_ccitt(data, init=0)`.
- `transport.py`: hidapi handles (for other device families).
- `rawusb.py`: **pyusb RawHandle** for SC2V2: `write_report`/
  `feature_get` (transport A), `write_bulk`/`read_bulk` (transport B,
  skips all-zero pushed reports), `_xfer` wraps pyusb errors as
  `RawUsbError`.
- `airodfu.py`: transport A `Link` (`command` = SET + poll until
  `[1]!=0 && [2]==cmd`; `version`, `block_version(idx)`=0x01+param,
  `start_block()`=0x05, `write_chunk`=0x06, `block_crc`=0x5B (60S
  only), `run_loader`=0x07, `verify`=0x08, `get_dfu_result`=0x0A);
  `update_image(..., close="airoha"|"sc2v2"|"stage")` — "stage" =
  chunks only, no close (current SC2V2 mode); `AirohaResetError` =
  link died at commit (device applied).
- `sc2flow.py`: `MeshLink` (B transport; `bulk(..., echo=True)` = the
  live-safe echo-matched read), `read_version`, `parse_container_version`,
  `_stage_and_commit` (per-image 0x05[2=flag]/0x06xN/0x07),
  `_wait_after_reboot`, **`update_sc2v2(main_handle, container, data, *,
  log, force, reopen)`** = the LIVE-VERIFIED SC2V2 flow;
  **`update_sc1(...)`** same signature = ticket-08 SC1-family model
  (session preamble 0x01/0x21/0x50 best-effort → hard 0x21 → 0x20;
  first-2-images cap; live hw test pending). `update_sc2` = old
  unverified 0x3170 model, kept for history; `airo_ready`/
  `find_mesh_handle` serve it.
- `sim.py`: FakeSc2V2 / FakeSc1 (`accept_session=False` = refuses the
  session cmds) / FakeAiroha (sets reply length byte; handles
  0x01/0x05/0x06/0x07/0x08/0x0A/0x5B) / FakeSc2 / build_container.
- `cli.py`: subcommands detect/check/download/version/update; SC2V2
  dispatch opens RawHandle(0x3217)+RawHandle(0x3220), passes
  `mesh_reopen=lambda: RawHandle(0x3220)`.
- Tests: `tests/` — 32 pass offline (sim-based), incl. reopen/retry
  paths. Run: `/tmp/opencode/venv-schuberth/bin/python -m pytest -q`.

## 9. Operational gotchas

- USB access on this machine is passwordless since 2026-10-19 (udev rule
  installed; user in plugdev). pkexec remains the fallback on machines
  without the rule: absolute paths only (cwd resets to /root); auth
  dialog on user's desktop; auth cache expires (~ask user to click
  Authenticate; if a pkexec-launched job logs nothing, it's waiting on
  the dialog). Orphaned root probes: `pkexec kill -9 <pid>`.
- One process can hold the device: EBUSY(16) on ctrl transfers = the
  background update job is still running.
- B-side reads return **stale pushed replies** right after opening the
  handle — drain or retry (see probe_5b_staging).
- After 0x08 (and sometimes 0x07) the device goes deaf until USB
  replug. Ask the user: "please unplug/replug".
- Chunk pace: keep poll_interval 0.002 (airodfu Link default); SC2.img
  ≈ 80 s, vp.bin ≈ 7 min.
- Long updates: run backgrounded with log to /tmp/opencode/updateN.log;
  don't poll, wait for completion notice.

## 10. Repo conventions & tickets

- Commit style: lowercase, meaningful topic prefix (not generic
  `feat:`); license (GPL-3.0-or-later) is first in history — never
  rewrite it later. Vendor binaries gitignored.
- Issues: `.scratch/linux-updater/issues/` (01–07, 11 done/nearly;
  **06 = this live validation**, has running commentary log appended;
  08 SC1, 09 PARTDATA grammar, 10 PRISM/QCC partition deferred).
- `docs/analysis/findings.md` = curated conclusions (updated through
  §5 above); this file = live working state. Keep both current.
