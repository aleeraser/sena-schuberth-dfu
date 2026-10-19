# CHECKPOINT — SC2V2 live-flashing session (2026-10-18/19)

Self-contained takeover state. If you read only one file, read this;
`docs/analysis/findings.md` is the curated RE knowledge base, this file
is the *working* state including dead ends and the live experiment log.

## 1. Goal & where we stand

Reverse-engineer the SCHUBERTH Bluetooth Device Manager (Windows NSIS
setup.exe + macOS .pkg, no Linux version) and build a Linux updater.
The Python package `schuberth_dfu` is complete and unit-tested (35 tests
pass offline). **Ticket 06 (end-to-end validation on the real SC2V2) is
blocked on hardware, not knowledge**: the vendor update flow is fully
reconstructed (findings.md "SC2V2 vendor flow, fully reconstructed") and
our package now reproduces it byte-exactly; the live unit refuses the
update **session handshake (cmd 0x20, status 2)** because its battery is
dead/removed — the headset does not power on at all, and the vendor app
enforces the same power/battery precondition. Next hardware step: a
working battery or a second SC2V2 unit; §7 has the plan.

## 2. Quickstart (fresh shell)

```bash
cd /home/alessandro/git/reverse-engineer/schuberth-firmware-updater
# venv (rebuild if gone): python3 -m venv /tmp/opencode/venv-schuberth
#   /tmp/opencode/venv-schuberth/bin/pip install -e .[dev]
# USB access needs root; pkexec works from the agent shell (polkit GUI
# prompt on the user's desktop). pkexec resets cwd → always absolute paths.
pkexec /tmp/opencode/venv-schuberth/bin/schuberth-dfu version
pkexec /tmp/opencode/venv-schuberth/bin/schuberth-dfu update --image /home/alessandro/git/reverse-engineer/schuberth-firmware-updater/firmware/sc2v2-2.4.0.0.img --yes
```

udev rules for hidraw are installed (`udev/99-schuberth-dfu.rules`) but
the SC2V2 path uses **pyusb raw USB** (hidraw/hidapi are unusable here,
see §5), which needs root (it detaches hid-generic).

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
- Device state at time of writing: responsive on both sides, version still
  2.3.2.1; **will not power on (dead/removed battery)** → session cmds
  (0x20/0x21/0x22/0x0F/0x10/0x12) answer status 2; flash steps refused.

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

### THE GATE (settled 2026-10-19): power/battery precondition
The vendor's 0x3217 flow requires the session handshake `0x20 → 0x22(x25) →
0x21` (0x10004bb8c/…bbc5/…bfc0, failure branch logs "UPDATE START MESH
HANDLE FIND") before any CSR download; the vendor aborts if it fails. Our
unit refuses (status 2) **because the headset does not power on at all —
dead/removed battery** (user confirmed: no power-on even unplugged). The
`0x0E` refusal (status 2) and inert commits are the same power/flash
precondition. The vendor app would fail identically on this unit. Ticket 06
is blocked on **hardware (working battery / another SC2V2 unit)**, not on
protocol knowledge.

### Corrected protocol facts (supersede older claims in §5 where they conflict)
- `sub_100108c1b` (c1b) puts the FF sentinel in the **reply buffer**, not the
  frame. All vendor frames are `[01 cmd 00 00 ...]` zero-padded 1023 B.
  (Our `[01 cmd FF]` probes worked for queries; commit needs `[01 07 00]`.)
- CSR download: `0x05` start `[01 05 00]`; chunks `[01 06 lenBE16 data≤1019]`
  (length at [2..3], data at [4]); last chunk cmd `0x0E`; per-chunk ack read
  (busy `[2]==1` → retry; non-busy reply ends the wait — status 2 does NOT
  stop the vendor loop, it exits the ack wait and continues).
- `0x20/0x22/0x21` are part of OUR deviceTarget's phase (0x10004b900+) —
  earlier note "0x20/0x22 only for deviceTarget 0x3240" was wrong.
- 0x3220 report sizes are 61 B OUT/IN; 1023 B SET_REPORT to it times out.
  The whole CSR download for SC2V2 runs on **0x3217** (slot 0 = 1086ec
  handle) — 0x3220 only carries the transport-A submesh block loop.
- Shim: `sub_10012e44c` write = HID output report id1 len 1023;
  `sub_10012e68e` read = 67 B input report. Handle obj: {+0x00 IOHIDDevice,
  +0x10 error, +0x40 buffered file, +0x90 timeout}.

### Phase map for deviceTarget 0x3217 (verified by chain trace)
`0x10003e3dc` PID chain (0x3210–0x321C all → 0x10003e54d "BBBBB") → chains
at 0x10003f691/0x100040b57 exclude 0x3217 → **default fallthrough** → QCC-BT
phase 0x10004b900–0x10004d600 (0x0A/0x01 → 0x20/0x22/0x21 → 0x21/0x20 →
0x05/chunks/0x0E → 0x07/0x08 → reopen → 0x0A "VP GOGO") → mesh/submesh block
loop (0x100045728) separately.

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
1. **Get a working battery / second SC2V2** → rerun
   `pkexec …/schuberth-dfu update --image …/firmware/sc2v2-2.4.0.0.img --yes`
   (csr_full.py is the raw driver if needed). Watch: 0x0E ack should be
   status 0 on a healthy unit; then version → 2.4.0.0 closes ticket 06.
2. If a healthy unit shows 0x0E→0 but commit inert: try `0x05` with [2]=1
   (second-chain flag byte variant) and check 0x0A payload semantics.
3. Offline (unblocked): ticket 09 PARTDATA grammar, 08 SC1 flow, 10 PRISM;
   then UI decision (ticket 03).

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
- `sc2flow.py`: `MeshLink` (B), `read_version`, `parse_container_version`,
  `parse_submesh_image_version` ("Submesh_v0.4b4.bin"→(0,4,0,0,4)),
  `airo_ready` (13× cmd-0x01 gate), `_reopen_mesh` (13× reopen after
  apply-reset), **`update_sc2v2(main_handle, mesh_handle, container,
  data, *, log, force, mesh_reopen)`** = the live flow (version skip →
  0x0F → per block: skip-if-type3-current, 0x01(idx), 0x05, chunks
  (stage), reopen+airo_ready per block → final 0x07+0x08 on mesh + B
  0x08). `update_sc2` = old SC2 (0x3170) flow, untouched.
- `sim.py`: FakeSc2V2 / FakeAiroha (sets reply length byte; handles
  0x01/0x05/0x06/0x07/0x08/0x0A/0x5B) / FakeSc2 / build_container.
- `cli.py`: subcommands detect/check/download/version/update; SC2V2
  dispatch opens RawHandle(0x3217)+RawHandle(0x3220), passes
  `mesh_reopen=lambda: RawHandle(0x3220)`.
- Tests: `tests/` — 32 pass offline (sim-based), incl. reopen/retry
  paths. Run: `/tmp/opencode/venv-schuberth/bin/python -m pytest -q`.

## 9. Operational gotchas

- pkexec: absolute paths only (cwd resets to /root); auth dialog on
  user's desktop; auth cache expires (~ask user to click Authenticate;
  if a pkexec-launched job logs nothing, it's waiting on the dialog).
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
