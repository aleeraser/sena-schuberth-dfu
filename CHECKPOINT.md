# CHECKPOINT — SC2V2 live-flashing session (2026-10-18/19)

Self-contained takeover state. If you read only one file, read this;
`docs/analysis/findings.md` is the curated RE knowledge base, this file
is the *working* state including dead ends and the live experiment log.

## 1. Goal & where we stand

Reverse-engineer the SCHUBERTH Bluetooth Device Manager (Windows NSIS
setup.exe + macOS .pkg, no Linux version) and build a Linux updater.
The Python package `schuberth_dfu` is complete and unit-tested (32 tests
pass offline). We are in **ticket 06: end-to-end validation on the real
device** — a SC2V2 headset (PID 0x3217). Many live flash attempts have
streamed every byte with matching CRCs, but **the firmware has not yet
been applied** (device still 2.3.2.1, target 2.4.0.0). The exact reason
is the open question; §7 has the current hypothesis and next experiment.

## 2. Quickstart (fresh shell)

```bash
cd /home/alessandro/git/reverse-engineer/schuberth-firmware-updater
# venv (rebuild if gone): python3 -m venv /tmp/opencode/venv-schuberth
#   /tmp/opencode/venv-schuberth/bin/pip install -e .[dev]
# USB access needs root; pkexec works from the agent shell (polkit GUI
# prompt on the user's desktop). pkexec resets cwd → always absolute paths.
pkexec /tmp/opencode/venv-schuberth/bin/schuberth-dfu version
pkexec /tmp/opencode/venv-schuberth/bin/schuberth-dfu update --image /tmp/opencode/sc2v2-dl.img --yes
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
- Target container: `/tmp/opencode/sc2v2-dl.img` — v2.4-build0,
  device_id 0x3217, 3 images: `SC2.img` (type 0, 1,075,012 B, magic
  "CSR-dfu2"), `vp.bin` (type 1, 5,817,184 B), `Submesh_v0.4b4.bin`
  (type 3, 1,224,847 B). Block idx = container image index (0,1,2).
- Device state at time of writing: responsive; staging area possibly
  dirty from probes (replug clears it).

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

## 6. Live experiment log (all logs in /tmp/opencode/updateN.log)

| # | flow variant | block 0 (SC2.img) | block 1 (vp.bin) | applied? |
|---|---|---|---|---|
| 1 | all via B 0x06 + B 0x07/0x08 | ACKed | — | **NO** (B writes inert) |
| 2 | A: 0x05,0x06*,0x08,0x0A | CRC race abort @0x7230 | — | no |
| 3 | + length-byte ready gate | Airoha silent (post-abort) | — | no |
| 4 | + airo_ready retry | full stream, EIO at 0x08 (re-enumerated) | — | no |
| 5 | + AirohaResetError | killed mid-run by us (pacing fix) | — | no |
| 6 | 2 ms poll | chunks OK, `GET_DFU_RESULT=1` treated as error (wrong) | — | no |
| 7 | result informational | OK+reset | 0x06 **status 2** | no |
| 8 | + 0x5B close | 0x5B **status 2** ×2 | — | no |
| 9 | 0x07+0x08 per block | ACK, reset, reopen | 0x06 status 2 | **NO** (main still 2.3.2.1 after replug) |
| 10 | stage all, 0x07+0x08 once | staged | 0x06 status 2 | no |
| 11 | + 0x0F re-arm per phase | staged | 0x06 status 2 | no |
| 12 | stage all, no closes | staged (1,075,012 B) | 0x06 status 2 | no |

Probes (tools/re/): `probe_sc2.py` (cmd walks), `probe_qcc_dfu.py`
(0x3217 transport-C download mode — inconclusive, run it right after a
0x07 before replug), `probe_5b_staging.py` (**key result**: with a
clean session, 0x5B rejected, but a **second 0x05+0x06 round was
ACCEPTED** after a first round of 64+8 chunks — small multi-round
staging works!). A capacity probe after that got rejected after only
24 chunks (device state was dirty by then; numbers unreliable — redo
after replug).

**Distinguishing observation (the current lead)**: probe round 2
(`0x01(1)` → `0x05` → chunks) worked; update12's block 1
(`0x01(1)` → **NOP** → `0x05` → chunks) failed. The only difference is
the NOP, which this device never echoes (unsupported in A framing).
Hypothesis: sending unsupported cmd 0x00 poisons the session → next
0x06 rejected with status 2. The vendor's NOP is fine because their
transport-C framing supports it.

## 7. Working-tree state at checkpoint time

Committed together with this file:
- `schuberth_dfu/sc2flow.py`: NOP call removed from update_sc2v2's
  per-block sequence (the experiment above).
- `tools/re/probe_5b_staging.py`: new probe.
Everything is pushed to `origin/main` (github.com/aleeraser/sena-schuberth-dfu).

### Next experiment (update13)
1. Replug USB (clear staging), `version` to confirm sane state.
2. `pkexec …/schuberth-dfu update --image /tmp/opencode/sc2v2-dl.img --yes`
   with NOP removed (stage-all mode: per block 0x01(idx)/0x05/0x06*,
   then single 0x07+0x08 at end + B 0x08).
3. If block 1 stages → let it finish → replug → `version` → expect
   main **2.4.0.0**.
4. If block 1 still rejected: capacity-probe after clean replug
   (stage continuously, find exact rejection offset; compare to
   1,075,012 / 1,224,847 / round numbers) — if staging capacity <
   vp.bin, the design must be per-block commit (0x07) and the problem
   is 0x07's commit semantics (maybe needs the device to be in a
   different mode; check `probe_qcc_dfu.py` right after 0x07).
5. Other unexplored leads: 0x01(idx) before block 1 (worked in probe,
   keep it); stale-reply artifacts on B reads (drain before queries);
   the Windows DFUEngine.dll as second opinion on the SC2V2 sequence;
   whether 0x0F-status-0-vs-2 correlates with staging success window.

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
