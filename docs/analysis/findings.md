# Findings ledger — SCHUBERTH Bluetooth Device Manager v1.6

Reverse-engineering notes. Every claim is tagged **[observed]** (direct artifact
evidence), **[derived]** (computed from artifact bytes), or **[inferred]**
(hypothesis needing more evidence). Evidence IDs are REA session records.

## Artifacts

| Artifact | SHA-256 | Format |
|---|---|---|
| `SCHUBERTHBluetoothDeviceManagerForMAC-v1.6.pkg` | `d3b3bb1e…6bbb72` | xar (pkg), Payload = gzip cpio |
| `SCHUBERTHBluetoothDeviceManagerForWindows-v1.6-setup.exe` | `0a068e61…5e9acd` | NSIS-3 Unicode |
| extracted `SCHUBERTHBluetoothDeviceManager` (macOS) | `ea94b0bc…9aaefcb` | Mach-O fat (x86_64 + arm64), ObjC/Cocoa |
| extracted `SCHUBERTHBluetoothDeviceManagerForWindows.exe` | — | PE32 x86 MFC app (36 MB) |
| extracted `DFUEngine.dll` | `efe2c341…02d706b` | PE32 x86 DLL, 7841 procedures |

## Architecture [observed]

- The app is a **white-label SENA Bluetooth Device Manager**. The macOS binary
  contains `SENABluetoothManagerAppController` class names and downloads from
  `https://firmware.sena.com/senabluetoothmanager/` (China mirror:
  `firmware.senachina.com`). SCHUBERTH branding only changes bundle id, icons,
  and the device catalog shown to the user.
  - Evidence: strings in both binaries; `+[SENABluetoothManagerAppController is_china_server]`.
- macOS app: Cocoa + WebKit (help pages), ObjC, Xcode 16, min macOS 11.5.
  Views: DeviceRecognition → DeviceSelection → DeviceSettings → Update/Restore/ManagerUpdate/Precaution.
- Windows app: MFC (VC80 side-by-side assemblies), NSIS installer, uses
  `DFUEngine.dll` + `ftd2xx.dll` (FTDI D2XX) + HID (`HidD_*`).
- Firmware files are downloaded from the SENA server to a local archive
  (`SCHUBERTHBluetoothDeviceManagerArchive`, config `*.sbdmconf`), then pushed
  to the device over USB. Update count is reported to
  `https://www.sena.com/support/update_count.php?PP=…` [observed strings].

## Device families (from strings + code) [observed]

- **Airoha BT SoC** (AB15xx family): log strings `AIROHA BLOCK %d UPDATE START`,
  `RUN_LOADER`, `COMMAND_GET_DFU_RESULT`, codenames `AIROHAC30/M1EVO/PHANTOM/
  PHANTOM_ANC/R1EVO/R2EVO/RT1/S1`.
- **QCC (Qualcomm)** blocks: `60S QCC BLOCK`, `QCC BT + VP ALL_UPDATE`.
- **AmbaSys camera SoC** (helmets with camera: 10C EVO, 50C, R1Pro…):
  `AmbaSysFW_10CEVO.bin`, `AmbaSysFW_50C.bin`, `AmbaSysFW_HD50C.bin`,
  `AmbaSysFW_KCA-HX7C.bin`, `AmbaSysFW_R1Pro.bin`.
- **CSR/BlueCore** (older SCHUBERTH SC1/SPH10 era, Windows only): DFUEngine.dll
  exports `CreateCOMBCSP`, `CreateCOMH4`, `BCCMDGetPS/SetPS`, HCI `makeopcode/
  getogf/getocf` → BCSP/H4 serial + PS keys = CSR (Cambridge Silicon Radio) DFU.
- **HID DFU (standard)**: `CHidDfuEngine` in the Windows exe; classic DFU-over-HID
  implemented in the macOS binary (see below).

## USB device identity [derived from disassembly]

All modern devices enumerate with **VID 0x092B (Airoha Technology)**; the macOS
app's device scan (IOHID-based shim, see transport) matches:

| Function | PID(s) | Context string |
|---|---|---|
| sub_1001083a6 | 0x3120 | `30kmesh pid[%04X]` |
| sub_100108544 | 0x3220 (+ usage page 0xFF00, usage 1) | `airoha mesh pid[%04X]` |
| sub_100108618 | 0x33F0 (+ 0xFF00/1) | `airoha mesh pid[%04X]` |
| sub_100108466 | 0x3160, 0x3220, ≤0x6500 branch | `qcc mesh pid[%04X]` |
| sub_1001086ec | large PID table: 0x4D16–0x5346, 0x5446…, 0x5590–0x562F, 0x5598…, 0x6038–0x6042, 0x6461–0x660F, 0x6800–0x683A, 0x6900, 0x6910 | `devs =[%04X]` |
| sub_1001082ab | VID 0x92B, PID ≤ 0x5346 (open-all mode, args 2/3) | — |

Hopper evidence: `ev_9437c6c4885a04d5f8cfa29d26323385efaedff995163fbd83adff38e714a87a` (sub_100108544 pseudocode).

## macOS transport [derived]

The macOS binary statically links a **libusb-compat-style shim implemented on
top of IOHID** (not raw libusb/IOKit-USB):

- `sub_10012d8da` = IOHIDManager init; `sub_10012d97c` = "usb_find_devices"
  (IOHIDManagerCopyDevices → fake usb_dev list: VID@+0x4, PID@+0x5, next@+0x7).
- `sub_10012de6a` = "usb_open" (allocates 0x1c0 handle, registers input-report
  callback + run-loop source).
- `sub_10012e44c` = "usb_bulk_write" → `IOHIDDeviceSetReport` (kIOHIDReportTypeOutput=1)
- `sub_10012e70e` = "usb_interrupt_write" → SetReport feature (type 2)
- `sub_10012e68e`/`sub_10012e4a5` = "usb_bulk_read" → drain input-report queue
- `sub_10012e69f`/`sub_10012e723` = "usb_interrupt_read" → `IOHIDDeviceGetReport` feature

→ **Linux equivalent: hidraw / hidapi.** No FTDI/bulk path needed for modern devices.

Report geometry [observed in code]:
- Output (bulk write) reports: **0x3FF = 1023 bytes** payload.
- Input (bulk read) replies: **0x43 = 67 bytes**; byte[1]=echo/command, byte[2]=status (0=OK, 1=busy/pending).
- Feature reports: **0x3E = 62 bytes**, report ID 0x02; byte[0]=ID, byte[1]=length, payload follows (sub_100108d34 reads 62-byte chunks).

## Standard DFU-over-HID layer (some devices) [derived]

`sub_1000158b0` GETSTATUS (feature report 0x02, 7 bytes: bStatus, poll[3], bState, iString),
`sub_100015ac7` DNLOAD (feature report 0x01 + block# + data), `sub_100015864` ABORT (report 0x03),
`sub_100015b38` DFU-file parser validating the 16-byte **DFU suffix** ("DFU" magic, pid/vid fields) —
standard `dfu-suffix` format.

## Airoha vendor command layer [partial]

Helpers at 0x100108a4f–0x100109206 wrap: write 1023-byte output report;
read 67-byte reply with busy-wait (`count on %d` retry loop, sleep 1s);
62-byte feature-report register read/write; command echo check `com[%d] lsatcom[%d] status[%d]`.
The orchestration of the full update (RUN_LOADER → per-BLOCK erase/program/verify →
GET_DFU_RESULT) lives in `-[UpdateViewController threadMethodUpdate:]`
(start 0x100032b60) — **too large for Hopper decompilation (OOM)**; analyze via
callees + local disassembly instead.

## Windows DFUEngine.dll [observed exports]

Multi-transport DFU stack: `CreateUSB` (FTDI), `CreateCOM`, `CreateCOMBCSP`,
`CreateCOMH4`, `CreateSimulated`; `DFURequests` = standard DFU state machine
(`Detach`, `MapDFUStatus`, `CanAbort`, `CanClrStatus`); `DFUTransportCOM` adds
CSR `BCCMDGetPS/BCCMDSetPS` (PS keys) and HCI opcode helpers;
`IsDFUFileValid` validates DFU files. Main exe adds `CHidDfuEngine` (HID DFU).

## Update server layout [observed strings]

- Base: `https://firmware.sena.com/senabluetoothmanager/` (+ `/x64/` for Windows x64 manager)
- Example files: `ucom3-v1.3-build0-lp1.img`, `UCOM6R-v1.2-build0-lp2.img` …
- Help: `…/SenaBluetoothDeviceManagerHelp/Contents/Resources/English/*.html`
- Registration: `https://hellodevice.cafe24.com/moa/moa_register.php`

## Update server protocol [observed, verified against live server]

- Base URL: `https://firmware.sena.com/senabluetoothmanager/`
  (China mirror `https://firmware.sena.com/senabluetoothmanager/` on
  `firmware.senachina.com`; selected by `+[SENABluetoothManagerAppController is_china_server]`).
- Two plain-text manifests at the base URL:
  - **`Firmware`** — latest version per product (used for update)
  - **`Revisions`** — every historical version (used for restore/downgrade)
- Manifest line format (CR-or-LF separated), verified live 2026-10-13:
  - `SENA` — vendor header line
  - `PRODUCT:version:filename.img` — e.g. `AIROHAST1:v2.5:SPIDER_ST1-v2.5.3-build0.img`
  - `PRODUCT:version:Language:filename.img` — language-specific variant
  - `PRODUCT:<n>` — per-product trailer line (count/flag)
  - `PRODUCT:<n>` trailer observed values vary (1..9).
- The app matches `PRODUCT` against its internal product name
  (`+[SENABluetoothManagerAppController sbdm_product_name:for_internal:]`), then
  downloads `base + filename` (`-[UpdateViewController downloadFirmwareFromServer]`).
- Airoha-family product keys in the manifest use `AIROHA*`/`QCC*` prefixes:
  `AIROHAST1`, `AIROHAS1`, `AIROHAM1EVO`, `AIROHAC30`, `AIROHASURGE`, `QCC5S`, …

## Device catalog (PID → internal product name) [derived from sbdm_product_name:for_internal:]

`-[...] sbdm_product_name:for_internal:` is a PID switch-tree (VID is always
0x092B). 179 pairs recovered; SCHUBERTH-relevant subset (SCHUBERTH build ships
images sc1/sc1m/SC10U/prism/SRL_EXT/SRL_Mesh/ucom3):

| PID | internal name | SCHUBERTH product |
|---|---|---|
| 0x3020 | PRISM | PRISM (camera) |
| 0x4510 | SRL | (SRL family) |
| 0x4530 | SRL2 | |
| 0x5622 | SC1A | SC1 |
| 0x5623 | SC10U | SC10 |
| 0x5624 | SC1S | SC1 |
| 0x6510 | ST1 | ST1 (SPIDER ST1) |

Other notable: 0x3132 50S, 0x3210 50SV2, 0x3232 50C, 0x3340 UCOM3, 0x3420 UCOM6R,
0x3430 UCOM7R, 0x6840 AIROHASURGE, 0x6500 RT1, 0x3110 30K, 0x3050 R1, 0x3070 M1.
Full 179-entry table recovered in session (see Evidence below); also display-name
variant (`for_internal:0x0`) returns marketing names incl. white-label partners.

## Firmware container: Airoha `.img` [derived from st1/s1/m1evo/c30 images + code]

Header (0x2d4 = 724 bytes total header incl. name records):

```
0x000 char[24]  version string "v2.5.3-build0"
0x018 u8[4]     magic 19 28 C5 E6
0x01C u32       model id (0x6800 ST1, 0x6814 S1, 0x6802 M1EVO, 0x683A C30)
0x020 u32       image count (=2: voice-prompts + main FW)
0x024 image[0]  {u32 a=1, u32 b=1, u32 file_offset, u32 size, u8 md5[16]}
0x044 image[1]  {u32 a=0, u32 b=0, u32 file_offset, u32 size, u8 md5[16]}
0x064 …         duplicate/secondary table (same fields + extra u32s)
0x10C char[128] image[0] name, e.g. "SPIDER_ST1_VP.bin"
0x18C …         per-image record: md5[16], offset, size, version u32s
0x244 char[128] image[1] name, e.g. "SPIDER_ST1.bin"
0x2C4           image[1] md5[16]
```

- **MD5** (verified: `md5(blob@0x2d4,0x1baee0) == d667bad7…015b`, same for image[1]).
- image[1] payload is a stock **Airoha AB156x loader image** (contains `ab156x`,
  `read_test_ref_setting`, version string) — the device-side loader from the
  Airoha SDK; SENA's host just streams it with its own framing.
- QCC devices (UCOM3/6R/7R) instead use the Qualcomm **APPUHDR5 / PARTDATA**
  partition container (magic `APPUHDR5` @0x180 in ucom3.img, `PARTDATA` records
  with 16-byte hashes).
- PRISM `.img` (`__prism_dfu_bluetooth__.img`): simple container, product-name
  string at file offset 0x10, **CRC-32 footer** (last 4 bytes = CRC32 of the
  rest, standard reflected table at `0x10016ad20`) — parser `sub_10010f6ab`.
- Generic loader used by all flows: `sub_10010ebf8` (171 KB pseudocode,
  multi-format validator; do NOT decompile whole).

## Airoha BT DFU command protocol (HID) [derived from threadMethodUpdate: disasm]

Transport: 62-byte reports (see "Report geometry" above). Command buffer:
`[0]=0x01, [1]=0x3C (len), [2]=cmd, [3..]=params`; dispatched by
`sub_100109206` which validates cmd against a 27-entry table
(`0x10024c620`: cmds 0x00–0x0D, 0x50–0x5B with per-cmd reply lengths),
writes the output report, then polls the 62-byte feature report (ID 2)
until echo matches. Reply: `[2]=echo cmd, [3]=status, [4..]=payload`.

Observed in the "Airoha BT Update Start" flow (0x10003bd6c–0x10003c3e3):

| cmd | params | role (confirmed live 2026-10-18 + log strings) |
|---|---|---|
| 1 | `[3]=block idx` (ignored by live fw) | VERSION CHECK per block ("BLOCK %d VERSION CHECK"; reply 5 bytes; "VERSION IS SAME, %d %d %d %d %d UPDATE SKIP") |
| 5 | — (bare) | UPDATE START: opens the block transfer ("BLOCK %d UPDATE START"); slow on live (~4 s, flash prep); params ignored |
| 6 | `[3]=chunk_len(≤0x3A)`, `[4..]=data` | block data write, 58-byte chunks; reply `[4..5]`=chunk CRC16 LE |
| 0x5B | `[3]=2`, `[4..5]=running block CRC16 LE` | 60S-style close only; **live SC2V2 rejects it (status 2)** — SC2V2 commits with 0x07 run-loader instead |
| 8 | — | VERIFY/apply ("AIROHA BT VERIFY"); device re-enumerates ~1 s after the block completes |
| 0x0A | — | COMMAND_GET_DFU_RESULT ("END COMMAND_GET_DFU_RESULT value[%d]") — logged, **not** gated; live answers 1 after applying; not sent by the SC2V2 loop |
| 7 | — | RUN_LOADER: SC2V2 per-block commit of the staged block (shared-region loop 0x10004150e) |

**SC2V2 per-block loop (confirmed live 2026-10-18 + shared region
0x10004139c, which the BBBBB branch enters):** `0x00 NOP` → `0x05`
start → `0x06` chunks (vendor writes via 90ac write-only, no per-chunk
reply wait) → `0x07` run-loader (commit) → `0x08` reboot. No 0x5B, no
0x0A — 0x5B on 0x3220 answers status 2.

- Per-chunk **CRC-16/CCITT (poly 0x1021, MSB-first table @0x10016a980, init 0)**
  appended implicitly: device returns its CRC at reply[4..5] (LE); host compares,
  and keeps a running CRC over the whole block, compared at block end
  ("NORMAL BLOCK[%d][%d][%d] CRC[0x%04X][0x%04X] Progress: %3d%%").
- 60S flow adds: RUN_LOADER, per-block type/id, "COMMAND_GET_DFU_RESULT".
- A second, transport-agnostic framing exists for BT/RFCOMM path
  (`sub_10010ad73`: `0xFC, len16|1, 0xC2, type, len16, seq16, cmd16, payload`,
  16-bit cmds e.g. 0x7003; reply `0xFF … 0xC2, status`) — used for device
  settings over BT, not needed for USB DFU.

## SC2 (user's device) [observed from live firmware + disasm]

- PIDs: **SC2 = 0x3170**, **SC2V2 = 0x3217** (recovered from container model-id
  field), **QCC_SC2 = 0x321b**, catalog also has `SC2Standard`.
- Manifest keys/URLs (live): `SC2:v1.5:SC2-v1.5-build0.img`,
  `SC2V2:v2.4:SC2-v2.4-build0.img`, `SC2Standard:v1.1:SC2_Standard-v1.1.1-build0.img`;
  full revision history in `Revisions`.
- Container = same SENA multi-image format (magic `1928c5e6`), **4 images**,
  all MD5-verified OK:
  - img[0] `a=0` 1.0 MB — **`CSR-dfu2`** image, name field `SC2#3170` →
    the SC2 is a **Qualcomm/CSR** chip (BlueCore DFU2 format), NOT Airoha.
  - img[1] `a=1` 5.8 MB — voice prompts (identical MD5 across SC2 v1.5/v2.4).
  - img[2] `a=3` 170 KB — `MESH3.0_v3.0.0.8.ldr` / `Mesh_Intercom_3.0.dxe`.
  - img[3] `a=4` 127 KB — `20210130_HeySiri_HeyGoogle_with_length.bin`
    (wake-word config).
- Container name records (between table and first blob) map to images
  **positionally** (verified on SC2 and ST1).
- Container model-id @0x1C equals the USB PID for SC2 (0x3170/0x3217) but not
  for Airoha devices (ST1=0x6800 vs PID 0x6510) — 0x6800–0x683A are DFU-mode
  PIDs in `sub_1001086ec`'s table. Treat @0x1C as "target device id".
- Update flow: SC2's PID is in the chain at 0x10003f7dd → section starting
  0x10003f824 (marker `AAAAAAAAAAAAAAAA`, then `Qcc Mesh Update start`,
  steps `[01][qm]`/`[02][qm]`, `Find Mesh`, `COMMAND_NOP`, `Runloader`,
  `30 crcerror`, `all_crc`, `nCountToWrite = %d`) — the CSR/QCC-mesh flow,
  consistent with Windows `DFUEngine.dll` (CSR DFU state machine `DFURequests`,
  `Detach`, `MapDFUStatus`, BCSP/H4 for the serial variant).
- CSR DFU2 image format is publicly documented: `ramikg/csr-dfu-parser`,
  `dogtopus` OTAU gist ("CSR-dfu2 is itself another file system"),
  reverseengineering.stackexchange q22435; fwupd issue #1890 (AIAIAI H05).
  The DFU wire protocol (DFU_READ/DFU_WRITE, PS keys, BCSP/H4) is the standard
  BlueCore DFU protocol from the CSR SDK.

## SC2V2 vendor flow — LIVE VERIFIED 2026-10-19 (device upgraded 2.3.2.1 → 2.4.0.0) [derived from threadMethodUpdate: 0x10004bb7f → 0x10005d2b0..0x10005f222; replayed exactly by schuberth-dfu update]

**SUPERSEDES the 2026-10-19 "fully reconstructed" model** (kept below for
history): that model wrongly assigned the 0x20/0x22/0x21 "session"
handshake, the 0x0E last-chunk cmd, and per-image 0x08/0x0A pairs to
0x3217. Those belong to the **PRISM family only**: the block at
0x10004bb8c+ is entered ONLY when `deviceTarget ∈ {0x5510, 0x5580,
0x5570, 0x5576, 0x3060}` — the chain at 0x10004bb02–0x10004bb85 ends in
`jne 0x10005d2b0`, so every other PID (incl. 0x3217) **skips the whole
handshake region**. A 0x3217 firmware answering status 2 to
0x20/0x21/0x22/0x0F/0x12/0x40/0x5A/0x5B simply does not implement those
commands; it is NOT a power/battery gate (the earlier "dead battery
blocks updates" conclusion was wrong — the vendor dialog for our device
says "SC2, SC1M, SC2 Standard: **Leave it powered off**", i.e. the
normal USB-charge state is the intended update state).

**The real 0x3217 sequence** (0x10005d2b0, loop stride 0x138 over the
container image table; entry fields: +4 = flag byte = container entry's
second u32 (parsed as `Image.flag`), +8 = ptr, +0xc = size, +0x24 =
skip/bookkeeping dword):

1. sleep(5) (0x10005d2b0 `mov edi,5; call sleep`).
2. For **every** container image, in table order — the submesh included,
   over transport B (0x3217) only; the 0x3220 A-side is never touched on
   this path (the rbx==2 submesh skip branches only fire for the PRISM
   PIDs):
   - `0x05` start, frame [2] = `Image.flag` (c1b `sub_100108c1b` blocks
     until a reply echoing the cmd arrives — no timeout, no retry cap);
   - chunks `[01 06 lenBE16 data(≤0x3FB)]`, length via `rol ax,8;
     mov word [2..3]` at 0x10005d458, data at [4..]; per-chunk ack =
     `sub_100108a72`: read 67 B in a **tight loop, no sleep, no bound**,
     retry while reply[2]==1 (busy), exit on any other status;
   - `0x07` commit (frame [01 07 ...], residual chunk bytes tolerated).
3. sleep(5) (0x10005e900), then the PID chains resolve to 0x10005f1e2:
   `0x08` reboot `[01 08 00]` — gated on the did_any flag (0x10005f1f2,
   set when image +0x24 bookkeeping dword is 0/2) — then sleep(1).
4. The device re-enumerates **by itself** (~40 s observed); the vendor
   reopens handles (0x10005ee5c / final phase 0x100060274) and re-reads
   versions. No 0x0A gating, no 0x0E, no session.

**Live replay evidence (csr11)**: SC2.img 1,075,012 B in 41.2 s, vp.bin
5,817,184 B in 155.7 s, Submesh 1,224,847 B in 113.1 s — every chunk ack
status 0, every commit status 0; 0x08 → device gone → back ~40 s later
with 0x01 answering `02 01 00 02 04 00 00` = **2.4.0.0**; 0x3220 Airoha
still 0.4.0.0.4. Timing: full update ≈ 4–6 min, dominated by staging.
Mid-run notes: after a commit the device can be silent to the next 0x05
for tens of seconds (it is writing flash) — c1b-style blocking reads wait
through it; pyusb-style capped retries misread this as failure (csr9
stalled exactly there).

**Transport timing primitives** (correction): `sub_100108a4f` = single
1023 B write (0x3ff), returns `not(ret)>>31` as bool; `sub_100108a72` =
67 B read busy loop (seed reply[2]=0xFF sentinel, retry while [2]==1,
read error → fail); `sub_100108c1b` = write + blocking echo read;
0x10013c855 = `sleep(edi)` thunk. The vendor app has **no timeouts
anywhere** in this loop — all pacing is device-driven.

### History (superseded): the 2026-10-19 "fully reconstructed" model, PRISM branch misread as 0x3217 [derived from threadMethodUpdate: default path for deviceTarget 0x3217; validated live with tools/re/csr_full.py]

**Dispatch**: all SC2-family PIDs 0x3210–0x321C share one entry
(0x10003e3dc–0x10003e54d → 0x10003e54d "BBBBB"). Inside, chains of
`cmp deviceTarget, PID` only branch for *other* families; 0x3217 falls
through every chain (`jne` default) to 0x100040b50 → **QCC-BT phase**
(~0x10004b900–0x10004d600). Handle slot 0 is the **B side (0x3217)** here
(opened via `sub_1001086ec` at 0x10004ad10) — no mesh handle needed for
main images.

**Frame semantics (correction to the 2026-10-18 notes)**: `sub_100108c1b`
does NOT write 0xFF into the command frame — the 0xFF sentinel is written
into the **reply buffer** at [2] before reading. Vendor frames are
`[01 cmd 00 00 ...]` zero-padded, 1023 B. Reply = pushed EP1 report
`[02 echo status ...]`; success = reply[2]==0; busy (reply[2]==1) retried
by re-reading. (Our earlier `[01 cmd FF ...]` frames were tolerated for
queries but made `0x07` commit a silent no-op: the vendor commit frame is
`[01 07 00 ...]`, see `mov byte [rbp-0xade], 0` before 0x10004cc18.)

**Sequence for 0x3217** (address order = execution order):

1. `0x0A` GET_DFU_RESULT peek; `0x01` version vs container; skip if same.
2. **Update session** (0x10004bb8c+): `0x20` start → `0x22` poll loop
   (25 tries, usleep(1 ms); reply[3]==1 special-case) → `0x21` confirm
   (failure branch retries, logging "1. --------UPDATE START MESH HANDLE
   FIND" @0x1002190c0). Before download: second pair `0x21` `0x20`
   (0x10004c5b7/0x10004c5e3).
3. **CSR download per image** (loop body 0x10004b168; second copy
   0x10004cb34+): `0x05` start → chunks via `sub_100108a4f` write-only
   `[01 06 lenBE16 data]`, len ≤ 0x3FB (1019), **length at [2..3] BE**
   (`rol r14w,8; mov word [rbp-0xade], r14w`), data at [4..]; last chunk
   cmd `0x0E` ("writeLAST") when offset+len == image size; per-chunk ack
   via `sub_100108a72` (read 67 B; retry while status==1; a read error
   also exits the ack wait — the vendor keeps streaming).
4. Commit `0x07` `[01 07 00]` ("QCC BT Runloader Start VP 2"), reboot
   `0x08` `[01 08 00]`, reopen B (`sub_1001086ec`, 13x), `0x0A` result,
   version compare ("VP (v..) vs (v..)", "VP GOGO").
5. Submesh (type-3 image) via the Airoha mesh transport-A block loop
   (0x100045728, 58 B chunks `[01 3C 06 len data]`, double CRC16) —
   confirmed working live earlier.

**Transport shim internals** (`sub_10012e44c` write / `sub_10012e68e`
read): handle object = {0x00 IOHIDDevice*, 0x10 error flag, 0x40 buffered
file*, 0x90 timeout}. Writes = HID output report id1, full length (1023);
reads = 67-byte input (GET_REPORT or EP). 0x3220's descriptor declares
61-byte reports → 1023 B SET_REPORT to it times out; 0x3217 accepts 1023 B
on EP2 OUT (bulk-ish interrupt); control SET/GET_REPORT on 0x3217 = EPIPE.

**Live status map on 0x3217 (frames `[01 cmd 00]`)**: OK(0): 0x01(version),
0x02(+4 B payload), 0x03, 0x05, 0x06/0x0E (ack), 0x07, 0x08, 0x0A(payload
[3]=2), 0x50, 0x51, 0x60(payload [3]=8). Refused(2): 0x0F, 0x10, 0x11,
0x12, 0x13, 0x20, 0x21, 0x22, 0x40, 0x5A, 0x5B. Chunk acks [02 06 00]
appear only with correct `[lenBE]` framing — with garbage length the
device answers but discards data (silent-inert).

**Hardware precondition (the user's unit)**: `0x12` (rV), `0x0F`,
`0x20/0x21/0x22` all status 2 regardless of ordering/params; headset does
not power on at all (dead/removed battery); commits `0x07` and the `0x0E`
finalization answer 0/2 but never apply. Conclusion: the vendor flow has a
**battery/power safety gate**; the vendor app fails identically on this
unit. Update validation requires a working battery (or another unit).

## SC2 update flow, decoded 2026-10-18 (SUPERSEDED — kept for history; the "SC2V2 vendor flow, fully reconstructed" section above is authoritative for 0x3217; this section still describes the other CSR families) [derived from threadMethodUpdate: 0x10003f824–0x100041600 + transport helpers 0x100108a4f–0x100109205]

Three HID transport variants, all indexing a global device-handle table at
**0x1002518d0** (slot 0 in every flow):

**Transport A "feature"** (Airoha BT) — 62-byte reports, see "Airoha BT DFU
command protocol" above.

**Transport B "bulk"** (normal-mode CSR/mesh devices):
- `sub_100108c1b(idx, cmd, resp)`: write **1023-byte** output report from cmd;
  read **67-byte** input report into resp; pre-fills resp[2]=0xFF; while
  resp[2]==1 re-reads (busy); success = resp[2]==0; logs
  `com[%d] lsatcom[%d] status[%d]` (resp[2], cmd[1], resp[1]).
- `sub_100108a4f(idx, cmd)`: write-only 1023-byte report.
- `sub_100108a72(idx)`: read 67-byte reply, busy-retry, success resp[2]==0.
- `sub_100108b04(idx, cmd, resp, n)`: write + read n bytes; on resp[2]==1
  re-write cmd and re-read, up to n retries.
- Frame: request `[0]=0x01, [1]=cmd, [2..]=params`; reply `[1]=status,
  [2]=result (0 OK / 1 busy), [3..]=payload`.

**Transport C "mesh DFU"** (after device re-enumerates; **65-byte** reports):
- `sub_100109161(idx, cmd, resp)`: write 65 + read 65, busy-retry resp[2]==1.
- `sub_1001090ac(idx, cmd)`: write 65 bytes only.
- `sub_1001090cf(idx)`: read 65 bytes, busy-retry, payload discarded.
- Same frame layout as B.

SC2 command set (bulk + mesh paths; distinct from the Airoha feature-path
numbering only in framing):

| cmd | params | role (log string) |
|---|---|---|
| 0x00 | — | COMMAND_NOP ("QCC COMMAND_NOP Fail") |
| 0x01 | — | version query; reply[3..6] = 4 version bytes |
| 0x05 | — | mesh version ("meshVesion %d.%d.%d. type %d, build %d") |
| 0x06 | [2]=0, [3]=len, [4..]=data | write chunk (≤0x3d=61 B mesh path, ≤0x3a=58 B bulk path) |
| 0x07 | — | "QCC Runloader Start" (enter download mode) |
| 0x08 | — | reboot into mesh DFU; host then re-finds the interface |
| 0x0F | — | "Qcc Mesh Update start" (once per image phase) |
| 0x12 | — | rV query; reply[3] |
| 0x5A | [3]=2, [4..5]=u16 chunk CRC16 LE | per-chunk CRC check (bulk mesh loop) |
| 0x5B | [3]=2, [4..5]=u16 running block CRC16 LE | block CRC check ("all_crc =[%x][%d] verAll[%x][%d]", "allCrc error", "30 crcerror") |

SC2 sequence (preamble 0x10003f824 → block loop 0x10004139c):
1. open normal device (`sub_1001086ec` PID table incl. 0x3170) → slot 0
2. transport B: cmd 0x01 → current version reply[3..6]; skip if same
3. transport B: cmd 0x0F ("Qcc Mesh Update start")
4. **Find Mesh**: `sub_100108466` up to 20 retries — opens the DFU-mode
   interface: VID 0x092B, PID ∈ **{0x3160, 0x3220, 0x6501, 0x6511}** → slot 0
5. transport B: cmd 0x12 (rV), cmd 0x0F ("Qcc Mesh Update start VP")
6. transport C: cmd 0x00 NOP, cmd 0x05
7. transport C block loop: cmd 0x06 chunks ≤61 B, data from the container
   image record ([r13+0x4c]=file_offset, [r13+0x50]=size)
8. transport C: cmd 0x07 (runloader), cmd 0x08 → Find Mesh again → next phase

Bulk-path mesh loop variant (50S/TERRIN region 0x10004e695, 6 blocks):
cmd 0x05 mesh version → per chunk: cmd 0x06 (58 B) write-only + separate
busy-ack read, then cmd 0x5A with the chunk CRC16; on fail logs "30
crcerror"; at block end cmd 0x5B with the running CRC16 ("all_crc").
CRC-16/CCITT init 0, same table as the Airoha path.

**Block table = container image records**: the loops read {+0x08 file_offset,
+0x0c size} with stride 0x10 — exactly the container image table
{type, flag, offset, size}; `a`=image type, `b`=flag. (Resolves the host-side
half of ticket 07; loader-internal meaning of the duplicate table at 0x64
still open.)

## Live SC2V2 USB topology + report-ID convention [observed 2026-10-18, tools/re/probe_sc2.py]

Connected SC2V2 enumerates as a composite with **two** HID interfaces:

- **092b:3217** (hidraw5, `3-3.1:1.0`): endpoints EP1 IN **16 B**, EP2 OUT
  **64 B** (interrupt). Report descriptor (33 B) is malformed:
  `85 01 09 02 96 FE 03 75 08 91 02` — `96 FE 03` is a vendor typo for
  `76 FE 03` (Report Count 0x03FE=1022), so Linux sizes Output id1 at 1 byte
  and truncates every write; Input id2 = 66 B (doesn't fit the 16 B IN
  endpoint either). Control `SET_REPORT(OUTPUT,id1,1023B)` **STALLs (EPIPE)**
  while the headset is in USB/charging mode.
- **092b:3220** "MediaTek Inc Airoha Headset" (hidraw7, `3-3.2:1.0`):
  **IN endpoint only** (EP3 IN 64 B) — output reports must go via
  SET_REPORT control transfers. Two vendor collections, both 61-byte data:
  usage page 0xFF00/usage 1 → Out id1 / In id2; usage page 0xFF13/usage 1 →
  Out id6 / In id7. This is exactly what `sub_100108544` ("airoha mesh
  pid[%04X]", usage page 0xFF00, usage 1) opens — the SC2V2's DFU path is
  the **Airoha transport A on 0x3220**, not transport B on 0x3217.
- The headset powers off its BT side when the USB cable is attached
  (charging/USB mode); the Airoha chip is bus-powered and 0x3220 stays
  present — this is the state the vendor updater operates in.

**Report-ID duplication (shim `sub_10012e461`, [derived]):** the write shim
takes the report ID from `buf[0]` and only strips it when it is 0:
`IOHIDDeviceSetReport(dev, type, reportID=buf[0], data=buf, len)` — so the
ID byte is **duplicated inside the payload**. Transport A write on the wire:
`SET_REPORT(OUTPUT, id=1)` with 62 B `[01 3C cmd ...]`. The device follows
the same convention: `GET_REPORT(id2)` replies `[02 ...]` (ID echoed as data
byte 0). Probe with the 61-byte frame (no leading 01) got silence; the
device answers GET_REPORT for FEATURE/INPUT/OUTPUT alike (all return the
same buffer).

**Live protocol confirmed (probe, 2026-10-18) [observed]:**
- 0x3220 transport A works: cmd 0x01 → `02 07 01 00 00 04 00 00 04 ...`
  ([2]=echo, [3]=status 0 OK). cmd 0x05 answers but **slowly (~4 s)** —
  its replies often surface in the *next* command's poll window (params
  are ignored).
- 0x3217 transport B works via **EP2 interrupt OUT, 1023 B frame with NO
  ID prefix on the wire** (the 1024 B ID-prefixed variant is ignored; 64 B
  truncated writes ignored). Replies are **pushed on EP1 IN** as short
  reports (~12 B): `02 01 00 02 03 02 01 ...` = ID, status=01, result=00
  OK, payload `02 03 02 01` → **device version 2.3.2.1** (manifest latest
  is 2.4 → the test device is behind; UPDATE SKIP will not trigger).
- Interpretation: SC2V2 = main CSR firmware (0x3217, transport B,
  container `SC2.img`) + **submesh module** (0x3220, transport A,
  container `Submesh_v0.4b4.bin` — the Airoha image). Both interfaces
  coexist; no runloader/re-enumeration observed for SC2V2.
- hidapi cannot drive these devices (ID-byte handling + kernel truncation);
  the CLI needs a pyusb backend with kernel-driver detach (root).

**CORRECTION (2026-10-19, first live flash attempt) [observed]:** the
above interpretation was wrong. Writing SC2.img+vp.bin as 0x06 chunks on
0x3217 and committing with 0x07+0x08 was fully ACKed (status 0) but did
**not** change the firmware (still 2.3.2.1 after reboot+replug); a bare
0x07 never re-enumerates. The vendor's SC2V2 branch (BBBBB → je
0x1000407ee/0x1000408ed, log "Qcc Mesh Update start VP") sends 0x0F on
0x3217 then calls **sub_100108544 (airoha mesh open)** and streams the
container through **transport A on 0x3220**: the Airoha side is the
master MCU (three blocks, one per container image; block cmds are slow,
~4 s, with replies surfacing in the *next* command's poll window).
Transport B on 0x3217 is for version query + session cmds
only; its 0x06/0x07 ACKs are inert. 0x0F/0x12 answer status 2 on live
devices and the vendor state machine proceeds anyway (the je branches
are the taken path).

**Airoha block-update lifecycle on live SC2V2 (2026-10-18) [observed]:**
per container image (block idx = image index): 0x01(idx) version check
(same 5 bytes for every param) → 0x00 NOP → 0x05 UPDATE START (bare,
~4 s) → 0x06 58-B chunks (device echoes per-chunk CRC-16/CCITT; all
matched for the full 1.07 MB SC2.img at ~4 ms/chunk with a 2 ms poll
interval — 50 ms polling was the pacing bottleneck, ~90 ms/chunk) →
0x07 RUN_LOADER commit → 0x08 (0x5B is rejected here: status 2; an
unclosed/uncommitted block makes the *next* block's 0x06 answer
status 2 too). After the block completes the **0x3220 interface
re-enumerates** (apply-reset; gone ~5 s) — the vendor re-opens after
every block (retry loop 0x10003c204). Transport B stays alive through
all of this; main version still reads 2.3.2.1 until the whole flow +
reboot completes.

## Unknowns / next steps

- ~~SC2V2 (0x3217) flow retarget~~ — resolved 2026-10-18: DFU path is
  the Airoha transport A on 0x3220 (cmd 5/6/8/0x0A per block, block idx
  = container image index); implemented in `sc2flow.update_sc2v2`.
  The 0x3217 interface's role (BT side? legacy?) still unclear.
- Exact phase→image mapping for SC2 (which container image goes in which
  0x0F phase; mesh .ldr vs main CSR-dfu2 ordering) — needs a live trace or
  deeper CFG of the dispatcher thunks 0x100038cf8/0x100038cff.
- Exact block-table semantics inside the AB156x loader blob (which u32s drive
  BLOCK id/type/address/version) — decode by diffing several images.
- Full command sequence for RUN_LOADER/erase in the 60S flow.
- Device settings read/write protocol (secondary feature; 0xFC/0xC2 framing).
- Windows FTDI/CSR path details (older SC1 via DFUEngine.dll BCSP).
- SC1A/SC1S (0x5622/0x5624) update flow on macOS (which helper family drives them).

## Method notes

- **Do not** call Hopper `analyze_function` on `-[UpdateViewController threadMethodUpdate:]`
  (OOM, killed user's Hopper once). Use `procedure_callees` + local capstone disassembly.
- Ghidra not configured on this host (`GHIDRA_INSTALL_DIR` unset).
