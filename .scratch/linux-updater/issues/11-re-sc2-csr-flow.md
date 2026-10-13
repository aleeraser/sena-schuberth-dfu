# 11 — RE search: SC2 CSR-DFU-over-HID flow

Status: done
Type: research

SC2 (PID 0x3170) / SC2V2 (0x3217) are Qualcomm/CSR devices; firmware img[0]
carries the `CSR-dfu2` magic and name `SC2#3170`. The macOS update section
starts at 0x10003f824 (`AAAAAAAAAAAAAAAA` marker) and uses the `[01][qm]` /
`[02][qm]` step markers, `Find Mesh`, `COMMAND_NOP`, `Runloader`,
`30 crcerror`, `all_crc`, `nCountToWrite = %d`.

Determine:
- how the CSR DFU protocol (DFU_READ/DFU_WRITE, PS keys, subversion check)
  is framed over the 62/1023-byte HID reports (compare with standard BCSP/H4
  framing in Windows `DFUEngine.dll` `CreateCOMBCSP/CreateCOMH4`),
- the image ordering (main FW → VP → mesh .ldr → img[3]) and per-image steps,
- how `CSR-dfu2` images are chunked + CRC'd (find `30 crcerror` / `all_crc`
  in disasm; local capstone only — never decompile the giant function).

Cross-reference public CSR DFU docs: ramikg/csr-dfu-parser, RE.SE q22435,
dogtopus OTAU gist.

Deliverable under `## Answer`.

## Answer

Full protocol model captured in findings.md "SC2 update flow, decoded".
Key facts:

- Framing is NOT BCSP/H4 — SENA uses its own command framing on HID reports:
  request `[0]=0x01, [1]=cmd, [2..]=params`; reply `[1]=status, [2]=result
  (0=OK, 1=busy→retry), [3..]=payload`.
- Two report geometries on the SC2 path: "bulk" 1023-byte out / 67-byte in
  (normal mode, PID 0x3170) and "mesh DFU" 65/65 (after re-enumeration).
- DFU-mode interface PIDs: **0x3160, 0x3220, 0x6501, 0x6511** (from
  `sub_100108466`); host polls up to 20× ("Find Mesh") after cmd 0x0F.
- Commands: 0x00 NOP, 0x01 version, 0x05 mesh version, 0x06 write
  (61-byte chunks on mesh path), 0x07 runloader, 0x08 reboot-to-DFU,
  0x0F start-phase, 0x12 rV, 0x5A chunk-CRC, 0x5B block-CRC (CRC-16/CCITT
  init 0).
- Block table = container image records {type, flag, offset, size}.
- Still open: exact phase→image ordering (needs live trace); implemented
  best-effort in `schuberth_dfu/sc2flow.py` behind an experimental flag.

## Comments

- 2026-10-13: decoded offline from local capstone listing
  (/tmp/opencode/sc2_flow.asm, transport_helpers.asm) + cfstr.py chained-fixup
  string resolver. No Hopper whole-function decompilation used.
