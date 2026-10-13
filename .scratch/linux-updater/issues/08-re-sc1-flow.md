# 08 — RE search: SC1 (0x5622/0x5624) + SC10U (0x5623) update flow

Status: ready
Type: research

SCHUBERTH's headline products (SC1, SC10) map to PIDs 0x5622/0x5624/0x5623.
In `threadMethodUpdate:` these PIDs are special-cased at 0x100044423–
0x100044467 (inside/after the 50SV2-mesh Airoha flow). Determine:

- which command sequence drives SC1 updates (same 62-byte cmd layer? the
  1023-byte bulk path? something else),
- which manifest product key SC1/SC10 use (`SC1A:1` trailer exists in the
  `Firmware` manifest but no version line — check `Revisions`),
- whether macOS uses the same path as Windows `DFUEngine.dll` (CSR/BCSP) or
  the Airoha HID path.

Method: local disassembly of 0x100044300–0x100045200 + callees; cross-check
Windows exe `CHidDfuEngine` strings.

## Comments
