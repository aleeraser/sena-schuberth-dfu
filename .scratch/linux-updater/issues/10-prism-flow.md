# 10 — PRISM flow (`__prism_dfu_bluetooth__.img`)

Status: blocked
Blocked by: 03

PRISM (PID 0x3020) uses the simple container (name@0x10 + CRC-32 footer,
parser `sub_10010f6ab`) and its own transfer flow (region 0x100058000–
0x100060e00 in `threadMethodUpdate:`, `[50][c][n]` step markers, camera
version compare "333Camere Version Same"). Decode the transfer framing and
implement.

## Comments
- 2026-10-19: big head start from the SC2V2 work — the region
  0x10004bb8c–0x10005f1e2 is now known to be the PRISM branch
  (entered only for deviceTarget {0x5510, 0x5580, 0x5570, 0x5576,
  0x3060} via the gate at 0x10004bb02–0x10004bb85). Mapped so far:
  session handshake 0x20 → 0x22 poll (25x, reply[3]==1 special case →
  0x10004dd8c) → 0x21 (+retry "UPDATE START MESH HANDLE FIND"), CSR
  download 0x05/0x06 with 0x0E "writeLAST" (0x10004b1da/0x10004d163),
  0x07 commit, 0x10004dc68 abort path (13-image status log), PRISM
  re-enumeration wait 0x10005ee5c. Vendor dialogs: "1. Disconnect the
  USB cable from the PRISM / 2. Wait until the PRISM completes update
  and powers off / 3. Connect USB cable ... and then power on it" —
  consistent with the `__prism_dfu_bluetooth__` name (BT transport; the
  app links IOBluetooth for this).
