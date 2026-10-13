# 10 — PRISM flow (`__prism_dfu_bluetooth__.img`)

Status: blocked
Blocked by: 03

PRISM (PID 0x3020) uses the simple container (name@0x10 + CRC-32 footer,
parser `sub_10010f6ab`) and its own transfer flow (region 0x100058000–
0x100060e00 in `threadMethodUpdate:`, `[50][c][n]` step markers, camera
version compare "333Camere Version Same"). Decode the transfer framing and
implement.

## Comments
