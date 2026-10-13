# 04 — Airoha command layer + version check

Status: done

Implement `airodfu.py` command primitives (see findings.md "Airoha BT DFU
command protocol"):

- `send_cmd(cmd, params)`: build 62-byte buffer `[0]=0x01, [1]=0x3C, [2]=cmd,
  [3..]=params`; write output report; poll feature report (ID 2, 62 bytes)
  until `[2]` echoes cmd; return reply.
- Command table (27 entries, cmds 0x00–0x0D + 0x50–0x5B) with expected reply
  lengths — port from `0x10024c620` table.
- `version_check(block)` (cmd 5): parse version bytes from reply.
- CRC-16/CCITT helper (poly 0x1021, init 0, MSB-first table).
- `check` CLI: read device version, compare against manifest version.

Needs a real device (or bus-pirate/`hid_listen` capture) to confirm reply
layout byte offsets; mark assumptions loudly in code.

## Comments
- 2026-10-13: implemented in `schuberth_dfu/airodfu.py` (Link + update_image); command reply lengths from the 0x10024c620 table; tested offline against FakeAiroha (tests/test_airodfu.py). Hardware validation pending (ticket 06).
