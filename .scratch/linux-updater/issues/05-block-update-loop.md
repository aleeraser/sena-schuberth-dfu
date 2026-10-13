# 05 — Airoha block-update loop

Status: done
Blocked by: 02, 04

Implement the per-block update sequence (Airoha BT flow):

1. For each block in the firmware image: `version_check` (cmd 5) → skip if
   same.
2. Write loop: cmd 6 with ≤58-byte chunks; after each chunk compare device
   CRC-16 (reply[4..5] LE) against host chunk CRC; maintain running block
   CRC; abort on mismatch ("Write CRC Check Fail").
3. `verify` (cmd 8) + running-CRC compare.
4. `get_dfu_result` (cmd 0x0A); non-zero → error.
5. Progress output per block ("BLOCK %d UPDATE OK").

Open question (see 07): where the block table (id/type/address/expected CRC/
version) comes from inside the AB156x loader blob.

## Comments
- 2026-10-13: implemented in `schuberth_dfu/airodfu.py` (Link + update_image); command reply lengths from the 0x10024c620 table; tested offline against FakeAiroha (tests/test_airodfu.py). Hardware validation pending (ticket 06).
