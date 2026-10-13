# 07 — RE search: block-table semantics in the AB156x loader blob

Status: ready
Type: research
The Airoha BT flow iterates "BLOCK %d" with per-block id/type/address/version/
expected-CRC. The main-FW blob (`SPIDER_ST1.bin` inside the container) is a
stock AB156x loader image; the block descriptors are parsed by `sub_10010ebf8`
(171 KB pseudocode — do NOT decompile whole; page via `inspect_analysis_view`)
or inline in `-[UpdateViewController threadMethodUpdate:]` (never decompile —
OOM'd Hopper once; use local capstone disassembly, see `tools/re/disfunc.py`).

Deliverable: answer under `## Answer` — struct of the block table, how
`[rbp-0x1168]`/`[rbp-0x1160]` block entries are filled, and how the host's
expected per-block CRC is derived (file CRC vs computed).

Approach: diff block-table regions across st1/s1/m1evo/c30 images; trace the
Airoha BT flow (0x10003bd6c–0x10003c3e3) reads of `[rax+rcx+8]` entry fields.

## Comments
## Comments

- 2026-10-13 (partial): the HOST-side block table is the container image
  table itself — the update loops read {+0x08 file_offset, +0x0c size} with
  stride 0x10 from the parsed container (see findings.md "SC2 update flow,
  decoded"); `a`=image type, `b`=flag. Still open: what the AB156x loader
  does with its internal duplicate table at container 0x64 and per-block
  version u32s.
