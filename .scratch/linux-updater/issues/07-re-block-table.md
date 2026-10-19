# 07 — RE search: block-table semantics in the AB156x loader blob

Status: done
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

## Answer (2026-10-20, capstone trace; supersedes the 10-13 partial —
stride is 0x20 for the SENADRIVER table, and the 0x138-stride entries are
a second on-disk file shape, see below)

**Q1 — block descriptors come from FILE offsets, not a parsed runtime
struct.** `sub_10010ebf8` is just load+validate (it writes the malloc'd
raw buffer to *rsi, returns size in rax); the flows index that raw buffer
directly:
- 60S/50S flow (`AIROHA 60S BLOCK %d type %d id UPDATE START`): count =
  dword[file+0x20] (0x10003aad4); entry base = file + i*0x138 (imul @
  0x10003aaef); block record = entry + count*0x20 + 0x24 with
  {+0 type, +4 id→cmd byte of {01,05,id} (0x10004e36a), +8 file-offset of
  data, +0xc size} — so "+4 param / +8 ptr / +0xc size / +0x24 flags"
  observed live are literal file offsets (+8 becomes a pointer only after
  load).
- 50SV2-MESH flow: descriptor = file + k*0x20 + 0x294 (0x100041d6f-87):
  +0x294 id, +0x298 type (==1 gates version check), +0x29c data offset,
  +0x2a0 size, +0x2a4..0x2b4 five expected VERSION dwords compared against
  the device reply (0x100041e3a-0x100041ec5). 0x294 = 0x24 + 2*0x138 —
  same layout.
- Confirmed on disk (sc1a/sc1m images): header version string @0, magic
  dword @0x18 (e6c52819 — checksum, unchecked on this path), device-id @
  0x1C, count @ 0x20, section table @ 0x24 {a, b, off, size, md5[16]}.

**Q2 — expected CRCs are COMPUTED from the bytes being sent; no CRC16
exists in the files.** CRC16/CCITT-FALSE table at 0x10016a980 (10 ref
sites). Two regimes: transport-B chunk flows compute after send and
COMPARE the device-echoed word at reply+4 ("…Write CRC Check Fail",
"CRC[0x%04X][0x%04X]" log); transport-A flows SEND their CRC in cmd 0x5A
{01 5A 00 02 chunk_crc} and finish with 0x5B {01 5B 00 02 rolling_crc16}
(device ACKs; 'all_crc'/'allCrc error', 6 retries @0x10004e8ca). Cmd 0x5B
variant on B is {01 00 5B 02 chunk_count16} (block-close, transport B).
Only file-sourced integrity = per-section MD5, verified inside
sub_10010ebf8 (matches our container.verify_all).

**Q3 — `size sub_10010ebf8(const char *path, void **out, char err[0x240],
u32 devtype)`**: stat/malloc/open/read/close via libc stubs; validates
version string ≤0x18 @0, magic @0x1C against a per-devtype whitelist
(dispatch 0x10010ef68-0x10010f3b5), count @0x20 > 0, then MD5-verifies
every 32-byte section entry (layouts A/B; overrun-checked). rax=0 on
failure. Error strings 0x100143c40-0x100143ed1 ("Firmware corrupted" …).

**Q4 — AB156x loader blob** (inside SC1A/SC1M images) starts with magic
"File\x00\xeb\x2a\x00T\x80" + a TLV record stream (e.g. 01 fe 00 06 |
addr 0x1e1b | 0xde30) — recognizable, schema not decoded (no ST1 sample
on disk; SPIDER_ST1.bin not embedded in the Windows exe either).

Undetermined: role of the runtime dword [rbp-0x1178]+0x20 as block-index
k (inferred state); the 0x18 checksum. — matches live observations on the
SC2V2 (csr11: device echoes match host-computed CRCs on A-side staging).
Status: done.
