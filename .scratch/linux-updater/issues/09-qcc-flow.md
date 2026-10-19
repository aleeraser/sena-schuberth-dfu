# 09 — QCC flow (UCOM3/6R/7R, `APPUHDR5` container)

Status: done
Blocked by: 05

Decode `APPUHDR5`/`PARTDATA` partition container (magic @0x180 in
`ucom3.img`; `PARTDATA` records with 16-byte hashes; TLV entries ending in
`END`) and the QCC update sequence ([B][0..9] steps, `COMMAND_ENTER_DNLD_MODE`,
`writeLAST`, Runloader — see findings.md flow map). Sample:
`ucom3-v1.3-build0-lp1.img` (4.5 MB, downloaded).

## Comments
## Comments

- 2026-10-13: unblocked (05 done). Offline recon of ucom3.img: `APPUHDR5`
  magic @0x17c, chip string `QCC512X` @0x188, then a u16 partition-id list
  (0xffff sentinels), then TLV `PARTDATA` records (NOT fixed 0x20 stride:
  first record = magic + {0x14000000, 0} + 16-byte hash; second carries an
  inline name "Image1" + u32 fields). Full record grammar + hash algo
  (md5? sha1-truncated?) still to decode; update sequence untouched.
- 2026-10-20: claimed → answered, see ## Answer. (The 10-13 note predates
  the current server samples: the grammar below is from
  `ucom3-v1.4.1-build0-lp1.img` / `UCOM6R-v1.3.1-build0-lp1.img`.)

## Answer

**Outer container**: the CURRENT server files are ordinary SENADRIVER
containers (magic e6c52819): UCOM3 = device_id **0x3340**, UCOM6R =
0x3430-family, 2 images (`<product>.bin` type 0 + `vp.bin` type 1), MD5s
verified with `schuberth-dfu download UCOM3`. `APPUHDR5` is the INNER
grammar of both image blobs (that is why the 10-13 raw sample had the
magic @0x17c).

**APPUHDR5 grammar** (decoded from real images, implemented as
`container.parse_qcc_partitions`, all multi-byte fields BIG-endian):

```
0x00 "APPUHDR5"                     magic (8 B)
0x08 u32BE 0x30                     header-block length
0x0C chip string "QCC512Xx\0..."    (12 B)
0x18 config block (u16 pairs incl. 0xffff sentinels) up to 0x3C
0x3C records, each:  "PARTDATA" (8) | u32BE total | u32BE kind | payload
    kind 0: 16 B key/hash blob (per-image random-looking)
    kind 1: 0x114 B descriptor: name "Image\x01", 8-byte TLV entries,
            terminated by "END\0" entry, then zero pad + 16 B hash
    kind 9: main firmware partition payload (UCOM3: 0xAB464 B)
    kind 7: voice-partition payload (vp.bin uses [0,1,7])
After last record: "APPUPFTR" | u32BE tableLen | tableLen/16 × 16-byte
    hash entries (md5/sha1/sha256 of payloads and 4 KiB chunks all
    rejected → keyed/proprietary digest; device-side verifies — the host
    forwards the blob untouched).
```

**Update flow** (threadMethodUpdate 0x1000337c5–0x100037432, entered for
PIDs {0x3430, 0x3340, 0x3341, 0x3420, 0x5590, …}): the SAME 1023-byte
bulk-B layer (c1b/a4f/a72, slot 0). Command inventory in address order:
`0x01` version → `0x03 [2]=05` ("COMMAND_ENTER_DNLD_MODE" OK/FAIL log
strings) → `0x13 [2]=0` preflight → per image: `0x05 [2=flag]`, `0x06`
chunks with **final chunk marked `0x0E`** (writeLAST switch at
0x100035113/0x10003512a), `0x07 [2]=0` commit → `0x08 [2]=0` reboot →
`0x0A` result; step logs "%@. %@[B][0..9]". Branch variants for
BT-only/+VP/EDN exist nearby ("QCC only BT Update Start" strings) —
exact branch-per-PID mapping is the residual unknown; implemented model
(`sc2flow.update_qcc`, sim-tested, 4 tests) is the common spine above.

**Implementation**: `update_qcc` wired behind family `qcc`
(0x3340/0x3341/0x3420/0x3430) with a static-model warning banner;
`FakeQcc` enforces ENTER_DNLD + writeLAST in tests. **Live validation
needs UCOM hardware** (watch for 0x03/0x13/0x0E replies on a real unit).
