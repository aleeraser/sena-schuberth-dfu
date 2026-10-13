# 09 — QCC flow (UCOM3/6R/7R, `APPUHDR5` container)

Status: blocked
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
