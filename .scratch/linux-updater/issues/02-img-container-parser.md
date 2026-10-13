# 02 — `.img` container parser (Airoha + PRISM + QCC sniff)

Status: done

Implement `container.py`:

- **Airoha container**: 724-byte header; magic `19 28 C5 E6` @0x18; model id
  @0x1C; image count @0x20; per-image `{a, b, file_offset, size, md5[16]}`
  records @0x24 stride 0x20; image names @0x10C/0x244. Verify MD5 of each
  blob. Sample files: `SPIDER_ST1-v2.5.3-build0.img`, `S1-v1.3.2-build1.img`,
  `M1_EVO-v2.3-build0.img`, `SENA_C30-v1.2.4-build0.img` (downloaded from
  firmware.sena.com).
- **PRISM container**: product name string @0x10, CRC-32 footer (last 4 bytes
  = CRC32 of the rest) — per `sub_10010f6ab`.
- **QCC**: detect `APPUHDR5` magic @0x180 and report "unsupported in v1".
- Tests over the four sample images (hashes recorded in findings.md).

## Comments

- 2026-10-13: implemented in `schuberth_dfu/container.py` + `crc.py`. Name
  records associate positionally with images (verified on st1 + sc2). All 6
  real images (st1/s1/m1evo/c30/sc2/sc2v2) MD5-verify in tests
  (`SCHUBERTH_TEST_IMGS=... pytest`). PRISM footer check via `crc32`.
