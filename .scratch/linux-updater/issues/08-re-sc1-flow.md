# 08 — RE search: SC1 (0x5622/0x5624) + SC10U (0x5623) update flow

Status: done
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
- 2026-10-20: claimed; static trace complete — see ## Answer below.

## Answer

**Transport**: the same 1023-byte bulk-B HID shim as SC2V2 (sub_100108c1b
write+echo-read / 100108a4f chunk write / 100108a72 busy-ack). NOT the
61/65-byte transport-C model of the old unverified `update_sc2()` notes,
and NOT Windows' DFUEngine/BCSP — on macOS the SC1 family goes through
`threadMethodUpdate:` exactly like SC2V2, with one addition: it *does*
implement the session commands (SC2V2 firmware answers status 2 to
0x2x/0x50; SC1 answers status 0 — that's where the "BT_MODULE_FIND AND
UPDATE START" log strings at 0x100051xxx/0x100053xxx live).

**Dispatch**: 0x5622/0x5623/0x5624 are members of the big *exclusion*
chain at 0x1000443a0–0x1000446c0 (together with 0x55xx Sena lines,
0x30xx, 0x6210, 0x6400, 0x5720, 0x5320/0x5330, 0x59xx…): they skip the
50S-family mesh-A loop block and run the generic continuation at
0x1000446c6.

**Sequence** (vendor addresses in parentheses):
1. Open main handle slot 0 (sub_1001086ec, 0x1000446ca); optional
   auxiliary "Airoha-style" handle slot 1 (sub_100108544 at
   0x100047c7f/0x100047ca1) — guarded, absence is non-fatal.
2. `0x01` version on slot 0 (0x100044837) → parse reply[3..6] → compare
   vs container version; equal → log "VERSION IS SAME" loop + exit.
3. `0x01` on slot 1 (0x1000495ab, edi=1) — aux/mesh version, log only.
4. Block-table parse per image (sub_10010ebf8, 0x10004de60/0x100046c95).
5. `0x01` (0x10004bf5a) → `0x21` BT-module-find (0x10004bfc0); success
   branch sends `0x50` arm (0x100051503, "UPDATE START MESH HANDLE
   FIND" log, retry loop). Best-effort.
6. sleep(2) → `0x21` (0x10004c5b7, hard-fail abort 0x10004ed7d) →
   sleep(10) → `0x20` (0x10004c5e3, hard-fail abort 0x10004eea1) →
   sleep(15).
7. Per image (loop capped at 2 — `cmp r12,2` 0x10004cc41; SC1A/SC1S/
   SC10U containers hold exactly 2: main .img + vp_en.bin):
   `0x05 [2=container flag byte]` → `0x06` chunks [lenBE16 data≤0x3FB]
   busy-ack → `0x07` commit. Identical framing to SC2V2 csr11.
8. `0x08 [01 08 00]` gated on did_any (0x10004cc6e/0x10004cc7e);
   cleanup (sub_100108269), reopen handles with retry
   (0x10004f1f1–0x10004f250); aux handle absent → DONE (0x10005d590).

**Manifest keys**: resolved live 2026-10-20 — `Firmware.txt` now carries
versioned entries: SC1A v2.1.1 (`SC1A-v2.1.1-build2.img`), SC1S v2.1,
SC10U v2.1, SC1M v1.1 (+ language variants). `Revisions` is alive too
(`schuberth-dfu check SC1A --all-revisions` works; the "403" noted in an
earlier comment was my own wrong manifest name). Container of SC1A: magic e6c52819, device_id=0x5622, count=2,
flags (0,1) — matches the flow's 2-image cap exactly. SC1M also appears
in the vendor dialog with SC2 ("Leave it powered off") — same update
posture as SC2V2.

**Live validation**: pending — needs SC1A/SC1S/SC10U hardware.
Implementation `sc2flow.update_sc1()` follows the steps above; the
session cmds are the only real difference from update_sc2v2.
- 2026-10-20 (follow-up): `je 0x10004ed7d`/`je 0x10004eea1` confirmed as
  log-and-abort epilogues (13-image loop → 0x100038cf8), so the second
  0x21 and 0x20 are true hard gates — implemented as such. Bonus: SC1M
  v1.1 container inspected → device_id **0x6400** (not 0x56xx), 2 images
  flags (0,1); 0x6400 is in the same exclusion chain, so SC1M maps to
  this flow too (catalog + families updated). 41 tests green
  (5 new SC1 sim tests). Status: research done; live flash validation
  needs SC1 hardware — tracked as a checklist item under ticket 06-style
  hardware runs.
