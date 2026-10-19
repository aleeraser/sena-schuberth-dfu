# 10 — PRISM flow (`__prism_dfu_bluetooth__.img`)

Status: blocked
Blocked by: PRISM hardware (research answered 2026-10-20; the
wrapper→drop-file transform needs observation on a real device — see
## Answer)

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

## Answer

**The PRISM update is a disk-copy, not a packet protocol.** Evidence:
`-[UpdateViewController ...]` PRISM strings `getPrismDiskPathWithDevice:`
(mount-point lookup), `checkPrismUpdateComplete`, `endPrismUpdate`, and
the drop-file name table in `__cstring`:
`prism.bin | __prism_dfu_bluetooth__.img | __prism_firmware__.bin | ...`
followed by the same scheme for the camera line (`__10c_firmware__.bin`,
`AmbaSysFW_10CEVO.bin`, `MISC/version.conf`, `__50c_firmware__.bin`,
`__hd50c_firmware__.bin`, ...). The dialog matches: "1. Disconnect the
USB cable from the PRISM. 2. Wait until the PRISM completes update and
powers off. 3. Connect USB cable to the PRISM and then power on it."
The 0x10010f6ab "simple container" parser = the drop-file validator
(CRC-32 over the whole file with a u32 trailer; product name at 0x10,
cut at 0x23; SMH10 special case for names starting with a space).

**Download artifact wrapper** (`PRISM-v1.0.0.0.img`, 14,409,492 B;
implemented read-only as `container.parse_prism_update_image`, 2 tests):

```
0x00 "v0.0.0.0" (28 B version string)   0x1C u32 pid 0x3020
0x20 u32 count 2                         0x2C u32 100 (flags?)
0x30 u32 comp0 region size 0x131EB0      0x34 16 B key
0x4C u32 main offset 0x131F14 ─┐ main offset + main size (0x50, 0xC8C000)
                               └ == file size exactly (two tiled components)
0x64 "CSR-dfu2" sub-header: 0x6E u32 bt image size 0x131EA0,
   0x74 72-B space-padded name "PRISM#3020"  → BT-module DFU component
   (= the __prism_dfu_bluetooth__ part); the ~13 MB tail is the camera
   firmware (contains Amba log strings like "DFU IDLE").
```

**Unresolved / needs hardware**: the exact wrapper→drop-file transform
(which bytes land in `__prism_dfu_bluetooth__.img` vs
`__prism_firmware__.bin`, and their CRC/name headers) is only observable
by watching what a Mac writes to a real PRISM's MSC volume; the app's
USB-HID 0x55xx handshake region (0x10004bb8c+) is for the 55xx devices,
NOT this flow (earlier note in Comments corrected). Implementation is
therefore intentionally not wired: `FAMILY_PRISM` stays "update flow not
implemented" in the CLI. Next step when hardware is available: capture
the drop files a Mac writes (or watch `checkPrismUpdateComplete`
against `MISC/version.conf`) and implement a `prism_disk_update.py`.
