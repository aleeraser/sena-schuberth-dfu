"""SC2/SC2V2 update flows (tickets 06/11) — from the macOS app's
-[UpdateViewController threadMethodUpdate:] (findings.md).

SC2V2 (0x3217) flow, LIVE-VERIFIED 2026-10-19 (real device upgraded
2.3.2.1 -> 2.4.0.0 with this sequence, tools/re csr11 replay):
  1. B handle (0x3217): cmd 0x01 version -> skip if same.
  2. sleep(5) (vendor 0x10005d2b0).
  3. Per container image, in table order — ALL of them, including the
     submesh: cmd 0x05 start [2=image.flag], cmd 0x06 chunks
     [01 06 lenBE16 data(<=1019)] with per-chunk ack (busy-retry,
     sub_100108a4f/100108a72), cmd 0x07 commit (0x10005d3dc..0x10005d4b1).
  4. sleep(5) (vendor 0x10005e900), then cmd 0x08 reboot [2]=0
     (0x10005f1e2, gated on "did anything") and sleep(1); the device
     re-enumerates itself and the app reopens the handles.

Superseded (see findings.md): the 0x20/0x22/0x21 "session handshake", the
0x0E last-chunk cmd, and per-image 0x08/0x0A pairs belong to the PRISM
family (PIDs 0x5510/0x5580/0x5570/0x5576/0x3060) — the vendor skips that
whole branch for every other PID via the gate at 0x10004bb85. A device
answer status 2 to 0x2x is therefore normal on 0x3217, not a power gate.
All frames are [01 cmd ...] zero-padded to 1023 B; sub_100108c1b never
writes FF into the frame (the FF sentinel is in the reply buffer).

The older update_sc2()/mesh-loop code models other device families
(SC1/PRISM tickets, UNVERIFIED) and is retained unchanged.
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from .container import SENAContainer
from .transport import Device, Handle, scan

DFU_MESH_PIDS = frozenset({0x3160, 0x3220, 0x6500, 0x6501, 0x6511})

CMD_NOP = 0x00
CMD_VERSION = 0x01
CMD_MESH_VERSION = 0x05
CMD_WRITE = 0x06
CMD_RUNLOADER = 0x07
CMD_REBOOT = 0x08
CMD_RESULT = 0x0A
CMD_DFU_START = 0x05
CMD_START = 0x0F
CMD_RV = 0x12
# Session commands: implemented by the SC1 family (ticket 08) and PRISM
# (0x55xx/0x3060, ticket 10); SC2V2 (0x3217) answers status 2 to these and
# the vendor never sends them there. 0x0E (write-last) is PRISM/50S-only.
CMD_SESSION_START = 0x20
CMD_BT_MODULE_FIND = 0x21
CMD_ARM_MESH = 0x50

CSR_CHUNK_LEN = 0x3FB         # 1019 B payload (vendor 0x100045964: mov eax,0x3fb)
MESH_CHUNK_LEN = 0x3D         # 61 bytes (0x100041452)
BULK_CHUNK_LEN = 0x3A         # 58 bytes (bulk mesh loop variant)


class Sc2Error(Exception):
    pass


class MeshLink:
    """Transports B + C over one Handle (or fake).

    Reply layout for both: [1]=status, [2]=result (0 OK, 1 busy -> retry),
    [3..]=payload. Busy replies are retried like sub_100108c1b/109161 do.
    """

    def __init__(self, handle, *, busy_delay: float = 0.1,
                 busy_retries: int = 1000):
        self.h = handle
        self.busy_delay = busy_delay
        self.busy_retries = busy_retries

    def _await_ok(self, read: Callable[[], bytes],
                  cmd: Optional[int] = None) -> bytes:
        for _ in range(self.busy_retries):
            rep = read()
            if rep == b"":
                raise Sc2Error("device stopped answering (link dead?)")
            if cmd is not None and (len(rep) <= 2 or rep[1] != cmd):
                continue  # stale pushed frame: live EP1 lags one push behind
            if len(rep) >= 3 and rep[2] != 1:
                return rep
            time.sleep(self.busy_delay)
        raise Sc2Error("device stuck busy (reply[2]==1)")

    def bulk(self, cmd: int, params: bytes = b"", *,
             echo: bool = False) -> bytes:
        """Transport B: write 1023, read 67 (sub_100108c1b model).
        `echo=True` additionally discards replies that do not echo `cmd`
        (needed on live 0x3217 hardware; the SC2V2 flow always uses it)."""
        self.h.write_bulk(cmd, params)
        rep = self._await_ok(self.h.read_bulk, cmd if echo else None)
        if rep[2] != 0:
            raise Sc2Error(f"bulk cmd {cmd:#02x} result={rep[2]}")
        return rep

    def mesh(self, cmd: int, params: bytes = b"") -> bytes:
        """Transport C: write 65, read 65 (sub_100109161 model)."""
        self.h.write_mesh(cmd, params)
        rep = self._await_ok(self.h.read_mesh)
        if rep[2] != 0:
            raise Sc2Error(f"mesh cmd {cmd:#02x} result={rep[2]}")
        return rep

    def write_chunk(self, data: bytes) -> None:
        """cmd 0x06 write + separate busy-ack read (sub_1001090ac/cf)."""
        if len(data) > MESH_CHUNK_LEN:
            raise Sc2Error(f"chunk too long: {len(data)}")
        self.h.write_mesh(CMD_WRITE, b"\x00" + bytes([len(data)]) + data)
        rep = self._await_ok(self.h.read_mesh)
        if rep[2] != 0:
            raise Sc2Error(f"write ack result={rep[2]}")


def find_mesh_handle(*, retries: int = 20, delay: float = 1.0,
                     log: Optional[Callable[[str], None]] = None,
                     opener: Callable = Handle) -> Handle:
    """Poll for the DFU-mode interface (the app's 'Find Mesh' step).

    DFU-mode PIDs are update interfaces, not catalog products, so scan()
    is told to accept them explicitly.
    """
    for i in range(retries):
        for d in scan(extra_pids=DFU_MESH_PIDS):
            if d.product_id in DFU_MESH_PIDS:
                if log:
                    log(f"mesh DFU interface up: PID {d.product_id:#06x}")
                return opener(d)
        if log:
            log(f"Find Mesh: retry {i + 1}/{retries}")
        time.sleep(delay)
    raise Sc2Error("mesh DFU interface never appeared")


def read_version(link: MeshLink, *, echo: bool = False) -> tuple:
    rep = link.bulk(CMD_VERSION, echo=echo)
    return tuple(rep[3:7])


def parse_submesh_image_version(name: str):
    """'Submesh_v0.4b4.bin' -> (0, 4, 0, 0, 4): the 5-tuple the module
    reports via transport A cmd 0x01 (live: 00 04 00 00 04)."""
    import re
    m = re.search(r"v(\d+)\.(\d+)b(\d+)", name or "")
    if not m:
        return None
    major, minor, build = (int(g) for g in m.groups())
    return (major, minor, 0, 0, build)


def airo_ready(alink, *, retries: int = 13, delay: float = 1.5,
               log: Optional[Callable[[str], None]] = None):
    """Vendor 'open airoha mesh' retry loop (0x100040a03, 13x): after the
    0x0F session cmd — and after an aborted transfer — the Airoha side can
    be briefly silent; gate on a successful cmd 0x01."""
    log = log or (lambda s: None)
    from .airodfu import AirohaError
    quick = alink.timeout
    alink.timeout = 5.0
    try:
        for i in range(retries):
            try:
                return tuple(alink.version())
            except AirohaError as exc:
                log(f"airoha not ready ({exc}); retry {i + 1}/{retries}")
                time.sleep(delay)
    finally:
        alink.timeout = quick
    raise Sc2Error("airoha interface never became ready")


def _stage_and_commit(link: MeshLink, images, data: bytes,
                      log: Callable[[str], None]) -> None:
    """Vendor per-image CSR download loop, shared by SC2V2 (0x10005d2b0)
    and SC1 (0x10004cb34): 0x05 [2=flag], 0x06 chunks [lenBE16 data]
    with echo-matched busy-ack, 0x07 commit. Aborts on the first ack
    with status != 0 — before any commit."""
    for idx, image in enumerate(images):
        blob = image.blob(data)
        log(f"staging image {idx} {image.name or '-'} type={image.type} "
            f"flag={image.flag} size={image.size:#x}")
        link.bulk(CMD_DFU_START, bytes([image.flag & 0xFF]), echo=True)
        off = 0
        while off < len(blob):
            chunk = blob[off:off + CSR_CHUNK_LEN]
            link.bulk(CMD_WRITE, len(chunk).to_bytes(2, "big") + chunk,
                      echo=True)
            off += len(chunk)
            if off == len(blob):
                log(f"  image {idx}: {len(blob)} B staged")
        link.bulk(CMD_RUNLOADER, echo=True)
        log(f"image {idx} committed (0x07)")


def _wait_after_reboot(main_handle, link, reopen, log):
    """The device re-enumerates after 0x08 (observed ~40 s on SC2V2);
    hand back a link on a fresh handle when `reopen` is provided."""
    if reopen is None:
        return link
    try:
        main_handle.close()
    except Exception:
        pass
    main_handle = None
    for i in range(120):
        try:
            main_handle = reopen()
            break
        except Exception as exc:
            log(f"reopen retry {i + 1}/120: {exc}")
            time.sleep(2)
    if main_handle is None:
        raise Sc2Error("device never came back after reboot")
    return MeshLink(main_handle)


def update_sc2v2(main_handle, container, data: bytes,
                 *, log: Optional[Callable[[str], None]] = None,
                 force: bool = False,
                 reopen: Optional[Callable[[], object]] = None) -> bool:
    """SC2V2 (0x3217) flow, vendor-exact and live-verified (module
    docstring). Every container image — including the submesh — stages
    over transport B: 0x05 [2=flag], 0x06 chunks, 0x07 commit; then one
    0x08 reboot at the very end. No session handshake, no 0x0E, no
    A-side (0x3220) traffic. Returns True if anything was written.
    Raises Sc2Error on device refusal (chunk ack status != 0 aborts
    before any commit)."""
    log = log or (lambda s: None)
    link = MeshLink(main_handle)
    ver = read_version(link, echo=True)
    target = parse_container_version(container.version)
    log(f"main version: {'.'.join(map(str, ver))} -> target "
        f"{'.'.join(map(str, target))}")
    if ver == target and not force:
        log("main: VERSION IS SAME, UPDATE SKIP")
        return False

    log("vendor sleep(5) (0x10005d2b0)")
    time.sleep(5)
    _stage_and_commit(link, container.images, data, log)
    log("vendor sleep(5) (0x10005e900)")
    time.sleep(5)
    try:
        link.bulk(CMD_REBOOT, b"\x00", echo=True)
    except Sc2Error as exc:
        log(f"reboot reply: {exc} (device restarts on commit)")
    time.sleep(1)
    link = _wait_after_reboot(main_handle, link, reopen, log)
    new = read_version(link, echo=True)
    log(f"main version now: {'.'.join(map(str, new))}")
    return True


def update_sc1(main_handle, container, data: bytes,
               *, log: Optional[Callable[[str], None]] = None,
               force: bool = False,
               reopen: Optional[Callable[[], object]] = None) -> bool:
    """SC1 family (SC1A 0x5622 / SC10U 0x5623 / SC1S 0x5624), static
    vendor model of ticket 08 (NOT yet hardware-verified — the live
    session replies can only be confirmed on real SC1 hardware).

    Same B-side CSR download as update_sc2v2, preceded by the vendor
    session preamble the SC1 firmware implements
    (0x10004bf5a..0x10004cc38):
      0x01 -> 0x21 + 0x50 (best-effort, vendor retries while logging
      "UPDATE START MESH HANDLE FIND") -> sleep(2) -> 0x21 -> sleep(10)
      -> 0x20 -> sleep(15); hard-fail aborts are 0x10004ed7d/0x10004eea1.
    The vendor image loop covers only the first TWO container entries
    (`cmp r12,2` at 0x10004cc41; SC1 containers hold exactly main + vp).
    """
    log = log or (lambda s: None)
    link = MeshLink(main_handle)
    ver = read_version(link, echo=True)
    target = parse_container_version(container.version)
    log(f"main version: {'.'.join(map(str, ver))} -> target "
        f"{'.'.join(map(str, target))}")
    if ver == target and not force:
        log("main: VERSION IS SAME, UPDATE SKIP")
        return False

    link.bulk(CMD_VERSION, echo=True)         # 0x10004bf5a
    for cmd in (CMD_BT_MODULE_FIND, CMD_ARM_MESH):
        try:
            link.bulk(cmd, echo=True)
        except Sc2Error as exc:
            log(f"session cmd {cmd:#02x}: {exc} "
                "(vendor retries in mesh-handle-find loop; continuing)")
    time.sleep(2)
    link.bulk(CMD_BT_MODULE_FIND, echo=True)  # 0x10004c5b7 (hard)
    time.sleep(10)
    link.bulk(CMD_SESSION_START, echo=True)   # 0x10004c5e3 (hard)
    time.sleep(15)

    images = container.images[:2]
    if len(container.images) > 2:
        log(f"note: {len(container.images)} images in container; vendor "
            "loop covers only the first 2")
    _stage_and_commit(link, images, data, log)

    try:
        link.bulk(CMD_REBOOT, b"\x00", echo=True)   # 0x10004cc6e, did_any-gated
    except Sc2Error as exc:
        log(f"reboot reply: {exc} (device restarts on commit)")
    time.sleep(1)
    link = _wait_after_reboot(main_handle, link, reopen, log)
    new = read_version(link, echo=True)
    log(f"main version now: {'.'.join(map(str, new))}")
    return True


def parse_container_version(version: str) -> tuple:
    """'v1.5-build0' -> (1, 5, 0, 0): the 4-tuple the device reports.

    The macOS app compares these and logs "VERSION IS SAME ... UPDATE
    SKIP"; we skip only on an exact 4-tuple match (conservative).
    """
    core = version.split("-", 1)[0].lstrip("vV")
    parts = [int(p) for p in core.split(".") if p.isdigit()]
    return tuple((parts + [0, 0, 0, 0])[:4])


def update_image(link: MeshLink, data: bytes, image,
                 progress: Optional[Callable[[int, int], None]] = None) -> None:
    blob = image.blob(data)
    for off in range(0, len(blob), MESH_CHUNK_LEN):
        link.write_chunk(blob[off:off + MESH_CHUNK_LEN])
        if progress:
            progress(min(off + MESH_CHUNK_LEN, len(blob)), len(blob))


def update_sc2(handle: Handle, container: SENAContainer, data: bytes,
               images: Optional[List] = None,
               log: Optional[Callable[[str], None]] = None,
               mesh_opener: Callable[[], Handle] = find_mesh_handle,
               force: bool = False) -> bool:
    """Run the SC2 flow. `images` selects container images, in order;
    default = all, in container order (UNVERIFIED ordering assumption).
    `mesh_opener` finds/opens the DFU interface (injectable for tests).
    Returns False (nothing written) if the device already reports the
    container's version, unless `force`."""
    log = log or (lambda s: None)
    link = MeshLink(handle)

    ver = read_version(link)
    log(f"device version: {'.'.join(map(str, ver))}")
    target = parse_container_version(container.version)
    if ver == target and not force:
        log(f"VERSION IS SAME, {'.'.join(map(str, ver))} UPDATE SKIP")
        return False
    log(f"target version: {'.'.join(map(str, target))}")
    log("Qcc Mesh Update start")
    link.bulk(CMD_START)

    log("Find Mesh")
    mesh_handle = mesh_opener()
    try:
        link = MeshLink(mesh_handle)
        rv = link.bulk(CMD_RV)[3]
        log(f"rV = {rv}")
        log("Qcc Mesh Update start VP")
        link.bulk(CMD_START)

        link.mesh(CMD_NOP)
        link.mesh(CMD_MESH_VERSION)
        for image in (images if images is not None else container.images):
            log(f"writing image type={image.type} size={image.size:#x} "
                f"name={image.name or '-'}")
            update_image(link, data, image,
                         progress=lambda done, total: log(
                             f"  {done * 100 // total}%") if done == total else None)
            link.mesh(CMD_RUNLOADER)
            link.mesh(CMD_REBOOT)
            mesh_handle.close()
            log("Find Mesh (next phase)")
            mesh_handle = mesh_opener()
            link = MeshLink(mesh_handle)
    finally:
        mesh_handle.close()
    log("done")
    return True
