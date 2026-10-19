"""SC2/SC2V2 update flows (tickets 06/11) — reconstructed from the macOS
app's -[UpdateViewController threadMethodUpdate:] (findings.md).

SC2V2 (0x3217) flow, static model confirmed against live probing 2026-10-19:
  1. B handle (0x3217): cmd 0x01 version -> skip if same.
  2. QCC update session (vendor 0x10004bb8c..0x10004bfc0): cmd 0x20 start,
     cmd 0x22 poll x25, cmd 0x21 confirm. Requires the headset's main
     system to be powered on; a USB-charge-mode device answers status 2
     and the vendor app aborts too.
  3. Per main image (type 0 BT, type 1 VP; vendor 0x10004b168/0x10004cb34):
     cmd 0x05 start, cmd 0x06 chunks [01 06 lenBE16 data(<=1019)] with
     per-chunk ack (busy-retry), cmd 0x0E last chunk, cmd 0x07 commit,
     cmd 0x08 reboot, cmd 0x0A result. Frames are [01 cmd 00 ...] —
     sub_100108c1b never writes FF into the frame (the FF sentinel is in
     the reply buffer).
  4. Submesh image (type 3) via the Airoha mesh interface (0x3220),
     transport A block loop (0x100045728), confirmed live (staging OK).
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
CMD_WRITE_LAST = 0x0E
CMD_START = 0x0F
CMD_RV = 0x12
CMD_SESSION_START = 0x20
CMD_SESSION_CONFIRM = 0x21
CMD_SESSION_WAIT = 0x22

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

    def _await_ok(self, read: Callable[[], bytes]) -> bytes:
        for _ in range(self.busy_retries):
            rep = read()
            if rep == b"":
                raise Sc2Error("device stopped answering (link dead?)")
            if len(rep) >= 3 and rep[2] != 1:
                return rep
            time.sleep(self.busy_delay)
        raise Sc2Error("device stuck busy (reply[2]==1)")

    def bulk(self, cmd: int, params: bytes = b"") -> bytes:
        """Transport B: write 1023, read 67 (sub_100108c1b model)."""
        self.h.write_bulk(cmd, params)
        rep = self._await_ok(self.h.read_bulk)
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


def read_version(link: MeshLink) -> tuple:
    rep = link.bulk(CMD_VERSION)
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


def _reopen_mesh(mesh_handle, mesh_reopen, log):
    """The Airoha side re-enumerates when it applies a block (observed
    live: verify on block 0 reset the 0x3220 interface). Close, wait for
    it to come back, hand out a fresh handle."""
    try:
        mesh_handle.close()
    except Exception:
        pass
    for i in range(13):
        time.sleep(1.5)
        try:
            return mesh_reopen()
        except Exception as exc:
            log(f"  mesh reopen retry {i + 1}/13: {exc}")
    raise Sc2Error("mesh interface never came back")


def qcc_session(link: MeshLink, log: Callable[[str], None],
                *, wait_retries: int = 25, go_retries: int = 13) -> None:
    """Vendor update-session handshake (0x10004bb8c/0x10004bbc5/0x10004bfc0):
    0x20 start, 0x22 poll (x25, usleep(1 ms)), 0x21 confirm. A charge-mode
    or dead-battery device answers status 2; the vendor app also fails
    there (retry loop logs 'UPDATE START MESH HANDLE FIND')."""
    try:
        link.bulk(CMD_SESSION_START)
    except Sc2Error as exc:
        raise Sc2Error(
            "device refused the update session (cmd 0x20). The headset's "
            "main system must be powered on with a working battery; a "
            "USB-charge-mode device answers status 2. Original error: "
            f"{exc}") from exc
    for _ in range(wait_retries):       # vendor loop: 0x19 tries, 1 ms sleep
        try:
            link.bulk(CMD_SESSION_WAIT)
            break
        except Sc2Error:
            time.sleep(0.001)
    else:
        raise Sc2Error("session wait (cmd 0x22) never succeeded")
    for i in range(go_retries):
        try:
            link.bulk(CMD_SESSION_CONFIRM)
            return
        except Sc2Error as exc:
            log(f"session confirm retry {i + 1}/{go_retries}: {exc}")
            time.sleep(0.001)
    raise Sc2Error("session confirm (cmd 0x21) never succeeded")


def csr_download(link: MeshLink, blob: bytes, *,
                 progress: Optional[Callable[[int, int], None]] = None,
                 busy_retries: int = 1000) -> None:
    """Vendor CSR download loop (0x10004b168): 0x05 start, then per chunk
    [01 06 lenBE16 data] (last chunk uses cmd 0x0E), then a per-chunk ack
    read (sub_100108a72 semantics: retry while device says busy [2]==1;
    a missing reply does not stop the vendor loop either)."""
    link.bulk(CMD_DFU_START)
    off = 0
    while off < len(blob):
        chunk = blob[off:off + CSR_CHUNK_LEN]
        cmd = CMD_WRITE_LAST if off + CSR_CHUNK_LEN >= len(blob) else CMD_WRITE
        link.h.write_bulk(cmd, len(chunk).to_bytes(2, "big") + chunk)
        for _ in range(busy_retries):
            rep = link.h.read_bulk()
            if not rep or all(b == 0 for b in rep):
                continue
            if len(rep) > 2 and rep[1] == cmd and rep[2] == 1:
                time.sleep(link.busy_delay)
                continue
            break
        off += len(chunk)
        if progress:
            progress(off, len(blob))


def update_sc2v2(main_handle, mesh_handle, container, data: bytes,
                 *, log: Optional[Callable[[str], None]] = None,
                 force: bool = False,
                 mesh_reopen: Optional[Callable[[], object]] = None) -> bool:
    """SC2V2 flow, vendor-exact (see module docstring; tools/re/csr_full.py
    is the standalone driver of the same sequence). Main images (types 0/1)
    stream over B (0x3217) with the session handshake; only the submesh
    image (type 3) goes through the Airoha mesh loop. Returns True if
    anything was written. Raises Sc2Error on device refusal."""
    log = log or (lambda s: None)
    link = MeshLink(main_handle)
    wrote = False
    ver = read_version(link)
    target = parse_container_version(container.version)
    log(f"main version: {'.'.join(map(str, ver))} -> target "
        f"{'.'.join(map(str, target))}")

    main_images = [(i, im) for i, im in enumerate(container.images)
                   if im.type in (0, 1)]
    mesh_images = [(i, im) for i, im in enumerate(container.images)
                   if im.type == 3]

    if main_images and (ver != target or force):
        log("QCC update session (0x20/0x22/0x21)")
        qcc_session(link, log)
        for n, (idx, image) in enumerate(main_images):
            if n:  # vendor's second pair (0x10004c5b7/0x10004c5e3)
                link.bulk(CMD_SESSION_CONFIRM)
                link.bulk(CMD_SESSION_START)
            log(f"CSR download image {image.name or idx} "
                f"type={image.type} size={image.size:#x}")
            csr_download(link, image.blob(data),
                         progress=lambda d, t: log(f"  {d * 100 // t}%")
                         if d == t else None)
            link.bulk(CMD_RUNLOADER)         # commit ("QCC BT Runloader Start")
            time.sleep(2.0)
            try:
                link.bulk(CMD_REBOOT)
            except Sc2Error as exc:
                log(f"reboot reply: {exc} (device may just restart)")
            time.sleep(3.0)
            while True:                      # drain boot-time pushes
                rep = main_handle.read_bulk(timeout_ms=300)
                if not rep:
                    break
            try:
                rep = link.bulk(CMD_RESULT)
                log(f"DFU result: {rep[3] if len(rep) > 3 else '?'}")
            except Sc2Error as exc:
                log(f"result query: {exc}")
            wrote = True
        new = read_version(link)
        log(f"main version now: {'.'.join(map(str, new))}")
    elif main_images:
        log("main: VERSION IS SAME, UPDATE SKIP")

    mesh_wrote = False
    if mesh_images:
        from .airodfu import (AirohaError, AirohaResetError,
                              Link as AiroLink, update_image)
        alink = AiroLink(mesh_handle, timeout=20.0)
        sm_ver = airo_ready(alink, log=log)
        log(f"airoha version: {'.'.join(map(str, sm_ver))}")
        for idx, image in mesh_images:
            sm_target = parse_submesh_image_version(image.name)
            if sm_ver == sm_target and not force:
                log(f"block {idx} ({image.name}): VERSION IS SAME, SKIP")
                continue
            log(f"writing block {idx} type={image.type} size={image.size:#x} "
                f"name={image.name or '-'}")
            from .rawusb import RawUsbError
            for attempt in (1, 2):
                try:
                    try:
                        bver = tuple(alink.block_version(idx))
                        log(f"block {idx} version check: "
                            f"{'. '.join(map(str, bver))}")
                    except AirohaError as exc:
                        log(f"block {idx} version check: {exc} (continuing)")
                    alink.start_block()
                    update_image(alink, data, image,
                                 progress=lambda d, t: log(f"  {d * 100 // t}%")
                                 if d == t else None, log=log, close="stage")
                    wrote = mesh_wrote = True
                    break
                except AirohaResetError as exc:
                    log(f"block {idx} applied by device ({exc})")
                    if mesh_reopen is None:
                        raise Sc2Error(f"block {idx} applied but link died") from exc
                    mesh_handle = _reopen_mesh(mesh_handle, mesh_reopen, log)
                    alink = AiroLink(mesh_handle, timeout=20.0)
                    sm_ver = airo_ready(alink, log=log)
                    wrote = mesh_wrote = True
                    break
                except (AirohaError, RawUsbError) as exc:
                    log(f"block {idx} attempt {attempt} failed: {exc}")
                    if attempt == 2 or mesh_reopen is None:
                        raise Sc2Error(f"block {idx} failed: {exc}") from exc
                    log("reopening mesh interface (device may have reset)")
                    mesh_handle = _reopen_mesh(mesh_handle, mesh_reopen, log)
                    alink = AiroLink(mesh_handle, timeout=20.0)
                    sm_ver = airo_ready(alink, log=log)
            if wrote and mesh_reopen is not None:
                time.sleep(2.0)
                mesh_handle = _reopen_mesh(mesh_handle, mesh_reopen, log)
                alink = AiroLink(mesh_handle, timeout=20.0)
                sm_ver = airo_ready(alink, log=log)
        # mesh commit for staged submesh blocks (vendor 0x07/0x08 on A)
        if not mesh_wrote:
            log("mesh: nothing staged, no commit")
        else:
            log("commit mesh blocks (0x07, 0x08)")
            try:
                alink.run_loader()
                log("run-loader acked")
            except (AirohaError, RawUsbError) as exc:
                log(f"run-loader: {exc}")
            try:
                alink.verify()
                log("mesh 0x08 acked")
            except (AirohaError, RawUsbError) as exc:
                log(f"mesh 0x08: {exc} (device likely rebooting)")
    log("done")
    return wrote


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
