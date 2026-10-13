"""SC2/SC2V2 "Qcc Mesh" update flow (ticket 11) — EXPERIMENTAL.

Decoded offline from the macOS app (findings.md "SC2 update flow,
decoded"). The wire framing and commands are evidence-backed, but the
phase->image ordering is not fully resolved and nothing here has run
against hardware. Treat as best-effort; keep a downgrade image handy.

Sequence (macOS 0x10003f824 preamble + 0x10004139c block loop):
  1. normal-mode handle (PID 0x3170/0x3217), transport B (1023/67):
     cmd 0x01 version -> skip if same; cmd 0x0F start
  2. "Find Mesh": device re-enumerates a DFU interface,
     PID in {0x3160, 0x3220, 0x6501, 0x6511}; poll up to 20x
  3. transport B: cmd 0x12 (rV), cmd 0x0F (VP phase)
  4. transport C (65/65): cmd 0x00 NOP, cmd 0x05, then per image
     cmd 0x06 chunks (<=61 B), then cmd 0x07 runloader, cmd 0x08 reboot
"""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from .container import SENAContainer
from .transport import Device, Handle, scan

DFU_MESH_PIDS = frozenset({0x3160, 0x3220, 0x6501, 0x6511})

CMD_NOP = 0x00
CMD_VERSION = 0x01
CMD_MESH_VERSION = 0x05
CMD_WRITE = 0x06
CMD_RUNLOADER = 0x07
CMD_REBOOT = 0x08
CMD_START = 0x0F
CMD_RV = 0x12

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
