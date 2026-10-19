"""Local web UI for the SCHUBERTH updater (`schuberth-dfu ui`).

A small stdlib-only server (ThreadingHTTPServer) with a JSON API and an
embedded single-page frontend under `schuberth_dfu/web/`. The layout and
wording deliberately mirror the vendor app's flow (DeviceRecognition ->
Precaution -> Update with progress -> result) for consistency; its
proprietary image assets are NOT shipped — the look is rebuilt with
neutral inline SVG/CSS.

The device plumbing is injectable (UIState) so the whole API can be
exercised against the simulated devices without hardware.
"""
from __future__ import annotations

import json
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Callable, List, Optional

VID = 0x092B

# Companion update interfaces (not products): hidden from the device list.
COMPANION_PIDS = frozenset({0x3220})


class DeviceInfo:
    """What the UI shows for a connected headset."""

    def __init__(self, product_id: int, name: str, family: Optional[str],
                 serial: str = ""):
        self.product_id = product_id
        self.name = name
        self.family = family
        self.serial = serial

    def to_json(self) -> dict:
        return {"pid": f"0x{self.product_id:04X}", "name": self.name,
                "family": self.family, "serial": self.serial,
                "supported": self.family is not None}


DeviceSource = Callable[[], List[DeviceInfo]]
VersionReader = Callable[[DeviceInfo], dict]
UpdateRunner = Callable[[DeviceInfo, str, bool, Callable[[str], None]],
                        dict]


def default_devices() -> List[DeviceInfo]:
    """Scan real hardware (raw-USB PIDs + kernel-HID devices)."""
    from .catalog import family_for_pid, load_catalog
    devices: List[DeviceInfo] = []
    seen = set()
    try:
        from .rawusb import scan_raw
        for pid, _, _ in scan_raw():
            if pid in COMPANION_PIDS or pid in seen:
                continue
            seen.add(pid)
            devices.append(DeviceInfo(
                pid, load_catalog().get(pid, f"PID {pid:#06x}"),
                family_for_pid(pid)))
    except Exception:
        pass
    try:
        from .transport import scan
        for d in scan():
            if d.product_id in COMPANION_PIDS or d.product_id in seen:
                continue
            seen.add(d.product_id)
            devices.append(DeviceInfo(
                d.product_id, load_catalog().get(d.product_id,
                                                 d.product_name),
                family_for_pid(d.product_id),
                d.serial_number or ""))
    except Exception:
        pass
    return devices


def default_versions(dev: DeviceInfo) -> dict:
    """Live {main, submesh} versions for the families we can talk to."""
    from .catalog import FAMILY_CSR, FAMILY_QCC, FAMILY_SC1
    out = {}
    if dev.family in (FAMILY_CSR, FAMILY_SC1, FAMILY_QCC):
        from .rawusb import RawHandle
        from .sc2flow import MeshLink, read_version
        link = MeshLink(RawHandle(dev.product_id))
        out["main"] = ".".join(map(str, read_version(link, echo=True)))
        if dev.product_id == 0x3217:
            try:
                from .airodfu import Link as AiroLink
                alink = AiroLink(RawHandle(0x3220), timeout=5.0)
                out["submesh"] = ".".join(map(str, alink.version()))
            except Exception:
                pass
    elif dev.family == "airoha":
        from .airodfu import Link
        from .transport import Handle
        link = Link(Handle(_find_dev(dev.product_id)))
        v = link.version()
        out["main"] = ".".join(map(str, v[:4]))
    return out


def _find_dev(product_id: int):
    from .transport import scan
    for d in scan():
        if d.product_id == product_id:
            return d
    raise RuntimeError(f"PID {product_id:#06x} vanished")


def default_update(dev: DeviceInfo, image_path: str, force: bool,
                   log: Callable[[str], None]) -> dict:
    """Perform one update, reusing the package flows. Returns
    {"ok": bool, "error": str|None}."""
    from .catalog import (FAMILY_AIROHA, FAMILY_CSR, FAMILY_QCC, FAMILY_SC1)
    from .container import parse_sena_container
    data = open(image_path, "rb").read()
    container = parse_sena_container(data)
    if not container.verify_all(data):
        return {"ok": False, "error": "container MD5 verification failed"}
    log(f"container {container.version}: "
        + ", ".join(i.name or str(i.type) for i in container.images))
    fam = dev.family
    try:
        if dev.product_id == 0x3217 or fam in (FAMILY_SC1, FAMILY_QCC):
            from .rawusb import RawHandle
            if dev.product_id == 0x3217:
                from .sc2flow import update_sc2v2 as flow
            elif fam == FAMILY_SC1:
                from .sc2flow import update_sc1 as flow
            else:
                from .sc2flow import update_qcc as flow
            flow(RawHandle(dev.product_id), container, data, log=log,
                 force=force, reopen=lambda: RawHandle(dev.product_id))
        elif fam == FAMILY_CSR:
            from .sc2flow import update_sc2
            update_sc2(_hid_handle(dev.product_id), container, data, log=log,
                       force=force)
        elif fam == FAMILY_AIROHA:
            from .airodfu import Link, update_image
            link = Link(_hid_handle(dev.product_id))
            for img in container.images:
                log(f"writing {img.name or img.type}")
                update_image(link, data, img,
                             progress=lambda d, t: log(f"  {d*100//t}%")
                             if d == t else None)
        else:
            return {"ok": False, "error": f"family {fam!r} not supported"}
        return {"ok": True, "error": None}
    except Exception as exc:
        log("".join(traceback.format_exception_only(type(exc), exc)).strip())
        return {"ok": False, "error": str(exc)}


def _hid_handle(product_id: int):
    from .transport import Handle
    return Handle(_find_dev(product_id))


def default_checker(product: str) -> dict:
    from .manifest import fetch_manifest, latest
    e = latest(fetch_manifest(), product)
    if e is None:
        return {"error": f"no manifest entry for {product!r}"}
    return {"product": e.product, "version": e.version,
            "filename": e.filename}


def default_prepare(product: str) -> dict:
    """Download the latest firmware for `product` into ./firmware/
    (gitignored). Reuses the file if already present."""
    import shutil
    import urllib.request
    from pathlib import Path
    from .manifest import download_url, fetch_manifest, latest
    e = latest(fetch_manifest(), product)
    if e is None:
        return {"error": f"no manifest entry for {product!r}"}
    outdir = Path("firmware")
    outdir.mkdir(exist_ok=True)
    dest = outdir / e.filename
    if not dest.exists():
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(download_url(e), timeout=300) as r, \
                open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        tmp.rename(dest)
    return {"path": str(dest), "version": e.version,
            "filename": e.filename}


class Job:
    """One queued update; UI polls status/log."""

    def __init__(self, dev: DeviceInfo, image: str, force: bool):
        self.dev = dev
        self.image = image
        self.force = force
        self.status = "queued"          # queued|running|done|failed
        self.log: List[str] = []
        self.result: dict = {}
        self.started = self.finished = None

    def to_json(self, with_log: bool = False) -> dict:
        j = {"status": self.status, "pid": self.dev.to_json(),
             "image": self.image, "force": self.force,
             "result": self.result}
        if with_log:
            j["log"] = self.log
        return j


class UIState:
    def __init__(self, devices: Optional[DeviceSource] = None,
                 versions: Optional[VersionReader] = None,
                 updater: Optional[UpdateRunner] = None,
                 checker: Optional[Callable[[str], dict]] = None,
                 preparer: Optional[Callable[[str], dict]] = None):
        self.devices = devices or default_devices
        self.versions = versions or default_versions
        self.updater = updater or default_update
        self.checker = checker or default_checker
        self.prepare = preparer or default_prepare
        self.job: Optional[Job] = None
        self.lock = threading.Lock()


def create_server(state: UIState, host: str = "127.0.0.1",
                  port: int = 8737) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "schuberth-dfu-ui"

        def log_message(self, fmt, *args):       # silence stderr spam
            pass

        # ---- helpers ----------------------------------------------------
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        # ---- routes -----------------------------------------------------
        def do_GET(self):                        # noqa: N802 (stdlib API)
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            try:
                if u.path == "/":
                    ref = resources.files("schuberth_dfu").joinpath(
                        "web", "index.html")
                    self._send(200, ref.read_bytes(), "text/html; charset=utf-8")
                elif u.path == "/api/state":
                    self._json(self._state())
                elif u.path == "/api/check":
                    self._json(self._check(q.get("product", [""])[0]))
                else:
                    self._json({"error": "not found"}, 404)
            except BrokenPipeError:
                pass
            except Exception as exc:
                self._json({"error": str(exc)}, 500)

        def do_POST(self):                       # noqa: N802
            u = urllib.parse.urlparse(self.path)
            try:
                body = json.loads(self.rfile.read(
                    int(self.headers.get("Content-Length", 0))))
            except (ValueError, json.JSONDecodeError):
                body = {}
            try:
                if u.path == "/api/update":
                    self._json(self._start_update(body))
                elif u.path == "/api/prepare":
                    self._json(self._prepare(body))
                else:
                    self._json({"error": "not found"}, 404)
            except Exception as exc:
                self._json({"error": str(exc)}, 500)

        # ---- API --------------------------------------------------------
        def _state(self) -> dict:
            out = {"devices": [], "job": None, "time": time.time()}
            for dev in state.devices():
                d = dev.to_json()
                if dev.family:
                    try:
                        d["versions"] = state.versions(dev)
                    except Exception as exc:
                        d["versions_error"] = str(exc)
                out["devices"].append(d)
            with state.lock:
                if state.job:
                    out["job"] = state.job.to_json(with_log=True)
            return out

        def _prepare(self, body: dict) -> dict:
            product = str(body.get("product") or "")
            if not product:
                return {"error": "product is required"}
            return state.prepare(product)

        def _check(self, product: str) -> dict:
            if not product:
                return {"error": "product is required"}
            return state.checker(product)

        def _start_update(self, body: dict) -> dict:
            pid = body.get("pid")
            image = body.get("image")
            force = bool(body.get("force"))
            if not pid or not image:
                return {"error": "pid and image are required"}
            devs = {d.product_id: d for d in state.devices()}
            try:
                dev = devs[int(pid, 16)]
            except (KeyError, ValueError):
                return {"error": f"device {pid} not connected"}
            with state.lock:
                if state.job and state.job.status in ("queued", "running"):
                    return {"error": "an update is already running"}
                job = Job(dev, str(image), force)
                state.job = job

            def worker():
                job.status = "running"
                job.started = time.time()

                def log(msg):
                    job.log.append(str(msg))
                    job.log = job.log[-400:]
                try:
                    job.result = state.updater(dev, image, force, log)
                    job.status = "done" if job.result.get("ok") else "failed"
                except Exception as exc:                     # safety net
                    job.result = {"ok": False, "error": str(exc)}
                    job.status = "failed"
                job.finished = time.time()

            threading.Thread(target=worker, daemon=True).start()
            return {"started": True}

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8737,
          open_browser: bool = True) -> None:
    state = UIState()
    httpd = create_server(state, host, port)
    url = f"http://{host}:{httpd.server_address[1]}/"
    print(f"SCHUBERTH updater UI: {url}  (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.4, lambda: _try_open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _try_open(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass
