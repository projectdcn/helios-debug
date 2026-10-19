"""helios-debug web UI: run the link check tools (scan, bcm, path, pingmap) and browse their reports.

Runs on the switch tray (or any host with the repo), standard library only:

    python3 -m ui                       # http://127.0.0.1:8780, inventories from ./inventory
    python3 -m ui --port 8780 --inventory-dir ~/helios-debug-ui/inventory

It listens on 127.0.0.1 only; open it through an SSH tunnel:  ssh -L 8780:localhost:8780 admin@<switch>
then browse http://localhost:8780. Requests whose Host is not localhost are refused (DNS rebinding), every POST needs
the X-Helios-Debug header (a web page cannot send it cross-origin), tool arguments are passed as a list (no shell)
and checked against the inventory. One tool runs at a time. An AFM password typed for a scan is handed to that one
run in its environment and kept nowhere else.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heliosdbg.inventory import load_inventory  # noqa: E402
from ui import access  # noqa: E402

TOOL = ROOT / "tools" / "link_check.py"
STATIC = Path(__file__).resolve().parent / "static"
TOOLS = ("scan", "link", "bcm", "path", "pingmap")
TARGET_RX = re.compile(r"^[A-Za-z0-9 _./:\[\],()-]{1,200}$")
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PORTS_RX = re.compile(r"^Ethernet\d{1,4}(,Ethernet\d{1,4}){0,63}$")
GPU_PORTS_RX = re.compile(r"^\d{1,2}(,\d{1,2}){0,35}$")
BDF_RX = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}
LOG_KEEP = 400_000          # characters of a job's output kept in memory (the full output is in the job's log file)


class BadRequest(Exception):
    pass


# ------------------------------------------------------------------ inventories and results

class State:
    def __init__(self, inventory_dir: Path, results_dir: Path):
        self.inventory_dir, self.results_dir = inventory_dir, results_dir
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.current: str | None = None

    def inventories(self) -> list[dict]:
        out = []
        for f in sorted(self.inventory_dir.glob("*.yaml")):
            if f.name.startswith("example"):
                continue
            try:
                inv = load_inventory(f)
            except Exception as e:  # noqa: BLE001 - listed with its error, not hidden
                out.append({"file": f.name, "error": f"{type(e).__name__}: {str(e)[:200]}"})
                continue
            out.append({"file": f.name, "rack": inv.rack, "switches": [h.name for h in inv.switches],
                        "computes": [h.name for h in inv.computes],
                        "local": [h.name for h in inv.switches + inv.computes if (h.extra or {}).get("local") is True],
                        "afm": bool((inv.afm or {}).get("url")),
                        "afm_password_env": ((inv.afm or {}).get("auth") or {}).get("password_env") or "HELIOS_AFM_PASSWORD"})
        return out

    def inventory(self, name: str):
        if not NAME_RX.match(name or "") or not name.endswith(".yaml"):
            raise BadRequest("unknown inventory")
        f = self.inventory_dir / name
        if not f.is_file():
            raise BadRequest(f"no inventory {name}")
        return f, load_inventory(f)

    def results(self, limit: int = 200) -> list[dict]:
        base = self.results_dir / "link-check"
        rows = []
        for d in base.glob("*/*"):
            if not d.is_dir():
                continue
            files = {p.name for p in d.iterdir() if p.is_file()}
            tool = d.name.split("-", 1)[0] if d.name.split("-", 1)[0] in TOOLS else "path"
            summary = ""
            for name in ("report.txt", "bcm.txt"):
                if name in files:
                    try:
                        lines = (d / name).read_text(errors="replace").splitlines()
                        summary = next((ln for ln in lines if re.search(r"GPU links:|<->|links? (checked|ok)|fail|ok\b", ln)),
                                       lines[0] if lines else "")[:200]
                    except OSError:
                        pass
                    break
            rows.append({"rack": d.parent.name, "name": d.name, "tool": tool, "mtime": d.stat().st_mtime,
                         "files": sorted(f for f in files if f.endswith((".html", ".txt", ".json"))),
                         "path": f"link-check/{d.parent.name}/{d.name}", "summary": summary})
        return sorted(rows, key=lambda r: -r["mtime"])[:limit]


# ------------------------------------------------------------------ building a tool command

def _names(value, allowed: list[str], what: str) -> str | None:
    if not value:
        return None
    vals = value if isinstance(value, list) else [v for v in str(value).split(",") if v]
    bad = [v for v in vals if v not in allowed]
    if bad:
        raise BadRequest(f"unknown {what}: {', '.join(map(str, bad))} (inventory has {', '.join(allowed)})")
    return ",".join(vals)


def _int(d: dict, key: str, lo: int, hi: int, default: int) -> int:
    v = d.get(key, default)
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise BadRequest(f"{key} must be a number") from None
    if not lo <= v <= hi:
        raise BadRequest(f"{key} must be {lo}..{hi}")
    return v


def build_args(state: State, req: dict) -> tuple[list[str], Path, str]:
    """(argv after the tool, output folder, rack) for a run request; every value checked."""
    tool = req.get("tool")
    if tool not in TOOLS:
        raise BadRequest(f"tool must be one of {', '.join(TOOLS)}")
    f, inv = state.inventory(req.get("inventory", ""))
    sws, cts = [h.name for h in inv.switches], [h.name for h in inv.computes]
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rack = inv.rack or f.stem
    out = state.results_dir / "link-check" / rack / f"{tool}-{stamp}"
    a = [tool, "--inventory", str(f), "--out", str(out)]
    if tool in ("scan", "pingmap"):
        s = _names(req.get("switches"), sws, "switch")
        t = _names(req.get("trays"), cts, "compute tray")
        a += (["--switches", s] if s else []) + (["--trays", t] if t else [])
    if tool == "scan":
        a += ["--interval", str(_int(req, "interval", 0, 600, 30))]
        if req.get("no_bcm"):
            a.append("--no-bcm")
        else:
            a += ["--bcm-max", str(_int(req, "bcm_max", 1, 512, 64))]
        if not req.get("afm"):
            a.append("--no-afm")
        cmp_ = req.get("compare")
        if cmp_:
            p = _result_file(state, f"{cmp_}/link_check.json")
            a += ["--compare", str(p)]
    elif tool == "link":
        target = " ".join(str(req.get("target") or "").split())
        if not TARGET_RX.match(target):
            raise BadRequest("link: give a switch port (st6 Ethernet257), a GPU port (ct13 0002:01:00.1 33), "
                             "slot17/gpu3/port33 or an AFM event (acc-id: 5, port-id: 32)")
        a.insert(1, target)
        a += ["--interval", str(_int(req, "interval", 0, 120, 10))]
        if req.get("no_bcm"):
            a.append("--no-bcm")
        if not req.get("afm"):
            a.append("--no-afm")
    elif tool == "pingmap":
        a += ["--rounds", str(_int(req, "rounds", 1, 100, 3)), "--wait", str(_int(req, "wait", 0, 3600, 60))]
    elif tool == "bcm":
        s = _names(req.get("switches"), sws, "switch")
        if s:
            a += ["--switch", s]
        ports = (req.get("ports") or "").replace(" ", "")
        if ports:
            if not PORTS_RX.match(ports):
                raise BadRequest("ports: Ethernet<N>[,Ethernet<N>...]")
            a += ["--ports", ports]
        if req.get("all"):
            a.append("--all")
    elif tool == "path":
        src = _names(req.get("src"), cts, "compute tray")
        if not src or "," in src:
            raise BadRequest("path needs one source tray")
        bdf = req.get("src_bdf") or ""
        if not BDF_RX.match(bdf):
            raise BadRequest("source GPU BDF like 0004:01:00.1")
        a += ["--src", src, "--src-bdf", bdf]
        dst = _names(req.get("dst"), cts, "compute tray")
        if dst:
            if "," in dst:
                raise BadRequest("one destination tray")
            a += ["--dst", dst]
        if req.get("dst_bdf"):
            if not BDF_RX.match(req["dst_bdf"]):
                raise BadRequest("destination GPU BDF like 0004:01:00.1")
            a += ["--dst-bdf", req["dst_bdf"]]
        elif req.get("dst_acc") not in (None, ""):
            a += ["--dst-acc", str(_int(req, "dst_acc", 0, 4095, 0))]
        else:
            raise BadRequest("path needs the destination GPU (BDF or accelerator id)")
        ports = (req.get("ports") or "").replace(" ", "")
        if ports:
            if not GPU_PORTS_RX.match(ports):
                raise BadRequest("GPU ports like 25,26")
            a += ["--ports", ports]
        a += ["--count", str(_int(req, "count", 1, 100, 1))]
        if req.get("no_ping"):
            a.append("--no-ping")
    return a, out, rack


def _result_file(state: State, rel: str) -> Path:
    base = (state.results_dir).resolve()
    p = (base / unquote(rel)).resolve()
    if base not in p.parents or not p.is_file():
        raise BadRequest("no such result file")
    return p


LINK_KEYS = ("switch", "asic", "sw_port", "desc", "sw_oper", "sw_admin", "tray", "bdf", "gpu_port", "state", "kind",
             "cause", "owner", "action", "afm_port", "matched_by")


def scan_view(state: State, rel: str) -> dict:
    """A scan's links, compact, for the rack map (rel: link-check/<rack>/scan-...)."""
    f = _result_file(state, f"{rel}/link_check.json")
    d = json.loads(f.read_text())
    links = [{k: ln.get(k) for k in LINK_KEYS} | {"evidence": (ln.get("evidence") or [])[:8]} for ln in d.get("links") or []]
    return {"path": rel, "time_utc": d.get("time_utc"), "rack": d.get("rack"), "links": links, "gpus": d.get("gpus") or [],
            "afm_view": (d.get("learned") or {}).get("afm_view"), "patterns": d.get("patterns") or [],
            "slots": (d.get("learned") or {}).get("slots") or {}}


# ------------------------------------------------------------------ jobs

def start_job(state: State, req: dict) -> dict:
    args, out, rack = build_args(state, req)
    with state.lock:
        if state.current and state.jobs[state.current]["status"] == "running":
            raise BadRequest(f"a {state.jobs[state.current]['tool']} run is already running - wait for it or stop it")
        jid = uuid.uuid4().hex[:12]
        env = dict(os.environ)
        if req.get("tool") in ("scan", "link") and req.get("afm") and req.get("afm_password"):
            _f, inv = state.inventory(req["inventory"])
            env[((inv.afm or {}).get("auth") or {}).get("password_env") or "HELIOS_AFM_PASSWORD"] = str(req["afm_password"])
        job = {"id": jid, "tool": req["tool"], "rack": rack, "inventory": req["inventory"], "argv": args,
               "out": str(out.relative_to(state.results_dir)), "status": "running", "rc": None,
               "started": time.time(), "ended": None, "log": "", "proc": None}
        (state.results_dir / "ui-jobs").mkdir(parents=True, exist_ok=True)
        logf = open(state.results_dir / "ui-jobs" / f"{jid}.log", "w")
        logf.write("$ link_check.py " + " ".join(args) + "\n")
        logf.flush()
        proc = subprocess.Popen([sys.executable, "-u", str(TOOL), *args], cwd=str(ROOT), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                start_new_session=True)
        env = None                       # the password is in the child's environment only
        job["proc"] = proc
        state.jobs[jid] = job
        state.current = jid

    def pump():
        for line in proc.stdout:
            logf.write(line)
            logf.flush()
            with state.lock:
                job["log"] = (job["log"] + line)[-LOG_KEEP:]
        rc = proc.wait()
        logf.close()
        with state.lock:
            job["rc"], job["ended"] = rc, time.time()
            if job["status"] == "running":
                job["status"] = {0: "ok", 1: "problems found", 2: "incomplete"}.get(rc, f"failed (rc {rc})")
    threading.Thread(target=pump, daemon=True).start()
    return public(job)


def stop_job(state: State, jid: str) -> dict:
    with state.lock:
        job = state.jobs.get(jid)
        if not job:
            raise BadRequest("no such job")
        if job["status"] == "running" and job["proc"]:
            try:
                os.killpg(job["proc"].pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            job["status"] = "stopped"
        return public(job)


def public(job: dict, since: int = 0) -> dict:
    j = {k: v for k, v in job.items() if k not in ("proc", "log")}
    j["log"] = job["log"][since:] if since < len(job["log"]) else ""
    j["log_len"] = len(job["log"])
    return j


# ------------------------------------------------------------------ HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "helios-debug-ui"
    state: State = None  # set by serve()

    def log_message(self, fmt, *args):  # quiet: one line per request on stderr only for errors
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") \
            else (self.headers.get("Host") or "").split("]")[0] + "]"
        return host in LOCAL_HOSTS

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, b"forbidden host", "text/plain")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        st = self.state
        try:
            if u.path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                              "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
            if u.path == "/api/state":
                with st.lock:
                    cur = public(st.jobs[st.current]) if st.current else None
                    recent = [public(j) | {"log": ""} for j in sorted(st.jobs.values(), key=lambda x: -x["started"])][:20]
                return self._json(200, {"inventories": st.inventories(), "current": cur, "jobs": recent,
                                        "host": os.uname().nodename})
            if u.path.startswith("/api/job/"):
                jid = u.path.rsplit("/", 1)[1]
                with st.lock:
                    job = st.jobs.get(jid)
                    if not job:
                        return self._json(404, {"error": "no such job"})
                    return self._json(200, public(job, int((q.get("since") or ["0"])[0] or 0)))
            if u.path == "/api/access":
                _f, inv = st.inventory((q.get("inventory") or [""])[0])
                return self._json(200, access.describe(inv))
            if u.path == "/api/scan":
                return self._json(200, scan_view(st, (q.get("path") or [""])[0]))
            if u.path == "/api/results":
                return self._json(200, {"results": st.results()})
            if u.path.startswith("/results/"):
                p = _result_file(st, u.path[len("/results/"):])
                ctype = mimetypes.guess_type(p.name)[0] or "text/plain"
                if ctype.startswith("text/") or ctype == "application/json":
                    ctype += "; charset=utf-8"
                extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src "
                                                    "'unsafe-inline'; img-src data:; frame-ancestors 'none'"}
                return self._send(200, p.read_bytes(), ctype, extra)
            return self._json(404, {"error": "not found"})
        except BadRequest as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {str(e)[:300]}"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, b"forbidden host", "text/plain")
        if self.headers.get("X-Helios-Debug") != "1" or "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._json(403, {"error": "missing X-Helios-Debug header / JSON body"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64_000:
                raise BadRequest("request too large")
            req = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(req, dict):
                raise BadRequest("JSON object expected")
            u = urlparse(self.path)
            if u.path == "/api/run":
                return self._json(200, start_job(self.state, req))
            if u.path in ("/api/access/check", "/api/access/install"):
                _f, inv = self.state.inventory(req.get("inventory", ""))
                if u.path.endswith("check"):
                    names = req.get("hosts") or None
                    return self._json(200, {"results": access.check(inv, names if isinstance(names, list) else None)})
                pw = req.pop("password", None)
                return self._json(200, access.install(inv, str(req.get("host", "")), str(pw or "")))
            if u.path == "/api/access/keygen":
                return self._json(200, access.create_key())
            m = re.fullmatch(r"/api/job/([0-9a-f]{12})/stop", u.path)
            if m:
                return self._json(200, stop_job(self.state, m.group(1)))
            return self._json(404, {"error": "not found"})
        except (BadRequest, access.AccessError) as e:
            return self._json(400, {"error": str(e)})
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad JSON"})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {str(e)[:300]}"})


def make_server(port: int, inventory_dir: Path, results_dir: Path, bind: str = "127.0.0.1") -> ThreadingHTTPServer:
    if bind not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit("the debug UI listens on localhost only; reach it through an SSH tunnel")
    Handler.state = State(inventory_dir, results_dir)
    return ThreadingHTTPServer((bind, port), Handler)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=int(os.environ.get("HELIOS_DEBUG_UI_PORT", 8780)))
    ap.add_argument("--inventory-dir", type=Path, default=Path(os.environ.get("HELIOS_DEBUG_INVENTORY_DIR", ROOT / "inventory")))
    ap.add_argument("--results-dir", type=Path, default=Path(os.environ.get("HELIOS_DEBUG_RESULTS_DIR", ROOT / "results")))
    a = ap.parse_args(argv)
    a.results_dir.mkdir(parents=True, exist_ok=True)
    srv = make_server(a.port, a.inventory_dir.expanduser(), a.results_dir.expanduser())
    print(f"helios-debug UI on http://127.0.0.1:{a.port}  (inventories: {a.inventory_dir}, results: {a.results_dir})")
    print(f"from your machine: ssh -L {a.port}:localhost:{a.port} <user>@{os.uname().nodename}  then http://localhost:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
