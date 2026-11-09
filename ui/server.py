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
import shutil
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

from heliosdbg import linkdiag  # noqa: E402
from heliosdbg.inventory import load_inventory  # noqa: E402
from heliosdbg.transport import is_local  # noqa: E402
from heliosdbg.term import TermError  # noqa: E402
from ui import access  # noqa: E402

TOOL = ROOT / "tools" / "link_check.py"
STATIC = Path(__file__).resolve().parent / "static"
# The page is read once, when the server starts: page and server code always match. (19 Oct: a server started before
# the Diagnose tab served the new page from disk and refused its 'link' runs - restart to get a newer UI.)
PAGE = (STATIC / "index.html").read_bytes()
VENDOR = {n: (t, (STATIC / "vendor" / n).read_bytes()) for n, t in (            # served as-is, a fixed list
    ("xterm/xterm.js", "text/javascript; charset=utf-8"), ("xterm/addon-fit.js", "text/javascript; charset=utf-8"),
    ("xterm/xterm.css", "text/css; charset=utf-8")) if (STATIC / "vendor" / n).is_file()}
TOOLS = ("scan", "link", "watch", "cabling", "isolate", "bcm", "path", "pingmap", "health", "fecwatch")
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
        self.access_checks: dict[str, dict] = {}     # inventory file -> {time, results} of its last access check
        self.live = None                               # heliosdbg.live.LiveRack of the one rack in live mode
        self.live_inventory = None
        self.live_starting = False
        self.live_view = 0.0                           # last time a page asked for the live state
        self.logins: dict = {}                         # {rack: the last login check's refused / unreachable nodes}
        self.current: str | None = None
        from heliosdbg.term import Terminals
        self.terms = Terminals(results_dir / "term")      # browser terminals (Access to the rack)

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
                        "quarantined": inv.quarantine_summary(),
                        "local": [h.name for h in inv.switches + inv.computes if is_local(h)],
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
            if not d.is_dir() or d.name.startswith("."):
                continue
            try:
                files = {p.name for p in d.iterdir() if p.is_file()}
                mtime = d.stat().st_mtime
            except OSError:                       # removed while listing (a newer check replaced it)
                continue
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
            rows.append({"rack": d.parent.name, "name": d.name, "tool": tool, "mtime": mtime,
                         "files": sorted(f for f in files if f.endswith((".html", ".txt", ".json"))),
                         "path": f"link-check/{d.parent.name}/{d.name}", "summary": summary,
                         "unsaved": (d / UNSAVED).exists()})
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


DISK_LOW_MB = 300                   # the UI says so (a shared /home: the g02-g17 jump host filled up four times, Oct-Nov)
DISK_STOP_MB = 50                   # ... and starts no check: a check on a full disk dies half-written (18 Oct: at mkdir)


def disk_info(state: State) -> dict:
    """The free space where the checks write their results."""
    p = state.results_dir
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        u = shutil.disk_usage(p)
    except OSError:
        return {}
    free = u.free // 1_000_000
    return {"free_mb": free, "total_mb": u.total // 1_000_000, "low": free < DISK_LOW_MB, "path": str(p)}


def build_args(state: State, req: dict) -> tuple[list[str], Path, str]:
    """(argv after the tool, output folder, rack) for a run request; every value checked."""
    tool = req.get("tool")
    if tool not in TOOLS:
        raise BadRequest(f"tool must be one of {', '.join(TOOLS)}")
    d = disk_info(state)
    if d and d["free_mb"] < DISK_STOP_MB:
        raise BadRequest(f"only {d['free_mb']} MB free on this machine ({d['path']}) - a check would stop half-written; "
                         "free some space first")
    f, inv = state.inventory(req.get("inventory", ""))
    sws, cts = [h.name for h in inv.switches], [h.name for h in inv.computes]
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rack = inv.rack or f.stem
    out = state.results_dir / "link-check" / rack / f"{tool}-{stamp}"
    a = [tool, "--inventory", str(f), "--out", str(out)]
    if tool in ("scan", "pingmap", "health", "fecwatch"):
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
    elif tool == "fecwatch":
        a += ["--minutes", str(_int(req, "minutes", 1, 120, 10))]
        if req.get("no_trays"):
            a.append("--no-trays")
    elif tool == "link":
        target = " ".join(str(req.get("target") or "").split())
        if not TARGET_RX.match(target):
            raise BadRequest("link: give a switch port (st6 Ethernet257), a GPU port (ct13 0002:01:00.1 33), "
                             "slot17/gpu3/port33 or an AFM event (acc-id: 5, port-id: 32)")
        a.insert(1, target)
        a += ["--interval", str(_int(req, "interval", 0, 120, 10)), "--hours", str(_int(req, "hours", 1, 720, 24))]
        if req.get("no_bcm"):
            a.append("--no-bcm")
        if req.get("no_timeline"):
            a.append("--no-timeline")
        if not req.get("afm"):
            a.append("--no-afm")
    elif tool == "watch":
        raw = req.get("targets") or ""
        targets = [" ".join(x.split()) for x in (raw if isinstance(raw, list) else str(raw).replace("\n", ";").split(";")) if x.strip()]
        if not targets or len(targets) > 64 or not all(TARGET_RX.match(x) for x in targets):
            raise BadRequest("watch: 1 to 64 links, one per line (st6 Ethernet257, ct13 0002:01:00.1 33, ...)")
        a[1:1] = targets
        a += ["--every", str(_int(req, "every", 2, 3600, 10)), "--duration", str(_int(req, "duration", 10, 86400, 600))]
    elif tool == "isolate":
        target = " ".join(str(req.get("target") or "").split())
        if not TARGET_RX.match(target):
            raise BadRequest("isolate: the link (st6 Ethernet257, ct13 0002:01:00.1 33, ...)")
        if " ".join(str(req.get("confirm") or "").split()) != target:
            raise BadRequest("isolate takes the link down: type the link exactly as above to confirm")
        if req.get("action") not in ("switch-flap", "gpu-flap"):
            raise BadRequest("action: switch-flap or gpu-flap")
        a.insert(1, target)
        a += ["--action", req["action"], "--hold", str(_int(req, "hold", 1, 300, 10)), "--yes-disruptive"]
    elif tool == "cabling":
        plan = str(req.get("plan") or "")
        if not plan.strip() or len(plan) > 2_000_000:
            raise BadRequest("cabling: paste the plan CSV (switch,port,slot,gpu,gpu_port)")
        d = state.results_dir / "ui-jobs"
        d.mkdir(parents=True, exist_ok=True)
        pf = d / f"plan-{stamp}-{uuid.uuid4().hex[:6]}.csv"
        pf.write_text(plan)
        a += ["--plan", str(pf)]
    elif tool == "health":
        if req.get("only") in ("switches", "trays"):
            a += ["--only", req["only"]]
        if req.get("no_drift"):
            a.append("--no-drift")
        if not req.get("afm"):
            a.append("--no-afm")
        if req.get("no_bmc"):
            a.append("--no-bmc")
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


def _result_dir(state: State, rel: str) -> Path:
    base = state.results_dir.resolve()
    p = (base / unquote(rel)).resolve()
    if base not in p.parents or not p.is_dir() or p.parent.parent.name != "link-check":
        raise BadRequest("no such run")
    return p


def _gz_json(path):
    import gzip
    with gzip.open(path, "rt") as f:
        return json.load(f)


def _result_file(state: State, rel: str) -> Path:
    base = (state.results_dir).resolve()
    p = (base / unquote(rel)).resolve()
    if base not in p.parents or not p.is_file():
        raise BadRequest("no such result file")
    return p


LINK_KEYS = ("switch", "asic", "sw_port", "desc", "sw_oper", "sw_admin", "tray", "bdf", "gpu_port", "state", "kind",
             "cause", "owner", "action", "afm_port", "matched_by", "vlans", "mtu", "flap_count", "last_down_time")


def overview(state: State) -> list[dict]:
    """Every inventory's rack with its latest scan's counts (and the one before, for what changed)."""
    out = []
    for i in state.inventories():
        if i.get("error"):
            out.append({"file": i["file"], "error": i["error"]})
            continue
        runs = sorted((state.results_dir / "link-check" / i["rack"]).glob("scan-*/link_check.json"), reverse=True)
        row = {"file": i["file"], "rack": i["rack"], "switches": len(i["switches"]), "computes": len(i["computes"]), "scans": len(runs)}
        if runs:
            try:
                d = json.loads(runs[0].read_text())
                c = {k: sum(1 for x in d.get("links") or [] if x.get("state") == k) for k in ("ok", "degraded", "down")}
                sc = d.get("scope") or {}
                part = ", ".join(x for x in (sc.get("switches"), sc.get("trays")) if x)
                if not sc and len(d.get("links") or []) and not part:   # older scans: no scope recorded
                    trays = {x.get("tray") for x in d.get("links") or [] if x.get("tray")}
                    part = ", ".join(sorted(trays)) if trays and len(trays) < len(i["computes"]) else ""
                row |= {"latest": f"link-check/{i['rack']}/{runs[0].parent.name}", "time_utc": d.get("time_utc"), **c,
                        "only": part,
                        "links": len(d.get("links") or []), "gpus_not_right": len(d.get("gpus") or [])}
            except (OSError, ValueError) as e:
                row["error"] = f"latest scan unreadable: {e}"
            row |= latest_full(i["rack"], runs, len(i["computes"]))
        out.append(row)
    return out


def latest_full(rack: str, runs: list, computes: int = 0) -> dict:
    """The newest scan of the whole rack that checked links (the Topology picture is drawn from it) and, when newer
    scans are partial (--switches / --trays) or checked no link, the newest of those with what it reported."""
    out, newer = {}, None
    for f in runs[:60]:
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        sc = d.get("scope") or {}
        partial = bool(sc.get("switches") or sc.get("trays"))
        if not d.get("scope") and d.get("links") and computes:    # older scans: no scope recorded
            trays = {x.get("tray") for x in d["links"] if x.get("tray")}
            partial = bool(trays) and len(trays) < computes - 1   # (one quarantined / unreadable tray is still full)
        if not partial and d.get("links"):
            out["latest_full"] = f"link-check/{rack}/{f.parent.name}"
            break
        if newer is None:
            newer = {"path": f"link-check/{rack}/{f.parent.name}", "time_utc": d.get("time_utc"),
                     "only": ", ".join(x for x in (sc.get("switches"), sc.get("trays")) if x),
                     "links": len(d.get("links") or []), "fdb_broken": d.get("fdb_broken") or [],
                     "not_checked": [{"node": x.get("node"), "role": x.get("role"), "error": str(x.get("error"))[:300]}
                                     for x in d.get("not_checked") or []][:6]}
    if newer and out.get("latest_full"):
        out["newer_partial"] = newer
    return out


def gpus_view(state: State, inventory: str) -> dict:
    """Every GPU of every tray as the rack's latest check read it (no login): accelerator, config phase, the GPU ports
    that were up - for choosing a GPU-to-GPU path."""
    import gzip
    f, inv = state.inventory(inventory)
    from heliosdbg import scans
    rd = state.results_dir / "link-check" / (inv.rack or f.stem)
    _d, folder = scans.newest(rd, need="raw/trays.json.gz")       # a check with links first; else any with trays read
    if folder is None:
        _d, folder = scans.newest(rd, need="raw/trays.json.gz", links=False)
    runs = [folder / "raw" / "trays.json.gz"] if folder else []
    if not runs:
        raise BadRequest("no check of this rack with links yet - run one first (Check all links)")
    try:
        trays = _gz_json(runs[0])
    except (OSError, ValueError, EOFError) as e:      # truncated copy (full disk): say so instead of a 500
        raise BadRequest(f"the latest check's tray data is unreadable ({type(e).__name__}) - run Check all links again") from None
    d = json.loads((runs[0].parent.parent / "link_check.json").read_text()) if (runs[0].parent.parent / "link_check.json").is_file() else {}
    slots = (d.get("learned") or {}).get("slots") or {}
    out = {}
    for name, t in sorted(trays.items()):
        out[name] = {"slot": slots.get(name), "error": t.get("error"),
                     "gpus": [{"bdf": g.get("bdf"), "accelerator": g.get("accelerator"), "phase": g.get("config_phase"),
                               "up": [p_["port"] for p_ in g.get("ports") or []
                                      if str(p_.get("link")).upper() == "LINK_UP" and str(p_.get("admin", "")).startswith("enable")]}
                              for g in t.get("gpus") or []]}
    return {"time_utc": d.get("time_utc") or runs[0].parent.parent.name.split("-", 1)[-1], "trays": out}


def port_view(state: State, rel: str, key: str) -> dict:
    """Everything a check saved about ONE link (no login): the link, both ends' raw records, and its state in the
    rack's earlier checks."""
    import gzip
    run = _result_dir(state, rel)
    d = json.loads((run / "link_check.json").read_text())
    ln = next((x for x in d.get("links") or [] if f"{x.get('switch')} {x.get('sw_port')}" == key), None)
    if ln is None:
        raise BadRequest(f"no link {key} in that check")
    out = {"link": ln, "time_utc": d.get("time_utc"), "switch": None, "gpu": None, "gpu_device": None, "history": []}
    try:
        sw = _gz_json(run / "raw" / "switches.json.gz").get(ln["switch"]) or {}
        a = (sw.get("asics") or {}).get(ln.get("asic") or "") or {}
        port = ln["sw_port"]
        out["switch"] = {"status": (a.get("status") or {}).get(port), "counters": (a.get("counters") or {}).get(port),
                         "fec": (a.get("fec") or {}).get(port), "presence": (a.get("presence") or {}).get(port),
                         "fdb": [r for r in a.get("fdb") or [] if r.get("Port") == port]}
    except (OSError, ValueError, EOFError):
        pass
    try:
        if ln.get("tray") and ln.get("bdf"):
            tr = _gz_json(run / "raw" / "trays.json.gz").get(ln["tray"]) or {}
            g = next((x for x in tr.get("gpus") or [] if x.get("bdf") == ln["bdf"]), None)
            if g:
                out["gpu_device"] = {k: g.get(k) for k in ("bdf", "accelerator", "config_phase", "vpod_accelerators")}
                out["gpu"] = next((p_ for p_ in g.get("ports") or [] if p_.get("port") == ln.get("gpu_port")), None)
    except (OSError, ValueError, EOFError):
        pass
    if out["switch"] is None or out["gpu"] is None:   # saved from Live: no raw files, the ends are in Live's reading
        from heliosdbg.live import as_read
        r = as_read(ln)
        if r is not ln:
            out["live_read"] = {"sw_oper": r.get("sw_oper"), "sw_admin": r.get("sw_admin"), "gpu_link": r.get("gpu_link"),
                                "time": (str((ln.get("evidence") or [""])[0]).split(": ", 1)[0].replace("Live ", ""))}
    now = _live_now(state, run.parent.name, key)       # Live running: the ends as it reads them now (mr2 9 Nov:
    if now and now.get("read"):                       # 'GPU end not read' beside 'Live now: down')
        out["live_read"] = {"sw_oper": now.get("sw_oper"), "sw_admin": now.get("sw_admin"), "gpu_link": now.get("gpu_link"),
                            "time": "now"}
    for f in sorted(run.parent.glob("scan-*/link_check.json"), reverse=True)[:12]:
        try:
            e = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        x = next((y for y in e.get("links") or [] if f"{y.get('switch')} {y.get('sw_port')}" == key), None)
        out["history"].append({"time_utc": e.get("time_utc"), "path": f"link-check/{run.parent.name}/{f.parent.name}",
                               "state": x.get("state") if x else None, "kind": x.get("kind") if x else None})
    return out


QUARANTINED_RX = re.compile(r"compute tray (\S+) is quarantined")
DESC_SLOT_RX = re.compile(r"Slot(\d+)/GPU", re.I)


def name_unread_trays(links: list, slots: dict) -> None:
    """Links of a tray the check did not read (quarantined) carry no tray name - the map showed them as '?'
    (g02-g17 ct05, 144 links). Name the tray from the cause, else from the slot in the switch port description."""
    by_slot = {str(v): k for k, v in slots.items()}
    for ln in links:
        if ln.get("tray"):
            continue
        m, s = QUARANTINED_RX.search(ln.get("cause") or ""), DESC_SLOT_RX.search(ln.get("desc") or "")
        name = m.group(1) if m else by_slot.get(s.group(1)) if s else None
        if name:
            ln["tray"], ln["tray_named_from"] = name, "switch port description"
            if s and name not in slots:
                slots[name] = int(s.group(1))


AFM_NAME_ID_RX = re.compile(r"^pod-\d+-(\d+)-")
TRAY_NUM_RX = re.compile(r"^[a-z]+0*(\d+)$", re.I)


def _rack_inventory(state: State, rack: str | None):
    for f in sorted(state.inventory_dir.glob("*.yaml")):
        try:
            inv = load_inventory(f)
        except Exception:  # noqa: BLE001 - a broken inventory is listed with its error elsewhere
            continue
        if (inv.rack or f.stem) == rack:
            return inv
    return None


AFM_POD_RX = re.compile(r"^(pod-\d+)-\d+-")


def afm_names(state: State, rack: str | None, slots: dict, switch_ids: dict) -> dict[str, str]:
    """{tray name: AFM node name} - what AFM shows: pod-1-0-SwitchTray, pod-1-0-ComputeTray. The inventory's
    afm_name wins; else pod-<n>-<AFM id>-<kind> with the pod taken from any afm_name in the inventory (pod-1 if none)."""
    inv = _rack_inventory(state, rack)
    hosts = (inv.all_switches + inv.computes + [h for h in inv.quarantined if h.role == "compute"]) if inv else []
    given = {h.name: str(h.extra["afm_name"]) for h in hosts if h.extra.get("afm_name")}
    pod = next((m.group(1) for m in map(AFM_POD_RX.match, given.values()) if m), "pod-1")
    out = {n: f"{pod}-{i}-SwitchTray" for n, i in switch_ids.items()}
    out |= {n: f"{pod}-{sl}-ComputeTray" for n, sl in slots.items() if sl is not None}
    return out | given


def ifcp_cabling(links: list, trays: dict, ifcp: dict) -> dict:
    """Is each cable where AFM says? A GPU port's IFCP session names the switch device / port at the other end of
    its real cable (peer_device_id / peer_port_id); compared with the switch port of the link (description +
    forwarding entry). Sets link['cable'] = confirmed / miscabled; returns the counts."""
    dev = {str(v): k for k, v in ((ifcp or {}).get("device") or {}).items()}
    by_port = {(tn, g.get("bdf"), p.get("port")): (p.get("ifcp") or {}) for tn, t in (trays or {}).items()
               for g in (t or {}).get("gpus") or [] for p in g.get("ports") or []}
    n = {"confirmed": 0, "miscabled": 0, "unconfirmed": 0, "examples": []}
    for ln in links:                                  # the GPU port's IFCP state, for the Topology IFCP view
        i = by_port.get((ln.get("tray"), ln.get("bdf"), ln.get("gpu_port")))
        if i:
            ln["ifcp"] = {"ll": i.get("ll_up"), "pe": i.get("peer_enabled"),
                          "err": "yes" in (str(i.get("in_error")).lower(), str(i.get("peer_in_error")).lower())}
    if not dev or not (ifcp or {}).get("port_is_ethernet"):
        n["unconfirmed"] = len(links)
        return n
    for ln in links:
        i = by_port.get((ln.get("tray"), ln.get("bdf"), ln.get("gpu_port"))) or {}
        if i.get("peer_device_id") in (None, "") or i.get("peer_port_id") in (None, "") or not ln.get("bdf") \
                or str(i["peer_device_id"]) not in dev:
            # no peer, or a device id this check could not name (e.g. a switch whose links were matched by
            # description only): not a verdict either way
            n["unconfirmed"] += 1
            continue
        peer = (dev.get(str(i["peer_device_id"])) or f"device {i['peer_device_id']}", f"Ethernet{i.get('peer_port_id')}")
        if peer == (ln.get("switch"), ln.get("sw_port")) and ln.get("kind") == "miscabled":
            # the IFCP peer confirms this switch end, but the GPU port at the far end is not the one the description
            # names (linkdiag.mark_described_elsewhere): the cable is not where the cabling plan says
            ln["cable"] = (f"miscabled: the cable of this switch port reaches {ln.get('tray')} {ln.get('bdf')} port "
                           f"{ln.get('gpu_port')} (its IFCP peer is this switch port), not the GPU port the description names")
            n["miscabled"] += 1
            if len(n["examples"]) < 20:
                n["examples"].append(f"{ln.get('switch')} {ln.get('sw_port')}: reaches {ln.get('tray')} {ln.get('bdf')} "
                                     f"port {ln.get('gpu_port')}, described as '{ln.get('desc')}'")
        elif peer == (ln.get("switch"), ln.get("sw_port")):
            ln["cable"] = "confirmed"
            n["confirmed"] += 1
        else:
            ln["cable"] = "miscabled: the cable reaches " + " ".join(peer)
            n["miscabled"] += 1
            if len(n["examples"]) < 20:
                n["examples"].append(f"{ln.get('switch')} {ln.get('sw_port')}: reaches {' '.join(peer)}")
    return n


def afm_switch_ids(state: State, rack: str | None) -> dict[str, int]:
    """{switch name: AFM SwitchTray id} for the rack's inventory. AFM numbers from 0 (pod-1-0-SwitchTray), the rack
    names from 1 (st1): the inventory's slot: or afm_name wins, else st<n> = n-1, else the order in the inventory."""
    inv = _rack_inventory(state, rack)
    if inv:
        out = {}
        for i, h in enumerate(inv.all_switches):
            m, n = AFM_NAME_ID_RX.match(str(h.extra.get("afm_name") or "")), TRAY_NUM_RX.match(h.name)
            if str(h.extra.get("slot", "")).isdigit():
                out[h.name] = int(h.extra["slot"])
            elif m:
                out[h.name] = int(m.group(1))
            else:
                out[h.name] = int(n.group(1)) - 1 if n and int(n.group(1)) > 0 else i
        return out
    return {}


def ai_ask(state: State, req: dict) -> dict:
    """Ask the AI about a check (path = link-check/<rack>/scan-...), one link of it (+ link = 'st6 Ethernet170') or a
    Diagnose result (path = link-check/<rack>/link-...). The evidence is built from the saved result, not the rack."""
    from heliosdbg import ai
    q, hist = str(req.get("question") or "")[:2000], req.get("history") or []
    if not isinstance(hist, list):
        raise BadRequest("history: a list of {q, a}")
    ev, subject, rack = _ai_subject(state, req, past=True)
    from heliosdbg import guide
    guide.steps_evidence(ev, [x for x in (req.get("steps") or []) if isinstance(x, dict)][:24])
    if ai.generic_howto(q):                  # a how-to about a kind of problem: the debug guide, not this problem's cause
        from heliosdbg import docsearch
        docs = docsearch.load()
        for d in (docs.search(q, k=5) if docs is not None else []):
            ev.add_doc(d)
        ev.howto = True
    try:
        out = ai.ask(ev, subject, q, hist)
    except ai.AIError as e:
        raise BadRequest(str(e)) from None
    if rack:                                 # the commands it suggests, checked like steps: Run from the answer
        try:
            _inv, roles = _rack_nodes(state, rack)
            ctx_text = "\n".join(x["text"] for x in ev.items) + "\n" + "\n".join(
                str(x.get("output") or "") for x in (req.get("steps") or []) if isinstance(x, dict))
            out["runnable"] = guide.runnable(out.get("answer") or "", roles, _rack_aliases(state, rack), ctx_text)
        except BadRequest:
            out["runnable"] = []
    return out


def _rack_aliases(state: State, rack: str) -> dict:
    """{AFM name: tray} from the rack's newest check (answers name pod-1-0-ComputeTray as often as c1)."""
    runs = sorted((state.results_dir / "link-check" / rack).glob("scan-*/link_check.json"), reverse=True)
    for f in runs[:1]:
        try:
            return {v: k for k, v in (scan_view(state, str(f.parent.relative_to(state.results_dir))).get("afm_names") or {}).items()}
        except Exception:  # noqa: BLE001 - without them only the inventory names are recognised
            return {}
    return {}


def _ai_subject(state: State, req: dict, past: bool = False):
    """(evidence, subject, rack) for a request naming a check / a link of it / a Diagnose result (+ past=True: the
    most similar resolutions people recorded)."""
    from heliosdbg import ai, cases
    spec = cases.spec_of(req)
    if spec is not None:                 # any problem: a tool report, a helios-tests result, outputs collected by hand
        try:
            ev, subject, rack = cases.context(spec, state.results_dir)
        except ai.AIError as e:
            raise BadRequest(str(e)) from None
        if past and rack:
            add_past_resolutions(state, ev, rack, "", str(req.get("question") or "") + " " + " ".join(x["text"] for x in ev.items[:8]))
        return ev, subject, rack
    rel = str(req.get("path") or "").strip("/")
    if not re.fullmatch(r"link-check/[A-Za-z0-9_.-]+/(?:scan-[0-9]{8}-[0-9]{6}(?:-live)?|link-[0-9]{8}-[0-9]{6})", rel):   # -live: saved from Live
        raise BadRequest("path: a saved result (link-check/<rack>/<tool>-...), test {run, tc_id}, or blocks [{node, command, output}]")
    rack = rel.split("/")[1]
    try:
        if "/link-" in rel:
            ev, subject = ai.diagnose_context(json.loads(_result_file(state, f"{rel}/link.json").read_text()))
        else:
            scan = scan_view(state, rel)
            link = str(req.get("link") or "").strip()
            ev, subject = ai.link_context(scan, link, _live_now(state, rack, link)) if link else ai.check_context(
                scan, *ai.focus_of(scan, str(req.get("question") or ""), _focus(req)))
    except ai.AIError as e:
        raise BadRequest(str(e)) from None
    if past:
        lk = str(req.get("link") or "").strip() or (subject[5:] if subject.startswith("link ") else "")
        add_past_resolutions(state, ev, rack, lk, str(req.get("question") or "") + " " + " ".join(x["text"] for x in ev.items[:8]))
    return ev, subject, rack


def _live_now(state: State, rack: str, link: str) -> dict | None:
    """Live's record of a link when Live is running on this rack (what the 'Live now' line shows)."""
    lv = state.live
    if lv is None or not link or lv.rack_name != rack:
        return None
    with lv.lock:
        r = lv.links.get(link)
        return dict(r) if r else None


def check_logins(state: State, name: str) -> dict:
    """One `true` per node of an inventory with its own user / key (heliosdbg/logins.py); kept for the banner."""
    from heliosdbg import logins
    _f, inv = state.inventory(name)
    r = logins.check(inv)
    with state.lock:
        state.logins[inv.rack] = {k: r[k] for k in ("rack", "time", "refused", "unreachable")}
    return r


def check_logins_at_start(state: State) -> None:
    """Every inventory's logins once, in the background, when the UI starts: a refused login is said on every page."""
    def run():
        for f in sorted(state.inventory_dir.glob("*.yaml")):
            try:
                check_logins(state, f.name)
            except Exception as e:  # noqa: BLE001 - a broken inventory is said where it is used
                print(f"login check of {f.name}: {type(e).__name__}: {str(e)[:160]}", flush=True)
                continue
        bad = {k: v["refused"] for k, v in state.logins.items() if v.get("refused")}
        print("login check: " + ("; ".join(f"{k}: refused on {', '.join(v)}" for k, v in bad.items()) if bad
                                 else "every reachable node accepts the inventory's login"), flush=True)
    threading.Thread(target=run, daemon=True, name="login-check").start()


def _focus(req: dict) -> list[str]:
    """The nodes a question is about (from the Ask button or an earlier answer): names only."""
    f = req.get("focus") or []
    return [str(x) for x in f if isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", x)][:16] if isinstance(f, list) else []


def _rack_nodes(state: State, rack: str):
    inv = _rack_inventory(state, rack)
    if inv is None:
        raise BadRequest(f"no inventory for rack {rack} on this machine")
    roles = {h.name: "switch" for h in inv.all_switches} | {h.name: "compute" for h in inv.all_computes}
    return inv, roles


def ai_guide(state: State, req: dict) -> dict:
    """The next step of a guided investigation (proposed by the AI, checked against the read-only allow-list)."""
    from heliosdbg import ai, guide
    ev, subject, rack = _ai_subject(state, req, past=True)
    if not rack:
        raise BadRequest("step by step needs the rack (its nodes are where the commands run) - pick one")
    _inv, roles = _rack_nodes(state, rack)
    steps = [s for s in (req.get("steps") or []) if isinstance(s, dict)][:12]
    q = str(req.get("question") or "").strip()[:300]
    if q:                                         # a follow-up typed on the panel: that is what to investigate now
        subject = q
        lk = str(req.get("link") or "")
        if lk and not re.search(r"\b(?:link|port|cable|optic|ifcp|fec|crc|flap|down|degraded|lane|signal)\b|"
                                + "|".join(re.escape(x) for x in lk.split()[1:]), q, re.I):
            from heliosdbg import cases    # not about the panel's link ('show me ip address configured on st1
            ev, _s, _r = cases.blocks_context([], q, rack)   # interface'): start from the question, as Debug a node does
    stay = _stay(ev, roles, _rack_aliases(state, rack), subject)
    if q and named_in(q, roles, _rack_aliases(state, rack)):    # the nodes it names, not the panel's link ends
        stay = named_in(q, roles, _rack_aliases(state, rack))
    try:
        out = guide.propose(ai, ev, subject, steps, roles, stay=stay)
    except (ai.AIError, guide.GuideError) as e:
        raise BadRequest(str(e)) from None
    if out.get("done") and req.get("blocks") is not None:   # a Debug-a-node question: helios-slm tests models on them
        _log_question(state, rack, subject, sorted(stay), steps, out)
    return out


def _log_question(state: State, rack: str, subject: str, stay: list, steps: list, out: dict) -> None:
    """One finished Debug-a-node investigation -> results/ai/questions.jsonl: what was asked, every command and its
    output, the conclusion (helios-slm realq.py replays them against new models - 9 Nov: the questions people really
    ask, 'check vlans on switch tray 1', were in no test)."""
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "rack": rack, "subject": subject, "stay": stay,
           "steps": [{k: (str(s.get(k) or "")[:6000] if k == "output" else s.get(k))
                      for k in ("node", "command", "rc", "output")} for s in steps if isinstance(s, dict)],
           "conclusion": out.get("conclusion"), "next": out.get("next"), "model": out.get("model"),
           "by_code": bool(out.get("by_code")), "contradicts": out.get("contradicts") or []}
    try:
        d = state.results_dir / "ai"
        d.mkdir(parents=True, exist_ok=True)
        with (d / "questions.jsonl").open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


_TRAY_RX = re.compile(r"\b(switch|compute)?\s*tray\s*#?\s*(\d{1,2})\b", re.I)


def named_in(text: str, roles: dict, aliases: dict) -> set:
    """The nodes a Debug-a-node description names: rack names (st1, ct07), AFM names (pod-1-0-SwitchTray), or 'switch
    tray 1' / 'compute tray 7' (9 Nov: 'check vlans on switch tray 1' had no focus - it went on to ct01 and st2)."""
    got = {n for n in roles if re.search(rf"\b{re.escape(n)}\b", text or "", re.I)}
    got |= {t for a, t in aliases.items() if t in roles and re.search(rf"\b{re.escape(a)}\b", text or "", re.I)}
    for m in _TRAY_RX.finditer(text or ""):
        kind = (m.group(1) or "compute").lower()
        num = int(m.group(2))
        got |= {n for n, r in roles.items() if r == ("switch" if kind == "switch" else "compute")
                and re.fullmatch(r"\D*0*(\d+)", n) and int(re.sub(r"\D", "", n)) == num}
    return got


def _stay(ev, roles: dict, aliases: dict, subject: str = "") -> set:
    """Where step by step may run commands when the question is about some nodes: those, and the nodes the evidence
    names (a link's other end) - not the rack's other problems (4 Nov: an st4 IFCP question went on to ct01, st5, ct03)."""
    focus = set(getattr(ev, "focus", None) or ()) or named_in(subject, roles, aliases)
    if not focus:
        return set()
    text = " ".join(x["text"] for x in ev.items if x.get("source") != "resolution")
    named = {n for n in roles if re.search(rf"\b{re.escape(n)}\b", text)} | {
        t for a, t in aliases.items() if t in roles and re.search(rf"\b{re.escape(a)}\b", text)}
    return (focus | named) & set(roles)


def ai_run(state: State, req: dict) -> dict:
    """Run one step the person clicked Run on - read-only allow-list checked again here."""
    from heliosdbg import guide
    from heliosdbg.transport import make_transport
    rel = str(req.get("path") or "").strip("/")
    if re.fullmatch(r"link-check/[A-Za-z0-9_.-]+/[a-z]+-[0-9]{8}-[0-9]{6}(?:-live)?", rel):
        rack = rel.split("/")[1]
    elif re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(req.get("rack") or "")):
        rack = str(req["rack"])
    else:
        raise BadRequest("path (a saved result) or rack")
    inv, roles = _rack_nodes(state, rack)
    node = str(req.get("node") or "")
    host = next((h for h in inv.all_switches + inv.all_computes if h.name == node), None)
    if host is None:
        raise BadRequest(f"no node {node!r} in this rack")
    try:
        guide.check(str(req.get("command") or ""), roles[node])
    except guide.GuideError as e:
        raise BadRequest(str(e)) from None
    t = make_transport(host, inv.transport or {})
    try:
        return guide.run(host, t, str(req.get("command")), roles[node], state.results_dir / "ai")
    finally:
        try:
            t.close()
        except Exception:  # noqa: BLE001
            pass


def ai_ticket(state: State, req: dict) -> dict:
    """A ticket for one audience: facts from the check, summary / request drafted by the AI (if one is connected)."""
    from heliosdbg import ai, ticket
    rel = str(req.get("path") or "").strip("/")
    if not re.fullmatch(r"link-check/[A-Za-z0-9_.-]+/scan-[0-9]{8}-[0-9]{6}(-live)?", rel):
        raise BadRequest("path: link-check/<rack>/scan-...")
    audience = str(req.get("audience") or "all")
    if audience not in ticket.AUDIENCES:
        raise BadRequest("audience: " + ", ".join(ticket.AUDIENCES))
    scan = scan_view(state, rel)
    probs = ticket.problems(scan)
    text = ticket.ai_paragraphs(ai, scan, audience, probs) if req.get("ai", True) else None
    return {"markdown": ticket.render(scan, audience, probs, text, f"results/{rel}/report.html"), "problems": probs,
            "ai": bool(text), "unsafe": (text or {}).get("unsafe"), "audience": audience}


def push_to_hub(kind: str, record: dict) -> None:
    """HELIOS_TRAIN_HUB (helios-slm's web UI, e.g. http://127.0.0.1:8770): the new resolution / rating also goes into
    its training review queue, in the background; the local results/ai/*.jsonl stays the record either way."""
    url = os.environ.get("HELIOS_TRAIN_HUB", "").rstrip("/")
    if not url:
        return

    def go():
        import urllib.request
        try:
            req = urllib.request.Request(url + "/api/hub/push", data=json.dumps({kind: record}).encode(),
                                         headers={"Content-Type": "application/json", "X-Helios-SLM": "1"})
            urllib.request.urlopen(req, timeout=30).read()
        except Exception as e:  # noqa: BLE001 - the hub being away never breaks the UI; import picks the file up later
            print(f"train hub: {kind} {record.get('id')} not pushed ({type(e).__name__}: {str(e)[:120]})", flush=True)
    threading.Thread(target=go, daemon=True).start()


def ai_resolution(state: State, req: dict) -> dict:
    """Record what a problem turned out to be and what fixed it (written by a person) - with the evidence of the
    check / link / Diagnose result it is about, as the AI sees it. Changes nothing on the rack."""
    from heliosdbg import resolutions
    from heliosdbg import cases
    rel = str(req.get("path") or "").strip("/")
    ev, subject = None, ""
    if rel or cases.spec_of(req) is not None:
        ev, subject, rack = _ai_subject(state, req)
        req = dict(req, rack=rack or str(req.get("rack") or ""))
        ev.items = [x for x in ev.items if x.get("source") != "resolution"]   # not earlier resolutions: no copying
    elif not str(req.get("rack") or "").strip() or not str(req.get("subject") or "").strip():
        raise BadRequest("path (a check / Diagnose result), or rack + subject (e.g. a test case id)")
    try:
        r = resolutions.record(state.results_dir, req, ev, subject)
        push_to_hub("resolution", r)
    except resolutions.ResolutionError as e:
        raise BadRequest(str(e)) from None
    return {"saved": r["id"], "resolution": r | {"evidence": len(r["evidence"])}, "count": len(resolutions.load(state.results_dir))}


def add_past_resolutions(state: State, ev, rack: str, link: str = "", text: str = "") -> None:
    """Show the AI the most similar resolutions people recorded for this rack (same link first)."""
    from heliosdbg import resolutions
    for r in resolutions.similar(resolutions.load(state.results_dir, rack), link, text):
        ev.add(resolutions.line(r), "resolution")


SMALLTALK_RX = re.compile(r"\s*(hi+|hello|hey|hiya|yo|good\s+(morning|afternoon|evening)|thanks?(\s+you)?|thank\s+you|thx|"
                          r"ok(ay)?|cool|great|nice|got\s+it|bye|help|\?)\s*[!.?]*\s*", re.I)


def smalltalk(q: str, scan: dict, rack: str, rel: str) -> dict:
    """A greeting / thanks / 'help': a short reply with what the chat can do and the rack's state in one line."""
    ls = scan.get("links") or []
    c: dict = {}
    for x in ls:
        c[x.get("state")] = c.get(x.get("state"), 0) + 1
    t = str(scan.get("time_utc") or "")
    m = re.match(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)", t)
    when = f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)} UTC" if m else t
    state_line = (f"{rack}: the check of {when} read {len(ls)} GPU links - "
                  + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) + ".")
    low = q.strip().lower()
    if low.startswith(("thank", "thx", "ok", "cool", "great", "nice", "got")):
        text = "You're welcome. Ask another question any time."
    elif low.startswith("bye"):
        text = "Bye - the conversation stays here until you press New."
    else:
        text = ("Hi. Ask me anything about this rack - for example:\n"
                "- What is wrong with this rack, and in what order should it be fixed?\n"
                "- Which links on st6 asic0 have no IFCP session?\n"
                "- What does 'forwarding entries without a switch port' mean?\n"
                "- How do I read the IFCP state of a GPU port?\n\n"
                f"Right now: {state_line} Open a link in the Rack map to ask about that link.")
    return {"answer": text, "model": "(no model needed)", "evidence": [], "docs": [], "unsafe": None, "wrong_device": [],
            "cited": [], "unknown_citations": [], "seconds": 0, "subject": "chat",
            "context": {"rack": rack, "path": rel, "time_utc": scan.get("time_utc"), "link": None, "live_changes": 0}}


def ai_chat(state: State, req: dict) -> dict:
    """One chat question about a rack: its check (the one shown, else the newest full one), the open link if any, the
    newest Live changes when Live runs for that rack, and matching documentation passages."""
    from heliosdbg import ai, docsearch
    name = str(req.get("inventory") or "")
    f, inv = state.inventory(name)
    rack = inv.rack or f.stem
    q = str(req.get("question") or "").strip()[:2000]
    if not q:
        raise BadRequest("type a question")
    rel = str(req.get("path") or "").strip("/")
    if not re.fullmatch(rf"link-check/{re.escape(rack)}/scan-[0-9]{{8}}-[0-9]{{6}}(-live)?", rel):
        runs = sorted((state.results_dir / "link-check" / rack).glob("scan-*/link_check.json"), reverse=True)
        lf = latest_full(rack, runs, len(inv.computes)).get("latest_full")
        if not lf:
            raise BadRequest(f"no check of {rack} yet - run Check all links first")
        rel = lf
    scan = scan_view(state, rel)
    if SMALLTALK_RX.fullmatch(q):                  # 'hi', 'thanks', 'ok': no model call, no rack dump
        return smalltalk(q, scan, rack, rel)
    live = []
    with state.lock:
        lv, lv_inv = state.live, state.live_inventory
    if lv is not None and lv_inv == name:
        try:
            live = [c for c in lv.status(0).get("changes") or [] if c.get("what") != "note"][-12:]
        except Exception:  # noqa: BLE001 - the chat works without it
            live = []
    link = str(req.get("link") or "").strip()
    try:
        macs = None
        if re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|\bmac\b|Ethernet\d+", q, re.I):   # MACs: the check's raw switch read
            import gzip
            from heliosdbg import rackmap
            raw = state.results_dir / rel / "raw" / "switches.json.gz"
            try:
                macs = rackmap.mac_index(_gz_json(raw)) if raw.is_file() else None
            except (OSError, ValueError, EOFError):
                macs = None
        ev, subject = ai.chat_context(scan, q, link if link and any(
            f"{x.get('switch')} {x.get('sw_port')}" == link for x in scan.get("links") or []) else "", live, docsearch.load(), macs,
            _focus(req))
        from heliosdbg import rackfacts
        hs = sorted((state.results_dir / "link-check" / rack).glob("health-*/health.json"), reverse=True)
        try:
            health = json.loads(hs[0].read_text()) if hs else None
        except (OSError, ValueError):
            health = None
        ages = rackfacts.ages(scan, health)
        ks = rackfacts.kinds(q) if not link else []
        if getattr(ev, "map_facts", None):        # 'which switch port is c1 connected to': the rack map answers it exactly
            ks = [k for k in ks if k not in ("links", "gpus")]
        if ks:                    # who answers, how many links / GPUs, quarantine, findings, when: exact lines, not the model's
            ev.check_facts = rackfacts.facts(
                ks, q, [h.name for h in inv.all_switches], [h.name for h in inv.all_computes],
                [(h.name, (h.quarantine or {}).get("reason", "")) for h in inv.quarantined], health,
                hs[0].parent.name if hs else "", scan, rel.rsplit("/", 1)[-1])
            ev.map_facts, ev.docs, ev.howto = [], [], False   # not the plane map, not the guide's older known-issue table
            for t in ev.check_facts:
                ev.add(t, "check")
        else:
            for t in rackfacts.answered_lines(q, health):   # the node asked about answered (or not) - not a doc's guess
                ev.add(t, "health")
        if not (getattr(ev, "map_facts", None) or getattr(ev, "check_facts", None)):   # a lookup is exact on its own
            add_past_resolutions(state, ev, rack, link or "", q)
        hist = req.get("history") or []
        try:
            out = ai.ask(ev, subject, q, hist if isinstance(hist, list) else [])
        except ai.AIError as e:
            if not (getattr(ev, "map_facts", None) or getattr(ev, "plan_facts", None) or getattr(ev, "check_facts", None)):
                raise
            # a rack-map / test-plan lookup needs no model: the exact lines, and why there is no explanation
            out = {"answer": f"_(No explanation: {e})_", "model": "none", "evidence": ev.items, "docs": getattr(ev, "docs", None) or [],
                   "map_facts": ev.map_facts, "plan_facts": ev.plan_facts, "check_facts": getattr(ev, "check_facts", []), "unsafe": None, "wrong_device": [], "cited": [], "unknown_citations": [],
                   "seconds": 0, "subject": subject}
    except ai.AIError as e:
        raise BadRequest(str(e)) from None
    out["off_facts"] = rackfacts.review(out.get("answer") or "", getattr(ev, "check_facts", None) or [])
    out = out | {"context": {"rack": rack, "path": rel, "time_utc": scan.get("time_utc"), "link": link or None,
                             "live_changes": len(live), "focus": getattr(ev, "focus", None) or [], "ages": ages,
                             "health": hs[0].parent.name if hs else None, "kinds": ks}}
    log_chat(state, q, out)
    return out


_VERSION: dict = {}


def code_version() -> dict:
    """{version, commit, built}: the bundle's BUILD_INFO.json (an installed copy), else the git checkout's commit (with
    '+changes' when files differ from it) - shown in the header, read by tools/deploy.py after an upgrade."""
    if not _VERSION:
        try:
            _VERSION.update(json.loads((ROOT / "BUILD_INFO.json").read_text()))
        except (OSError, ValueError):
            try:
                git = ["git", "-C", str(ROOT)]
                c = subprocess.run(git + ["rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5).stdout.strip()
                dirty = subprocess.run(git + ["status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True,
                                       timeout=5).stdout.strip()
                _VERSION.update({"version": (c or "unknown") + ("+changes" if dirty else ""), "commit": c})
            except (OSError, subprocess.SubprocessError):
                _VERSION["version"] = "unknown"
    return dict(_VERSION)


def version_info(state: State) -> dict:
    """The code version and whether the UI is busy (a running job, Live, an open terminal) - an upgrade waits for idle."""
    with state.lock:
        jobs = sum(1 for j in state.jobs.values() if j.get("status") == "running")
        live = state.live is not None
    try:
        terms = sum(1 for t in state.terms.list() if not t.get("closed"))
    except Exception:  # noqa: BLE001
        terms = 0
    return code_version() | {"busy": {"jobs": jobs, "live": live, "terminals": terms}, "idle": not (jobs or live or terms),
                             "disk": disk_info(state),
                             "logins": {k: v for k, v in state.logins.items() if v.get("refused")}}


CHAT_LOG = "chat.jsonl"
CHAT_LOG_MAX = 20 * 1024 * 1024                         # then chat.jsonl.1 (one old file kept)


def log_chat(state: State, q: str, out: dict) -> None:
    """Every chat question and its answer in <results>/ai/chat.jsonl: what was asked, the checks it was answered from,
    the exact lines, the answer and the model - so a wrong answer is found without a thumbs-down, and the questions
    can be asked again after a model or code change (tools/chat_replay.py). Never fails the answer."""
    if getattr(state, "no_chat_log", False):          # tools/chat_replay.py asks again: not new questions
        return
    ctx = out.get("context") or {}
    rec = {"time_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), "question": q, "rack": ctx.get("rack"),
           "path": ctx.get("path"), "health": ctx.get("health"), "link": ctx.get("link"), "kinds": ctx.get("kinds") or [],
           "focus": ctx.get("focus") or [], "check_facts": out.get("check_facts") or [], "map_facts": out.get("map_facts") or [],
           "answer": out.get("answer"), "answer_id": out.get("answer_id"), "model": out.get("model"),
           "off_facts": out.get("off_facts") or [], "unsafe": out.get("unsafe"), "seconds": out.get("seconds")}
    try:
        d = state.results_dir / "ai"
        d.mkdir(parents=True, exist_ok=True)
        f = d / CHAT_LOG
        if f.is_file() and f.stat().st_size > CHAT_LOG_MAX:
            f.replace(d / (CHAT_LOG + ".1"))
        with state.lock, f.open("a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass


CONFIG_KEEP = 30                                       # saved reads kept per node (the oldest go)
NODE_RX = re.compile(r"^[A-Za-z0-9][\w.-]*$")


def _config_dir(state: State, rack: str, node: str = "") -> Path:
    if not NODE_RX.match(rack) or (node and not NODE_RX.match(node)):
        raise BadRequest("bad rack / node name")
    return state.results_dir / "config" / rack / node if node else state.results_dir / "config" / rack


def _free_stamp(d: Path) -> str:
    """A UTC stamp no saved read in d uses yet: two reads in the same second must not overwrite each other."""
    t = time.time()
    while True:
        st = time.strftime("%Y%m%d-%H%M%S", time.gmtime(t))
        if not (d / f"{st}.json").exists() and not (d / f"rack-{st}.json").exists():
            return st
        t += 1


def save_config(state: State, rack: str, out: dict, stamp: str) -> str:
    """Keep a config read as results/config/<rack>/<node>/<UTC>.json (newest CONFIG_KEEP per node): what a node
    looked like before an AFM reset / reconfigure is otherwise gone. Returns the path under results/."""
    d = _config_dir(state, rack, out["node"])
    d.mkdir(parents=True, exist_ok=True)
    rel = f"config/{rack}/{out['node']}/{stamp}.json"
    (d / f"{stamp}.json").write_text(json.dumps(out | {"saved": rel}, default=str))
    for old in sorted(d.glob("*.json"))[:-CONFIG_KEEP]:
        old.unlink(missing_ok=True)
    return f"config/{rack}/{out['node']}/{stamp}.json"


def saved_configs(state: State, inventory: str, node: str = "") -> dict:
    """{node: [{path, time_utc}] newest first} of the saved config reads of a rack (one node, or all)."""
    f, inv = state.inventory(inventory)
    rack = inv.rack or f.stem
    base = _config_dir(state, rack)
    out = {}
    for d in sorted(base.glob("*")) if base.is_dir() else []:
        if d.is_dir() and (not node or d.name == node):
            out[d.name] = [{"path": f"config/{rack}/{d.name}/{p.name}", "stamp": p.stem}
                           for p in sorted(d.glob("*.json"), reverse=True)]
    return {"rack": rack, "nodes": out}


def config_zip(state: State, inventory: str, stamp: str = "") -> tuple[bytes, str]:
    """A zip of a rack's saved config reads: the newest per node, or those of one whole-rack read (stamp)."""
    import io
    import zipfile
    f, inv = state.inventory(inventory)
    rack = inv.rack or f.stem
    if stamp and not re.match(r"^\d{8}-\d{6}$", stamp):
        raise BadRequest("bad stamp")
    base = _config_dir(state, rack)
    buf, n = io.BytesIO(), 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for d in sorted(base.glob("*")) if base.is_dir() else []:
            if not d.is_dir():
                continue
            files = [d / f"{stamp}.json"] if stamp else sorted(d.glob("*.json"))[-1:]
            for p in files:
                if p.is_file():
                    z.write(p, f"{rack}-config/{d.name}-{p.stem}.json")
                    n += 1
        if stamp and (base / f"rack-{stamp}.json").is_file():
            z.write(base / f"rack-{stamp}.json", f"{rack}-config/rack-summary-{stamp}.json")
    if not n:
        raise BadRequest("no saved config reads for this rack yet - read a node or the whole rack first")
    return buf.getvalue(), f"{rack}-config-{stamp or 'newest'}.zip"


def _read_one(h, inv, is_switch: bool) -> dict:
    from heliosdbg import config_view
    from heliosdbg.compute import ComputeTray
    from heliosdbg.sonic import SonicSwitch
    from heliosdbg.transport import make_transport
    t = make_transport(h, inv.transport or {})
    t0 = time.time()
    try:
        out = config_view.switch_config(SonicSwitch(h, t)) if is_switch else config_view.compute_config(ComputeTray(h, t))
    finally:
        try:
            t.close()
        except Exception:  # noqa: BLE001
            pass
    return out | {"node": h.name, "address": h.host, "read_s": round(time.time() - t0, 1),
                  "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _tray_slots(inv) -> dict:
    return {int(h.extra["slot"]): h.name for h in inv.all_computes
            if str((h.extra or {}).get("slot", "")).isdigit()}       # 'FILL-ME' in a discovered draft: no slot


def _newest_saved(state: State, rack: str, names) -> dict:
    """{node: its newest saved config read} for the named nodes that have one."""
    out = {}
    for n in names:
        d = _config_dir(state, rack, n)
        last = sorted(d.glob("*.json"))[-1:] if d.is_dir() else []
        if last:
            try:
                out[n] = json.loads(last[0].read_text())
            except (OSError, ValueError):
                pass
    return out


def node_config(state: State, req: dict) -> dict:
    """The read-only configuration of one switch / compute tray (Config tab): SONiC CONFIG_DB per ASIC, or afmctl's
    GPU and port configuration. Read live, over the same transport as the checks; kept (save_config) with a summary,
    and for a switch its forwarding entries checked against the trays' newest saved reads."""
    from heliosdbg import config_view
    f, inv = state.inventory(req.get("inventory", ""))
    name = str(req.get("node", ""))
    sw = next((h for h in inv.all_switches if h.name == name), None)
    ct = next((h for h in inv.all_computes if h.name == name), None)
    if not (sw or ct):
        raise BadRequest(f"no switch or compute tray {name!r} in {req.get('inventory')}")
    rack = inv.rack or f.stem
    try:
        out = _read_one(sw or ct, inv, bool(sw))
    except Exception as e:  # noqa: BLE001 - a switch that does not answer fails before its sections
        raise BadRequest(f"{name} not read: {type(e).__name__}: {str(e)[:300]}") from None
    if all(v.get("error") for v in out["sections"].values()):   # nothing read: not kept as if it were its config
        raise BadRequest(f"{name} not read: {next(iter(out['sections'].values()))['error']}")
    out["summary"] = config_view.summary(out)
    if sw:
        trays = {t: c for t, c in _newest_saved(state, rack, [h.name for h in inv.all_computes]).items()
                 if config_view.ports_read(c)}
        if trays:
            out["fdb_check"] = config_view.fdb_check({name: out}, trays, _tray_slots(inv)) | {
                "trays_from": {t: c.get("time_utc") for t, c in trays.items()}}
    out["saved"] = save_config(state, rack, out, _free_stamp(_config_dir(state, rack, name)))
    return out


def rack_config(state: State, req: dict) -> dict:
    """Every switch and compute tray of the rack read at once (4 at a time: the jump host's session limit), each
    saved, plus what stands out: values few nodes have (odd_ones) and forwarding entries no GPU port answers."""
    from concurrent.futures import ThreadPoolExecutor
    from heliosdbg import config_view
    f, inv = state.inventory(req.get("inventory", ""))
    rack = inv.rack or f.stem
    with state.lock:
        if getattr(state, "config_busy", False):
            raise BadRequest("a whole-rack config read is already running - wait for it")
        state.config_busy = True
    try:
        return _rack_config(state, f, inv, rack)
    finally:
        state.config_busy = False


def _rack_config(state: State, f, inv, rack: str) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    from heliosdbg import config_view
    stamp = _free_stamp(_config_dir(state, rack))
    hosts = [(h, True) for h in inv.all_switches] + [(h, False) for h in inv.all_computes]
    t0 = time.time()

    def one(x):
        h, is_sw = x
        try:
            return h.name, _read_one(h, inv, is_sw), None
        except Exception as e:  # noqa: BLE001 - one node off the network does not stop the others
            return h.name, None, f"{type(e).__name__}: {str(e)[:300]}"
    with ThreadPoolExecutor(max_workers=4) as pool:
        res = list(pool.map(one, hosts))
    cfgs, errors, nodes = {}, {}, []
    for n, out, err in res:
        if err:
            errors[n] = err
            continue
        bad = {k: v["error"] for k, v in out["sections"].items() if v.get("error")}
        if len(bad) == len(out["sections"]):          # nothing readable: as unreachable, not as a config
            errors[n] = next(iter(bad.values()))
            continue
        out["summary"] = config_view.summary(out)
        out["saved"] = save_config(state, rack, out, stamp)
        cfgs[n] = out
        nodes.append({"node": n, "kind": out["kind"], "saved": out["saved"], "read_s": out["read_s"],
                      "errors": bad, "summary": out["summary"]})
    swc = {n: c for n, c in cfgs.items() if c["kind"] == "switch"}
    trc = {n: c for n, c in cfgs.items() if c["kind"] == "compute" and config_view.ports_read(c)}
    result = {"rack": rack, "stamp": stamp, "read_s": round(time.time() - t0, 1), "nodes": nodes, "errors": errors,
              "odd": config_view.odd_ones(cfgs),
              "fdb_check": config_view.fdb_check(swc, trc, _tray_slots(inv)) if swc and trc else None}
    d = _config_dir(state, rack)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"rack-{stamp}.json").write_text(json.dumps(result, default=str))
    for old in sorted(d.glob("rack-*.json"))[:-CONFIG_KEEP]:
        old.unlink(missing_ok=True)
    return result


def scan_view(state: State, rel: str) -> dict:
    """A scan's links, compact, for the rack map (rel: link-check/<rack>/scan-...)."""
    f = _result_file(state, f"{rel}/link_check.json")
    d = json.loads(f.read_text())
    links = [{k: ln.get(k) for k in LINK_KEYS} | {"evidence": (ln.get("evidence") or [])[:8]} for ln in d.get("links") or []]
    slots = dict((d.get("learned") or {}).get("slots") or {})
    name_unread_trays(links, slots)
    acc, trays = {}, {}                               # {tray:bdf: accelerator id} as the trays reported it (= AFM acc-id)
    raw = f.parent / "raw" / "trays.json.gz"
    if raw.is_file():
        import gzip
        try:
            trays = _gz_json(raw)
            for tn, t in trays.items():
                for g in (t or {}).get("gpus") or []:
                    if g.get("bdf") and str(g.get("accelerator", "")).isdigit():
                        acc[f"{tn}:{g['bdf']}"] = int(g["accelerator"])
        except (OSError, ValueError, EOFError):        # truncated raw file: the view without IFCP / accelerator ids
            acc, trays = {}, {}
    cabling = ifcp_cabling(links, trays, (d.get("learned") or {}).get("ifcp"))
    sw_ids = afm_switch_ids(state, d.get("rack"))
    return {"path": rel, "time_utc": d.get("time_utc"), "rack": d.get("rack"), "links": links, "gpus": d.get("gpus") or [],
            "afm_view": (d.get("learned") or {}).get("afm_view"), "patterns": d.get("patterns") or [],
            "root_causes": d.get("root_causes") or live_causes(d), "not_checked": d.get("not_checked") or [],
            "scope": d.get("scope") or {}, "fdb_broken": d.get("fdb_broken") or [],
            "vlan_findings": d.get("vlan_findings") or [], "vlans": (d.get("learned") or {}).get("vlans") or {},
            "slots": slots, "switch_ids": sw_ids, "afm_names": afm_names(state, d.get("rack"), slots, sw_ids), "cabling": cabling,
            "gpu_map": (d.get("learned") or {}).get("gpu_map") or {}, "gpu_acc": acc,
            "ifcp_in_use": (d.get("learned") or {}).get("ifcp_in_use", True)}


def live_causes(d: dict) -> list[dict]:
    """Findings of a check saved from Live before it wrote its own (4 Nov: 695 degraded, no finding listed): its links
    grouped, Live's 'll_up no' readings as IFCP."""
    if not d.get("live"):
        return []
    ls = []
    for x in d.get("links") or []:
        if x.get("state") == "unknown":
            continue
        if (x.get("kind") == "live" and x.get("state") == "degraded" and "GPU LINK_UP" in (x.get("cause") or "")
                and re.search(r"IFCP ll_up (?!yes)\w", x.get("cause") or "")):
            x = dict(x, kind="ifcp", owner=x.get("owner") or "GPU / AFM vendor")
        ls.append(x)
    return [dict({k: v for k, v in g.items() if k != "links"}, links=[f"{x['switch']} {x['sw_port']}" for x in g["links"]])
            for g in linkdiag.group_causes(ls)]


SECRET_RX = re.compile(r"^\s*(password|passwd|token|secret)\s*:\s*\S", re.I | re.M)
ADDR_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
USER_RX = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


def discover_rack(req: dict) -> dict:
    from heliosdbg import discover
    from heliosdbg.rack import fan_out
    rack = str(req.get("rack") or "").strip()
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,40}$", rack):
        raise BadRequest("rack name: lower case letters, digits, - and _ (e.g. mr4)")
    addrs = [x for x in re.split(r"[\s,]+", str(req.get("switches") or "")) if x]
    if not addrs or len(addrs) > 16 or not all(ADDR_RX.match(x) for x in addrs):
        raise BadRequest("switch addresses: 1 to 16, comma or space separated")
    us, uc = str(req.get("switch_user") or "admin"), str(req.get("compute_user") or "")
    if not USER_RX.match(us) or (uc and not USER_RX.match(uc)):
        raise BadRequest("user names: letters, digits, _ . -")
    key = str(req.get("key_file") or "").strip() or None
    if key and not re.match(r"^[~A-Za-z0-9_./-]{1,200}$", key):
        raise BadRequest("key file: a path like ~/.ssh/id_ed25519")
    jump = None
    jh = str(req.get("jump_host") or "").strip()
    if jh:                                            # a rack reachable only through a jump host (g02-g17)
        ju, jp = str(req.get("jump_user") or "").strip(), _int(req, "jump_port", 1, 65535, 22)
        if not ADDR_RX.match(jh) or (ju and not USER_RX.match(ju)):
            raise BadRequest("jump host: an address (and a user name: letters, digits, _ . -)")
        jump = {"host": jh, "port": jp, **({"user": ju} if ju else {}), "via": "exec"}
    found, errors = [], {}
    for a, v, e in fan_out(lambda x: discover.read_switch(x, us, key_file=key, jump=jump), addrs):
        if e:
            errors[a] = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            found.append(v)
    if not found:
        raise BadRequest("no switch could be read: " + "; ".join(f"{a}: {m}" for a, m in errors.items()))
    afm_url = str(req.get("afm_url") or "").strip() or f"https://{addrs[0]}"
    trays = None
    if req.get("afm") and req.get("afm_password"):
        from heliosdbg.afm import Afm, AfmUnavailable
        try:                                          # in memory only: os.environ leaked it to any child started
            trays = discover.afm_trays(Afm({"url": afm_url, "auth": {"password": str(req["afm_password"])}}), set(addrs))
        except AfmUnavailable as e:
            errors["afm"] = str(e)
    text = discover.draft(rack, found, us, uc or "FILL-ME-tray-user", afm_url, trays, key, jump=jump)
    return {"yaml": text, "switches": found, "errors": errors}


def _has_secret(text: str) -> bool:
    """A password / token value anywhere in the YAML - also inside {...} maps the line regex does not see."""
    import yaml
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return False                                  # not valid: refused by the inventory check after this

    def walk(v) -> bool:
        if isinstance(v, dict):
            return any((re.fullmatch(r"(password|passwd|token|secret)", str(k), re.I) and v[k] not in (None, ""))
                       or walk(v[k]) for k in v)
        if isinstance(v, list):
            return any(walk(x) for x in v)
        return False
    return walk(doc)


def _qint(q: dict, name: str, default: int) -> int:
    """A number from the query string; not a number = 400, not a 500 with a traceback."""
    v = (q.get(name) or [""])[0]
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        raise BadRequest(f"{name}: a whole number") from None


def inventory_text(state: State, name: str) -> dict:
    """An inventory file as written (comments kept), for editing in Add / edit a rack - also one that does not load."""
    if not NAME_RX.match(name or "") or not name.endswith(".yaml"):
        raise BadRequest("unknown inventory")
    f = state.inventory_dir / name
    if not f.is_file():
        raise BadRequest(f"no inventory {name}")
    return {"file": f.name, "name": re.sub(r"(\.local)?\.yaml$", "", f.name), "yaml": f.read_text()}


def _write_inventory(f: Path, text: str) -> Path | None:
    """Write an inventory, keeping the previous file beside it as <file>.bak-<time>; the backup, if one was made."""
    backup = None
    if f.exists() and f.read_text() != text:          # an edit keeps the previous file beside it
        backup = f.with_name(f"{f.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        n = 1
        while backup.exists():                        # two saves in one second: the first backup is kept
            backup, n = f.with_name(f"{f.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{n}"), n + 1
        backup.write_text(f.read_text())
    part = f.with_name(f".{f.name}.saving")           # a full disk mid-write leaves the old file, not half a new one
    part.write_text(text)
    os.replace(part, f)
    return backup


_QFLOW = re.compile(r"""(,\s*quarantine:\s*(?:\{[^{}]*\}|'[^']*'|"[^"]*"|[^,}#]*?)(?=\s*[,}]))"""
                    r"""|(quarantine:\s*(?:\{[^{}]*\}|'[^']*'|"[^"]*"|[^,}#]*?)\s*,\s*)""")


def _drop_quarantine(text: str, node: str) -> str | None:
    """The inventory text with ``node``'s quarantine taken out, comments and layout kept - or None when its entry is
    not written in a way this can edit (then: Add / edit a rack)."""
    lines = text.splitlines(keepends=True)
    name_rx = re.compile(r"""(^\s*-\s*\{?\s*|[{,]\s*)name:\s*['"]?""" + re.escape(node) + r"""['"]?\s*[,}\n#]""")
    for i, ln in enumerate(lines):
        if not name_rx.search(ln if ln.endswith("\n") else ln + "\n"):
            continue
        if "{" in ln and "}" in ln and "quarantine:" in ln:          # - {name: ct05, ..., quarantine: {...}}
            new, n = _QFLOW.subn("", ln, count=1)
            return "".join(lines[:i] + [new] + lines[i + 1:]) if n else None
        if "{" in ln:
            return None
        ind = len(ln) - len(ln.lstrip(" -"))                         # - name: ct05 / quarantine: ... below it
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip(" ")) >= ind
                                  and not lines[j].lstrip().startswith("-")):
            if re.match(r"\s*quarantine:", lines[j]) and len(lines[j]) - len(lines[j].lstrip(" ")) == ind:
                k = j + 1                                              # and its own lines, indented deeper
                while k < len(lines) and lines[k].strip() and len(lines[k]) - len(lines[k].lstrip(" ")) > ind:
                    k += 1
                return "".join(lines[:j] + lines[k:])
            j += 1
        return None
    return None


def lift_quarantine(state: State, req: dict) -> dict:
    """One click on the rack map: take a node's quarantine out of the rack's inventory (the previous file kept as
    <file>.bak-<time>). Only that key may change - anything else and nothing is written."""
    import yaml
    name, node = str(req.get("inventory") or ""), str(req.get("node") or "").strip()
    f, inv = state.inventory(name)
    q = inv.quarantine_summary()
    if node not in q:
        raise BadRequest(f"{node or 'that node'} is not quarantined in {f.name}")
    text = f.read_text()
    new = _drop_quarantine(text, node)
    before, after = yaml.safe_load(text), (yaml.safe_load(new) if new is not None else None)
    want = json.loads(json.dumps(before))
    for sec in ("switches", "computes"):
        for h in want.get(sec) or []:
            if isinstance(h, dict) and str(h.get("name")) == node:
                h.pop("quarantine", None)
    if after != want:
        raise BadRequest(f"{node}'s entry in {f.name} is written in a way this button cannot edit safely - remove its "
                         "'quarantine:' in Add / edit a rack (Edit the rack chosen at the top)")
    backup = _write_inventory(f, new)
    return {"file": f.name, "node": node, "was": q[node], "backup": backup.name if backup else None}


def save_inventory(state: State, req: dict) -> dict:
    name = str(req.get("name") or "").strip()
    if not re.match(r"^[a-z0-9][a-z0-9_-]{0,40}$", name):
        raise BadRequest("file name: lower case letters, digits, - and _ (saved as <name>.local.yaml)")
    text = str(req.get("yaml") or "")
    if not text.strip() or len(text) > 500_000:
        raise BadRequest("empty inventory")
    if SECRET_RX.search(text) or _has_secret(text):
        raise BadRequest("the inventory holds a password / token - use key login or password_env: VAR")
    f = state.inventory_dir / f"{name}.local.yaml"
    if f.exists() and not req.get("overwrite"):
        raise BadRequest(f"{f.name} exists - tick overwrite to replace it")
    backup = None
    tmp = state.inventory_dir / f".{name}.check.yaml"
    tmp.write_text(text)
    try:
        inv = load_inventory(tmp)
    except Exception as e:  # noqa: BLE001
        raise BadRequest(f"not a valid inventory: {type(e).__name__}: {str(e)[:200]}") from None
    finally:
        tmp.unlink(missing_ok=True)
    backup = _write_inventory(f, text)
    return {"file": f.name, "backup": backup.name if backup else None, "rack": inv.rack, "switches": len(inv.switches), "computes": len(inv.computes),
            "fill_me": sum(ln.count("FILL-ME") for ln in text.splitlines() if not ln.lstrip().startswith("#"))}


def fill_missing(inv, links: list[dict], older: list[Path]) -> dict:
    """Switches / trays of the inventory the starting check did not read get their links from the newest earlier check
    that read them, so Live follows them too (g02-g17 24 Oct: st1, st2, st4 not read - FDB entries SONiC's show mac
    fails on - and Live left their 1296 links grey on 3 Nov although both ends answered). Their state is not known
    until Live reads them; the old check's state is not carried. Returns {node: that check's time}; links appended."""
    has = {x["switch"] for x in links} | {x.get("tray") for x in links if x.get("tray")}
    need = {h.name for h in inv.switches + inv.computes} - has
    seen, filled = {f"{x['switch']} {x['sw_port']}" for x in links}, {}
    for run in older:
        if not need:
            break
        try:
            e = json.loads(run.read_text())
        except (OSError, ValueError):
            continue
        got = set()
        for x in e.get("links") or []:
            k = f"{x.get('switch')} {x.get('sw_port')}"
            hit = {x.get("switch"), x.get("tray")} & need
            if not x.get("switch") or not x.get("sw_port") or not hit or k in seen:
                continue
            seen.add(k)
            got |= hit
            links.append(dict(x, state="unknown", filled_from=e.get("time_utc")))
        for n in got:
            filled[n] = e.get("time_utc")
        need -= got
    return filled


def live_start(state: State, req: dict) -> dict:
    from heliosdbg.live import LiveRack
    from heliosdbg.rack import Rack
    name = req.get("inventory", "")
    f, inv = state.inventory(name)
    runs = sorted((state.results_dir / "link-check" / (inv.rack or f.stem)).glob("scan-*/link_check.json"), reverse=True)
    if not runs:
        raise BadRequest("live mode starts from a check of the rack - run Check all links first")
    d, links, at = {}, [], 0
    for at, run in enumerate(runs[:60]):              # the newest check that read links: one that read nothing
        try:                                          # (every switch off the network) is no starting point
            d = json.loads(run.read_text())
        except (OSError, ValueError):
            continue
        links = [x for x in d.get("links") or [] if x.get("switch") and x.get("sw_port")]
        if links:
            break
    if not links:
        raise BadRequest("no check of this rack has links - run Check all links again")
    filled = fill_missing(inv, links, runs[at + 1:at + 1 + 30])   # 4 Nov: 6 partial 24 Oct scans hid st1, st2, st4's 19 Oct one
    reconcile_s, max_h = float(_int(req, "reconcile_s", 60, 3600, 300)), _int(req, "max_h", 0, 168, 8)
    with state.lock:                                  # one start at a time: two at once left one session running
        if state.live_starting:                       # unreachable (double click)
            raise BadRequest("live mode is being started - a moment")
        state.live_starting = True
    try:
        afm = None
        if req.get("afm") and req.get("afm_password") and (inv.afm or {}).get("url"):
            from heliosdbg.afm import Afm, AfmUnavailable
            try:                                      # in memory only, not os.environ (children inherited it)
                afm = Afm(dict(inv.afm, auth=dict((inv.afm or {}).get("auth") or {}, password=str(req["afm_password"]))))
            except AfmUnavailable as e:
                raise BadRequest(str(e)) from None
        jump = (inv.transport or {}).get("jump") or {}
        new = LiveRack(Rack(inv), links, rack_name=inv.rack or f.stem,
                       ifcp_in_use=bool((d.get("learned") or {}).get("ifcp_in_use", False)),
                       reconcile_s=reconcile_s, afm=afm, max_s=None if max_h == 0 else max_h * 3600.0,
                       idle_s=None if req.get("keep_unwatched") is True else 1800.0,
                       log_dir=None, last_view=lambda: state.live_view,
                       jump_limited=jump.get("via") == "exec", check_time=d.get("time_utc"), filled=filled)
        new.check_path = str(runs[at])
        # everything checked and built: only now is the running session stopped
        with state.lock:
            old, state.live = state.live, None
        if old is not None:                           # closing its streams takes seconds: not under the lock
            old.stop(f"live mode turned on for {inv.rack}" if state.live_inventory != name else "restarted")
        with state.lock:
            state.live_view = time.time()
            state.live, state.live_inventory = new, name
            new.start()
    finally:
        with state.lock:
            state.live_starting = False
    return {"started": True, "rack": inv.rack, "links": len(links), "from_check": d.get("time_utc"), "filled": filled}


def live_status(state: State, since: int) -> dict:
    with state.lock:
        lv = state.live
        state.live_view = time.time()
    if lv is None:
        return {"running": False}
    return lv.status(since) | {"inventory": state.live_inventory}


# ------------------------------------------------------------------ jobs

def start_job(state: State, req: dict) -> dict:
    args, out, rack = build_args(state, req)
    with state.lock:
        if state.current and state.jobs[state.current]["status"] == "running":
            raise BadRequest(f"a {state.jobs[state.current]['tool']} run is already running - wait for it or stop it")
        jid = uuid.uuid4().hex[:12]
        env = dict(os.environ)
        if req.get("tool") in ("scan", "link", "health") and req.get("afm") and req.get("afm_password"):
            _f, inv = state.inventory(req["inventory"])
            env[((inv.afm or {}).get("auth") or {}).get("password_env") or "HELIOS_AFM_PASSWORD"] = str(req["afm_password"])
        if req.get("tool") == "health" and not req.get("no_bmc") and req.get("bmc_password"):
            env["HELIOS_BMC_PASSWORD"] = str(req["bmc_password"])          # this run only, never stored
        job = {"id": jid, "tool": req["tool"], "rack": rack, "inventory": req["inventory"], "argv": args,
               "out": str(out.relative_to(state.results_dir)), "status": "running", "rc": None,
               "started": time.time(), "ended": None, "log": "", "proc": None}
        (state.results_dir / "ui-jobs").mkdir(parents=True, exist_ok=True)
        _prune_job_files(state.results_dir / "ui-jobs", state.jobs)
        if req["tool"] == "scan":                     # kept only if the user saves it
            out.mkdir(parents=True, exist_ok=True)
            (out / UNSAVED).write_text("run from the UI; removed when a newer check of the rack finishes, unless saved\n")
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
        for old in [j for j in sorted(state.jobs.values(), key=lambda j: j["started"])
                    if j["status"] != "running"][:-JOBS_KEEP]:       # their logs stay on disk (ui-jobs/)
            del state.jobs[old["id"]]

    def pump():
        try:
            for line in proc.stdout:
                try:                                  # a full disk must not stop reading the tool's output: its
                    logf.write(line)                  # pipe would fill and block it (an isolate holding a link down)
                    logf.flush()
                except OSError:
                    pass
                with state.lock:
                    job["log"] = (job["log"] + line)[-LOG_KEEP:]
        finally:
            rc = proc.wait()
            try:
                logf.close()
            except OSError:
                pass
            if job["tool"] == "scan" and rc in (0, 1) and (out / "link_check.json").is_file():
                # only a full check with links replaces older unsaved ones: a check of one switch, or one that read
                # nothing (every switch off the network), must not delete the last full check (audit 4 Nov)
                try:
                    from heliosdbg import scans
                    d = json.loads((out / "link_check.json").read_text())
                    full = bool(d.get("links")) and not scans.partial(d)
                except (OSError, ValueError):
                    full = False
                if full:
                    lv = state.live
                    keep = {out} | ({Path(lv.check_path).parent} if lv is not None and getattr(lv, "check_path", None) else set())
                    with state.lock:
                        job["dropped"] = drop_unsaved(out.parent, keep)
            with state.lock:
                job["rc"], job["ended"] = rc, time.time()
                job["status"] = ("stopped" if job.get("stopping") else
                                 {0: "ok", 1: "problems found", 2: "incomplete"}.get(rc, f"failed (rc {rc})"))
    threading.Thread(target=pump, daemon=True).start()
    return public(job)


UNSAVED = ".unsaved"          # a check run from the UI is kept only when the user saves it (3 Nov: "allow user to save")
SCAN_RX = re.compile(r"^link-check/[\w.-]+/scan-\d{8}-\d{6}(-live)?$")


def drop_unsaved(rack_dir: Path, keep) -> list[str]:
    """A newer check of the rack finished: earlier checks the user did not save are removed (only ones marked unsaved;
    checks from before this choice, or run outside the UI, have no mark and stay). keep: a folder, or a set of them
    (the new check, the check Live follows). Renamed first, so a reader never sees a half-removed folder."""
    keep = {Path(k) for k in (keep if isinstance(keep, (set, list, tuple)) else [keep])}
    gone = []
    for d in rack_dir.glob("scan-*"):
        if d not in keep and d.is_dir() and (d / UNSAVED).is_file():
            trash = d.with_name("." + d.name + ".removing")
            try:
                d.rename(trash)
            except OSError:
                continue
            shutil.rmtree(trash, ignore_errors=True)
            gone.append(d.name)
    return gone


def save_scan(state: State, rel: str) -> dict:
    if not SCAN_RX.match(rel or ""):
        raise BadRequest("not a check folder")
    d = (state.results_dir / rel).resolve()
    if state.results_dir.resolve() not in d.parents or not d.is_dir():
        raise BadRequest("no such check")
    with state.lock:                          # not while drop_unsaved runs (it holds the lock)
        if not d.is_dir():
            raise BadRequest("this check was removed meanwhile (a newer full check replaced it)")
        (d / UNSAVED).unlink(missing_ok=True)
    return {"saved": rel}


def live_save(state: State, what: str) -> dict:
    """Live writes nothing by itself: 'check' keeps what it read as a check of the rack (in the Scan / Mark lists),
    'log' writes its change log (the last 20000 changes, kept in memory)."""
    with state.lock:
        lv = state.live
    if lv is None:
        raise BadRequest("no live session to save - turn live on first")
    st = lv.status(0)
    now = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    if what == "log":
        out = state.results_dir / "live" / f"{lv.rack_name}-{now}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with lv.lock:
            rows = list(lv.changes)
        out.write_text("".join(json.dumps(c) + "\n" for c in rows))
        return {"saved": str(out.relative_to(state.results_dir)), "changes": len(rows)}
    src = lv.check_path
    try:
        d = json.loads(Path(src).read_text()) if src else {}
    except (OSError, ValueError):
        d = {}
    from heliosdbg.live import as_read as live_read
    links, counts = [], {}
    with lv.lock:
        for k, ln in lv.src.items():
            cur = lv.links[k]
            x = {f: v for f, v in ln.items() if f != "filled_from"}
            stt = cur["state"] or "unknown"
            if cur["read"]:
                said = (f"switch oper {cur['sw_oper'] or '?'} / admin {cur['sw_admin'] or '?'}, GPU {cur['gpu_link'] or 'not read'}"
                        f", IFCP ll_up {cur['ll_up'] or '?'}")
                if (stt == "degraded" and cur["sw_oper"] == "up" and cur["gpu_link"] == "LINK_UP"
                        and cur["ll_up"] not in (None, "yes")):   # Live's own reading names the cause (st4 4 Nov)
                    x.update(kind="ifcp", cause=f"physical link up but no IFCP session (read by Live: {said})",
                             owner=x.get("owner") or "GPU / AFM vendor", check_kind=ln.get("kind") or "")
                elif stt != ln.get("state"):
                    x.update(kind="live", cause=f"read by Live: {said}", check_kind=ln.get("kind") or "")
                x["evidence"] = [f"Live {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}: {said}"] + list(ln.get("evidence") or [])[:6]
                x = live_read(x)                    # its ends as Live read them, the check's lines marked older (9 Nov)
            else:
                stt = "unknown"                     # as Live showed it, quarantined trays too (audit 4 Nov)
                x["cause"] = ("not read by Live (" + ("tray quarantined: no GPU to read" if ln.get("kind") == "tray_quarantined"
                                                       else "switch and tray not reached") + ")"
                              + (f" - the check said {ln.get('state')}" if ln.get("state") else ""))
            x["state"] = stt
            counts[stt] = counts.get(stt, 0) + 1
            links.append(x)
    bad = [{"node": n.split()[0], "error": f.get("error")} for n, f in st["followers"].items() if f.get("ok") is False]
    root = [dict({k: v for k, v in g.items() if k != "links"}, links=[f"{x['switch']} {x['sw_port']}" for x in g["links"]])
            for g in linkdiag.group_causes([x for x in links if x.get("state") != "unknown"])]
    d.update(links=links, time_utc=now, patterns=[], root_causes=root, not_checked=bad,
             live={"from_check": lv.check_time, "filled": lv.filled, "started": lv.started, "reconciles": lv.reconciles})
    out = state.results_dir / "link-check" / lv.rack_name / f"scan-{now}-live"
    out.mkdir(parents=True, exist_ok=True)
    (out / "link_check.json").write_text(json.dumps(d, indent=1))
    line = (f"{len(links)} GPU links: {counts.get('ok', 0)} ok, {counts.get('degraded', 0)} degraded, {counts.get('down', 0)} down"
            + (f", {counts['unknown']} not known" if counts.get("unknown") else "") + " (saved from Live)")
    (out / "report.txt").write_text(f"Scale-up link check saved from Live ({lv.rack_name})\n{line}\n"
                                    f"Live started from the check of {lv.check_time}; {lv.reconciles} re-read(s) of the rack.\n")
    return {"saved": f"link-check/{lv.rack_name}/{out.name}", "summary": line}


def stop_job(state: State, jid: str) -> dict:
    with state.lock:
        job = state.jobs.get(jid)
        if not job:
            raise BadRequest("no such job")
        if job["status"] == "running" and job["proc"] and not job.get("stopping"):
            # 'running' until the tool has exited: an isolate stopped here still brings its link back (minutes), and
            # no other run may start meanwhile
            job["stopping"] = True
            try:
                os.killpg(job["proc"].pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if job["tool"] != "isolate":              # an isolate is never killed: its restore must finish
                proc = job["proc"]

                def kill_later():
                    time.sleep(KILL_AFTER_S)
                    if proc.poll() is None:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                threading.Thread(target=kill_later, daemon=True).start()
        return public(job)


KILL_AFTER_S = 60
CODE_DIRS = ("tools", "heliosdbg", "ui")              # the source the guide links to (/code/<path>), read-only
CODE_TOP = ("README.md", "pyproject.toml", "docs/link-debug-guide.md", "inventory/example.yaml",
            "inventory/example-fullrack.yaml")


def code_files() -> list[str]:
    """The code a user may read or download from the UI: the tools, the library, the UI and the README / examples.
    Never inventories of real racks, results or backups."""
    out = [t for t in CODE_TOP if (ROOT / t).is_file()]
    for d in CODE_DIRS:
        for f in sorted((ROOT / d).rglob("*")):
            r = f.relative_to(ROOT).as_posix()
            if f.is_file() and f.suffix in (".py", ".sh") and "__pycache__" not in r and ".bak" not in r:
                out.append(r)
    return out


def code_file(path: str) -> Path:
    if path not in code_files():
        raise BadRequest("not a code file of helios-debug")
    return ROOT / path


def code_page(path: str) -> bytes:
    """One source file, line-numbered (#L<n> links to a line), with its download and the whole code as a zip."""
    import html as H
    lines = code_file(path).read_text(errors="replace").splitlines()
    rows = "".join(f"<tr id='L{n}'><td class=n><a href='#L{n}'>{n}</a></td><td><pre>{H.escape(t) or ' '}</pre></td></tr>"
                   for n, t in enumerate(lines, 1))
    others = "".join(f"<option{' selected' if f == path else ''}>{H.escape(f)}</option>" for f in code_files())
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,"
            f"initial-scale=1'><title>{H.escape(path)}</title><style>"
            ":root{--bg:#fbfbfa;--fg:#1d1f21;--mut:#5f6368;--line:#dcdcd8;--hl:#fff3c4;--acc:#0b6bcb}"
            "@media (prefers-color-scheme:dark){:root{--bg:#16181b;--fg:#e6e6e3;--mut:#8a8f94;--line:#33363b;"
            "--hl:#3d3618;--acc:#6aaef5}}"
            "body{margin:0;background:var(--bg);color:var(--fg);font:14px -apple-system,Segoe UI,Roboto,sans-serif}"
            "header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 16px;"
            "display:flex;gap:12px;flex-wrap:wrap;align-items:center}a{color:var(--acc)}"
            "select{max-width:100%;font:inherit}table{border-collapse:collapse;width:100%}"
            "td{vertical-align:top;padding:0}td.n{text-align:right;padding:0 10px;user-select:none;width:1%}"
            "td.n a{color:var(--mut);text-decoration:none;font:12px/1.5 ui-monospace,Menlo,monospace}"
            "pre{margin:0;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;"
            "overflow-wrap:anywhere}tr:target{background:var(--hl)}"
            f"</style></head><body><header><strong>{H.escape(path)}</strong><span style='color:var(--mut)'>"
            f"{len(lines)} lines, read-only</span><a href='/code/{H.escape(path)}?raw=1'>Download this file</a>"
            "<a href='/code.zip'>Download all the code (zip)</a>"
            "<select onchange=\"location.href='/code/'+this.value\" aria-label='Another file'>" + others + "</select>"
            f"</header><table>{rows}</table></body></html>").encode()


def code_zip() -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in code_files():
            z.write(ROOT / f, "helios-debug/" + f)
    return buf.getvalue()


JOBS_LOGS_KEEP = 200                                  # run logs (and pasted cabling plans) kept in ui-jobs/


def _prune_job_files(d: Path, jobs: dict) -> None:
    """Drop the oldest run logs and cabling plans beyond JOBS_LOGS_KEEP each, skipping runs still in memory."""
    live = {f"{j}.log" for j in jobs}
    for pat in ("*.log", "plan-*.csv"):
        try:
            files = sorted(d.glob(pat), key=lambda f: f.stat().st_mtime)
        except OSError:
            continue
        for f in files[:-JOBS_LOGS_KEEP]:
            if f.name not in live:
                try:
                    f.unlink()
                except OSError:
                    pass


JOBS_KEEP = 50                                        # finished runs kept in memory (up to 400 KB of log each)


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
                return self._send(200, PAGE, "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                              "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
            if u.path == "/api/term/read":                   # long poll: new output of one terminal
                import base64
                s = st.terms.get((q.get("id") or [""])[0])
                r = s.read(_qint(q, "since", 0), wait=15.0)
                return self._json(200, {"data": base64.b64encode(r["data"]).decode(), "next": r["next"],
                                        "closed": r["closed"], "dropped": r["dropped"]})
            if u.path == "/api/ai/status":
                from heliosdbg import ai, docsearch
                return self._json(200, ai.status() | {"docs": docsearch.sources()})
            if u.path == "/api/ai/feedback":
                from heliosdbg import feedback
                return self._json(200, feedback.stats(st.results_dir))
            if u.path == "/api/cases/tests":          # helios-tests results to ask about (any part of the rack)
                from heliosdbg import cases
                g = (lambda k: (q.get(k) or [""])[0][:120])
                rows = cases.tests(_qint(q, "limit", 400), g("outcome"), g("rack"), g("q"))
                return self._json(200, {"tests": rows, "dir": str(cases.tests_results()),
                                        "available": (cases.tests_results() / "index.csv").is_file()})
            if u.path == "/api/cases/reports":        # saved tool results other than link checks / Diagnose
                from heliosdbg import cases
                return self._json(200, {"reports": cases.reports(st.results_dir)})
            if u.path == "/api/cases/racks":          # the racks this machine has an inventory for (nodes for step by step)
                racks = []
                for f in sorted(st.inventory_dir.glob("*.yaml")):
                    try:
                        inv = load_inventory(f)
                        racks.append({"rack": inv.rack or f.stem, "nodes": [h.name for h in inv.all_switches + inv.all_computes]})
                    except Exception:  # noqa: BLE001
                        continue
                return self._json(200, {"racks": racks})
            if u.path == "/api/ai/resolutions":
                from heliosdbg import resolutions
                rack = (q.get("rack") or [""])[0]
                return self._json(200, {"resolutions": resolutions.load(st.results_dir, rack or None),
                                        "categories": resolutions.CATEGORIES})
            if u.path == "/api/term/list":
                return self._json(200, {"terminals": st.terms.list()})
            if u.path == "/api/version":
                return self._json(200, version_info(st))
            if u.path.startswith("/static/vendor/"):          # the bundled terminal emulator (xterm.js), nothing else
                name = u.path[len("/static/vendor/"):]
                f = VENDOR.get(name)
                if not f:
                    return self._json(404, {"error": "not found"})
                return self._send(200, f[1], f[0])
            if u.path == "/api/inventory/text":
                return self._json(200, inventory_text(st, (parse_qs(u.query).get("file") or [""])[0]))
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
                    return self._json(200, public(job, _qint(q, "since", 0)))
            if u.path == "/api/access":
                name = (q.get("inventory") or [""])[0]
                _f, inv = st.inventory(name)
                return self._json(200, access.describe(inv) | {"last_check": st.access_checks.get(name)})
            if u.path == "/topology":
                g = ROOT / "docs" / "scaleup-topology.html"
                if not g.is_file():
                    return self._json(404, {"error": "the topology page is not installed"})
                return self._send(200, g.read_bytes(), "text/html; charset=utf-8",   # self-contained: data + drawing, no fetches
                                  {"Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' "
                                                              "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
                                                              "img-src data:; frame-ancestors 'self'"})   # shown in the UI's Topology tab
            if u.path == "/code.zip":
                return self._send(200, code_zip(), "application/zip",
                                  {"Content-Disposition": 'attachment; filename="helios-debug-code.zip"'})
            if u.path.startswith("/code/"):
                path = unquote(u.path[len("/code/"):])
                if (q.get("raw") or [""])[0]:
                    return self._send(200, code_file(path).read_bytes(), "text/plain; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="{Path(path).name}"'})
                return self._send(200, code_page(path), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                                              "script-src 'unsafe-inline'; frame-ancestors 'self'"})
            if u.path == "/guide":
                g = ROOT / "docs" / "link-debug-guide.html"
                if not g.is_file():
                    return self._json(404, {"error": "the debug guide is not installed"})
                return self._send(200, g.read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"})
            if u.path == "/api/health/ticket":
                from heliosdbg import ticket
                run = _result_dir(st, (q.get("path") or [""])[0])
                if not (run / "health.json").is_file():
                    raise BadRequest("not a node health run")
                try:
                    md = ticket.health_finding(json.loads((run / "health.json").read_text()), _qint(q, "i", -1),
                                               f"results/{run.relative_to(st.results_dir)}/report.html")
                except (IndexError, ValueError) as e:
                    raise BadRequest(str(e)) from None
                return self._send(200, md.encode(), "text/markdown; charset=utf-8")
            if u.path == "/api/bundle":
                from heliosdbg import bundle
                rel = (q.get("path") or [""])[0]
                run = _result_dir(st, rel)
                if (q.get("finding") or [""])[0].isdigit() and (run / "health.json").is_file():
                    i = int(q["finding"][0])
                    try:
                        data, _stats = bundle.build_finding(run, i)
                    except IndexError:
                        raise BadRequest(f"finding {i}: not in this check") from None
                    return self._send(200, data, "application/zip",
                                      {"Content-Disposition": f'attachment; filename="{run.parent.name}-{run.name}-finding-{i + 1}.zip"'})
                data, _stats = bundle.build(run)
                return self._send(200, data, "application/zip",
                                  {"Content-Disposition": f'attachment; filename="{run.parent.name}-{run.name}.zip"'})
            if u.path == "/api/cabling.csv":
                from heliosdbg import cabling
                f, inv = st.inventory((q.get("inventory") or [""])[0])
                from heliosdbg import scans
                d, _folder = scans.newest(st.results_dir / "link-check" / (inv.rack or f.stem), full=True)
                if not d:
                    raise BadRequest("no check of the whole rack with links yet - run Check all links first")
                text = cabling.export(d.get("links") or [])
                return self._send(200, text.encode(), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{inv.rack or f.stem}-cabling.csv"'})
            if u.path == "/api/config/saved":
                return self._json(200, saved_configs(st, (q.get("inventory") or [""])[0], (q.get("node") or [""])[0]))
            if u.path == "/api/config/zip":
                data, name = config_zip(st, (q.get("inventory") or [""])[0], (q.get("stamp") or [""])[0])
                return self._send(200, data, "application/zip", {"Content-Disposition": f'attachment; filename="{name}"'})
            if u.path == "/api/overview":
                return self._json(200, {"racks": overview(st)})
            if u.path == "/api/live":
                return self._json(200, live_status(st, _qint(q, "since", 0)))
            if u.path == "/api/gpus":
                return self._json(200, gpus_view(st, (q.get("inventory") or [""])[0]))
            if u.path == "/api/port":
                return self._json(200, port_view(st, (q.get("path") or [""])[0], (q.get("key") or [""])[0]))
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
        except (BadRequest, TermError) as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            return self._json(500, {"error": f"{type(e).__name__}: {str(e)[:300]}"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, b"forbidden host", "text/plain")
        if self.headers.get("X-Helios-Debug") != "1" or "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._json(403, {"error": "missing X-Helios-Debug header / JSON body"})
        try:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise BadRequest("bad Content-Length") from None
            if n < 0 or n > (2_200_000 if urlparse(self.path).path == "/api/run" else 64_000):   # /api/run: a cabling plan
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
                    res = access.check(inv, names if isinstance(names, list) else None)
                    if not names:
                        self.state.access_checks[req.get("inventory", "")] = {"time": time.time(), "results": res}
                    return self._json(200, {"results": res})
                pw = req.pop("password", None)
                return self._json(200, access.install(inv, str(req.get("host", "")), str(pw or "")))
            if u.path == "/api/live/start":
                pw = req.pop("afm_password", None)
                return self._json(200, live_start(self.state, dict(req, afm_password=pw)))
            if u.path == "/api/scan/save":
                return self._json(200, save_scan(self.state, str(req.get("path") or "")))
            if u.path in ("/api/live/save-check", "/api/live/save-log"):
                return self._json(200, live_save(self.state, "check" if u.path.endswith("check") else "log"))
            if u.path == "/api/live/stop":
                with self.state.lock:
                    lv = self.state.live
                if lv is not None:
                    lv.stop("turned off in the UI")
                return self._json(200, {"running": False})
            if u.path == "/api/discover":
                pw = req.get("afm_password")
                req["afm_password"] = None
                return self._json(200, discover_rack(dict(req, afm_password=pw)))
            if u.path == "/api/inventory/save":
                return self._json(200, save_inventory(self.state, req))
            if u.path == "/api/inventory/lift_quarantine":
                return self._json(200, lift_quarantine(self.state, req))
            if u.path == "/api/cases/judge":          # the health rules on pasted outputs - no AI needed
                from heliosdbg import ai, cases, pasted
                try:
                    bs = cases.clean_blocks(req.get("blocks"))
                except ai.AIError as e:
                    raise BadRequest(str(e)) from None
                found, seen = pasted.judge_blocks(bs)
                return self._json(200, {"findings": found, "checked": seen})
            if u.path == "/api/ai/chat":
                return self._json(200, ai_chat(self.state, req))
            if u.path == "/api/ai/guide":
                return self._json(200, ai_guide(self.state, req))
            if u.path == "/api/ai/run":
                return self._json(200, ai_run(self.state, req))
            if u.path == "/api/ai/ticket":
                return self._json(200, ai_ticket(self.state, req))
            if u.path == "/api/ai/ask":
                return self._json(200, ai_ask(self.state, req))
            if u.path == "/api/ai/resolution":
                return self._json(200, ai_resolution(self.state, req))
            if u.path == "/api/ai/feedback":
                from heliosdbg import ai, feedback
                try:
                    r = feedback.record(self.state.results_dir, req, ai.RECENT)
                    push_to_hub("feedback", r)
                except feedback.FeedbackError as e:
                    raise BadRequest(str(e)) from None
                return self._json(200, {"saved": r["id"], "rating": r["rating"], **feedback.stats(self.state.results_dir)})
            if u.path == "/api/config":
                return self._json(200, node_config(self.state, req))
            if u.path == "/api/config/rack":
                return self._json(200, rack_config(self.state, req))
            if u.path == "/api/logins":
                return self._json(200, check_logins(self.state, req.get("inventory", "")))
            if u.path == "/api/term/open":
                _f, inv = self.state.inventory(req.get("inventory", ""))
                name = str(req.get("node", ""))
                host = next((h for h in inv.all_switches + inv.all_computes if h.name == name), None)
                if host is None:
                    raise BadRequest(f"no switch or compute tray {name!r} in {req.get('inventory')}")
                t = self.state.terms.open(host, inv.transport or {}, _int(req, "cols", 20, 500, 120), _int(req, "rows", 5, 200, 32))
                return self._json(200, {"id": t.id, "node": t.node, "how": t.how,
                                        "address": f"{host.user + '@' if host.user else ''}{host.host}"})
            if u.path == "/api/term/write":
                data = req.get("data")
                if not isinstance(data, str) or len(data) > 32_000:
                    raise BadRequest("data: text, at most 32 000 characters")
                self.state.terms.get(str(req.get("id", ""))).write(data.encode("utf-8", "surrogateescape"))
                return self._json(200, {"ok": True})
            if u.path == "/api/term/resize":
                self.state.terms.get(str(req.get("id", ""))).resize(_int(req, "cols", 20, 500, 120), _int(req, "rows", 5, 200, 32))
                return self._json(200, {"ok": True})
            if u.path == "/api/term/close":
                self.state.terms.close(str(req.get("id", "")))
                return self._json(200, {"ok": True})
            if u.path == "/api/access/keygen":
                return self._json(200, access.create_key())
            m = re.fullmatch(r"/api/job/([0-9a-f]{12})/stop", u.path)
            if m:
                return self._json(200, stop_job(self.state, m.group(1)))
            return self._json(404, {"error": "not found"})
        except (BadRequest, access.AccessError, TermError) as e:
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
    if not os.environ.get("HELIOS_DEBUG_NO_LOGIN_CHECK"):
        check_logins_at_start(Handler.state)
    print(f"helios-debug UI on http://127.0.0.1:{a.port}  (inventories: {a.inventory_dir}, results: {a.results_dir})")
    print(f"from your machine: ssh -L {a.port}:localhost:{a.port} <user>@{os.uname().nodename}  then http://localhost:{a.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
