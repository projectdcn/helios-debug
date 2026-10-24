"""Live link state of one rack (read-only, off by default - it keeps connections open).

  * switch trays: their syslog followed as a stream - 'Port EthernetN oper state set from up to down' and
    'Configure EthernetN admin status to down' change the link at once
  * compute trays: their kernel log followed - an 'ifoe <bdf>: ... link up / down' line re-reads that GPU's ports
    (afmctl show port), a few seconds later, once
  * every reconcile_s (300): a light re-read of everything - switch port status per ASIC, afmctl show port per GPU -
    catches what a stream missed (a restart, a dropped connection)
  * AFM (password given): its events polled every 30 s and listed with the changes
  * a rack reached through a jump host that allows few sessions (transport.jump.via: exec) gets no streams - the
    re-reads only - and says so
Stops by itself after max_s (8 h; None = until turned off) or when nobody has looked for idle_s (30 min; None = never). Changes are kept in memory (last
2000) and appended to results/live/<rack>-<UTC date>.jsonl.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from .afmctl import Afmctl
from .transport import build_command, is_local

SW_STREAM = ("tail -n0 -F /var/log/syslog | grep --line-buffered -E 'oper state set from|admin status to'")
TRAY_STREAM = ("journalctl -kf -n0 -o short-iso-precise | grep --line-buffered -E 'ifoe .*link (up|down)'")
OPER_RX = re.compile(r"Port (Ethernet\d+) oper state set from (\w+) to (\w+)")
ADMIN_RX = re.compile(r"portmgrd.*Configure (Ethernet\d+) admin status to (\w+)")
IFOE_RX = re.compile(r"ifoe ([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d)")
PHYSICAL = ("phys_never_up", "phys_went_down", "phys_no_optic", "one_sided", "sw_admin_down", "gpu_admin",
            "tray_unreachable")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


LOG_MIN_FREE = 200 << 20           # the change log stops writing below this much free space
STREAM_MAX_S = 24 * 3600          # one log stream's remote timeout; after it ends it is reopened


def wrap(cmd: str, max_s: float) -> str:
    """The remote / local command line of a stream: the pipeline runs in its own process group (setsid) under timeout;
    the wrapper then waits on its stdin - the SSH channel's pty, or our pipe - and when that closes (live mode turned
    off, connection lost) kills the whole group. MR3 c1 19 Oct: without this, 'journalctl -kf' outlived a closed
    channel until it next had a line to write."""
    inner = f"timeout {int(max_s) + 60} bash -c {shlex.quote(cmd)}"
    guard = (f"setsid bash -c {shlex.quote(inner)} & P=$!; "
             f"trap 'kill -- -$P 2>/dev/null; kill $P 2>/dev/null' EXIT HUP TERM INT; read -r _")   # also on a hang-up
    return build_command(guard, sudo=True)


class Stream:
    """A command whose output is read line by line: locally (Popen, stdin a pipe we hold) or over the node's SSH
    connection (a channel with a pty). Closing either ends the command and everything it started (see wrap)."""

    def __init__(self, node, cmd: str, max_s: float):
        self.node, self.proc, self.chan = node, None, None
        full = wrap(cmd, max_s)
        if is_local(node.host):
            self.proc = subprocess.Popen(["bash", "-c", full], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            self.lines = self.proc.stdout
        else:
            client = node.t._ensure()
            self.chan = client.get_transport().open_session()
            self.chan.get_pty()
            self.chan.exec_command(full)
            self.lines = self.chan.makefile("r")

    def close(self) -> None:
        try:
            if self.proc is not None:
                if self.proc.stdin:
                    self.proc.stdin.close()          # the wrapper's read ends -> it kills the pipeline's group
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.proc.pid, signal.SIGTERM)
            if self.chan is not None:
                try:
                    self.chan.sendall(b"\n")         # ends the wrapper's read; its trap kills the pipeline
                    time.sleep(0.3)
                except Exception:  # noqa: BLE001
                    pass
                self.chan.close()
        except Exception:  # noqa: BLE001 - already gone
            pass


def link_state(lk: dict, ifcp_in_use: bool) -> str:
    sw_down = lk.get("sw_oper") not in (None, "up")
    gpu_down = lk.get("gpu_link") not in (None, "LINK_UP")
    if sw_down or gpu_down:
        return "down"
    if lk.get("gpu_link") is None and not lk.get("bdf"):
        # the GPU end was never read (tray unreachable / not matched at the check): a switch port that is up says
        # nothing about the link - MR2 19 Oct from the switch, trays refusing the login, showed '288 ok'
        return "degraded" if lk.get("scan_kind") == "tray_not_programmed" else "unknown"
    if ifcp_in_use and lk.get("ll_up") not in (None, "yes"):
        return "degraded"
    if lk.get("scan_state") == "degraded" and lk.get("scan_kind") not in PHYSICAL:
        return "degraded"                          # e.g. not programmed, GPU not set up: not a link up/down matter
    return "ok"


class LiveRack:
    def __init__(self, rack, links: list[dict], *, rack_name: str, ifcp_in_use: bool = False, reconcile_s: float = 300,
                 max_s: float = 8 * 3600, idle_s: float = 1800, afm=None, log_dir: Path | None = None,
                 last_view=lambda: time.time(), stream_cls=Stream, jump_limited: bool = False):
        self.rack, self.rack_name, self.ifcp = rack, rack_name, ifcp_in_use
        self.reconcile_s, self.max_s, self.idle_s, self.afm = reconcile_s, max_s, idle_s, afm
        self.last_view, self.stream_cls, self.jump_limited = last_view, stream_cls, jump_limited
        self.lock = threading.RLock()
        self.stop_ev = threading.Event()
        self.started, self.stopped, self.stop_reason = time.time(), None, None
        self.links: dict[str, dict] = {}
        self.by_port: dict[tuple, str] = {}
        self.by_gpu: dict[tuple, list[str]] = {}
        for ln in links:
            k = f"{ln['switch']} {ln['sw_port']}"
            self.links[k] = {"switch": ln["switch"], "asic": ln.get("asic"), "sw_port": ln["sw_port"], "tray": ln.get("tray"),
                             "bdf": ln.get("bdf"), "gpu_port": ln.get("gpu_port"), "scan_state": ln.get("state"),
                             "scan_kind": ln.get("kind"), "sw_oper": None, "sw_admin": None, "gpu_link": None,
                             "gpu_admin": None, "ll_up": None, "state": ln.get("state"), "since": None}
            self.by_port[(ln["switch"], ln["sw_port"])] = k
            if ln.get("tray") and ln.get("bdf") and ln.get("gpu_port") is not None:
                self.by_gpu.setdefault((ln["tray"], ln["bdf"]), []).append(k)
        self.changes: deque = deque(maxlen=2000)
        self.seq = 0
        self.followers: dict[str, dict] = {}
        self.streams: list = []
        self.threads: list[threading.Thread] = []
        self.last_event = None
        self.reconciles = 0
        self.pending_gpu: dict[tuple, float] = {}
        self.log_path = (log_dir / f"{rack_name}-{datetime.now(timezone.utc):%Y%m%d}.jsonl") if log_dir else None
        self.log_paused = False
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ state changes
    def _set(self, k: str, field: str, value, source: str) -> None:
        with self.lock:
            lk = self.links.get(k)
            if lk is None or lk.get(field) == value:
                return
            old = lk.get(field)
            lk[field] = value
            before = lk["state"]
            lk["state"] = link_state(lk, self.ifcp)
            if old is not None:                      # the first fill is not a change
                self._record({"link": k, "what": field, "from": old, "to": value, "source": source})
            if lk["state"] != before:
                lk["since"] = _now()
                if old is not None or before not in (None, lk["state"]):
                    self._record({"link": k, "what": "state", "from": before, "to": lk["state"], "source": source})

    def _record(self, ch: dict) -> None:
        self.seq += 1
        ch = {"seq": self.seq, "t": _now(), **ch}
        self.changes.append(ch)
        self.last_event = ch["t"]
        if self.log_path and not self.log_paused:
            try:
                if self.seq % 50 == 1 and shutil.disk_usage(self.log_path.parent).free < LOG_MIN_FREE:
                    # a shared, nearly full disk (g02-g17 jump host /home: 4.9 GB, full twice in Oct): the change log
                    # stops, Live goes on in memory - a full disk breaks other users' files (known_hosts, 22 Oct)
                    self.log_paused = True
                    self.changes.append({"seq": self.seq, "t": ch["t"], "link": None, "what": "note", "from": None,
                                         "to": "change log paused: less "
                                         f"than {LOG_MIN_FREE >> 20} MB free on {self.log_path.parent}", "source": "live"})
                    return
                with self.log_path.open("a") as fh:
                    fh.write(json.dumps(ch) + "\n")
            except OSError:
                pass

    def note(self, text: str, source: str) -> None:
        with self.lock:
            self._record({"link": None, "what": "note", "from": None, "to": text, "source": source})

    # ------------------------------------------------------------------ line handlers
    def on_switch_line(self, switch: str, line: str) -> None:
        m = OPER_RX.search(line)
        if m and (switch, m.group(1)) in self.by_port:
            self._set(self.by_port[(switch, m.group(1))], "sw_oper", m.group(3).lower(), "switch log")
            return
        m = ADMIN_RX.search(line)
        if m and (switch, m.group(1)) in self.by_port:
            self._set(self.by_port[(switch, m.group(1))], "sw_admin", m.group(2).lower(), "switch log")

    def on_tray_line(self, tray: str, line: str) -> None:
        m = IFOE_RX.search(line)
        if m and (tray, m.group(1)) in self.by_gpu:
            with self.lock:
                self.pending_gpu.setdefault((tray, m.group(1)), time.monotonic() + 3)

    def apply_gpu_ports(self, tray: str, bdf: str, ports: list[dict], source: str) -> None:
        by = {int(p.get("id", p.get("port_id"))): p for p in ports}
        for k in self.by_gpu.get((tray, bdf), []):
            p = by.get(self.links[k]["gpu_port"])
            if p is None:
                continue
            st, sp = p.get("status") or {}, p.get("spec") or {}
            self._set(k, "gpu_link", st.get("link_status"), source)
            self._set(k, "gpu_admin", sp.get("admin_state"), source)
            self._set(k, "ll_up", (st.get("ifcp") or {}).get("ll_up"), source)

    # ------------------------------------------------------------------ workers
    def _follow(self, name: str, node, cmd: str, handler) -> None:
        f = self.followers[name]
        while not self.stop_ev.is_set():
            st = None
            try:
                st = self.stream_cls(node, cmd, min(self.max_s or STREAM_MAX_S, STREAM_MAX_S))   # a stream ends, is reopened
                with self.lock:
                    self.streams.append(st)
                f.update(ok=True, error=None, connected=_now())
                for line in st.lines:
                    if self.stop_ev.is_set():
                        break
                    f["events"] += 1
                    handler(node.host.name, line)
                if not self.stop_ev.is_set():
                    raise RuntimeError("stream ended")
            except Exception as e:  # noqa: BLE001 - reported, retried
                f.update(ok=False, error=f"{type(e).__name__}: {str(e)[:160]}")
            finally:
                if st is not None:
                    st.close()
                    with self.lock:
                        if st in self.streams:
                            self.streams.remove(st)
            self.stop_ev.wait(15)

    def _read_gpu(self, tray: str, bdf: str, source: str) -> None:
        self.apply_gpu_ports(tray, bdf, Afmctl(self.rack.computes[tray]).ports_raw(bdf), source)

    def reconcile(self, source: str = "re-read") -> None:
        for name, sw in self.rack.switches.items():
            asics = {lk["asic"] for lk in self.links.values() if lk["switch"] == name}
            for asic in asics:
                try:
                    for r in sw.interfaces_status(asic or None):
                        k = self.by_port.get((name, r.get("Interface")))
                        if k:
                            self._set(k, "sw_oper", str(r.get("Oper", "")).lower() or None, source)
                            self._set(k, "sw_admin", str(r.get("Admin", "")).lower() or None, source)
                    self.followers.setdefault(f"{name} re-read", {"kind": "re-read"}).update(ok=True, error=None)
                except Exception as e:  # noqa: BLE001
                    self.followers.setdefault(f"{name} re-read", {"kind": "re-read"}).update(ok=False, error=f"{type(e).__name__}: {str(e)[:160]}")
        for (tray, bdf) in list(self.by_gpu):
            if tray not in self.rack.computes:
                continue
            try:
                self._read_gpu(tray, bdf, source)
                self.followers.setdefault(f"{tray} re-read", {"kind": "re-read"}).update(ok=True, error=None)
            except Exception as e:  # noqa: BLE001
                self.followers.setdefault(f"{tray} re-read", {"kind": "re-read"}).update(ok=False, error=f"{type(e).__name__}: {str(e)[:160]}")
        self.reconciles += 1

    def _loop(self) -> None:
        next_rec, next_afm, afm_since = 0.0, 0.0, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        while not self.stop_ev.is_set():
            now = time.monotonic()
            if self.max_s is not None and time.time() - self.started > self.max_s:
                self.stop(f"stopped by itself after {self.max_s / 3600:.0f} h")
                break
            if self.idle_s is not None and time.time() - self.last_view() > self.idle_s:
                self.stop(f"stopped by itself: nobody looked for {self.idle_s / 60:.0f} min")
                break
            if now >= next_rec:
                self.reconcile("re-read" if self.reconciles else "first read")
                next_rec = now + self.reconcile_s
            with self.lock:
                due = [g for g, t in self.pending_gpu.items() if t <= now]
                for g in due:
                    del self.pending_gpu[g]
            for tray, bdf in due:
                try:
                    self._read_gpu(tray, bdf, "tray log")
                except Exception:  # noqa: BLE001 - the next re-read covers it
                    pass
            if self.afm is not None and now >= next_afm:
                next_afm = now + 30
                try:
                    items = self.afm.get(f"/events/v1/events?field-selector=meta.creation-time%3E{afm_since}").get("items") or []
                    for e in sorted(items, key=lambda x: (x.get("meta") or {}).get("creation-time") or ""):
                        afm_since = max(afm_since, ((e.get("meta") or {}).get("creation-time") or afm_since)[:19] + "Z")
                        if re.search(r"link|port", str(e.get("type")), re.I):
                            self.note(f"{e.get('type')}: {e.get('message')}", "afm")
                    self.followers.setdefault("afm events", {"kind": "afm"}).update(ok=True, error=None)
                except Exception as e:  # noqa: BLE001
                    self.followers.setdefault("afm events", {"kind": "afm"}).update(ok=False, error=f"{type(e).__name__}: {str(e)[:160]}")
            self.stop_ev.wait(1)

    def start(self) -> None:
        if not self.jump_limited:
            for name, sw in self.rack.switches.items():
                self.followers[f"{name} log"] = {"kind": "switch log", "events": 0, "ok": None, "error": None}
                self.threads.append(threading.Thread(target=self._follow, args=(f"{name} log", sw, SW_STREAM, self.on_switch_line), daemon=True))
            for name, ct in self.rack.computes.items():
                if any(t == name for t, _b in self.by_gpu):
                    self.followers[f"{name} log"] = {"kind": "tray log", "events": 0, "ok": None, "error": None}
                    self.threads.append(threading.Thread(target=self._follow, args=(f"{name} log", ct, TRAY_STREAM, self.on_tray_line), daemon=True))
        else:
            self.note("reached through a jump host with few sessions: no log streams, re-reads only", "live")
        self.threads.append(threading.Thread(target=self._loop, daemon=True))
        for t in self.threads:
            t.start()
        self.note(f"live mode on: {len(self.links)} links, re-read every {self.reconcile_s:.0f} s", "live")

    def stop(self, reason: str = "turned off") -> None:
        if self.stop_ev.is_set():
            return
        self.stop_ev.set()
        self.stopped, self.stop_reason = time.time(), reason
        with self.lock:
            for st in list(self.streams):
                st.close()
        self.note(f"live mode off: {reason}", "live")
        try:
            self.rack.close()
        except Exception:  # noqa: BLE001
            pass

    def status(self, since_seq: int = 0) -> dict:
        with self.lock:
            counts = {}
            for lk in self.links.values():
                counts[lk["state"] or "unknown"] = counts.get(lk["state"] or "unknown", 0) + 1
            return {"rack": self.rack_name, "running": not self.stop_ev.is_set(), "started": self.started,
                    "stopped": self.stopped, "stop_reason": self.stop_reason, "last_event": self.last_event,
                    "reconcile_s": self.reconcile_s, "reconciles": self.reconciles, "jump_limited": self.jump_limited,
                    "max_s": self.max_s, "idle_s": self.idle_s,
                    "followers": {k: dict(v) for k, v in self.followers.items()}, "counts": counts,
                    "links": {k: {"state": v["state"], "since": v["since"], "sw_oper": v["sw_oper"], "sw_admin": v["sw_admin"],
                                  "gpu_link": v["gpu_link"], "ll_up": v["ll_up"]} for k, v in self.links.items()},
                    "changes": [c for c in self.changes if c["seq"] > since_seq][-200:], "seq": self.seq}
