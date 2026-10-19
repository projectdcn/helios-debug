"""One timeline for one link: what both ends and AFM logged about it, and who changed it (read-only).

  switch syslog    portmgrd 'Configure EthernetN admin status to down' (CONFIG_DB admin change), orchagent 'oper
                   state set from up to down', xcvrd/DomInfo flap_count, link-training failures, VLAN member / static
                   FDB add and remove
  switch auth.log  sudo COMMAND=... naming the port: who ran 'config interface ... shutdown EthernetN' (MR3 19 Oct:
                   admin, 03:06:36)
  tray journal     kernel lines of that GPU (ifoe <bdf>: ...) and afmctl's disruptive actions (port admin state,
                   device reset)
  AFM              events naming the switch port (PortName EthernetN) or the GPU port (acc-id: A, port-id: P), and
                   audit records naming the switch port (only with the AFM view)
Times are UTC. Lines are filtered on the node (grep), so only a few hundred come back.
"""
from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timedelta, timezone

SW_PATTERNS = (r"admin status to|oper state set from|flap_count|LinkTraining|LT failure|link training|"
               r"Add member .* to VLAN|Remove member|FDB (SET|DEL)|Remove bridge port|Add bridge port|"
               r"transceiver|xcvr.*(insert|remov|plug)")
MAX_LINES = 800
CHANGES = re.compile(r"\bconfig\b|shutdown|startup|\bhset\b|\bhdel\b|\bdel\b|ip link set|portconfig|sfputil|reset|"
                     r"\bmtu\b|\bspeed\b|\bfec\b", re.I)
READ_ONLY = re.compile(r"^\S*(z?grep|cat|head|tail|show|journalctl|ls|date)\b|\bshow\b|config_db\.json")


def _sw_cmd(port: str, hours: int) -> str:
    p = shlex.quote(port)
    files = "/var/log/syslog /var/log/syslog.[0-9]* /var/log/auth.log /var/log/auth.log.[0-9]*"
    return (f"sudo zgrep -h -w {p} {files} 2>/dev/null | grep -E {shlex.quote(SW_PATTERNS + '|COMMAND=')} "
            f"| sort -k1,1n -k2,2M -k3,3n -k4,4 | tail -n {MAX_LINES}; echo '@@NOW'; date -u '+%Y %b %d %H:%M:%S'")


def _tray_cmd(bdf: str, hours: int) -> str:
    b = shlex.quote(bdf)
    return (f"sudo journalctl -o short-iso-precise --utc --since '-{int(hours)}h' --no-pager -k 2>/dev/null | grep -F {b} | tail -n 300; "
            f"sudo journalctl -o short-iso-precise --utc --since '-{int(hours)}h' --no-pager -t afmctl 2>/dev/null "
            f"| grep -F 'kind=disruptive' | grep 'phase=end' | tail -n 300")


SW_LINE = re.compile(r"^(\d{4} \w{3} +\d+ \d\d:\d\d:\d\d(?:\.\d+)?) \S+ (\w+) ([^:]+): (?::- )?(.*)$")
ISO_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:[.,]\d+)?)(?:[+-]\d\d:?\d\d|Z)? \S+ ([^:]+): (.*)$")


def _sw_time(s: str) -> datetime | None:
    s = re.sub(r"\.\d+$", "", s)
    try:
        return datetime.strptime(s, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def classify_switch(proc: str, msg: str) -> tuple[str, str]:
    if "COMMAND=" in msg:
        who = re.search(r"^\s*(\S+)\s*:", msg)
        cmd = msg.split("COMMAND=", 1)[1]
        if READ_ONLY.search(cmd) or not CHANGES.search(cmd):
            return "other", cmd[:160]           # reads (this tool's own greps, show ...) are not part of the story
        return "command", f"{who.group(1) if who else '?'} ran: {cmd}"
    m = re.search(r"admin status to (\w+)", msg)
    if m and "portmgrd" in proc:
        return "admin", f"admin {m.group(1)} written (CONFIG_DB, portmgrd)"
    m = re.search(r"oper state set from (\w+) to (\w+)", msg)
    if m:
        return "oper", f"link {m.group(1)} -> {m.group(2)}"
    m = re.search(r"'flap_count': '(\d+)'", msg)
    if m:
        return "flap", f"flap count {m.group(1)}"
    if re.search(r"LT failure|LinkTraining|link training", msg, re.I):
        return "training", msg[:160]
    if re.search(r"Remove member|FDB DEL|Remove bridge port", msg):
        return "unprogram", msg[:160]
    if re.search(r"Add member|FDB SET|Add bridge port", msg):
        return "program", msg[:160]
    return "other", msg[:160]


def parse_switch(text: str, since: datetime) -> list[dict]:
    out, seen_flap = [], None
    for ln in text.splitlines():
        if ln.startswith("@@NOW"):
            break
        m = SW_LINE.match(ln)
        if not m:
            continue
        t = _sw_time(m.group(1))
        if t is None or t < since:
            continue
        kind, text_ = classify_switch(m.group(3), m.group(4))
        if kind == "admin" and "admin status to" in m.group(4) and "orchagent" in m.group(3):
            continue
        if kind == "flap":                      # DomInfoUpdateTask repeats the same count: keep changes only
            if text_ == seen_flap:
                continue
            seen_flap = text_
        if kind == "other":
            continue
        out.append({"t": t.isoformat(), "side": "switch", "source": m.group(3).strip(), "kind": kind, "text": text_})
    return out


def parse_tray(text: str, since: datetime) -> list[dict]:
    out = []
    for ln in text.splitlines():
        m = ISO_LINE.match(ln.strip())
        if not m:
            continue
        try:
            t = datetime.fromisoformat(m.group(1).replace(",", ".")).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if t < since:
            continue
        src, msg = m.group(2).strip(), m.group(3)
        if src.startswith("afmctl"):
            cmd = re.search(r'cmd="([^"]*)"', msg)
            st = re.search(r"status=(\S+)", msg)
            who = re.search(r"user=(\S+)", msg)
            out.append({"t": t.isoformat(), "side": "tray", "source": "afmctl", "kind": "command",
                        "text": f"{who.group(1) if who else '?'} ran: {cmd.group(1) if cmd else msg[:120]} (status {st.group(1) if st else '?'})"})
        else:
            kind = "error" if re.search(r"fail|error|timeout", msg, re.I) else "driver"
            out.append({"t": t.isoformat(), "side": "tray", "source": src, "kind": kind, "text": msg[:200]})
    return _collapse(out)


def _collapse(evs: list[dict], window_s: float = 5.0) -> list[dict]:
    """Repeated identical driver lines within a few seconds -> one line with a count."""
    out = []
    for e in evs:
        key = (e["side"], e["kind"], re.sub(r"0x[0-9a-f]+", "", e["text"]))
        if out and out[-1].get("_k") == key and \
                (datetime.fromisoformat(e["t"]) - datetime.fromisoformat(out[-1]["_last"])).total_seconds() <= window_s:
            out[-1]["count"] = out[-1].get("count", 1) + 1
            out[-1]["_last"] = e["t"]
            continue
        out.append(dict(e, _k=key, _last=e["t"]))
    for e in out:
        e.pop("_k", None)
        e.pop("_last", None)
    return out


def afm_events(afm, sw_port: str, acc: str | None, gpu_port: int | None, since: datetime) -> list[dict]:
    """AFM events naming this switch port or this GPU port, and audit records naming the switch port."""
    iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    word = re.compile(rf"\b{re.escape(sw_port)}\b")
    gpu = re.compile(rf"acc-id:\s*{re.escape(str(acc))}\s*,\s*port-id:\s*{gpu_port}\b") if acc not in (None, "") and gpu_port is not None else None
    for path, kind in ((f"/events/v1/events?field-selector=meta.creation-time%3E{iso}", "afm event"),
                       (f"/audit/v1/events?field-selector=meta.creation-time%3E{iso}", "afm audit")):
        try:
            items = afm.get(path).get("items") or []
        except Exception as e:  # noqa: BLE001 - the rest of the timeline stands without it
            out.append({"t": since.isoformat(), "side": "afm", "source": kind, "kind": "error", "text": f"not read: {e}"})
            continue
        for e in items:
            ts = (e.get("meta") or {}).get("creation-time") or ""
            body = json.dumps(e) if kind == "afm audit" else str(e.get("message") or "")
            if not (word.search(body) or (gpu and gpu.search(body))):
                continue
            try:
                t = datetime.fromisoformat(ts.replace("Z", "+00:00")[:26] + ("+00:00" if "+" not in ts[19:] else ""))
            except ValueError:
                t = since
            if t < since:
                continue
            if kind == "afm event":
                text = f"{e.get('type')}: {e.get('message')}"
            else:
                text = f"{(e.get('user') or {}).get('name', '?')} {e.get('action')} {(e.get('resource') or {}).get('kind')} " \
                       f"{(e.get('resource') or {}).get('name') or ''}"
            out.append({"t": t.isoformat(), "side": "afm", "source": kind, "kind": e.get("type") or e.get("action") or "afm",
                        "text": text[:240]})
    return out


def collect(sw, sw_port: str, tray, bdf: str | None, acc: str | None, gpu_port: int | None, hours: int = 24,
            afm=None) -> dict:
    """{events: [...] sorted by time, errors: {side: message}, since}."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    evs, errors = [], {}
    try:
        evs += parse_switch(sw.sh(_sw_cmd(sw_port, hours), timeout=180), since)
    except Exception as e:  # noqa: BLE001
        errors["switch"] = f"{type(e).__name__}: {str(e)[:200]}"
    if tray is not None and bdf:
        try:
            evs += parse_tray(tray.sh(_tray_cmd(bdf, hours), timeout=180), since)
        except Exception as e:  # noqa: BLE001
            errors["tray"] = f"{type(e).__name__}: {str(e)[:200]}"
    if afm is not None:
        evs += afm_events(afm, sw_port, acc, gpu_port, since)
    evs.sort(key=lambda e: e["t"])
    return {"since": since.isoformat(), "hours": hours, "events": evs, "errors": errors}


def summary(tl: dict) -> list[str]:
    ev = tl["events"]
    n = lambda k: sum(1 for e in ev if e["kind"] == k)  # noqa: E731
    lines = [f"{len(ev)} events in the last {tl['hours']} h: {n('oper')} link changes, {n('admin')} admin changes, "
             f"{n('command')} commands, {sum(1 for e in ev if e['side'] == 'afm')} AFM records, "
             f"{sum(1 for e in ev if e['side'] == 'tray')} tray lines"]
    cmds = [e for e in ev if e["kind"] == "command" and e["side"] == "switch"]
    if cmds:
        lines.append(f"last switch command on this port: {cmds[-1]['t'][:19]} {cmds[-1]['text'][:160]}")
    admin = [e for e in ev if e["kind"] == "admin"]
    if admin and not cmds:
        lines.append(f"admin changes with no matching command in auth.log ({len(admin)}): written to CONFIG_DB by something "
                     "other than the CLI (an agent / script) - see the timeline")
    return lines
