"""What sits around one link (read-only): the switch's afm-agent and the node agent of the tray's slot, the clocks of
both ends (NTP and their offset - what the timeline's times can be trusted to), the switch port's VLAN mode, the
GPU's IFCP / config state. A link can be fine and the control plane around it not (and the other way round).
"""
from __future__ import annotations

import re
import time

from .rack import fan_out


def _clock(node) -> dict:
    t0 = time.time()
    out = node.sh("timedatectl show -p NTPSynchronized --value 2>/dev/null; date +%s.%N", timeout=30).split()
    t1 = time.time()
    remote = float(out[-1]) if out else None
    return {"ntp": (out[0] == "yes") if len(out) > 1 else None,
            "offset_s": (remote - (t0 + t1) / 2) if remote else None, "rtt_s": t1 - t0}


def collect(sw, tray, slot: int | None, ln, switches_in_rack: int = 1) -> list[dict]:
    """[{check, ok (True / False / None = unknown), detail}]"""
    checks: list[dict] = []

    def add(name, ok, detail):
        checks.append({"check": name, "ok": ok, "detail": detail})

    try:
        r = sw.sh("sudo docker ps --filter name=afm-agent --format '{{.Status}}'; echo @@; "
                  "sudo docker exec afm-agent ps -eo pid,etimes,args 2>/dev/null", timeout=60)
        status, _, ps = r.partition("@@")
        add("afm-agent on the switch", status.strip().startswith("Up"), status.strip() or "container not running")
        add("switch-agent process", bool(re.search(r"/switch-agent\b", ps)), "running" if "/switch-agent" in ps else "not found in afm-agent")
        if slot is not None:
            m = re.search(rf"^\s*\d+\s+(\d+)\s+\S*sb-node-agent\s+-slot-id\s+{slot}\b.*?(?:-controllers\s+(\S+))?$", ps, re.M)
            add(f"node agent of slot {slot}", True if m else (False if switches_in_rack == 1 else None),
                (f"on {ln.switch}, up {int(m.group(1)) // 60} min" + (f", controllers {m.group(2)}" if m.group(2) else ""))
                if m else (f"not running on {ln.switch}, the rack's only switch tray (MR2 19 Oct: switch-agent only) - "
                           "the tray's GPUs have no node agent" if switches_in_rack == 1 else
                           f"not on {ln.switch} (it may run on another switch tray of the rack)"))
    except Exception as e:  # noqa: BLE001
        add("afm-agent on the switch", None, f"not read: {type(e).__name__}: {str(e)[:120]}")
    clocks = {}
    for node, val, exc in fan_out(_clock, [n for n in (sw, tray) if n is not None]):
        clocks[node.host.name] = val if not exc else {"error": f"{type(exc).__name__}: {str(exc)[:100]}"}
    for name, c in clocks.items():
        if c.get("error"):
            add(f"clock of {name}", None, c["error"])
        else:
            add(f"clock of {name}", c["ntp"], f"NTP {'synchronised' if c['ntp'] else 'NOT synchronised'}")
    names = list(clocks)
    if len(names) == 2 and all(clocks[n].get("offset_s") is not None for n in names):
        d = clocks[names[1]]["offset_s"] - clocks[names[0]]["offset_s"]
        add("clock offset between the ends", abs(d) < 2.0,
            f"{names[1]} is {d:+.1f} s from {names[0]} (timeline times of the two sides are off by this much)")
    add("static forwarding entry", None if ln.sw_oper is None else (ln.fdb_static or None),
        "static forwarding entry present" if ln.fdb_static else "no static forwarding entry for this port (not programmed by AFM, or no vPOD)")
    g = ln.gpu or {}
    i = g.get("ifcp") or {}
    if g:
        add("IFCP session", i.get("ll_up") == "yes",
            f"ll_up {i.get('ll_up')}, peer_enabled {i.get('peer_enabled')}, errors {i.get('in_error')}/{i.get('peer_in_error')}")
    return checks
