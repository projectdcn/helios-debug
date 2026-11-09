"""Can this UI log into every node of a rack? One `true` per node, with the inventory's own user and key - read-only.

9 Nov 2026: the jump host's UI had logged into the g02-g17 switches as tenant_hpe; the switches refused it from 2 Nov
(the laptop's inventory was changed to admin then, the installer keeps the jump host's own inventory), and every
switch command from that UI failed 'Authentication failed' for a week without anything saying so.
"""
from __future__ import annotations

import time

from . import reach
from .rack import Rack, fan_out


REFUSED = ("login_refused", "host_key")       # the node answered and said no: the inventory's user / key / known_hosts


def _one(item):
    role, node = item
    t0 = time.time()
    r = node.t.run("true", timeout=25)
    if r.rc != 0:
        raise RuntimeError(f"rc={r.rc} {(r.stderr or r.stdout or '').strip()[:300]}")
    return round(time.time() - t0, 1)


def check(inv, workers: int = 4) -> dict:
    """{rack, time, nodes: [{node, role, user, host, ok, kind, what, next, seconds}], refused, unreachable}."""
    rack = Rack(inv)
    items = [("switch", n) for n in rack.switches.values()] + [("compute", n) for n in rack.computes.values()]
    rows = []
    try:
        for (role, node), secs, exc in fan_out(_one, items, workers=workers):
            h = node.host
            row = {"node": h.name, "role": role, "user": getattr(h, "user", "") or "", "host": h.host, "ok": exc is None,
                   "seconds": secs}
            if exc is not None:
                acc = reach.classify(str(exc) if isinstance(exc, RuntimeError) else exc, row["user"], h.host)
                row.update(kind=(acc or {}).get("kind") or "error", what=(acc or {}).get("what") or str(exc)[:200],
                           next=(acc or {}).get("next") or "")
            rows.append(row)
    finally:
        rack.close()
    rows.sort(key=lambda r: (r["role"] != "switch", r["node"]))
    refused = [r["node"] for r in rows if not r["ok"] and r.get("kind") in REFUSED]
    return {"rack": inv.rack, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "nodes": rows,
            "refused": refused, "unreachable": [r["node"] for r in rows if not r["ok"] and r["node"] not in refused]}
