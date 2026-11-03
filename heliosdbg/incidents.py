"""Health findings to the AIOps incident API (helios-slm, POST /api/v1/incidents/explain; docs/incident-api.md there):
each finding becomes an incident - the finding as its alert, the outputs it rests on as evidence - so the incident
brain explains, groups and keeps it with the rest, without the AIOps platform collecting anything itself.

An incident's id is made from the rack and the finding's identity (history.key: node, check, area, its text without
numbers), so the same finding sent again on the next run replaces its incident instead of adding one.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from .history import key

PATH = "/api/v1/incidents/explain"


def incident_id(rack: str, f: dict) -> str:
    return "hd-" + (rack or "rack").replace(" ", "-")[:20] + "-" + hashlib.sha1(f"{rack}|{key(f)}".encode()).hexdigest()[:12]


def to_incident(f: dict, rack: str, started: str) -> dict:
    labels = {k: str(f[k]) for k in ("node", "check", "area", "owner") if f.get(k)}
    labels["rack"] = rack
    evidence = []
    if f.get("evidence"):
        evidence.append({"source": f["node"], "title": f.get("command") or f["check"],
                         "text": "\n".join(f["evidence"])[:6000]})
    evidence.append({"source": "helios-debug", "title": f"health rule {f['check']} ({f['area']})",
                     "text": f"finding: {f['what']}\nlikely cause (rule): {f.get('cause') or '-'}\nnext (rule): "
                             f"{f.get('next') or '-'}\nowner: {f.get('owner') or '-'}"
                             + (f"\nnodes: {', '.join(f['nodes'])}" if f.get("nodes") else "")})
    return {"id": incident_id(rack, f), "rack": rack, "title": f"{f['node']}: {f['what']}"[:200], "started": started,
            "alerts": [{"name": f"helios-debug {f['check']}", "severity": f["severity"], "source": "helios-debug",
                        "labels": labels, "summary": f["what"][:300]}],
            "evidence": evidence}


def send(base_url: str, incs: list[dict], timeout: float = 120) -> list[dict]:
    """POST each incident; [{id, ok, area, summary, problems | error}]. One refused incident does not stop the rest;
    the API not answering at all does (10 x 120 s held a health run - and --every - for 20 minutes)."""
    out, away = [], None
    for inc in incs:
        if away:
            out.append({"id": inc["id"], "ok": False, "error": f"not sent: {away}"})
            continue
        req = urllib.request.Request(base_url.rstrip("/") + PATH, data=json.dumps(inc).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read())
            ex = d.get("explanation") or {}
            out.append({"id": d.get("id") or inc["id"], "ok": True, "area": ex.get("area"),
                        "summary": ex.get("summary"), "problems": (d.get("checks") or {}).get("problems") or []})
        except urllib.error.HTTPError as e:
            out.append({"id": inc["id"], "ok": False, "error": f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"})
        except Exception as e:  # noqa: BLE001 - the API away / slow: reported, the health run stands
            out.append({"id": inc["id"], "ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"})
            if isinstance(e, (urllib.error.URLError, TimeoutError, ConnectionError, OSError)):
                away = f"the API did not answer ({type(e).__name__})"
    return out


def pick(res: dict, every: bool = False, max_n: int = 10) -> tuple[list[dict], int]:
    """(findings to send, how many left out): the new ones since the last run (all on a first run, or with every),
    critical first, at most max_n."""
    ch = res.get("changes") or {}
    # per-node findings on every run (a first run sent the rack-wide '4 of 18 trays' ones, later runs per-node ones:
    # one problem, two incident ids); older health.json without them: the grouped findings
    pool = (res.get("node_findings") or res["findings"]) if every or not ch.get("since") else ch.get("new") or []
    pool = sorted(pool, key=lambda f: (f["severity"] != "critical", f["node"], f["check"]))
    return pool[:max_n], max(0, len(pool) - max_n)
