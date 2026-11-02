"""Health over time: what changed since the rack's previous health check - new findings, findings gone, and the
same finding with a number that grew (corrected ECC errors, a disk filling up, a CRM table climbing, more kernel
error lines) - plus one line per run in health-history.jsonl and pruning of old runs (the jump host's /home is
small: g02-g17, 4.9 GB shared).
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

HISTORY = "health-history.jsonl"


def key(f: dict) -> str:
    """A finding's identity across runs: node, check, area and its text with the numbers taken out."""
    node = f.get("node", "")
    if " of " in node or node.endswith(" trays"):          # a rack-wide finding: '3 of 18 trays' -> its count changes
        node = re.sub(r"\d+", "#", node)
    return "|".join([node, f.get("check", ""), f.get("area", ""), re.sub(r"\d+(?:\.\d+)?", "#", f.get("what", ""))])


def _numbers(text: str) -> list[float]:
    return [float(x) for x in re.findall(r"\d+(?:\.\d+)?", text or "")]


def previous(rack_dir: Path, current: Path | None = None) -> dict | None:
    """The newest earlier health.json of this rack (health-<UTC stamp> folders sort by time)."""
    runs = sorted(p for p in rack_dir.glob("health-*/health.json") if current is None or p.parent != current)
    for p in reversed(runs):
        try:
            return json.loads(p.read_text()) | {"_dir": p.parent.name}
        except (OSError, ValueError):
            continue
    return None


def compare(prev: dict | None, res: dict) -> dict:
    """{since, new, gone, grew, same} - findings by key; 'grew' when a number in the same finding went up."""
    if not prev:
        return {"since": None, "new": [], "gone": [], "grew": [], "same": 0}
    # only nodes checked both times are compared (a run of three trays after a full-rack run says nothing about the
    # other fifteen), and a node not reached now cannot have 'resolved' its findings
    both = (set(prev.get("nodes") or {}) & set(res.get("nodes") or {})) - set(res.get("unreachable") or [])

    def ours(f):
        names = f.get("nodes") or [f.get("node")]
        return not (prev.get("nodes") and res.get("nodes")) or all(n in both for n in names)
    # per node, before the rack-wide grouping: '4 of 18 trays' today and a single tray yesterday are the same findings
    before = {key(f): f for f in prev.get("node_findings") or prev.get("findings") or [] if ours(f)}
    now_all = {key(f): f for f in res.get("node_findings") or res.get("findings") or []}
    now = {k: f for k, f in now_all.items() if ours(f)}
    unreached = set(res.get("unreachable") or [])
    grew = []
    for k in now.keys() & before.keys():
        a, b = _numbers(before[k]["what"]), _numbers(now[k]["what"])
        if len(a) == len(b) and any(y > x for x, y in zip(a, b)):
            grew.append({"node": now[k]["node"], "check": now[k]["check"], "before": before[k]["what"],
                         "now": now[k]["what"]})
    return {"since": prev.get("time"), "since_dir": prev.get("_dir"),
            "new": [now[k] for k in now.keys() - before.keys()],
            "gone": [before[k] for k in before.keys() - now.keys() if before[k].get("node") not in unreached],
            "grew": grew, "same": len(now.keys() & before.keys()),
            "not_compared": len(now_all) - len(now)}


def text(ch: dict) -> list[str]:
    """report.txt lines for the changes."""
    if not ch.get("since"):
        return ["== CHANGES: first health check of this rack here (nothing to compare with)", ""]
    out = [f"== CHANGES since {ch['since']} UTC: {len(ch['new'])} new, {len(ch['gone'])} gone, "
           f"{len(ch['grew'])} grew, {ch['same']} unchanged"]
    out += [f"+ NEW {f['severity']}: {f['node']}: {f['what']}" for f in ch["new"]]
    out += [f"^ GREW: {g['node']}: {g['before']}  ->  {g['now']}" for g in ch["grew"]]
    out += [f"- GONE: {f['node']}: {f['what']}" for f in ch["gone"]]
    return out + [""]


def record(rack_dir: Path, res: dict, run_dir: Path) -> None:
    """One line per run: time, folder, counts, the keys of the findings (for trends without reading every run)."""
    line = {"time": res.get("time"), "dir": run_dir.name, "summary": res.get("summary"),
            "unreachable": res.get("unreachable"), "changes": {k: len(v) if isinstance(v, list) else v
                                                               for k, v in (res.get("changes") or {}).items()
                                                               if k in ("new", "gone", "grew", "same")},
            "findings": sorted(key(f) for f in res.get("findings") or [])}
    with open(rack_dir / HISTORY, "a") as fh:
        fh.write(json.dumps(line) + "\n")


def prune(rack_dir: Path, keep: int) -> list[str]:
    """Keep the newest `keep` health runs whole; of older ones keep only health.json (what history compares with).
    Returns the folders thinned."""
    if keep <= 0:
        return []
    runs = sorted(p for p in rack_dir.glob("health-*") if p.is_dir())
    thinned = []
    for d in runs[:-keep]:
        extra = [p for p in d.iterdir() if p.name != "health.json"]
        if not extra:
            continue
        for p in extra:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
        thinned.append(d.name)
    return thinned
