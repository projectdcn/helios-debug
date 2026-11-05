"""Resolutions: what a problem turned out to be and what fixed it, written by the person who debugged it.

Each record keeps the evidence exactly as the AI saw it (the [E..] items of the link / check / Diagnose result) next
to the human-written cause and fix, so it is two things at once:
  * a "past resolution" the AI is shown when a similar problem comes up (looked up by link, then by words);
  * a training example for helios-slm (`python -m helios_slm.resai build`): the evidence in, the human answer out -
    the only real root-cause answers there are (the checker's own wording teaches the model nothing new).

Stored append-only in <results>/ai/resolutions.jsonl (one JSON object per line; a correction is a new record with
`replaces` = the old id). Nothing about the rack is changed by recording one.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

CATEGORIES = {
    "cabling": "cable / optic / seating (site)",
    "gpu": "GPU / AFM / IFCP (AMD)",
    "switch": "switch / SONiC (switch owner)",
    "config": "configuration (VLAN, vPOD, forwarding entries)",
    "env": "test environment / tooling",
    "transient": "went away by itself / not reproduced",
    "other": "other",
}
FILE = "resolutions.jsonl"


class ResolutionError(ValueError):
    pass


def _clean(s, n: int) -> str:
    return re.sub(r"[ \t]+", " ", str(s or "")).strip()[:n]


def record(results_dir: Path, rec: dict, ev=None, subject: str = "") -> dict:
    """Validate and append one resolution; returns the stored record (with id and time)."""
    cause, fix = _clean(rec.get("cause"), 2000), _clean(rec.get("fix"), 2000)
    if len(cause) < 10:
        raise ResolutionError("cause: say in a sentence what the problem turned out to be")
    cat = str(rec.get("category") or "other")
    if cat not in CATEGORIES:
        raise ResolutionError("category: " + ", ".join(CATEGORIES))
    path = str(rec.get("path") or "").strip("/")
    if path and not re.fullmatch(r"link-check/[A-Za-z0-9_.-]+/(scan|link)-[0-9]{8}-[0-9]{6}(?:-live)?", path):
        raise ResolutionError("path: link-check/<rack>/scan-... or link-...")
    steps = [{"node": _clean(s.get("node"), 80), "command": _clean(s.get("command"), 400),
              "output": str(s.get("output") or "")[:3000]} for s in (rec.get("steps") or []) if isinstance(s, dict)][:12]
    now = time.time()
    out = {
        "id": time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + f"-{int(now * 1000) % 1000:03d}",
        "time_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)),
        "rack": _clean(rec.get("rack") or (path.split("/")[1] if path else ""), 80),
        "path": path,
        "link": _clean(rec.get("link"), 80),
        "subject": _clean(subject or rec.get("subject"), 200),
        "category": cat,
        "cause": cause,
        "fix": fix,
        "confirmed": bool(rec.get("confirmed")),
        "by": _clean(rec.get("by"), 80),
        "replaces": _clean(rec.get("replaces"), 40),
        "ai_answer": str(rec.get("ai_answer") or "")[:6000],      # what the AI said before - to compare, not to train on
        "steps": steps,
        "verdict": getattr(ev, "verdict", None) if ev is not None else None,
        "evidence": [{"ref": x["ref"], "text": x["text"], "source": x.get("source", "")} for x in (ev.items if ev is not None else [])],
    }
    d = Path(results_dir) / "ai"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / FILE, "a") as fh:
        fh.write(json.dumps(out, ensure_ascii=False) + "\n")
    return out


def load(results_dir: Path, rack: str | None = None) -> list[dict]:
    """Every current resolution (a replaced one left out), newest first."""
    f = Path(results_dir) / "ai" / FILE
    if not f.is_file():
        return []
    recs = []
    for ln in f.read_text(errors="replace").splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("id"):
            recs.append(r)
    gone = {r["replaces"] for r in recs if r.get("replaces")}
    recs = [r for r in recs if r["id"] not in gone and (not rack or r.get("rack") == rack)]
    return sorted(recs, key=lambda r: r["id"], reverse=True)


def line(r: dict) -> str:
    """One resolution as an evidence line for the AI."""
    what = r.get("link") or r.get("subject") or "the rack"
    return (f"Past resolution ({r.get('time_utc', '')[:10]}, {r.get('rack')}, {what}"
            + (", confirmed" if r.get("confirmed") else ", not confirmed") + f"): {CATEGORIES.get(r.get('category'), '')} - "
            f"cause: {r.get('cause')}" + (f"; fixed by: {r['fix']}" if r.get("fix") else ""))


def similar(recs: list[dict], link: str = "", text: str = "", k: int = 2) -> list[dict]:
    """The resolutions most like a link / question: the same link first, then the best word matches."""
    if not recs:
        return []
    same = [r for r in recs if link and r.get("link") == link]
    rest = [r for r in recs if r not in same]
    picked = same[:k]
    if len(picked) < k and text and rest:
        from .docsearch import Index
        idx = Index([{"title": r.get("link") or r.get("subject") or "", "section": r.get("category", ""),
                      "text": f"{r.get('cause')} {r.get('fix')} " + " ".join(x["text"] for x in r.get("evidence", [])[:12]),
                      "_i": i} for i, r in enumerate(rest)])
        for hit in idx.search(text, k=k - len(picked), min_score=4.0):
            picked.append(rest[hit["_i"]])
    return picked
