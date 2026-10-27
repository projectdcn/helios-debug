"""👍 / 👎 on the AI's answers, with the correct answer when it was wrong.

Each record keeps the exact messages the model was sent (ai.RECENT, by answer id) next to its answer, the rating and
the person's correction, so helios-slm can train on them (`python -m helios_slm.feedback build`):
  * 👎 + a correction -> a preference pair (prompt, chosen = the correction, rejected = the model's answer) for DPO,
    and an SFT example (prompt -> the correction);
  * 👍 -> the answer confirmed as good (an SFT example, and the 'chosen' side when the same prompt also got a 👎).
Stored append-only in <results>/ai/feedback.jsonl. Nothing on the rack is changed.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

FILE = "feedback.jsonl"


class FeedbackError(ValueError):
    pass


def _clean(s, n: int) -> str:
    return re.sub(r"[ \t]+", " ", str(s or "")).strip()[:n]


def record(results_dir: Path, req: dict, recent: dict) -> dict:
    rating = str(req.get("rating") or "")
    if rating not in ("up", "down"):
        raise FeedbackError("rating: up or down")
    aid = str(req.get("answer_id") or "")
    src = recent.get(aid) or {}
    if not src:
        raise FeedbackError("that answer is no longer known to this UI (it was restarted) - ask again, then rate it")
    correction = str(req.get("correction") or "").strip()[:6000]
    guided = any("guiding an investigation step by step" in str(m.get("content") or "") for m in src.get("messages") or []
                 if m.get("role") == "system")
    if guided and correction and not correction.lstrip().startswith("{"):   # a step-by-step conclusion is answered in JSON
        cause, _, nxt = correction.partition("\nNext:")
        correction = json.dumps({"done": True, "conclusion": cause.strip(), "next": nxt.strip()})
    now = time.time()
    out = {
        "id": time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + f"-{int(now * 1000) % 1000:03d}",
        "time_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)),
        "answer_id": aid,
        "rating": rating,
        "correction": correction,
        "comment": _clean(req.get("comment"), 1000),
        "by": _clean(req.get("by"), 80),
        "rack": _clean(req.get("rack"), 80),
        "path": _clean(req.get("path"), 200),
        "link": _clean(req.get("link"), 80),
        "subject": src.get("subject", ""),
        "model": src.get("model", ""),
        "answer": src.get("answer", ""),
        "messages": src.get("messages") or [],
    }
    d = Path(results_dir) / "ai"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / FILE, "a") as fh:
        fh.write(json.dumps(out, ensure_ascii=False) + "\n")
    return out


def load(results_dir: Path) -> list[dict]:
    f = Path(results_dir) / "ai" / FILE
    out = []
    for ln in (f.read_text(errors="replace").splitlines() if f.is_file() else []):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("rating") in ("up", "down"):
            out.append(r)
    return out


def stats(results_dir: Path) -> dict:
    rs = load(results_dir)
    return {"ratings": len(rs), "up": sum(r["rating"] == "up" for r in rs), "down": sum(r["rating"] == "down" for r in rs),
            "corrections": sum(bool(r.get("correction")) for r in rs)}
