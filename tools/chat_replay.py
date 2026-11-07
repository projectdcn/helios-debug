#!/usr/bin/env python3
"""Ask the chat's questions again - after a model is promoted or the chat's code changed - and say which answers have
that disagrees with the exact lines, or whose exact lines changed.

The questions: the ones people asked (results/ai/chat.jsonl, newest first, one per question and rack), else the
starter set in tools/chat_questions.txt. Each is asked against the same saved link check it was first answered from
(the newest full one for the starter set), through the UI's own chat code and the model the UI uses (HELIOS_AI_URL /
HELIOS_AI_MODEL) - nothing on the rack is read or changed. The report: results/ai/replay-<UTC>.jsonl.

    python tools/chat_replay.py --inventory g02-g17.local.yaml [--n 30] [--questions FILE]
Exit status 1 when an answer disagrees with its exact lines (rackfacts.review: a number they do not have, a node
called unreachable that answered, the instructions copied).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ui import server  # noqa: E402


def logged(results: Path, rack: str, n: int) -> list[dict]:
    rows = []
    for f in (results / "ai" / "chat.jsonl.1", results / "ai" / "chat.jsonl"):
        if f.is_file():
            for ln in f.read_text().splitlines():
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    continue
    seen, out = set(), []
    for r in reversed(rows):
        k = (r.get("question") or "").strip().lower()
        if k and r.get("rack") == rack and not r.get("link") and k not in seen:
            seen.add(k)
            out.append(r)
    return out[:n]


def starter(path: Path) -> list[dict]:
    return [{"question": ln.strip()} for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--inventory", required=True, help="inventory file name, e.g. g02-g17.local.yaml")
    ap.add_argument("--inventory-dir", type=Path, default=Path(os.environ.get("HELIOS_DEBUG_INVENTORY_DIR", ROOT / "inventory")))
    ap.add_argument("--results-dir", type=Path, default=Path(os.environ.get("HELIOS_DEBUG_RESULTS_DIR", ROOT / "results")))
    ap.add_argument("--questions", type=Path, help="one question per line (default: the logged ones, else the starter set)")
    ap.add_argument("--n", type=int, default=30)
    a = ap.parse_args(argv)
    st = server.State(a.inventory_dir.expanduser(), a.results_dir.expanduser())
    st.no_chat_log = True
    f, inv = st.inventory(a.inventory)
    rack = inv.rack or f.stem
    qs = starter(a.questions) if a.questions else (logged(st.results_dir, rack, a.n)
                                                   or starter(ROOT / "tools" / "chat_questions.txt"))[:a.n]
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out_f = st.results_dir / "ai" / f"replay-{stamp}.jsonl"
    out_f.parent.mkdir(parents=True, exist_ok=True)
    off = changed = failed = 0
    with out_f.open("w") as fh:
        for i, r in enumerate(qs, 1):
            q = r["question"]
            try:
                ans = server.ai_chat(st, {"inventory": a.inventory, "path": r.get("path") or "", "question": q})
            except Exception as e:  # noqa: BLE001 - one question's failure is reported, the rest still run
                failed += 1
                print(f"{i:3} ERROR  {q}\n        {e}")
                fh.write(json.dumps({"question": q, "error": str(e)}) + "\n")
                continue
            facts = ans.get("check_facts") or []
            was = r.get("check_facts")
            diff = was is not None and [t for t in was if not t.startswith("These are")] != [
                t for t in facts if not t.startswith("These are")]
            off += bool(ans.get("off_facts"))
            changed += bool(diff)
            mark = "WRONG " if ans.get("off_facts") else "FACTS " if diff else "ok    "
            print(f"{i:3} {mark} {q}" + (f"  ({'; '.join(ans['off_facts'])})" if ans.get("off_facts") else ""))
            if ans.get("off_facts") or diff:
                print("        " + (ans.get("answer") or "").replace("\n", " ")[:240])
            fh.write(json.dumps({"question": q, "path": ans["context"]["path"], "kinds": ans["context"]["kinds"],
                                 "check_facts": facts, "was_facts": was, "facts_changed": diff, "answer": ans.get("answer"),
                                 "was_answer": r.get("answer"), "off_facts": ans.get("off_facts"), "model": ans.get("model")},
                                default=str) + "\n")
    print(f"\n{len(qs)} questions: {off} disagreeing with their exact lines, {changed} whose exact lines changed, "
          f"{failed} failed - {out_f}")
    return 1 if off else 0


if __name__ == "__main__":
    sys.exit(main())
