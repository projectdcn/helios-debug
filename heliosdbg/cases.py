"""Evidence for any problem on the rack, not only links - what the AI is asked about and what helios-slm trains on
(its training hub builds its prompts with these same functions, so a taught case and a question here look alike):

  report  a saved result of any helios-debug tool other than a link check / Diagnose (Switch signal / bcm, path,
          pingmap, watch, cabling, isolate): results/link-check/<rack>/<tool>-<time>/ (report.txt, bcm.txt, ...)
  test    one helios-tests result: a row of its results/index.csv (case, outcome, message) + the case's log
  blocks  command outputs / logs a person collected - on a switch, a tray, a BMC, anywhere: [{node, command, output}]

Each becomes numbered evidence items [E1].. like a link check's; long outputs keep the lines that matter (errors,
failures, down / missing / mismatch ...) plus the start and the end. Nothing here touches the rack.
    HELIOS_TESTS_RESULTS  helios-tests' results folder (default ~/dev/helios-tests/results)
"""
from __future__ import annotations

import csv
import os
import re
from pathlib import Path

from .ai import AIError, Evidence
from .guide import compact

TOOLS = ("bcm", "path", "pingmap", "watch", "cabling", "isolate", "health")
REPORT_RX = re.compile(r"link-check/[A-Za-z0-9_.-]+/(?:bcm|path|pingmap|watch|cabling|isolate|health)-[0-9]{8}-[0-9]{6}")
IMPORTANT = re.compile(
    r"\b(fail\w*|error\w*|err\b|down|not ok|nok|timeout|timed out|denied|refused|missing|mismatch\w*|warn\w*|critical|"
    r"fatal|panic|degraded|blocked|unreachable|no such|cannot|can't|unable|invalid|exceed\w*|lost|drop\w*|abort\w*|"
    r"assert\w*|traceback|exception|skipp?ed|partial|not present|absent|offline|stuck|hang\w*|retry\w*|crc|ecc|xid)\b", re.I)
MAX_BLOCKS = 12


def tests_results() -> Path:
    return Path(os.environ.get("HELIOS_TESTS_RESULTS", "~/dev/helios-tests/results")).expanduser()


def output_items(ev: Evidence, head: str, text: str, budget: int, source: str) -> None:
    """One output as evidence: a heading item, then its lines packed into items (the lines that matter first when the
    output is longer than the budget; '...' marks what was left out)."""
    lines = [ln.rstrip() for ln in compact(str(text or "")).splitlines() if ln.strip()]
    ev.add(f"{head}: " + (f"{len(lines)} lines" if lines else "no output"), source)
    if not lines:
        return
    keep = set(range(len(lines)))
    if sum(len(x) for x in lines) > budget * 280:
        imp = [i for i, ln in enumerate(lines) if IMPORTANT.search(ln)]
        keep = set(range(min(3, len(lines)))) | set(range(max(0, len(lines) - 4), len(lines)))
        for i in imp:
            if sum(len(lines[k]) for k in keep) > budget * 240:
                break
            keep.add(i)
    chunk, prev = "", -1
    for i in sorted(keep):
        piece = ("... | " if prev >= 0 and i != prev + 1 else "") + lines[i][:400]
        if chunk and len(chunk) + len(piece) > 300:
            ev.add(chunk, source)
            chunk = ""
        chunk = f"{chunk} | {piece}" if chunk else piece
        prev = i
    if chunk:
        ev.add(chunk + (" | ..." if prev < len(lines) - 1 else ""), source)


def general(ev: Evidence) -> Evidence:
    ev.mode = "general"           # build_messages: the any-problem system prompt
    return ev


# ------------------------------------------------------------------------------------------------ report

def reports(results_dir: Path, limit: int = 300) -> list[dict]:
    """The saved results of the tools other than a link check / Diagnose, newest first."""
    out = []
    for d in (Path(results_dir) / "link-check").glob("*/*-*"):
        rel = f"link-check/{d.parent.name}/{d.name}"
        if d.is_dir() and REPORT_RX.fullmatch(rel):
            txt = next((f for f in ("report.txt", "bcm.txt") if (d / f).is_file()), "")
            first = ""
            if txt:
                ls = [x for x in (d / txt).read_text(errors="replace").splitlines() if x.strip()]
                first = next((x for x in ls if IMPORTANT.search(x) or re.search(r"\bok\b|links?", x)), ls[0] if ls else "")
            out.append({"path": rel, "rack": d.parent.name, "tool": d.name.split("-", 1)[0], "name": d.name,
                        "when": _when(d.name), "summary": first.strip()[:160]})
    return sorted(out, key=lambda r: r["name"].split("-", 1)[1], reverse=True)[:limit]


def _when(name: str) -> str:
    m = re.search(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)", name)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)} UTC" if m else name


def health_context(d: Path, rack: str, name: str, node: str = "") -> tuple[Evidence, str, str]:
    """A node health result as evidence: one item per finding (what, cause, owner, evidence lines) - of one node when
    ``node`` is given - and the checks that could not run (a missing finding there is not health)."""
    import json
    res = json.loads((d / "health.json").read_text())
    fs = [f for f in res.get("findings") or [] if not node or f["node"] == node]
    ev = general(Evidence())
    s = res.get("summary") or {}
    ev.add(f"Rack {rack}: helios-debug node health of {_when(name)}" + (f", node {node}" if node else "") +
           f": {s.get('critical', 0)} critical, {s.get('warning', 0)} warning on {len(res.get('nodes') or {})} node(s)"
           + (f"; not reached: {', '.join(res['unreachable'])}" if res.get("unreachable") else ""), "health")
    for f in fs[:40]:
        ev.add(f"{f['severity'].upper()} {f['node']} [{f['area']}, owner {f['owner']}]: {f['what']} - {f['cause']}. "
               f"Evidence ({f['command'][:120]}): " + " | ".join(f["evidence"][:4])[:600], "health")
    nr = {n: v.get("not_run") for n, v in (res.get("nodes") or {}).items() if v.get("not_run") and (not node or n == node)}
    if nr:
        ev.add("Not checked (command missing or failed): " + "; ".join(f"{n}: {', '.join(v)}" for n, v in sorted(nr.items())), "health")
    if not fs:
        ev.add("No problem found" + (f" on {node}" if node else " on the nodes checked"), "health")
        ev.verdict = "ok"
    return ev, (f"the health of {node}" if node else f"the node health result {name}"), rack


def report_context(results_dir: Path, rel: str, node: str = "") -> tuple[Evidence, str, str]:
    if not REPORT_RX.fullmatch(rel or ""):
        raise AIError("path: link-check/<rack>/<bcm|path|pingmap|watch|cabling|isolate|health>-<time>")
    d = Path(results_dir) / rel
    if not d.is_dir():
        raise AIError(f"no result {rel}")
    rack, name = rel.split("/")[1], rel.split("/")[2]
    tool = name.split("-", 1)[0]
    if tool == "health" and (d / "health.json").is_file():
        return health_context(d, rack, name, node)
    ev = general(Evidence())
    ev.add(f"Rack {rack}: helios-debug {tool} result of {_when(name)}", tool)
    files = [f for f in ("report.txt", "bcm.txt") if (d / f).is_file()]
    files += sorted(f.name for f in d.glob("*.txt") if f.name not in files)[:4]
    for f in files[:MAX_BLOCKS]:
        output_items(ev, f"{tool} {f}", (d / f).read_text(errors="replace"), max(4, 50 // max(1, len(files))), tool)
    return ev, f"the {tool} result {name}", rack


# ------------------------------------------------------------------------------------------------ test

def tests(limit: int = 3000, outcome: str = "", rack: str = "", q: str = "") -> list[dict]:
    """helios-tests results (index.csv), newest first; outcome / rack / text filters."""
    f = tests_results() / "index.csv"
    if not f.is_file():
        return []
    rows = []
    with open(f, newline="", errors="replace") as fh:
        for r in csv.DictReader(fh):
            if outcome and r.get("outcome") != outcome or rack and r.get("rack") != rack:
                continue
            if q and q.lower() not in " ".join(str(v) for v in r.values()).lower():
                continue
            rows.append({k: r.get(k, "") for k in ("rack", "run", "started", "tc_id", "test", "outcome", "duration_s",
                                                    "message", "log")})
    rows.sort(key=lambda r: (r["started"], r["log"]), reverse=True)
    return rows[:limit]


def find_test(run: str, tc_id: str, test: str = "") -> dict:
    for r in tests(100000, q=run):
        if r["run"] == run and r["tc_id"] == tc_id and (not test or r["test"] == test):
            return r
    raise AIError(f"no helios-tests result {tc_id} {test} in run {run}")


def test_context(row: dict) -> tuple[Evidence, str, str]:
    ev = general(Evidence())
    ev.add(f"helios-tests {row.get('tc_id')} ({row.get('test')}) on rack {row.get('rack')}, run {row.get('run')} "
           f"started {row.get('started')}: outcome {str(row.get('outcome') or '?').upper()} after {row.get('duration_s')} s", "test")
    msg = re.sub(r"\s+", " ", str(row.get("message") or "")).strip()
    if len(msg) > 1800:                  # a traceback: where it failed is at its end
        msg = msg[:600] + " ... " + msg[-1195:]
    for i in range(0, len(msg), 450):
        ev.add(("Message: " if i == 0 else "Message (cont.): ") + msg[i:i + 450], "test")
    log = str(row.get("log") or "")
    p = (tests_results() / log).resolve()
    if log and str(p).startswith(str(tests_results().resolve())) and p.is_file():
        output_items(ev, f"Test log {p.name}", p.read_text(errors="replace")[-200000:], 40, "test log")
    elif log:
        ev.add(f"Test log {log}: not on this machine", "test")
    if str(row.get("outcome")) == "passed":
        ev.verdict = "ok"
    return ev, f"test {row.get('tc_id')} ({row.get('test')})", str(row.get("rack") or "")


# ------------------------------------------------------------------------------------------------ blocks

def clean_blocks(blocks, subject: str = "") -> list[dict]:
    if isinstance(blocks, list) and not blocks and subject.strip():
        return []                        # a symptom alone: step by step starts from the description
    if not isinstance(blocks, list) or not blocks:
        raise AIError("blocks: [{node, command, output}] - at least one output")
    out = []
    for b in blocks[:MAX_BLOCKS]:
        if not isinstance(b, dict) or not str(b.get("output") or "").strip():
            continue
        out.append({"node": str(b.get("node") or "").strip()[:80], "command": str(b.get("command") or "").strip()[:300],
                    "output": str(b.get("output"))[:200000]})
    if not out:
        raise AIError("every block is empty - paste an output")
    return out


def blocks_context(blocks, subject: str = "", rack: str = "") -> tuple[Evidence, str, str]:
    bs = clean_blocks(blocks, subject or "")
    ev = general(Evidence())
    if not bs:
        ev.add(f"Reported symptom{' on rack ' + rack if rack else ''}: {(subject or '').strip()[:600]} - nothing collected yet: "
               "start with the read-only commands that show it", "symptom")
        return ev, (subject or "").strip()[:160], rack
    ev.add(f"Outputs collected by hand{' on rack ' + rack if rack else ''}: {len(bs)}", "outputs")
    for b in bs:
        where = f"On {b['node']}" if b["node"] else "Output"
        output_items(ev, where + (f": `{b['command']}`" if b["command"] else ""), b["output"], max(4, 54 // len(bs)), "outputs")
    return ev, (subject or "").strip()[:160] or "the problem these outputs show", rack


# ------------------------------------------------------------------------------------------------ any

def context(spec: dict, results_dir: Path) -> tuple[Evidence, str, str]:
    """(evidence, subject, rack) of {path: a report result} | {test: {run, tc_id, test}} | {blocks, subject, rack}."""
    if spec.get("blocks") is not None:
        return blocks_context(spec["blocks"], str(spec.get("subject") or ""), str(spec.get("rack") or ""))
    if isinstance(spec.get("test"), dict):
        t = spec["test"]
        return test_context(find_test(str(t.get("run") or ""), str(t.get("tc_id") or ""), str(t.get("test") or "")))
    return report_context(results_dir, str(spec.get("path") or "").strip("/"), str(spec.get("node") or "")[:80])


def spec_of(req: dict) -> dict | None:
    """The any-problem part of a request, or None (a link check / Diagnose path: the link evidence builders)."""
    if req.get("blocks") is not None or isinstance(req.get("test"), dict):
        return {k: req.get(k) for k in ("blocks", "subject", "rack", "test") if req.get(k) is not None}
    if REPORT_RX.fullmatch(str(req.get("path") or "").strip("/")):
        return {"path": str(req["path"]).strip("/")} | ({"node": str(req["node"])} if req.get("node") else {})
    return None
