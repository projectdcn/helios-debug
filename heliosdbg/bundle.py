"""Evidence bundle of one run (scan, link, bcm, path, pingmap): a zip with its reports, JSON, raw outputs and command
logs, plus ticket.txt - a short text to paste into a ticket for AMD / HPE / the site. Lines that look like a password,
token or private key are redacted on the way in (the tools never write them, this is a second guard).
"""
from __future__ import annotations

import gzip
import io
import json
import re
import time
import zipfile
from pathlib import Path

SECRET = re.compile(r"(?i)(password|passwd|secret|token|authorization|cookie)\s*[:=]\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----"
                    r"[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
TEXT = (".txt", ".json", ".html", ".log", ".csv", ".md")


def redact(text: str) -> tuple[str, int]:
    n = 0

    def sub(m):
        nonlocal n
        n += 1
        return (m.group(1) + ": <REDACTED>") if m.group(1) else "<PRIVATE KEY REDACTED>"
    return SECRET.sub(sub, text), n


def _redact_json(data: bytes) -> tuple[bytes, int]:
    """Redact inside each string of a JSON file - the text pattern would eat the closing quotes and break it."""
    count = 0

    def clean(v):
        nonlocal count
        if isinstance(v, str):
            t, n = redact(v)
            count += n
            return t
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        return [clean(x) for x in v] if isinstance(v, list) else v
    return json.dumps(clean(json.loads(data)), indent=1).encode(), count


def ticket(run: Path) -> str:
    tool = run.name.split("-", 1)[0]
    lines = [f"Helios scale-up link debug - {tool} on rack {run.parent.name}, {run.name.split('-', 1)[-1]} UTC", ""]
    rep = run / ("bcm.txt" if (run / "bcm.txt").is_file() else "report.txt")
    if rep.is_file():
        body = rep.read_text(errors="replace").splitlines()
        lines += body[:60] + (["... (full report in the bundle)"] if len(body) > 60 else [])
    lj = run / "link.json"
    if lj.is_file():
        d = json.loads(lj.read_text())
        ln = d.get("link") or {}
        lines += ["", f"Link: {ln.get('switch')} {ln.get('asic')} {ln.get('sw_port')} <-> {ln.get('tray')} {ln.get('bdf')} "
                      f"port {ln.get('gpu_port')}", f"State: {ln.get('state')}", f"Cause: {ln.get('cause')}",
                  f"Owner: {ln.get('owner')}", f"Next step: {ln.get('action')}"]
    lines += ["", "Attached: report.html (open in a browser), the JSON results, raw/ (every command run and its output)."]
    return "\n".join(lines) + "\n"


def build(run: Path) -> tuple[bytes, dict]:
    """(zip bytes, {files, redacted}) of one run folder."""
    buf, stats = io.BytesIO(), {"files": 0, "redacted": 0}
    root = run.name
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(run.rglob("*")):
            if not f.is_file():
                continue
            rel = f"{root}/{f.relative_to(run)}"
            data = f.read_bytes()
            if f.suffix == ".gz":
                try:
                    txt, n = redact(gzip.decompress(data).decode("utf-8", "replace"))
                    data, stats["redacted"] = gzip.compress(txt.encode()), stats["redacted"] + n
                except OSError:
                    pass
            elif f.suffix == ".json":
                try:
                    data, n = _redact_json(data)
                except ValueError:                       # not JSON after all: as text
                    txt, n = redact(data.decode("utf-8", "replace"))
                    data = txt.encode()
                stats["redacted"] += n
            elif f.suffix in TEXT:
                txt, n = redact(data.decode("utf-8", "replace"))
                data, stats["redacted"] = txt.encode(), stats["redacted"] + n
            z.writestr(rel, data)
            stats["files"] += 1
        z.writestr(f"{root}/ticket.txt", ticket(run))
        z.writestr(f"{root}/BUNDLE_INFO.json", json.dumps({"run": root, "rack": run.parent.name,
                                                           "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                           **stats}, indent=1))
    return buf.getvalue(), stats


def build_finding(run: Path, i: int) -> tuple[bytes, dict]:
    """(zip bytes, stats) for one finding of a node health run: ticket.md, the finding, the raw outputs of its node(s)
    only, report.html - what its owner needs and nothing about the other nodes."""
    from .ticket import health_finding
    res = json.loads((run / "health.json").read_text())
    f = (res.get("findings") or [])[i]
    nodes = set(f.get("nodes") or [f["node"]])
    buf, stats = io.BytesIO(), {"files": 0, "redacted": 0}
    root = f"{run.name}-finding-{i + 1}"

    def put(name, text, raw=False):
        txt, n = (text, 0) if raw else redact(text)
        z.writestr(f"{root}/{name}", txt)
        stats["files"] += 1
        stats["redacted"] += n

    def clean(v):                 # redact inside each string, so the JSON stays JSON
        if isinstance(v, str):
            t, n = redact(v)
            stats["redacted"] += n
            return t
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        return [clean(x) for x in v] if isinstance(v, list) else v
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        put("ticket.md", health_finding(res, i, "report.html"))
        put("finding.json", json.dumps(clean(f), indent=1), raw=True)
        raw = run / "raw" / "outputs.json.gz"
        if raw.is_file():
            outs = json.loads(gzip.decompress(raw.read_bytes()))
            put("outputs.json", json.dumps(clean({n: outs[n] for n in sorted(nodes) if n in outs}), indent=1), raw=True)
        if (run / "report.html").is_file():
            put("report.html", (run / "report.html").read_text(errors="replace"))
    return buf.getvalue(), stats
