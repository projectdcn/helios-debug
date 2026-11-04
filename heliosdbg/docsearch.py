"""Documentation the AI chat can look things up in (BM25, standard library only).

Sources:
  * this repo's debug guide, docs/link-debug-guide.md, split by heading (always - it ships with the UI);
  * document indexes made by helios-slm (`python -m helios_slm.docs fetch ...` -> <dir>/<name>/chunks.jsonl), from
    HELIOS_AI_DOCS (folders separated by ':') or, when unset, ~/dev/helios-slm/data/docs if it exists. Internal
    documentation therefore stays on the machine that fetched it (a jump host without helios-slm has the guide only).
Each passage: {title, section, url, text, source}.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "link-debug-guide.md"
ID_RX = re.compile(r"(?:tc|hc|maint|hw)-[a-z0-9]+(?:-[a-z0-9]+)*-?\d+[a-z]?|(?:tc|hc)-\d+")
_STOP = set("the a an and or of to in on for is are be by with this that it as at from what how which when where do does "
            "i you we can my your our not no list give please me tell".split())
# the words people use for what the guide calls something else ('brcm' / 'broadcom' -> the Broadcom shell's commands)
SYNONYMS = {"broadcom": ["bcmcmd", "bsh"], "brcm": ["broadcom", "bcmcmd", "bsh"], "bcm": ["broadcom", "bcmcmd"],
            "serdes": ["broadcom", "lane", "snr"], "asic": ["broadcom"]}
GUIDE_BOOST = 1.4         # the debug guide is written for debugging questions; manuals and issue trackers are background
_DEBUG_Q = re.compile(r"\b(debug\w*|troubleshoot\w*|diagnos\w*|commands?|links?|ports?|down|fail\w*|flap\w*|errors?|fix|"
                      r"check|signal|broadcom|brcm|bcm\w*)\b", re.I)


def tokens(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9_]+(?:[.-][a-z0-9_]+)*", (text or "").lower()) if w not in _STOP and len(w) > 1]


def guide_passages(path: Path = GUIDE, size: int = 1400) -> list[dict]:
    if not path.is_file():
        return []
    out, title, sec, buf = [], "Link debug guide", "", []

    def flush():
        text = "\n".join(buf).strip()
        while text:
            cut = text[:size]
            if len(text) > size and "\n" in cut:
                cut = cut[:cut.rfind("\n")]
            out.append({"title": title, "section": sec or title, "url": "docs/link-debug-guide.html", "text": cut.strip(),
                        "source": "debug guide"})
            text = text[len(cut):].strip()
    for ln in path.read_text(errors="replace").splitlines():
        m = re.match(r"^(#{1,4})\s+(.*)", ln)
        if m:
            flush()
            buf, sec = [], m.group(2).strip()
            if len(m.group(1)) == 1:
                title = sec
            continue
        buf.append(ln)
    flush()
    return [p for p in out if len(p["text"]) > 40]


def index_dirs() -> list[Path]:
    env = os.environ.get("HELIOS_AI_DOCS")
    roots = [Path(p).expanduser() for p in env.split(":") if p] if env is not None else [Path("~/dev/helios-slm/data/docs").expanduser()]
    out = []
    for r in roots:
        if (r / "chunks.jsonl").is_file():
            out.append(r)
        elif r.is_dir():
            out += sorted(d for d in r.iterdir() if (d / "chunks.jsonl").is_file())
    return out


class Index:
    def __init__(self, chunks: list[dict], k1: float = 1.4, b: float = 0.75):
        self.chunks, self.k1, self.b = chunks, k1, b
        self.toks = [tokens(f"{c.get('title', '')} {c.get('section', '')} {c.get('section', '')} {c.get('text', '')}") for c in chunks]
        self.tf = [Counter(t) for t in self.toks]
        self.avg = sum(len(t) for t in self.toks) / max(1, len(self.toks))
        df = Counter(w for t in self.tf for w in t)
        n = len(chunks)
        self.idf = {w: math.log(1 + (n - c + 0.5) / (c + 0.5)) for w, c in df.items()}

    def search(self, query: str, k: int = 3, min_score: float = 2.0) -> list[dict]:
        boost = GUIDE_BOOST if _DEBUG_Q.search(query or "") else 1.0      # 'what is AFM': the manual, as before
        q0 = tokens(query)
        q = [w for w in dict.fromkeys(q0 + [x for w in q0 for x in SYNONYMS.get(w, [])]) if w in self.idf]
        ids = [w for w in q if ID_RX.fullmatch(w)]          # a test case id named: its passages come first
        scored = []
        for i, tf in enumerate(self.tf):
            s, ln = 0.0, len(self.toks[i])
            for w in q:
                f = tf.get(w)
                if f:
                    s += self.idf[w] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * ln / self.avg))
            if ids and any(w in tf for w in ids):           # its own passage far ahead; one that mentions it, a bit
                s += 50.0 if any(w in tokens(self.chunks[i].get("title", "")) for w in ids) else 5.0
            if self.chunks[i].get("source") == "debug guide":
                s *= boost
            if s >= min_score:
                scored.append((s, i))
        scored.sort(key=lambda x: -x[0])
        # no one source fills every slot (705 test-plan rows would crowd out the manuals) unless an id was named
        cap, per, out = (k if ids else max(2, (k + 1) // 2)), {}, []
        for s, i in scored:
            src = self.chunks[i].get("source", "")
            if per.get(src, 0) < cap:
                per[src] = per.get(src, 0) + 1
                out.append(dict(self.chunks[i], score=round(s, 2)))
                if len(out) == k:
                    break
        return out


_CACHE: dict = {}


def load() -> Index | None:
    dirs = index_dirs()
    key = (GUIDE.stat().st_mtime if GUIDE.is_file() else 0,
           tuple((str(d), (d / "chunks.jsonl").stat().st_mtime) for d in dirs))
    if key in _CACHE:
        return _CACHE[key]
    chunks = guide_passages()
    for d in dirs:
        name = d.name
        try:
            meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").is_file() else {}
        except ValueError:
            meta = {}
        for line in (d / "chunks.jsonl").read_text(errors="replace").splitlines():
            try:
                c = json.loads(line)
            except ValueError:
                continue
            chunks.append({"title": c.get("title") or name, "section": c.get("section") or "", "url": c.get("url") or meta.get("url", ""),
                           "text": c.get("text") or "", "source": meta.get("name") or name})
    idx = Index(chunks) if chunks else None
    _CACHE.clear()
    _CACHE[key] = idx
    return idx


def sources() -> list[dict]:
    """[{source, passages}] of what the chat can look up (for the page)."""
    idx = load()
    c: Counter = Counter(x["source"] for x in (idx.chunks if idx else []))
    return [{"source": k, "passages": v} for k, v in sorted(c.items())]
