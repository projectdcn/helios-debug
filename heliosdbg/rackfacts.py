"""Exact answers to the chat's counting questions - from the newest link check and health check, never the model.

6 Nov the model answered 'how many switches are reachable' from the guide's 2 Nov known-issues table (reach.py now
gives it the exact lines). The same can happen to every question with one right answer: how many links are down, which
GPUs are not active, which trays are quarantined, what the health check found, when the rack was last checked. kinds()
names what a question asks for, facts() writes the lines - shown to the person as they are, with the time and age of
the check they come from; the model only explains them.
"""
from __future__ import annotations

import calendar
import re
import time
from collections import Counter

from . import reach

STALE_H = 6                                    # older than this: the answer says so and offers Run Health

_COUNT = r"(?:how\s+many|number\s+of|count|which|list|what\s+(?:are|is)\s+the|any|is\s+there|are\s+there|show)"
KIND_RX = {
    "links": re.compile(rf"\b{_COUNT}\b.*\b(?:links?|ports?)\b|\b(?:links?|ports?)\b.*\b(?:are|is)\s+(?:down|degraded|ok|up|"
                        r"unknown|broken)\b", re.I | re.S),
    "gpus": re.compile(rf"\b{_COUNT}\b.*\b(?:gpus?|accelerators?)\b|\b(?:gpus?|accelerators?)\b.*\b(?:idle|not\s+active|"
                       r"active|provider|programmed|missing)\b", re.I | re.S),
    "quarantine": re.compile(r"\bquarantin\w*", re.I),
    "health": re.compile(rf"\b(?:critical|warnings?|findings?|firmware|health\s+(?:check\s+)?(?:found|find|say|show|report)\w*)\b"
                         rf"|\b{_COUNT}\b.*\b(?:health|alarms?|alerts?|ntp|watchdog|restart\w*|reboot\w*|containers?|"
                         r"systemd|syslog|bmc|fans?|psus?|disk|nic\s+firmware)\b", re.I | re.S),
    "when": re.compile(r"\b(?:when|how\s+old|how\s+long\s+ago|last|latest|newest)\b.*\b(?:checks?|checked|scans?|health|"
                       r"runs?|read)\b", re.I | re.S),
}
WHY_RX = re.compile(r"\b(?:why|how\s+(?:do|can|to|should)|fix|cause|explain)\b|\bwhat\s+does\b.*\bmean\b", re.I | re.S)
_NODE = re.compile(r"\b(st\d+|ct\d{2})\b", re.I)
_ASIC = re.compile(r"\b(asic\d)\b", re.I)
_IFCP = re.compile(r"\bifcp\b|\bsessions?\b|\bll_?up\b", re.I)
_QTRAY = re.compile(r"compute tray (\S+) is quarantined")
_STATE = re.compile(r"\b(down|degraded|ok|up|unknown|broken)\b", re.I)
TOPIC_WORDS = re.compile(r"\b(firmware|ntp|watchdog|restart\w*|reboot\w*|nic\w*|rdma|gpu\w*|bmc|syslog|disk|fan|psu|"
                         r"memory|cpu|afm\w*|container\w*|systemd|temperature|hot)\b", re.I)


def kinds(q: str) -> list[str]:
    """The exact facts a chat question asks for ('reach' first: who answers); [] for a why / how / fix question."""
    q = q or ""
    out = ["reach"] if reach.is_question(q) else []
    if WHY_RX.search(q) and not out:
        return []
    return out + [k for k, rx in KIND_RX.items() if rx.search(q) and not (k == "links" and out and "link" not in q.lower())]


def parse_time(t) -> float | None:
    """A check's UTC time ('20261104-225936' of a link check, '2026-11-05 04:42' of a health check) -> epoch seconds."""
    for fmt in ("%Y%m%d-%H%M%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return float(calendar.timegm(time.strptime(str(t), fmt)))
        except (TypeError, ValueError):
            continue
    return None


def age_h(t, now: float | None = None) -> float | None:
    e = parse_time(t)
    return None if e is None else round(((now or time.time()) - e) / 3600, 1)


def _age(h: float | None) -> str:
    if h is None:
        return "age unknown"
    return f"{round(h * 60)} min old" if h < 1 else f"{h:g} h old" if h < 48 else f"{h / 24:.1f} days old"


def ages(scan: dict | None, health: dict | None, now: float | None = None) -> dict:
    """{link_check_h, health_h, stale} - what the UI shows under every answer."""
    lh = age_h((scan or {}).get("time_utc"), now) if scan else None
    hh = age_h((health or {}).get("time"), now) if health else None
    known = [h for h in (lh, hh) if h is not None]
    return {"link_check_h": lh, "health_h": hh, "stale": bool(known) and min(known) > STALE_H,
            "link_check_utc": (scan or {}).get("time_utc"), "health_utc": (health or {}).get("time")}


def _nodes(q: str) -> set[str]:
    return {m.group(1).lower() for m in _NODE.finditer(q or "")}


def link_lines(scan: dict, scan_dir: str, q: str) -> list[str]:
    ls = scan.get("links") or []
    want = _nodes(q)
    asics = {m.group(1).lower() for m in _ASIC.finditer(q or "")}
    mine = [x for x in ls if (not want or str(x.get("switch")).lower() in want or str(x.get("tray")).lower() in want)
            and (not asics or str(x.get("asic")).lower() in asics)]
    where = f" of {', '.join(sorted(want | asics))}" if want or asics else ""
    st = Counter(x.get("state") for x in mine)
    out = [f"Link check {scan.get('time_utc')} UTC ({scan_dir}): {len(mine)} GPU links{where} - "
           + ", ".join(f"{st[s]} {s}" for s in ("ok", "degraded", "down", "unknown") if st[s])]
    bad = Counter((x.get("state"), x.get("kind") or "?") for x in mine if x.get("state") != "ok")
    if bad:
        out.append("Not ok, by kind: " + ", ".join(f"{n} {s} ({k})" for (s, k), n in bad.most_common()))
    per = Counter(x.get("switch") for x in mine if x.get("state") != "ok")
    if per and len(per) > 1:
        out.append("Not ok, by switch: " + ", ".join(f"{s} {n}" for s, n in sorted(per.items())))
    nosess = [x for x in mine if (x.get("ifcp") or {}).get("ll") == "no" and x.get("state") != "down"]
    if nosess:
        out.append(f"Up without an IFCP session: {len(nosess)}")
    m = _STATE.search(q or "")
    asked = {"up": "ok", "broken": "down"}.get(m.group(1).lower(), m.group(1).lower()) if m else ""
    pick = [x for x in mine if x.get("state") == asked] if asked and asked != "ok" else []
    if _IFCP.search(q or ""):                  # 'which links have no IFCP session': the IFCP ones, whatever their state
        asked, pick = "no IFCP session", [x for x in mine if x.get("kind") == "ifcp" or x in nosess]
        if not pick:
            out.append("No link of these has a missing IFCP session in this check")
    if pick and len(pick) <= 12:
        for x in pick:
            out.append(f"  {asked}: {x.get('switch')} {x.get('asic') or ''} {x.get('sw_port')} <-> {x.get('tray') or '?'} "
                       f"{x.get('bdf') or '?'} port {x.get('gpu_port')} - {str(x.get('cause') or '')[:120]}")
    elif pick:
        out.append(f"{len(pick)} links are {asked} - too many to list here; open the Rack map, or name a switch or tray")
    return out


def gpu_lines(scan: dict, scan_dir: str, q: str) -> list[str]:
    want = _nodes(q)
    seen = {(x.get("tray"), x.get("bdf")) for x in scan.get("links") or [] if x.get("tray") and x.get("bdf")}
    seen = {g for g in seen if not want or str(g[0]).lower() in want}
    bad = [g for g in scan.get("gpus") or [] if not want or str(g.get("tray")).lower() in want]
    trays = Counter(g.get("tray") for g in bad)
    out = [f"Link check {scan.get('time_utc')} UTC ({scan_dir}): {len(seen)} GPUs seen on "
           f"{len({t for t, _ in seen})} trays; {len(bad)} with a problem" + (" - every GPU is fine" if not bad else "")]
    for (s, k), n in Counter((g.get("state"), g.get("kind")) for g in bad).most_common():
        ph = Counter(g.get("phase") for g in bad if (g.get("state"), g.get("kind")) == (s, k))
        out.append(f"{n} {s} ({k}" + (f", config_phase {', '.join(p for p in ph if p)}" if any(ph) else "") + ")")
    if trays:
        out.append(f"By tray ({len(trays)} trays): " + ", ".join(f"{t} {n}" for t, n in sorted(trays.items())))
    return out


def quarantine_lines(quarantined: list, scan: dict | None, health: dict | None) -> list[str]:
    """quarantined: [(name, reason)] from the inventory."""
    out = [("Inventory: quarantined (not read by the checks): "
            + "; ".join(f"{n} ({r})" for n, r in quarantined)) if quarantined else "Inventory: no node is quarantined"]
    if health is not None:
        hq = health.get("quarantined") or []
        out.append(f"Health check {health.get('time')} UTC: " + (f"quarantined {', '.join(map(str, hq))}" if hq else
                                                                "no node quarantined"))
    if scan is not None:
        ql = [x for x in scan.get("links") or [] if x.get("kind") == "tray_quarantined"]
        if ql:
            out.append(f"Link check {scan.get('time_utc')} UTC: {len(ql)} links of quarantined trays "
                       f"({', '.join(sorted({x.get('tray') or (_QTRAY.search(str(x.get('cause'))) or [0, '?'])[1] for x in ql}))}) were not checked - the tray was "
                       "quarantined then")
    return out


def health_lines(health: dict | None, health_dir: str, q: str) -> list[str]:
    if not health:
        return ["No health check of this rack yet (Health: reads every node, read-only)"]
    f = health.get("findings") or []
    want, topic = _nodes(q), {m.group(1).lower().rstrip("s") for m in TOPIC_WORDS.finditer(q or "")}

    def hit(x):
        node = str(x.get("node") or "") + " " + str(x.get("what") or "")
        return ((not want or any(re.search(rf"\b{n}\b", node, re.I) for n in want))
                and (not topic or any(t in str(x.get("what") or "").lower() for t in topic)))

    sel = [x for x in f if hit(x)]
    sev = Counter(x.get("severity") for x in sel)
    scope = (" about " + ", ".join(sorted(want | topic))) if want or topic else ""
    out = [f"Health check {health.get('time')} UTC ({health_dir}): {len(sel)} findings{scope} - "
           + (", ".join(f"{sev[s]} {s}" for s in ("critical", "warning", "info") if sev[s]) or "none")]
    for x in sorted(sel, key=lambda x: {"critical": 0, "warning": 1}.get(x.get("severity"), 2))[:10]:
        out.append(f"  {x.get('severity')}: {x.get('node')}: {str(x.get('what') or '')[:160]}")
    if len(sel) > 10:
        out.append(f"  ... and {len(sel) - 10} more (Node health tab)")
    return out


def when_lines(scan: dict | None, scan_dir: str, health: dict | None, health_dir: str, now: float | None = None) -> list[str]:
    a = ages(scan, health, now)
    out = []
    if scan is not None:
        out.append(f"Newest link check: {scan.get('time_utc')} UTC ({scan_dir}), {_age(a['link_check_h'])}")
    out.append(f"Newest health check: {health.get('time')} UTC ({health_dir}), {_age(a['health_h'])}" if health else
               "No health check of this rack yet")
    return out


def facts(ks: list[str], q: str, switches: list[str], computes: list[str], quarantined: list, health: dict | None,
          health_dir: str, scan: dict | None, scan_dir: str, now: float | None = None) -> list[str]:
    """The exact lines for the kinds a question asks for, then how old the checks are."""
    out: list[str] = []
    for k in ks:
        if k == "reach":
            out += reach.facts(switches, computes, [n for n, _ in quarantined], health, health_dir, scan, scan_dir)[:-1]
        elif k == "links" and scan is not None:
            out += link_lines(scan, scan_dir, q)
        elif k == "gpus" and scan is not None:
            out += gpu_lines(scan, scan_dir, q)
        elif k == "quarantine":
            out += quarantine_lines(quarantined, scan, health)
        elif k == "health":
            out += health_lines(health, health_dir, q)
        elif k == "when":
            out += when_lines(scan, scan_dir, health, health_dir, now)
    if out:
        a = ages(scan, health, now)
        old = [f"link check {_age(a['link_check_h'])}" if scan is not None else "",
               f"health check {_age(a['health_h'])}" if health else ""]
        out.append("These are the newest checks (" + ", ".join(o for o in old if o) + "), not this minute"
                   + (": run Health / Check all links again for now" if a["stale"] else ""))
    return out


_NUM = re.compile(r"(?<![\w.:-])(\d+)(?![\w.:-])")
_UNREACH = re.compile(r"\b(st\d+|ct\d{2})\b[^.;\n]{0,40}?\b(?:is|are|was|were)\s+(?:not\s+reachable|unreachable|not\s+reached|"
                      r"down|offline|off the network)", re.I)
ECHO = ("the question asks for", "answer from these lines", "from the newest checks, exactly")


def stray_numbers(answer: str, lines: list[str]) -> list[str]:
    """Counts in the model's explanation that none of the exact lines has (6 Nov: '16 switches are reachable' against
    6) - shown under the answer, so a wrong number is never the last word. Times, dates, ports and ids are skipped:
    only whole numbers standing alone are compared."""
    if not lines:
        return []
    have = {m.group(1) for t in lines for m in _NUM.finditer(t)}
    got = [m.group(1) for m in _NUM.finditer(re.sub(r"\[[EDS]\d+\]", "", answer or ""))]
    return sorted({n for n in got if n not in have and int(n) > 1}, key=int)


def review(answer: str, lines: list[str]) -> list[str]:
    """What is wrong with an explanation next to its exact lines: a number they do not have, a node called unreachable
    that answered (6 Nov: 'ct06 is not reachable' - its afmctl read had failed), the prompt's own words copied."""
    if not lines:
        return []
    out = [f"{n} is not in the exact lines" for n in stray_numbers(answer, lines)]
    missed = {n.lower() for t in lines if "NOT reached" in t for n in re.findall(r"\b(?:st\d+|ct\d{2})\b", t.split("NOT reached")[1])}
    for m in _UNREACH.finditer(answer or ""):
        if m.group(1).lower() not in missed and any(m.group(1).lower() in t.lower() for t in lines):
            out.append(f"calls {m.group(1)} unreachable - the exact lines say it answered")
    if any(e in (answer or "").lower() for e in ECHO):
        out.append("copies the instructions instead of answering")
    return list(dict.fromkeys(out))


def answered_lines(q: str, health: dict | None) -> list[str]:
    """For a question that names a node and is not a counting one ('what should I check first on ct06'): whether it
    answered the newest health check - 6 Nov the model called ct06 unreachable from an older documentation passage."""
    if not health:
        return []
    nodes, un = health.get("nodes") or {}, {str(n).lower() for n in health.get("unreachable") or []}
    out = []
    for n in sorted(_nodes(q)):
        name = next((k for k in nodes if k.lower() == n), None)
        if n in un:
            out.append(f"{n} did NOT answer over SSH at the health check of {health.get('time')} UTC")
        elif name:
            nr = nodes[name].get("not_run") or []
            out.append(f"{name} answered over SSH at the health check of {health.get('time')} UTC (reachable)"
                       + (f"; on it {', '.join(nr)} did not run - a failed read, not a reachability problem" if nr else ""))
        mine = [x for x in health.get("findings") or [] if re.search(rf"\b{n}\b", f"{x.get('node')} {x.get('what')}", re.I)]
        for x in sorted(mine, key=lambda x: {"critical": 0, "warning": 1}.get(x.get("severity"), 2))[:4]:
            out.append(f"Health finding on {n} ({x.get('severity')}): {str(x.get('what') or '')[:160]}"
                       + (f" - next: {str(x.get('next'))[:120]}" if x.get("next") else ""))
    return out
