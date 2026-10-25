"""Ticket / handover write-ups from a check, for the people who have to act (AMD / AFM, the switch owner, site /
cabling, the operator).

The FACTS of a ticket are never written by the model: the title, impact, the evidence table (ports, MACs, counts,
times), what was already checked and the report path come from the saved check here. The AI writes only the short
summary and the "what we need from you" paragraph for the chosen audience, from the same evidence (numbered [E..]),
and the ticket says so. Without a model the ticket is still complete (those two paragraphs say "not written").
"""
from __future__ import annotations

import re
import time

AUDIENCES = {
    "amd": "AMD (GPU / AFM team)",
    "switch": "the switch / SONiC owner",
    "site": "site / cabling",
    "operator": "the rack operator",
    "all": "everyone involved",
}


def _tray_links(ls, pred):
    return [x for x in ls if pred(x)]


def problems(scan: dict) -> list[dict]:
    """Each problem of a check with its exact facts: {id, title, owner, audience, impact, facts: [..], links: [..]}."""
    names = scan.get("afm_names") or {}
    nm = (lambda n: f"{names[n]} ({n})" if n in names else str(n))
    ls = scan.get("links") or []
    out: list[dict] = []
    # chips with links up but no IFCP session
    chips: dict = {}
    for x in ls:
        d = chips.setdefault((x.get("switch"), x.get("asic") or ""), {"n": 0, "nosess": [], "down": 0})
        d["n"] += 1
        if (x.get("ifcp") or {}).get("ll") == "no" and x.get("state") != "down":
            d["nosess"].append(x)
    for (sw, asic), d in sorted(chips.items()):
        if len(d["nosess"]) >= max(8, d["n"] // 4):
            trays = sorted({x.get("tray") for x in d["nosess"] if x.get("tray")})
            ex = d["nosess"][:6]
            out.append({"title": f"{nm(sw)} {asic}: {len(d['nosess'])} of {d['n']} GPU links up without an IFCP session",
                        "audience": "amd", "owner": "AMD (GPU / AFM)",
                        "impact": f"the GPUs on those {len(d['nosess'])} links have no control-plane session through this "
                                  f"switch chip - every compute tray is affected ({len(trays)} trays)",
                        "facts": [f"switch ports admin up / oper up and GPU ports LINK_UP, but IFCP link-level up = no and "
                                  f"peer enabled = none on {len(d['nosess'])} links of {sw} {asic}; the other chips' links "
                                  f"have their sessions",
                                  "examples: " + "; ".join(f"{x['switch']} {x.get('asic')} {x['sw_port']} <-> "
                                                         f"{x.get('tray')} {x.get('bdf')} port {x.get('gpu_port')}" for x in ex)],
                        "links": [f"{x['switch']} {x['sw_port']}" for x in d["nosess"]]})
    # switches whose forwarding table breaks `show mac`
    by: dict = {}
    for f in scan.get("fdb_broken") or []:
        by.setdefault(f.get("switch"), []).append(f)
    for sw, fs in sorted(by.items()):
        src: dict = {}
        for f in fs:
            src[f.get("source") or "?"] = src.get(f.get("source") or "?", 0) + 1
        hw_only = sum(v for k, v in src.items() if k.startswith("hardware"))
        test_macs = [f for f in fs if str(f.get("mac", "")).upper().startswith("00:11:22:33")]
        out.append({"title": f"{nm(sw)}: {len(fs)} forwarding entries without a switch port - `show mac` fails, the switch "
                             f"cannot be checked",
                    "audience": "amd" if hw_only and not test_macs else "switch",
                    "owner": "AFM (left in the hardware)" if hw_only and not test_macs else "whoever added the entries / the switch owner",
                    "impact": f"SONiC's `show mac` fails on {sw} (KeyError SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID), so none of "
                              f"{sw}'s GPU links can be checked",
                    "facts": [f"{n} {k}" for k, n in src.items()] +
                             [f"{f.get('ns') or ''} Vlan{f.get('vlan') or '?'} {f.get('mac')} -> {f.get('port') or 'no port'} "
                              f"({f.get('type') or '?'}, {f.get('source')})" for f in fs[:12]] +
                             ([f"... {len(fs) - 12} more"] if len(fs) > 12 else []),
                    "links": []})
    # the checker's root-cause groups (cabling, quarantined trays, ...), without the IFCP chips above
    for rc in scan.get("root_causes") or []:
        kind = str(rc.get("kind") or "")
        if kind == "ifcp" and any(len(d["nosess"]) >= 8 for d in chips.values()):
            continue
        lk = rc.get("links") or []
        aud = {"site (cabling)": "site", "operator": "operator", "GPU / AFM vendor": "amd", "switch vendor": "switch"}.get(
            rc.get("owner") or "", "operator")
        out.append({"title": f"{rc.get('title') or kind}: {len(lk)} link{'s' if len(lk) != 1 else ''}",
                    "audience": aud, "owner": rc.get("owner") or "",
                    "impact": rc.get("cause") or "", "facts": [f"links: {', '.join(lk[:12])}" + (" ..." if len(lk) > 12 else "")]
                    + ([f"checker's next step: {rc['action']}"] if rc.get("action") else []), "links": lk})
    for x in scan.get("not_checked") or []:
        if "without a switch port" in str(x.get("error")):
            continue
        out.append({"title": f"{x.get('role') or 'node'} {x.get('node')} could not be read", "audience": "operator",
                    "owner": "the operator", "impact": "its links are unknown in this check",
                    "facts": [str(x.get("error"))[:300]], "links": []})
    for i, p in enumerate(out, 1):
        p["id"] = i
    return out


def render(scan: dict, audience: str, probs: list[dict], ai_text: dict | None, report_url: str = "") -> str:
    """The ticket as Markdown."""
    who = AUDIENCES.get(audience, AUDIENCES["all"])
    sel = [p for p in probs if audience == "all" or p["audience"] == audience] or probs
    ls = scan.get("links") or []
    c: dict = {}
    for x in ls:
        c[x.get("state")] = c.get(x.get("state"), 0) + 1
    when = str(scan.get("time_utc") or "")
    m = re.match(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)", when)
    when_h = f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)} UTC" if m else when
    title = (f"[{scan.get('rack')}] " + (sel[0]["title"] if len(sel) == 1 else f"{len(sel)} problems found by the link check of {when_h}"))
    L = [f"# {title}", "", f"For: {who}  ", f"Rack: {scan.get('rack')} - link check of {when_h} (read only)  ",
         f"Links checked: {len(ls)} (" + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) + ")", ""]
    L += ["## Summary", (ai_text or {}).get("summary") or "_(not written - no AI model connected; the facts below are complete)_", ""]
    for i, p in enumerate(sel, 1):
        L += [f"## {i}. {p['title']}", f"**Impact:** {p['impact']}  ", f"**Owner:** {p['owner']}", "", "Evidence:"]
        L += [f"- {f}" for f in p["facts"]]
        L += [""]
    L += ["## What we need from you", (ai_text or {}).get("ask") or "_(not written - no AI model connected)_", ""]
    L += ["## Already checked (read only)",
          "- every GPU link: switch port state and description, forwarding table, counters / FEC, both ends' link state, "
          "IFCP state and peer of each GPU port, VLAN membership",
          "- nothing on the rack was changed for this report", ""]
    if report_url:
        L += [f"Full report: {report_url}", ""]
    L += [f"_Written {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by helios-debug. Evidence and counts come from "
          f"the check; " + ("the summary and request were drafted by the AI " + str((ai_text or {}).get('model') or '') +
                           " - check them" if ai_text and ai_text.get("summary") else "no AI text") + "._"]
    return "\n".join(L)


def ai_paragraphs(ai, scan: dict, audience: str, probs: list[dict], env=None) -> dict | None:
    """The summary and the request, drafted by the model from the problems' facts. None without a model."""
    sel = [p for p in probs if audience == "all" or p["audience"] == audience] or probs
    ev = ai.Evidence()
    for p in sel:
        ev.add(f"[Problem {p['id']}] {p['title']} - impact: {p['impact']} - owner: {p['owner']}", "ticket")
        for f in p["facts"][:6]:
            ev.add(f"[Problem {p['id']}] {f}", "ticket")
    who = AUDIENCES.get(audience, AUDIENCES["all"])
    msgs = [{"role": "system", "content": "You write short, factual engineering tickets about an AMD Helios GPU rack. Use only "
             "the evidence given, keep every number and name exact, no speculation beyond 'likely'. Name only switches, trays "
             "and ports that appear in the evidence; do not say a problem is known, new or how long it lasted unless the evidence "
             "says so; do not cite evidence numbers like E4 (the reader does not see them). Plain text, no headings."},
            {"role": "user", "content": f"Evidence:\n{ev.block()}\n\nFor {who}, answer ONLY with this JSON object:\n"
             '{"summary": "<2-4 sentences: what is wrong, how widespread, since when if known>", '
             f'"ask": ["<what we need {who} to look at or do, most important first; 2-5 items; mark anything that would '
             'change the rack>"]}'}]
    try:
        text, model = ai.chat(msgs, env, max_tokens=800)
    except Exception:  # noqa: BLE001 - the ticket is complete without it
        return None
    from .guide import GuideError, parse_step
    try:
        d = parse_step(text)
        summary = str(d.get("summary") or "").strip()
        asks = d.get("ask") or []
        asks = [str(x).strip() for x in (asks if isinstance(asks, list) else [asks]) if str(x).strip()]
    except GuideError:                     # not JSON: keep the text as the summary, no request list
        summary, asks = re.sub(r"\s+", " ", text).strip()[:1200], []
    ask = "\n".join(f"- {x.lstrip('-* ').strip()}" for x in asks[:6])
    return {"summary": summary, "ask": ask, "model": model, "unsafe": ai.unsafe_text(summary + " " + ask)}
