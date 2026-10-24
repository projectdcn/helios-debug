"""Advisory AI for the debug UI: root cause, how to debug further and what to do, from a check's own evidence.

The model is any OpenAI-compatible chat server (helios-slm's mlx_lm.server on a Mac, Ollama / llama.cpp / vLLM):
    HELIOS_AI_URL    default http://127.0.0.1:8090/v1 ("off" turns the AI off)
    HELIOS_AI_MODEL  default: the first model the server lists
    HELIOS_AI_KEY    optional bearer key
The UI on the jump host reaches a model on your Mac through the same SSH session as the UI tunnel:
    ssh -N -L 8780:localhost:8780 -R 8090:127.0.0.1:8090 -p 8059 tenant-hpe@<jump host>

What the model sees is built here from the saved check (never from the rack live): the link's verdict, cause, evidence
lines, its IFCP / VLAN / cable state, the chip's and switch's state, switch problems (forwarding entries without a
switch port), VLAN findings - each item numbered [E1].. so the answer can cite it. The answer is ADVISORY: a step
that would change the rack (port flap / shutdown, reboot, config reload, clearing the forwarding table, ...) is
flagged in the reply (``unsafe``); nothing here runs anything on the rack.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8090/v1"

SYSTEM = (
    "You are the debugging assistant of helios-debug, a read-only link checker for an AMD Helios scale-up GPU rack "
    "(UALink-style fabric). Facts about this rack: switch trays run SONiC with 2 switch chips (ASICs) each; AFM "
    "(the fabric manager) names them pod-1-<n>-SwitchTray / pod-1-<n>-ComputeTray, numbered from 0 (st1 = "
    "pod-1-0-SwitchTray, ct01 = pod-1-0-ComputeTray); each compute tray has 4 GPUs with 36 ports each; every GPU "
    "port has one cable to one switch port; AFM programs a static forwarding entry per GPU port and one VLAN per GPU "
    "port number on each chip; IFCP is the link-level control protocol between a GPU port and its switch port (its "
    "peer names the switch port at the other end of the real cable); `show mac` is SONiC's forwarding-table command.\n"
    "How to reason: when many links of one switch chip (or one tray / GPU) share a fault, the cause is what they share "
    "(that chip, its switch agent or AFM's programming of it), not each link; a single bad link points at its cable, "
    "connector or one end.\n"
    "Read-only commands that exist - use only these, on the device named, with the real names from the evidence:\n"
    "  switch tray (SONiC, per chip -n asic0 / -n asic1): show interfaces status -n asicN; show interfaces description "
    "-n asicN; show mac -n asicN; show interfaces counters -n asicN; show vlan brief -n asicN; sudo sonic-db-cli -n asicN "
    "APPL_DB keys 'FDB_TABLE:*'; sudo sonic-db-cli -n asicN ASIC_DB keys 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*'; "
    "docker ps (agents); show logging | tail -200\n"
    "  compute tray (Ubuntu + afmctl, needs sudo): sudo afmctl show device --json; sudo afmctl show port -b <bdf> --json "
    "(IFCP state per port: status.ifcp.ll_up / peer_enabled / peer_device_id / peer_port_id); dmesg | tail -100\n"
    "  this UI: Diagnose a link (both ends + 24 h timeline), Watch links, Switch signal (Broadcom view), Live mode, "
    "Topology (Links / IFCP / VLAN views), Config (a node's configuration)\n"
    "There is no `show mac` or SONiC CLI on a compute tray and no afmctl on a switch tray.\n"
    "Answer ONLY from the evidence items [E1].. you are given - cite them like [E3]; if the evidence does not say, "
    "say what is missing and which read-only command would show it. Never invent port numbers, MACs or commands.\n"
    "Write short sections with these headings exactly:\n"
    "### Root cause\n(one or two sentences: the most likely cause, and how sure you are)\n"
    "### Why\n(the evidence that points there, with citations)\n"
    "### Debug next (read-only)\n(numbered commands or UI views that confirm it without changing the rack)\n"
    "### Remediation\n(what fixes it, and who does it: site / cabling, the switch or AFM owner, AMD, the operator); "
    "mark any step that changes the rack with 'CHANGES THE RACK:' and say what it disturbs\n"
    "Keep it under 300 words. Prefer the simplest explanation that covers all the evidence."
)

UNSAFE = re.compile(
    r"\b((?:flap|bounce|toggle)\s+(?:the\s+|a\s+|its\s+)?(?:fabric\s+)?(?:port|link|interface|ethernet\d+)\w*|"
    r"shut\s*(?:down)?\s+(?:the\s+)?(?:port|interface|link)s?|config\s+interface\s+\S+\s+(?:shutdown|startup)|"
    r"ip\s+link\s+set\s+\S+\s+down|reboot\w*|power[\s-]*cycle\w*|config\s+(?:reload|load)\b|"
    r"systemctl\s+(?:stop|restart|disable)|docker\s+(?:stop|restart|rm)|rm\s+-rf|sonic-clear\s+fdb|"
    r"(?:clear|flush)\s+(?:the\s+)?fdb|decommission\w*|afmctl\s+(?:reset|idle|disable)\w*|sonic-db-cli\s+\S+\s+del\b)\b",
    re.I)
NEGATION = re.compile(r"\b(not|never|don't|do not|avoid|without|unless|no need to|must not|should not)\b[^.;:\n]{0,40}$", re.I)


class AIError(RuntimeError):
    pass


# ------------------------------------------------------------------------------------------------ model server

def settings(env=None) -> dict:
    env = os.environ if env is None else env
    url = (env.get("HELIOS_AI_URL") or DEFAULT_URL).strip().rstrip("/")
    return {"url": "" if url.lower() in ("off", "none", "0") else url, "model": (env.get("HELIOS_AI_MODEL") or "").strip(),
            "key": (env.get("HELIOS_AI_KEY") or "").strip()}


def _req(url: str, key: str, body: dict | None = None, timeout: float = 5):
    hdr = {"Content-Type": "application/json"} | ({"Authorization": "Bearer " + key} if key else {})
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=hdr,
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


_MODEL_CACHE: dict = {}


def status(env=None) -> dict:
    """{configured, reachable, url, model[, error]} - never the key."""
    s = settings(env)
    if not s["url"]:
        return {"configured": False, "reachable": False, "url": "", "model": "", "error": "AI turned off (HELIOS_AI_URL=off)"}
    try:
        d = _req(s["url"] + "/models", s["key"], timeout=3)
        names = [m.get("id") for m in d.get("data") or [] if m.get("id")]
        model = s["model"] or (names[0] if names else "")
        _MODEL_CACHE[s["url"]] = model
        return {"configured": True, "reachable": bool(model), "url": s["url"], "model": model,
                **({} if model else {"error": "the model server lists no model"})}
    except Exception as e:  # noqa: BLE001 - down, refused, timeout
        return {"configured": True, "reachable": False, "url": s["url"], "model": s["model"],
                "error": f"no model server answering at {s['url']} ({type(e).__name__}) - start it (helios-slm: "
                         f"mlx_lm.server ... --port 8090), and on the jump host add -R 8090:127.0.0.1:8090 to the UI tunnel"}


def chat(messages: list[dict], env=None, max_tokens: int = 900, timeout: float = 240) -> tuple[str, str]:
    """(answer, model) from the configured server."""
    s = settings(env)
    if not s["url"]:
        raise AIError("AI turned off (HELIOS_AI_URL=off)")
    model = s["model"] or _MODEL_CACHE.get(s["url"]) or status(env).get("model")
    if not model:
        raise AIError(status(env).get("error") or "no model")
    try:
        d = _req(s["url"] + "/chat/completions", s["key"],
                 {"model": model, "messages": messages, "temperature": 0.1, "max_tokens": max_tokens}, timeout=timeout)
    except urllib.error.URLError as e:
        raise AIError(f"the model server did not answer: {e}") from None
    try:
        text = d["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise AIError("unexpected answer from the model server") from None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()      # reasoning models: keep the answer
    return text, model


def unsafe_text(text: str) -> str | None:
    """The first step that would change the rack the text SUGGESTS (a mention after 'do not / never ...' is a warning)."""
    for m in UNSAFE.finditer(text or ""):
        if not NEGATION.search(text[max(0, m.start() - 60):m.start()]):
            return m.group(0)
    return None


# ------------------------------------------------------------------------------------------------ evidence

class Evidence:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, text, source: str = "") -> None:
        t = re.sub(r"\s+", " ", str(text or "")).strip()
        if t and not any(x["text"] == t for x in self.items) and len(self.items) < 60:
            self.items.append({"ref": f"E{len(self.items) + 1}", "text": t[:600], "source": source})

    def block(self) -> str:
        return "\n".join(f"[{x['ref']}] {x['text']}" for x in self.items)


def _names(scan: dict) -> dict:
    return scan.get("afm_names") or {}


def _nm(n, names) -> str:
    return f"{names[n]} ({n})" if n in names else str(n)


def _link_facts(ev: Evidence, ln: dict, names: dict, source: str) -> None:
    sw, tray = ln.get("switch"), ln.get("tray")
    ev.add(f"Link {sw} {ln.get('asic') or ''} {ln.get('sw_port')} <-> {_nm(tray, names) if tray else 'tray not read'} "
           f"GPU {ln.get('bdf') or '?'} port {ln.get('gpu_port') if ln.get('gpu_port') is not None else '?'}; "
           f"switch {(_nm(sw, names))}; described as '{ln.get('desc') or ''}'", source)
    ev.add(f"Verdict: {ln.get('state') or '?'}" + (f", kind {ln['kind']}" if ln.get("kind") else "") +
           (f": {ln['cause']}" if ln.get("cause") else "") + (f" (owner: {ln['owner']})" if ln.get("owner") else ""), source)
    if ln.get("action"):
        ev.add(f"The checker's suggested next step: {ln['action']}", source)
    ev.add(f"Switch port: admin {ln.get('sw_admin') or '?'}, oper {ln.get('sw_oper') or '?'}"
           + (f"; transceiver presence {ln['presence']}" if ln.get("presence") else ""), source)
    i = ln.get("ifcp") or {}
    if i:
        ev.add(f"IFCP on the GPU port: link-level up = {i.get('ll')}, peer enabled = {i.get('pe')}, error = {i.get('err')}", source)
    if ln.get("cable"):
        ev.add(f"Cable check: {ln['cable']}", source)
    if ln.get("vlans") is not None:
        ev.add("VLAN of the switch port: " + (", ".join(f"{v} ({m or 'untagged'})" for v, m in ln["vlans"]) or "none"), source)
    for e in (ln.get("evidence") or [])[:10]:
        ev.add(e, source + " evidence")


def _chip_summary(ev: Evidence, scan: dict, sw: str, asic: str, names: dict) -> None:
    ls = [x for x in scan.get("links") or [] if x.get("switch") == sw and (x.get("asic") or "") == (asic or "")]
    if not ls:
        return
    c: dict = {}
    for x in ls:
        c[x.get("state")] = c.get(x.get("state"), 0) + 1
    no_sess = sum(1 for x in ls if (x.get("ifcp") or {}).get("ll") == "no" and x.get("state") != "down")
    ev.add(f"Chip {_nm(sw, names)} {asic}: {len(ls)} links - " + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) +
           (f"; {no_sess} links up without an IFCP session" if no_sess else ""), "check")


def _switch_problems(ev: Evidence, scan: dict, names: dict, only: str | None = None) -> None:
    by: dict = {}
    for f in scan.get("fdb_broken") or []:
        if only and f.get("switch") != only:
            continue
        by.setdefault(f.get("switch"), []).append(f)
    for sw, fs in sorted(by.items()):
        src: dict = {}
        for f in fs:
            src[f.get("source")] = src.get(f.get("source"), 0) + 1
        ev.add(f"{_nm(sw, names)}: SONiC `show mac` fails - {len(fs)} forwarding entries without a switch port ("
               + ", ".join(f"{v} {k}" for k, v in src.items()) + "), e.g. " +
               "; ".join(f"{f.get('ns') or ''} Vlan{f.get('vlan') or '?'} {f.get('mac')} -> {f.get('port') or 'no port'}"
                         for f in fs[:4]) + "; this switch's links could not be checked", "check")
    for x in scan.get("not_checked") or []:
        if (not only or x.get("node") == only) and "without a switch port" not in str(x.get("error")):
            ev.add(f"{x.get('role') or 'node'} {x.get('node')} could not be read: {str(x.get('error'))[:200]}", "check")


def link_context(scan: dict, key: str) -> tuple[Evidence, str]:
    """Evidence for one link of a check ('st6 Ethernet170')."""
    ln = next((x for x in scan.get("links") or [] if f"{x.get('switch')} {x.get('sw_port')}" == key), None)
    if ln is None:
        raise AIError(f"no link {key} in this check")
    names, ev = _names(scan), Evidence()
    ev.add(f"Rack {scan.get('rack')}, check of {scan.get('time_utc')} (UTC)", "check")
    _link_facts(ev, ln, names, "link")
    _chip_summary(ev, scan, ln.get("switch"), ln.get("asic") or "", names)
    _switch_problems(ev, scan, names, only=ln.get("switch"))
    for f in scan.get("vlan_findings") or []:
        if f.get("switch") == ln.get("switch") and (f.get("port") in (None, ln.get("sw_port"))):
            ev.add(f"VLAN finding ({f.get('kind')}): {f.get('detail')}", "check")
    for g in scan.get("gpus") or []:
        if g.get("tray") == ln.get("tray") and g.get("bdf") == ln.get("bdf"):
            ev.add(f"GPU state: {g.get('state')} {g.get('kind')}: {g.get('cause')}", "check")
    for rc in scan.get("root_causes") or []:
        if key in (rc.get("links") or []):
            ev.add(f"The checker groups it under: {rc.get('title') or rc.get('kind')} - {rc.get('cause') or ''} "
                   f"({len(rc.get('links') or [])} links)", "check")
            break
    return ev, f"link {key}"


def diagnose_context(detail: dict) -> tuple[Evidence, str]:
    """Evidence for a 'Diagnose a link' result (link.json)."""
    ln = detail.get("link") or {}
    ev = Evidence()
    ev.add(f"Rack {detail.get('rack')}, diagnosed {detail.get('time_utc')} (UTC), target '{detail.get('target')}'", "diagnose")
    _link_facts(ev, ln, {}, "diagnose")
    if detail.get("switch_counters"):
        c = detail["switch_counters"]
        ev.add("Switch port counters: " + ", ".join(f"{k} {v}" for k, v in list(c.items())[:12]), "diagnose")
    if detail.get("switch_fdb") is not None:
        ev.add(f"Forwarding entries on the switch port: {len(detail['switch_fdb'])} "
               + "; ".join(f"Vlan{r.get('Vlan')} {r.get('MacAddress')} {r.get('Type')}" for r in detail["switch_fdb"][:4]), "diagnose")
    g = detail.get("gpu") or {}
    if g:
        ev.add(f"GPU {g.get('bdf')}: accelerator {g.get('accelerator')}, config phase {g.get('config_phase')}, "
               f"reaches {g.get('vpod_accelerators')} accelerators in its vPOD", "diagnose")
    for x in detail.get("gpu_state") or []:
        ev.add(f"GPU state: {x.get('state')} {x.get('kind')}: {x.get('cause')}", "diagnose")
    for c in (detail.get("hand_commands") or [])[:6]:
        ev.add(f"Command the checker suggests for this link: {c}", "diagnose")
    for t in (detail.get("timeline") or [])[-8:]:
        ev.add(f"Timeline: {t.get('time') or t.get('t') or ''} {t.get('what') or t.get('text') or t}", "diagnose")
    return ev, f"diagnosed link {ln.get('switch')} {ln.get('sw_port')}"


def check_context(scan: dict) -> tuple[Evidence, str]:
    """Evidence for a whole check, as separate numbered problems ([Problem 1] ..) so a small model keeps independent
    faults apart (24 Oct: one answer merged ct05's quarantine with st6 asic0's missing IFCP sessions)."""
    names, ev = _names(scan), Evidence()
    ls = scan.get("links") or []
    c: dict = {}
    for x in ls:
        c[x.get("state")] = c.get(x.get("state"), 0) + 1
    ev.add(f"Rack {scan.get('rack')}, check of {scan.get('time_utc')} (UTC): {len(ls)} GPU links checked - "
           + ", ".join(f"{v} {k}" for k, v in sorted(c.items())), "check")
    cab = scan.get("cabling") or {}
    if cab:
        ev.add(f"Cables confirmed by IFCP: {cab.get('confirmed')}, miscabled: {cab.get('miscabled')}, "
               f"not confirmable: {cab.get('unconfirmed')}", "check")
    n = 0

    def problem(title: str, lines: list[str]) -> None:
        nonlocal n
        n += 1
        for t in lines:
            ev.add(f"[Problem {n}: {title}] {t}", "check")
    # 1. chips where most links share one IFCP fault
    chips: dict = {}
    for x in ls:
        d = chips.setdefault((x.get("switch"), x.get("asic") or ""), {"n": 0, "nosess": 0, "down": 0})
        d["n"] += 1
        d["nosess"] += (x.get("ifcp") or {}).get("ll") == "no" and x.get("state") != "down"
        d["down"] += x.get("state") == "down"
    for (sw, asic), d in sorted(chips.items()):
        if d["nosess"] >= max(8, d["n"] // 4):
            problem(f"IFCP on {_nm(sw, names)} {asic}",
                    [f"{d['nosess']} of the chip's {d['n']} links are physically up but have no IFCP session (link-level "
                     f"control not up); the other chips' links have theirs - so it is this chip, not the GPUs"])
    # 2. switches whose forwarding table breaks `show mac`
    by: dict = {}
    for f in scan.get("fdb_broken") or []:
        by.setdefault(f.get("switch"), []).append(f)
    for sw, fs in sorted(by.items()):
        src: dict = {}
        for f in fs:
            src[f.get("source")] = src.get(f.get("source"), 0) + 1
        problem(f"forwarding table of {_nm(sw, names)}",
                [f"SONiC `show mac` fails on {sw}: {len(fs)} forwarding entries without a switch port ("
                 + ", ".join(f"{v} {k}" for k, v in src.items()) + "), e.g. " +
                 "; ".join(f"{f.get('ns') or ''} Vlan{f.get('vlan') or '?'} {f.get('mac')} -> {f.get('port') or 'no port'}"
                           for f in fs[:3]) + f"; so none of {sw}'s links could be checked"])
    # 3. the checker's own root-cause groups (not the IFCP chip ones already above)
    for rc in (scan.get("root_causes") or [])[:8]:
        title = rc.get("title") or rc.get("kind") or "group"
        if "ifcp" in str(rc.get("kind", "")).lower() and any(k for k in chips if chips[k]["nosess"] >= 8):
            continue
        problem(title, [f"{rc.get('cause') or ''} - {len(rc.get('links') or [])} links, e.g. "
                        f"{', '.join((rc.get('links') or [])[:3])}" + (f" (owner: {rc['owner']})" if rc.get("owner") else "")])
    # 4. nodes not read for other reasons
    other = [x for x in scan.get("not_checked") or [] if "without a switch port" not in str(x.get("error"))]
    if other:
        problem("nodes that could not be read", [f"{x.get('role') or 'node'} {x.get('node')}: {str(x.get('error'))[:160]}" for x in other[:6]])
    vf = scan.get("vlan_findings") or []
    if vf:
        problem("VLANs", [f"{f.get('kind')} on {f.get('switch')} {f.get('asic') or ''}: {f.get('detail')}" for f in vf[:5]])
    elif scan.get("vlans"):
        ev.add("VLANs: no VLAN problem found on the chips read", "check")
    for g in (scan.get("gpus") or [])[:4]:
        problem(f"GPU {g.get('tray')} {g.get('bdf')}", [f"{g.get('state')} {g.get('kind')}: {g.get('cause')}"])
    return ev, "this check of the rack"


CHECK_MODE = ("The evidence lists separate problems as [Problem N: ...]. Treat them as INDEPENDENT unless an evidence "
              "item links them. For each problem write '### Problem N: <title>' and under it three short lines: "
              "'Root cause:', 'Debug next (read-only):' (one or two commands, on the right device), 'Remediation (who):'. "
              "Then '### Order' - which problem to fix first and why. Under 350 words.")

WRONG_DEVICE = [
    (re.compile(r"afmctl[^\n]{0,80}\b(?:on\s+)?(?:st\d|switch(?:\s+tray)?)\b|\b(?:on\s+)(?:st\d|the\s+switch)[^\n]{0,20}afmctl", re.I),
     "afmctl runs on compute trays, not on switch trays"),
    (re.compile(r"\b(?:show\s+(?:mac|vlan|interfaces)|sonic-db-cli)\b[^\n]{0,60}\bon\s+ct\d", re.I),
     "SONiC commands (show mac / show vlan / sonic-db-cli) run on switch trays, not on compute trays"),
]


def wrong_device(text: str) -> list[str]:
    return [why for rx, why in WRONG_DEVICE if rx.search(text or "")]


def ask(ev: Evidence, subject: str, question: str = "", history: list | None = None, env=None) -> dict:
    """{answer, model, evidence, unsafe, cited, unknown_citations, seconds}."""
    q = (question or "").strip() or (f"What is the root cause of {subject}, how do I confirm it, and how is it fixed?")
    turns = [m for h in (history or [])[-6:] if isinstance(h, dict) and h.get("q") and h.get("a")
             for m in ({"role": "user", "content": str(h["q"])[:2000]}, {"role": "assistant", "content": str(h["a"])[:4000]})]
    system = SYSTEM + ("\n" + CHECK_MODE if subject == "this check of the rack" and not turns else "")
    if turns:          # a follow-up: the evidence once, the earlier turns, then the new question
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Evidence about {subject}:\n{ev.block()}"},
                {"role": "assistant", "content": "Understood - I will answer from these evidence items."},
                *turns, {"role": "user", "content": f"Question: {q}"}]
    else:
        msgs = [{"role": "system", "content": system},
                {"role": "user", "content": f"Evidence about {subject}:\n{ev.block()}\n\nQuestion: {q}"}]
    t0 = time.time()
    text, model = chat(msgs, env)
    refs = {x["ref"] for x in ev.items}
    cited = sorted(set(re.findall(r"\bE(\d+)\b", text)), key=int)
    return {"answer": text, "model": model, "evidence": ev.items, "unsafe": unsafe_text(text), "wrong_device": wrong_device(text),
            "cited": [f"E{n}" for n in cited if f"E{n}" in refs],
            "unknown_citations": [f"E{n}" for n in cited if f"E{n}" not in refs],
            "seconds": round(time.time() - t0, 1), "subject": subject}
