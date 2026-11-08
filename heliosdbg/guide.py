"""Guided debugging: the AI proposes the next read-only command, the person clicks Run, the output becomes evidence for
the next step - until the AI can say what the cause is.

Safety, independent of the model:
  * a command runs only if it matches the READ-ONLY allow-list of its kind of node (SONiC switch tray / compute tray)
    and names a node of the rack's inventory; anything else - other commands, `;` `&&` `|` (except a final
    `| grep / tail / head`), `$( )`, backticks, redirects - is refused before anything is sent;
  * the page runs nothing by itself: every step is a click; the server checks the command again when it runs it;
  * output is cut to OUTPUT_MAX characters for the model; every run (node, command, exit code, time - not the
    output) is appended to results/ai/guided.log.
"""
from __future__ import annotations

import json
import re
import shlex
import time
from pathlib import Path

from . import platforms
from .platforms import sonic as _sonic
from .checks import _NS, _WORD  # noqa: F401

OUTPUT_MAX = 6000
# the grep pattern: quoted, or one word with no glob / quote characters and no leading '-' - it runs in a shell, and a
# pattern like /etc/[gs]hadow expanded to file names made grep print them (audit 4 Nov)
_GREP_PAT = r"(?:'[^'|]{1,80}'|\"[^\"|]{1,80}\"|[A-Za-z0-9_.:/=,@+][A-Za-z0-9_.:/=,@+-]{0,79})"
# flags before or after the pattern ('grep pfc -i' - g02-g17 4 Nov, refused before): flags only, never an argument
_GREP_FLAGS = r"(?:\s+-[iwEFvc]+)*"
_TAIL = rf"(?:\s*\|\s*(?:grep{_GREP_FLAGS}\s+{_GREP_PAT}{_GREP_FLAGS}|tail\s+-n?\s*\d+|head\s+-n?\s*\d+))?"

SWITCH_RO = platforms.read_only("switch")     # (pattern, needs sudo), from each platform's READ_ONLY
COMPUTE_RO = platforms.read_only("compute")
FORBIDDEN = re.compile(r"[;&`$<>\n\r\\]|\|\|")
# a PCI address the model made up: 0000:00:00.0 is the host bridge, never a GPU (g02-g17 4 Nov: afmctl 'No such device')
PLACEHOLDER_BDF = re.compile(r"\b0000:00:00\.0\b")


class GuideError(ValueError):
    pass


# helios-debug's Broadcom view of one switch port (heliosdbg/bcm.py, the reads Diagnose a link makes): finds the port's
# Broadcom logical port, reads lock / training / faults / per-lane signal, SNR and eye / FEC histogram, and compares it
# with a working port of the same chip - one step instead of five bcmcmd lookups the model cannot map by itself
BCM_VIEW = re.compile(r"bcm-view(?:\s+-n\s+(asic\d))?\s+(Ethernet\d+)")


def unreachable(step: dict) -> dict | None:
    """{what, owner, next} when a step could not log in to its node (ssh exit 255: no route, refused, timed out ..)."""
    if str(step.get("rc")) != "255":
        return None
    from .reach import classify
    return classify(str(step.get("output") or ""), host=str(step.get("node") or ""))


def _pipe(c: str) -> int:
    """Where the command's pipe is (-1: none), skipping a '|' inside quotes (sonic-db-cli's 'TABLE|key'); -2: more than one."""
    q, at = "", -1
    for i, ch in enumerate(c):
        if q:
            q = "" if ch == q else q
        elif ch in "'\"":
            q = ch
        elif ch == "|":
            if at >= 0:
                return -2
            at = i
    return at


def check(command: str, role: str) -> tuple[str, bool]:
    """(the command, needs sudo) when it is on the read-only allow-list for that kind of node, else GuideError."""
    c = re.sub(r"^\s*sudo\s+(-n\s+)?", "", str(command or "")).strip()
    if not c or len(c) > 300:
        raise GuideError("no command, or longer than 300 characters")
    if FORBIDDEN.search(c) or _pipe(c) == -2:
        raise GuideError("only a single command (optionally '| grep / tail / head') is allowed - no ; && $( ) ` or redirects")
    if role == "switch" and BCM_VIEW.fullmatch(c):
        return c, False
    rules = SWITCH_RO if role == "switch" else COMPUTE_RO if role == "compute" else []
    for pat, sudo in rules:
        if re.fullmatch(f"(?:{pat}){_TAIL}", c):            # grouped: the tail applies to every alternative
            if PLACEHOLDER_BDF.search(c):
                raise GuideError("0000:00:00.0 is a placeholder, not a GPU's PCI address - take the address from "
                                 "'sudo afmctl show device --json' (or 'sudo amd-smi list --json') on that tray first")
            return c, sudo
    kind = "switch tray (SONiC)" if role == "switch" else "compute tray"
    raise GuideError(f"'{c}' is not on the read-only list for a {kind} - the guided mode runs only show / read commands "
                     f"(run anything else yourself in the Terminal)")


GUIDE_SYSTEM_ADD = (
    "\nYou are now guiding an investigation step by step. Answer ONLY with one JSON object, no other text:\n"
    '{"done": false, "node": "<a node name from the inventory list>", "command": "<one read-only command>", '
    '"why": "<what this will show, one sentence>"}\n'
    'or, when the evidence (including the outputs of earlier steps [S1]..) is enough:\n'
    '{"done": true, "conclusion": "<root cause in two sentences, citing [E..] / [S..]>", "next": "<what to do and who>"}\n'
    "Each command must be read-only and exist on that node (switch trays: show ..., sudo sonic-db-cli ..., docker ps; "
    "compute trays: sudo afmctl show ..., dmesg, ip -br link, sudo amd-smi metric / static, sudo ipmitool sel list, "
    "ibv_devinfo, systemctl status <unit>; health: show system-health detail, crm show resources all, watchdogutil status, "
    "sudo docker exec <container> supervisorctl status, sudo docker logs --tail 100 <container>, show reboot-cause history, "
    "sudo journalctl -k -p err -n 200 --no-pager, sudo amd-smi metric --ecc --json, sudo amd-smi bad-pages -g N; "
    "the switch ASIC's own view of a link that is down, flaps or has errors: bcm-view -n asicN EthernetX; "
    "no IFCP session on a switch's links: sudo ip -n asicN -s -o link show (does the switch CPU receive from its ports), "
    "systemctl status afm-agent, sudo tail -n 100 /opt/amd/afm/agent/logs/ifcp-err.log, "
    "sudo ls -lt /opt/amd/afm/agent/logs/ - a log that stopped being written means a stuck agent). One command, no ; && pipes except '| grep X' or '| tail -N'. "
    "Use only PCI addresses (-b ..) seen in the evidence or an earlier step; when none is, list them first "
    "(sudo afmctl show device --json). Do not repeat a command already run. Stay on the problem asked about: its nodes "
    "only, not the rack's other problems. At most 6 steps; conclude earlier when you can."
)


def compact(output: str) -> str:
    """afmctl's --json port / device listings in one line per port / GPU (36 ports of JSON are ~6000 characters on one
    line: cut for the model, the ports after the first dozen were never seen). Anything else unchanged."""
    t = (output or "").strip()
    rx = _sonic.cpu_rx(t) if not t.startswith("{") else None
    if rx is not None:                      # 'ip -s -o link show': ~110 KB for 257 ports - what it says, in one line
        return _sonic.cpu_rx_line(rx)
    if not t.startswith("{"):
        return output
    try:
        d = json.loads(t.split("\n[stderr]", 1)[0])
    except ValueError:
        return output
    lines = []
    for dev in d.get("device") or []:
        if not isinstance(dev, dict):
            continue
        if dev.get("port"):
            lines.append(f"GPU {dev.get('bdf')}:")
            for p in dev["port"]:
                sp, st = p.get("spec") or {}, p.get("status") or {}
                ic = st.get("ifcp") or {}
                lines.append(f" port {p.get('id')}: {st.get('link_status')}, admin {sp.get('admin_state')}, "
                             f"IFCP ll_up {ic.get('ll_up')} peer_enabled {ic.get('peer_enabled')} peer {ic.get('peer_device_id')}/"
                             f"{ic.get('peer_port_id')}" + (" IN ERROR" if "yes" in (ic.get("in_error"), ic.get("peer_in_error")) else ""))
        else:
            sp, st = dev.get("spec") or {}, dev.get("status") or {}
            state = st.get("state") or st.get("oper_state")
            lines.append(f"GPU {dev.get('bdf')}: accelerator {sp.get('accelerator_id')}, config_phase {sp.get('config_phase')}, "
                         + (f"state {state}, " if state else "") + f"vPOD accelerators {len(sp.get('vpod_accelerators') or [])}")
    return "\n".join(lines) if lines else output


_IFCP_ERR = re.compile(r'"ts":"(\d{4}-\d\d-\d\dT[\d:.]+)Z?"[^\n]*?"msg":"(Ethernet\d+): Error sending discover')


def _age_min(ts: str) -> int | None:
    import datetime as dt
    try:
        t = dt.datetime.fromisoformat(ts[:19]).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None
    return int((dt.datetime.now(dt.timezone.utc) - t).total_seconds() // 60)


_CPU_RX = re.compile(r"^CPU receive[^:]*: \d+ Ethernet ports, (\d+) with link; (\d+) of those", re.M)
_GPU_PORT = re.compile(r"^\s*port (\d+): (\S+?)(?:, (\S+?))?, admin (\w+)", re.M)
_SW_PORT = re.compile(r"^(Ethernet\d+)\s+\S+\s+\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+(up|down)\s+(up|down)\b", re.M)


def step_facts(steps: list[dict]) -> list[str]:
    """What the outputs of the steps show, read by code (not the model): GPU ports with no signal against the rest of
    the GPU, switch ports admin up / oper down. g02-g17 4 Nov (mr2): one link down at both ends, and the model's
    conclusion was to power the switch tray off and on."""
    facts, gpu_down, sw_down, sw_dark, cpu_dead = [], 0, 0, False, False
    sw_remote = sw_lane = False
    sw_cfg = ""
    for i, s in enumerate(steps, 1):
        out, node = str(s.get("output") or ""), s.get("node")
        for bdf, body in re.findall(r"^GPU (\S+):\n((?:\s+port .*\n?)+)", out, re.M):
            ports = _GPU_PORT.findall(body)
            down = [(n, st, extra) for n, st, extra, _a in ports if st != "LINK_UP"]
            if down and len(down) < len(ports):
                gpu_down += len(down)
                facts.append(f"[S{i}] {node} GPU {bdf}: port(s) " + ", ".join(f"{n} {st}" + (f"/{x}" if x else "") for n, st, x in down)
                             + f" - the other {len(ports) - len(down)} ports of this GPU are up, so the GPU and its tray work")
        bv = re.search(r"^Broadcom view of (Ethernet\d+)[^\n]*\nVerdict \(code[^)]*\): (.*)$", out, re.M)
        if bv:
            facts.append(f"[S{i}] {node} {bv.group(1)}, Broadcom (switch ASIC): {bv.group(2)}")
            verdict = bv.group(2)
            if "receives no signal on any" in verdict:
                sw_dark = True
            elif "remote fault" in verdict:
                sw_remote = True
            elif "no signal on lane(s)" in verdict:
                sw_lane = True
            elif "configured differently" in verdict or "loopback" in verdict or "disabled" in verdict:
                sw_cfg = verdict
        errs = _IFCP_ERR.findall(out) if "ifcp-err.log" in str(s.get("command") or "") else []
        if errs:
            newest = max(t for t, _p in errs)
            age = _age_min(newest)
            ports = {p_ for _t, p_ in errs}
            facts.append(f"[S{i}] {node} ifcp-err.log: the newest error is from {newest[:19].replace('T', ' ')} UTC"
                         + (f" ({age} min before this was read)" if age is not None else "")
                         + f", 'Error sending discover message' on {len(ports)} port(s) in these lines"
                         + ("; nothing newer - if the links are ok again now, the fault has cleared (check IFCP again)"
                            if age is not None and age >= 10 else ""))
        m = _CPU_RX.search(out)
        if m and int(m.group(1)) >= 8 and int(m.group(2)) == 0:
            cpu_dead = True
            facts.append(f"[S{i}] {node}: none of its {m.group(1)} ports with link has received a packet on the switch CPU "
                         "- the chip passes nothing up, so IFCP discovery on this switch hears no GPU (the switch's packet "
                         "path: its switch services / kernel driver), not the cables or the GPUs")
        elif m:
            facts.append(f"[S{i}] {node}: {m.group(2)} of its {m.group(1)} ports with link receive packets on the CPU - "
                         "the switch's packet path to the CPU works")
        for port, oper, admin in _SW_PORT.findall(out):
            if oper == "down" and admin == "up":
                sw_down += 1
                facts.append(f"[S{i}] {node} {port}: admin up, oper down - enabled, but no link (not shut by configuration)")
    if gpu_down and sw_dark:
        facts.append("Together: the GPU port has no link (NO_PHY_LINK) and the switch receives no signal on any lane while "
                     "it transmits - neither end sees the other: the cable or a connector of that one link (site / cabling: "
                     "reseat or swap it). Not the GPU, not the switch tray: their other ports work.")
    elif gpu_down and sw_remote:
        facts.append("Together: the switch receives the GPU and locks, the GPU port has no link and the switch reads a "
                     "remote fault - only the switch-to-GPU direction fails: the switch's transmitter on that port, that "
                     "direction of the cable, or the GPU port's receiver. Swap the cable first; the trays' other ports work.")
    elif gpu_down and sw_lane:
        facts.append("Together: the GPU port is down and the switch lacks signal on some lanes only - one lane of the "
                     "cable / connector (site / cabling: reseat or swap that one cable).")
    elif sw_cfg:
        facts.append(f"Together: the switch end is set up wrong for this link ({sw_cfg.split(':')[0]}) - fix the "
                     "configuration before touching the cable.")
    elif cpu_dead:
        facts.append("Together: the switch CPU receives nothing from any port while the links are up - the AFM agent "
                     "is not the first suspect, the switch's packet path to its CPU is (it can clear by itself - check again; "
                     "restarting switch services or rebooting changes the switch: only with a go-ahead).")
    elif gpu_down and sw_down:
        facts.append("Together: one link has no signal at either end - the cable, a connector or a transceiver (site / "
                     "cabling: reseat or swap that one cable). Restarting or powering a whole tray is out of proportion for it.")
    return facts


# 'on st1: `show interfaces status -n asic1 Ethernet257`' / 'on pod-1-0-ComputeTray (c1): `sudo afmctl ...`' in an answer
_ON_CMD = re.compile(r"\bon\s+(?:the\s+)?([A-Za-z0-9][\w.-]*)(?:\s*\(([\w.-]+)\))?\s*:?\s*`([^`\n]{2,300})`")


_CMD_START = re.compile(r"^(?:sudo\s+)?(?:show|bcm-view|bcmcmd|afmctl|amd-smi|sonic-db-cli|docker|dmesg|journalctl|systemctl|"
                        r"rdma|nicctl|crm|watchdogutil|ip\s|lspci|ibv_devinfo|ipmitool\s+sel|tail\s+-n|ls\s+-lt|uname|dkms|"
                        r"cat\s+/proc/cmdline|ls\s+/boot)\b")
_BDF = r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d"


def context_values(text: str) -> dict:
    """The values a placeholder can only mean here, when the evidence / earlier outputs name exactly one: the switch
    tray, chip and port of the link, the GPU's tray and PCI address, the port's Broadcom logical port."""
    def one(vals):
        vals = list(dict.fromkeys(vals))
        return vals[0] if len(vals) == 1 else None
    links = re.findall(r"\b(st\d+)\s+(asic\d)\s+(Ethernet\d+)\b", text)
    gpus = re.findall(rf"\((c\d+|ct\d+)\)\s+GPU\d+\s+\(({_BDF})\)", text)
    lp = one(re.findall(r"\(logical (\d+)\)", text))
    v = {"switch": one([x[0] for x in links]), "asic": one([x[1] for x in links]), "port": one([x[2] for x in links]),
         "tray": one([x[0] for x in gpus]), "bdf": one([x[1] for x in gpus]), "logical": lp}
    return {k: x for k, x in v.items() if x}


def _fill(cmd: str, v: dict) -> tuple[str, list[str]]:
    """Placeholders replaced by the one value the context gives: <bdf>, <logical>, asicN / -n N, EthernetX."""
    used = []
    def sub(rx, key, val=None):
        nonlocal cmd
        if key in v and re.search(rx, cmd):
            cmd = re.sub(rx, val or v[key], cmd)
            used.append(key)
    sub(r"<bdf>|<BDF>|<pci(?:[ _-]address)?>", "bdf")
    sub(r"LANE_INDEX=<[a-z]+>", "logical", "LANE_INDEX=0")          # lane 0 - the output says so; lane 1 by hand
    sub(r"<logical(?:[ _-]port)?>|<port[ _-]id>|<PORT_ID>", "logical")
    if "asic" in v:
        sub(r"\basicN\b|<asic>", "asic")
        sub(r"(\bbcmcmd\s+-n\s+)(?:N\b|<[nN]>|<unit>|<asic>)", "asic", r"\g<1>" + v["asic"][-1])
        sub(r"(\s-n\s+)<asic(?:N|\d)?>", "asic", r"\g<1>" + v["asic"])
    sub(r"\bEthernet(?:X|N|<port>)\b|<port>|<interface>", "port")
    return cmd, used


def runnable(text: str, roles: dict, aliases: dict | None = None, context: str = "") -> list[dict]:
    """The commands an answer suggests: [{node, command, allowed, refused, why?}] - each checked against the read-only
    list exactly like a step, so the person can run it from the answer (and continue step by step). 'on st1: `..`'
    names the node; a command without one goes to the one switch tray / GPU tray the evidence is about. Placeholders
    (<bdf>, <logical>, asicN, EthernetX) are filled when the evidence or an earlier output names exactly one value."""
    al = {n.lower(): n for n in roles} | {str(k).lower(): v for k, v in (aliases or {}).items() if v in roles}
    v = context_values(context or "")
    out, seen, spans = [], set(), []
    found = []
    for m in _ON_CMD.finditer(text or ""):
        node = al.get((m.group(2) or "").lower()) or al.get(m.group(1).lower())
        spans.append(m.span(3))
        if node:
            found.append((node, m.group(3).strip()))
    for m in re.finditer(r"`([^`\n]{2,300})`", text or ""):
        if any(a <= m.start(1) < b for a, b in spans) or not _CMD_START.match(m.group(1).strip()):
            continue
        c = m.group(1).strip()
        sw = v.get("switch") if v.get("switch") in roles else None
        tray = v.get("tray") if v.get("tray") in roles else None
        node = sw if re.match(r"(?:sudo\s+)?(?:show|bcm[\w-]*|sonic-db-cli|crm|watchdogutil|docker)\b", c) else tray if re.match(
            r"(?:sudo\s+)?(?:afmctl|amd-smi|rdma|nicctl|lspci|ibv_devinfo)\b", c) else None
        if node:
            found.append((node, c))
    for node, cmd in found:
        if (node, cmd) in seen:
            continue
        seen.add((node, cmd))
        filled, used = _fill(cmd, v)
        item = {"node": node, "command": filled, "allowed": False, "refused": None}
        if used:
            item["why"] = "filled in from the evidence: " + ", ".join(f"{k} {v[k]}" for k in used)
        if re.search(r"<[^<>]*>", filled):
            item["refused"] = "it has a placeholder (<...>) - ask for the exact command, or continue step by step"
        else:
            try:
                item["command"], _sudo = check(filled, roles[node])
                item["allowed"] = True
            except GuideError as e:
                item["refused"] = str(e)
        out.append(item)
        pm = re.search(r"(?:-n\s+(asic\d)\b.*?)?\b(Ethernet\d+)\b", item["command"]) if roles[node] == "switch" and item["allowed"] else None
        bv = f"bcm-view{' -n ' + pm.group(1) if pm.group(1) else ''} {pm.group(2)}" if pm else ""
        if bv and (node, "bcm", pm.group(2)) not in seen and not item["command"].startswith("bcm"):
            seen.add((node, "bcm", pm.group(2)))
            out.append({"node": node, "command": bv, "allowed": True, "refused": None,
                        "why": "the switch ASIC's own view of that port (signal, lock, SNR, FEC) - helios-debug reads it"})
    return out[:10]


def steps_evidence(ev, steps: list[dict]) -> None:
    """Commands already run (from answers or step by step) as evidence for the next question: what code reads in their
    outputs first, then each output (cut)."""
    ran = [(i, s) for i, s in enumerate(steps, 1) if isinstance(s, dict) and str(s.get("rc")) != "skipped"]
    if not ran:
        return
    for f in step_facts([s for _i, s in ran]):
        ev.add("From the commands run: " + f, "steps")
    for i, s in ran[-8:]:
        u = unreachable(s)
        ev.add(f"Command S{i} run on {s.get('node')}: `{s.get('command')}` - " + (f"not run, could not log in: {u['what']}" if u else
               f"exit {s.get('rc')}, output: " + for_model(compact(str(s.get("output") or ""))).strip()[:480]), "steps")


def _ranges(ns: list[int]) -> str:
    out, i = [], 0
    while i < len(ns):
        j = i
        while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1:
            j += 1
        out.append(str(ns[i]) if i == j else f"{ns[i]}-{ns[j]}")
        i = j + 1
    return ",".join(out)


def for_model(text: str) -> str:
    """A GPU's 36 port lines grouped by state, the smallest groups (the odd ports) first - a small model read 'port 13
    NO_PHY_LINK' in the middle of 35 LINK_UP lines as 'the GPU port is up', and a cut output lost it (mr2 4 Nov)."""
    def one(m):
        groups: dict[str, list[int]] = {}
        for n, rest in re.findall(r"^\s*port (\d+): (.*)$", m.group(2), re.M):
            groups.setdefault(re.sub(r"\s+peer \S+/\S+$", "", rest.strip()), []).append(int(n))
        total = sum(len(v) for v in groups.values())
        lines = [f"GPU {m.group(1)} ({total} ports):"]
        for state, ns in sorted(groups.items(), key=lambda kv: len(kv[1])):
            lines.append(f" port{'s' if len(ns) > 1 else ''} {_ranges(sorted(ns))}: {state}")
        return "\n".join(lines) + "\n"
    return re.sub(r"^GPU (\S+):\n((?:[ \t]+port .*\n?)+)", one, text or "", flags=re.M)


def steps_block(steps: list[dict]) -> str:
    out = []
    for i, s in enumerate(steps[-8:], 1):
        u = unreachable(s)
        if u:            # not evidence about the problem: the node could not be reached at all
            out.append(f"[S{i}] on {s.get('node')}: `{s.get('command')}` NOT RUN - could not log in to {s.get('node')}: "
                       f"{u['what']}. Do not propose more steps on {s.get('node')}.")
            continue
        out.append(f"[S{i}] on {s.get('node')}: `{s.get('command')}` (exit {s.get('rc')}) ->\n"
                   + for_model(compact(str(s.get("output") or ""))).strip()[:OUTPUT_MAX // 2])
    return "\n".join(out)


def parse_step(text: str) -> dict:
    t = re.sub(r"```(?:json)?", "", text or "")
    i = t.find("{")
    while i != -1:
        depth = 0
        for k in range(i, len(t)):
            depth += (t[k] == "{") - (t[k] == "}")
            if depth == 0:
                try:
                    v = json.loads(t[i:k + 1])
                    if isinstance(v, dict):
                        return v
                except ValueError:
                    break
                break
        i = t.find("{", i + 1)
    raise GuideError("the model did not answer with a step (JSON) - ask again")


def messages(ai, ev, subject: str, steps: list[dict], nodes: dict) -> list[dict]:
    """The chat messages of one guided step - also what helios-slm (vguide.py) trains and evaluates on."""
    msgs = ai.build_messages(ev, subject)
    msgs[0]["content"] += GUIDE_SYSTEM_ADD
    node_list = ", ".join(f"{n} ({r})" for n, r in sorted(nodes.items()))
    facts = step_facts(steps)
    q = (f"Nodes you may use: {node_list}.\n"
         + (f"Steps run so far:\n{steps_block(steps)}\n" if steps else "No step run yet.\n")
         + ("What code read in these outputs (exact - where your reading differs, this is right; build on it):\n"
            + "\n".join("- " + f for f in facts) + "\n" if facts else "")
         + (f"{len(steps)} steps run: conclude now ({{\"done\": true, ...}}).\n" if len(steps) >= 6 else "")
         + "What is the next read-only step (or your conclusion)?")
    msgs[-1]["content"] = msgs[-1]["content"].rsplit("\n\nQuestion:", 1)[0] + "\n\n" + q
    return msgs


EXAMPLES = {   # exact forms a refused proposal is shown again (models add flags a command does not take: -n asic0 -d all)
    "switch": ["show system-health detail", "show system-health summary", "watchdogutil status", "crm show resources all",
               "show platform psustatus", "show platform temperature", "show reboot-cause history",
               "docker exec pmon supervisorctl status", "docker logs --tail 100 swss0", "show interfaces status -n asic0",
               "show logging | grep watchdog", "systemctl status watchdog-control", "bcm-view -n asic0 Ethernet8",
               "systemctl status afm-agent", "tail -n 100 /opt/amd/afm/agent/logs/ifcp-err.log", "ls -lt /opt/amd/afm/agent/logs/",
               "ip -n asic0 -s -o link show"],
    "compute": ["sudo afmctl show device --json", "sudo amd-smi list --json", "sudo amd-smi metric --ecc --json",
                "sudo journalctl -k -p err -n 200 --no-pager", "dmesg | grep -i amdgpu", "lspci -d 1002:", "lspci -k -d 1002:", "uname -r", "dkms status", "rdma link show",
                "systemctl --failed --no-pager", "df -h", "free -m"],
}


class NotJSON(GuideError):
    def __init__(self, text: str):
        super().__init__("the model did not answer with a step (JSON) - ask again")
        self.text = text


def propose(ai, ev, subject: str, steps: list[dict], nodes: dict, env=None, retries: int = 1, stay=()) -> dict:
    """The model's next step: {done, node, command, why, allowed, refused} or {done, conclusion, next}. A proposal the
    read-only list refuses goes back to the model with the reason and the exact forms allowed, once (g02-g17 2 Nov:
    'show system-health detail -n asic0 -d all' was refused, and proposed again on every 'Another step')."""
    msgs = messages(ai, ev, subject, steps, nodes)
    try:
        out = _propose_once(ai, msgs, subject, steps, nodes, env, stay)
    except NotJSON as e:                     # once more, told so (g02-g17 4 Nov: step 8 came back as prose)
        msgs = msgs + [{"role": "assistant", "content": e.text[:1500]},
                       {"role": "user", "content": "That was not the JSON object. Answer with ONE JSON object only: the next "
                        "step, or {\"done\": true, \"conclusion\": ..., \"next\": ...}."}]
        out = _propose_once(ai, msgs, subject, steps, nodes, env, stay) | {"retried": True}
    for _ in range(retries):
        if out.get("done") or out.get("allowed") or not out.get("refused") or out["refused"].startswith("already run"):
            break
        role = nodes.get(out.get("node"), "switch")
        msgs = msgs + [{"role": "assistant", "content": out.get("_text", "")},
                       {"role": "user", "content": f"Refused: {out['refused']}. Propose ONE command that exists on that node, "
                        f"exactly in one of these forms (or another plain show / read command without extra flags): "
                        f"{'; '.join(EXAMPLES.get(role, EXAMPLES['switch']))}. Answer with the JSON object only."}]
        out = _propose_once(ai, msgs, subject, steps, nodes, env, stay) | {"retried": True}
    if out.get("done") and out.get("contradiction"):     # once more, told so: its own MTU reading is not low
        from .ai import FABRIC_MTU
        msgs = msgs + [{"role": "assistant", "content": out.get("_text", "")},
                       {"role": "user", "content": f"Your conclusion says \"{out['contradiction']}\" - that MTU is not below "
                        f"the fabric's {FABRIC_MTU}, so the MTU is not the cause. Conclude again from what the outputs show, "
                        f"or propose another step. Answer with the JSON object only."}]
        again = _propose_once(ai, msgs, subject, steps, nodes, env, stay)
        out = again | {"retried": True, "contradiction_before": out["contradiction"]}
    out.pop("_text", None)
    return out


def _seen(msgs: list[dict]) -> str:
    """What the model was shown about the rack: evidence and step outputs, not the documentation passages."""
    return "\n".join(str(m.get("content") or "").split("\n\nDocumentation passages:")[0] for m in msgs if m.get("role") == "user")


def _propose_once(ai, msgs, subject: str, steps: list[dict], nodes: dict, env=None, stay=()) -> dict:
    text, model = ai.chat(msgs, env, max_tokens=500)
    try:
        st = parse_step(text)
    except GuideError:
        raise NotJSON(text) from None
    st["model"] = model
    if st.get("done"):          # remembered: a 👍 / 👎 on the conclusion teaches the guided mode (helios-slm)
        from .ai import Evidence, invented, mtu_contradiction, unsafe_text
        concl, nxt = str(st.get("conclusion") or ""), str(st.get("next") or "")
        return {"done": True, "conclusion": concl, "next": nxt, "model": model, "facts": step_facts(steps),
                "unsafe": unsafe_text(concl + "\n" + nxt), "_text": text,
                "not_in_evidence": invented(concl, Evidence(), _seen(msgs)), "contradiction": mtu_contradiction(concl),
                "answer_id": ai.remember(msgs, text, model, subject + " (step by step)")}
    node = str(st.get("node") or "").strip()
    out = {"done": False, "node": node, "command": str(st.get("command") or "").strip(), "why": str(st.get("why") or ""),
           "model": model, "allowed": False, "refused": None, "_text": text}
    if node not in nodes:
        out["refused"] = f"'{node}' is not a node of this rack"
        return out
    if stay and node not in stay:
        out["refused"] = (f"{node} is not part of the problem asked about - stay on {', '.join(sorted(stay))}, or conclude")
        return out
    down = next((u for s_ in steps if s_.get("node") == node for u in [unreachable(s_)] if u), None)
    if down:
        out["refused"] = f"{node} could not be reached in an earlier step ({down['what']}) - use another node, or conclude"
        return out
    try:
        out["command"], _sudo = check(out["command"], nodes[node])
        if any(s.get("node") == node and s.get("command") == out["command"] for s in steps):
            out["refused"] = "already run - ask again for another step"
        else:
            out["allowed"] = True
    except GuideError as e:
        out["refused"] = str(e)
    return out


_STATUS_ROW = re.compile(r"^(Ethernet\d+)\s+(\S+)\s+\S+\s+\d+\s+\S+\s+\S+\s+(\S+)\s+(up|down)\s+(up|down)\b", re.M)


def bcm_view(transport, ns: str | None, port: str) -> tuple[int, str]:
    """(rc, text): the switch ASIC's own view of one port, judged by bcm.judge against a working port of the chip."""
    from . import bcm
    status, used = {}, ns
    for cand in ([ns] if ns else ["asic0", "asic1", None]):
        r = transport.run("show interfaces status" + (f" -n {cand}" if cand else ""), timeout=90, sudo=False)
        if r.rc == 255:                                  # not logged in: say so, as any other step
            return 255, (r.stdout or "") + "\n[stderr] " + (getattr(r, "stderr", "") or "")
        status = {m.group(1): {"Lanes": m.group(2), "Vlan": m.group(3), "Oper": m.group(4), "Admin": m.group(5)}
                  for m in _STATUS_ROW.finditer(r.stdout or "")}
        if port in status:
            used = cand
            break
    if port not in status:
        return 1, f"{port} is not in 'show interfaces status{' -n ' + ns if ns else ''}' on this switch tray"
    st = status[port]
    ref = bcm.reference_port(status, {port})

    class _Sw:                                           # bcm.read_ports runs its own 'sudo -n timeout 60 bcmcmd ...'
        def run(self, cmd, timeout=120):
            return transport.run(cmd, timeout=timeout, sudo=False)
    views = bcm.read_ports(_Sw(), used, {port: st["Lanes"]} | ({ref[0]: ref[1]} if ref else {}))
    v, refv = views.get(port) or {}, (views.get(ref[0]) if ref else None)
    refv = refv if refv and not refv.get("error") else None
    finding, ev = bcm.judge(v, refv, oper_down=st["Oper"] != "up")
    unit = bcm.unit_flag(used)
    lp = v.get("logical", "<logical>")
    if st["Oper"] == "up" and isinstance(lp, int):       # an up link: are errors growing right now?
        dl = bcm.delta(_Sw(), used, lp, wait=10)
        grew = bcm.judge_delta(dl)
        ev.append(f"  counters read twice, {dl.get('seconds')} s apart: " + (dl["error"] if dl.get("error") else
                  ", ".join(f"{k} +{c}" for k, c in {**dl["fec"], **dl["mac"]}.items() if c) or "nothing grew"))
        if grew and not finding:
            finding = grew
    lines = [f"Broadcom view of {port}{' (' + used + ')' if used else ''}: SONiC lanes {st['Lanes']}, oper {st['Oper']}, admin {st['Admin']}",
             "Verdict (code, heliosdbg/bcm.py): " + (finding or "the switch ASIC sees nothing wrong on this port"), *ev]
    if refv:
        lines.append(f"Reference - a working port of the same chip, {ref[0]}: {bcm.brief(refv)}")
    lines += ["", "Read with (run them yourself the same way):",
              f"  sudo bcmcmd{unit} 'show pmap'   (physical port {st['Lanes'].split(',')[0]} -> {v.get('bcm_port', '?')}, logical {lp})"]
    lines += [f"  sudo bcmcmd{unit} 'bsh -c \"lt {t} lookup PORT_ID={lp}{x}\"'" for t, x in (
        ("PC_PORT_STATUS", " STATUS=STATUS_ALL"), ("PC_PHY_STATUS", " LANE_INDEX=0"),
        ("PC_PHY_STATUS_2", " LANE_INDEX=0 STATUS=STATUS_2_ALL"), ("PC_PORT_CUMULATIVE_DIAG_STATS", ""),
        ("LM_LINK_STATE", ""), ("PC_PORT", ""), ("PC_FDR_STATS", ""), ("CTR_MAC_ERR", ""))]
    return (0 if not v.get("error") else 1), "\n".join(lines)


def run(host, transport, command: str, role: str, log_dir: Path | None = None) -> dict:
    """Run one allowed read-only command on a node (the allow-list is checked again here)."""
    c, sudo = check(command, role)
    t0 = time.time()
    try:
        bv = BCM_VIEW.fullmatch(c)
        if bv:
            rc, out = bcm_view(transport, bv.group(1), bv.group(2))
            r = None
        elif c.startswith("bcmcmd"):                     # it reads stdin: closed, and a time limit
            from .transport import build_command
            at = _pipe(c)
            head, tail = (c[:at], c[at + 1:]) if at >= 0 else (c, "")
            r = transport.run(build_command(f"timeout 60 {head.strip()} </dev/null 2>&1", sudo=True)
                              + (" | " + tail.strip() if tail else ""), timeout=90, sudo=False)
        elif sudo and _pipe(c) >= 0:                      # sudo for the command only; the grep / tail runs as the user
            from .transport import build_command
            head, tail = c[:_pipe(c)], c[_pipe(c) + 1:]
            r = transport.run(build_command(head.strip(), sudo=True) + " | " + tail.strip(), timeout=90, sudo=False)
        else:
            r = transport.run(c, timeout=90, sudo=sudo)
        if r is not None:
            rc, out = r.rc, (r.stdout or "") + (("\n[stderr] " + r.stderr) if getattr(r, "stderr", "") else "")
    except Exception as e:  # noqa: BLE001 - shown as the step's output
        rc, out = -1, f"{type(e).__name__}: {str(e)[:300]}"
    if log_dir:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with (log_dir / "guided.log").open("a") as fh:
                fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {host.name} rc={rc} "
                         f"{round(time.time() - t0, 1)}s {shlex.quote(c)}\n")
        except OSError:
            pass
    if rc == 0 and not out.strip():
        out = "(no output - the command printed nothing" + (": afmctl knows no GPU at that address on this tray - list them "
                                                           "with 'sudo afmctl show device --json'" if " -b " in c else "") + ")"
    u = unreachable({"rc": rc, "output": out, "node": host.name})
    if u:
        out = f"Could not log in to {host.name}: {u['what']}.\nNext: {u['next']} (owner: {u['owner']})\n\n{out}"
    out = compact(out)                                   # before cutting: a cut JSON cannot be read any more
    if len(out) > OUTPUT_MAX:
        out = out[:OUTPUT_MAX // 2] + f"\n... ({len(out) - OUTPUT_MAX} characters cut) ...\n" + out[-OUTPUT_MAX // 2:]
    return {"node": host.name, "command": c, "rc": rc, "output": out, "seconds": round(time.time() - t0, 1)}
