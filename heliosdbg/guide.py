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

OUTPUT_MAX = 6000
_NS = r"(?:\s+-n\s+asic\d)?"
_WORD = r"[A-Za-z0-9_.:/\[\]*'\"-]+"
_TAIL = rf"(?:\s*\|\s*(?:grep(?:\s+-[iwEFv]+)*\s+{_WORD}|tail\s+-n?\s*\d+|head\s+-n?\s*\d+))?"

SWITCH_RO = [   # (pattern, needs sudo)
    (rf"show\s+interfaces\s+(?:status|description|counters(?:\s+fec-stats|\s+errors|\s+rates)?|transceiver\s+(?:presence|eeprom|lpmode))"
     rf"{_NS}(?:\s+-d\s+all)?(?:\s+-i)?(?:\s+Ethernet\d+)?", False),
    (rf"show\s+mac{_NS}(?:\s+-p\s+Ethernet\d+|\s+-v\s+\d+)?", True),
    (rf"show\s+vlan\s+brief{_NS}", False),
    (r"show\s+(?:version|platform\s+(?:summary|psustatus|fan|temperature|syseeprom|firmware\s+status)|system-memory|"
     r"processes\s+summary|uptime|services|environment|reboot-cause)", False),
    (rf"show\s+(?:pfc\s+counters|queue\s+counters|pfcwd\s+stats|buffer_pool\s+watermark){_NS}", False),
    (r"systemctl\s+status\s+[A-Za-z0-9@_.-]+(?:\s+--no-pager)?", False),
    (r"show\s+logging(?:\s+-f)?", True),
    (rf"show\s+lldp\s+(?:table|neighbors){_NS}", False),
    (rf"sonic-db-cli{_NS}\s+(?:APPL_DB|ASIC_DB|CONFIG_DB|STATE_DB|COUNTERS_DB)\s+(?:keys|hgetall|hget|exists|scan)\s+{_WORD}(?:\s+{_WORD})?", True),
    (r"docker\s+ps(?:\s+-a)?", True),
    (r"uptime|free\s+-[mh]|df\s+-h", False),
    # SONiC and switch platform health, read-only (heliosdbg/health.py and its follow-ups)
    (r"show\s+(?:system-health\s+(?:summary|detail|monitor-list|sysready-status)|platform\s+(?:voltage|current|ssdhealth)|"
     r"reboot-cause(?:\s+history)?|feature\s+status|interfaces\s+counters\s+errors|ip\s+interfaces|ndp|arp)", False),
    (r"crm\s+show\s+(?:resources\s+(?:all|fdb|ipv4\s+route|ipv6\s+route|nexthop|neighbor|acl\s+table|acl\s+group)|thresholds\s+all|summary)", True),
    (r"watchdogutil\s+status|ssdutil(?:\s+-d\s+/dev/[a-z0-9]+)?|sensors|decode-syseeprom", True),
    (r"docker\s+exec\s+[a-z][a-z0-9_-]*\s+(?:supervisorctl\s+status(?:\s+[a-z][a-z0-9_-]*)?|cat\s+/etc/supervisor/critical_processes|"
     r"ps\s+-eo\s+[a-z,]+)", True),
    (r"docker\s+(?:logs\s+--tail\s+\d{1,4}\s+[a-z][a-z0-9_-]*|inspect\s+[a-z][a-z0-9_-]*|stats\s+--no-stream)", True),
    (r"ls\s+-l?\s*/var/core|cat\s+/proc/(?:meminfo|loadavg|uptime)|df\s+-P(?:\s+/[a-z/]*)*", True),
    (r"journalctl\s+(?:-k|-u\s+[A-Za-z0-9@_.-]+|-p\s+(?:err|warning|crit))(?:\s+-p\s+(?:err|warning|crit))?(?:\s+-n\s+\d+)?"
     r"(?:\s+--since\s+-?\d+[hm]|\s+--since\s+'-\d+\s+min')?(?:\s+--no-pager)?(?:\s+-q)?", True),
    (r"systemctl\s+(?:status\s+[A-Za-z0-9@_.-]+(?:\s+--no-pager)?|--failed(?:\s+--no-pager)?|is-active\s+[A-Za-z0-9@_.-]+)", False),
]
COMPUTE_RO = [
    (r"afmctl\s+show\s+(?:device|port|port\s+accelerator-addr|vpod|version|stats)(?:\s+-b\s+[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d)?(?:\s+--json)?", True),
    (r"dmesg(?:\s+-T)?", True),
    (r"ip\s+-br\s+(?:link|addr)", False),
    (r"uptime|free\s+-[mh]|df\s+-h|uname\s+-a", False),
    (r"lspci(?:\s+-[nvkD]+)?(?:\s+-s\s+[0-9a-f:.]+)?", False),
    (r"journalctl\s+(?:-k|-u\s+[A-Za-z0-9@_.-]+|-p\s+(?:err|warning|crit))(?:\s+-p\s+(?:err|warning|crit))?(?:\s+-n\s+\d+)?"
     r"(?:\s+--since\s+-?\d+[hm]|\s+--since\s+'-\d+\s+min')?(?:\s+--no-pager)?(?:\s+-q)?", True),
    (r"df\s+-[Ph](?:\s+/[a-z/]*)*|cat\s+/proc/(?:meminfo|loadavg|uptime)|rdma\s+link\s+show|lspci\s+-d\s+1002:", False),
    # any part of the tray, read-only: GPUs, RDMA NICs, the BMC through the host, services
    (r"amd-smi\s+(?:list|static|metric|firmware|topology|xgmi|process|bad-pages|ras)(?:\s+-[A-Za-z]+|\s+--[a-z-]+|\s+-g\s+\d+)*", True),
    (r"rocm-smi(?:\s+--show[a-z]+|\s+-[itucfPa]|\s+--json)*", True),
    (r"ibv_devinfo(?:\s+-[vl])?(?:\s+-d\s+[A-Za-z0-9_]+)?|rdma\s+(?:link|dev)(?:\s+show)?", False),
    (r"ipmitool\s+(?:sel\s+(?:list|elist|info)|sdr(?:\s+list|\s+elist)?|fru(?:\s+print)?|sensor(?:\s+list)?|"
     r"chassis\s+status|mc\s+info|lan\s+print)", True),
    (r"systemctl\s+status\s+[A-Za-z0-9@_.-]+(?:\s+--no-pager)?|systemctl\s+--failed(?:\s+--no-pager)?", False),
    (r"lsmod|sensors|nvme\s+list|ethtool(?:\s+-[Sim])?\s+[A-Za-z0-9_.-]+", False),
]
FORBIDDEN = re.compile(r"[;&`$<>\n\r\\]|\|\|")


class GuideError(ValueError):
    pass


def check(command: str, role: str) -> tuple[str, bool]:
    """(the command, needs sudo) when it is on the read-only allow-list for that kind of node, else GuideError."""
    c = re.sub(r"^\s*sudo\s+(-n\s+)?", "", str(command or "")).strip()
    if not c or len(c) > 300:
        raise GuideError("no command, or longer than 300 characters")
    if FORBIDDEN.search(c) or c.count("|") > 1:
        raise GuideError("only a single command (optionally '| grep / tail / head') is allowed - no ; && $( ) ` or redirects")
    rules = SWITCH_RO if role == "switch" else COMPUTE_RO if role == "compute" else []
    for pat, sudo in rules:
        if re.fullmatch(pat + _TAIL, c):
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
    "sudo journalctl -k -p err -n 200 --no-pager, sudo amd-smi metric --ecc --json, sudo amd-smi bad-pages -g N). One command, no ; && pipes except '| grep X' or '| tail -N'. "
    "Do not repeat a command already run. At most 6 steps; conclude earlier when you can."
)


def compact(output: str) -> str:
    """afmctl's --json port / device listings in one line per port / GPU (36 ports of JSON are ~6000 characters on one
    line: cut for the model, the ports after the first dozen were never seen). Anything else unchanged."""
    t = (output or "").strip()
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


def steps_block(steps: list[dict]) -> str:
    out = []
    for i, s in enumerate(steps[-8:], 1):
        out.append(f"[S{i}] on {s.get('node')}: `{s.get('command')}` (exit {s.get('rc')}) ->\n"
                   + compact(str(s.get("output") or ""))[:OUTPUT_MAX // 2])
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
    q = (f"Nodes you may use: {node_list}.\n"
         + (f"Steps run so far:\n{steps_block(steps)}\n" if steps else "No step run yet.\n")
         + "What is the next read-only step (or your conclusion)?")
    msgs[-1]["content"] = msgs[-1]["content"].rsplit("\n\nQuestion:", 1)[0] + "\n\n" + q
    return msgs


EXAMPLES = {   # exact forms a refused proposal is shown again (models add flags a command does not take: -n asic0 -d all)
    "switch": ["show system-health detail", "show system-health summary", "watchdogutil status", "crm show resources all",
               "show platform psustatus", "show platform temperature", "show reboot-cause history",
               "docker exec pmon supervisorctl status", "docker logs --tail 100 swss0", "show interfaces status -n asic0",
               "show logging | grep watchdog", "systemctl status watchdog-control"],
    "compute": ["sudo amd-smi metric --ecc --json", "sudo amd-smi list --json", "sudo afmctl show device --json",
                "sudo journalctl -k -p err -n 200 --no-pager", "dmesg | grep -i amdgpu", "lspci -d 1002:", "rdma link show",
                "systemctl --failed --no-pager", "df -h", "free -m"],
}


def propose(ai, ev, subject: str, steps: list[dict], nodes: dict, env=None, retries: int = 1) -> dict:
    """The model's next step: {done, node, command, why, allowed, refused} or {done, conclusion, next}. A proposal the
    read-only list refuses goes back to the model with the reason and the exact forms allowed, once (g02-g17 2 Nov:
    'show system-health detail -n asic0 -d all' was refused, and proposed again on every 'Another step')."""
    msgs = messages(ai, ev, subject, steps, nodes)
    out = _propose_once(ai, msgs, subject, steps, nodes, env)
    for _ in range(retries):
        if out.get("done") or out.get("allowed") or not out.get("refused") or out["refused"].startswith("already run"):
            break
        role = nodes.get(out.get("node"), "switch")
        msgs = msgs + [{"role": "assistant", "content": out.get("_text", "")},
                       {"role": "user", "content": f"Refused: {out['refused']}. Propose ONE command that exists on that node, "
                        f"exactly in one of these forms (or another plain show / read command without extra flags): "
                        f"{'; '.join(EXAMPLES.get(role, EXAMPLES['switch']))}. Answer with the JSON object only."}]
        out = _propose_once(ai, msgs, subject, steps, nodes, env) | {"retried": True}
    out.pop("_text", None)
    return out


def _propose_once(ai, msgs, subject: str, steps: list[dict], nodes: dict, env=None) -> dict:
    text, model = ai.chat(msgs, env, max_tokens=500)
    st = parse_step(text)
    st["model"] = model
    if st.get("done"):          # remembered: a 👍 / 👎 on the conclusion teaches the guided mode (helios-slm)
        return {"done": True, "conclusion": str(st.get("conclusion") or ""), "next": str(st.get("next") or ""), "model": model,
                "answer_id": ai.remember(msgs, text, model, subject + " (step by step)")}
    node = str(st.get("node") or "").strip()
    out = {"done": False, "node": node, "command": str(st.get("command") or "").strip(), "why": str(st.get("why") or ""),
           "model": model, "allowed": False, "refused": None, "_text": text}
    if node not in nodes:
        out["refused"] = f"'{node}' is not a node of this rack"
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


def run(host, transport, command: str, role: str, log_dir: Path | None = None) -> dict:
    """Run one allowed read-only command on a node (the allow-list is checked again here)."""
    c, sudo = check(command, role)
    t0 = time.time()
    try:
        r = transport.run(c, timeout=90, sudo=sudo)       # sudo -n applies to the command, not a final grep / tail
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
    out = compact(out)                                   # before cutting: a cut JSON cannot be read any more
    if len(out) > OUTPUT_MAX:
        out = out[:OUTPUT_MAX // 2] + f"\n... ({len(out) - OUTPUT_MAX} characters cut) ...\n" + out[-OUTPUT_MAX // 2:]
    return {"node": host.name, "command": c, "rc": rc, "output": out, "seconds": round(time.time() - t0, 1)}
