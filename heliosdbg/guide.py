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
    "sudo journalctl -k -p err -n 200 --no-pager, sudo amd-smi metric --ecc --json, sudo amd-smi bad-pages -g N). One command, no ; && pipes except '| grep X' or '| tail -N'. "
    "Use only PCI addresses (-b ..) seen in the evidence or an earlier step; when none is, list them first "
    "(sudo afmctl show device --json). Do not repeat a command already run. At most 6 steps; conclude earlier when you can."
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
        u = unreachable(s)
        if u:            # not evidence about the problem: the node could not be reached at all
            out.append(f"[S{i}] on {s.get('node')}: `{s.get('command')}` NOT RUN - could not log in to {s.get('node')}: "
                       f"{u['what']}. Do not propose more steps on {s.get('node')}.")
            continue
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
    "compute": ["sudo afmctl show device --json", "sudo amd-smi list --json", "sudo amd-smi metric --ecc --json",
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


def run(host, transport, command: str, role: str, log_dir: Path | None = None) -> dict:
    """Run one allowed read-only command on a node (the allow-list is checked again here)."""
    c, sudo = check(command, role)
    t0 = time.time()
    try:
        if sudo and _pipe(c) >= 0:                        # sudo for the command only; the grep / tail runs as the user
            from .transport import build_command
            head, tail = c[:_pipe(c)], c[_pipe(c) + 1:]
            r = transport.run(build_command(head.strip(), sudo=True) + " | " + tail.strip(), timeout=90, sudo=False)
        else:
            r = transport.run(c, timeout=90, sudo=sudo)
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
    u = unreachable({"rc": rc, "output": out, "node": host.name})
    if u:
        out = f"Could not log in to {host.name}: {u['what']}.\nNext: {u['next']} (owner: {u['owner']})\n\n{out}"
    out = compact(out)                                   # before cutting: a cut JSON cannot be read any more
    if len(out) > OUTPUT_MAX:
        out = out[:OUTPUT_MAX // 2] + f"\n... ({len(out) - OUTPUT_MAX} characters cut) ...\n" + out[-OUTPUT_MAX // 2:]
    return {"node": host.name, "command": c, "rc": rc, "output": out, "seconds": round(time.time() - t0, 1)}
