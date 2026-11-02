"""The core of every health check, whatever the platform: a finding (one problem with its evidence, area, owner and
next step), the thresholds, how a command's output is read (a missing command is 'not checked', never 'healthy'),
running a check through a flaky jump host, the generic Linux disk / memory rules, the rack-wide grouping, the summary
and report.txt. What is checked on which kind of node lives in heliosdbg/platforms/ - one module per platform.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable

CRITICAL, WARNING = "critical", "warning"
_NS = r"(?:\s+-n\s+asic\d)?"                     # allow-list pattern parts (platforms' READ_ONLY, guide.py)
_WORD = r"[A-Za-z0-9_.:/\[\]*'\"-]+"
OWNERS = {"sonic": "network", "switch": "network", "power": "hardware", "thermal": "hardware", "bmc": "hardware",
          "afm": "AFM", "gpu": "compute", "compute": "compute", "os": "compute", "rdma": "compute"}

# thresholds (the inventory's health: block overrides them)
LIMITS = {"disk_warn": 85, "disk_crit": 95, "mem_avail_warn": 10, "mem_avail_crit": 5, "crm_warn": 85, "crm_crit": 98,
          "gpu_hot": 100, "cert_days": 30, "restart_warn": 1, "syslog_burst": 20}


@dataclass
class Platform:
    """What one platform checks on a node: its read-only commands [(check, command, sudo)], an optional collect(node,
    outs, opts) for checks that depend on earlier outputs (one per container, per ASIC namespace), judge(node, outs,
    ctx) -> findings, and the command prefixes Debug a node may run there (read-only)."""
    name: str
    role: str                                   # switch | compute
    about: str
    commands: list = field(default_factory=list)
    judge: Callable | None = None
    collect: Callable | None = None
    read_only: list = field(default_factory=list)   # [(regex, needs sudo)] Debug a node may run here
    judge_rack: Callable | None = None          # judge_rack({node: outs}) -> findings across the nodes (consistency)


def finding(node: str, role: str, check: str, area: str, severity: str, what: str, cause: str, nxt: str,
            evidence: list[str], command: str = "") -> dict:
    return {"node": node, "role": role, "check": check, "area": area, "severity": severity, "what": what,
            "cause": cause, "owner": OWNERS.get(area, "lab team"), "next": nxt,
            "evidence": [str(x)[:300] for x in evidence[:8]], "command": command}


def _num(v) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", str(v or "").replace(",", ""))
    return float(m.group(0)) if m else None


def _cmd(outs: dict, check: str) -> str:
    return (outs.get(check) or {}).get("cmd", "")


def _out(outs: dict, check: str) -> str | None:
    """The output of a check, None when it was not run, failed with no output, or the command does not exist here."""
    r = outs.get(check)
    if not r:
        return None
    text = (r.get("out") or "").rstrip()   # leading spaces kept: SONiC's tables align on the header's columns
    if missing(r):
        return None
    return text if text.strip() or r.get("rc") == 0 else None


MISSING_RX = re.compile(r"command not found|No such command|Usage: |Traceback \(most recent|Error: No such|is not recognized|"
                        r"unknown command|invalid choice", re.I)


def missing(r: dict) -> bool:
    """The command did not run, does not exist on this node (rc 126 / 127, 'command not found', a usage text) or failed
    with no output - its check is 'not checked', never 'healthy'. rc 1 with no output is an answer (grep: no match)."""
    rc, out, err = r.get("rc"), (r.get("out") or "").strip(), r.get("err") or ""
    if rc is None or rc in (126, 127):
        return True
    if MISSING_RX.search(err + "\n" + "\n".join(out.splitlines()[:3])) and not (rc == 0 and out and not MISSING_RX.search(out[:200])):
        return True
    return rc not in (0, 1) and not out


# ------------------------------------------------------------------------------------------------ Linux, any node

def parse_df(text: str) -> list[tuple[str, int]]:
    out = []
    for ln in text.splitlines()[1:]:
        toks = ln.split()
        if len(toks) >= 6 and toks[-2].endswith("%"):
            out.append((toks[-1], int(toks[-2].rstrip("%"))))
    return out


def _disk(node, role, outs, F, area):
    t = _out(outs, "disk")
    if t is None:
        return
    for mount, pct in parse_df(t):
        if pct >= LIMITS["disk_warn"]:
            sev = CRITICAL if pct >= LIMITS["disk_crit"] else WARNING
            F.append(finding(node, role, "disk", area, sev, f"{mount} is {pct} % full",
                             f"the filesystem {mount} is (nearly) full - logs, cores or images stop being written and "
                             "services that write there fail", f"read 'sudo du -xh {mount} --max-depth=2 | sort -h | tail' "
                             "for what fills it (logs, /var/core, old images); cleaning up CHANGES THE NODE",
                             [f"{mount} {pct}%"], _cmd(outs, "disk")))


def _memory(node, role, outs, F, area):
    t = _out(outs, "memory")
    if t is None:
        return
    kv = {m.group(1): int(m.group(2)) for m in re.finditer(r"(MemTotal|MemAvailable):\s+(\d+)", t)}
    if kv.get("MemTotal"):
        pct = 100 * kv.get("MemAvailable", 0) / kv["MemTotal"]
        if pct < LIMITS["mem_avail_warn"]:
            F.append(finding(node, role, "memory", area, CRITICAL if pct < LIMITS["mem_avail_crit"] else WARNING,
                             f"only {pct:.0f} % memory available ({kv.get('MemAvailable', 0) // 1024} of "
                             f"{kv['MemTotal'] // 1024} MiB)", "memory is (nearly) exhausted - a process leaks or the "
                             "node runs more than it can hold; the kernel will kill processes (OOM)",
                             "read 'top -b -n1 -o %MEM | head -20' for the largest processes", t.splitlines()[:2],
                             _cmd(outs, "memory")))


# ------------------------------------------------------------------------------------------------ collection

TRANSIENT = re.compile(r"ChannelException|Connect failed|SSHException|EOFError|Connection reset|timed out", re.I)


def _run(node, check: str, cmd: str, sudo: bool, outs: dict, timeout: float = 120, tries: int = 3) -> None:
    """One check's command; a session the jump host refused (it allows ~10 at a time) is tried again."""
    for i in range(tries):
        try:
            r = node.run(cmd, sudo=sudo, timeout=timeout)
            outs[check] = {"cmd": cmd, "rc": r.rc, "out": r.stdout, "err": r.stderr}
        except Exception as e:  # noqa: BLE001 - recorded: the check is reported as not run
            outs[check] = {"cmd": cmd, "rc": None, "out": "", "err": f"{type(e).__name__}: {e}"}
        r_ = outs[check]
        if not ((r_["rc"] is None or r_["rc"] == 255 and not r_["out"]) and TRANSIENT.search(r_["err"] or "x")) or i == tries - 1:
            return
        time.sleep(1.5 * (i + 1))


def collect(node, platforms: list, opts: dict | None = None) -> dict:
    """Every check's output of these platforms on one node: {check: {cmd, rc, out, err}}."""
    outs: dict = {}
    for p in platforms:
        for check, cmd, sudo in p.commands:
            _run(node, check, cmd, sudo, outs)
        if p.collect:
            p.collect(node, outs, opts or {})
    return outs


def judge(node: str, outs: dict, platforms: list, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    for p in platforms:
        if p.judge:
            F += p.judge(node, outs, ctx or {})
    return F


def not_run(outs: dict) -> list[str]:
    """Checks whose command did not run or does not exist on this node (reported, so a missing finding is not read
    as healthy)."""
    return sorted(k for k, r in outs.items() if missing(r))


def rack_wide(findings: list[dict], nodes_by_role: dict[str, int], min_nodes: int = 3, share: float = 0.2) -> list[dict]:
    """The same finding on many nodes of a kind (corrected machine checks on every tray, the same RDMA ports polling on
    four) is one finding 'on N of M ...' - one cause to look for, not N lines. Its evidence keeps one line per node."""
    def key(f):
        return (f["role"], f["check"], f["area"], f["severity"], re.sub(r"\d+", "#", f["what"]))
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        groups.setdefault(key(f), []).append(f)
    out = []
    for k, fs in groups.items():
        role, total = k[0], nodes_by_role.get(k[0], 0)
        names = sorted({f["node"] for f in fs})
        if len(names) >= min_nodes and total and len(names) >= share * total:
            f0 = fs[0]
            kind = "trays" if role == "compute" else "switches" if role == "switch" else "nodes"
            out.append(dict(f0, node=f"{len(names)} of {total} {kind}", nodes=names,
                            what=f"on {len(names)} of {total} {kind} ({', '.join(names)}): " + re.sub(r"^\d+ ", "", f0["what"]),
                            cause=f0["cause"] + " - the same on many nodes: look for one common cause (a platform / firmware "
                                  "behaviour, a configuration, cabling not done) before suspecting each node",
                            evidence=[f"{f['node']}: {f['what'][:120]}" for f in sorted(fs, key=lambda x: x["node"])][:20]))
        else:
            out += fs
    return out


def summary(findings: list[dict]) -> dict:
    by_area: dict[str, int] = {}
    for f in findings:
        by_area[f["area"]] = by_area.get(f["area"], 0) + 1
    return {"critical": sum(f["severity"] == CRITICAL for f in findings),
            "warning": sum(f["severity"] == WARNING for f in findings), "by_area": by_area}


def report_text(res: dict) -> str:
    """report.txt: what the AI and a person read first - every finding with its evidence, by severity."""
    s = res["summary"]
    lines = [f"Node health of rack {res['rack']}  {res['time']} UTC", "",
             f"{s['critical']} critical, {s['warning']} warning finding(s) on {len(res['nodes'])} node(s) checked"
             + (f"; nodes not reached: {', '.join(res['unreachable'])}" if res.get("unreachable") else ""), ""]
    for sev in (CRITICAL, WARNING):
        fs = [f for f in res["findings"] if f["severity"] == sev]
        if not fs:
            continue
        lines.append(f"== {sev.upper()} ({len(fs)})")
        for f in fs:
            lines += [f"- {f['node']}: {f['what']}", f"    cause: {f['cause']}", f"    area: {f['area']}, owner: {f['owner']}",
                      f"    next: {f['next']}", f"    evidence ({f['command']}):"] + [f"      {e}" for e in f["evidence"]]
        lines.append("")
    skipped = {n: v["not_run"] for n, v in res["nodes"].items() if v.get("not_run")}
    if skipped:
        lines.append("== NOT CHECKED (command missing or failed on the node)")
        lines += [f"- {n}: {', '.join(v)}" for n, v in sorted(skipped.items())]
    if not res["findings"]:
        lines.append("No problem found on the nodes checked.")
    return "\n".join(lines) + "\n"
