"""Outputs a person collected and pasted (Any problem): the node health rules on them, and test results in any format.

Not everyone runs the health check or helios-tests (TAC, test, sales). When a pasted command is one the health check
knows - typed the way people type it (`show platform fan`, `sudo amd-smi metric --json`, `dmesg`, `rdma link`) - the
same platform rules (heliosdbg/platforms/) judge its output, so the problem, its cause, owner and next step are there
without the AI. A pasted test result (JUnit XML, or a CSV with an outcome / status / result column) becomes its failed
cases. Nothing here touches the rack.
"""
from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET

from .checks import CRITICAL, WARNING, finding
from .platforms import PLATFORMS

# (platform, check, the command as typed - after sudo / '2>/dev/null' / a trailing '| grep ..' are dropped).
# Only forms whose output the rule reads: amd-smi needs --json, docker ps needs the Names / Status format.
_ = r"(?:\s+\S+)*"
TYPED = [
    ("sonic", "health", r"show system-health(?: summary| detail)?(?:\s+-n\s+asic\d)?"),
    ("sonic", "crm", r"crm show resources all"),
    ("sonic", "disk", r"df(?:\s+-[A-Za-z]+)*(?:\s+/\S*)*"),
    ("sonic", "memory", r"(?:cat /proc/meminfo|grep" + _ + r" /proc/meminfo)"),
    ("sonic", "uptime", r"cat /proc/uptime"),
    ("sonic", "cores", r"ls(?:\s+-[A-Za-z1]+)* /var/core/?"),
    ("sonic", "reboot", r"show reboot-cause"),
    ("sonic", "reboot_history", r"show reboot-cause history"),
    ("sonic", "psu", r"show platform psustatus"),
    ("sonic", "fan", r"show platform fan"),
    ("sonic", "temperature", r"show platform temperature"),
    ("sonic", "voltage", r"show platform voltage"),
    ("sonic", "watchdog", r"watchdogutil status"),
    ("sonic", "syslog", r"(?:show logging|(?:cat|tail|grep)" + _ + r" /var/log/syslog\S*)" + _),
    ("sonic", "leak", r"show platform leak status"),
    ("sonic", "leak_channels", r"show platform leak channels"),
    ("sonic", "ssd", r"show platform ssdhealth"),
    ("sonic", "ntp", r"(?:show ntp|chronyc sources)"),
    ("sonic", "bmc_health", r"bmc-manager health"),
    ("sonic", "bmc_power", r"bmc-manager power-status"),
    ("sonic", "images", r"sonic-installer list"),
    ("sonic", "mgmt", r"sonic-db-cli CONFIG_DB (?:keys|KEYS) '?MGMT_INTERFACE\|\*'?"),
    ("afm-switch", "afm_agent", r"systemctl is-active afm-agent"),
    ("amd-gpu", "gpus", r"amd-smi list" + _ + r" --json" + _),
    ("amd-gpu", "ecc", r"amd-smi metric(?:\s+-g\s+\d+)?(?: --ecc)?" + _ + r" --json" + _),
    ("amd-gpu", "pcie", r"amd-smi metric(?:\s+-g\s+\d+)?(?: --pcie)?" + _ + r" --json" + _),
    ("amd-gpu", "metric", r"amd-smi metric(?:\s+-g\s+\d+)?(?! --ecc| --pcie)" + _ + r" --json" + _),
    ("amd-gpu", "processes", r"amd-smi process" + _ + r" --json" + _),
    ("afm-compute", "afmctl", r"afmctl show device" + _ + r" --json"),
    ("linux", "kernel", r"(?:dmesg|journalctl -k)" + _),
    ("linux", "failed", r"systemctl (?:--failed|list-units --failed)" + _),
    ("rdma", "rdma", r"rdma link(?: show)?"),
    ("rdma", "nic_ports", r"nicctl show port(?:\s+-b\s+\S+)?(?: -j| --json)"),
]
TYPED_RX = [(p, c, re.compile(rx)) for p, c, rx in TYPED]
ROLE = {"sonic": "switch", "afm-switch": "switch"}


def typed(command: str) -> str:
    """What was run, as the rules list it: no sudo, no '2>/dev/null', no trailing '| grep / tail / head'."""
    c = re.sub(r"^\s*sudo\s+(?:-n\s+)?", "", str(command or "")).strip()
    c = re.sub(r"\s+2>\s*/dev/null|\s+2>&1", "", c)
    c = re.split(r"\s+\|\s+(?:grep|egrep|tail|head|less|more)\b", c)[0]
    return " ".join(c.split())


def checks_of(command: str) -> list[tuple[str, str]]:
    """[(platform, check)] whose rule reads this command's output."""
    c = typed(command)
    return [(p, ck) for p, ck, rx in TYPED_RX if rx.fullmatch(c)]


def _nicctl(out: str) -> str:
    return out if "@@port " in out else "@@port all\n" + out      # the health check's own wrapper marks each card


def judge_blocks(blocks: list[dict]) -> tuple[list[dict], list[dict]]:
    """(findings, [{node, command, checks}]) - the health rules on every pasted output whose command they know, and
    test results (JUnit XML / CSV) summarised. A rule that finds nothing adds no finding: 'checked' says what was."""
    by_node: dict[tuple[str, str], dict] = {}
    seen, F = [], []
    for b in blocks:
        node = b.get("node") or "the node"
        tests = test_failures(b.get("output") or "")
        if tests is not None:
            F += tests_finding(node, b.get("command") or "test result", tests)
            seen.append({"node": node, "command": b.get("command") or "", "checks": ["test result"]})
            continue
        hits = checks_of(b.get("command") or "")
        seen.append({"node": node, "command": b.get("command") or "", "checks": [f"{p}:{c}" for p, c in hits]})
        for p, c in hits:
            out = _nicctl(b["output"]) if c == "nic_ports" else b["output"]
            by_node.setdefault((node, p), {})[c] = {"cmd": b.get("command") or "", "rc": 0, "out": out, "err": ""}
    for (node, p), outs in by_node.items():
        plat = PLATFORMS[p]
        try:
            got = plat.judge(node, outs, {"role": ROLE.get(p, "compute"), "gpus": 4, "pasted": True}) or []
        except Exception as e:  # noqa: BLE001 - a rule that cannot read a pasted output must not stop the others
            got = [finding(node, plat.role, "pasted", "compute", WARNING, f"the {p} rules could not read this output",
                           f"{type(e).__name__}: {str(e)[:160]}", "paste the full output of the command, unedited",
                           [], ", ".join(o["cmd"] for o in outs.values())[:200])]
        F += [f | {"from": "pasted"} for f in got]
    return F, seen


# ---------------------------------------------------------------------------------------------- test results

FAILED = re.compile(r"^(fail\w*|error\w*|broken|blocked|timeout|timed.?out|crash\w*|abort\w*|nok|not ok|false)$", re.I)


def test_failures(text: str) -> dict | None:
    """{total, failed: [(case, outcome, message)]} of a JUnit XML or a results CSV; None when it is neither."""
    t = (text or "").lstrip()
    if t.startswith("<") and re.search(r"<testsuites?\b|<testcase\b", t[:4000]):
        if re.search(r"<!DOCTYPE|<!ENTITY", t[:4000], re.I):
            return None                                       # no entity expansion from a pasted file
        try:
            root = ET.fromstring(t)
        except ET.ParseError:
            return None
        cases, failed = root.iter("testcase"), []
        total = 0
        for tc in cases:
            total += 1
            for kind in ("failure", "error"):
                e = tc.find(kind)
                if e is not None:
                    name = ".".join(x for x in (tc.get("classname"), tc.get("name")) if x)
                    msg = (e.get("message") or (e.text or "")).strip().splitlines()
                    failed.append((name or "?", kind, msg[0][:200] if msg else ""))
                    break
        return {"total": total, "failed": failed}
    first = t.splitlines()[0] if t else ""
    if "," not in first and "\t" not in first:
        return None
    try:
        rows = list(csv.DictReader(io.StringIO(t), dialect=csv.Sniffer().sniff(first, ",\t;")))
    except csv.Error:
        return None
    cols = {k.lower().strip(): k for k in (rows[0].keys() if rows else []) if k}
    oc = next((cols[k] for k in ("outcome", "status", "result", "verdict") if k in cols), None)
    if not oc:
        return None
    name = next((cols[k] for k in ("tc_id", "test", "name", "case", "testcase", "test_name") if k in cols), None)
    msg = next((cols[k] for k in ("message", "reason", "error", "details", "comment") if k in cols), None)
    failed = [(str(r.get(name) or "?") if name else f"row {i + 2}", str(r.get(oc)).strip(), str(r.get(msg) or "")[:200] if msg else "")
              for i, r in enumerate(rows) if FAILED.match(str(r.get(oc) or "").strip())]
    return {"total": len(rows), "failed": failed}


def tests_finding(node: str, what: str, t: dict) -> list[dict]:
    if not t["failed"]:
        return []
    n = len(t["failed"])
    return [finding(node, "test", "tests", "test", CRITICAL if n * 4 >= max(t["total"], 1) else WARNING,
                    f"{n} of {t['total']} test case(s) failed: " + ", ".join(c for c, _o, _m in t["failed"][:5])
                    + (" ..." if n > 5 else ""),
                    "the test result says so - its messages are the evidence; the cause is in the nodes the cases ran on",
                    "ask the AI about it, or paste the failing case's log and the node outputs it points at",
                    [f"{c}: {o}" + (f" - {m}" if m else "") for c, o, m in t["failed"][:8]], what)]
