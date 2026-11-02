"""Node health: what is wrong on each switch tray, compute tray and AFM of a rack beyond the GPU links - SONiC (health,
containers, critical processes, CRM tables, disk, memory, cores, reboot cause, syslog errors, saved configuration),
the switch platform (PSUs, fans, temperatures, voltages, watchdog), the compute trays (GPUs, ECC, PCIe, GPU
configuration, kernel errors, OS disk / memory, RDMA NICs, failed services) and AFM (agent, controller and agent
certificates; with the AFM password, AFM's view of every compute node).

Read-only: every command below only reads. Each problem becomes one finding with the evidence lines it rests on, the
area of its cause (the incident brain's areas: sonic, switch, power, thermal, bmc, afm, gpu, compute, os, rdma), who
owns the fix and the next step - as a link check's root causes do.

Collection (collect_switch / collect_compute) and judgement (judge_switch / judge_compute) are separate: the rules
read the outputs only, so they are tested on recorded outputs without a rack.
"""
from __future__ import annotations

import json
import re
import time

from .parsers import parse_table

CRITICAL, WARNING = "critical", "warning"
OWNERS = {"sonic": "network", "switch": "network", "power": "hardware", "thermal": "hardware", "bmc": "hardware",
          "afm": "AFM", "gpu": "compute", "compute": "compute", "os": "compute", "rdma": "compute"}

# switch: (check, command, sudo); {ns} = ' -n asicN' per ASIC namespace where a command takes one
SWITCH_CMDS = [
    ("health", "show system-health summary", True),
    ("containers", "docker ps -a --format '{{.Names}}\t{{.Status}}'", True),
    ("restarts", "docker inspect -f '{{.Name}} {{.RestartCount}} {{.State.StartedAt}}' $(docker ps -q)", True),
    ("uptime", "cat /proc/uptime", False),
    ("crm", "crm show resources all", True),
    ("disk", "df -P / /var/log /host", False),
    ("memory", "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo", False),
    ("cores", "ls -1 /var/core", True),
    ("reboot", "show reboot-cause", False),
    ("reboot_history", "show reboot-cause history", False),
    ("psu", "show platform psustatus", False),
    ("fan", "show platform fan", False),
    ("temperature", "show platform temperature", False),
    ("voltage", "show platform voltage", False),
    ("watchdog", "watchdogutil status", True),
    ("syslog", "grep -hE ' (ERR|CRIT|ALERT|EMERG) ' /var/log/syslog.1 /var/log/syslog | tail -n 400", True),
    ("afm_agent", "systemctl is-active afm-agent", False),
]
CRITICAL_CONTAINERS = re.compile(r"^(pmon|database\d*|swss\d*|syncd\d*|lldp\d*|bgp\d*|teamd\d*|radv|snmp|gnmi|telemetry)$")
SUPERVISOR_CMD = "docker exec {c} sh -c 'cat /etc/supervisor/critical_processes; echo ===; supervisorctl status'"
CONTROLLER_CERT_CMD = "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -enddate"
AGENT_CERT_CMD = ("sh -c 'for f in /opt/amd/afm/agent/sysconfig/config*/*.pem; do e=$(openssl x509 -noout -enddate -in \"$f\" "
                  "2>/dev/null) && echo \"$f $e\"; done'")
DRIFT_TABLES = ("PORT", "VLAN", "VLAN_MEMBER", "PORT_QOS_MAP", "PFC_WD", "BUFFER_PG", "BUFFER_QUEUE")
RUNNING_CMD = "sonic-cfggen{ns} -d --print-data"
SAVED_CMD = "sonic-cfggen{ns} -j /etc/sonic/config_db{n}.json --print-data"

COMPUTE_CMDS = [
    ("gpus", "amd-smi list --json", True),
    ("ecc", "amd-smi metric --ecc --json", True),
    ("pcie", "amd-smi metric --pcie --json", True),
    ("metric", "amd-smi metric --usage --power --temperature --mem-usage --json", True),
    ("processes", "amd-smi process --json", True),
    ("afmctl", "afmctl show device --json 2>/dev/null", True),
    ("disk", "df -P /", False),
    ("memory", "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo", False),
    ("kernel", "journalctl -k -p err --since '-60 min' --no-pager -q", True),
    ("rdma", "rdma link show", False),
    ("failed", "systemctl --failed --no-pager --plain --no-legend", False),
]

BENIGN_UNITS = {"systemd-networkd-wait-online.service"}   # fails on most servers with an unplugged port: not a fault

# thresholds (the inventory's health: block overrides them)
LIMITS = {"disk_warn": 85, "disk_crit": 95, "mem_avail_warn": 10, "mem_avail_crit": 5, "crm_warn": 85, "crm_crit": 98,
          "gpu_hot": 100, "cert_days": 30, "restart_warn": 1, "syslog_burst": 20}
UNEXPECTED_REBOOT = re.compile(r"kernel panic|watchdog|power loss|hardware|thermal|unknown|crash|oom", re.I)
ASKED_REBOOT = re.compile(r"user issued|warm-reboot|fast-reboot|soft-reboot|config reload|\[user:", re.I)
SYSLOG_SIGNS = [   # (pattern, area, what) - the first match names a group of error lines
    (re.compile(r"SAI_STATUS_(?!SUCCESS)\w+|orchagent.*(fail|error)", re.I), "sonic", "orchagent / SAI errors"),
    (re.compile(r"syncd.*(crash|abort|exit|fail)", re.I), "sonic", "syncd failures"),
    (re.compile(r"Out of memory|oom-kill|Killed process", re.I), "sonic", "out of memory"),
    (re.compile(r"(xcvrd|psud|thermalctld|ledd|syseepromd|pcied).*(exit|fail|crash|error)", re.I), "sonic", "platform daemon errors"),
    (re.compile(r"(PSU|fan|temperature|thermal|voltage)", re.I), "power", "platform alarms"),
    (re.compile(r"(MCE|machine check|EDAC|I/O error|nvme.*(error|fail)|ext4.*error)", re.I), "switch", "hardware / disk errors"),
]
KERNEL_SIGNS = [
    (re.compile(r"\[Hardware Error\]: (Uncorrected|Fatal|Deferred)", re.I), "compute", "uncorrected machine-check errors"),
    (re.compile(r"\[Hardware Error\]: Corrected error", re.I), "compute", "corrected machine-check errors (CPU / cache / memory)"),
    (re.compile(r"\[Hardware Error\]:", re.I), None, ""),           # the detail lines of the events above: counted with them
    (re.compile(r"amdgpu.*(fault|timeout|reset|ras|error)|gpu.*(hang|reset)", re.I), "gpu", "GPU driver errors"),
    (re.compile(r"(MCE|machine check|EDAC|mce:)", re.I), "compute", "machine-check / memory errors"),
    (re.compile(r"(AER|pcieport|PCIe Bus Error)", re.I), "gpu", "PCIe errors"),
    (re.compile(r"(nvme|I/O error|ext4.*error|XFS)", re.I), "os", "disk / filesystem errors"),
    (re.compile(r"(ionic|mlx5|bnxt|rdma).*(error|fail|down|timeout)", re.I), "rdma", "RDMA NIC errors"),
    (re.compile(r"Out of memory|oom-kill|Killed process", re.I), "os", "out of memory"),
]


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


# ------------------------------------------------------------------------------------------------ switch rules

def _health(node, outs, F):
    t = _out(outs, "health")
    if t is None:
        return
    bad = [ln.strip() for ln in t.splitlines() if re.search(r"Not OK|Not Running|red|Not Accessible", ln, re.I)]
    if re.search(r"System status summary\s*\n\s*System status LED\s+red", t, re.I) or \
            re.search(r"Status:\s*Not OK", t, re.I):
        F.append(finding(node, "switch", "health", "sonic", WARNING, "SONiC system health is Not OK",
                         "SONiC's own health monitor reports a service or a hardware item not OK (the lines below say which)",
                         "read 'show system-health detail' for the item named here; the other findings on this switch usually "
                         "name the same cause", bad or t.splitlines()[:6], _cmd(outs, "health")))


def _containers(node, outs, F, uptime_s):
    t = _out(outs, "containers")
    if t is None:
        return
    down = []
    for ln in t.splitlines():
        name, _, status = ln.partition("\t")
        name, status = name.strip(), status.strip()
        if not name:
            continue
        if re.match(r"(Exited|Restarting|Dead|Created)", status) and (CRITICAL_CONTAINERS.match(name) or name.startswith("afm")):
            down.append((name, status))
    for name, status in down:
        afm = name.startswith("afm")
        F.append(finding(node, "switch", "containers", "afm" if afm else "sonic", CRITICAL,
                         f"container {name} is not running ({status})",
                         f"the {name} container exited or keeps restarting" + (
                             " - the AFM agent / controller on this switch is down" if afm else
                             " - the services in it (and what depends on them) are down"),
                         f"read 'docker logs --tail 100 {name}' and the syslog lines of {name}; starting it again CHANGES "
                         "THE SWITCH - for its owner to decide", [f"{name}: {status}"], _cmd(outs, "containers")))
    r = _out(outs, "restarts")
    if r is None:
        return
    lim = LIMITS["restart_warn"]
    now = time.time()
    for ln in r.splitlines():
        toks = ln.split()
        if len(toks) != 3 or not toks[1].isdigit():
            continue
        name, count = toks[0].lstrip("/"), int(toks[1])
        started = _iso_epoch(toks[2])
        young = started is not None and uptime_s is not None and uptime_s > 3600 and now - started < min(uptime_s - 600, 86400)
        if count >= lim or (young and (CRITICAL_CONTAINERS.match(name) or name.startswith("afm"))):
            ago = f", started {_ago(now - started)} ago" if started else ""
            F.append(finding(node, "switch", "restarts", "afm" if name.startswith("afm") else "sonic", WARNING,
                             f"container {name} restarted ({count} restart(s){ago})",
                             f"{name} restarted after the switch booted - a crash or a manual restart",
                             f"read 'docker logs --tail 100 {name}' and the syslog around its start time", [ln.strip()],
                             _cmd(outs, "restarts")))


def _iso_epoch(s: str) -> float | None:
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", s or "")
    if not m:
        return None
    try:
        import calendar
        return float(calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")))
    except ValueError:
        return None


def _ago(sec: float) -> str:
    sec = max(0, int(sec))
    return f"{sec // 86400} d" if sec >= 86400 else f"{sec // 3600} h" if sec >= 3600 else f"{sec // 60} min"


def parse_supervisor(text: str) -> tuple[list[str], dict[str, str]]:
    """'cat critical_processes; echo ===; supervisorctl status' -> (critical programs, {program: STATE})."""
    crit_part, _, status_part = text.partition("===")
    crit = []
    for ln in crit_part.splitlines():
        m = re.match(r"\s*(?:program|group):(\S+)", ln)
        if m:
            crit.append(m.group(1))
    status = {}
    for ln in status_part.splitlines():
        toks = ln.split()
        if len(toks) >= 2 and toks[1].isupper():
            status[toks[0].split(":")[-1]] = toks[1]
    return crit, status


PMON_DAEMONS = ("psud", "thermalctld", "xcvrd", "ledd", "syseepromd", "pcied", "sensormond", "stormond", "chassisd")
BROKEN_STATES = ("FATAL", "BACKOFF")       # supervisor gave up on / keeps restarting the program, critical or not


def _critical(node, outs, F):
    for key, r in sorted(outs.items()):
        if not key.startswith("critical:"):
            continue
        c = key.split(":", 1)[1]
        t = (r.get("out") or "")
        if "===" not in t:
            continue
        crit, status = parse_supervisor(t)
        if not crit and c == "pmon":        # pmon lists no critical programs: its platform daemons are what matters
            crit = [p for p in PMON_DAEMONS if p in status]
        down = [f"{p}:{status.get(p, 'not listed')}" for p in crit if status.get(p) != "RUNNING"
                and not (p == "dsserve" and status.get("syncd") == "RUNNING")]
        down += [f"{p}:{s}" for p, s in status.items() if s in BROKEN_STATES and p not in crit]
        if not down:
            continue
        daemons = ", ".join(d.split(":")[0] for d in down)
        F.append(finding(node, "switch", "critical", "sonic", CRITICAL, f"critical process(es) down in {c}: {daemons}",
                         f"a SONiC daemon in {c} stopped - what it serves is stale or missing (e.g. pmon: psud -> PSU "
                         "status N/A, thermalctld -> temperatures, xcvrd -> transceivers; swss: orchagent -> no new "
                         "programming)", f"read the syslog lines of {daemons.split(',')[0]} and 'docker exec {c} supervisorctl "
                         f"status'; starting it again CHANGES THE SWITCH - for the network team to decide", down, r.get("cmd", "")))


def parse_crm(text: str) -> list[tuple[str, str, int, int]]:
    """'crm show resources all' -> [(asic, resource, used, available)] (resource tables only)."""
    out, asic = [], ""
    for ln in text.splitlines():
        s = ln.strip()
        if re.fullmatch(r"ASIC\d+", s):
            asic = s.lower()
            continue
        m = re.match(r"^([a-z][a-z0-9_]+)\s+(\d+)\s+(\d+)\s*$", s)
        if m:
            out.append((asic, m.group(1), int(m.group(2)), int(m.group(3))))
    return out


def _crm(node, outs, F):
    t = _out(outs, "crm")
    if t is None:
        return
    for asic, res, used, avail in parse_crm(t):
        total = used + avail
        if not total or used == 0:
            continue
        pct = 100 * used / total
        if avail == 0 or pct >= LIMITS["crm_warn"]:
            sev = CRITICAL if avail == 0 or pct >= LIMITS["crm_crit"] else WARNING
            F.append(finding(node, "switch", "crm", "sonic", sev,
                             f"{asic or 'ASIC'} {res} table {pct:.0f} % used ({used} used, {avail} available)",
                             f"the ASIC's {res} table is (nearly) full - new entries fail (SAI_STATUS_TABLE_FULL)" +
                             (": something floods MAC addresses or entries are not aged out" if res.startswith("fdb") else ""),
                             f"read 'show mac{' -n ' + asic if asic else ''}' (or the table's own show command) for what fills it",
                             [f"{asic} {res} used {used} available {avail}"], _cmd(outs, "crm")))


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


def _cores(node, outs, F):
    t = _out(outs, "cores")
    if not t:
        return
    files = [ln.strip() for ln in t.splitlines() if ln.strip() and not ln.startswith("ls:")]
    if files:
        procs = sorted({re.split(r"\.\d", f)[0] for f in files})
        F.append(finding(node, "switch", "cores", "sonic", WARNING, f"{len(files)} core file(s) in /var/core: {', '.join(procs[:5])}",
                         "a SONiC process crashed and dumped core (the file name says which and when)",
                         "match the core's time with 'show reboot-cause history' and the syslog; attach it to a SONiC issue",
                         files[:6], _cmd(outs, "cores")))


def _reboot(node, outs, F):
    t = _out(outs, "reboot")
    if t is None:
        return
    if t and UNEXPECTED_REBOOT.search(t) and not ASKED_REBOOT.search(t):
        hist = parse_table(_out(outs, "reboot_history") or "")[:3]
        F.append(finding(node, "switch", "reboot", "switch", WARNING, f"last reboot was not asked for: {t.splitlines()[0][:160]}",
                         "the switch rebooted by itself (kernel panic, watchdog, power loss or an unknown cause)",
                         "read 'show reboot-cause history' and the syslog before that time; a power loss -> the PSUs and "
                         "the feed; a watchdog / panic -> the kernel log of the previous boot",
                         [t.splitlines()[0]] + [" ".join(str(v) for v in h.values())[:200] for h in hist],
                         _cmd(outs, "reboot")))


def _platform(node, outs, F):
    t = _out(outs, "psu")
    if t is not None:
        for r in parse_table(t):
            st = str(r.get("Status", "")).strip()
            if st and st.upper() not in ("OK",):
                F.append(finding(node, "switch", "psu", "power", CRITICAL if st.upper() in ("NOT OK", "NOT PRESENT") else WARNING,
                                 f"{r.get('PSU', 'PSU')} status {st}", "a power supply is failed, unplugged or has lost its "
                                 "input - the switch runs without redundancy" if st.upper() != "N/A" else
                                 "the PSU status is not read (N/A): psud in pmon is down, or the PSU is not reporting",
                                 "check the PSU's input feed and seating on site; N/A on every PSU -> 'docker exec pmon "
                                 "supervisorctl status psud' first", [" ".join(str(v) for v in r.values())[:200]], _cmd(outs, "psu")))
    t = _out(outs, "fan")
    if t is not None:
        for r in parse_table(t):
            st, pres = str(r.get("Status", "")).strip(), str(r.get("Presence", "")).strip()
            if (st and st.upper() != "OK") or (pres and pres.lower() != "present"):
                F.append(finding(node, "switch", "fan", "thermal", CRITICAL if pres.lower() == "not present" else WARNING,
                                 f"fan {r.get('FAN', r.get('Drawer', '?'))}: status {st or '?'}, {pres or 'presence ?'}",
                                 "a fan is failed or missing - the switch heats up", "replace / reseat the fan on site; "
                                 "watch 'show platform temperature' meanwhile",
                                 [" ".join(str(v) for v in r.values())[:200]], _cmd(outs, "fan")))
    t = _out(outs, "temperature")
    if t is not None:
        for r in parse_table(t):
            temp, high, crit = _num(r.get("Temperature")), _num(r.get("High TH")), _num(r.get("Crit High TH"))
            warn = str(r.get("Warning", "")).strip().lower() == "true"
            if warn or (temp is not None and high is not None and temp >= high):
                F.append(finding(node, "switch", "temperature", "thermal",
                                 CRITICAL if crit is not None and temp is not None and temp >= crit else WARNING,
                                 f"{r.get('Sensor', 'sensor')} at {temp} C (high threshold {high}, critical {crit})",
                                 "the switch is too hot - airflow, a fan, or the room", "read 'show platform fan' and the "
                                 "inlet temperature; the site checks airflow / cooling",
                                 [" ".join(str(v) for v in r.values())[:200]], _cmd(outs, "temperature")))
    t = _out(outs, "voltage")
    if t is not None:
        for r in parse_table(t):
            if str(r.get("Warning", "")).strip().lower() == "true":
                F.append(finding(node, "switch", "voltage", "power", WARNING, f"{r.get('Sensor', 'sensor')} voltage "
                                 f"{r.get('Voltage', '?')} outside its thresholds", "a supply rail is out of range - a "
                                 "PSU or the board's regulator", "read 'show platform psustatus'; hardware owner checks the "
                                 "PSUs / board", [" ".join(str(v) for v in r.values())[:200]], _cmd(outs, "voltage")))
    t = _out(outs, "watchdog")
    if t is not None and re.search(r"Status:\s*Unarmed", t, re.I):
        F.append(finding(node, "switch", "watchdog", "sonic", WARNING, "hardware watchdog not armed",
                         "the watchdog service did not arm the hardware watchdog at start: if the switch OS hangs, nothing "
                         "restarts it", "read 'systemctl status watchdog-control' (or the platform's watchdog service); "
                         "arming it CHANGES THE SWITCH - for the network team to decide", t.splitlines()[:2],
                         _cmd(outs, "watchdog")))


SERIOUS_LOG = re.compile(r"TABLE_FULL|crash|core dumped|segfault|Out of memory|oom-kill|Killed process|kernel panic|"
                         r"fatal|abort", re.I)


def _norm_line(ln: str) -> tuple[str, str]:
    """(daemon, message with numbers / addresses / timestamps blanked) - the same message repeated is one group."""
    m = re.match(r"^(?:\d{4}\s+)?\w{3}\s+\d+\s+[\d:.]+\s+\S+\s+(?:[A-Z]+\s+)?([\w#@.-]+?)(?:\[\d+\])?:\s*(.*)$", ln.strip())
    daemon, msg = (m.group(1), m.group(2)) if m else ("", ln.strip())
    msg = re.sub(r"message repeated \d+ times: \[\s*(.*?)\]$", r"\1", msg)
    msg = re.sub(r"0x[0-9a-f]+|\b\d+(\.\d+)?\b", "#", msg, flags=re.I)
    return daemon, msg.strip(" :-")[:160]


def _syslog(node, outs, F):
    t = _out(outs, "syslog")
    if not t:
        return
    lines = [ln for ln in t.splitlines() if ln.strip()]
    groups: dict[tuple, list[str]] = {}
    for ln in lines:
        groups.setdefault(_norm_line(ln), []).append(ln)
    top = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    serious = [(k, ls) for k, ls in top if SERIOUS_LOG.search(ls[-1])]
    area = next((a for rx, a, _w in SYSLOG_SIGNS for (_d, _m), ls in top[:3] if rx.search(ls[-1])), "sonic")
    what = "; ".join(f"{len(ls)}x {d + ': ' if d else ''}{m[:70]}" for (d, m), ls in top[:3])
    F.append(finding(node, "switch", "syslog", area, CRITICAL if serious else WARNING,
                     f"{len(lines)} syslog error line(s), {len(groups)} distinct message(s): {what}"[:300],
                     ("serious errors among them: " + "; ".join(f"{d}: {m[:80]}" for (d, m), _ls in serious[:2])) if serious else
                     "the switch logs these errors repeatedly; one message repeated is usually one cause (a daemon "
                     "polling something that fails) - check whether it matters for what is broken",
                     "read the full lines around the first occurrence ('sudo grep -n <word> /var/log/syslog | head'); "
                     "match them with the other findings on this switch",
                     [ls[-1] for _k, ls in (serious or top)[:4]], _cmd(outs, "syslog")))


def _afm_switch(node, outs, F):
    t = _out(outs, "afm_agent")
    if t is not None and t.strip() in ("inactive", "failed", "activating", "deactivating"):
        F.append(finding(node, "switch", "afm_agent", "afm", CRITICAL, f"afm-agent service is {t.strip()}",
                         "the AFM agent on this switch is not running - AFM loses this switch and its node agents",
                         "read 'systemctl status afm-agent' and 'docker logs --tail 100 afm-agent'; starting it again "
                         "CHANGES THE SWITCH - for the AFM owner", [t.strip()], _cmd(outs, "afm_agent")))
    for key in ("controller_cert", "agent_certs"):
        c = _out(outs, key)
        if not c:
            continue
        for ln in c.splitlines():
            m = re.search(r"notAfter=(.+)$", ln)
            if not m:
                continue
            try:
                import calendar
                end = calendar.timegm(time.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            except ValueError:
                continue
            days = (end - time.time()) / 86400
            if days < LIMITS["cert_days"]:
                what = ln.split(" notAfter=")[0].strip() or "AFM controller (port 443)"
                F.append(finding(node, "switch", key, "afm", CRITICAL if days < 0 else WARNING,
                                 f"certificate {'expired' if days < 0 else 'expires in %d days' % days}: {what}",
                                 "an AFM certificate is " + ("expired - TLS between AFM and its agents fails" if days < 0
                                                             else "about to expire"),
                                 "renew it as the AFM guide says (CHANGES THE RACK - for the AFM owner)", [ln.strip()],
                                 _cmd(outs, key)))


def _drift(node, outs, F):
    for key in sorted(k for k in outs if k.startswith("running:")):
        ns = key.split(":", 1)[1]
        run_t, saved_t = _out(outs, key), _out(outs, f"saved:{ns}")
        if not run_t or not saved_t:
            continue
        try:
            run, saved = json.loads(run_t), json.loads(saved_t)
        except ValueError:
            continue
        diffs = []
        for table in DRIFT_TABLES:
            a, b = run.get(table) or {}, saved.get(table) or {}
            for k in sorted(set(a) | set(b)):
                if a.get(k) != b.get(k):
                    if k not in b:
                        diffs.append(f"{table}|{k}: only in the running config")
                    elif k not in a:
                        diffs.append(f"{table}|{k}: only in the saved config")
                    else:
                        fs = sorted(f for f in set(a[k]) | set(b[k]) if (a[k] or {}).get(f) != (b[k] or {}).get(f)) \
                            if isinstance(a[k], dict) and isinstance(b[k], dict) else ["value"]
                        diffs.append(f"{table}|{k}: " + ", ".join(f"{f} running {(a[k] or {}).get(f)!r} saved "
                                                                  f"{(b[k] or {}).get(f)!r}" for f in fs[:3]))
        if diffs:
            F.append(finding(node, "switch", "drift", "switch", WARNING, f"{ns or 'host'}: running configuration differs "
                             f"from the saved one ({len(diffs)} entr{'y' if len(diffs) == 1 else 'ies'})",
                             "someone changed the configuration and did not save it (or saved without applying) - a reload "
                             "or reboot brings back the saved one", "compare the entries below with what the rack should "
                             "have; 'config save' or 'config reload' CHANGES THE SWITCH - for the network team",
                             diffs[:8], outs[key].get("cmd", "")))


def judge_switch(node: str, outs: dict) -> list[dict]:
    F: list[dict] = []
    up = _num((_out(outs, "uptime") or "").split(" ")[0]) if _out(outs, "uptime") else None
    _health(node, outs, F)
    _containers(node, outs, F, up)
    _critical(node, outs, F)
    _crm(node, outs, F)
    _disk(node, "switch", outs, F, "sonic")
    _memory(node, "switch", outs, F, "sonic")
    _cores(node, outs, F)
    _reboot(node, outs, F)
    _platform(node, outs, F)
    _syslog(node, outs, F)
    _afm_switch(node, outs, F)
    _drift(node, outs, F)
    return F


# ------------------------------------------------------------------------------------------------ compute rules

def _gpu_list(text: str | None) -> list[dict]:
    """amd-smi --json output in either shape ({gpu_data: [...]} or [...]) -> the per-GPU dicts."""
    if not text:
        return []
    rows, dec, i = [], json.JSONDecoder(), 0
    while True:                           # several JSON documents one after another (g02-g17: the GPUs, then the AI NICs)
        j = min([k for k in (text.find("[", i), text.find("{", i)) if k >= 0], default=-1)
        if j < 0:
            break
        try:
            d, i = dec.raw_decode(text, j)
        except ValueError:
            i = j + 1
            continue
        part = d.get("gpu_data") if isinstance(d, dict) else d
        rows += [r for r in part or [] if isinstance(r, dict) and "gpu" in r]
    return rows


def _val(x):
    return x.get("value") if isinstance(x, dict) else x


def judge_compute(node: str, outs: dict, expect_gpus: int = 4) -> list[dict]:
    F: list[dict] = []
    gpus = _gpu_list(_out(outs, "gpus"))
    smi_err = (outs.get("gpus") or {}).get("rc") not in (0, None) and re.search(r"Exception|not supported|error", (outs.get("gpus") or {}).get("out", ""), re.I)
    if smi_err:
        msg = re.sub(r"\s+", " ", outs["gpus"]["out"]).strip()[:240]
        F.append(finding(node, "compute", "gpus", "gpu", CRITICAL, "amd-smi cannot read the GPUs on this tray",
                         "amd-smi fails (the amdgpu driver is not loaded, the GPUs are not initialised, or amd-smi does not "
                         "match the driver) - nothing on the tray can use the GPUs as they are", "read 'sudo dmesg | grep -i "
                         "amdgpu | tail -30' and 'lsmod | grep amdgpu'; the GPU owner reloads the driver or reboots the tray "
                         "(CHANGES THE TRAY)", [msg], _cmd(outs, "gpus")))
    elif _out(outs, "gpus") is not None and len(gpus) < expect_gpus:
        F.append(finding(node, "compute", "gpus", "gpu", CRITICAL, f"{len(gpus)} of {expect_gpus} GPUs visible to amd-smi",
                         "a GPU is missing from the OS - not seated, failed, or lost on the PCIe bus",
                         "read 'sudo lspci -d 1002:' and 'sudo dmesg | grep -i amdgpu' for the missing one; the BMC event log "
                         "next (hardware owner)", [f"GPU {g.get('gpu')}: {g.get('bdf', '')}" for g in gpus],
                         _cmd(outs, "gpus")))
    for g in _gpu_list(_out(outs, "ecc")):
        e = g.get("ecc") or {}
        unc, corr = _num(e.get("total_uncorrectable_count")), _num(e.get("total_correctable_count"))
        if unc:
            F.append(finding(node, "compute", "ecc", "gpu", CRITICAL, f"GPU {g.get('gpu')}: {int(unc)} uncorrectable ECC error(s)",
                             "the GPU's memory has uncorrectable errors - jobs on it crash; pages may be retired",
                             f"read 'sudo amd-smi bad-pages -g {g.get('gpu')}' and 'sudo amd-smi ras'; the GPU owner decides on a "
                             "reset / RMA", [json.dumps(e)[:250]], _cmd(outs, "ecc")))
        elif corr and corr >= 100:
            F.append(finding(node, "compute", "ecc", "gpu", WARNING, f"GPU {g.get('gpu')}: {int(corr)} correctable ECC errors",
                             "the GPU's memory corrects many errors - it may be degrading", "watch whether the count grows; "
                             f"'sudo amd-smi bad-pages -g {g.get('gpu')}'", [json.dumps(e)[:250]], _cmd(outs, "ecc")))
    for g in _gpu_list(_out(outs, "pcie")):
        p = g.get("pcie") or {}
        w, mw = _num(_val(p.get("width"))), _num(_val(p.get("max_width") or p.get("max_pcie_width")))
        s, ms = _num(_val(p.get("speed"))), _num(_val(p.get("max_speed") or p.get("max_pcie_speed")))
        if (w and mw and w < mw) or (s and ms and s < ms):
            F.append(finding(node, "compute", "pcie", "gpu", WARNING, f"GPU {g.get('gpu')}: PCIe link x{w:.0f} at {s} "
                             f"(max x{mw or 0:.0f} at {ms})", "the GPU's PCIe link trained below its maximum - a riser, "
                             "seating or the slot", "read 'sudo lspci -vv -s <bdf> | grep -i lnk'; hardware owner reseats",
                             [json.dumps(p)[:250]], _cmd(outs, "pcie")))
    for g in _gpu_list(_out(outs, "metric")):
        temp = _num(_val(((g.get("temperature") or {}).get("hotspot"))))
        if temp is not None and temp >= LIMITS["gpu_hot"]:
            F.append(finding(node, "compute", "metric", "thermal", WARNING, f"GPU {g.get('gpu')} hotspot at {temp:.0f} C",
                             "the GPU runs hot - airflow, a fan, or its cooling", "read the tray's BMC thermal sensors and "
                             "fans; site checks cooling", [json.dumps(g.get("temperature"))[:200]], _cmd(outs, "metric")))
    busy = {}
    for g in _gpu_list(_out(outs, "processes")):
        procs = [p for p in g.get("process_list") or [] if isinstance(p, dict) and "No running" not in str(p.get("process_info", ""))]
        for p in procs:
            info = p.get("process_info") if isinstance(p.get("process_info"), dict) else p
            busy.setdefault(str(info.get("name") or "?"), []).append(str(g.get("gpu")))
    if busy:
        F.append(finding(node, "compute", "processes", "compute", WARNING,
                         "GPU(s) in use: " + "; ".join(f"{n.split('/')[-1][:50]} on GPU {', '.join(gs)}" for n, gs in busy.items())[:240],
                         "a workload runs on these GPUs - tests and jobs share them (results and timings are affected)",
                         "read 'sudo amd-smi process' for the owner and its PID; stopping it CHANGES THE TRAY - for its owner",
                         [f"{n} on GPU {', '.join(gs)}" for n, gs in busy.items()], _cmd(outs, "processes")))
    t = _out(outs, "afmctl")
    if t:
        try:
            from .afmctl import parse_show_device
            devs = parse_show_device(t)
        except Exception:  # noqa: BLE001 - a non-JSON answer: afmctl is not there or failed
            devs = []
        bad = [d for d in devs if str(d.config_phase).upper() != "ACTIVE"]
        if bad:
            F.append(finding(node, "compute", "afmctl", "afm", CRITICAL if len(bad) == len(devs) else WARNING,
                             f"{len(bad)} of {len(devs)} GPU(s) not ACTIVE in afmctl ({', '.join(sorted({d.config_phase or '?' for d in bad}))})",
                             "AFM has not programmed these GPUs on the tray (not in a vPOD, the node agent did not apply it, "
                             "or the GPU failed its setup) - their links carry no traffic",
                             "check the tray in AFM (compute node state, vPOD) and the node agent of this tray on its switch",
                             [f"{d.bdf} acc {d.accel_id or '-'} {d.config_phase}" for d in bad], _cmd(outs, "afmctl")))
    _disk(node, "compute", outs, F, "os")
    _memory(node, "compute", outs, F, "os")
    t = _out(outs, "kernel")
    if t:
        lines = [ln for ln in t.splitlines() if ln.strip() and "-- No entries --" not in ln]
        groups: dict[str, tuple[str, list[str]]] = {}
        for ln in lines:
            for rx, area, what in KERNEL_SIGNS:
                if rx.search(ln):
                    if area:
                        groups.setdefault(what, (area, []))[1].append(ln)
                    break
        for what, (area, ls) in groups.items():
            sev = CRITICAL if what.startswith("uncorrected") or len(ls) >= 10 and not what.startswith("corrected") else WARNING
            F.append(finding(node, "compute", "kernel", area, sev,
                             f"{len(ls)} kernel error line(s) in the last hour: {what}", f"the tray's kernel logged {what}",
                             "read 'sudo journalctl -k -p err --since -2h' around these lines; GPU / PCIe errors -> "
                             "'sudo amd-smi ras'", ls[-5:], _cmd(outs, "kernel")))
    t = _out(outs, "rdma")
    if t:
        bad = [ln for ln in t.splitlines() if ln.startswith("link") and ("state ACTIVE" not in ln or "LINK_UP" not in ln)
               and "physical_state DISABLED" not in ln]   # an administratively disabled (unused) port is not a fault
        if bad:
            F.append(finding(node, "compute", "rdma", "rdma", WARNING, f"{len(bad)} RDMA NIC port(s) not ACTIVE / LINK_UP",
                             "a scale-out NIC port is down - its cable, the leaf switch port, or the NIC",
                             "read 'ip -br link' and the NIC's leaf switch port; the cable / optic next",
                             bad[:6], _cmd(outs, "rdma")))
    t = _out(outs, "failed")
    if t:
        units = [ln.split()[0] for ln in t.splitlines() if ln.strip() and ".service" in ln and ln.split()[0] not in BENIGN_UNITS]
        if units:
            F.append(finding(node, "compute", "failed", "os", WARNING, f"{len(units)} failed systemd unit(s): {', '.join(units[:5])}",
                             "services on the tray failed to start or crashed", "read 'systemctl status <unit>' and "
                             "'journalctl -u <unit> -n 50' for each", t.splitlines()[:6], _cmd(outs, "failed")))
    return F


def judge_afm(computes: list[dict]) -> list[dict]:
    """AFM's view of every compute node (GET computenodes): not admitted / not healthy / GPUs not ready."""
    F = []
    for n in computes or []:
        md, st = n.get("metadata") or {}, n.get("status") or {}
        name = md.get("name") or n.get("name") or "?"
        flat = json.dumps(st).lower()
        bad = [k for k in ("unhealthy", "unreachable", "notready", "not_ready", "failed", "degraded", "unknown")
               if re.search(rf'"{k}"|: "{k}', flat)]
        if bad:
            F.append(finding(f"AFM {name}", "afm", "afm_nodes", "afm", WARNING, f"AFM reports compute node {name}: {', '.join(bad)}",
                             "AFM sees this compute node as not healthy (its agent, its GPUs or its admission)",
                             "open the node in AFM and its node agent's log on the switch that serves it",
                             [json.dumps(st)[:280]], "GET /configs/cluster/v1/computenodes"))
    return F


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


def collect_switch(sw, drift: bool = True) -> dict:
    """Every switch check's output: {check: {cmd, rc, out, err}}."""
    outs: dict = {}
    for check, cmd, sudo in SWITCH_CMDS:
        _run(sw, check, cmd, sudo, outs)
    names = [ln.split("\t")[0].strip() for ln in (outs["containers"].get("out") or "").splitlines()
             if "\tUp" in ln]
    if missing(outs["containers"]):          # no container list: the critical processes are not checked either
        outs["critical"] = {"cmd": SUPERVISOR_CMD.format(c="<container>"), "rc": None, "out": "",
                            "err": "the container list could not be read"}
    for c in names:
        if CRITICAL_CONTAINERS.match(c):
            _run(sw, f"critical:{c}", SUPERVISOR_CMD.format(c=c), True, outs, timeout=60)
    if "afm-controller" in names:
        _run(sw, "controller_cert", CONTROLLER_CERT_CMD, True, outs, timeout=30)
    if "afm-agent" in names:
        _run(sw, "agent_certs", AGENT_CERT_CMD, True, outs, timeout=60)
    if drift:
        try:
            nss = sw.namespaces()
        except Exception:  # noqa: BLE001
            nss = []
        for ns in nss:
            n = ns[4:] if ns else ""
            flag = f" -n {ns}" if ns else ""
            _run(sw, f"running:{ns or ''}", RUNNING_CMD.format(ns=flag), True, outs, timeout=180)
            _run(sw, f"saved:{ns or ''}", SAVED_CMD.format(ns=flag, n=n), True, outs, timeout=180)
    return outs


def collect_compute(tray) -> dict:
    outs: dict = {}
    for check, cmd, sudo in COMPUTE_CMDS:
        _run(tray, check, cmd, sudo, outs)
    return outs


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
