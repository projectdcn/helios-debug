"""SONiC switch OS and the switch platform: system health, containers and restarts, critical processes in each
container, CRM tables, disk, memory, core files, reboot cause, PSUs / fans / temperatures / voltages / watchdog, syslog
errors grouped by message, running vs saved configuration. Read-only."""
from __future__ import annotations

import json
import re
import time

from ..checks import CRITICAL, LIMITS, WARNING, Platform, _cmd, _disk, _memory, _num, _out, _run, clip, finding, missing  # noqa: F401
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

_DBKEY = r"'[A-Z][A-Z0-9_]*\|[A-Za-z0-9_.:*/-]*'"     # a quoted 'TABLE|key' (the '|' is the key's, not a pipe)
READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (rf"show\s+interfaces\s+(?:status|description|counters(?:\s+fec-stats|\s+errors|\s+rates)?|transceiver\s+(?:presence|eeprom|lpmode))"
         rf"{_NS}(?:\s+-d\s+all)?(?:\s+-i)?(?:\s+Ethernet\d+)?", False),
    (rf"show\s+mac{_NS}(?:\s+-p\s+Ethernet\d+|\s+-v\s+\d+)?", True),
    (rf"show\s+vlan\s+brief{_NS}", False),
    (r"show\s+(?:version|platform\s+(?:summary|psustatus|fan|temperature|syseeprom|firmware\s+status)|system-memory|"
         r"processes\s+summary|uptime|services|environment|reboot-cause)", False),
    (rf"show\s+(?:pfc\s+counters|queue\s+counters|pfcwd\s+stats|buffer_pool\s+watermark){_NS}", False),
    (r"systemctl\s+status\s+[A-Za-z0-9@_.-]+(?:\s+(?:--no-pager|-l|--full|-n\s+\d{1,3}))*", False),
    (r"show\s+logging", True),                    # not -f: it never ends and holds a jump-host session
    (rf"show\s+lldp\s+(?:table|neighbors){_NS}", False),
    (rf"sonic-db-cli{_NS}\s+(?:APPL_DB|ASIC_DB|CONFIG_DB|STATE_DB|COUNTERS_DB)\s+(?:keys|hgetall|hget|exists|scan)\s+(?:{_DBKEY}|{_WORD})(?:\s+{_WORD})?", True),
    (r"docker\s+ps(?:\s+-a)?", True),
    (r"uptime|free\s+-[mh]|df\s+-h", False),
    # QFX5252 switch tray (HPE guide, 3 Nov 2026): leak, PCIe, interface errors / flaps / FEC, NTP, images, management, BMC
    (rf"show\s+(?:platform\s+(?:leak\s+(?:status|channels)|pcieinfo|current)|ntp|interfaces\s+(?:alias|errors\s+Ethernet\d+|"
         rf"flap\s+Ethernet\d+|fec\s+status{_NS}(?:\s+Ethernet\d+)?|transceiver\s+(?:info|status){_NS}(?:\s+Ethernet\d+)?))", False),
    (r"chronyc\s+(?:tracking|sources(?:\s+-v)?)|ip\s+-br\s+(?:-4\s+|-6\s+)?(?:address|addr|link)\s+show\s+eth[01]|"
     r"ip\s+route\s+show\s+(?:default|dev\s+eth[01])|pgrep\s+-af\s+'dhclient\.\*eth0'", False),
    (r"sonic-installer\s+list|bmc-manager\s+(?:status|health|power-status|version|flash-info|check)|"
     r"bmc-manager\s+(?:dmesg|journal)\s+errors", True),
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
    # the AFM agent's own logs on the switch (st4 4 Nov: IFCP stuck on 'resource temporarily unavailable'), last lines only
    (r"tail\s+-n\s+\d{1,4}\s+/opt/amd/afm/agent/logs/(?:ifcp|ifcp-err|switch_agent_out|sb_agent_out|switch_agent_err|sb_agent_err)\.log", True),
    (r"ls\s+-lt\s+/opt/amd/afm/agent/logs/?", True),
    # whether the chip passes packets up to the CPU at all (st4 4 Nov: 0 of 216 ports with link had received one)
    (r"ip(?:\s+-n\s+asic\d+)?\s+-s\s+-o\s+link\s+show", True),
    # the Broadcom shell, reads only (docs/link-debug-guide.md, heliosdbg/bcm.py) - never prbs / eyescan / loopback / set
    (r"bcmcmd(?:\s+-n\s+\d)?\s+(?:'(?:show pmap|ps(?:\s+\w+)?)'|\"(?:show pmap|ps(?:\s+\w+)?)\"|"
     r"'bsh -c \"(?:PortStatus(?:\s+\d+)?|lt LM_LINK_STATE traverse|lt (?:PC_PORT_STATUS|PC_PHY_STATUS|PC_PHY_STATUS_2|"
     r"PC_PORT_CUMULATIVE_DIAG_STATS|LM_LINK_STATE|PC_PORT|PC_FDR_STATS|CTR_MAC|CTR_MAC_ERR) lookup "
     r"PORT_ID=\d+(?: LANE_INDEX=\d)?(?: STATUS=STATUS_(?:2_)?ALL)?)\"')", True),
]
from ..parsers import parse_table

# (check, command, sudo); {ns} = ' -n asicN' per ASIC namespace where a command takes one
COMMANDS = [
    ('health', 'show system-health summary', True),
    ('containers', "docker ps -a --format '{{.Names}}\t{{.Status}}'", True),
    ('restarts', "docker inspect -f '{{.Name}} {{.RestartCount}} {{.State.StartedAt}}' $(docker ps -q)", True),
    ('uptime', 'cat /proc/uptime', False),
    ('crm', 'crm show resources all', True),
    ('disk', 'df -P / /var/log /host', False),
    ('memory', "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo", False),
    ('cores', 'ls -1 /var/core', True),
    ('reboot', 'show reboot-cause', False),
    ('reboot_history', 'show reboot-cause history', False),
    ('psu', 'show platform psustatus', False),
    ('fan', 'show platform fan', False),
    ('temperature', 'show platform temperature', False),
    ('voltage', 'show platform voltage', False),
    ('watchdog', 'watchdogutil status', True),
    ('syslog', "grep -hE ' (ERR|CRIT|ALERT|EMERG) ' /var/log/syslog.1 /var/log/syslog | tail -n 400", True),
    # QFX5252 switch tray (HPEN SONiC): leak detection, SSD, clock, BMC through bmc-manager, images, management
    # interface - from the HPE switch tray configuration and management guide (3 Nov 2026), outputs as on g02-g17 st5
    ('leak', 'show platform leak status', False),
    ('leak_channels', 'show platform leak channels', False),
    ('ssd', 'show platform ssdhealth', False),
    ('ntp', 'show ntp', False),
    ('bmc_health', 'bmc-manager health', True),
    ('bmc_power', 'bmc-manager power-status', True),
    ('images', 'sonic-installer list', True),
    ('mgmt', "sonic-db-cli CONFIG_DB KEYS 'MGMT_INTERFACE|*'", True),
]
CRITICAL_CONTAINERS = re.compile(r"^(pmon|database\d*|swss\d*|syncd\d*|lldp\d*|bgp\d*|teamd\d*|radv|snmp|gnmi|telemetry)$")
SUPERVISOR_CMD = "docker exec {c} sh -c 'cat /etc/supervisor/critical_processes; echo ===; supervisorctl status'"
DRIFT_TABLES = ("PORT", "VLAN", "VLAN_MEMBER", "PORT_QOS_MAP", "PFC_WD", "BUFFER_PG", "BUFFER_QUEUE")
RUNNING_CMD = "sonic-cfggen{ns} -d --print-data"
SAVED_CMD = "sonic-cfggen{ns} -j /etc/sonic/config_db{n}.json --print-data"
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
    lim = LIMITS["restart_warn"]
    now = time.time()
    hits = [(n, c, s, ln) for n, c, s, ln in _started(outs)
            if c >= lim or (_young(s, uptime_s, now) and (CRITICAL_CONTAINERS.match(n) or n.startswith("afm")))]
    # the containers started within a minute of each other are one event (g02-g17 5 Nov: swss0, syncd0, bgp0, teamd0,
    # radv and snmp of asic0 at once, on one switch after another - six warnings per switch for one restart)
    hits.sort(key=lambda h: h[2] or 0)
    events: list[list] = []
    for h in hits:
        if events and h[2] and events[-1][-1][2] and h[2] - events[-1][-1][2] <= 60 and h[1] < lim:
            events[-1].append(h)
        else:
            events.append([h])
    for ev in events:
        names = sorted(n for n, _c, _s, _l in ev)          # one order on every switch: the rack-wide grouping matches
        count, started = max(c for _n, c, _s, _l in ev), ev[0][2]
        when = f"started {_utc(started)} UTC ({_ago(now - started)} ago)" if started else "start time unknown"
        afm = all(n.startswith("afm") for n in names)
        how = (f"restarted {count} times since it was created - it keeps crashing" if count >= lim else
               "restart count 0: stopped and started (a manual restart, a service restart or a config reload), not "
               "crash-looping")
        if len(ev) == 1:
            what = f"container {names[0]} started after the switch booted"
            cause = f"{names[0]} was started again after the switch booted - {how}"
        else:
            asics = {m.group(1) for m in (re.search(r"(\d+)$", n) for n in names) if m}
            whose = f"asic{asics.pop()}'s services" if len(asics) == 1 else "switch services"
            what = f"{whose} started again together: {', '.join(names)}"
            cause = (f"{len(names)} containers started within a minute of each other after the switch booted - one "
                     f"restart of {whose}, not {len(names)} crashes; {how}")
        F.append(dict(finding(node, "switch", "restarts", "afm" if afm else "sonic", WARNING, what, cause,
                              "ask who restarted them and why; read 'docker logs --tail 100 <container>' and the syslog "
                              "around the start time", [when] + [l.strip() for _n, _c, _s, l in ev][:8],
                              _cmd(outs, "restarts")), when=when, started=started))


def _started(outs) -> list[tuple[str, int, float | None, str]]:
    """[(container, restart count, start epoch, line)] of the 'docker inspect' restarts listing."""
    out = []
    for ln in (_out(outs, "restarts") or "").splitlines():
        toks = ln.split()
        if len(toks) == 3 and toks[1].isdigit():
            out.append((toks[0].lstrip("/"), int(toks[1]), _iso_epoch(toks[2]), ln))
    return out


def _young(started, uptime_s, now) -> bool:
    """Started after the switch booted (not with it) - within the last day."""
    return started is not None and uptime_s is not None and uptime_s > 3600 and now - started < min(uptime_s - 600, 86400)


def _utc(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(epoch))


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
        # a critical program supervisord does not have at all is not configured on this switch (radv's radvd on a
        # QFX5252 fabric with no IPv6 router advertisement - g02-g17 st5, 4 Nov), not down
        down = [f"{p}:{status[p]}" for p in crit if p in status and status[p] != "RUNNING"
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


def _kv(text: str) -> dict:
    """'Device leak status         Normal' / 'Health       : 100.0%' lines as {key: value}."""
    out = {}
    for ln in (text or "").splitlines():
        m = re.match(r"\s*([A-Za-z][\w ()/.-]*?)\s*(?::\s+|\s{2,})(\S.*)$", ln)
        if m:
            out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def _tray(node, outs, F):
    """The QFX5252 switch tray beyond PSUs / fans: leak detection, SSD wear, NTP, the BMC (bmc-manager over the internal
    USB link, so it answers even when the BMC's own address does not), the image the next reboot boots, management."""
    t = _out(outs, "leak")
    if t is not None:
        kv = _kv(t)
        st, alert = kv.get("device leak status", ""), kv.get("hardware comparator alert", "")
        if (st and st.lower() != "normal") or alert.lower() == "yes":
            F.append(finding(node, "switch", "leak", "thermal", CRITICAL, f"leak detection: device leak status {st or '?'}"
                             + (", hardware comparator alert" if alert.lower() == "yes" else ""),
                             "a leak sensor of the liquid cooling (manifold / cold plates) reports a leak",
                             "read 'show platform leak channels' for the location; the site inspects the cooling loop NOW "
                             "- liquid near powered equipment", t.splitlines()[:6], _cmd(outs, "leak")))
        bad = [k for k in ("fpga access", "adc access") if kv.get(k) and kv[k].lower() != "good"]
        if bad:
            F.append(finding(node, "switch", "leak", "thermal", WARNING, "leak detection cannot read its sensors ("
                             + ", ".join(f"{k} {kv[k]}" for k in bad) + ")", "a leak would not be detected",
                             "hardware owner: 'show platform leak status' again, then the BMC event log",
                             t.splitlines()[:6], _cmd(outs, "leak")))
    t = _out(outs, "leak_channels")
    if t is not None:
        for r in parse_table(t):
            ds = str(r.get("Data-status", "")).strip()
            if ds and ds.lower() != "good":
                F.append(finding(node, "switch", "leak", "thermal", WARNING, f"leak sensor {r.get('Name', '?')} "
                                 f"({r.get('Location', '?')}): data {ds}", "this sensor is not read - a leak there would "
                                 "not be detected", "hardware owner checks the sensor and its cable",
                                 [" ".join(str(v) for v in r.values())[:200]], _cmd(outs, "leak_channels")))
    t = _out(outs, "ssd")
    if t is not None:
        h = _num(_kv(t).get("health"))
        if h is not None and h < 80:
            F.append(finding(node, "switch", "ssd", "switch", CRITICAL if h < 50 else WARNING, f"SSD health {h:g} %",
                             "the switch's SSD (SONiC and its logs) is wearing out", "plan the SSD replacement with the "
                             "hardware owner; keep the configuration saved off the switch", t.splitlines()[:4], _cmd(outs, "ssd")))
    t = _out(outs, "ntp")
    if t is not None and re.search(r"Leap status\s*:\s*Not synchroni[sz]ed", t, re.I):
        srcs = [ln.split() for ln in t.splitlines() if re.match(r"\s*\^", ln)]      # ^? <addr> stratum poll reach ...
        silent = [x for x in srcs if len(x) > 4 and x[4] == "0"]
        F.append(finding(node, "switch", "ntp", "sonic", WARNING, "clock not synchronised to NTP",
                         ("no NTP source answers" + (f" (all {len(srcs)} configured: reach 0)" if srcs and len(silent) == len(srcs)
                                                       else "") if not srcs or len(silent) == len(srcs) else
                          "no NTP source selected")
                         + ": times in this switch's logs and events cannot be matched with the other nodes', and "
                         "certificate checks fail once the clock drifts far enough",
                         "make an NTP server reachable from the management network ('show ntp' lists the configured "
                         "ones); adding one ('sudo config ntp add') CHANGES THE SWITCH - for the network team",
                         [x for x in t.splitlines() if re.search(r"Leap status|Stratum|^\s*\^", x)][:6], _cmd(outs, "ntp")))
    t = _out(outs, "bmc_health")
    if t is not None:
        m = re.search(r"BMC STATUS:\s*([A-Z ]+?)\s*[║|]", t)
        down = [ln.strip() for ln in t.splitlines() if re.match(r"\s+\S+\s+(inactive|failed|activating)\b", ln)]
        if (m and m.group(1).strip() != "HEALTHY") or down:
            F.append(finding(node, "switch", "bmc", "bmc", WARNING, "switch BMC: " + (m.group(1).strip().lower() if m else "")
                             + (" - services " + ", ".join(down[:4]) if down else ""), "the switch's BMC (OpenBMC) is not "
                             "healthy: out-of-band access, sensors through Redfish and its console may not work",
                             "'sudo bmc-manager status' and 'sudo bmc-manager journal errors' on the switch; recovering it "
                             "(power-cycle of the BMC) CHANGES THE SWITCH - hardware owner", down[:6] or t.splitlines()[-6:],
                             _cmd(outs, "bmc_health")))
    r = outs.get("bmc_power") or {}
    if not missing(r):
        lines = [ln.strip() for ln in ((r.get("out") or "") + "\n" + (r.get("err") or "")).splitlines()]
        for ln in lines:
            m = re.match(r"\[(WARN|FAIL)\]\s*(.+)", ln)
            if m:
                wdt = re.search(r"WDT|watchdog", m.group(2), re.I)
                F.append(finding(node, "switch", "bmc", "bmc", CRITICAL if m.group(1) == "FAIL" else WARNING,
                                 f"switch BMC: {m.group(2)}", "the BMC was restarted by its own watchdog (it hung or "
                                 "crashed)" if wdt else "the BMC's power / presence check reports a problem",
                                 "'sudo bmc-manager journal errors' and 'sudo bmc-manager dmesg errors' on the switch; if "
                                 "it repeats, the hardware owner", [ln], _cmd(outs, "bmc_power")))
    t = _out(outs, "images")
    if t is not None:
        kv = _kv(t)
        cur, nxt = kv.get("current", ""), kv.get("next", "")
        if cur and nxt and cur != nxt:
            F.append(finding(node, "switch", "image", "sonic", WARNING, f"the next reboot boots {nxt}, not the running {cur}",
                             "an image was installed or set as next and the switch has not rebooted into it",
                             "confirm with the network team that this is planned before anyone reboots the switch",
                             t.splitlines()[:4], _cmd(outs, "images")))
    t = _out(outs, "mgmt")
    if t is not None:
        keys = [k.strip() for k in t.splitlines() if k.strip().startswith("MGMT_INTERFACE|")]
        if len({k.split("|")[1] for k in keys if k.count("|") >= 2}) > 1:
            F.append(finding(node, "switch", "mgmt", "sonic", WARNING, f"{len(keys)} management interfaces configured",
                             "more than one management interface with a gateway: the default route flips between them and "
                             "the switch drops off the management network", "keep one (eth0 or eth1) in "
                             "MGMT_INTERFACE; changing it CHANGES THE SWITCH - from its console, network team",
                             keys[:6], _cmd(outs, "mgmt")))


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
    what = "; ".join(f"{len(ls)}x {d + ': ' if d else ''}{clip(m, 70)}" for (d, m), ls in top[:3])
    F.append(finding(node, "switch", "syslog", area, CRITICAL if serious else WARNING,
                     clip(f"{len(lines)} syslog error line(s), {len(groups)} distinct message(s): {what}", 300),
                     ("serious errors among them: " + "; ".join(f"{d}: {m[:80]}" for (d, m), _ls in serious[:2])) if serious else
                     "the switch logs these errors repeatedly; one message repeated is usually one cause (a daemon "
                     "polling something that fails) - check whether it matters for what is broken",
                     "read the full lines around the first occurrence ('sudo grep -n <word> /var/log/syslog | head'); "
                     "match them with the other findings on this switch",
                     [ls[-1] for _k, ls in (serious or top)[:4]], _cmd(outs, "syslog")))


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


def vlans_running(outs: dict) -> dict[str, dict[str, dict]]:
    """The VLANs of each ASIC namespace from its running configuration (read for drift already): {ns: {vlan id:
    {members, tagging: {mode: n}}}}. g02-g17 9 Nov: VLAN 100 / 200 / 300 with 72 member ports each on every chip."""
    got: dict[str, dict[str, dict]] = {}
    for key in sorted(k for k in outs if k.startswith("running:")):
        try:
            run = json.loads(_out(outs, key) or "")
        except ValueError:
            continue
        if not isinstance(run, dict):
            continue
        vl: dict[str, dict] = {}
        for name, v in (run.get("VLAN") or {}).items():
            vid = str((v or {}).get("vlanid") or re.sub(r"\D", "", name))
            vl[vid] = {"members": 0, "tagging": {}}
        for k, v in (run.get("VLAN_MEMBER") or {}).items():
            vid = re.sub(r"\D", "", k.split("|", 1)[0])
            m = vl.setdefault(vid, {"members": 0, "tagging": {}})
            m["members"] += 1
            mode = str((v or {}).get("tagging_mode") or "?")
            m["tagging"][mode] = m["tagging"].get(mode, 0) + 1
        got[key.split(":", 1)[1] or "host"] = vl
    return got


def _vlan_sig(vl: dict) -> tuple:
    return tuple(sorted((vid, v["members"]) for vid, v in vl.items()))


def _vlan_say(vl: dict) -> str:
    return ", ".join(f"VLAN {vid} x {v['members']}" for vid, v in sorted(vl.items(), key=lambda x: int(x[0] or 0))) or "no VLAN"


def _vlans(node, outs, F):
    """The chips of one switch tray carry different VLANs or member counts (they serve the same trays' GPUs)."""
    per = {ns: vl for ns, vl in vlans_running(outs).items() if ns != "host"}
    if len(per) < 2 or len({_vlan_sig(vl) for vl in per.values()}) == 1:
        return
    F.append(finding(node, "switch", "vlan", "sonic", WARNING, "its switch chips carry different VLANs: "
                     + "; ".join(f"{ns} {_vlan_say(vl)}" for ns, vl in sorted(per.items())),
                     "the VLAN configuration was applied to one chip and not the other (or changed on one): the GPU "
                     "ports of that chip are in the wrong VLAN or none", "compare 'show vlan brief -n asic0' with -n asic1; "
                     "fixing the VLAN members CHANGES THE SWITCH - for the network team",
                     [f"{ns}: {_vlan_say(vl)}" for ns, vl in sorted(per.items())], "show vlan brief -n asicN"))


def judge_rack(outs_by_node: dict[str, dict]) -> list[dict]:
    """Across the switch trays: chips whose VLANs (ids, member counts) differ from what most chips of the rack carry."""
    chips = {(node, ns): vl for node, outs in outs_by_node.items() for ns, vl in vlans_running(outs).items() if ns != "host"}
    if len(chips) < 3:
        return []
    sigs: dict[tuple, list] = {}
    for c, vl in chips.items():
        sigs.setdefault(_vlan_sig(vl), []).append(c)
    if len(sigs) == 1:
        return []
    ref_sig = max(sigs, key=lambda s: len(sigs[s]))
    ref = chips[sigs[ref_sig][0]]
    odd = sorted(c for s, cs in sigs.items() if s != ref_sig for c in cs)
    ev = [f"most chips ({len(sigs[ref_sig])} of {len(chips)}): {_vlan_say(ref)}"]
    for c in odd:
        vl = chips[c]
        diff = ([f"VLAN {v} missing" for v in sorted(set(ref) - set(vl))] + [f"VLAN {v} extra" for v in sorted(set(vl) - set(ref))]
                + [f"VLAN {v} {vl[v]['members']} members, not {ref[v]['members']}" for v in sorted(set(vl) & set(ref))
                   if vl[v]["members"] != ref[v]["members"]])
        ev.append(f"{c[0]} {c[1]}: " + "; ".join(diff))
    return [finding(f"{len(outs_by_node)} switches", "switch", "vlan_rack", "sonic", WARNING,
                    f"{len(odd)} switch chip(s) carry other VLANs than the rest of the rack: "
                    + ", ".join(f"{n} {ns}" for n, ns in odd),
                    "every chip serves one port of each GPU in the same VLANs; a chip that differs was configured "
                    "differently (or changed later) - its GPU ports are in the wrong VLAN or none",
                    "compare 'show vlan brief -n asicN' on those chips with a good one; fixing the VLAN members CHANGES "
                    "THE SWITCH - for the network team", ev, "show vlan brief -n asicN")]


CPU_RX_CMD = "ip{ns} -s -o link show"
_IP_LINE = re.compile(r"^\d+:\s+(Ethernet\d+)(?:@\S+)?:\s+<([^>]*)>.*?RX:[^\\]*\\\s+(\d+)\s+(\d+).*?TX:[^\\]*\\\s+(\d+)\s+(\d+)", re.M)


def cpu_rx(text: str) -> dict | None:
    """What the switch CPU receives from the front ports, from 'ip -s -o link show' (one line per netdev): {ports,
    up (ports with link), rx (of those, received a packet on the CPU), tx, quiet: up ports with RX 0 (a few)}.
    None when the text is not that listing."""
    rows = _IP_LINE.findall(text or "")
    if not rows:
        return None
    up = [(p, int(rxp), int(txp)) for p, flags, _rb, rxp, _tb, txp in rows if "LOWER_UP" in flags.split(",")]
    return {"ports": len(rows), "up": len(up), "rx": sum(1 for _p, r, _t in up if r > 0),
            "tx": sum(1 for _p, _r, t in up if t > 0), "quiet": [p for p, r, _t in up if r == 0][:6]}


def cpu_rx_line(s: dict, ns: str = "") -> str:
    return (f"CPU receive{' ' + ns if ns else ''}: {s['ports']} Ethernet ports, {s['up']} with link; {s['rx']} of those "
            f"have received packets on the CPU, {s['up'] - s['rx']} none" + (f" (e.g. {', '.join(s['quiet'])})" if s["quiet"] else "")
            + f"; {s['tx']} have sent")


def _cpu_rx(node, outs, F, uptime_s=None):
    keys = sorted(k for k in outs if k == "cpu_rx" or k.startswith("cpu_rx:"))
    got = {k.split(":", 1)[1] if ":" in k else "": cpu_rx(_out(outs, k) or "") for k in keys}
    now = time.time()
    young = {n: s for n, _c, s, _l in _started(outs) if _young(s, uptime_s, now)}
    for key in keys:
        ns = key.split(":", 1)[1] if ":" in key else ""
        s = got[ns]
        if not s or s["up"] < 8 or s["rx"]:
            continue
        cause = ("the switch chip passes nothing up to the CPU (its CPU packet path: SONiC syncd / the kernel network "
                 "driver) - whatever listens on the ports from the CPU (IFCP discovery, LLDP) hears nothing, so IFCP "
                 "sessions stay down on every link of this chip although the links are up; on a working switch every "
                 "port with link receives")
        nxt = ("compare with another switch ('sudo ip -n asicN -s -o link show'); read 'docker ps' (syncd) and 'show "
               "logging | grep -i syncd'; restarting the switch services or rebooting the switch changes the switch - only "
               "with the operator's go-ahead; switch owner / AMD if it stays")
        ev = [cpu_rx_line(s, ns)]
        # what the chip's own services did: a restart of them resets the counters - and is the first thing to ask about
        # (g02-g17 5 Nov: asic0's swss0 / syncd0 restarted on every switch, asic0 then received nothing, asic1 all)
        n = ns[4:] if ns.startswith("asic") else ""
        svc = sorted(c for c in young if c in (f"syncd{n}", f"swss{n}"))
        if svc:
            ago = _ago(now - min(young[c] for c in svc))
            cause = (f"{ns}'s services ({', '.join(svc)}) were started again {ago} before this check and the chip has "
                     f"passed nothing to the CPU since: the counters start at 0 with them, but every port with link "
                     f"should have received LLDP / IFCP frames within a minute - the CPU path did not come back after "
                     f"that restart. The chip passes nothing up to the CPU (its CPU packet path: SONiC syncd / the "
                     f"kernel network driver), so IFCP discovery and LLDP hear nothing and IFCP stays down on every link "
                     f"of this chip although the links are up")
            nxt = (f"ask who restarted {ns}'s services and why (an AFM / test procedure?); read 'docker logs --tail 100 "
                   f"syncd{n}' and the syslog since then; " + nxt)
            ev.append(f"{', '.join(svc)} started {_utc(min(young[c] for c in svc))} UTC ({ago} before this check)")
        fine = [o for o, t in got.items() if o != ns and t and t["up"] >= 8 and t["rx"] == t["up"]]
        if fine:
            ev.append("the same switch's " + ", ".join(f"{o} receives on all {got[o]['up']} of its ports with link"
                                                      for o in fine)
                      + (" (its services were not restarted)" if svc and not any(
                          c in young for o in fine for c in (f"syncd{o[4:]}", f"swss{o[4:]}")) else ""))
        f = finding(node, "switch", "cpu_rx", "switch", CRITICAL,
                    f"{ns or 'switch'}: none of the {s['up']} ports with link has received a packet on the switch CPU",
                    cause, nxt, ev, outs[key].get("cmd", ""))
        if svc:                                  # the rack-wide grouping sees a restart run switch by switch
            f |= {"started": min(young[c] for c in svc), "when": ev[1].split(" started ", 1)[1]}
        F.append(f)


def judge(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
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
    _tray(node, outs, F)
    _syslog(node, outs, F)
    _drift(node, outs, F)
    _vlans(node, outs, F)
    _cpu_rx(node, outs, F, up)
    return F


def collect(sw, outs: dict, opts: dict) -> None:
    """One critical-process check per critical container that is up, and with drift the running vs saved
    configuration of every ASIC namespace."""
    names = [ln.split("\t")[0].strip() for ln in (outs["containers"].get("out") or "").splitlines()
             if "\tUp" in ln]
    if missing(outs["containers"]):          # no container list: the critical processes are not checked either
        outs["critical"] = {"cmd": SUPERVISOR_CMD.format(c="<container>"), "rc": None, "out": "",
                            "err": "the container list could not be read"}
    for c in names:
        if CRITICAL_CONTAINERS.match(c):
            _run(sw, f"critical:{c}", SUPERVISOR_CMD.format(c=c), True, outs, timeout=60)
    try:
        nss = sw.namespaces()
    except Exception:  # noqa: BLE001
        nss = []
    for ns in nss:
        _run(sw, f"cpu_rx:{ns or ''}", CPU_RX_CMD.format(ns=f" -n {ns}" if ns else ""), True, outs, timeout=60)
    if opts.get("drift", True):
        try:
            nss = sw.namespaces()
        except Exception:  # noqa: BLE001
            nss = []
        for ns in nss:
            n = ns[4:] if ns else ""
            flag = f" -n {ns}" if ns else ""
            _run(sw, f"running:{ns or ''}", RUNNING_CMD.format(ns=flag), True, outs, timeout=180)
            _run(sw, f"saved:{ns or ''}", SAVED_CMD.format(ns=flag, n=n), True, outs, timeout=180)


PLATFORM = Platform("sonic", "switch", "SONiC switch OS and the switch platform (PSUs, fans, sensors, watchdog)",
                    COMMANDS, judge, collect,
                    read_only=READ_ONLY, judge_rack=judge_rack)
