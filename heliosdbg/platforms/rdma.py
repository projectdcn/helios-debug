"""The scale-out network of a compute tray: its RDMA NICs - port state and why a port is down (no optic, no light,
the leaf), optics temperature, link flaps, drop / error counters, and the NIC firmware (mixed on one tray, or
different between trays). Read-only.

The port detail comes from the NIC's own tool when it is there (AMD Pensando: `nicctl show port`, one JSON per card;
g02-g17 2 Nov: 'Transceiver removed' on the 8 AI NICs of 7 trays - the ports RDMA showed as POLLING have no optic).
"""
from __future__ import annotations

import json
import re

from ..checks import CRITICAL, WARNING, Platform, _cmd, _out, finding
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (r"ibv_devinfo(?:\s+-[vl])?(?:\s+-d\s+[A-Za-z0-9_]+)?|rdma\s+(?:link|dev)(?:\s+show)?", False),
    (r"nicctl\s+show\s+(?:port|card|lif|pcie|qos|dcqcn|rdma|version|environment)(?:\s+-b\s+[0-9a-f]{4}:[0-9a-f]{2}:"
     r"[0-9a-f]{2}\.\d)?(?:\s+-j)?", True),
]

# every card's port JSON in one session: '@@card <bdf> <flavour/.../firmware>' lines, then '@@port <bdf>' + its JSON
# (nicctl wants -b when a tray has cards of more than one flavour; with one flavour a plain show covers them all)
NICCTL_PORTS = (
    'L=$(nicctl show port -j 2>&1); if echo "$L" | grep -q "Available cards"; then echo "$L" | sed -n '
    "'s/^  \\([0-9a-f]*:[0-9a-f]*:[0-9a-f]*\\.[0-9]\\) \\/ [^ ]*  \\(.*\\)$/@@card \\1 \\2/p'; "
    "for b in $(echo \"$L\" | sed -n 's/^  \\([0-9a-f]*:[0-9a-f]*:[0-9a-f]*\\.[0-9]\\) .*/\\1/p'); do "
    'echo "@@port $b"; nicctl show port -b $b -j; done; else echo "@@port all"; echo "$L"; fi')
# drop / error counters of every RDMA netdev (since boot)
NIC_COUNTERS = ("for d in $(rdma link show | sed -n 's/.* netdev \\([^ ]*\\).*/\\1/p'); do echo \"@@dev $d\"; "
                "ethtool -S $d 2>/dev/null | grep -E 'hw_(rx|tx)_dropped|rx_over_errors|rx_missed_errors|"
                "tx_aborted_errors|rx_csum_error'; done")

COMMANDS = [
    ('rdma', 'rdma link show', False),
    ('nic_ports', NICCTL_PORTS, True),
    ('nic_counters', NIC_COUNTERS, True),
]
LINK_DOWN_EVENTS = 3          # an up port that went down more often than this since the NIC started: flapping


def parse_nicctl(text: str | None, bad: list | None = None) -> tuple[dict[str, str], list[dict]]:
    """({card bdf: flavour/.../firmware}, [{card, name, admin, oper, reason, xcvr, pid, temp, temp_warn, temp_alarm,
    down_events}]) from NICCTL_PORTS' output. Cards whose port JSON could not be read go into `bad`."""
    cards: dict[str, str] = {}
    ports: list[dict] = []
    bad = [] if bad is None else bad
    for m in re.finditer(r"^@@card (\S+) (\S+)", text or "", re.M):
        cards[m.group(1)] = m.group(2)
    for block in (text or "").split("@@port ")[1:]:
        card, _, body = block.partition("\n")
        try:
            d = json.loads(body[body.find("{"):]) if "{" in body else {}
        except ValueError:
            d = None
        if not isinstance(d, dict) or not d.get("nic"):
            bad.append(card.strip() or "?")
            continue
        for nic in d.get("nic") or []:
            for p in nic.get("port") or []:
                st, sp = p.get("status") or {}, p.get("spec") or {}
                ports.append({"card": card.strip(), "name": sp.get("name") or st.get("physical_port") or "?",
                              "admin": sp.get("admin_state"), "oper": st.get("operational_status"),
                              "reason": st.get("port_down_reason"), "xcvr": st.get("transceiver_state"),
                              "pid": st.get("transceiver_pid"), "temp": _f(st.get("transceiver_temperature")),
                              "temp_warn": _f(st.get("transceiver_warning_temperature")),
                              "temp_alarm": _f(st.get("transceiver_alarm_temperature")),
                              "down_events": int(_f(st.get("number_of_link_down_events")) or 0)})
    return cards, ports


def _f(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _firmware(flavour: str) -> tuple[str, str]:
    """'vulcano/rudra/pulsar/1.130.5-a-7' -> ('vulcano', '1.130.5-a-7')."""
    parts = flavour.split("/")
    return parts[0], parts[-1]


def _down_cause(down_ports: list[dict]) -> tuple[str, str, bool]:
    """(cause, next step, nothing plugged in) of the down ports, from the NIC's own down reasons."""
    reasons: dict[str, int] = {}
    for p in down_ports:          # an empty cage can also say reason 'None' (g02-g17 ct10's unused eth1/2): the optic decides
        r = "Transceiver removed" if str(p["xcvr"]).upper() == "REMOVED" else str(p["reason"] or "unknown")
        reasons[r] = reasons.get(r, 0) + 1
    if reasons and set(reasons) <= {"Transceiver removed"}:
        # no count here: the rack-wide grouping keeps one node's cause, and ct05's '4 port(s)' read wrong next to
        # ct10's 8 (5 Nov) - the evidence lines carry each node's count
        return ("no optic / cable in these NIC ports (the NIC says 'Transceiver removed' for every one of them) - the "
                "scale-out cabling is not installed, or was pulled",
                "site: plug in / check the optics and cables of these NICs and their leaf switch ports", True)
    if reasons:
        return ("the NIC gives: " + ", ".join(f"{r} ({n})" for r, n in sorted(reasons.items())),
                "'Transceiver removed': nothing plugged in; no light / signal: the optic or cable, then the leaf switch "
                "port; read 'sudo nicctl show port -b <card>' for the port", False)
    return ("a scale-out NIC port is down - its cable, the leaf switch port, or the NIC",
            "read 'ip -br link' and the NIC's leaf switch port; the cable / optic next", False)


def judge(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    unread: list[str] = []
    nic_text = _out(outs, "nic_ports")
    cards, ports = parse_nicctl(nic_text, unread)
    if nic_text and (unread or not ports):
        F.append(finding(node, "compute", "nic_ports", "rdma", WARNING,
                         "nicctl gave no readable port data" + (f" for card(s) {', '.join(unread[:6])}" if unread else ""),
                         "the NIC port checks (why a port is down, optics, flaps, firmware) were not made for these "
                         "cards - empty or non-JSON output from nicctl", "read 'sudo nicctl show port -j' by hand",
                         [re.sub(r"\s+", " ", nic_text)[:200]], _cmd(outs, "nic_ports")))
    down_ports = [p for p in ports if str(p["admin"]).upper() == "UP" and str(p["oper"]).upper() != "UP"]
    t = _out(outs, "rdma")
    if t is not None and not t.strip() and cards:
        F.append(finding(node, "compute", "rdma", "rdma", WARNING,
                         f"no RDMA ports listed, but nicctl sees {len(cards)} NIC card(s)",
                         "the NICs are there but have no RDMA devices - the NIC's RDMA driver is not loaded",
                         "read 'lsmod | grep -i rdma' and 'sudo dmesg | grep -i rdma | tail'; loading the driver CHANGES "
                         "THE TRAY - for its owner", [], _cmd(outs, "rdma")))
    if t:
        bad = [ln for ln in t.splitlines() if ln.startswith("link") and ("state ACTIVE" not in ln or "LINK_UP" not in ln)
               and "physical_state DISABLED" not in ln]   # an administratively disabled (unused) port is not a fault
        if bad:
            cause, nxt, no_optic = _down_cause(down_ports)
            F.append(finding(node, "compute", "rdma", "rdma", WARNING, f"{len(bad)} RDMA NIC port(s) not ACTIVE / LINK_UP",
                             cause, nxt, bad[:6] + [f"{p['card']} {p['name']}: {p['oper']}, {p['reason']}, optic "
                                                    f"{p['xcvr']}" for p in down_ports[:2]], _cmd(outs, "rdma")))
            if no_optic:
                F[-1]["owner"] = "site"
    for p in ports:
        if str(p["oper"]).upper() != "UP":
            continue
        if p["down_events"] > LINK_DOWN_EVENTS:
            F.append(finding(node, "compute", "nic_flaps", "rdma", WARNING,
                             f"NIC {p['card']} {p['name']}: link went down {p['down_events']} times",
                             "a scale-out link that flaps - a marginal optic, cable or leaf port",
                             "compare with the leaf switch port's flap count; reseat / swap the optic (on site)",
                             [json.dumps(p)[:250]], _cmd(outs, "nic_ports")))
        warn, alarm = p["temp_warn"], p["temp_alarm"]
        if p["temp"] and ((warn and p["temp"] >= warn) or (alarm and p["temp"] >= alarm)):
            crit = bool(alarm and p["temp"] >= alarm)
            F.append(finding(node, "compute", "nic_optic", "thermal", CRITICAL if crit else WARNING,
                             f"NIC {p['card']} {p['name']}: optic {p['pid']} at {p['temp']:.0f} C (warning "
                             f"{warn or 0:.0f}, alarm {alarm or 0:.0f})", "the optic runs hot - airflow or the optic",
                             "site checks the tray's airflow; swap the optic if it stays hot", [json.dumps(p)[:250]],
                             _cmd(outs, "nic_ports")))
    by_kind: dict[str, dict[str, list[str]]] = {}
    for bdf, flav in cards.items():
        kind, fw = _firmware(flav)
        by_kind.setdefault(kind, {}).setdefault(fw, []).append(bdf)
    for kind, fws in sorted(by_kind.items()):
        if len(fws) > 1:
            F.append(finding(node, "compute", "nic_firmware", "rdma", WARNING,
                             f"{kind} NICs run {len(fws)} firmware versions: "
                             + ", ".join(f"{fw} ({len(b)})" for fw, b in sorted(fws.items())),
                             "the NICs of one kind on this tray were not all updated - mixed firmware can behave "
                             "differently under the same traffic", "the NIC owner updates them to one version (CHANGES THE "
                             "TRAY)", [f"{fw}: {', '.join(sorted(b))}" for fw, b in sorted(fws.items())],
                             _cmd(outs, "nic_ports")))
    t = _out(outs, "nic_counters")
    if t:
        dev, hits = "", []
        for ln in t.splitlines():
            if ln.startswith("@@dev "):
                dev = ln[6:].strip()
                continue
            k, _, v = ln.strip().partition(":")
            n = _f(v.strip())
            if n and n > 0:
                hits.append(f"{dev} {k.strip()} {int(n)}")
        if hits:
            F.append(finding(node, "compute", "nic_counters", "rdma", WARNING,
                             f"{len(hits)} NIC drop / error counter(s) above 0 since boot",
                             "frames dropped or errors on scale-out NICs - congestion (PFC / ECN not set up), a bad link, "
                             "or host buffers", "read them again in a few minutes: growing counters are a live problem; "
                             "'sudo ethtool -S <dev>' for the rest", hits[:8], _cmd(outs, "nic_counters")))
    return F


def judge_rack(outs_by_node: dict[str, dict]) -> list[dict]:
    """Across the trays: NICs of one kind whose firmware (the set of versions on a tray) differs from tray to tray.
    The same mix on every tray is the per-tray finding, not this one."""
    sets: dict[str, dict[tuple, set[str]]] = {}
    for node, outs in outs_by_node.items():
        cards, _ports = parse_nicctl(_out(outs, "nic_ports"))
        per: dict[str, set[str]] = {}
        for flav in cards.values():
            kind, v = _firmware(flav)
            per.setdefault(kind, set()).add(v)
        for kind, vs in per.items():
            sets.setdefault(kind, {}).setdefault(tuple(sorted(vs)), set()).add(node)
    F = []
    for kind, groups in sorted(sets.items()):
        if len(groups) > 1:
            mixed = sorted(n for v, ns in groups.items() if len(v) > 1 for n in ns)
            F.append(dict(finding(f"{len(outs_by_node)} trays", "compute", "nic_firmware_rack", "rdma", WARNING,
                             f"{kind} NIC firmware differs between trays: "
                             + "; ".join(f"{' + '.join(v)} on {len(n)}" for v, n in sorted(groups.items())),
                             "the trays were not all updated to one NIC firmware"
                             + (f"; {len(mixed)} of them also mix versions on their own NICs (a part of each tray "
                                "updated)" if mixed else ""),
                             "the NIC owner picks one version for the rack (CHANGES THE TRAYS)",
                             [f"{' + '.join(v)}: {', '.join(sorted(n))}" for v, n in sorted(groups.items())],
                             "nicctl show port -j"), absorbs="nic_firmware"))   # the per-tray mix: this one says it
    return F


PLATFORM = Platform("rdma", "compute", "the scale-out RDMA NICs of a compute tray (port state and why, optics, flaps, "
                    "counters, firmware)", COMMANDS, judge, read_only=READ_ONLY, judge_rack=judge_rack)
