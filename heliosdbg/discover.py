"""Draft an inventory for a new rack from its switch trays (read-only), for the UI's New rack form.

From each switch address given (SSH with this machine's key, as every tool here): hostname, ASIC namespaces, the
switch ports described 'To ComputeTray SlotN/...' - so which tray slots exist and how many GPU links each has.
With the AFM view (afm url + password): the ComputeNode of each slot - its name (afm_name) and any IPv4 in its
status ip-config (offered as the tray address, to verify). Tray addresses that nothing tells are left as FILL-ME.
The draft never holds a password: logins are keys, or password_env naming a variable you set yourself.
"""
from __future__ import annotations

import re
from collections import Counter

import yaml

from .afmctl import parse_port_description
from .inventory import Host
from .sonic import SonicSwitch
from .transport import SshTransport

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_switch(addr: str, user: str, timeout: float = 15, key_file: str | None = None, jump: dict | None = None) -> dict:
    h = Host(name=addr, host=addr, role="switch", user=user, key_file=key_file or None)
    sw = SonicSwitch(h, SshTransport(h, connect_timeout=timeout, jump=jump))
    try:
        name = sw.sh("hostname", timeout=30).strip()
        slots: Counter = Counter()
        gpus: dict = {}
        nss = sw.namespaces()
        for ns in nss:
            for _port, desc in sw.port_descriptions(ns).items():
                cab = parse_port_description(desc)
                if cab:
                    slots[cab[0]] += 1
                    gpus.setdefault(cab[0], set()).add(cab[1])
        return {"address": addr, "hostname": name, "asics": [n for n in nss if n], "slots": dict(sorted(slots.items())),
                "gpus_per_slot": {s: len(g) for s, g in sorted(gpus.items())}}
    finally:
        sw.close()


def afm_trays(afm, switch_addrs: set[str]) -> dict[int, dict]:
    """{slot: {afm_name, ip}} from AFM ComputeNodes; ip = first IPv4 in status ip-config not a switch / controller."""
    out = {}
    for n in afm.computes():
        slot = (n.get("spec") or {}).get("slot-id")
        if slot is None:
            continue
        st = n.get("status") or {}
        ctrl = set(IPV4.findall(str(st.get("controllers") or "")))
        ips = [ip for ip in IPV4.findall(str(st.get("ip-config") or "")) if ip not in switch_addrs | ctrl
               and not ip.startswith(("127.", "169.254.", "0."))]
        out[int(slot)] = {"afm_name": n["meta"]["name"], "ip": ips[0] if ips else None}
    return out


def draft(rack: str, switches: list[dict], user_switch: str, user_compute: str, afm_url: str | None,
          trays_from_afm: dict[int, dict] | None, key_file: str | None = None, jump: dict | None = None) -> str:
    slots = sorted({s for sw in switches for s in sw["slots"]})
    sw_entries = []
    for i, sw in enumerate(switches, 1):
        sw_entries.append({"name": f"st{i}" if len(switches) > 1 else "st1", "host": sw["address"]})
    ct_entries = []
    for i, s in enumerate(slots, 1):
        a = (trays_from_afm or {}).get(s) or {}
        e = {"name": f"ct{i:02d}" if len(slots) > 9 else f"c{i}", "host": a.get("ip") or f"FILL-ME-slot{s}-address", "slot": s}
        if a.get("afm_name"):
            e["afm_name"] = a["afm_name"]
        ct_entries.append(e)
    doc = {"rack": rack, "transport": {"kind": "ssh", "connect_timeout": 15},
           "defaults": {"switch": {"user": user_switch}, "compute": {"user": user_compute}},
           "switches": sw_entries, "computes": ct_entries}
    if key_file:
        doc["defaults"]["common"] = {"key_file": key_file}
    if jump:
        doc["transport"]["jump"] = jump
    if afm_url:
        doc["afm"] = {"url": afm_url, "verify_tls": False, "auth": {"username": "admin", "password_env": "HELIOS_AFM_PASSWORD"}}
    head = [f"# {rack}: drafted by helios-debug from {', '.join(sw['hostname'] + ' (' + sw['address'] + ')' for sw in switches)}",
            "# Check every FILL-ME and every address before use. No passwords here: key login, or password_env: VAR.",
            "# Tray slots seen in the switch port descriptions: " +
            ", ".join(f"slot {s} ({sum(sw['slots'].get(s, 0) for sw in switches)} links, "
                      f"{max(sw['gpus_per_slot'].get(s, 0) for sw in switches)} GPUs)" for s in slots)]
    if trays_from_afm:
        head.append("# Tray addresses / afm_name from AFM ComputeNodes (status ip-config) - verify them.")
    return "\n".join(head) + "\n" + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
