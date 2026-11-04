"""Scale-up link diagnosis: collect both ends of every GPU link and name the root cause of each link that is down
or degraded. Rack-agnostic: works from the inventory's switches and compute trays only; which switch port belongs to
which GPU port is learned from the rack itself (the GPU port's own MAC, `afmctl show port` spec.nw_mac_addr, in the
switches' forwarding tables), with the switch port descriptions as the fallback for links AFM has not programmed.

Used by tools/link_check.py (`scan` and `path`). Read-only: SSH + `afmctl show`, `show interfaces`, `show mac`.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field

from . import reach
from .afmctl import Afmctl, parse_port_description
from .parsers import parse_table
from .rack import fan_out

COUNTERS = ("RX_ERR", "RX_DRP", "TX_ERR", "TX_DRP")
FEC = ("FEC_CORR", "FEC_UNCORR", "FEC_SYMBOL_ERR")

# owners: who acts on a cause
OPERATOR, SITE, SWITCH_VENDOR, GPU_VENDOR = "operator", "site (cabling)", "switch vendor", "GPU / AFM vendor"
# kinds judged per GPU, not per link: reported in "GPU state", left out of the per-ASIC / per-GPU patterns
GPU_LEVEL = ("gpu_not_active", "gpu_not_programmed")

# root-cause kinds: grouping key and the one-line summary of a group
KINDS = {
    "tray_unreachable": "compute tray not reachable",
    "tray_quarantined": "compute tray quarantined in the inventory",
    "tray_missing": "no compute tray in the inventory for this slot",
    "fdb_empty": "switch forwarding table empty when read - GPU ports could not be identified",
    "gpu_missing": "GPU port not found on the tray",
    "sw_admin_down": "switch port administratively down",
    "gpu_admin": "GPU port administratively disabled",
    "phys_never_up": "no physical link on either end, never up since the tray booted",
    "phys_went_down": "no physical link on either end, went down after being up",
    "phys_no_optic": "no transceiver / cable detected in the switch port",
    "one_sided": "one-sided link: the two ends disagree",
    "bit_errors": "bit errors growing on a link that is up",
    "ifcp": "physical link up but no IFCP session",
    "not_programmed": "link up but not programmed by AFM",
    "miscabled": "GPU port reaches a different switch port than described",
    "tray_not_programmed": "the switch has no forwarding entry for any GPU port of the tray (not programmed by AFM)",
    "gpu_not_active": "GPU not configured on the tray (afmctl config_phase not ACTIVE)",
    "gpu_not_programmed": "GPU in a vPOD in AFM but not programmed on the tray",
    "afm_port_failed": "AFM reports the GPU port failed although the link and IFCP are up",
    "afm_port_stale": "AFM still reports the GPU port ready although the link is down",
}


def num(v) -> int | None:
    try:
        return int(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def ns_flag(ns) -> str:
    return f" -n {ns}" if ns else ""


class FdbBrokenEntries(RuntimeError):
    """The switch's forwarding table holds entries without a switch port: SONiC's own `show mac` then fails
    (KeyError 'SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID') and no link of that switch can be matched. g02-g17 st1 23 Oct:
    static Vlan100 entries for test MACs 00:11:22:33:44:55 / ...3D:54 written at runtime to APPL_DB FDB_TABLE for
    ports the hardware had no bridge port for. Reported as a problem on the switch, not worked around."""

    def __init__(self, switch: str, ns, entries: list[dict]):
        self.switch, self.ns, self.entries = switch, ns, entries
        shown = "; ".join(f"Vlan{e.get('vlan') or '?'} {e['mac']} -> {e.get('port') or 'no port'} ({e.get('type') or '?'}, "
                          f"{e.get('source')})" for e in entries[:6])
        super().__init__(f"forwarding table has {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} without a switch "
                         f"port on {switch}{' ' + ns if ns else ''} - SONiC `show mac` fails on them, so no link of this "
                         f"switch could be matched: {shown}{' ...' if len(entries) > 6 else ''}")


_BROKEN_FDB_SCRIPT = (                               # one command per ASIC: the ASIC_DB FDB entries without a bridge port
    "sonic-db-cli{ns} ASIC_DB keys 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*' | while IFS= read -r k; do "
    "sonic-db-cli{ns} ASIC_DB hgetall \"$k\" | grep -q SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID || echo \"$k\"; done")


def broken_fdb_entries(sw, ns) -> list[dict]:
    """[{mac, vlan, port, type, source}] of the forwarding entries the hardware holds without a switch port, with
    what the switch agent asked for (APPL_DB FDB_TABLE: written at runtime) or the configuration (CONFIG_DB)."""
    import shlex
    out = sw.sh("bash -c " + shlex.quote(_BROKEN_FDB_SCRIPT.format(ns=ns_flag(ns))), sudo=True, timeout=300)
    found = []
    for ln in out.splitlines():
        m = re.search(r'"mac":"([0-9A-Fa-f:]{17})"', ln)
        if not m:
            continue
        mac = m.group(1).upper()
        e = {"mac": mac, "vlan": None, "port": None, "type": None, "source": "hardware only"}
        for db, src in (("APPL_DB", "APPL_DB FDB_TABLE - added at runtime"), ("CONFIG_DB", "CONFIG_DB FDB - configured")):
            try:
                keys = [k for k in sw.sh(f"sonic-db-cli{ns_flag(ns)} {db} keys {shlex.quote('FDB*' + mac)}", sudo=True).split()
                        if k.upper().endswith(mac)]
            except Exception:  # noqa: BLE001 - the entry is reported with what could be read
                keys = []
            if keys:
                f = parse_db_kv(sw.sh(f"sonic-db-cli{ns_flag(ns)} {db} hgetall {shlex.quote(keys[0])}", sudo=True))
                vm = re.search(r"Vlan(\d+)", keys[0])
                e |= {"vlan": vm.group(1) if vm else None, "port": f.get("port"), "type": f.get("type"), "source": src}
                break
        found.append(e)
    return found


def parse_db_kv(text: str) -> dict:
    """sonic-db-cli hgetall output ("{'port': 'Ethernet8', 'type': 'static'}") -> dict."""
    import ast
    try:
        v = ast.literal_eval(text.strip() or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, SyntaxError):
        return {}


_VLAN_SCRIPT = (                                   # one command per ASIC: every VLAN, every member with its tagging mode
    "for k in $(sonic-db-cli{ns} CONFIG_DB keys 'VLAN|*'); do echo \"V ${{k#VLAN|}}\"; done; "
    "for k in $(sonic-db-cli{ns} CONFIG_DB keys 'VLAN_MEMBER|*'); do "
    "echo \"M ${{k#VLAN_MEMBER|}} $(sonic-db-cli{ns} CONFIG_DB hget \"$k\" tagging_mode)\"; done")


def read_vlans(sw, ns) -> dict:
    """{'vlans': [Vlan100, ...], 'members': {EthernetN: [[Vlan100, tagging_mode], ...]}} of one ASIC (CONFIG_DB).
    g02-g17 23 Oct: Vlan2 (no members) and Vlan100/200/300, 72 GPU ports each, one VLAN per GPU port number."""
    import shlex
    out = sw.sh("bash -c " + shlex.quote(_VLAN_SCRIPT.format(ns=ns_flag(ns))), sudo=True, timeout=300)
    vlans, members = set(), {}
    for ln in out.splitlines():
        f = ln.split()
        if len(f) >= 2 and f[0] == "V":
            vlans.add(f[1])
        elif len(f) >= 2 and f[0] == "M" and "|" in f[1]:
            v, port = f[1].split("|", 1)
            vlans.add(v)
            members.setdefault(port, []).append([v, f[2] if len(f) > 2 else ""])
    return {"vlans": sorted(vlans, key=lambda v: int(re.sub(r"\D", "", v) or 0)), "members": members}


_FLAP_SCRIPT = (                                   # one command per ASIC: APPL_DB PORT_TABLE of every port (one call each)
    "for k in $(sonic-db-cli{ns} APPL_DB keys 'PORT_TABLE:Ethernet*'); do "
    "echo \"${{k#PORT_TABLE:}}|$(sonic-db-cli{ns} APPL_DB hgetall \"$k\")\"; done")


def read_flaps(sw, ns) -> dict:
    """{EthernetN: (flap_count, last_down_time)} of one ASIC, from APPL_DB PORT_TABLE (portmgrd counts every oper
    down; the same fields Diagnose reads with port_states). A link that works now but went down many times is a
    marginal cable / connector the up/down state alone does not show."""
    out = {}
    for ln in sw.sh(_FLAP_SCRIPT.format(ns=ns_flag(ns)), sudo=True, timeout=300).splitlines():
        port, _, rest = ln.partition("|")
        if not port.strip().startswith("Ethernet"):
            continue
        d = parse_db_kv(rest)
        out[port.strip()] = (num(d.get("flap_count")), str(d.get("last_down_time") or "") or None)
    return out


def read_fdb(sw, ns) -> list[dict]:
    """`show mac` of one ASIC; when SONiC's command fails on entries without a switch port, raise FdbBrokenEntries
    naming them (instead of a bare KeyError line)."""
    try:
        return parse_table(sw.sh(f"show mac{ns_flag(ns)}", sudo=True, timeout=180))
    except Exception as e:  # noqa: BLE001 - only this known failure is explained; anything else propagates
        if "SAI_FDB_ENTRY_ATTR" not in str(e):
            raise
        entries = broken_fdb_entries(sw, ns)
        if not entries:
            raise
        raise FdbBrokenEntries(sw.host.name, ns, entries) from e


# ---------------------------------------------------------------------------------------------- collection

def collect_switch(sw) -> dict:
    """Per ASIC namespace: port state, descriptions, FDB, counters, FEC; whether the platform reports optics."""
    out = {"name": sw.host.name, "asics": {}, "error": None}
    broken = []                                      # FdbBrokenEntries of every ASIC (all are reported, not the first)
    try:
        for ns in sw.namespaces():
            key = ns or ""
            status = {r.get("Interface"): r for r in parse_table(sw.sh(f"show interfaces status{ns_flag(ns)} -d all"))}
            desc = sw.port_descriptions(ns)
            try:
                fdb = read_fdb(sw, ns)
            except FdbBrokenEntries as e:
                broken.append(e)
                continue
            cnt = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters{ns_flag(ns)} -d all", timeout=180))}
            fec = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters fec-stats{ns_flag(ns)}", timeout=180))}
            pres = {r.get("Port"): r.get("Presence", "") for r in
                    parse_table(sw.run(f"show interfaces transceiver presence{ns_flag(ns)}", sudo=True, timeout=180).stdout)}
            try:
                flaps = read_flaps(sw, ns)
            except Exception:  # noqa: BLE001 - flap counts are extra evidence: without them the links are still checked
                flaps = {}
            try:
                vl = read_vlans(sw, ns)
            except Exception as e:  # noqa: BLE001 - VLANs are extra: a failed read is noted, the links are still checked
                vl = {"vlans": [], "members": {}, "error": f"{type(e).__name__}: {str(e)[:160]}"}
            out["asics"][key] = {"status": status, "desc": desc, "fdb": fdb, "counters": cnt, "fec": fec, "presence": pres,
                                 "vlan": vl, "flaps": flaps}
    except Exception as e:  # noqa: BLE001 - an unreachable switch is reported, not fatal
        out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    if broken:                                       # a problem on the switch: named in full, entries kept
        out["fdb_broken"] = [dict(x, ns=e.ns) for e in broken for x in e.entries]
        out["error"] = ("FdbBrokenEntries: " + " | ".join(str(e) for e in broken))[:1500]
        out["asics"] = {}                            # no link of this switch is judged from a partial read
    return out


def sample_counters(sw, asics: list[str]) -> dict:
    out = {}
    for ns in asics:
        n = ns or None
        cnt = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters{ns_flag(n)} -d all", timeout=180))}
        fec = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters fec-stats{ns_flag(n)}", timeout=180))}
        fdb = read_fdb(sw, n)
        out[ns] = {"counters": cnt, "fec": fec, "fdb": fdb}
    return out


def collect_tray(tray) -> dict:
    """Every GPU port of the tray: own MAC, admin, link status, fault, up/down durations, IFCP."""
    out = {"name": tray.host.name, "host": tray.host.host, "slot": (tray.host.extra or {}).get("slot"),
           "gpus": [], "error": None}
    try:
        a = Afmctl(tray)
        accels = a.vpod_accels()
        for d in a.devices():
            ports = []
            for p in a.ports_raw(d.bdf):
                sp, st = p.get("spec") or {}, p.get("status") or {}
                i = st.get("ifcp") or {}
                ports.append({"port": int(p.get("id", p.get("port_id"))), "station": num(sp.get("station_id")),
                              "mac": str(sp.get("nw_mac_addr", "")).lower(), "admin": sp.get("admin_state"),
                              "link": st.get("link_status"), "fault": st.get("fault"),
                              "up_ms": num(st.get("link_up_duration")), "down_ms": num(st.get("link_down_duration")),
                              "fec_mode": sp.get("fec_mode"), "loopback": sp.get("loopback_mode"),
                              "ifcp": {k: i.get(k) for k in ("link_up", "ll_up", "in_error", "peer_enabled",
                                                              "peer_in_error", "peer_device_id", "peer_port_id")}})
            acc, reach = accels.get(d.bdf, ("", set()))
            out["gpus"].append({"bdf": d.bdf, "accelerator": acc, "vpod_accelerators": len(reach),
                                "config_phase": d.config_phase, "ports": sorted(ports, key=lambda x: x["port"])})
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    return out


# ---------------------------------------------------------------------------------------------- joining

@dataclass
class Link:
    switch: str
    asic: str
    sw_port: str
    desc: str = ""
    sw_oper: str | None = None
    sw_admin: str | None = None
    tray: str | None = None
    bdf: str | None = None
    gpu_port: int | None = None
    station: int | None = None
    gpu: dict | None = None             # the tray-side port record
    matched_by: str = ""                # "mac" | "description"
    fdb_static: bool = False
    fdb_static_late: bool | None = None  # the second read of the forwarding table (None = not re-read)
    vpod_accelerators: int | None = None
    bcm: dict | None = None             # Broadcom shell view of the switch port (problem links only)
    bcm_ref: dict | None = None         # the same view of a working port on that ASIC (reference)
    deltas: dict = field(default_factory=dict)
    fec_total: dict = field(default_factory=dict)
    presence: str = ""
    state: str = "ok"                   # ok | degraded | down
    kind: str = ""                      # KINDS key
    cause: str = ""
    evidence: list = field(default_factory=list)
    owner: str = ""
    action: str = ""
    afm_port: str | None = None         # AFM gpu-info port oper-state (with the AFM view)
    vlans: list | None = None           # [[Vlan100, tagging_mode], ...] of the switch port (None = VLANs not read)
    mtu: str | None = None              # switch port MTU ('show interfaces status'; the fabric uses 9100)
    flap_count: int | None = None       # APPL_DB PORT_TABLE flap_count of the switch port (None = not read)
    last_down_time: str | None = None   # APPL_DB PORT_TABLE last_down_time


def join(switches: list[dict], trays: list[dict], quarantined: dict | None = None) -> tuple[list[Link], dict]:
    """One Link per switch port described as cabled to a compute tray, joined to its GPU port. Returns the links and
    what was learned: {tray: slot}, {(tray, desc gpu): bdf}."""
    by_mac = {}
    for t in trays:
        for g in t["gpus"]:
            for p in g["ports"]:
                if p["mac"]:
                    by_mac[p["mac"]] = (t, g, p)
    links, slot_votes, gpu_votes, gpu_map, matched = [], {}, {}, {}, set()
    for s in switches:
        for ns, a in s["asics"].items():
            static = {}
            for r in a["fdb"]:
                if str(r.get("Type", "")).lower() == "static":
                    static.setdefault(r.get("Port"), set()).add(str(r.get("MacAddress", "")).lower())
            for port, desc in a["desc"].items():
                cab = parse_port_description(desc)
                if not cab:
                    continue
                st = a["status"].get(port, {})
                ln = Link(s["name"], ns, port, desc, st.get("Oper"), st.get("Admin"), presence=a["presence"].get(port, ""),
                          mtu=str(st.get("MTU") or "") or None)
                vl = a.get("vlan") or {}
                ln.vlans = None if vl.get("error") or "members" not in vl else vl["members"].get(port, [])
                ln.fdb_static = bool(static.get(port))
                ln.flap_count, ln.last_down_time = (a.get("flaps") or {}).get(port, (None, None))
                hits = [by_mac[mac] for mac in sorted(static.get(port, ())) if mac in by_mac]
                hit = next((h for h in hits if h[2]["port"] == cab[3]), None)
                if hit is None and len(hits) == 1:
                    # the port's one static entry is another GPU port number than its description says: the entry
                    # (the GPU port's own MAC) names the real far end; the description is checked against it below
                    hit = hits[0]
                if hit:
                    t, g, p = hit
                    ln.tray, ln.bdf, ln.gpu_port, ln.station, ln.gpu, ln.matched_by = t["name"], g["bdf"], p["port"], p["station"], p, "mac"
                    matched.add((t["name"], g["bdf"], p["port"]))
                    slot_votes.setdefault(t["name"], {}).setdefault(cab[0], 0)
                    slot_votes[t["name"]][cab[0]] += 1
                    gpu_votes.setdefault((t["name"], g["bdf"]), {}).setdefault(cab[1], 0)
                    gpu_votes[(t["name"], g["bdf"])][cab[1]] += 1
                ln._cab = cab
                links.append(ln)
    slots = {t: max(v, key=v.get) for t, v in slot_votes.items()}
    for t in trays:                                   # inventory slot wins when given
        if t.get("slot") is not None:
            slots[t["name"]] = int(t["slot"])
    # the GPU number each GPU is described with: the majority over its links matched by MAC (one miscabled link, or a
    # swapped pair, is outvoted - it no longer teaches a wrong GPU number to the description fallback)
    gpu_of = {}
    for (tn, bdf), v in gpu_votes.items():
        best = max(v, key=v.get)
        gpu_map[(tn, best)] = bdf
        if v[best] >= 2 and v[best] * 2 > sum(v.values()):
            gpu_of[(tn, bdf)] = best
    mark_described_elsewhere(links, slots, slot_votes, gpu_of, trays)
    by_slot = {v: k for k, v in slots.items()}
    tray_by_name = {t["name"]: t for t in trays}
    for ln in links:                                  # fallback: description + what the healthy links taught
        if ln.tray:
            continue
        slot, dgpu, _, port = ln._cab
        tname = by_slot.get(slot)
        if not tname:
            if quarantined and slot in quarantined:
                ln._quarantined = quarantined[slot]
            continue
        ln.tray = tname
        bdf, how = gpu_map.get((tname, dgpu)), "description"
        t = tray_by_name.get(tname)
        if bdf is None:
            # by elimination: port p exists once per GPU; the copy no switch port claimed by MAC is this one
            left = [g["bdf"] for g in (t or {}).get("gpus", []) for q in g["ports"]
                    if q["port"] == port and (tname, g["bdf"], port) not in matched]
            bdf, how = (left[0], "elimination") if len(left) == 1 else (None, how)
        g = next((g for g in (t or {}).get("gpus", []) if g["bdf"] == bdf), None)
        p = next((p for p in (g or {}).get("ports", []) if p["port"] == port), None)
        if p:
            ln.bdf, ln.gpu_port, ln.station, ln.gpu, ln.matched_by = bdf, port, p["station"], p, how
            matched.add((tname, bdf, port))
    return links, {"slots": slots, "gpu_map": {f"{k[0]}:GPU{k[1]}": v for k, v in gpu_map.items()}}


def mark_described_elsewhere(links: list[Link], slots: dict, slot_votes: dict, gpu_of: dict, trays: list[dict]) -> int:
    """A link matched by the GPU port's own MAC whose description names another tray slot, GPU or GPU port than the
    one the MAC belongs to: the cable is not where the cabling plan (the descriptions) says - or the description is
    wrong. Sets ln._desc_off = ((slot, gpu, port) real, partner link described as reaching it or None).
    The accelerator number in the description is NOT compared: on g02-g17 it is a naming convention of its own (AFM
    acc 0 described as acc 3, ...), and an acc off by one alone is no cabling fault. A tray's slot counts only when
    the inventory gives it or a clear majority of its links agree, a GPU number only by a clear majority (gpu_of).
    When more than a quarter of the matched links (and more than 8) disagree, it is a numbering convention of the rack,
    not cabling: nothing is marked. Returns how many links were marked."""
    inv_slot = {t["name"] for t in trays if t.get("slot") is not None}
    sure_slot = {t for t, v in slot_votes.items() if t in inv_slot or (v[slots[t]] >= 2 and v[slots[t]] * 2 > sum(v.values()))}
    sure_slot |= inv_slot
    by_desc = {(x._cab[0], x._cab[1], x._cab[3]): x for x in links if getattr(x, "_cab", None)}
    off = []
    for ln in links:
        if ln.matched_by != "mac" or not getattr(ln, "_cab", None):
            continue
        d = ln._cab
        real = (slots.get(ln.tray) if ln.tray in sure_slot else d[0], gpu_of.get((ln.tray, ln.bdf), d[1]), ln.gpu_port)
        if real != (d[0], d[1], d[3]):
            off.append((ln, real))
    if len(off) > max(8, sum(1 for x in links if x.matched_by == "mac") // 4):
        return 0
    for ln, real in off:
        partner = by_desc.get(real)
        ln._desc_off = (real, partner if partner is not ln else None)
    return len(off)


# ---------------------------------------------------------------------------------------------- diagnosis

def _dur(ms) -> str:
    if ms is None:
        return "?"
    s = ms / 1000
    return f"{s / 86400:.1f} d" if s >= 86400 else f"{s / 3600:.1f} h" if s >= 3600 else f"{s / 60:.0f} min" if s >= 60 else f"{s:.0f} s"


def learn_ifcp(links: list[Link]) -> dict:
    """How IFCP names the peer: {switch: device id} by majority over links matched by MAC, and whether peer_port_id
    is the EthernetN number (>= 90 % of those links). g02-g17: device id = switch number, port id = EthernetN."""
    votes, same, total = {}, 0, 0
    for ln in links:
        i = (ln.gpu or {}).get("ifcp") or {}
        if ln.matched_by != "mac" or i.get("peer_device_id") in (None, ""):
            continue
        votes.setdefault(ln.switch, {}).setdefault(str(i["peer_device_id"]), 0)
        votes[ln.switch][str(i["peer_device_id"])] += 1
        m = re.fullmatch(r"Ethernet(\d+)", ln.sw_port)
        total += 1
        same += bool(m and str(i.get("peer_port_id")) == m.group(1))
    dev = {sw: max(v, key=v.get) for sw, v in votes.items()}
    return {"device": dev, "port_is_ethernet": bool(total) and same / total >= 0.9, "checked_links": total}


def ifcp_peer_problem(ln: Link, ifcp_map: dict) -> str | None:
    """None when the GPU port's IFCP peer is this link's switch port (or cannot be judged), else what it reaches."""
    i = (ln.gpu or {}).get("ifcp") or {}
    dev, pid = i.get("peer_device_id"), i.get("peer_port_id")
    if dev in (None, "") or not ifcp_map.get("device"):
        return None
    by_dev = {v: k for k, v in ifcp_map["device"].items()}
    peer_sw = by_dev.get(str(dev))
    wrong_sw = peer_sw is not None and peer_sw != ln.switch
    wrong_port = ifcp_map.get("port_is_ethernet") and f"Ethernet{pid}" != ln.sw_port
    if wrong_sw or wrong_port:
        return f"IFCP peer is {peer_sw or 'device ' + str(dev)} Ethernet{pid}" if ifcp_map.get("port_is_ethernet") \
            else f"IFCP peer is {peer_sw or 'device ' + str(dev)} port {pid}"
    return None


def ifcp_running(trays: dict) -> bool:
    """False when not a single LINK_UP GPU port of the rack has an IFCP session or knows a peer: IFCP is not running
    on this rack (MR2 18 Oct: 288 links, every one ll_up no / no peer, yet the L2 ping passed on every port), so it
    is reported once for the rack instead of as 288 degraded links. One port with a session = IFCP is in use and
    every port without one is a problem (g02-g17: 2 of 2,445)."""
    seen = False
    for t in trays.values():
        for g in t.get("gpus") or []:
            for p in g.get("ports") or []:
                if "LINK_UP" not in str(p.get("link") or "") or "NO_PHY" in str(p.get("link") or ""):
                    continue
                seen = True
                i = p.get("ifcp") or {}
                if i.get("ll_up") == "yes" or i.get("peer_enabled") not in (None, "", "None") \
                        or i.get("peer_device_id") not in (None, ""):
                    return True
    return not seen


def diagnose(ln: Link, trays: dict, optics_reported: bool, interval_s: float, ifcp_map: dict | None = None,
             ifcp_in_use: bool = True) -> Link:
    """Set state / cause / evidence / owner / action. First matching rule wins (bottom layer first)."""
    up = lambda v: str(v or "").lower() == "up"  # noqa: E731
    g, ev = ln.gpu, ln.evidence
    ev.append(f"switch {ln.switch} {ln.asic or ''} {ln.sw_port}: admin {ln.sw_admin}, oper {ln.sw_oper}"
              + (f", MTU {ln.mtu}" if ln.mtu else "")
              + (f", flap count {ln.flap_count}" + (f", last down {ln.last_down_time}" if ln.last_down_time else "")
                 if ln.flap_count is not None else "") + f"; described as '{ln.desc}'")
    t = trays.get(ln.tray) if ln.tray else None
    if g:
        ev.append(f"GPU {ln.tray} {ln.bdf} port {ln.gpu_port}: admin {g['admin']}, link {g['link']}, fault {g['fault']}, "
                  f"up {_dur(g['up_ms'])} / down {_dur(g['down_ms'])} since boot; IFCP ll_up {g['ifcp'].get('ll_up')}, "
                  f"peer_enabled {g['ifcp'].get('peer_enabled')}")

    def set_(state, kind, cause, owner, action):
        ln.state, ln.kind, ln.cause, ln.owner, ln.action = state, kind, cause, owner, action
        return ln

    if t is not None and t.get("error"):
        if re.search(r"authenticat|permission denied", t["error"], re.I):    # MR2 19 Oct, from the switch: key not yet on the trays
            return set_("down", "tray_unreachable", f"compute tray {ln.tray}: login refused (this machine's SSH key is not "
                        f"installed there)", OPERATOR, "Install the key on the tray (debug UI: SSH access tab - Check all, "
                        "the tray's password, Install key; or ssh-copy-id) and scan again. The links themselves are not judged.")
        acc = reach.classify(t["error"])
        if acc and acc["kind"] in ("host_key", "sudo", "dns", "jump_session"):   # an access problem, not the tray
            return set_("down", "tray_unreachable", f"compute tray {ln.tray}: {acc['what']}", OPERATOR,
                        acc["next"][:1].upper() + acc["next"][1:] + ". The links themselves are not judged.")
        if up(ln.sw_oper):              # g02-g17 3 Nov: ct10 'site (cabling)' while st5 read all 24 of its ports up
            return set_("down", "tray_unreachable", f"compute tray {ln.tray} not reachable over SSH"
                        + (f" ({acc['what']})" if acc else "") + " - its switch ports are up, so it is powered and cabled",
                        OPERATOR, "Find why it does not answer from here: its management network / route, or its OS (the "
                        "BMC console shows which). Every link of the tray is affected (one root cause); the links themselves "
                        "are not judged.")
        return set_("down", "tray_unreachable", f"compute tray {ln.tray} not reachable over SSH"
                    + (f" ({acc['what']})" if acc else ""), SITE,
                    "Check the tray's power and BMC; every link of the tray is affected (one root cause).")
    if not ln.tray and getattr(ln, "_quarantined", None):
        name, reason = ln._quarantined
        return set_("down" if not up(ln.sw_oper) else "degraded", "tray_quarantined",
                    f"compute tray {name} is quarantined in the inventory ({reason})", OPERATOR,
                    (f"The quarantine's end date has passed: if {name} is still out of service, set a new 'until:' in the "
                     f"inventory; if it is back, remove the quarantine and scan again." if "quarantine ended" in reason else
                     f"Expected while {name} is out of service; lift the quarantine when it is back and scan again."))
    unread = sorted(n for n, x in (trays or {}).items() if x.get("error"))
    if not ln.tray and unread:          # MR3 19 Oct from the switch: trays in the inventory, but not reachable from there
        cab = parse_port_description(ln.desc or "")
        return set_("down", "tray_unreachable",
                    f"slot {cab[0] if cab else '?'}: its tray did not answer - not reachable: {', '.join(unread)}", SITE,
                    "Make the tray reachable from where this runs (network / SSH key; from a switch tray: its route to the "
                    "trays), or set slot: on the inventory entries so an unreachable tray is named per slot.")
    if not ln.tray:
        return set_("down" if not up(ln.sw_oper) else "degraded", "tray_missing",
                    "no compute tray in the inventory answers for this switch port's slot", OPERATOR,
                    "Add the tray to the inventory, or check that it is powered and reachable.")
    if not g:
        return set_("down" if not up(ln.sw_oper) else "degraded", "gpu_missing",
                    f"GPU port not found on {ln.tray} (GPU not listed by afmctl, or numbering not learned)", GPU_VENDOR,
                    "Check `afmctl show device` on the tray: every GPU should be listed and ACTIVE.")
    if str(ln.sw_admin or "").lower() != "up":
        return set_("down", "sw_admin_down", "switch port administratively down", OPERATOR,
                    f"Bring it up: sudo config interface{ns_flag(ln.asic)} startup {ln.sw_port}")
    if str(g["admin"] or "").lower() != "enabled":
        st = (g["station"] if g["station"] is not None else ln.gpu_port // 2)
        return set_("down", "gpu_admin", f"GPU port admin state is '{g['admin']}'", OPERATOR,
                    f"Enable it: sudo env AFMCTL_FORCE_UPDATE=1 afmctl update port -b {ln.bdf} -s {st} -p {ln.gpu_port} --admin-state enable")
    gpu_up = "LINK_UP" in str(g["link"] or "") and "NO_PHY" not in str(g["link"] or "")
    if not up(ln.sw_oper) and not gpu_up:
        never = g["up_ms"] == 0
        what = "never came up since the tray booted" if never else f"was up, down for the last {_dur(g['down_ms'])}"
        if optics_reported and str(ln.presence).lower().startswith("not"):
            return set_("down", "phys_no_optic", f"no physical link: no transceiver / cable detected in {ln.switch} {ln.sw_port}", SITE,
                        "Seat or replace the cable / optic in the switch port.")
        return set_("down", "phys_never_up" if never else "phys_went_down", f"no physical link on either end ({g['link']}); {what}",
                    SITE,
                    "Reseat or swap the cable / cartridge between the two ports; if the fault stays on the port after a swap, "
                    "that port's side (switch or tray) owns it." + ("" if optics_reported else
                    " (This switch platform reports no transceiver presence or optic power, so a cable fault cannot be told "
                    "from a port fault remotely.)"))
    if up(ln.sw_oper) != gpu_up:
        return set_("down", "one_sided", f"one-sided link: switch port {'up' if up(ln.sw_oper) else 'down'}, GPU port {g['link']}",
                    SITE, "The two ends disagree: verify the cable lands where the switch port description says "
                          "(the IFCP peer of the GPU port names the switch port it really reaches).")
    wrong = ifcp_peer_problem(ln, ifcp_map or {})
    if wrong:
        return set_("degraded", "miscabled", f"{wrong}, but this link is {ln.switch} {ln.sw_port} by the forwarding table / "
                                             f"description ('{ln.desc}')", SITE,
                    "Trace the cable: either it is in another switch port than the description says, or the description "
                    "is wrong. Fix the cabling (or the description) so both agree.")
    off = getattr(ln, "_desc_off", None)
    if off:
        (slot, gpu, port), partner = off
        d = ln._cab
        i = g.get("ifcp") or {}
        seen = ("the GPU port's own MAC in the port's forwarding entry" +
                (", and its IFCP peer is this switch port" if ifcp_map and ifcp_map.get("port_is_ethernet") and
                 str(i.get("peer_port_id")) == ln.sw_port[8:] and i.get("peer_device_id") not in (None, "") else ""))
        ev.append(f"described as Slot{d[0]}/GPU{d[1]}/Port{d[3]}; the cable reaches slot {slot} GPU{gpu} port {port} "
                  f"({ln.tray} {ln.bdf}) by {seen}")
        return set_("degraded", "miscabled",
                    f"the description says Slot{d[0]}/GPU{d[1]}/Port{d[3]} ('{ln.desc}'), but the cable reaches {ln.tray} "
                    f"(slot {slot}) GPU{gpu} {ln.bdf} port {port} - by {seen}"
                    + (f"; {partner.switch} {partner.sw_port} is the port described as reaching it" if partner else ""),
                    SITE, "The cable is not where the cabling plan (the port descriptions) says: re-cable it to the plan "
                          "(the ports described as reaching each other" + (f": {ln.sw_port} and {partner.sw_port}" if partner else "")
                          + "), or, if the plan is what is wrong, correct the descriptions. Check with Cabling plan.")
    fec_bad = ln.deltas.get("FEC_UNCORR", 0) > 0
    err_bad = any(ln.deltas.get(k, 0) > 0 for k in ("RX_ERR",))
    if fec_bad or err_bad:
        grow = ", ".join(f"{k} +{v}" for k, v in ln.deltas.items() if v)
        return set_("degraded", "bit_errors", f"bit errors on a link that is up ({grow} in {interval_s:.0f} s)",
                    SITE,
                    "Marginal cable / connector: reseat it, then sample again; if the errors follow the cable after a swap, "
                    "replace the cable.")
    i = g["ifcp"]
    if not ifcp_in_use:
        ev.append("IFCP not judged: no GPU port on this rack has an IFCP session or peer (not running here)")
    elif i.get("ll_up") != "yes" or i.get("peer_enabled") != "yes" or "yes" in (i.get("in_error"), i.get("peer_in_error")):
        return set_("degraded", "ifcp", f"physical link up but no IFCP session (ll_up {i.get('ll_up')}, peer_enabled "
                                f"{i.get('peer_enabled')}, in_error {i.get('in_error')}, peer_in_error {i.get('peer_in_error')})",
                    GPU_VENDOR, "Collect `afmctl show port -b <bdf> --json` from the tray and the switch's forwarding entries "
                                "for this port, and raise it with the GPU / AFM vendor.")
    if not ln.fdb_static and ln.fdb_static_late:
        ev.append("no static forwarding entry at the first read, present at the second: a vPOD change was in progress")
        return set_("ok", "", "", "", "")
    if not ln.fdb_static and ln.vpod_accelerators == 0:
        ev.append("afmctl lists no vPOD accelerators for this GPU")
        return set_("ok", "", "", "", "")
    if not ln.fdb_static:
        return set_("degraded", "not_programmed", "link and IFCP up but the switch port has no static forwarding entry (not programmed by AFM)",
                    GPU_VENDOR, "Check the GPU is in a vPOD and AFM shows the port PortReady; raise it with the AFM vendor.")
    return set_("ok", "", "", "", "")


FDB_RETRIES, FDB_RETRY_S = 3, 10.0

# kinds where the switch ASIC's own view of the lanes says which side / layer fails
BCM_KINDS = ("phys_never_up", "phys_went_down", "one_sided", "bit_errors")


def add_bcm(rack, links: list, sw_res: dict, log=print, limit: int = 64, force: set | None = None) -> None:
    """Broadcom shell evidence for physical-layer problem links (at most ``limit`` ports, read-only): per lane
    signal detect / lock / SNR, and a sharper cause. Skipped quietly where bcmcmd is missing."""
    from . import bcm
    todo: dict = {}
    for ln in links:
        if (ln.kind in BCM_KINDS or (ln.switch, ln.sw_port) in (force or ())) and sum(len(v) for v in todo.values()) < limit:
            todo.setdefault((ln.switch, ln.asic), []).append(ln)
    if not todo:
        return
    log(f"reading the Broadcom shell for {sum(len(v) for v in todo.values())} problem link(s) ...")
    by_sw: dict = {}
    for (swn, asic), lns in todo.items():
        by_sw.setdefault(swn, []).append((asic, lns))

    def one(swn):
        sw, res = rack.switches[swn], {}
        for asic, lns in by_sw[swn]:
            status = (sw_res[swn]["asics"].get(asic) or {}).get("status", {})
            ports = {ln.sw_port: (status.get(ln.sw_port) or {}).get("Lanes", "") for ln in lns}
            ref = bcm.reference_port(status, set(ports))
            if ref:
                ports[ref[0]] = ref[1]
            res[asic] = bcm.read_ports(sw, asic or None, ports)
            res[asic]["__ref__"] = res[asic].get(ref[0]) if ref else None
        return res
    for swn, val, exc in fan_out(one, list(by_sw)):
        for asic, lns in by_sw[swn]:
            for ln in lns:
                v = (val or {}).get(asic, {}).get(ln.sw_port) if not exc else {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}
                ln.bcm = {k: x for k, x in (v or {}).items() if k != "raw"} or None
                ref = (val or {}).get(asic, {}).get("__ref__") if not exc else None
                ln.bcm_ref = {k: x for k, x in (ref or {}).items() if k != "raw"} or None
                finding, ev = bcm.judge(v or {}, ref, oper_down=str(ln.sw_oper or "").lower() != "up")
                ln.evidence += ev
                if finding:
                    ln.cause += f"; switch ASIC: {finding}"
                    if ln.kind in ("phys_never_up", "phys_went_down") and "receives no signal on any" in finding \
                            and "transmitter is on" in finding:
                        ln.cause += (" - and the GPU sees no link either, so neither direction gets through: the cable / "
                                     "connector / cartridge between them (or a GPU port whose transmitter and receiver "
                                     "both fail), not the switch port's transmitter")


def quarantined_slots(inv) -> dict:
    """{slot: (tray name, reason)} for compute trays quarantined in the inventory (with a ``slot:``)."""
    out = {}
    for h in getattr(inv, "quarantined", []) or []:
        slot = (h.extra or {}).get("slot")
        if h.role == "compute" and str(slot).lstrip("-").isdigit():
            q = h.quarantine or {}
            reason = q.get("reason") or "out of service"
            if q.get("until") and str(q["until"])[:10] < __import__("datetime").date.today().isoformat():
                reason += f"; the quarantine ended {str(q['until'])[:10]} - still in force until the inventory changes"
            out[int(slot)] = (h.name, reason)
    return out


def mark_unprogrammed_trays(links: list, trays: dict) -> list[str]:
    """A tray that was read, whose GPU ports appear in NO switch forwarding table while other trays' do: its switch ports
    cannot be paired with GPU ports by MAC, and the reason is that AFM has not programmed it - not missing GPUs.
    MR3 19 Oct 09:09: c2's 144 static entries gone from st1, its GPU port MACs changed to 00:1f:0e:..; the scan had said
    'GPU port not found' 144 times."""
    by_tray: dict = {}
    for ln in links:
        if ln.tray:
            by_tray.setdefault(ln.tray, []).append(ln)
    matched = {t for t, ls in by_tray.items() if any(x.matched_by == "mac" for x in ls)}
    out = []
    for t, ls in by_tray.items():
        tr = trays.get(t) or {}
        if t in matched or tr.get("error") or not tr.get("gpus") or not matched:
            continue
        out.append(t)
        for ln in ls:
            if ln.kind in ("gpu_missing", ""):
                ln.state = "down" if str(ln.sw_oper or "").lower() != "up" else "degraded"
                ln.kind, ln.owner = "tray_not_programmed", OPERATOR
                ln.cause = (f"the switch has no forwarding entry for any GPU port of {t} (other trays have theirs): AFM is not "
                            f"programming {t} - its GPUs in no vPOD, or a reconfigure / reset not finished")
                ln.action = (f"Check {t} in AFM (vPOD membership, admission, a pending reconfigure) and reconfigure the tray from "
                             "AFM if its GPUs should be in use; then check again.")
    return out


def afm_pairs(trays: dict, slots: dict, afm_nodes: list[dict], inv_afm_names: dict) -> tuple[dict, dict]:
    """Pair tray GPUs with AFM GPUs. Trays -> ComputeNodes by inventory afm_name, else slot (learned from the switch
    port descriptions, = AFM spec.slot-id). GPUs within a pair by accelerator id = AFM acc-id; one GPU left over on
    each side is paired by elimination (MR3 19 Oct: a reset GPU came back accelerator 0 while AFM still had 7).
    Returns ({(tray, bdf): (node name, AFM gpu record)}, {tray: node name})."""
    by_name = {n["meta"]["name"]: n for n in afm_nodes}
    by_slot = {(n.get("spec") or {}).get("slot-id"): n for n in afm_nodes}
    node_of, out = {}, {}
    for t in trays.values():
        n = by_name.get(inv_afm_names.get(t["name"]) or "") or by_slot.get(slots.get(t["name"]))
        if not n or t.get("error"):
            continue
        node_of[t["name"]] = n["meta"]["name"]
        afm_gpus = list((((n.get("status") or {}).get("scale-up-info") or {}).get("gpu-info") or {}).values())
        left = list(afm_gpus)
        rest = []
        for g in t["gpus"]:
            m = next((a for a in left if str(a.get("acc-id")) == str(g.get("accelerator"))), None)
            if m is not None:
                left.remove(m)
                out[(t["name"], g["bdf"])] = (n["meta"]["name"], m)
            else:
                rest.append(g)
        if len(rest) == 1 and len(left) == 1:
            out[(t["name"], rest[0]["bdf"])] = (n["meta"]["name"], left[0] | {"_paired": "elimination"})
    return out, node_of


def check_gpus(trays: dict, links: list[Link], pairs: dict | None) -> list[dict]:
    """GPU-level state (not per link): a GPU whose afmctl config_phase is not ACTIVE. Without the AFM view it is
    flagged only when other GPUs of the rack are ACTIVE (PROVIDER also means "in no vPOD"); with it, when AFM has the
    GPU in a vPOD or AFM's accelerator id differs. The GPU's links that are otherwise ok become degraded with it.
    Returns [{tray, bdf, accelerator, phase, kind, cause, action, afm}]."""
    gpus = [(t["name"], g) for t in trays.values() if not t.get("error") for g in t["gpus"]]
    any_active = any(str(g.get("config_phase")).upper() == "ACTIVE" for _t, g in gpus)
    found = []
    for tname, g in gpus:
        phase, acc = str(g.get("config_phase") or ""), str(g.get("accelerator") or "")
        node, a = (pairs or {}).get((tname, g["bdf"]), (None, None))
        f = None
        if pairs is not None and a is not None:
            in_vpod = a.get("vpod-membership") or ""
            if phase.upper() != "ACTIVE" and in_vpod:
                f = ("down", "gpu_not_programmed",
                     f"AFM has {node} GPU {a.get('index')} (accelerator {a.get('acc-id')}) in vPOD {in_vpod}, but the tray "
                     f"reports it {phase or '?'} with accelerator {acc or '?'} - not programmed (e.g. after a GPU reset)")
            elif acc != str(a.get("acc-id")) and phase.upper() == "ACTIVE":
                f = ("degraded", "gpu_not_programmed",
                     f"tray accelerator {acc} differs from AFM's {a.get('acc-id')} for {node} GPU {a.get('index')}")
        elif phase.upper() != "ACTIVE" and any_active:
            f = ("degraded", "gpu_not_active",
                 f"config_phase {phase or '?'} (accelerator {acc or '?'}) while other GPUs of the rack are ACTIVE - in no "
                 f"vPOD, or a GPU reset that was not re-programmed (add the AFM view to tell which)")
        if not f:
            continue
        state, kind, cause = f
        action = (f"Reconfigure the compute tray from AFM (POST .../computenodes/{node}/Reconfigure, or the AFM UI) and "
                  f"check `afmctl show device` shows the GPU ACTIVE again; raise it with the AFM vendor if a GPU reset "
                  f"leaves it unprogrammed." if node else
                  "Check the GPU's vPOD membership in AFM; reconfigure the tray from AFM if it should be in one.")
        found.append({"tray": tname, "bdf": g["bdf"], "accelerator": acc, "phase": phase, "state": state, "kind": kind,
                      "cause": cause, "action": action, "afm": {"node": node, "index": (a or {}).get("index"),
                                                               "acc_id": (a or {}).get("acc-id"),
                                                               "vpod": (a or {}).get("vpod-membership")} if a else None})
        for ln in links:
            if ln.tray == tname and ln.bdf == g["bdf"]:
                ln.evidence.append(f"GPU {g['bdf']}: {cause}")
                if ln.state == "ok":
                    ln.state, ln.kind, ln.cause, ln.owner, ln.action = state, kind, cause, GPU_VENDOR, action
    return found


def check_afm_ports(links: list[Link], pairs: dict) -> None:
    """With the AFM view: AFM's port oper-state against the real link. PortFailed / PortDown on a link that is up
    with IFCP (or IFCP not in use) -> afm_port_failed; PortReady on a link that is down -> afm_port_stale."""
    for ln in links:
        _node, a = pairs.get((ln.tray, ln.bdf), (None, None))
        if a is None or ln.gpu_port is None:
            continue
        ports = a.get("ports") or []
        p = next((x for x in ports if x.get("id") == ln.gpu_port), None)
        if p is None and 0 <= ln.gpu_port < len(ports) and "id" not in ports[ln.gpu_port]:
            p = ports[ln.gpu_port]
        if p is None:
            continue
        ln.afm_port = p.get("oper-state")
        if ln.state == "ok" and ln.afm_port not in ("PortReady", "PortDisabled", None):
            ln.state, ln.kind, ln.owner = "degraded", "afm_port_failed", GPU_VENDOR
            ln.cause = f"AFM reports {ln.tray} {ln.bdf} port {ln.gpu_port} {ln.afm_port} although the link and IFCP are up"
            ln.action = ("Compare with the AFM events for this port (link_failed / ifoe_netport_*); if the link stays up, "
                         "raise it with the AFM vendor (AFM state not following the link).")
        elif ln.state == "down" and ln.afm_port == "PortReady":
            ln.evidence.append(f"AFM still reports the GPU port PortReady (link down for {ln.kind})")
            if ln.kind in ("phys_never_up", "phys_went_down", "one_sided", "sw_admin_down", "gpu_admin"):
                ln.cause += "; AFM still reports the port PortReady"


def scan(rack, interval_s: float = 30.0, log=print, bcm_view: bool = True, bcm_max: int = 64,
         afm_cfg: dict | None = None) -> dict:
    t0 = time.monotonic()
    log(f"reading {len(rack.switches)} switches and {len(rack.computes)} compute trays ...")
    sw_res, tr_res = {}, {}
    for sw, val, exc in fan_out(collect_switch, list(rack.switches.values())):
        sw_res[sw.host.name] = val if not exc else {"name": sw.host.name, "asics": {}, "error": str(exc)}
    # an empty forwarding table (AFM reprogramming at that moment: MR2 19 Oct 01:18, back 30 s later) leaves every
    # port unmatched - read it again a few times before joining
    for _ in range(int(FDB_RETRIES)):
        empty = [n for n, v in sw_res.items() if not v.get("error") and v["asics"]
                 and not any(r for a in v["asics"].values() for r in a["fdb"] if str(r.get("Type", "")).lower() == "static")]
        if not empty:
            break
        log(f"forwarding table empty on {', '.join(empty)} - reading it again in {FDB_RETRY_S:.0f} s ...")
        time.sleep(FDB_RETRY_S)
        for n in empty:
            sw = rack.switches[n]
            for ns in list(sw_res[n]["asics"]):
                try:
                    sw_res[n]["asics"][ns]["fdb"] = read_fdb(sw, ns or None)
                except Exception:  # noqa: BLE001 - keep what we have
                    pass
    fdb_empty = {n for n, v in sw_res.items() if not v.get("error") and v["asics"]
                 and not any(r for a in v["asics"].values() for r in a["fdb"] if str(r.get("Type", "")).lower() == "static")}
    for tr, val, exc in fan_out(collect_tray, list(rack.computes.values())):
        tr_res[tr.host.name] = val if not exc else {"name": tr.host.name, "gpus": [], "error": str(exc), "slot": None}
    links, learned = join(list(sw_res.values()), list(tr_res.values()), quarantined_slots(rack.inv))
    # second counter sample: errors are judged by what grows, not by totals since boot
    wait = max(0.0, interval_s - (time.monotonic() - t0))
    log(f"sampling counters again in {wait:.0f} s ...")
    time.sleep(wait)
    t1 = time.monotonic()
    again = {}
    for sw, val, exc in fan_out(lambda s: sample_counters(s, list(sw_res[s.host.name]["asics"])),
                                [s for s in rack.switches.values() if not sw_res[s.host.name].get("error")]):
        if not exc:
            again[sw.host.name] = val
            continue
        try:                                          # once more: without it no error counter of this switch is judged
            again[sw.host.name] = sample_counters(sw, list(sw_res[sw.host.name]["asics"]))
        except Exception as e:  # noqa: BLE001 - said in the report (not checked), not 'all links ok'
            sw_res[sw.host.name]["resample_error"] = f"{type(e).__name__}: {str(e)[:200]}"
            log(f"  {sw.host.name}: second counter sample failed - its error counters are not judged")
    span = interval_s if interval_s else (time.monotonic() - t1)
    optics = {}
    for name, s in sw_res.items():
        vals = [v for a in s["asics"].values() for v in a["presence"].values()]
        optics[name] = bool(vals) and any(str(v).lower() == "present" for v in vals)
    ifcp_map = learn_ifcp(links)
    ifcp_in_use = ifcp_running(tr_res)
    for ln in links:
        a0 = sw_res[ln.switch]["asics"].get(ln.asic, {})
        a1 = (again.get(ln.switch) or {}).get(ln.asic, {})
        for k in COUNTERS:
            b, e = num((a0.get("counters", {}).get(ln.sw_port) or {}).get(k)), num((a1.get("counters", {}).get(ln.sw_port) or {}).get(k))
            if b is not None and e is not None and e > b:
                ln.deltas[k] = e - b
        for k in FEC:
            b, e = num((a0.get("fec", {}).get(ln.sw_port) or {}).get(k)), num((a1.get("fec", {}).get(ln.sw_port) or {}).get(k))
            ln.fec_total[k] = e
            if b is not None and e is not None and e > b:
                ln.deltas[k] = e - b
        if a1.get("fdb") is not None:
            ln.fdb_static_late = any(r.get("Port") == ln.sw_port and str(r.get("Type", "")).lower() == "static" for r in a1["fdb"])
        t = tr_res.get(ln.tray) or {}
        ln.vpod_accelerators = next((g.get("vpod_accelerators") for g in t.get("gpus", []) if g["bdf"] == ln.bdf), None)
        diagnose(ln, tr_res, optics.get(ln.switch, False), span, ifcp_map, ifcp_in_use)
    learned["ifcp"] = ifcp_map
    learned["ifcp_in_use"] = ifcp_in_use
    for ln in links:
        if ln.kind == "tray_missing" and ln.switch in fdb_empty:
            ln.kind, ln.state, ln.owner = "fdb_empty", "degraded", OPERATOR
            ln.cause = (f"{ln.switch} had no static forwarding entry when read (AFM reprogramming, or no vPOD), so this switch "
                        f"port could not be matched to a GPU port")
            ln.action = ("Scan again in a minute; or set slot: for every compute tray in the inventory, so ports are matched "
                         "by their description even without forwarding entries.")
    learned["fdb_empty_switches"] = sorted(fdb_empty)
    mark_unprogrammed_trays(links, tr_res)
    afm_view, pairs = {"checked": False, "reason": "not asked for"}, None
    if afm_cfg is not None:
        from .afm import Afm, AfmUnavailable
        try:
            nodes = Afm(afm_cfg).computes()
            names = {h.name: (h.extra or {}).get("afm_name") for h in rack.inv.computes if (h.extra or {}).get("afm_name")}
            pairs, node_of = afm_pairs(tr_res, learned.get("slots") or {}, nodes, names)
            check_afm_ports(links, pairs)
            afm_view = {"checked": True, "nodes": len(nodes), "trays_paired": node_of,
                        "gpus_paired": len(pairs), "by_elimination": sum(1 for _n, a in pairs.values() if a.get("_paired"))}
            log(f"AFM view: {len(nodes)} compute nodes, {len(pairs)} GPUs paired with the trays")
        except AfmUnavailable as e:
            afm_view = {"checked": False, "reason": str(e)}
            log(f"AFM view not checked: {e}")
        except Exception as e:  # noqa: BLE001 - the switch / tray scan stands without it
            afm_view = {"checked": False, "reason": f"{type(e).__name__}: {str(e)[:160]}"}
            log(f"AFM view not checked: {afm_view['reason']}")
    learned["afm_view"] = afm_view
    gpu_findings = check_gpus(tr_res, links, pairs)
    if bcm_view:
        add_bcm(rack, links, sw_res, log, bcm_max)
    learned["vlans"] = {f"{s['name']} {ns}".strip(): {"vlans": (a.get("vlan") or {}).get("vlans") or [],
                                                      "error": (a.get("vlan") or {}).get("error")}
                        for s in sw_res.values() for ns, a in s["asics"].items()}
    return {"switches": sw_res, "trays": tr_res, "links": links, "learned": learned, "optics_reported": optics,
            "vlan_findings": vlan_findings(list(sw_res.values()), links),
            "interval_s": span, "gpus": gpu_findings}


def group_causes(links: list[Link]) -> list[dict]:
    """Problem links grouped by root-cause kind (and owner), down before degraded, most links first: a powered-off
    or quarantined tray is one line, not 144."""
    groups = {}
    for ln in links:
        if ln.state == "ok":
            continue
        tray = ln.tray if ln.kind == "tray_unreachable" else \
            (ln._quarantined[0] if ln.kind == "tray_quarantined" and getattr(ln, "_quarantined", None) else "")
        key = (ln.state, ln.kind, ln.owner, tray)
        groups.setdefault(key, []).append(ln)
    out = []
    for (state, kind, owner, tray), v in groups.items():
        label = KINDS.get(kind, kind)
        if tray:
            label = f"{label}: {tray}"
        out.append({"state": state, "kind": kind, "cause": label, "owner": owner, "count": len(v), "links": v})
    return sorted(out, key=lambda g: (g["state"] != "down", -g["count"]))


def vlan_findings(switches: list[dict], links: list[Link]) -> list[dict]:
    """VLAN problems, each {kind, switch, asic, port, vlan, detail}:
    not_in_vlan     a GPU-facing switch port that is in no VLAN (its traffic has nowhere to go)
    vlan_mismatch   a port whose VLAN / tagging differs from what the same ASIC uses for the same GPU port number on the
                    other GPUs (g02-g17: one VLAN per GPU port number per ASIC, all priority_tagged)
    fdb_off_vlan    a static forwarding entry on a VLAN its port is not a member of
    vlan_set        an ASIC whose VLANs (with members) differ from the rack's other ASICs"""
    out, sets = [], {}
    by_chip: dict = {}
    for ln in links:
        if ln.vlans is None:
            continue
        if not ln.vlans:
            out.append({"kind": "not_in_vlan", "switch": ln.switch, "asic": ln.asic, "port": ln.sw_port, "vlan": None,
                        "detail": f"GPU-facing port ({ln.desc}) is in no VLAN"})
        cab = getattr(ln, "_cab", None)
        if cab and ln.vlans:
            by_chip.setdefault((ln.switch, ln.asic, cab[3]), []).append(ln)
    for (sw, asic, gport), ls in by_chip.items():
        votes: dict = {}
        for ln in ls:
            k = tuple(map(tuple, sorted(ln.vlans)))
            votes[k] = votes.get(k, 0) + 1
        if len(votes) < 2:
            continue
        want = max(votes, key=votes.get)
        for ln in ls:
            if tuple(map(tuple, sorted(ln.vlans))) != want:
                out.append({"kind": "vlan_mismatch", "switch": sw, "asic": asic, "port": ln.sw_port,
                            "vlan": ",".join(v for v, _m in ln.vlans),
                            "detail": f"{ln.sw_port} (GPU port {gport}) is in {_vl(ln.vlans)}; the other {votes[want]} GPUs' "
                                      f"port {gport} on {sw} {asic} are in {_vl([list(x) for x in want])}"})
    for s in switches:
        for ns, a in s["asics"].items():
            vl = a.get("vlan") or {}
            if vl.get("error") or "members" not in vl:
                continue
            members = vl["members"]
            used = frozenset(v for ms in members.values() for v, _m in ms)
            sets[(s["name"], ns)] = used
            for r in a.get("fdb") or []:
                if str(r.get("Type", "")).lower() != "static":
                    continue
                v = f"Vlan{r.get('Vlan')}" if str(r.get("Vlan", "")).isdigit() else str(r.get("Vlan", ""))
                port = r.get("Port")
                if port in members and v not in [x for x, _m in members[port]]:
                    out.append({"kind": "fdb_off_vlan", "switch": s["name"], "asic": ns, "port": port, "vlan": v,
                                "detail": f"static entry {r.get('MacAddress')} on {v} -> {port}, but {port} is in "
                                          f"{_vl(members[port])}"})
    if len(set(sets.values())) > 1:
        common = max(set(sets.values()), key=lambda x: sum(1 for v in sets.values() if v == x))
        for (sw, ns), used in sets.items():
            if used != common:
                out.append({"kind": "vlan_set", "switch": sw, "asic": ns, "port": None, "vlan": ",".join(sorted(used)),
                            "detail": f"{sw} {ns} uses VLANs {', '.join(sorted(used)) or 'none'}; the other ASICs "
                                      f"use {', '.join(sorted(common))}"})
    return out


def _vl(ms) -> str:
    return " + ".join(f"{v} ({m or 'untagged'})" for v, m in ms) or "no VLAN"


def link_dict(ln: Link) -> dict:
    d = asdict(ln)
    d.pop("gpu", None)
    return d


# ---------------------------------------------------------------------------------------------- repeat-ping map

def plane_owner(switches: list[dict]) -> dict[int, str]:
    """{GPU port number: 'switch asic'} from the port descriptions: one ASIC carries one port number for every GPU."""
    votes: dict[int, dict] = {}
    for s in switches:
        for ns, a in s["asics"].items():
            for desc in a["desc"].values():
                cab = parse_port_description(desc)
                if cab:
                    k = f"{s['name']} {ns}".strip()
                    votes.setdefault(cab[3], {}).setdefault(k, 0)
                    votes[cab[3]][k] += 1
    return {p: max(v, key=v.get) for p, v in votes.items()}


def ping_map(trays: list, rounds: int = 3, wait_s: float = 60, afmctl=Afmctl, log=print, sleep=time.sleep) -> dict:
    """Ring of L2 pings - each GPU to the GPU in the same position on the next tray, over every port that is up on
    both - repeated ``rounds`` times, ``wait_s`` apart. Returns per pair and per GPU port number how often each check
    failed, so a loss that stays on one link can be told from one that moves."""
    info = {}
    for t, val, exc in fan_out(lambda t: _ping_targets(t, afmctl), trays):
        if exc:
            log(f"{t.host.name}: afmctl not readable: {str(exc)[:120]}")
        else:
            info[t.host.name] = val
    names = [t.host.name for t in trays if t.host.name in info]
    jobs = {}
    for i, n in enumerate(names):
        peer = names[(i + 1) % len(names)] if len(names) > 1 else None
        if not peer:
            continue
        for g, (bdf, acc, up) in enumerate(info[n]["gpus"]):
            if g < len(info[peer]["gpus"]):
                pbdf, pacc, pup = info[peer]["gpus"][g]
                common = sorted(up & pup)
                if common:
                    jobs.setdefault(n, []).append((bdf, peer, pbdf, pacc, common))
    pairs: dict[str, dict] = {}
    by_port: dict[int, dict] = {}
    tray_obj = {t.host.name: t for t in trays}
    for r in range(rounds):
        log(f"ping round {r + 1}/{rounds} ({sum(len(v) for v in jobs.values())} pairs) ...")

        def run(n):
            a, out = afmctl(tray_obj[n]), []
            for bdf, peer, pbdf, pacc, ports in jobs.get(n, []):
                res, cmd = a.ping(bdf, pacc, ports)
                out.append((n, bdf, peer, pbdf, pacc, ports, res, cmd))
            return out
        for _, val, exc in fan_out(run, list(jobs)):
            for n, bdf, peer, pbdf, pacc, ports, res, cmd in (val or []):
                key = f"{n} {bdf} -> {peer} {pbdf} (acc {pacc})"
                pr = pairs.setdefault(key, {"rounds": 0, "ports": len(ports), "fails": {}, "busy": 0})
                pr["rounds"] += 1
                pr["busy"] += bool(res.busy)
                for p in ports:
                    bp = by_port.setdefault(p, {"pings": 0, "fails": 0, "checks": {}, "pairs": set()})
                    bp["pings"] += 1
                    failed = res.port_checks.get(str(p)) or []
                    if failed:
                        bp["fails"] += 1
                        bp["pairs"].add(key)
                        for c in failed:
                            bp["checks"][c] = bp["checks"].get(c, 0) + 1
                        pr["fails"].setdefault(p, []).append(r + 1)
        if r + 1 < rounds:
            sleep(wait_s)
    for v in by_port.values():
        v["pairs"] = sorted(v["pairs"])
    return {"rounds": rounds, "wait_s": wait_s, "pairs": pairs, "ports": by_port}


def _ping_targets(tray, afmctl=Afmctl) -> dict:
    a = afmctl(tray)
    accels = a.vpod_accels()
    gpus = []
    for d in a.devices():
        up = {p.id for p in a.ports(d.bdf) if p.up}
        gpus.append((d.bdf, accels.get(d.bdf, ("", set()))[0], up))
    return {"gpus": gpus}


def judge_ping_map(pm: dict, owner: dict[int, str]) -> list[str]:
    """Plain-language reading of a ping map: which port numbers (and so which switch ASICs) fail, sticky or moving."""
    out = []
    bad = {p: v for p, v in pm["ports"].items() if v["fails"]}
    if not bad:
        return [f"No ping loss in {pm['rounds']} rounds over {len(pm['pairs'])} GPU pairs."]
    per_asic: dict[str, int] = {}
    for p, v in bad.items():
        per_asic[owner.get(p, "?")] = per_asic.get(owner.get(p, "?"), 0) + v["fails"]
    out.append("Failing GPU port numbers: " + ", ".join(
        f"{p} ({v['fails']}/{v['pings']} pings, {owner.get(p, '?')})" for p, v in sorted(bad.items())))
    out.append("Failures per switch ASIC: " + ", ".join(f"{k} {n}" for k, n in sorted(per_asic.items(), key=lambda x: -x[1])))
    sticky = [(k, p, r) for k, pr in pm["pairs"].items() for p, r in pr["fails"].items() if len(r) == pr["rounds"] > 1]
    moving = [(k, p, r) for k, pr in pm["pairs"].items() for p, r in pr["fails"].items() if len(r) < pr["rounds"]]
    if sticky:
        out.append(f"Sticky (every round): {len(sticky)} pair-ports, e.g. " + "; ".join(f"{k} port {p}" for k, p, _ in sticky[:4])
                   + " - points at those links.")
    if moving:
        out.append(f"Moving (some rounds only): {len(moving)} pair-ports - points at the fabric / AFM rather than one link.")
    if len(per_asic) == 1 and "?" not in per_asic:
        out.append(f"All loss is on one switch ASIC ({next(iter(per_asic))}): check that ASIC first.")
    return out


def compare(prev_links: list[dict], links: list[Link]) -> dict:
    """What changed since an earlier scan (its link_check.json "links"), keyed by switch port: newly down / degraded,
    recovered, still bad with another cause."""
    key = lambda d: f"{d['switch']} {d['asic']} {d['sw_port']}".replace("  ", " ")  # noqa: E731
    before = {key(d): d for d in prev_links}
    out = {"new_problems": [], "recovered": [], "changed": [], "still_bad": 0, "not_in_earlier": 0}
    for ln in links:
        k = key({"switch": ln.switch, "asic": ln.asic, "sw_port": ln.sw_port})
        b = before.get(k)
        if b is None:                     # not in the earlier check (partial / older): no 'new problem' to claim
            out["not_in_earlier"] += 1
            continue
        was = b.get("state", "ok")
        if was == "ok" and ln.state != "ok":
            out["new_problems"].append(f"{k} <-> {ln.tray} port {ln.gpu_port}: {ln.state}, {ln.cause}")
        elif was != "ok" and ln.state == "ok":
            out["recovered"].append(f"{k} <-> {ln.tray} port {ln.gpu_port} (was {was}: {b.get('cause', '')})")
        elif was != "ok" and ln.state != "ok":
            out["still_bad"] += 1
            if b.get("kind") != ln.kind:
                out["changed"].append(f"{k}: {b.get('kind')} -> {ln.kind}")
    return out


def suspects(links: list[Link], min_links: int = 2) -> list[str]:
    """Patterns across problem links (trays out of service left out), as plain sentences:
    - several on one GPU: that GPU / tray side (or, all on one ASIC, either end)
    - the same GPU position (BDF) on several trays: something shared by that position (cable bundle / cartridge)
    - several on one switch ASIC: that ASIC, the more so on adjacent ports (one connector / cage)."""
    bad = [x for x in links if x.state != "ok" and x.kind not in ("tray_quarantined", "tray_unreachable", "tray_missing", *GPU_LEVEL)]
    judged = [x for x in links if x.kind not in ("tray_quarantined", "tray_unreachable", "tray_missing", *GPU_LEVEL)]
    kinds = {x.kind for x in bad}
    if len(bad) >= 8 and len(kinds) == 1 and len(bad) >= 0.9 * len(judged):
        return [f"rack-wide: {len(bad)} of {len(judged)} links have the same cause ({KINDS.get(next(iter(kinds)), next(iter(kinds)))})"
                f" - look for one common cause (configuration, a service, a software version) before suspecting "
                f"individual GPUs, cables or switch ASICs"]
    out = []
    per_gpu: dict[str, list] = {}
    for x in bad:
        if x.tray and x.bdf:
            per_gpu.setdefault(f"{x.tray} {x.bdf}", []).append(x)
    for g, v in sorted(per_gpu.items(), key=lambda kv: -len(kv[1])):
        if len(v) >= min_links:
            ports = ", ".join(str(x.gpu_port) for x in sorted(v, key=lambda x: x.gpu_port or 0))
            sws = sorted({f"{x.switch} {x.asic}".strip() for x in v})
            where = (f"on {len(sws)} different switch ASICs - suspect the GPU / tray side rather than separate cables"
                     if len(sws) > 1 else f"all on {sws[0]} - could be either end; compare with other GPUs on that ASIC")
            out.append(f"GPU {g}: {len(v)} problem links (ports {ports}), {where}.")
    per_pos: dict[str, set] = {}
    for x in bad:
        if x.bdf:
            per_pos.setdefault(x.bdf, set()).add(x.tray)
    for bdf, trays in sorted(per_pos.items(), key=lambda kv: -len(kv[1])):
        if len(trays) >= 3:
            out.append(f"GPU position {bdf}: problem links on {len(trays)} trays ({', '.join(sorted(trays))}) and on no other "
                       f"position - suspect something shared by that GPU position (cabling bundle / cartridge / tray "
                       f"slot) rather than {len(trays)} separate faults." if len(per_pos) == 1 else
                       f"GPU position {bdf}: problem links on {len(trays)} trays ({', '.join(sorted(trays))}).")
    per_asic: dict[str, list] = {}
    for x in bad:
        per_asic.setdefault(f"{x.switch} {x.asic}".strip(), []).append(x)
    for k, v in sorted(per_asic.items(), key=lambda kv: -len(kv[1])):
        if len(v) < 3:
            continue
        nums = sorted(int(m.group(1)) for x in v if (m := re.fullmatch(r"Ethernet(\d+)", x.sw_port)))
        near = bool(nums) and nums[-1] - nums[0] <= 8
        out.append(f"{k}: {len(v)} problem links (" + ", ".join(f"Ethernet{n}" for n in nums) + ")" +
                   (" on adjacent ports - suspect one connector / cage on that switch" if near else " - suspect that switch ASIC") + ".")
    return out
