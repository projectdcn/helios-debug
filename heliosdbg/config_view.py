"""Read-only configuration of one switch or compute tray, for the debug UI's Config view.

  switch tray   SONiC's configuration database of the host and of every ASIC namespace (`sonic-cfggen -d
                --print-data [-n asicN]`): PORT, VLAN, VLAN_MEMBER, PORT_QOS_MAP, BUFFER_*, DEVICE_METADATA, ...
  compute tray  afmctl's view of each GPU (`afmctl show device --json`, `afmctl show port -b <bdf> --json`) and the
                OS basics (os-release, kernel, interfaces)
Nothing is written. Each section is {"title", "data" (parsed JSON or text), "error"}.
"""
from __future__ import annotations

import json
import re
import shlex


def _section(title: str, fn) -> dict:
    try:
        return {"title": title, "data": fn(), "error": None}
    except Exception as e:  # noqa: BLE001 - one unreadable part does not hide the others
        return {"title": title, "data": None, "error": f"{type(e).__name__}: {str(e)[:300]}"}


def switch_config(sw) -> dict:
    """{kind: 'switch', sections: {host | asicN: section}} - CONFIG_DB of the host and each ASIC."""
    def cfg(ns):
        flag = f" -n {shlex.quote(ns)}" if ns else ""
        return json.loads(sw.sh(f"sonic-cfggen -d --print-data{flag}", sudo=True, timeout=120))
    out = {"host": _section("host (global CONFIG_DB)", lambda: cfg(None))}
    if out["host"]["error"]:                   # did not answer: no namespaces to ask (not an exception out of here)
        return {"kind": "switch", "sections": out}
    nss = _section("ASIC namespaces", sw.namespaces)
    if nss["error"]:
        out["namespaces"] = nss
        return {"kind": "switch", "sections": out}
    for ns in nss["data"] or []:
        if ns:
            out[ns] = _section(f"{ns} CONFIG_DB", lambda ns=ns: cfg(ns))
    return {"kind": "switch", "sections": out}


def compute_config(ct) -> dict:
    """{kind: 'compute', sections: {devices, ports, os}} - afmctl's GPU / port configuration and OS basics."""
    def afm(args):
        return json.loads(ct.run(f"afmctl {args} 2>/dev/null", sudo=True, timeout=90).check().stdout)

    def devices():
        return afm("show device --json")

    dev = _section("GPUs (afmctl show device)", devices)
    if dev["error"] and re.search(r"no route|timed out|refused|unreachable|rc=255|authenticat|permission denied",
                                  dev["error"], re.I):
        # the tray did not answer: the other parts would come back empty, not failed (g02-g17 3 Nov: ct06 / ct10
        # 'read' with empty ports and OS while off the network)
        return {"kind": "compute", "sections": {k: {"title": t, "data": None, "error": dev["error"]} for k, t in
                                                (("devices", dev["title"]), ("ports", "GPU ports (afmctl show port)"),
                                                 ("os", "OS and interfaces"))}}
    from .afmctl import _devices                  # the same reading of `show device --json` as the scans
    bdfs = [str(d["bdf"]) for d in (_devices(dev["data"]) if dev.get("data") is not None else []) if d.get("bdf")]

    def ports():
        return {b: afm(f"show port -b {shlex.quote(b)} --json") for b in sorted(set(bdfs))}

    def os_basics():
        txt = ct.run("cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)='; uname -r; "
                     "ip -br addr 2>/dev/null", timeout=30).stdout
        return txt
    return {"kind": "compute", "sections": {"devices": dev, "ports": _section("GPU ports (afmctl show port)", ports),
                                            "os": _section("OS and interfaces", os_basics)}}



# ------------------------------------------------------------------ reading what a config says (Config tab)

def _devs(doc) -> list[dict]:
    """afmctl's `show device` / `show port` JSON: {"device": [...]} or a list."""
    if isinstance(doc, list):
        return doc
    return (doc or {}).get("device") or (doc or {}).get("devices") or []


def factory_mac(mac: str | None) -> bool:
    """A GPU port MAC AFM did not assign: AFM's are locally administered (02:...); the factory ones are not
    (g02-g17 3 Nov: 13 trays in PROVIDER reported 00:1f:0e:00:00:00 on every tray, the switches held 02:00:00:...)."""
    try:
        return not (int(str(mac).split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def compute_summary(cfg: dict) -> list[dict]:
    """One row per GPU: what decides whether its links can work - phase, mode, vPOD, MACs, ports up / IFCP up."""
    secs = cfg.get("sections") or {}
    ports = (secs.get("ports") or {}).get("data") or {}
    rows = []
    for d in _devs((secs.get("devices") or {}).get("data")):
        sp, st = d.get("spec") or {}, d.get("status") or {}
        bdf = str(d.get("bdf"))
        pl = next((x.get("port") or [] for x in _devs(ports.get(bdf)) if str(x.get("bdf")) == bdf), None)
        if pl is None:
            pl = next((x.get("port") or [] for x in _devs(ports.get(bdf))), [])
        macs = sorted({(p.get("spec") or {}).get("nw_mac_addr") for p in pl} - {None, ""})
        vp = ((sp.get("scaleup_fabric") or {}).get("virtual_pod") or {}) if isinstance(sp.get("scaleup_fabric"), dict) else {}
        rows.append({
            "bdf": bdf, "accelerator": sp.get("accelerator_id"), "phase": sp.get("config_phase"),
            "mode": sp.get("virtualization_mode"), "failover": sp.get("failover_mode"),
            "vpod": vp.get("id") or "", "firmware": st.get("firmware_version"),
            "ports": len(pl),
            "link_up": sum(1 for p in pl if (p.get("status") or {}).get("link_status") == "LINK_UP"),
            "ifcp_up": sum(1 for p in pl if ((p.get("status") or {}).get("ifcp") or {}).get("ll_up") == "yes"),
            "macs": macs, "factory_mac": any(factory_mac(m) for m in macs)})
    return rows


def switch_summary(cfg: dict) -> dict:
    """{asicN: {ports, fdb, vlan_members, vlans, mtu: {value: n}, fec, speed, admin}} from each ASIC's CONFIG_DB."""
    from collections import Counter
    out = {}
    for name, sec in (cfg.get("sections") or {}).items():
        db = sec.get("data")
        if name == "host" or not isinstance(db, dict):
            continue
        port = db.get("PORT") or {}
        out[name] = {"ports": len(port), "fdb": len(db.get("FDB") or {}), "vlan_members": len(db.get("VLAN_MEMBER") or {}),
                     "vlans": sorted(db.get("VLAN") or {}),
                     **{f: dict(Counter(str(v.get(f)) for v in port.values() if isinstance(v, dict) and f in v))
                        for f in ("mtu", "fec", "speed", "admin_status")}}
    return out


def ports_read(cfg: dict) -> bool:
    """A tray read whose GPU ports were read (not an error, not empty): only such reads may judge forwarding entries."""
    sec = ((cfg or {}).get("sections") or {}).get("ports") or {}
    return not sec.get("error") and bool(sec.get("data"))


def summary(cfg: dict) -> dict:
    return {"gpus": compute_summary(cfg)} if cfg.get("kind") == "compute" else {"asics": switch_summary(cfg)}


def fdb_check(switches: dict, trays: dict, slots: dict | None = None) -> dict:
    """The switches' static forwarding entries against the GPU port MACs the trays report, per switch / ASIC:
      no_gpu_port   entries whose MAC no GPU port of the tray the port leads to has (that GPU lost the MAC AFM gave it -
                    a reset or a mode change - or the entry is stale)
      other_tray    entries whose MAC is a GPU port of another tray than the one the port's description names
    Only entries whose port leads to a tray that was read are judged. switches / trays: {name: config read};
    slots: {slot number: tray name}."""
    from .afmctl import parse_port_description
    have = {}
    for tn, cfg in trays.items():
        ports = ((cfg.get("sections") or {}).get("ports") or {}).get("data") or {}
        for bdf, doc in ports.items():
            for dv in _devs(doc):
                for p in dv.get("port") or []:
                    m = str((p.get("spec") or {}).get("nw_mac_addr") or "").lower()
                    if m:
                        have.setdefault(m, set()).add(tn)
    out = {"trays_read": sorted(trays), "switches": {}}
    for sn, cfg in switches.items():
        for asic, sec in (cfg.get("sections") or {}).items():
            db = sec.get("data")
            if asic in ("host", "namespaces") or not isinstance(db, dict):
                continue
            desc = {k: (v or {}).get("description", "") for k, v in (db.get("PORT") or {}).items()}
            ok, miss, other = 0, {}, {}
            for key, v in (db.get("FDB") or {}).items():
                mac = key.split("|")[-1].lower()
                port = (v or {}).get("port", "")
                cab = parse_port_description(desc.get(port, "") or "")
                tray = (slots or {}).get(cab[0]) if cab else None
                if tray is None or tray not in trays:
                    continue                      # the tray behind this port is unknown or was not read
                if tray in have.get(mac, ()):
                    ok += 1
                elif mac in have:
                    other.setdefault(tray, []).append(port)
                else:
                    miss.setdefault(tray, []).append(port)
            out["switches"][f"{sn} {asic}"] = {
                "matched": ok, "no_gpu_port": {t: len(p) for t, p in sorted(miss.items())},
                "other_tray": {t: len(p) for t, p in sorted(other.items())},
                "examples": {t: sorted(p)[:4] for t, p in sorted({**miss, **other}.items())}}
    return out


def odd_ones(cfgs: dict) -> list[dict]:
    """Values one node has and most others do not, across a rack read: GPU phase / mode / firmware / factory MACs,
    switch PORT mtu / fec / speed / admin, and per-ASIC table sizes. [{what, value, nodes, others}]"""
    from collections import Counter, defaultdict
    findings = []

    def judge(what, per_node):              # per_node: {node: value}
        c = Counter(per_node.values())
        if len(c) < 2:
            return
        common, _n = c.most_common(1)[0]
        for val, _k in c.items():
            if val == common:
                continue
            findings.append({"what": what, "value": val, "nodes": sorted(n for n, v in per_node.items() if v == val),
                             "others": common, "others_n": c[common]})
    gpu_fields = ("phase", "mode", "failover", "firmware", "factory_mac", "vpod")
    per = defaultdict(dict)
    for node, cfg in cfgs.items():
        if cfg.get("kind") != "compute":
            continue
        for g in compute_summary(cfg):
            for f in gpu_fields:
                per[f][f"{node} {g['bdf']}"] = str(g[f])
    for f in gpu_fields:
        # by tray when all its GPUs agree, so '13 trays' reads as trays, not 52 GPUs
        byt = defaultdict(set)
        for k, v in per[f].items():
            byt[k.split()[0]].add(v)
        flat = {t: next(iter(v)) for t, v in byt.items() if len(v) == 1}
        judge(f"GPU {f}", flat)
        for t, v in byt.items():
            if len(v) > 1:
                judge(f"GPU {f} on {t}", {k: x for k, x in per[f].items() if k.startswith(t + " ")})
    sw = {n: c for n, c in cfgs.items() if c.get("kind") == "switch"}
    for f in ("mtu", "fec", "speed", "admin_status"):
        vals = {}
        for n, cfg in sw.items():
            for asic, sec in (cfg.get("sections") or {}).items():
                db = sec.get("data")
                if asic == "host" or not isinstance(db, dict):
                    continue
                for p, v in (db.get("PORT") or {}).items():
                    if isinstance(v, dict) and f in v:
                        vals[f"{n} {asic} {p}"] = str(v[f])
        judge(f"PORT {f}", vals)
    for t in ("FDB", "VLAN_MEMBER", "PORT", "VLAN"):
        sizes = {}
        for n, cfg in sw.items():
            for asic, sec in (cfg.get("sections") or {}).items():
                if asic != "host" and isinstance(sec.get("data"), dict):
                    sizes[f"{n} {asic}"] = str(len(sec["data"].get(t) or {}))
        judge(f"{t} entries", sizes)
    for f in ("hwsku", "platform", "type"):
        meta = {}
        for n, cfg in sw.items():
            db = ((cfg.get("sections") or {}).get("host") or {}).get("data")
            if isinstance(db, dict):
                meta[n] = str(((db.get("DEVICE_METADATA") or {}).get("localhost") or {}).get(f))
        judge(f"DEVICE_METADATA {f}", meta)
    return findings
