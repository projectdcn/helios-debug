"""One switch port through SONiC's databases, side by side - what `dump state port` shows, which crashes on the
multi-ASIC QFX5252 (SONiC 202505: 'validateNamespace: Initialize global DB config', 9 Nov 2026). Read-only.

The JTAC 'SONiC Interface' deck's method: CONFIG_DB -> APPL_DB -> ASIC_DB -> STATE_DB; stop at the first record that is
missing - the daemon that should have written it is the suspect (portmgrd: CONFIG -> APPL; orchagent / PortOrch,
the lane list: APPL -> ASIC; portsyncd, the kernel netdev: STATE).
"""
from __future__ import annotations

import ast
import re

STAGES = (
    ("CONFIG_DB", "PORT|{p}", "the intended configuration (config_db.json, config commands)",
     "not configured: the port is not in CONFIG_DB (config_db.json / breakout)"),
    ("APPL_DB", "PORT_TABLE:{p}", "what portmgrd published from it",
     "portmgrd did not publish it (validation against the HwSKU failed, or the daemon is down): its log in syslog"),
    ("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:{oid}", "the SAI port object syncd programmed into the chip",
     "orchagent / PortOrch never bound it to a chip port (lane list mismatch, SAI discovery): 'docker logs syncd' / "
     "syslog initializePort"),
    ("STATE_DB", "PORT_TABLE|{p}", "the kernel netdev's state (portsyncd)",
     "portsyncd has no record: the kernel netdev was not created / not seen (ip -d link show)"),
)
KEEP = ("admin_status", "oper_status", "netdev_oper_status", "state", "speed", "mtu", "fec", "lanes", "alias",
        "description", "flap_count", "last_down_time", "last_up_time", "SAI_PORT_ATTR_ADMIN_STATE", "SAI_PORT_ATTR_SPEED",
        "SAI_PORT_ATTR_MTU", "SAI_PORT_ATTR_HW_LANE_LIST", "SAI_PORT_ATTR_FEC_MODE")


def _ns(asic: str | None) -> str:
    return f" -n {asic}" if asic else ""


def oid_command(asic: str | None, port: str) -> str:
    return f"sonic-db-cli{_ns(asic)} COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {port}"


def command(asic: str | None, db: str, key: str) -> str:
    return f"sonic-db-cli{_ns(asic)} {db} HGETALL '{key}'"


def parse(out: str) -> dict:
    """sonic-db-cli HGETALL prints a Python dict ({} when the key is missing)."""
    t = (out or "").strip()
    if not t.startswith("{"):
        return {}
    try:
        d = ast.literal_eval(t)
    except (ValueError, SyntaxError):
        return dict(re.findall(r"'([^']+)': '([^']*)'", t))
    return {str(k): str(v) for k, v in d.items()} if isinstance(d, dict) else {}


def read(run, asic: str | None, port: str) -> dict:
    """run(cmd) -> stdout. {oid, records: {db: dict}, commands: [..]}."""
    cmds, rec = [], {}
    c = oid_command(asic, port)
    cmds.append(c)
    oid = (run(c) or "").strip().strip('"') or None
    if oid and not oid.startswith("oid:"):
        oid = None
    for db, key, _w, _miss in STAGES:
        if "{oid}" in key and not oid:
            rec[db] = None                           # no OID: the ASIC record cannot even be looked up
            continue
        c = command(asic, db, key.format(p=port, oid=oid))
        cmds.append(c)
        rec[db] = parse(run(c))
    return {"oid": oid, "records": rec, "commands": cmds, "asic": asic}


def judge(r: dict, port: str) -> dict:
    """{stages: [{db, what, present, fields}], gap: {db, why} | None, mismatches: [..], summary}."""
    rec = r["records"]
    stages, gap = [], None
    for db, _key, what, miss in STAGES:
        d = rec.get(db)
        ok = bool(d)
        stages.append({"db": db, "what": what, "present": ok, "fields": {k: v for k, v in (d or {}).items() if k in KEEP}})
        if not ok and gap is None:
            gap = {"db": db, "why": miss if d is not None or db != "ASIC_DB" else
                   "no OID in COUNTERS_PORT_NAME_MAP: " + miss}
    c, a, s, x = (rec.get(k) or {} for k in ("CONFIG_DB", "APPL_DB", "STATE_DB", "ASIC_DB"))
    mm = []
    adm = {"CONFIG_DB": c.get("admin_status"), "APPL_DB": a.get("admin_status"), "STATE_DB": s.get("admin_status"),
           "ASIC_DB": {"true": "up", "false": "down"}.get(x.get("SAI_PORT_ATTR_ADMIN_STATE", ""), None)}
    seen = {k: v for k, v in adm.items() if v}
    if len(set(seen.values())) > 1:
        mm.append("admin state differs: " + ", ".join(f"{k} {v}" for k, v in seen.items()))
    sp = {"CONFIG_DB": c.get("speed"), "APPL_DB": a.get("speed"), "ASIC_DB": x.get("SAI_PORT_ATTR_SPEED")}
    seen = {k: v for k, v in sp.items() if v}
    if len(set(seen.values())) > 1:
        mm.append("speed differs: " + ", ".join(f"{k} {v}" for k, v in seen.items()))
    if a.get("mtu") and x.get("SAI_PORT_ATTR_MTU") and int(x["SAI_PORT_ATTR_MTU"]) - int(a["mtu"]) not in (0, 22):
        mm.append(f"MTU differs: APPL_DB {a['mtu']}, ASIC_DB {x['SAI_PORT_ATTR_MTU']} (the SAI MTU is the port MTU + 22)")
    oper = a.get("oper_status") or s.get("netdev_oper_status")
    if gap:
        summary = f"{port} stops at {gap['db']}: {gap['why']}."
    elif mm:
        summary = f"{port} is in every database, but " + "; ".join(mm) + "."
    elif c.get("admin_status") == "down":
        summary = (f"{port} is shut by configuration: admin_status down in CONFIG_DB, and every database after it agrees"
                   + (f" (last down {a.get('last_down_time')})" if a.get("last_down_time") else "")
                   + f" - not the cable or the far end. If it should be up, start it again - CHANGES THE SWITCH: sudo config "
                     f"interface{_ns(r.get('asic'))} startup {port} (and config save to keep it).")
    else:
        summary = (f"{port} is in every database and they agree (admin {c.get('admin_status')}); it is "
                   + (f"oper {oper}" if oper else "of unknown oper state")
                   + (" - programmed end to end: a link that is down is a link matter (cable, far end), not configuration."
                      if oper == "down" else "."))
    return {"stages": stages, "gap": gap, "mismatches": mm, "summary": summary, "oid": r.get("oid"),
            "commands": r.get("commands") or []}
