"""Read-only configuration of one switch or compute tray, for the debug UI's Config view.

  switch tray   SONiC's configuration database of the host and of every ASIC namespace (`sonic-cfggen -d
                --print-data [-n asicN]`): PORT, VLAN, VLAN_MEMBER, PORT_QOS_MAP, BUFFER_*, DEVICE_METADATA, ...
  compute tray  afmctl's view of each GPU (`afmctl show device --json`, `afmctl show port -b <bdf> --json`) and the
                OS basics (os-release, kernel, interfaces)
Nothing is written. Each section is {"title", "data" (parsed JSON or text), "error"}.
"""
from __future__ import annotations

import json
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
    for ns in sw.namespaces():
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

