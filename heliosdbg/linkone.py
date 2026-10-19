"""One link from whatever identifier you have: which switch port and which GPU port it is, so only that switch tray and
that compute tray are read (tools/link_check.py link, the UI's Diagnose / Rack map).

Accepted, case-insensitive, separated by spaces, '/' or ':':
  st6 Ethernet257          st6/asic1/Ethernet257       the switch end
  ct13 0002:01:00.1 33     ct13/0002:01:00.1/port33    the GPU end by BDF and GPU port
  ct13 gpu1 port33         the GPU end by the GPU number of the switch port descriptions
  slot17/gpu3/port33       AFM's peer display / the description's Slot/GPU/Port
  acc-id: 5, port-id: 32   an AFM ifoe_netport_* event (accelerator id + GPU port)
The rack's latest scan (link_check.json) resolves most of them without logging in anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .afmctl import parse_port_description

SEP = r"[\s/:]+"
_FORMS = [
    ("switch", re.compile(rf"^(?P<sw>[\w.-]+?){SEP}(?:(?P<asic>asic\d+){SEP})?(?P<port>ethernet\d+)$", re.I)),
    ("bdf", re.compile(rf"^(?P<tray>[\w.-]+?){SEP}(?P<bdf>[0-9a-f]{{4}}:[0-9a-f]{{2}}:[0-9a-f]{{2}}\.\d){SEP}(?:port\s*)?(?P<p>\d+)$", re.I)),
    ("slot", re.compile(rf"^(?:to\s+computetray\s+)?slot\s*(?P<slot>\d+){SEP}gpu\s*(?P<g>\d+)(?:\[\d+\])?{SEP}port\s*(?P<p>\d+)$", re.I)),
    ("traygpu", re.compile(rf"^(?P<tray>[\w.-]+?){SEP}gpu\s*(?P<g>\d+)(?:\[\d+\])?{SEP}(?:port\s*)?(?P<p>\d+)$", re.I)),
    ("acc", re.compile(r"acc(?:elerator)?[-_ ]?id\D{0,4}(?P<acc>\d+)\D+port[-_ ]?id\D{0,4}(?P<p>\d+)", re.I)),
]


class TargetError(ValueError):
    pass


@dataclass
class Target:
    text: str
    kind: str
    switch: str | None = None
    sw_port: str | None = None
    tray: str | None = None
    bdf: str | None = None
    gpu_port: int | None = None
    slot: int | None = None
    gpu: int | None = None          # GPU number as the switch port descriptions write it
    acc: str | None = None
    how: str = ""                   # how it was resolved

    def matches(self, ln) -> bool:
        g = (lambda k: ln.get(k)) if isinstance(ln, dict) else (lambda k: getattr(ln, k, None))
        if self.switch and self.sw_port:
            return g("switch") == self.switch and str(g("sw_port")).lower() == self.sw_port.lower()
        if self.tray and self.bdf is not None and self.gpu_port is not None:
            return g("tray") == self.tray and g("bdf") == self.bdf and g("gpu_port") == self.gpu_port
        if self.slot is not None and self.gpu is not None and self.gpu_port is not None:
            cab = parse_port_description(g("desc") or "")
            return bool(cab) and (cab[0], cab[1], cab[3]) == (self.slot, self.gpu, self.gpu_port)
        return False


def parse(text: str, switches: list[str], trays: list[str]) -> Target:
    t = " ".join((text or "").split())
    if not t or len(t) > 200:
        raise TargetError("give a switch port (st6 Ethernet257), a GPU port (ct13 0002:01:00.1 33), "
                          "slot17/gpu3/port33 or an AFM event (acc-id: 5, port-id: 32)")
    for kind, rx in _FORMS:
        m = rx.search(t) if kind == "acc" else rx.match(t)
        if not m:
            continue
        d = m.groupdict()
        if kind == "switch":
            sw = next((s for s in switches if s.lower() == d["sw"].lower()), None)
            if not sw:
                raise TargetError(f"no switch {d['sw']} in the inventory ({', '.join(switches)})")
            return Target(t, kind, switch=sw, sw_port="Ethernet" + re.sub(r"\D", "", d["port"]))
        if kind in ("bdf", "traygpu"):
            tr = next((x for x in trays if x.lower() == d["tray"].lower()), None)
            if not tr:
                raise TargetError(f"no compute tray {d['tray']} in the inventory ({', '.join(trays)})")
            if kind == "bdf":
                return Target(t, kind, tray=tr, bdf=d["bdf"].lower(), gpu_port=int(d["p"]))
            return Target(t, kind, tray=tr, gpu=int(d["g"]), gpu_port=int(d["p"]))
        if kind == "slot":
            return Target(t, kind, slot=int(d["slot"]), gpu=int(d["g"]), gpu_port=int(d["p"]))
        return Target(t, kind, acc=d["acc"], gpu_port=int(d["p"]))
    raise TargetError(f"cannot read '{t}' - give a switch port (st6 Ethernet257), a GPU port (ct13 0002:01:00.1 33), "
                      "slot17/gpu3/port33 or an AFM event (acc-id: 5, port-id: 32)")


def resolve(t: Target, prev_links: list[dict] | None, tray_slots: dict[str, int], read_desc=None, read_devices=None) -> Target:
    """Fill in the switch and the tray to read. prev_links: the latest scan's links; tray_slots: {tray: slot} from the
    inventory / that scan; read_desc(): {switch: {port: description}}; read_devices(): {tray: {bdf: accelerator}}."""
    if t.kind == "acc":
        devs = read_devices() if read_devices else {}
        hit = [(tr, b) for tr, d in devs.items() for b, acc in d.items() if str(acc) == t.acc]
        if not hit:
            raise TargetError(f"no GPU with accelerator id {t.acc} on the trays read")
        t.tray, t.bdf = hit[0]
        t.how = f"accelerator {t.acc} is {t.tray} {t.bdf} (afmctl show device)"
    if t.kind == "traygpu":
        if t.tray in tray_slots:
            t.slot = tray_slots[t.tray]
        else:
            raise TargetError(f"slot of {t.tray} unknown: set slot: on its inventory entry, run a scan first, or give "
                              "the BDF (ct13 0002:01:00.1 33)")
    for ln in prev_links or []:
        if t.matches(ln):
            t.switch, t.sw_port, t.tray = ln.get("switch"), ln.get("sw_port"), ln.get("tray") or t.tray
            t.how = (t.how + "; " if t.how else "") + "latest scan"
            return t
    if t.kind == "slot" and read_desc:
        for sw, ports in read_desc().items():
            for port, desc in ports.items():
                cab = parse_port_description(desc)
                if cab and (cab[0], cab[1], cab[3]) == (t.slot, t.gpu, t.gpu_port):
                    t.switch, t.sw_port = sw, port
                    t.tray = next((tr for tr, s in tray_slots.items() if s == t.slot), None)
                    t.how = "switch port descriptions"
                    return t
        raise TargetError(f"no switch port is described as Slot{t.slot}/GPU{t.gpu}/Port{t.gpu_port}")
    if t.kind == "switch":
        t.how = t.how or "switch port given"
    elif t.kind == "traygpu":
        t.how = t.how or f"{t.tray} = slot {t.slot}"
    return t
