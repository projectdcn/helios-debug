"""The rack map as facts for the AI chat: which GPU port is cabled to which switch port, the MACs AFM programmed, the
accelerator ids, the VLAN of a port, the plane map, and the path between two GPUs - all from a saved check, never from
the model's memory (a model trained on port numbers would recite wrong ones; looked up, they are exact and current).

Names understood in a question: ct02 / c2 / pod-1-1-ComputeTray, GPU0..3 (AFM numbering), a PCI address
(0004:01:00.1), 'acc 7' (accelerator id), st6 / pod-1-5-SwitchTray, asic0, Ethernet170, a MAC (02:00:00:0f:01:1f).
"""
from __future__ import annotations

import re

_GPU_RX = re.compile(r"\b(?:gpu\s*|g)(\d)\b", re.I)
_BDF_RX = re.compile(r"\b([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d)\b", re.I)
_ACC_RX = re.compile(r"\bacc(?:elerator)?(?:[\s_-]*id)?\s*[#:]?\s*(\d{1,3})\b", re.I)
_MAC_RX = re.compile(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", re.I)
_TRAY_RX = re.compile(r"\b(ct\d{2}|c\d|pod-\d+-\d+-ComputeTray)\b", re.I)
_SW_RX = re.compile(r"\b(st\d+|pod-\d+-\d+-SwitchTray)\b", re.I)
TOPO_WORDS = re.compile(r"\b(connected|cabled|cabling|wired|topology|rack\s*map|map|plane|which\s+(switch|port|gpu)|"
                        r"path|route|between|reach|mac|address|accelerator|acc|bdf|pci|port\s+\d+|gpu\s*\d|vlan)\b", re.I)


def _gpu_num(scan: dict, tray: str, bdf: str):
    for k, v in (scan.get("gpu_map") or {}).items():
        if v == bdf and k.startswith(f"{tray}:GPU"):
            return int(k.split("GPU", 1)[1])
    return None


def gpu_label(scan: dict, tray: str, bdf: str) -> str:
    n, acc = _gpu_num(scan, tray, bdf), (scan.get("gpu_acc") or {}).get(f"{tray}:{bdf}")
    return f"GPU{n if n is not None else '?'} ({bdf}" + (f", acc {acc}" if acc is not None else "") + ")"


def _ranges(nums) -> str:
    nums = sorted(set(nums))
    return ",".join(str(x) for x in nums)


def resolve_gpus(scan: dict, question: str) -> list[tuple[str, str]]:
    """(tray, bdf) of every GPU the question names, in the order named."""
    names = {v.lower(): k for k, v in (scan.get("afm_names") or {}).items()}
    links = [x for x in scan.get("links") or [] if x.get("tray") and x.get("bdf")]
    trays = {x["tray"] for x in links}
    found: list[tuple[int, tuple[str, str]]] = []       # (position in the question, GPU): in the order named
    acc_of = {v: k for k, v in (scan.get("gpu_acc") or {}).items()}          # acc -> "tray:bdf"
    for m in _ACC_RX.finditer(question or ""):
        k = acc_of.get(int(m.group(1)))
        if k:
            t, b = k.split(":", 1)
            found.append((m.start(), (t, b)))
    # "ct02 GPU0", "pod-1-1-ComputeTray gpu 0", "ct02 0004:01:00.1"
    for m in re.finditer(r"(ct\d{2}|c\d|pod-\d+-\d+-ComputeTray)\W{0,3}(?:(?:gpu\s*|g)(\d)\b|([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d))?",
                         question or "", re.I):
        t = names.get(m.group(1).lower(), m.group(1).lower())
        if t not in trays:
            continue
        if m.group(2) is not None:
            b = (scan.get("gpu_map") or {}).get(f"{t}:GPU{m.group(2)}")
            if b:
                found.append((m.start(), (t, b)))
        elif m.group(3):
            found.append((m.start(), (t, m.group(3).lower())))
    return list(dict.fromkeys(g for _pos, g in sorted(found)))


def plane_map(scan: dict) -> str:
    """GPU port number -> the switch chip that carries it (the same for every GPU of the rack)."""
    owner: dict = {}
    for x in scan.get("links") or []:
        if x.get("gpu_port") is not None and x.get("switch"):
            owner.setdefault(f"{x['switch']} {x.get('asic') or ''}".strip(), set()).add(int(x["gpu_port"]))
    if not owner:
        return ""
    names = scan.get("afm_names") or {}
    parts = [f"{k.split()[0]}{' (' + names[k.split()[0]] + ')' if k.split()[0] in names else ''} {' '.join(k.split()[1:])}: "
             f"GPU ports {_ranges(v)}" for k, v in sorted(owner.items())]
    return "Plane map (which switch chip carries each GPU port number; the same for every GPU): " + "; ".join(parts)


def tray_lines(scan: dict, tray: str, only_bdf: str | None = None) -> list[str]:
    """One line per GPU of a tray: its label and, per switch chip, its GPU ports -> switch ports (+ problem links)."""
    names = scan.get("afm_names") or {}
    by: dict = {}
    for x in scan.get("links") or []:
        if x.get("tray") == tray and x.get("bdf") and (not only_bdf or x["bdf"] == only_bdf):
            by.setdefault(x["bdf"], []).append(x)
    out = []
    for bdf, ls in sorted(by.items(), key=lambda kv: (_gpu_num(scan, tray, kv[0]) if _gpu_num(scan, tray, kv[0]) is not None else 9, kv[0])):
        chips: dict = {}
        for x in sorted(ls, key=lambda x: int(x.get("gpu_port") or 0)):
            chips.setdefault(f"{x['switch']} {x.get('asic') or ''}", []).append(x)
        bad = [x for x in ls if x.get("state") != "ok"]
        out.append(f"{names.get(tray, tray)} ({tray}) {gpu_label(scan, tray, bdf)}: {len(ls)} links - "
                   + "; ".join(f"{c}: GPU ports {'/'.join(str(x.get('gpu_port')) for x in xs)} -> "
                               f"{'/'.join(x['sw_port'] for x in xs)}" for c, xs in sorted(chips.items()))
                   + (f"; not ok: " + ", ".join(f"port {x.get('gpu_port')} ({x['switch']} {x['sw_port']}) {x.get('state')}"
                                               f"{' ' + x['kind'] if x.get('kind') else ''}" for x in bad[:6]) if bad else "; all ok"))
    return out


def path_lines(scan: dict, a: tuple[str, str], b: tuple[str, str]) -> list[str]:
    """The path between two GPUs: on each GPU port number both GPUs land on the same switch chip, so the path is
    GPU A port p -> that chip -> GPU B port p; plus each side's state and B's accelerator id (afmctl test ping)."""
    la = {int(x["gpu_port"]): x for x in scan.get("links") or [] if (x.get("tray"), x.get("bdf")) == a and x.get("gpu_port") is not None}
    lb = {int(x["gpu_port"]): x for x in scan.get("links") or [] if (x.get("tray"), x.get("bdf")) == b and x.get("gpu_port") is not None}
    common = sorted(set(la) & set(lb))
    if not common:
        return [f"No common GPU port between {a[0]} {a[1]} and {b[0]} {b[1]} in this check."]
    chips: dict = {}
    for p in common:
        x, y = la[p], lb[p]
        chips.setdefault(f"{x['switch']} {x.get('asic') or ''}", []).append((p, x, y))
    out = [f"Path {a[0]} {gpu_label(scan, *a)} <-> {b[0]} {gpu_label(scan, *b)}: {len(common)} GPU ports in common; on each "
           f"port number both GPUs land on the same switch chip"]
    up_all = [p for p in common if la[p].get("state") == "ok" and lb[p].get("state") == "ok"]
    weak = [f"{c.strip()} ({sum(1 for p, x, y in xs if x.get('state') == 'ok' and y.get('state') == 'ok')} of {len(xs)})"
            for c, xs in sorted(chips.items()) if any(x.get("state") != "ok" or y.get("state") != "ok" for p, x, y in xs)]
    out.append(f"Summary: {len(up_all)} of {len(common)} common ports have both ends ok"
               + (f"; not fully ok: {', '.join(weak)}" if weak else "; every chip on the path is fully ok"))
    for c, xs in sorted(chips.items()):
        up = [p for p, x, y in xs if x.get("state") == "ok" and y.get("state") == "ok"]
        out.append(f"via {c}: " + "; ".join(f"port {p}: {x['sw_port']} -> {y['sw_port']}" for p, x, y in xs)
                   + f" ({len(up)} of {len(xs)} with both ends ok)")
    acc = (scan.get("gpu_acc") or {}).get(f"{b[0]}:{b[1]}")
    if acc is not None:
        out.append(f"To test it (read-only data path test, Expert: GPU-to-GPU path): on {a[0]}: `sudo afmctl test ping -b {a[1]} "
                   f"-c 1 --dst-accelerator {acc} --port <ports>`")
    return out


def facts(scan: dict, question: str, macs: dict | None = None) -> list[str]:
    """Rack-map facts for a question (empty when it does not ask about the map)."""
    q = question or ""
    if not (TOPO_WORDS.search(q) or _MAC_RX.search(q) or _BDF_RX.search(q) or _ACC_RX.search(q)):
        return []
    out = []
    pm = plane_map(scan)
    if re.search(r"\b(plane|topology|map|which\s+switch|cabl|connected|wired)\b", q, re.I) and pm:
        out.append(pm)
        out.append("Names: AFM numbers trays from 0 (pod-1-0-SwitchTray = st1, pod-1-0-ComputeTray = ct01); GPU0..3 is AFM's "
                   "GPU index; each GPU has 36 ports (0..35), one cable each to one switch port")
    gpus = resolve_gpus(scan, q)
    if len(gpus) >= 2 and re.search(r"\b(path|route|between|reach|to)\b", q, re.I):
        out += path_lines(scan, gpus[0], gpus[1])
    else:
        names = {v.lower(): k for k, v in (scan.get("afm_names") or {}).items()}
        named_trays = []
        for m in _TRAY_RX.finditer(q):
            t = names.get(m.group(1).lower(), m.group(1).lower())
            if t not in named_trays:
                named_trays.append(t)
        for t, b in gpus:
            out += tray_lines(scan, t, b)
        for t in named_trays:
            if not any(g[0] == t for g in gpus):
                out += tray_lines(scan, t)
            if not any(x.get("tray") == t for x in scan.get("links") or []):
                nc = [x for x in scan.get("not_checked") or [] if x.get("node") == t]
                out.append(f"{t}: no GPU link of it in this check" + (f" - not read: {str(nc[0].get('error'))[:160]}" if nc else
                           " (the tray was not read or reports no GPUs), so its cabling is not known from this check"))
    for m in _MAC_RX.finditer(q):
        mac = m.group(1).lower()
        hit = (macs or {}).get(mac)
        out.append(f"MAC {mac}: " + (f"static forwarding entry on {hit['switch']} {hit.get('ns') or ''} {hit['port']} Vlan{hit.get('vlan')}"
                                     if hit else "not in the forwarding tables this check read"))
    for m in re.finditer(r"\b(?:(st\d+)\s+(?:asic\d\s+)?)?(Ethernet\d+)\b", q, re.I):
        sw, port = (m.group(1) or "").lower(), m.group(2)
        for x in [x for x in scan.get("links") or [] if x.get("sw_port") == port and (not sw or x.get("switch") == sw)][:3]:
            ms = [k for k, v in (macs or {}).items() if v.get("switch") == x["switch"] and v.get("port") == port]
            out.append(f"{x['switch']} {x.get('asic') or ''} {port} <-> {x.get('tray') or '?'} "
                       + (gpu_label(scan, x['tray'], x['bdf']) if x.get("tray") and x.get("bdf") else "GPU ?")
                       + f" port {x.get('gpu_port')}; described as '{x.get('desc') or ''}'; state {x.get('state')}"
                       + (f"; VLAN {', '.join(v for v, _m in x['vlans'])}" if x.get("vlans") else "")
                       + (f"; forwarding entry MAC {', '.join(ms)}" if ms else ""))
    unread = [x.get("node") for x in scan.get("not_checked") or [] if x.get("role") == "switch"]
    if out and unread:
        out.append(f"This check could not read switch(es) {', '.join(unread)}: their GPU links are missing above "
                   f"(a GPU has 36 links; here fewer are listed)")
    return out[:30]


def mac_index(raw_switches: dict) -> dict:
    """{mac: {switch, ns, port, vlan, type}} from a check's raw switch read (static forwarding entries)."""
    out = {}
    for sw, s in (raw_switches or {}).items():
        for ns, a in ((s or {}).get("asics") or {}).items():
            for r in a.get("fdb") or []:
                mac = str(r.get("MacAddress") or "").lower()
                if mac:
                    out[mac] = {"switch": sw, "ns": ns, "port": r.get("Port"), "vlan": r.get("Vlan"), "type": r.get("Type")}
    return out
