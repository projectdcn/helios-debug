"""Cabling plan check: the expected cabling (a CSV from the site) against what a scan found - no login needed.

Plan CSV, one row per switch port (header names are matched case-insensitively; '#' lines are comments):
    switch,port,slot,gpu,gpu_port          e.g.  st6,Ethernet257,17,2,13
  slot / gpu / gpu_port are the switch port description's Slot / GPU / Port numbers ('To ComputeTray Slot17/GPU2[..]/Port13');
  'tray' may replace 'slot' (the inventory name).
What the scan saw for each switch port: its description, and - when matched by the GPU port's own MAC in the switch
forwarding table, or named by the GPU port's IFCP peer - the real far end (tray, BDF, GPU port).
"""
from __future__ import annotations

import csv
import io

from .afmctl import parse_port_description

FIELDS = ("switch", "port", "slot", "gpu", "gpu_port")


def read_plan(text: str, tray_slots: dict[str, int] | None = None) -> list[dict]:
    rows = [r for r in (text or "").splitlines() if r.strip() and not r.lstrip().startswith("#")]
    if not rows:
        raise ValueError("empty plan")
    rd = csv.DictReader(io.StringIO("\n".join(rows)))
    head = {h.strip().lower(): h for h in rd.fieldnames or []}
    need = {"switch", "port", "gpu", "gpu_port"}
    if not need <= set(head) or not ({"slot", "tray"} & set(head)):
        raise ValueError("plan header needs switch, port, slot (or tray), gpu, gpu_port")
    out = []
    for i, r in enumerate(rd, 2):
        g = lambda k: (r.get(head[k]) or "").strip() if k in head else ""  # noqa: E731
        slot = g("slot")
        if not slot and g("tray"):
            if g("tray") not in (tray_slots or {}):
                raise ValueError(f"line {i}: slot of tray {g('tray')} unknown - give slot")
            slot = str(tray_slots[g("tray")])
        try:
            out.append({"switch": g("switch"), "port": g("port"), "slot": int(slot), "gpu": int(g("gpu")),
                        "gpu_port": int(g("gpu_port")), "line": i})
        except ValueError:
            raise ValueError(f"line {i}: slot, gpu and gpu_port must be numbers") from None
    return out


def export(links: list[dict]) -> str:
    """The cabling a scan saw, as a plan CSV (descriptions; a starting point to correct against the site's records)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(FIELDS)
    for ln in sorted(links, key=lambda x: (x["switch"], int("".join(c for c in x["sw_port"] if c.isdigit()) or 0))):
        cab = parse_port_description(ln.get("desc") or "")
        if cab:
            w.writerow([ln["switch"], ln["sw_port"], cab[0], cab[1], cab[3]])
    return buf.getvalue()


def check(plan: list[dict], links: list[dict], slots: dict[str, int], gpu_map: dict[str, str]) -> dict:
    """{problems: [...], ok: n, plan_rows: n}. gpu_map: learned {'tray:GPUg': bdf} of the scan; slots: {tray: slot}."""
    by_port = {(ln["switch"], ln["sw_port"]): ln for ln in links}
    tray_of_slot = {s: t for t, s in slots.items()}
    bdf_to_gpu = {(k.split(":GPU")[0], v): int(k.split(":GPU")[1]) for k, v in (gpu_map or {}).items() if ":GPU" in k}
    probs, ok, planned = [], 0, set()
    for p in plan:
        k = (p["switch"], p["port"])
        planned.add(k)
        want = f"Slot{p['slot']}/GPU{p['gpu']}/Port{p['gpu_port']}"
        ln = by_port.get(k)
        if ln is None:
            probs.append({"kind": "not_found", "switch": p["switch"], "port": p["port"], "plan": want,
                          "detail": "the scan has no GPU link on this switch port (not described as cabled to a tray, "
                                    "or the switch was not read)"})
            continue
        cab = parse_port_description(ln.get("desc") or "")
        bad = False
        if not cab or (cab[0], cab[1], cab[3]) != (p["slot"], p["gpu"], p["gpu_port"]):
            probs.append({"kind": "description", "switch": p["switch"], "port": p["port"], "plan": want,
                          "seen": ln.get("desc"), "detail": f"described as '{ln.get('desc')}', the plan says {want}"})
            bad = True
        real = None
        if ln.get("tray") and ln.get("bdf") is not None and ln.get("matched_by") == "mac":
            g = bdf_to_gpu.get((ln["tray"], ln["bdf"]))
            real = (slots.get(ln["tray"]), g, ln.get("gpu_port"))
        if ln.get("kind") == "miscabled":
            probs.append({"kind": "cabled_elsewhere", "switch": p["switch"], "port": p["port"], "plan": want,
                          "seen": ln.get("cause"), "detail": f"IFCP: {ln.get('cause')}"})
            bad = True
        elif real and None not in real and real != (p["slot"], p["gpu"], p["gpu_port"]):
            t = tray_of_slot.get(p["slot"], f"slot {p['slot']}")
            probs.append({"kind": "cabled_elsewhere", "switch": p["switch"], "port": p["port"], "plan": want,
                          "seen": f"Slot{real[0]}/GPU{real[1]}/Port{real[2]} ({ln['tray']} {ln['bdf']} port {ln['gpu_port']})",
                          "detail": f"{p['switch']} {p['port']} reaches {ln['tray']} {ln['bdf']} port {ln['gpu_port']}; "
                                    f"move the far end to {t} GPU{p['gpu']} port {p['gpu_port']}"})
            bad = True
        ok += not bad
    for k, ln in sorted(by_port.items()):
        if k not in planned and parse_port_description(ln.get("desc") or ""):
            probs.append({"kind": "not_in_plan", "switch": k[0], "port": k[1], "seen": ln.get("desc"),
                          "detail": "a GPU link the plan does not list"})
    return {"plan_rows": len(plan), "ok": ok, "problems": probs}
