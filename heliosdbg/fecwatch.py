"""Watch FEC: read every link's FEC twice, minutes apart, and say what changed in between - read-only, nothing is
cleared. The JTAC 'SONiC Interface' deck (9 Nov 2026): FEC counters are cumulative since the last clear, so the signal
is the delta, not the total; clearing (portstat -c / sonic-clear fecstats) changes the switch and loses the history.
The difference of two histogram reads is the histogram of the window: its deepest bin is how close the link came to
the cliff while we watched.

Switch end: show interfaces counters fec-stats, portstat -fh and show interfaces flap per chip. GPU end: afmctl show
port statistics fec -p 0-35 per GPU (histogram, uncorrectables, link up count).
"""
from __future__ import annotations

from . import l1
from .afmctl import Afmctl


def ns_flag(ns) -> str:
    return f" -n {ns}" if ns else ""


def read_switch(sw) -> dict:
    """{asic: {"fec": {port: {...}}, "hist": {port: bins}, "flaps": {port: count}}}."""
    out = {}
    for ns in sw.namespaces():
        fec = l1.fec_stats(sw.sh(f"show interfaces counters fec-stats{ns_flag(ns)}", timeout=180))
        hist = {h["port"]: h["bins"] for h in l1.histograms(sw.sh(f"portstat -fh{ns_flag(ns)}", timeout=180)) if h["port"]}
        try:
            flaps = {p: v["count"] for p, v in l1.flaps(sw.sh(f"show interfaces flap{ns_flag(ns)}", timeout=180)).items()}
        except Exception:  # noqa: BLE001 - an older image without 'show interfaces flap': the FEC is still compared
            flaps = {}
        out[ns or ""] = {"fec": fec, "hist": hist, "flaps": flaps}
    return out


def read_tray(tray) -> dict:
    """{bdf: {port: {"bins", "uncorr", "link_up"}}}."""
    a, out = Afmctl(tray), {}
    for d in a.devices():
        out[d.bdf] = {h["port"]: {"bins": h["bins"], "uncorr": h["uncorr"], "link_up": h["link_up"]}
                      for h in l1.histograms(a.fec_stats(d.bdf)) if h["port"] is not None}
    return out


def _d(a, b) -> int:
    return max(0, (b or 0) - (a or 0))


def compare(sw0: dict, sw1: dict, tr0: dict, tr1: dict, seconds: float) -> dict:
    """One row per port read both times: what grew in the window."""
    rows = []
    for swn, chips in sw1.items():
        for ns, now in chips.items():
            was = (sw0.get(swn) or {}).get(ns) or {}
            for p, f1 in now["fec"].items():
                f0 = (was.get("fec") or {}).get(p)
                if f0 is None:
                    continue
                h0, h1 = (was.get("hist") or {}).get(p), now["hist"].get(p)
                win = [_d(x, y) for x, y in zip(h0, h1)] if h0 and h1 else None
                rows.append({"end": "switch", "node": swn, "asic": ns, "port": p, "state": f1["state"],
                             "uncorr": _d(f0["uncorr"], f1["uncorr"]), "corr": _d(f0["corr"], f1["corr"]),
                             "window_max_t": l1.max_t(win) if win and any(win) else None,
                             "max_t": l1.max_t(h1) if h1 else None,
                             "flaps": _d((was.get("flaps") or {}).get(p), now["flaps"].get(p)) if now["flaps"] else None})
    for tn, gpus in tr1.items():
        for bdf, ports in gpus.items():
            for p, g1 in ports.items():
                g0 = ((tr0.get(tn) or {}).get(bdf) or {}).get(p)
                if g0 is None:
                    continue
                win = [_d(x, y) for x, y in zip(g0["bins"], g1["bins"])]
                rows.append({"end": "gpu", "node": tn, "asic": bdf, "port": p, "state": "",
                             "uncorr": _d(g0["uncorr"], g1["uncorr"]), "corr": sum(win[1:]),
                             "window_max_t": l1.max_t(win) if any(win[1:]) else None, "max_t": l1.max_t(g1["bins"]),
                             "flaps": _d(g0["link_up"], g1["link_up"])})
    return {"seconds": round(seconds), "rows": rows}


def _name(r: dict) -> str:
    return (f"{r['node']} {r['port']}" if r["end"] == "switch" else f"{r['node']} GPU {r['asic']} port {r['port']}")


def summary(rep: dict) -> list[str]:
    rows = rep["rows"]
    mins = rep["seconds"] / 60
    lost = sorted((r for r in rows if r["uncorr"]), key=lambda r: -r["uncorr"])
    cliff = [r for r in rows if (r["window_max_t"] or 0) >= 12]
    worse = [r for r in rows if 6 <= (r["window_max_t"] or 0) < 12]
    flap = [r for r in rows if r["flaps"]]
    sw, gp = sum(r["end"] == "switch" for r in rows), sum(r["end"] == "gpu" for r in rows)
    lines = [f"FEC watched for {mins:.1f} min: {sw} switch ports and {gp} GPU ports read twice (nothing cleared)."]
    lines.append(f"Lost frames in the window (uncorrectable grew) on {len(lost)} port(s)" + (
        ": " + ", ".join(f"{_name(r)} +{r['uncorr']:,}" for r in lost[:12]) if lost else "."))
    lines.append(f"At the cliff in the window (a codeword needed 12+ of 15 symbols) on {len(cliff)} port(s)" + (
        ": " + ", ".join(f"{_name(r)} {r['window_max_t']} of 15" for r in cliff[:12]) if cliff else "."))
    lines.append(f"Degrading in the window (6-11 of 15) on {len(worse)} port(s)" + (
        ": " + ", ".join(f"{_name(r)} {r['window_max_t']}" for r in sorted(worse, key=lambda r: -r["window_max_t"])[:12])
        if worse else "."))
    lines.append(f"Went down and came back in the window on {len(flap)} port(s)" + (
        ": " + ", ".join(_name(r) for r in flap[:12]) if flap else "."))
    if not (lost or cliff or worse or flap):
        lines.append("Every link stayed within bins 0-5 while watched: nothing is losing margin right now.")
    else:
        lines.append("Next: for each port named, compare both ends of its link (the end with the deeper tail receives "
                     "worse); a link that keeps losing frames or sits at the cliff is a reseat / swap of that one cable "
                     "(changes the rack: with a go-ahead).")
    return lines
