"""Watch chosen links for a while (read-only): every N seconds both ends are read again - switch port admin / oper and
error / FEC counters, GPU port link / admin and its IFCP session - and every change is recorded. For links that come
and go, where a single scan or diagnosis happens to catch them up.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from .afmctl import Afmctl
from .linkdiag import COUNTERS, FEC, num
from .parsers import parse_table
from .rack import fan_out


def _ns(n):
    return f" -n {n}" if n else ""


def read_round(rack, links: list) -> dict:
    """{link key: {sw_oper, sw_admin, gpu_link, gpu_admin, ll_up, counters {...}}} - one read of every watched link."""
    by_sw: dict = {}
    for ln in links:
        by_sw.setdefault(ln.switch, set()).add(ln.asic)
    by_tray: dict = {}
    for ln in links:
        if ln.tray and ln.bdf:
            by_tray.setdefault(ln.tray, set()).add(ln.bdf)

    def sw_read(name):
        sw, res = rack.switches[name], {}
        for asic in by_sw[name]:
            n = asic or None
            st = {r.get("Interface"): r for r in parse_table(sw.sh(f"show interfaces status{_ns(n)} -d all", timeout=120))}
            cnt = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters{_ns(n)} -d all", timeout=120))}
            fec = {r.get("IFACE"): r for r in parse_table(sw.sh(f"show interfaces counters fec-stats{_ns(n)}", timeout=120))}
            res[asic] = (st, cnt, fec)
        return res

    def tray_read(name):
        a, res = Afmctl(rack.computes[name]), {}
        for bdf in by_tray[name]:
            res[bdf] = {int(p.get("id", p.get("port_id"))): p for p in a.ports_raw(bdf)}
        return res
    sws, trs = {}, {}
    for node, v, e in fan_out(lambda x: sw_read(x.host.name), [rack.switches[n] for n in by_sw]):
        sws[node.host.name] = (v, e)
    for node, v, e in fan_out(lambda x: tray_read(x.host.name), [rack.computes[n] for n in by_tray]):
        trs[node.host.name] = (v, e)
    out = {}
    for ln in links:
        k = key(ln)
        row = {"error": None}
        v, e = sws.get(ln.switch, (None, None))
        if e or v is None:
            row["error"] = f"switch: {type(e).__name__}: {str(e)[:100]}" if e else "switch not read"
        else:
            st, cnt, fec = v[ln.asic]
            s = st.get(ln.sw_port) or {}
            row["sw_oper"], row["sw_admin"] = str(s.get("Oper", "")).lower() or None, str(s.get("Admin", "")).lower() or None
            row["counters"] = {c: num((cnt.get(ln.sw_port) or {}).get(c)) for c in COUNTERS} | \
                              {c: num((fec.get(ln.sw_port) or {}).get(c)) for c in FEC}
        if ln.tray and ln.bdf:
            v, e = trs.get(ln.tray, (None, None))
            if e or v is None:
                row["error"] = (row["error"] + "; " if row["error"] else "") + (f"tray: {type(e).__name__}: {str(e)[:100]}" if e else "tray not read")
            else:
                p = (v.get(ln.bdf) or {}).get(ln.gpu_port) or {}
                st, sp = p.get("status") or {}, p.get("spec") or {}
                i = st.get("ifcp") or {}
                row["gpu_link"], row["gpu_admin"], row["ll_up"] = st.get("link_status"), sp.get("admin_state"), i.get("ll_up")
        out[k] = row
    return out


def key(ln) -> str:
    return f"{ln.switch} {ln.sw_port}"


FIELDS = ("sw_admin", "sw_oper", "gpu_admin", "gpu_link", "ll_up")
BAD = ("RX_ERR", "TX_ERR", "FEC_UNCORR")       # growth that is a problem; corrected FEC / drops are reported only


def state_of(row: dict) -> str:
    if row.get("error"):
        return "unread"
    up = row.get("sw_oper") == "up" and str(row.get("gpu_link") or "LINK_UP").upper() == "LINK_UP"
    return "up" if up and row.get("ll_up") in (None, "yes") else "down" if not up else "no-ifcp"


def run(rack, links: list, interval: float, duration: float, log=print, stop=lambda: False) -> dict:
    rounds, changes = [], []
    prev: dict = {}
    t_end = time.monotonic() + duration
    n = 0
    while True:
        t0 = time.monotonic()
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            cur = read_round(rack, links)
        except Exception as e:  # noqa: BLE001 - one bad round is recorded, the watch goes on
            cur = {key(ln): {"error": f"{type(e).__name__}: {str(e)[:120]}"} for ln in links}
        rounds.append({"t": stamp, "links": {k: {"state": state_of(v), **{f: v.get(f) for f in FIELDS}, "error": v.get("error")}
                                               for k, v in cur.items()}})
        for k, v in cur.items():
            p = prev.get(k)
            if p is not None:
                for f in FIELDS:
                    if v.get(f) != p.get(f) and not (v.get("error") or p.get("error")):
                        changes.append({"t": stamp, "link": k, "what": f, "from": p.get(f), "to": v.get(f)})
                for c, x in (v.get("counters") or {}).items():
                    y = (p.get("counters") or {}).get(c)
                    if x is not None and y is not None and x > y:
                        changes.append({"t": stamp, "link": k, "what": c, "from": y, "to": x, "delta": x - y})
            prev[k] = v if not v.get("error") else prev.get(k, v)
        n += 1
        flaps = sum(1 for c in changes if c["what"] == "sw_oper")
        log(f"round {n} {stamp}: " + ", ".join(f"{k} {state_of(v)}" for k, v in cur.items()) + (f"  ({flaps} link changes so far)" if flaps else ""))
        if time.monotonic() >= t_end or stop():
            break
        time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    per = {}
    for ln in links:
        k = key(ln)
        states = [r["links"][k]["state"] for r in rounds]
        per[k] = {"rounds": len(states), "up": states.count("up"), "down": states.count("down"), "no_ifcp": states.count("no-ifcp"),
                  "unread": states.count("unread"),
                  "link_changes": sum(1 for c in changes if c["link"] == k and c["what"] in ("sw_oper", "gpu_link")),
                  "errors_grew": {c["what"]: sum(x.get("delta", 0) for x in changes if x["link"] == k and x["what"] == c["what"])
                                  for c in changes if c["link"] == k and c.get("delta") and c["what"] in BAD},
                  "counters_grew": {c["what"]: sum(x.get("delta", 0) for x in changes if x["link"] == k and x["what"] == c["what"])
                                    for c in changes if c["link"] == k and c.get("delta") and c["what"] not in BAD}}
    return {"interval_s": interval, "duration_s": duration, "rounds": rounds, "changes": changes, "per_link": per}
