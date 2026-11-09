"""Link-level (L1) readings, read by code: FEC counters and histograms (the switch: show interfaces counters fec-stats /
fec-histogram, portstat -f / -fh; the GPU end: afmctl show port statistics fec), port flaps (show interfaces flap), the
retimers (gearboxutil interfaces status), a port's records in the SONiC databases (sonic-db-cli ... hgetall) and a GPU
port's anomaly counters (afmctl show device health --detail).

The rules are the JTAC 'SONiC Interface' deck's (J. Buchsteiner, Nov 2026), as they apply to the QFX5252 / MI450X fabric
(checked on g02-g17 st1, SONiC 202505, 9 Nov): KP4 RS-FEC corrects up to 15 symbols per codeword - the deepest non-zero
histogram bin (MAX_T) 0-5 is a comfortable margin, 12 or more is close to the cliff, and uncorrectable codewords must stay
0; on the GPU end a 'Link up count' above 1 means the port went down and came back. The retimers pass FEC through: the
switch chip and the GPU are the two ends that count it.
"""
from __future__ import annotations

import re
from datetime import datetime

T = 15                                   # KP4: symbols one codeword can have corrected


def _n(s: str) -> int:
    return int(s.replace(",", ""))


# ------------------------------------------------------------------ FEC counters (show interfaces counters fec-stats)

_FEC_ROW = re.compile(r"^\s*(Ethernet\d+)\s+([UDX])\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+(\S+)\s+(\S+)\s+(\S+)", re.M)


def fec_stats(text: str) -> dict:
    """{port: {state, corr, uncorr, sym, pre_ber_max}} from 'show interfaces counters fec-stats' / 'portstat -f'."""
    out = {}
    for p, st, corr, unc, sym, _pre, _post, peak in _FEC_ROW.findall(text or ""):
        out[p] = {"state": st, "corr": _n(corr), "uncorr": _n(unc), "sym": _n(sym), "pre_ber_max": peak}
    return out


def _ber(x: str) -> float:
    try:
        return float(x)
    except ValueError:
        return -1.0


def fec_line(text: str) -> str | None:
    """A whole chip's FEC table (~257 rows) in one line; None under 8 rows."""
    f = fec_stats(text)
    if len(f) < 8:
        return None
    st = {k: sum(1 for v in f.values() if v["state"] == k) for k in "UDX"}
    unc = sorted(((p, v["uncorr"]) for p, v in f.items() if v["uncorr"]), key=lambda x: -x[1])
    peak = sorted(((p, v["pre_ber_max"]) for p, v in f.items() if _ber(v["pre_ber_max"]) > 0), key=lambda x: -_ber(x[1]))
    return (f"FEC counters: {len(f)} ports ({st['U']} up, {st['D']} down, {st['X']} shut) since the counters were cleared; "
            + (f"uncorrectable codewords on {len(unc)} ports (most: {', '.join(f'{p} {n:,}' for p, n in unc[:4])}) - a count "
               "that does not grow between two reads is from the link coming up, not live loss" if unc
               else "no uncorrectable codewords on any port")
            + (f"; highest pre-FEC BER peak {peak[0][1]} on {peak[0][0]} (KP4 corrects up to 2.4e-4)" if peak else ""))


# ------------------------------------------------------------------ FEC histograms (switch and GPU end)

_BIN = re.compile(r"^\s*BIN(\d+)\s+([\d,]+)\s*$", re.M)
_FH_ROW = re.compile(r"^\s*(Ethernet\d+)\s+((?:[\d,]+\s+){15}[\d,]+)\s*$", re.M)
_AFM_BIN = re.compile(r"FEC CW symbol errs (\d+)\s*:\s*(\d+)")


def histograms(text: str) -> list[dict]:
    """[{who, bins (16), uncorr, link_up}] - one per port the output shows."""
    t = text or ""
    out = []
    b = {int(i): _n(v) for i, v in _BIN.findall(t)}
    if len(b) >= 8:
        out.append({"who": "", "bins": [b.get(i, 0) for i in range(T + 1)], "uncorr": None, "link_up": None})
    for p, row in _FH_ROW.findall(t):
        out.append({"who": p, "bins": [_n(x) for x in row.split()], "uncorr": None, "link_up": None})
    for blk in re.split(r"(?=^BDF\s*:)", t, flags=re.M):
        a = {int(i): int(v) for i, v in _AFM_BIN.findall(blk)}
        if len(a) >= 8:
            bdf = re.search(r"^BDF\s*:\s*(\S+)", blk, re.M)
            port = re.search(r"Port id\s*:\s*(\d+)", blk)
            unc = re.search(r"uncorrectable\s*:\s*(\d+)", blk)
            up = re.search(r"Link up count\s*:\s*(\d+)", blk)
            out.append({"who": f"GPU {bdf.group(1) if bdf else '?'} port {port.group(1) if port else '?'}",
                        "bins": [a.get(i, 0) for i in range(T + 1)], "uncorr": int(unc.group(1)) if unc else None,
                        "link_up": int(up.group(1)) if up else None})
    return out


def max_t(bins: list[int]) -> int:
    return max((i for i, n in enumerate(bins) if n), default=0)


def hist_says(h: dict) -> str:
    k = max_t(h["bins"])
    s = (f"deepest corrected codeword {k} of {T} symbols (MAX_T {k}, {h['bins'][k]:,} codeword{'s' if h['bins'][k] != 1 else ''}"
         f" there) - " + ("a comfortable margin" if k <= 5 else "less margin: watch it" if k < 12
                          else "close to the cliff: a slightly worse codeword is uncorrectable"))
    if h["uncorr"] is not None:
        s += (", no uncorrectable codewords" if not h["uncorr"] else f", {h['uncorr']:,} uncorrectable codewords - frames lost")
    if h["link_up"] is not None:
        s += (f", link up count {h['link_up']} (" + ("up once: no flap since the counters started" if h["link_up"] <= 1
              else f"came up {h['link_up']} times: it went down and back {h['link_up'] - 1} time(s)") + ")")
    return s


# ------------------------------------------------------------------ flaps (show interfaces flap)

_FLAP = re.compile(r"^\s*(Ethernet\d+)\s+(\d+)\s+(Up|Down)\s+(Up|Down)\s+(Never|\w{3} \w{3} \d\d \d\d:\d\d:\d\d \d{4})"
                   r"\s+(Never|\w{3} \w{3} \d\d \d\d:\d\d:\d\d \d{4})", re.M)


def _t(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def flaps(text: str) -> dict:
    return {p: {"count": int(n), "admin": a, "oper": o, "down": d, "up": u} for p, n, a, o, d, u in _FLAP.findall(text or "")}


def flap_says(p: str, f: dict) -> str:
    d, u = _t(f["down"]), _t(f["up"])
    s = f"{p}: flap count {f['count']}, admin {f['admin']}, oper {f['oper']}"
    if d and u and u >= d:
        s += f"; last went down {f['down']} UTC and came back {int((u - d).total_seconds())} s later"
    elif d:
        s += f"; down since {f['down']} UTC" + (f" (last up {f['up']})" if u else "")
    elif u:
        s += f"; never went down since it first came up ({f['up']} UTC)"
    return s


def flap_line(text: str) -> str | None:
    f = flaps(text)
    if len(f) < 8:
        return None
    down = [p for p, v in f.items() if v["oper"] == "Down"]
    many = sorted(f.items(), key=lambda x: -x[1]["count"])
    latest = max(((p, _t(v["down"])) for p, v in f.items() if _t(v["down"])), key=lambda x: x[1], default=None)
    return (f"Flaps: {len(f)} ports, {len(down)} down now; flap counts from {min(v['count'] for v in f.values())} to "
            f"{many[0][1]['count']} (most: {', '.join(f'{p} {v['count']}' for p, v in many[:4])})"
            + (f"; the latest link-down: {latest[0]} at {latest[1]:%a %b %d %H:%M:%S %Y} UTC" if latest else ""))


# ------------------------------------------------------------------ retimers (gearboxutil interfaces status)

_GB = re.compile(r"^\s*(\d+)\s+(Ethernet\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(up|down)\s+(up|down)\s*$", re.M)


def gearbox(text: str) -> dict:
    return {p: {"phy": int(ph), "mac_lanes": ml, "line_lanes": ll, "oper": o, "admin": a}
            for ph, p, ml, _ms, _pl, _ps, ll, _ls, o, a in _GB.findall(text or "")}


def gearbox_line(text: str) -> str | None:
    g = gearbox(text)
    if len(g) < 8:
        return None
    down = [p for p, v in g.items() if v["oper"] == "down"]
    return (f"Retimers (gearbox): {len(g)} ports behind {len({v['phy'] for v in g.values()})} retimer PHYs; {len(g) - len(down)} "
            f"up, {len(down)} down" + (f" ({' '.join(down[:12])}{' ...' if len(down) > 12 else ''})" if down else ""))


# ------------------------------------------------------------------ a port's database records, GPU port anomalies

_DB = re.compile(r"sonic-db-cli(?:\s+-n\s+(asic\d))?\s+(\w+_DB)\s+hgetall\s+['\"]?([^'\"\s]+)", re.I)
_KEEP = ("admin_status", "oper_status", "netdev_oper_status", "state", "flap_count", "mtu", "speed", "fec", "lanes",
         "description", "last_down_time", "last_up_time")


def db_fact(cmd: str, out: str) -> str | None:
    m = _DB.search(cmd or "")
    if not m or not (out or "").strip().startswith("{"):
        return None
    kv = dict(re.findall(r"'([\w-]+)': '([^']*)'", out))
    if not kv:
        return f"{m.group(2)} {m.group(3)}: no such record (the key is missing from this database)"
    return f"{m.group(2)} {m.group(3)}: " + ", ".join(f"{k} {kv[k]}" for k in _KEEP if k in kv)


def anomalies(text: str) -> list[tuple[str, int]]:
    blk = (text or "").split("Anomalies:", 1)
    if len(blk) < 2:
        return []
    return sorted(((k.strip(), int(v)) for k, v in re.findall(r"^\s+([A-Za-z][\w ]+?):\s*(\d+)\s*$", blk[1], re.M)
                   if int(v) and not k.strip().startswith("Perfmon")), key=lambda x: -x[1])   # Perfmon: timers, not faults


# ------------------------------------------------------------------ for the guide

def compact(text: str) -> str | None:
    """A whole chip's FEC / flap / retimer table in one line (the model saw ~30 of 257 rows), None for anything else."""
    return fec_line(text) or flap_line(text) or gearbox_line(text)


def facts(i: int, node: str, where: str, cmd: str, out: str) -> list[str]:
    """What one step's L1 output shows, read by code."""
    got = []
    line = compact(out) if not out.startswith(("FEC counters:", "Flaps:", "Retimers")) else out.split("\n", 1)[0]
    if line:
        got.append(f"[S{i}] {where}: {line}")
    f = fec_stats(out)
    for p, v in f.items() if 0 < len(f) <= 6 else []:
        got.append(f"[S{i}] {where} {p} FEC: {v['corr']:,} corrected, {v['uncorr']:,} uncorrectable codewords, "
                   f"pre-FEC BER peak {v['pre_ber_max']} (counted since the counters were cleared)")
    port = (re.search(r"\b(Ethernet\d+)\b", cmd or "") or [None, ""])[1]
    for h in histograms(out):
        got.append(f"[S{i}] {node} {h['who'] or port or 'port'} FEC histogram: {hist_says(h)}")
    fl = flaps(out)
    for p, v in fl.items() if 0 < len(fl) <= 6 else []:
        got.append(f"[S{i}] {where} {flap_says(p, v)}")
    g = gearbox(out)
    for p, v in g.items() if 0 < len(g) <= 6 else []:
        got.append(f"[S{i}] {where} {p} retimer PHY {v['phy']}: oper {v['oper']}, admin {v['admin']} (MAC lanes "
                   f"{v['mac_lanes']}, line lanes {v['line_lanes']})")
    d = db_fact(cmd, out)
    if d:
        got.append(f"[S{i}] {where} {d}")
    an = anomalies(out)
    if an:
        got.append(f"[S{i}] {node} GPU port anomaly counters (since the counters started): "
                   + ", ".join(f"{k} {v:,}" for k, v in an[:6]))
    return got


_CLEAN = re.compile(r"\bno (?:FEC )?errors\b|\berror[- ]free\b|\bno uncorrectable\b", re.I)
_NO_FLAP = re.compile(r"\bnever flapped\b|\bno flaps?\b|\bhas not flapped\b|\bdid not flap\b", re.I)


def contradictions(i: int, node: str, out: str, text: str) -> list[str]:
    got = []
    unc = [h for h in histograms(out) if h["uncorr"]] + [
        {"who": p, "uncorr": v["uncorr"]} for p, v in fec_stats(out).items() if v["uncorr"]][:1]
    if unc and re.search(r"\bno uncorrectable\b", text or "", re.I):
        got.append(f"it says there are no uncorrectable codewords, but [S{i}] on {node} shows {unc[0]['uncorr']:,}")
    fl = flaps(out)
    flapped = [p for p, v in fl.items() if v["count"] > 1] if len(fl) <= 6 else []
    flapped += [h["who"] for h in histograms(out) if (h["link_up"] or 0) > 1]
    if flapped and _NO_FLAP.search(text or ""):
        got.append(f"it says it never flapped, but [S{i}] on {node} shows {flapped[0]} went down and came back")
    return got
