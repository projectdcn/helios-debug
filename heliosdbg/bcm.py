"""Broadcom shell (bcmcmd) view of switch ports: what the switch ASIC's SerDes sees on each lane.

Read-only: ``show pmap``, ``bsh -c "PortStatus"`` and logical-table lookups (``lt <TABLE> lookup``) only - never
``prbs``, ``eyescan``, loopback or any set / insert. Verified on g02-g17 (QFX5252, SONiC, SDK 6.5.34 LTSW / SDKLT,
18 Oct 2026); ``portmod`` / ``phy diag`` do not exist on these LTSW chips.

Per port:
  PC_PORT_STATUS   PMD_RX_LOCK, PMD_LANE_RX_LOCK (lane bit mask), LINK_TRAINING(_DONE), LOCAL_FAULT, REMOTE_FAULT
  PC_PHY_STATUS    per lane: RX_SIGNAL_DETECT, TX_SQUELCH, RX_SQUELCH
  PC_PHY_STATUS_2  per lane: RX_SNR, EYE_UP / EYE_DOWN (3 PAM4 eyes), AM_LOCK_LIVE, LINK_TIME
  PC_PORT_CUMULATIVE_DIAG_STATS  FEC codeword histogram: bin k = codewords with k symbol errors, the last bin =
                   uncorrectable (RS544: up to 15 correctable) - how close the link runs to the FEC limit
  LM_LINK_STATE    the link manager's view: PHY_LINK, LINK_STATE, LOCAL_FAULT, REMOTE_FAULT (mr2 4 Nov: LOCAL_FAULT=1
                   here on a dark port while PC_PORT_STATUS read 0)
  PC_PORT          the port's configuration: ENABLE, SPEED, NUM_LANES, FEC_MODE, LINK_TRAINING, AUTONEG, LOOPBACK_MODE
  PC_FDR_STATS     the same FEC histogram over the last window only (FDR_START_TIME / FDR_END_TIME, ns; ~19 s on mr2)
  CTR_MAC_ERR      MAC error counters: RX_FCS_ERR_PKT, RX_CODE_ERR_PKT, TX_ERR_PKT, ...
SONiC EthernetN -> Broadcom port: the port's first lane (``show interfaces status`` Lanes) is the physical port in
``show pmap``; e.g. st6 Ethernet261 lanes 201,202 -> cd100, logical port 220.
"""
from __future__ import annotations

import re
import shlex

LANE_FIELDS = ("RX_SIGNAL_DETECT", "TX_SQUELCH", "RX_SQUELCH")
LANE2_FIELDS = ("RX_SNR", "EYE_UP", "EYE_DOWN", "AM_LOCK_LIVE", "LINK_TIME")
NEAR_FEC_LIMIT = 10                       # worst corrected codeword (of 15) in the FDR window: close to the limit
SNR_INVALID = 99900                       # what RX_SNR reads on a lane with no signal
SEP = "@@HELIOS-BCM@@"
CFG_FIELDS = ("ENABLE", "SPEED", "NUM_LANES", "FEC_MODE", "LINK_TRAINING", "AUTONEG", "LOOPBACK_MODE", "MAX_FRAME_SIZE")
CFG_MATCH = ("SPEED", "NUM_LANES", "FEC_MODE", "LINK_TRAINING", "AUTONEG")     # what two ports of one rack share
MAC_ERRS = ("RX_FCS_ERR_PKT", "RX_CODE_ERR_PKT", "TX_ERR_PKT", "TX_FCS_ERR_PKT", "RX_UNDER_SIZE_PKT", "RX_JABBER_PKT",
            "RX_FRAGMENT_PKT", "RX_RUNT_PKT", "TX_FIFO_UNDER_RUN_PKT", "RX_MTU_CHECK_ERR_PKT")


def port_cmds(lp: int) -> list[str]:
    """The per-port reads after the lane reads (read_ports / _view keep this order)."""
    return [f'bsh -c "lt LM_LINK_STATE lookup PORT_ID={lp}"', f'bsh -c "lt PC_PORT lookup PORT_ID={lp}"',
            f'bsh -c "lt PC_FDR_STATS lookup PORT_ID={lp}"', f'bsh -c "lt CTR_MAC_ERR lookup PORT_ID={lp}"']


def unit_flag(ns: str | None) -> str:
    """bcmcmd unit for a SONiC namespace: asic1 -> ' -n 1'; single-ASIC switch -> ''."""
    m = re.search(r"(\d+)$", ns or "")
    return f" -n {m.group(1)}" if m else ""


def _int(v: str):
    m = re.match(r"^\s*(0x[0-9a-fA-F_]+|-?\d+)", v)
    if not m:
        return v.strip()
    s = m.group(1).replace("_", "")
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def parse_lt(text: str) -> dict:
    """``lt X lookup`` output -> {FIELD: value}; arrays ``F[0-1]=a,F[2-7]=b`` -> list; symbols stay strings."""
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line or line.startswith(("lookup", "Table", "bsh", "ERROR")):
            continue
        for part in re.split(r",(?=[A-Z_0-9]+(?:\[[\d-]+\])?=)", line):
            m = re.match(r"^([A-Z_0-9]+)(?:\[(\d+)(?:-(\d+))?\])?=(.*)$", part.strip())
            if not m:
                continue
            name, lo, hi, val = m.group(1), m.group(2), m.group(3), _int(m.group(4))
            if lo is None:
                out[name] = val
                continue
            arr = out.setdefault(name, [])
            if not isinstance(arr, list):
                arr = out[name] = []
            for i in range(int(lo), int(hi or lo) + 1):
                while len(arr) <= i:
                    arr.append(None)
                arr[i] = val
    return out


def parse_pmap(text: str) -> dict[int, tuple[str, int]]:
    """``show pmap`` -> {physical port: (name, logical port)}."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[1].isdigit() and f[2].isdigit() and f[3].isdigit():
            out[int(f[3])] = (f[0], int(f[2]))
    return out


def _script(unit: str, cmds: list[str]) -> str:
    """One shell line running several bcmcmd commands (one SSH round trip); stdin closed - bcmcmd reads it."""
    return "; ".join(f"sudo -n timeout 60 bcmcmd{unit} {shlex.quote(c)} </dev/null 2>&1; echo {SEP}" for c in cmds)


def port_map(sw, ns) -> dict[int, tuple[str, int]]:
    return parse_pmap(sw.run(_script(unit_flag(ns), ["show pmap"]), timeout=120).stdout)


PORTS_PER_CALL = 8      # ports read per SSH round trip (each still one bcmcmd call per table lookup)


def read_ports(sw, ns, ports: dict[str, str], pmap: dict | None = None) -> dict[str, dict]:
    """{EthernetN: lanes '201,202'} -> {EthernetN: bcm view} for one ASIC; a port that cannot be mapped gets
    {'error': ...}. Ports are read PORTS_PER_CALL at a time in one SSH round trip."""
    unit = unit_flag(ns)
    pmap = pmap if pmap is not None else port_map(sw, ns)
    out, jobs = {}, []
    for port, lanes in ports.items():
        lane_ids = [int(x) for x in re.findall(r"\d+", str(lanes or ""))]
        hit = pmap.get(lane_ids[0]) if lane_ids else None
        if not hit:
            out[port] = {"error": f"no Broadcom port for lanes '{lanes}' in show pmap"}
            continue
        name, lp = hit
        cmds = [f'bsh -c "lt PC_PORT_STATUS lookup PORT_ID={lp} STATUS=STATUS_ALL"',
                f'bsh -c "lt PC_PORT_CUMULATIVE_DIAG_STATS lookup PORT_ID={lp}"']
        for i in range(len(lane_ids)):
            cmds += [f'bsh -c "lt PC_PHY_STATUS lookup PORT_ID={lp} LANE_INDEX={i}"',
                     f'bsh -c "lt PC_PHY_STATUS_2 lookup PORT_ID={lp} LANE_INDEX={i} STATUS=STATUS_2_ALL"']
        cmds += port_cmds(lp)
        jobs.append((port, name, lp, lane_ids, cmds))
    for k in range(0, len(jobs), PORTS_PER_CALL):
        chunk = jobs[k:k + PORTS_PER_CALL]
        allc = [c for j in chunk for c in j[4]]
        r = sw.run(_script(unit, allc), timeout=60 + 30 * len(allc))
        parts = r.stdout.replace("\r", "").split(SEP)
        off = 0
        for port, name, lp, lane_ids, cmds in chunk:
            mine = parts[off:off + len(cmds)]
            off += len(cmds)
            if len(mine) < len(cmds):
                out[port] = {"error": f"bcmcmd answered {len(mine)} of {len(cmds)} commands (rc {r.rc})", "bcm_port": name}
                continue
            out[port] = _view(name, lp, lane_ids, mine)
    return out


def fdr(t: dict) -> dict | None:
    """PC_FDR_STATS -> {seconds, codewords, bins[0..16], uncorrectable, symbol_errors}; None when not read."""
    if "CODE_WORDS" not in t:
        return None
    bins = [t.get(f"CODE_WORD_S{k}_ERRORS" if k <= 8 else f"CODE_WORD_{k}_ERRORS") for k in range(17)]
    a, b = t.get("FDR_START_TIME"), t.get("FDR_END_TIME")
    return {"seconds": round((b - a) / 1e9, 1) if isinstance(a, int) and isinstance(b, int) and b > a else None,
            "codewords": t.get("CODE_WORDS"), "bins": [x if isinstance(x, int) else 0 for x in bins],
            "uncorrectable": t.get("UNCORRECTABLE_CODE_WORDS"), "symbol_errors": t.get("SYMBOL_ERRORS")}


def worst_bin(bins) -> int | None:
    """The most symbol errors any corrected codeword had (bins 1-15); None when there is no histogram."""
    return max([k for k, c in enumerate(bins[1:16], 1) if c] or [0]) if bins else None


def _view(name, lp, lane_ids, parts) -> dict:
    st, fec = parse_lt(parts[0]), parse_lt(parts[1])
    lanes_out = []
    for i in range(len(lane_ids)):
        a, b = parse_lt(parts[2 + 2 * i]), parse_lt(parts[3 + 2 * i])
        lanes_out.append({k: a.get(k) for k in LANE_FIELDS} | {k: b.get(k) for k in LANE2_FIELDS})
    more = [parse_lt(x) for x in parts[2 + 2 * len(lane_ids):]] + [{}] * 4
    lm, cfg, fd, me = more[:4]
    return {"link": {k: lm.get(k) for k in ("PHY_LINK", "LINK_STATE", "LOCAL_FAULT", "REMOTE_FAULT")} if lm else None,
            "cfg": {k: cfg.get(k) for k in CFG_FIELDS} if cfg else None,
            "fdr": fdr(fd),
            "mac_err": {k: me.get(k) for k in MAC_ERRS if isinstance(me.get(k), int)} if me else None,
            "bcm_port": name, "logical": lp, "lanes_sonic": lane_ids,
            "port": {k: st.get(k) for k in ("PMD_RX_LOCK", "PMD_LANE_RX_LOCK", "LINK_TRAINING",
                                            "LINK_TRAINING_DONE", "LOCAL_FAULT", "REMOTE_FAULT",
                                            "MAC_DISABLED", "PHY_DISABLED", "FEC_MODE")},
            "lane": lanes_out,
            "fec_bins": fec.get("FEC_CODE_WORD_ERROR_COUNTERS"),
            "fec": {k: fec.get(k) for k in ("FEC_CODEWORDS", "FEC_CORRECTED_CODEWORDS",
                                            "FEC_UNCORRECTED_CODEWORDS", "FEC_SYMBOL_ERRORS")},
            "raw": parts}


def brief(v: dict) -> str:
    """One line per port for a read of many ports: lanes with signal, lock mask, training, SNR / eye range, FEC."""
    if not v or v.get("error"):
        return f"not read: {v.get('error') if v else '?'}"
    p, ln = v["port"], v["lane"]
    sig = sum(1 for x in ln if x.get("RX_SIGNAL_DETECT") == 1)
    snrs = [x.get("RX_SNR") for x in ln if isinstance(x.get("RX_SNR"), int) and x.get("RX_SNR") != SNR_INVALID]
    eyes = [e for x in ln for e in (x.get("EYE_UP") or []) if isinstance(e, int) and e > 0]
    worst = worst_bin(v.get("fec_bins") or [])
    fd = v.get("fdr")
    return (f"{v['bcm_port']}: signal {sig}/{len(ln)} lanes, lock {p.get('PMD_LANE_RX_LOCK')}, training "
            f"{'done' if p.get('LINK_TRAINING_DONE') else 'not done'}, SNR "
            f"{(str(min(snrs)) + '-' + str(max(snrs))) if snrs else 'n/a'}, eye up {min(eyes) if eyes else 'n/a'}+"
            f", FEC worst {worst if worst is not None else 'n/a'}/15 uncorr {(v.get('fec') or {}).get('FEC_UNCORRECTED_CODEWORDS')}"
            + (f"; last {fd['seconds']} s worst {worst_bin(fd['bins'])}/15 uncorr {fd['uncorrectable']}" if fd else ""))


def reference_port(status: dict, exclude: set) -> tuple[str, str] | None:
    """A working trunk port of the ASIC (oper up, not one of the problem ports): (EthernetN, lanes) or None."""
    for port, r in sorted(status.items(), key=lambda kv: int(re.sub(r"\D", "", kv[0] or "") or 0)):
        if port not in exclude and r.get("Vlan") == "trunk" and str(r.get("Oper", "")).lower() == "up" and r.get("Lanes"):
            return port, r["Lanes"]
    return None


def _lanes(idx: list[int]) -> str:
    return ", ".join(str(i) for i in idx)


def _snr(lane: dict):
    v = lane.get("RX_SNR")
    return None if v in (None, SNR_INVALID) or not isinstance(v, int) else v


def judge(v: dict, ref: dict | None = None, oper_down: bool = False) -> tuple[str, list[str]]:
    """(finding, evidence lines) from one port's bcm view. The finding names the layer that fails on the switch
    side; '' when the bcm view shows nothing wrong.

    ``ref``: the bcm view of a working port on the same ASIC - what a clean lane reads on this rack (SNR / eye
    units are Broadcom's, so the comparison is relative, never an absolute threshold). ``oper_down``: SONiC
    reported the port down when the scan read it; a port the ASIC then sees fully locked came back in between
    (flapping)."""
    if not v or v.get("error"):
        return "", [f"Broadcom view not read: {v.get('error') if v else 'not collected'}"]
    p, ln = v["port"], v["lane"]
    n = len(ln)
    lm, cfg, fd = v.get("link") or {}, v.get("cfg") or {}, v.get("fdr")
    ev = [f"Broadcom {v['bcm_port']} (logical {v['logical']}): PMD_RX_LOCK {p.get('PMD_RX_LOCK')}, lane lock mask "
          f"{p.get('PMD_LANE_RX_LOCK')}, link training {'done' if p.get('LINK_TRAINING_DONE') else 'not done'}, "
          f"local fault {p.get('LOCAL_FAULT')}, remote fault {p.get('REMOTE_FAULT')}"]
    if lm:
        ev.append(f"  link manager (LM_LINK_STATE): PHY_LINK {lm.get('PHY_LINK')}, LINK_STATE {lm.get('LINK_STATE')}, "
                  f"local fault {lm.get('LOCAL_FAULT')}, remote fault {lm.get('REMOTE_FAULT')}")
    if cfg:
        ev.append("  configuration (PC_PORT): " + ", ".join(f"{k} {cfg.get(k)}" for k in CFG_FIELDS if cfg.get(k) is not None))
    for i, x in enumerate(ln):
        snr = x.get("RX_SNR")
        eyes = "/".join(str(e) for e in (x.get("EYE_UP") or []) if e is not None)
        ev.append(f"  lane {i}: signal detect {x.get('RX_SIGNAL_DETECT')}, TX squelch {x.get('TX_SQUELCH')}, "
                  f"RX_SNR {'n/a' if snr in (None, SNR_INVALID) else snr}, eye up {eyes or 'n/a'}")
    bins, unc = v.get("fec_bins") or [], (v.get("fec") or {}).get("FEC_UNCORRECTED_CODEWORDS")
    if bins:
        worst = max([k for k, c in enumerate(bins[1:16], 1) if c] or [0])
        ev.append(f"  FEC codewords since the counters started: worst corrected codeword had {worst} symbol errors "
                  f"(RS544 corrects up to 15), uncorrectable {unc}")
    if fd and not fd["codewords"]:
        ev.append("  FEC over the last window (PC_FDR_STATS): no codewords - nothing is received")
    elif fd:
        ev.append(f"  FEC over the last {fd['seconds'] if fd['seconds'] is not None else '?'} s (PC_FDR_STATS): "
                  f"{fd['codewords']} codewords, worst corrected {worst_bin(fd['bins'])} symbol errors, uncorrectable "
                  f"{fd['uncorrectable']}")
    errs = {k: c for k, c in (v.get("mac_err") or {}).items() if c}
    if errs:
        ev.append("  MAC error counters since they were cleared (CTR_MAC_ERR): " + ", ".join(f"{k} {c}" for k, c in errs.items()))
    ref_cfg = (ref or {}).get("cfg") or {}
    diffs = [f"{k} {cfg.get(k)} vs {ref_cfg.get(k)}" for k in CFG_MATCH
             if cfg.get(k) is not None and ref_cfg.get(k) is not None and cfg.get(k) != ref_cfg.get(k)]
    if diffs:
        ev.append(f"  configured differently from the working port {ref.get('bcm_port')}: " + ", ".join(diffs))
    if cfg.get("LOOPBACK_MODE") not in (None, "PC_LPBK_NONE"):
        return (f"the port is in loopback ({cfg.get('LOOPBACK_MODE')}): it talks to itself, never to the GPU - someone "
                f"ran a loopback test and did not end it; clear it the way it was set (a change - not from here)"), ev
    if cfg.get("ENABLE") == 0:
        return "the switch ASIC has the port disabled (PC_PORT ENABLE 0): it neither sends nor listens", ev
    no_sig = [i for i, x in enumerate(ln) if x.get("RX_SIGNAL_DETECT") == 0]
    tx_off = [i for i, x in enumerate(ln) if x.get("TX_SQUELCH") == 1]
    if no_sig and len(no_sig) == n:
        tx = ("its transmitter is squelched on lane(s) " + _lanes(tx_off)) if tx_off else "its own transmitter is on"
        return f"the switch receives no signal on any of its {n} lanes (RX_SIGNAL_DETECT 0) while {tx}", ev
    if no_sig:
        return (f"no signal on lane(s) {_lanes(no_sig)} of {n}, the other lane(s) have signal: one lane of the cable / "
                f"connector / cartridge"), ev
    ref_ok = bool(ref) and not ref.get("error") and ref.get("lane")
    ref_snr = min([x for x in (_snr(r) for r in ref["lane"]) if x is not None] or [0]) if ref_ok else 0
    if ref_ok:
        ev.append(f"  reference: working port {ref['bcm_port']} on the same ASIC, lowest lane RX_SNR {ref_snr or 'n/a'}")
    if diffs and (not p.get("PMD_RX_LOCK") or (p.get("LINK_TRAINING") and not p.get("LINK_TRAINING_DONE")) or oper_down):
        return (f"signal arrives but the port is configured differently from a working port of the same chip ("
                + ", ".join(diffs) + "): the two ends cannot agree - check the port's speed / FEC / training "
                "configuration against the rack's"), ev
    if not p.get("PMD_RX_LOCK"):
        snrs = [_snr(x) for x in ln]
        if all(x is not None for x in snrs) and ref_snr and min(snrs) >= 0.9 * ref_snr:
            return (f"a signal arrives on every lane and reads like a working lane's (RX_SNR {min(snrs)}, working port "
                    f"{ref_snr}), yet the receiver never locks (PMD_RX_LOCK 0): not a weak signal - check lane order, "
                    f"polarity and speed / FEC settings on both ends, or the GPU port's own PHY"), ev
        return ("signal arrives on every lane but the receiver cannot lock (PMD_RX_LOCK 0)"
                + (f", with a lower RX_SNR than a working port ({min(x for x in snrs if x is not None)} vs {ref_snr})"
                   if ref_snr and any(x is not None for x in snrs) else "")
                + ": marginal signal or a damaged lane"), ev
    if p.get("LINK_TRAINING") and not p.get("LINK_TRAINING_DONE"):
        return "the receiver locks but link training does not finish", ev
    lf, rf = p.get("LOCAL_FAULT") or lm.get("LOCAL_FAULT"), p.get("REMOTE_FAULT") or lm.get("REMOTE_FAULT")
    if rf and not lf:
        return ("remote fault: the switch receives the GPU and locks, but the GPU end signals it does not receive the "
                "switch - the switch-to-GPU direction (the switch's transmitter, that direction of the cable, or the "
                "GPU port's receiver)"), ev
    if lf or rf:
        return f"PCS fault: local {lf}, remote {rf} - the receiver locks but cannot align the data", ev
    if fd and fd["uncorrectable"]:
        return (f"the link is up but loses data: {fd['uncorrectable']} uncorrectable FEC codewords in the last "
                f"{fd['seconds']} s - a marginal lane; compare its SNR with the working port, reseat / clean the cable"), ev
    w = worst_bin(fd["bins"]) if fd else None
    if w is not None and w >= NEAR_FEC_LIMIT:
        return (f"the link is up but runs close to the FEC limit: codewords with {w} of the 15 correctable symbol errors "
                f"in the last {fd['seconds']} s - a marginal lane, it will drop data before long"), ev
    if oper_down:
        return ("flapping: SONiC had the port down, but moments later the ASIC had it locked and trained on every lane "
                "with signal - the link drops and comes back; scan again or watch the counters, and check the cable "
                "seating"), ev
    return "", ev


DELTA_FEC = ("FEC_CODEWORDS", "FEC_CORRECTED_CODEWORDS", "FEC_UNCORRECTED_CODEWORDS", "FEC_SYMBOL_ERRORS")


def delta(sw, ns, lp: int, wait: int = 10) -> dict:
    """The port's error counters read twice, ``wait`` s apart, in one SSH round trip: {seconds, fec: {F: d},
    mac: {F: d}} - what is happening now, not since the counters were cleared. {'error': ...} when not read."""
    reads = [f'bsh -c "lt PC_PORT_CUMULATIVE_DIAG_STATS lookup PORT_ID={lp}"', f'bsh -c "lt CTR_MAC_ERR lookup PORT_ID={lp}"']
    unit = unit_flag(ns)
    wait = max(1, min(int(wait), 60))
    r = sw.run(_script(unit, reads) + f"; sleep {wait}; " + _script(unit, reads), timeout=120 + wait)
    parts = r.stdout.replace("\r", "").split(SEP)
    if len(parts) < 4:
        return {"error": f"bcmcmd answered {len(parts) - 1} of 4 reads (rc {r.rc})"}
    (f0, m0, f1, m1) = (parse_lt(x) for x in parts[:4])
    def d(a, b, keys):
        return {k: b[k] - a[k] for k in keys if isinstance(a.get(k), int) and isinstance(b.get(k), int)}
    return {"seconds": wait, "fec": d(f0, f1, DELTA_FEC), "mac": d(m0, m1, MAC_ERRS)}


def judge_delta(dl: dict) -> str:
    """'' when no errors grew between the two reads; else what grew."""
    if not dl or dl.get("error"):
        return ""
    grew = {"FEC_UNCORRECTED_CODEWORDS": dl["fec"].get("FEC_UNCORRECTED_CODEWORDS", 0)} | dl["mac"]
    grew = [f"{k} +{c}" for k, c in grew.items() if c > 0]      # corrected codewords grow on every working link
    return (f"errors are growing now: {', '.join(grew)} in {dl['seconds']} s - the link loses frames; a marginal lane "
            f"or a dirty / loose connector") if grew else ""
