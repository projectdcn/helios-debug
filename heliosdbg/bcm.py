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
SONiC EthernetN -> Broadcom port: the port's first lane (``show interfaces status`` Lanes) is the physical port in
``show pmap``; e.g. st6 Ethernet261 lanes 201,202 -> cd100, logical port 220.
"""
from __future__ import annotations

import re
import shlex

LANE_FIELDS = ("RX_SIGNAL_DETECT", "TX_SQUELCH", "RX_SQUELCH")
LANE2_FIELDS = ("RX_SNR", "EYE_UP", "EYE_DOWN", "AM_LOCK_LIVE", "LINK_TIME")
SNR_INVALID = 99900                       # what RX_SNR reads on a lane with no signal
SEP = "@@HELIOS-BCM@@"


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


def _view(name, lp, lane_ids, parts) -> dict:
    st, fec = parse_lt(parts[0]), parse_lt(parts[1])
    lanes_out = []
    for i in range(len(lane_ids)):
        a, b = parse_lt(parts[2 + 2 * i]), parse_lt(parts[3 + 2 * i])
        lanes_out.append({k: a.get(k) for k in LANE_FIELDS} | {k: b.get(k) for k in LANE2_FIELDS})
    return {"bcm_port": name, "logical": lp, "lanes_sonic": lane_ids,
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
    bins = v.get("fec_bins") or []
    worst = max([k for k, c in enumerate(bins[1:16], 1) if c] or [0]) if bins else None
    return (f"{v['bcm_port']}: signal {sig}/{len(ln)} lanes, lock {p.get('PMD_LANE_RX_LOCK')}, training "
            f"{'done' if p.get('LINK_TRAINING_DONE') else 'not done'}, SNR "
            f"{(str(min(snrs)) + '-' + str(max(snrs))) if snrs else 'n/a'}, eye up {min(eyes) if eyes else 'n/a'}+"
            f", FEC worst {worst if worst is not None else 'n/a'}/15 uncorr {(v.get('fec') or {}).get('FEC_UNCORRECTED_CODEWORDS')}")


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
    ev = [f"Broadcom {v['bcm_port']} (logical {v['logical']}): PMD_RX_LOCK {p.get('PMD_RX_LOCK')}, lane lock mask "
          f"{p.get('PMD_LANE_RX_LOCK')}, link training {'done' if p.get('LINK_TRAINING_DONE') else 'not done'}, "
          f"local fault {p.get('LOCAL_FAULT')}, remote fault {p.get('REMOTE_FAULT')}"]
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
    if p.get("LOCAL_FAULT") or p.get("REMOTE_FAULT"):
        return f"PCS fault: local {p.get('LOCAL_FAULT')}, remote {p.get('REMOTE_FAULT')}", ev
    if oper_down:
        return ("flapping: SONiC had the port down, but moments later the ASIC had it locked and trained on every lane "
                "with signal - the link drops and comes back; scan again or watch the counters, and check the cable "
                "seating"), ev
    return "", ev
