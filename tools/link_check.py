"""Scale-up link check: find down or degraded GPU links and their root cause, or check one GPU-to-GPU path.

    python tools/link_check.py scan --inventory <inv>                 # every link of the rack, root cause per problem
    python tools/link_check.py scan --inventory <inv> --interval 60   # longer error sample (default 30 s)
    python tools/link_check.py pingmap --inventory <inv> --rounds 6 --wait 300   # loss per port / ASIC, sticky or moving
    python tools/link_check.py path --inventory <inv> --src <tray> --src-bdf 0004:01:00.1 --dst-acc 8 --ports 25,26
    python tools/link_check.py path ... --no-ping                      # one path, without the L2 ping
    python tools/link_check.py bcm --inventory <inv> --switch st6 --ports Ethernet257,Ethernet261   # Broadcom shell view

Works on any rack described by an inventory (switches + compute trays, SSH access with sudo for afmctl and
`show mac`); no AFM password. Which switch port belongs to which GPU port is learned from the rack itself (each GPU
port's own MAC in the switches' forwarding tables), the switch port descriptions are the fallback. Read-only; `path`
also runs `afmctl test ping` unless --no-ping.

scan: per link (switch port <-> GPU port) the state (ok / degraded / down) and, for each problem, the root cause,
the evidence it rests on, who owns the fix and the next step. Bottom layer first: tray reachable, admin state on both
ends, physical link on both ends (never up / went down, one-sided), bit errors that GROW during the sample, IFCP
session, AFM forwarding entry. Problems sharing a cause are grouped (a powered-off tray is one line).

path: per GPU port of one source GPU and one destination accelerator: tray side, IFCP, the switch's forwarding entries
for both MACs (static, on a described, oper-up port, one ASIC), then the ping and the counters around it. The GPU
number in a switch port description is reported only: descriptions may number a tray's GPUs differently from afmctl.

Output (--out, default results/link-check/<rack>/<UTC time>/): report.html (self-contained, shareable),
report.txt, link_check.json, and the raw outputs read (raw/*.json.gz). A scan needs ~50 MB free.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from heliosdbg.afmctl import Afmctl, parse_port_description  # noqa: E402
from heliosdbg.inventory import load_inventory  # noqa: E402
from heliosdbg.linkdiag import GPU_LEVEL  # noqa: E402
from heliosdbg.parsers import parse_table  # noqa: E402
from heliosdbg.rack import Rack, fan_out  # noqa: E402

COUNTERS = ("RX_ERR", "RX_DRP", "RX_OVR", "TX_ERR", "TX_DRP", "TX_OVR")
FEC = ("FEC_UNCORR", "FEC_CORR", "FEC_SYMBOL_ERR")


def num(v) -> int | None:
    try:
        return int(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def tray_slot(tray) -> int | None:
    """The tray's AFM slot from the inventory (``slot:``); None = not checked (the rack itself is the reference)."""
    v = (tray.host.extra or {}).get("slot")
    return int(v) if str(v).lstrip("-").isdigit() else None


class Side:
    """One end of the path: a compute tray and one of its GPUs."""

    def __init__(self, tray, raw_dir: Path, tag: str):
        self.tray, self.name, self.a, self.raw, self.tag = tray, tray.host.name, Afmctl(tray), raw_dir, tag

    def save(self, what: str, text: str) -> None:
        (self.raw / f"{self.tag}-{self.name}-{what}.txt").write_text(text)

    def load(self):
        self.devs = self.a.devices()
        self.accels = self.a.vpod_accels()                      # {bdf: (own acc, {reachable accs})}
        self.addr = self.a.accel_addr()                         # {bdf: {port: {acc: mac}}}
        self.save("devices", json.dumps([d.__dict__ for d in self.devs], indent=1))
        return self

    def bdf_of_acc(self, acc: str) -> str | None:
        return next((b for b, (a, _) in self.accels.items() if a == str(acc)), None)

    def ports(self, bdf: str) -> dict[int, dict]:
        raw = self.a.ports_raw(bdf)
        self.save(f"ports-{bdf.replace(':', '_')}", json.dumps(raw, indent=1))
        out = {}
        for p in raw:
            st, sp = p.get("status") or {}, p.get("spec") or {}
            i = st.get("ifcp") or {}
            out[int(p.get("id", p.get("port_id")))] = {
                "admin": sp.get("admin_state"), "link": st.get("link_status"),
                "ll_up": i.get("ll_up"), "peer_enabled": i.get("peer_enabled"),
                "in_error": i.get("in_error"), "peer_in_error": i.get("peer_in_error")}
        return out


def switch_tables(rack, raw_dir: Path) -> dict:
    """Per switch and ASIC: FDB rows, port descriptions, oper/admin state - one pass over every switch."""
    def one(sw):
        out = {}
        for ns in sw.namespaces():
            fdb = sw.fdb(ns)
            desc = sw.port_descriptions(ns)
            status = {r.get("Interface"): r for r in parse_table(sw.sh(f"show interfaces status{' -n ' + ns if ns else ''} -d all"))}
            out[ns or ""] = {"fdb": fdb, "desc": desc, "status": status}
        (raw_dir / f"switch-{sw.host.name}.json").write_text(json.dumps(out, indent=1, default=str))
        return out
    res = {}
    for sw, val, exc in fan_out(one, list(rack.switches.values())):
        res[sw.host.name] = val if not exc else {"error": str(exc)}
    return res


def find_mac(tables: dict, mac: str) -> list[dict]:
    hits = []
    for swn, by_ns in tables.items():
        for ns, t in (by_ns.items() if "error" not in by_ns else []):
            for r in t["fdb"]:
                if str(r.get("MacAddress", "")).lower() == mac.lower():
                    port = r.get("Port")
                    st = t["status"].get(port, {})
                    hits.append({"switch": swn, "asic": ns, "port": port, "vlan": r.get("Vlan"), "type": r.get("Type"),
                                 "desc": t["desc"].get(port, ""), "oper": st.get("Oper"), "admin": st.get("Admin")})
    return hits


def counters(rack, involved: set[tuple]) -> dict:
    """{(switch, asic, port): {counter: value}} for the involved switch ports."""
    by_sw: dict[str, set[str]] = {}
    for sw, ns, _ in involved:
        by_sw.setdefault(sw, set()).add(ns)

    def one(swn):
        sw, out = rack.switches[swn], {}
        for ns in by_sw[swn]:
            c = sw.interfaces_counters(ns or None)
            f = sw.fec_stats(ns or None)
            for (s, n, port) in involved:
                if s == swn and n == ns:
                    row = {k: num((c.get(port) or {}).get(k)) for k in COUNTERS}
                    row.update({k: num((f.get(port) or {}).get(k)) for k in FEC})
                    out[(s, n, port)] = row
        return out
    res = {}
    for _, val, exc in fan_out(one, list(by_sw)):
        if not exc:
            res.update(val)
    return res


def delta(before: dict, after: dict) -> dict:
    return {k: (after[k] - before[k]) for k in after if after.get(k) is not None and before.get(k) is not None
            and after[k] != before[k]}


def judge(p: int, s: dict, d: dict, src_entry, dst_entry, ping: dict | None, deltas: dict) -> str:
    def port_ok(x):
        return x and str(x.get("admin", "")).lower() == "enabled" and "UP" in str(x.get("link", "")).upper()

    if not port_ok(s):
        return f"tray side: source GPU port {p} is {s and s.get('admin')}/{s and s.get('link')}"
    if not port_ok(d):
        return f"tray side: destination GPU port {p} is {d and d.get('admin')}/{d and d.get('link')}"
    ifcp_note = ""
    for who, x in (("source", s), ("destination", d)):
        if x.get("ll_up") != "yes" or x.get("peer_enabled") != "yes" or "yes" in (x.get("in_error"), x.get("peer_in_error")):
            ifcp_note = (f"IFCP: {who} port {p} ll_up={x.get('ll_up')} peer_enabled={x.get('peer_enabled')} "
                         f"in_error={x.get('in_error')} peer_in_error={x.get('peer_in_error')}")
            if ping is None or ping["failed"]:      # the ping decides; IFCP down alone is reported with its result
                return ifcp_note
            break
    for who, e in (("destination", dst_entry), ("source", src_entry)):
        if not e["hit"]:
            return f"switch: no forwarding entry for the {who}'s MAC {e['mac'] or '(afmctl gave none)'} on port {p}"
        if e["problem"]:
            return f"switch: {who} entry {e['problem']}"
    if src_entry["hit"]["switch"] != dst_entry["hit"]["switch"] or src_entry["hit"]["asic"] != dst_entry["hit"]["asic"]:
        return "switch: source and destination entries are on different ASICs (one plane per GPU port expected)"
    if ping is None:
        return "ok up to the switch (no ping)"
    if ping["failed"]:
        moved = {k: v for k, v in deltas.items() if v}
        return f"data path: ping failed ({', '.join(ping['failed'])}){' - counters moved: ' + json.dumps(moved) if moved else ''}"
    return f"ok (L2 ping passes; {ifcp_note} - IFCP down but the data path works)" if ifcp_note else "ok"


def check_entry(hits: list[dict], want_slot: int | None, port: int) -> dict:
    if not hits:
        return {"hit": None, "problem": None}
    h = hits[0]
    cab = parse_port_description(h["desc"])
    problems = []
    if len(hits) > 1:
        problems.append(f"MAC on {len(hits)} switch ports: {[(x['switch'], x['asic'], x['port']) for x in hits]}")
    if str(h.get("type", "")).lower() != "static":
        problems.append(f"type {h.get('type')} (not static)")
    if str(h.get("oper", "")).lower() != "up":
        problems.append(f"{h['switch']} {h['asic']} {h['port']} oper {h.get('oper')}")
    if not cab:
        problems.append(f"{h['switch']} {h['port']} has no ComputeTray description")
    else:
        if want_slot is not None and cab[0] != want_slot:
            problems.append(f"{h['switch']} {h['port']} is cabled to slot {cab[0]}, expected slot {want_slot}")
        if cab[3] != port:
            problems.append(f"{h['switch']} {h['port']} is cabled to GPU port {cab[3]}, expected port {port}")
    h["cabled"] = {"slot": cab[0], "gpu": cab[1], "acc": cab[2], "port": cab[3]} if cab else None
    return {"hit": h, "problem": "; ".join(problems) or None}


def path_cmd(a) -> int:
    inv = load_inventory(a.inventory)
    rack = Rack(inv)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out = a.out or ROOT / "results" / "link-check" / (inv.rack or "rack") / stamp
    _OUTS.append(out)
    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    say = []

    def log(line=""):
        print(line)
        say.append(line)

    try:
        if a.src not in rack.computes or (a.dst and a.dst not in rack.computes):
            print(f"unknown tray: computes in the inventory are {sorted(rack.computes)}", file=sys.stderr)
            return 2
        src = Side(rack.computes[a.src], raw, "src").load()
        dst = src if not a.dst or a.dst == a.src else Side(rack.computes[a.dst], raw, "dst").load()
        if a.src_bdf not in src.accels:
            print(f"{a.src} has no GPU {a.src_bdf}: {sorted(src.accels)}", file=sys.stderr)
            return 2
        dst_bdf = a.dst_bdf or dst.bdf_of_acc(a.dst_acc)
        if not dst_bdf or dst_bdf not in dst.accels:
            print(f"{dst.name}: no GPU for {a.dst_bdf or 'accelerator ' + str(a.dst_acc)}: "
                  f"{ {b: v[0] for b, v in dst.accels.items()} }", file=sys.stderr)
            return 2
        src_acc, reach = src.accels[a.src_bdf]
        dst_acc = dst.accels[dst_bdf][0]
        log(f"Link check {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")
        log(f"source      {src.name} {a.src_bdf} (accelerator {src_acc})")
        log(f"destination {dst.name} {dst_bdf} (accelerator {dst_acc})")
        if dst_acc not in reach:
            log(f"!! accelerator {dst_acc} is not in the source's vpod_accelerators ({len(reach)} listed): not in one vPOD")

        sp, dp = src.ports(a.src_bdf), dst.ports(dst_bdf)
        usable = sorted(p for p in sp if p in dp and str(sp[p]["admin"]).lower() == "enabled" == str(dp[p]["admin"]).lower()
                        and "UP" in str(sp[p]["link"]).upper() and "UP" in str(dp[p]["link"]).upper())
        ports = [int(x) for x in a.ports.split(",")] if a.ports else usable
        log(f"ports       {','.join(map(str, ports))}  ({len(usable)} of {len(sp)} usable on both GPUs)")

        tables = switch_tables(rack, raw)
        for swn, t in tables.items():
            if "error" in t:
                log(f"!! {swn}: switch tables not read: {t['error'][:200]}")
        s_slot, d_slot = tray_slot(src.tray), tray_slot(dst.tray)
        entries = {}
        for p in ports:
            dmac = (src.addr.get(a.src_bdf, {}).get(p) or {}).get(dst_acc)
            smac = (dst.addr.get(dst_bdf, {}).get(p) or {}).get(src_acc)
            de = check_entry(find_mac(tables, dmac), d_slot, p) if dmac else {"hit": None, "problem": None}
            se = check_entry(find_mac(tables, smac), s_slot, p) if smac else {"hit": None, "problem": None}
            de["mac"], se["mac"] = dmac, smac
            entries[p] = (se, de)

        involved = {(e["hit"]["switch"], e["hit"]["asic"], e["hit"]["port"]) for p in ports for e in entries[p] if e["hit"]}
        before = counters(rack, involved)
        pings = {}
        if not a.no_ping and ports:
            for i in range(max(1, a.count)):
                res, r = src.a.ping(a.src_bdf, dst_acc, ports)
                src.save(f"ping-{i + 1}", r.stdout)
                for p in ports:
                    failed = res.port_checks.get(str(p)) or []
                    pings.setdefault(p, {"runs": 0, "failed": set()})
                    pings[p]["runs"] += 1
                    pings[p]["failed"].update(failed)
                if res.busy:
                    log("!! afmctl answered 'Device or resource busy' after retries: another ping runs on the tray")
        after = counters(rack, involved) if pings else {}

        log("")
        log(f"{'port':>4}  {'source side':<34} {'destination side':<34} verdict")
        result = []
        for p in ports:
            se, de = entries[p]
            ping = None if a.no_ping else {"failed": sorted(pings.get(p, {}).get("failed", set()))}
            dl = {}
            for e in (se, de):
                if e["hit"]:
                    k = (e["hit"]["switch"], e["hit"]["asic"], e["hit"]["port"])
                    if k in before and k in after:
                        dl[f"{k[0]} {k[2]}"] = delta(before[k], after[k])
            verdict = judge(p, sp.get(p), dp.get(p), se, de, ping, dl)
            show = lambda e: f"{e['hit']['switch']} {e['hit']['asic']} {e['hit']['port']}" if e["hit"] else "no entry"  # noqa: E731
            log(f"{p:>4}  {show(se):<34} {show(de):<34} {verdict}")
            result.append({"port": p, "station": p // 2, "source_port": sp.get(p), "destination_port": dp.get(p),
                           "source_entry": se, "destination_entry": de, "ping": ping, "counter_deltas": dl,
                           "verdict": verdict})
        bad = [r for r in result if not (r["verdict"] == "ok" or r["verdict"].startswith(("ok up to", "ok (")))]
        log("")
        log(f"{len(result) - len(bad)} of {len(result)} ports ok" + (f"; first problem: port {bad[0]['port']}: {bad[0]['verdict']}" if bad else ""))
        log(f"evidence: {out}")
        (out / "link_check.json").write_text(json.dumps({
            "time_utc": stamp, "source": {"tray": src.name, "bdf": a.src_bdf, "accelerator": src_acc},
            "destination": {"tray": dst.name, "bdf": dst_bdf, "accelerator": dst_acc}, "ports": result,
            "counters_before": {" ".join(k): v for k, v in before.items()},
            "counters_after": {" ".join(k): v for k, v in after.items()}}, indent=1, default=str))
        (out / "report.txt").write_text("\n".join(say) + "\n")
        return 1 if bad else 0
    finally:
        rack.close()



# ------------------------------------------------------------------------------------------------- scan

def esc(v) -> str:
    import html
    return html.escape(str(v if v is not None else ""))


def _not_checked(res) -> list[tuple[str, str, str, str]]:
    """[(name, 'switch' | 'tray', error, what to do)] for every node the scan could not read. A switch that cannot be
    read means none of its links were checked (MR2 18 Oct: every login refused and the report said 'All links ok')."""
    def hint(err: str) -> str:
        e = err.lower()
        if "authentication" in e or "permission denied" in e:
            return ("login refused: install your SSH key on it (ssh-copy-id) and set key_file, or export the "
                    "password_env variable the inventory names in this shell")
        if "timed out" in e or "timeout" in e or "no route" in e or "unreachable" in e or "refused" in e:
            return "not reachable: check the address in the inventory, the network / VPN, or transport.jump"
        if "sudo" in e:
            return "needs sudo without a password prompt for the inventory user"
        return "see the error"
    out = [(n, "switch", s["error"], hint(s["error"])) for n, s in res["switches"].items() if s.get("error")]
    out += [(n, "tray", t["error"], hint(t["error"])) for n, t in res["trays"].items() if t.get("error")]
    return out


_OUTS: list = []        # report folders of the current command (the command log is saved there)


class CommandLog:
    """Every command the tool runs on a switch / tray (time, exit code, duration, output), like the test reports'
    command logs: report.html shows each node's log (outputs trimmed to --log-keep lines), raw/commands.log.gz
    keeps everything."""

    def __init__(self):
        import threading
        self.entries: list[dict] = []
        self._lock = threading.Lock()

    def __enter__(self):
        from heliosdbg import transport
        transport.RECORDERS.append(self._add)
        return self

    def __exit__(self, *exc):
        from heliosdbg import transport
        if self._add in transport.RECORDERS:
            transport.RECORDERS.remove(self._add)

    def _add(self, host, cmd, res, err, t0):
        e = {"host": host, "cmd": cmd, "t": t0, "rc": res.rc if res else None,
             "s": round(res.duration, 2) if res else None, "out": res.stdout if res else "",
             "err": (res.stderr if res else "") or "", "error": err}
        with self._lock:
            self.entries.append(e)

    @staticmethod
    def _when(t) -> str:
        return time.strftime("%H:%M:%S", time.gmtime(t))

    def text(self) -> str:
        out = []
        for e in sorted(self.entries, key=lambda e: (e["host"], e["t"])):
            head = f"[{e['host']}] {self._when(e['t'])} UTC  $ {e['cmd']}"
            tail = (f"  -> {e['error']}" if e["error"] else f"  -> rc={e['rc']} {e['s']}s")
            out.append(head + "\n" + tail + "\n" + e["out"] + (("\n[stderr]\n" + e["err"]) if e["err"].strip() else ""))
        return "\n".join(out)

    def save(self, folder: Path) -> None:
        import gzip
        with gzip.open(folder / "commands.log.gz", "wt") as fh:
            fh.write(self.text())

    def html(self, order: list[str], keep: int = 200) -> str:
        by: dict[str, list] = {}
        for e in self.entries:
            by.setdefault(e["host"], []).append(e)
        hosts = [h for h in order if h in by] + sorted(h for h in by if h not in order)
        parts = []
        for h in hosts:
            ents = sorted(by[h], key=lambda e: e["t"])
            nlines = sum(e["out"].count("\n") + 1 for e in ents)
            bad = sum(1 for e in ents if e["error"] or e["rc"] not in (0, None))
            items = []
            for e in ents:
                lines = e["out"].splitlines()
                shown = "\n".join(lines[:keep])
                more = len(lines) - keep
                st = (f"<span class='err'>{esc(e['error'])}</span>" if e["error"] else
                      f"rc {e['rc']}" if e["rc"] == 0 else f"<span class='err'>rc {e['rc']}</span>")
                items.append(f"<div class='ch'>{self._when(e['t'])} UTC · {st}{(' · ' + str(e['s']) + ' s') if e['s'] is not None else ''}</div>"
                             f"<pre>$ {esc(e['cmd'])}\n{esc(shown)}"
                             + (f"\n... {more} more lines (full output in raw/commands.log.gz)" if more > 0 else "")
                             + (f"\n[stderr]\n{esc(e['err'].strip()[:4000])}" if e["err"].strip() else "") + "</pre>")
            parts.append(f"<details><summary>Command log: <b>{esc(h)}</b> ({len(ents)} commands, {nlines} lines"
                         f"{', ' + str(bad) + ' failed' if bad else ''})</summary>{''.join(items)}</details>")
        return "".join(parts)


def _ranges(nums) -> str:
    """[18, 19, 20, 22] -> '18-20, 22'."""
    nums = sorted({n for n in nums if n is not None})
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else f"{nums[i]}-{nums[j]}")
        i = j + 1
    return ", ".join(out)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 'es' if word.endswith('ch') else 's'}"


RANK = {"ok": 0, "degraded": 1, "down": 2}


def asic_gpu_map(links) -> dict:
    """{asic key: {tray: {bdf: {"ports": [...], "ok": n, "total": n, "worst": state}}}} plus per-ASIC totals - which
    GPU ports each switch ASIC carries (one plane per GPU port number) and how many of them are ok."""
    m: dict = {}
    for ln in links:
        if not ln.tray or not ln.bdf:
            continue
        k = f"{ln.switch} {ln.asic}".strip()
        c = m.setdefault(k, {}).setdefault(ln.tray, {}).setdefault(ln.bdf, {"ports": [], "ok": 0, "total": 0, "worst": "ok"})
        c["ports"].append(ln.gpu_port)
        c["total"] += 1
        c["ok"] += ln.state == "ok"
        if RANK.get(ln.state, 0) > RANK[c["worst"]]:
            c["worst"] = ln.state
    return m


def map_lines(links) -> list[str]:
    """Text form of the ASIC -> GPU map for report.txt."""
    out = []
    for k, trays in sorted(asic_gpu_map(links).items()):
        tot = sum(c["total"] for t in trays.values() for c in t.values())
        ok = sum(c["ok"] for t in trays.values() for c in t.values())
        parts = []
        for tray, gpus in sorted(trays.items()):
            ports = sorted({p for c in gpus.values() for p in c["ports"]})
            parts.append(f"{tray} {len(gpus)} GPU x ports {_ranges(ports)}")
        out.append(f"  {k}: {ok}/{tot} links ok - " + "; ".join(parts))
    return out


def write_html(path: Path, rack_name: str, when: str, res: dict, groups: list[dict], cmdlog: "CommandLog | None" = None,
               log_keep: int = 200) -> None:
    links = res["links"]
    n = {k: sum(1 for x in links if x.state == k) for k in ("ok", "degraded", "down")}
    rows = []
    for g in groups:
        for ln in g["links"]:
            rows.append(f"<tr class='{ln.state}'><td>{esc(ln.state)}</td><td>{esc(ln.switch)} {esc(ln.asic)} {esc(ln.sw_port)}</td>"
                        f"<td>{esc(ln.tray)} {esc(ln.bdf)} port {esc(ln.gpu_port)}</td><td>{esc(ln.cause)}</td>"
                        f"<td>{esc(ln.owner)}</td><td>{esc(ln.action)}</td><td><details><summary>show</summary>"
                        + "".join(f"<div>{esc(e)}</div>" for e in ln.evidence) + "</details></td></tr>")
    summary = "".join(f"<tr class='{g['state']}'><td>{esc(g['state'])}</td><td>{g['count']}</td><td>{esc(g['cause'])}</td>"
                      f"<td>{esc(g['owner'])}</td></tr>" for g in groups)
    per_asic = {}
    for ln in links:
        if ln.state != "ok" and ln.kind not in ("tray_quarantined", "tray_unreachable", "tray_missing", *GPU_LEVEL):
            k = f"{ln.switch} {ln.asic}".strip()
            per_asic[k] = per_asic.get(k, 0) + 1
    asic_rows = "".join(f"<tr><td>{esc(k)}</td><td>{n}</td></tr>" for k, n in sorted(per_asic.items(), key=lambda x: -x[1]))
    cab = res["learned"].get("ifcp") or {}
    ifcp_in_use = res["learned"].get("ifcp_in_use", True)
    unreach = [t["name"] for t in res["trays"].values() if t.get("error")] + \
              [s["name"] for s in res["switches"].values() if s.get("error")]

    # notes: what was and was not checked, in plain words
    notes = []
    if not ifcp_in_use:
        notes.append("<b>IFCP is not running on this rack.</b> No GPU port has an IFCP session or knows a peer, so IFCP is not "
                     "judged per link and the cabling cannot be cross-checked against IFCP. Links are judged on the other "
                     "layers. Whether traffic flows without it: <code>link_check.py path</code> runs an L2 ping over chosen ports.")
    elif cab.get("device"):
        notes.append(f"Cabling checked against IFCP on {cab.get('checked_links', 0)} links: each GPU port's IFCP peer is the "
                     f"switch port that the forwarding table / port description names.")
    else:
        notes.append("Cabling not checked against IFCP (no IFCP peer data).")
    by = {}
    for ln in links:
        by[ln.matched_by or "none"] = by.get(ln.matched_by or "none", 0) + 1
    notes.append("Switch port to GPU port matching: " + ", ".join(f"{v} by {'the GPU port MAC in the switch forwarding table' if k == 'mac' else 'the switch port description' if k == 'description' else k}"
                                                              for k, v in sorted(by.items(), key=lambda kv: -kv[1])) + ".")
    if not any(res["optics_reported"].values()):
        notes.append("Optics: this switch platform reports no transceiver presence or optic power, so a cable fault cannot "
                     "be told from a port fault remotely.")
    notes.append(f"Bit errors count only when they grow during the {res['interval_s']:.0f} s sample.")
    av = res["learned"].get("afm_view") or {}
    notes.append(f"AFM view: {av.get('nodes')} compute nodes read; {av.get('gpus_paired')} GPUs paired with the trays "
                 f"(GPU vPOD membership, accelerator ids and AFM's port state checked)." if av.get("checked") else
                 f"AFM view not checked ({esc(av.get('reason'))}). GPU state is judged from the trays alone; AFM's port "
                 f"state is not compared.")
    gf = res.get("gpus") or []
    gpu_rows = "".join(f"<tr class='{g['state']}'><td>{esc(g['state'])}</td><td>{esc(g['tray'])}</td><td>{esc(g['bdf'])}</td>"
                       f"<td>{esc(g['accelerator'])}</td><td>{esc(g['phase'])}</td>"
                       f"<td>{esc((g.get('afm') or {}).get('node') or '')} {esc('GPU ' + str(g['afm']['index']) + ', accelerator ' + str(g['afm']['acc_id']) + ', vPOD ' + str(g['afm']['vpod'] or 'none') if g.get('afm') else '')}</td>"
                       f"<td>{esc(g['cause'])}</td><td>{esc(g['action'])}</td></tr>" for g in gf)

    # ASIC -> GPU map
    amap = asic_gpu_map(links)
    trays = sorted({t for v in amap.values() for t in v})
    map_head = "<tr><th>Switch ASIC</th><th>Links ok</th>" + "".join(f"<th>{esc(t)}</th>" for t in trays) + "</tr>"
    map_rows = []
    for k, tv in sorted(amap.items()):
        tot = sum(c["total"] for t in tv.values() for c in t.values())
        ok = sum(c["ok"] for t in tv.values() for c in t.values())
        cells = []
        for t in trays:
            gpus = tv.get(t, {})
            cells.append("<td>" + "".join(f"<div class='chip {c['worst']}' title='{esc(t)} {esc(b)}'>{esc(b)} · ports "
                                          f"{esc(_ranges(c['ports']))} · {c['ok']}/{c['total']}</div>"
                                          for b, c in sorted(gpus.items())) + "</td>")
        cls = "ok" if ok == tot else "down" if ok == 0 else "degraded"
        map_rows.append(f"<tr><td><b>{esc(k)}</b></td><td class='{cls}'>{ok}/{tot}</td>{''.join(cells)}</tr>")

    # every link
    def pnum(x):
        m_ = re.search(r"(\d+)$", x or "")
        return int(m_.group(1)) if m_ else 0
    all_rows = []
    for ln in sorted(links, key=lambda x: (x.switch, x.asic or "", pnum(x.sw_port))):
        g = ln.gpu or {}
        i = g.get("ifcp") or {}
        ifcp = ("not running" if not ifcp_in_use else ("up" if i.get("ll_up") == "yes" else f"down (ll_up {i.get('ll_up')})")) if g else ""
        fec = f"+{ln.deltas.get('FEC_CORR', 0)} / +{ln.deltas.get('FEC_UNCORR', 0)}" if ln.deltas or g else ""
        all_rows.append(
            f"<tr class='{ln.state}' data-s='{ln.state}'><td>{esc(ln.state)}</td><td>{esc(ln.switch)}</td><td>{esc(ln.asic)}</td>"
            f"<td>{esc(ln.sw_port)}</td><td>{esc(ln.sw_admin)}/{esc(ln.sw_oper)}</td><td>{esc(ln.tray)}</td><td>{esc(ln.bdf)}</td>"
            f"<td>{esc(ln.gpu_port)}</td><td>{esc(g.get('admin', ''))}/{esc(str(g.get('link', ''))[:28])}</td><td>{esc(ifcp)}</td><td>{esc(ln.afm_port or '')}</td>"
            f"<td>{esc(fec)}</td><td>{esc(ln.matched_by)}</td><td>{esc(ln.cause or '')}</td></tr>")

    nsw, ntr = len(res["switches"]), len(res["trays"])
    path.write_text(f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Scale-up link report - {esc(rack_name)}</title><style>
:root{{--bg:#f6f7f9;--fg:#1b2129;--mut:#5d6977;--rule:#d9dee4;--card:#ffffff;--down:#b42318;--deg:#b54708;--ok:#067647;
--okbg:#e7f6ec;--degbg:#fef3e2;--downbg:#fdecea}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12161b;--fg:#e6eaef;--mut:#96a2b0;--rule:#2b3540;--card:#1a2027;--down:#f97066;
--deg:#fdb022;--ok:#47cd89;--okbg:#10291b;--degbg:#33250c;--downbg:#3a1512}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,'Segoe UI',Arial,sans-serif;margin:0;padding:24px max(16px,4vw)}}
h1{{font-size:1.5rem;margin:0}}h2{{font-size:1.1rem;margin:28px 0 8px}}.mut{{color:var(--mut)}}
.k{{display:flex;flex-wrap:wrap;gap:24px;margin:14px 0}}.k b{{display:block;font-size:1.6rem}}
.notes{{background:var(--card);border:1px solid var(--rule);border-radius:8px;padding:10px 16px}}.notes li{{margin:4px 0}}
.wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;min-width:760px;font-size:13px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--rule);vertical-align:top}}th{{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg)}}
tr.down td:first-child,td.down{{color:var(--down);font-weight:600}}tr.degraded td:first-child,td.degraded{{color:var(--deg);font-weight:600}}
tr.ok td:first-child,td.ok{{color:var(--ok)}}
.chip{{display:inline-block;margin:2px 4px 2px 0;padding:2px 6px;border-radius:6px;font:12px ui-monospace,Menlo,Consolas,monospace;white-space:nowrap}}
.chip.ok{{background:var(--okbg)}}.chip.degraded{{background:var(--degbg);color:var(--deg)}}.chip.down{{background:var(--downbg);color:var(--down)}}
.bar{{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0}}input,select{{font:inherit;padding:4px 8px;border:1px solid var(--rule);border-radius:6px;background:var(--card);color:var(--fg)}}
.scroll{{max-height:70vh;overflow:auto;border:1px solid var(--rule);border-radius:8px}}
code,details div{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
details{{margin:4px 0}}summary{{cursor:pointer;color:var(--fg)}}.ch{{color:var(--mut);margin-top:8px}}.err{{color:var(--down);font-weight:600}}
pre{{background:var(--card);border:1px solid var(--rule);border-radius:6px;padding:8px;overflow-x:auto;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:2px 0 6px}}
</style></head><body>
<h1>Scale-up link report: {esc(rack_name)}</h1>
<div class='mut'>{esc(when)} UTC · {_plural(nsw, 'switch')}, {_plural(ntr, 'compute tray')} · read-only</div>
<div class='k'><span><b>{len(links)}</b>GPU links</span><span><b style='color:var(--ok)'>{n['ok']}</b>ok</span>
<span><b style='color:var(--deg)'>{n['degraded']}</b>degraded</span><span><b style='color:var(--down)'>{n['down']}</b>down</span></div>
{('<h2 style="color:var(--down)">Not checked</h2><p>The scan could not read these, so their links are missing or incomplete below.</p><ul>' + ''.join(f'<li><b>{esc(r)} {esc(nm)}</b>: {esc(e[:200])}<br><span class="mut">{esc(h)}</span></li>' for nm, r, e, h in _not_checked(res)) + '</ul>') if unreach else ''}
<h2>Notes</h2><ul class='notes'>{''.join(f'<li>{x}</li>' for x in notes)}</ul>
{(("<h2>Changes since the earlier scan</h2><p>" + esc(f"{len(res['compare']['new_problems'])} new problem(s), {len(res['compare']['recovered'])} recovered, {res['compare']['still_bad']} still bad") + "</p>" + "".join(f"<div><code>new: {esc(x)}</code></div>" for x in res['compare']['new_problems']) + "".join(f"<div><code>recovered: {esc(x)}</code></div>" for x in res['compare']['recovered'])) if res.get('compare') else '')}
{("<h2>Patterns</h2>" + "".join(f"<p>{esc(x)}</p>" for x in res.get('suspects') or [])) if res.get('suspects') else ''}
<h2>GPU state</h2>{("<div class='wrap'><table><tr><th>State</th><th>Tray</th><th>GPU (BDF)</th><th>Accelerator</th><th>Phase</th><th>AFM</th><th>Cause</th><th>Next step</th></tr>" + gpu_rows + "</table></div>") if gpu_rows else ("<p>Every GPU is ACTIVE on the trays read" + (" and matches AFM." if av.get('checked') else ".") + "</p>" if any(not t.get('error') for t in res['trays'].values()) else "<p class='err'>Not checked: no compute tray could be read.</p>")}
<h2>Root causes</h2><div class='wrap'><table><tr><th>State</th><th>Links</th><th>Cause</th><th>Owner</th></tr>{summary or "<tr><td colspan=4>No problem links.</td></tr>"}</table></div>
<h2>Problem links</h2><div class='wrap'><table><tr><th>State</th><th>Switch port</th><th>GPU port</th><th>Cause</th><th>Owner</th><th>Next step</th><th>Evidence</th></tr>
{''.join(rows) or ("<tr><td colspan=7>All links ok.</td></tr>" if links and not any(r == "switch" for _n, r, _e, _h in _not_checked(res)) else "<tr><td colspan=7>No problem found among the links that could be checked - see Not checked above.</td></tr>")}</table></div>
{("<h2>Problem links per switch ASIC</h2><p class='mut'>Trays out of service left out. Problems spread over many ASICs point at the trays or cabling; many on one ASIC point at that ASIC.</p><div class='wrap'><table style='min-width:320px'><tr><th>Switch ASIC</th><th>Problem links</th></tr>" + asic_rows + "</table></div>") if asic_rows else ""}
<h2>Switch ASIC to GPU map</h2>
<p class='mut'>Which GPU ports each switch ASIC carries (a GPU port number is one plane, on one ASIC) and how many of them are ok. Green: all ok; amber / red: at least one degraded / down - see All links.</p>
<div class='wrap'><table>{map_head}{''.join(map_rows) or "<tr><td>No links matched.</td></tr>"}</table></div>
<h2>All links ({len(links)})</h2>
<div class='bar'><input id='q' type='search' placeholder='Filter: switch port, tray, BDF, cause ...' aria-label='Filter links' size='34'>
<select id='st' aria-label='State'><option value=''>all states</option><option>ok</option><option>degraded</option><option>down</option></select>
<span id='cnt' class='mut'></span></div>
<div class='scroll'><table id='all'><thead><tr><th>State</th><th>Switch</th><th>ASIC</th><th>Switch port</th><th>Admin/oper</th><th>Tray</th><th>GPU (BDF)</th>
<th>GPU port</th><th>GPU admin/link</th><th>IFCP</th><th>AFM port</th><th>FEC corr / uncorr (sample)</th><th>Matched by</th><th>Cause</th></tr></thead>
<tbody>{''.join(all_rows)}</tbody></table></div>
{("<h2>Command logs</h2><p class='mut'>Every command run on each switch and compute tray during this scan, with its output (trimmed to " + str(log_keep) + " lines per command here; everything is in raw/commands.log.gz).</p>" + cmdlog.html(sorted(res['switches']) + sorted(res['trays']), log_keep)) if cmdlog and cmdlog.entries else ''}
<script>
(function(){{var q=document.getElementById('q'),st=document.getElementById('st'),cnt=document.getElementById('cnt'),
rows=Array.prototype.slice.call(document.querySelectorAll('#all tbody tr'));
function f(){{var t=q.value.toLowerCase(),s=st.value,n=0;rows.forEach(function(r){{var on=(!s||r.dataset.s===s)&&(!t||r.textContent.toLowerCase().indexOf(t)>=0);
r.style.display=on?'':'none';if(on)n++;}});cnt.textContent=n+' of '+rows.length+' shown';}}
q.addEventListener('input',f);st.addEventListener('change',f);f();}})();
</script>
</body></html>
""")


def _filtered_rack(a):
    inv = load_inventory(a.inventory)
    rack = Rack(inv)
    for attr, want in (("switches", getattr(a, "switches", None)), ("computes", getattr(a, "trays", None))):
        if want:
            keep = {x.strip() for x in want.split(",") if x.strip()}
            unknown = keep - set(getattr(rack, attr))
            if unknown:
                raise SystemExit(f"unknown {attr}: {sorted(unknown)} (inventory: {sorted(getattr(rack, attr))})")
            setattr(rack, attr, {k: v for k, v in getattr(rack, attr).items() if k in keep})
    return inv, rack


def _only_selected_trays(res, rack) -> list:
    """--trays: keep only the links cabled to the selected trays. Without this every port cabled to a tray left out
    of the run reads as 'no compute tray in the inventory' (g02-g17 18 Oct: --trays ct13,ct14 on st6 gave 360 of
    them, and ct05's quarantined links)."""
    keep = set(rack.computes)
    slots = {s for t, s in (res.get("learned") or {}).get("slots", {}).items() if t in keep}
    slots |= {v for v in (tray_slot(t) for t in rack.computes.values()) if v is not None}
    out = []
    for ln in res["links"]:
        cab = parse_port_description(ln.desc or "")
        if ln.tray in keep or (ln.tray is None and cab and cab[0] in slots):
            out.append(ln)
    return out


def _room(folder: Path, need_mb: int = 50) -> None:
    """Refuse before collecting when the report folder's disk is nearly full (g02-g17 18 Oct: the jump host's /home
    filled up and a scan died at mkdir with a traceback)."""
    import shutil
    p = folder
    while not p.exists():
        p = p.parent
    free = shutil.disk_usage(p).free // 2**20
    if free < need_mb:
        raise SystemExit(f"only {free} MB free under {p} - free some space or give --out on another disk (needs ~{need_mb} MB)")


def scan_cmd(a) -> int:
    from heliosdbg import linkdiag
    inv, rack = _filtered_rack(a)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out = a.out or ROOT / "results" / "link-check" / (inv.rack or "rack") / f"scan-{stamp}"
    _OUTS.append(out)
    _room(out)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    cmdlog = CommandLog()
    try:
        with cmdlog:
            res = linkdiag.scan(rack, a.interval, bcm_view=not a.no_bcm, bcm_max=a.bcm_max,
                                afm_cfg=None if a.no_afm else (inv.afm or {}))
    finally:
        rack.close()
    cmdlog.save(out / "raw")
    if getattr(a, "trays", None):
        res["links"] = _only_selected_trays(res, rack)
    links, groups = res["links"], linkdiag.group_causes(res["links"])
    lines = [f"Scale-up link scan {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC  rack {inv.rack}",
             f"{len(links)} GPU links: " + ", ".join(f"{sum(1 for x in links if x.state == k)} {k}" for k in ("ok", "degraded", "down")), ""]
    for g in groups:
        lines.append(f"{g['state'].upper():<9}{g['count']:>4}  {g['cause']}  [{g['owner']}]")
        for ln in g["links"][:6]:
            gp = f"{ln.tray} {ln.bdf} port {ln.gpu_port}" if ln.gpu_port is not None else (ln.tray or "?")
            lines.append(f"{'':15}{ln.switch} {ln.asic} {ln.sw_port} <-> {gp}" + (f": {ln.cause}" if g["count"] <= 6 else ""))
        if g["count"] > 6:
            lines.append(f"{'':15}... {g['count'] - 6} more")
        lines.append(f"{'':15}next: {g['links'][0].action}")
    per_asic = {}
    for ln in links:
        if ln.state != "ok" and ln.kind not in ("tray_quarantined", "tray_unreachable", "tray_missing", *GPU_LEVEL):
            k = f"{ln.switch} {ln.asic}".strip()
            per_asic[k] = per_asic.get(k, 0) + 1
    sus = linkdiag.suspects(links)
    if sus:
        lines.append("")
        lines += [f"pattern: {x}" for x in sus]
        res["suspects"] = sus
    if per_asic:
        lines.append("")
        lines.append("problem links per switch ASIC (trays out of service left out): " +
                     ", ".join(f"{k} {n}" for k, n in sorted(per_asic.items(), key=lambda x: -x[1])))
    ml = map_lines(links)
    if ml:
        lines.append("")
        lines.append("switch ASIC -> GPU ports (links ok / total):")
        lines += ml
    if not res["learned"].get("ifcp_in_use", True):
        lines.append("note: IFCP is not running on this rack - no GPU port has an IFCP session or peer; links are judged "
                     "on the other layers (check with `path`: an L2 ping that passes means the data path works without it)")
    av = res["learned"].get("afm_view") or {}
    lines.append("")
    lines.append(f"AFM view: {av['nodes']} compute nodes, {av['gpus_paired']} GPUs paired with the trays"
                 + (f" ({av['by_elimination']} by elimination - accelerator id differs)" if av.get("by_elimination") else "")
                 if av.get("checked") else f"AFM view not checked: {av.get('reason')}")
    gf = res.get("gpus") or []
    read = [t for t in res["trays"].values() if not t.get("error")]
    lines.append("GPU state: " + ("not checked - no compute tray could be read" if not read else
                                  f"{len(gf)} GPU(s) not right:" if gf else
                                  f"every GPU ACTIVE on the {len(read)} tray(s) read" + (" and matching AFM" if av.get("checked") else "")))
    for g in gf:
        lines.append(f"  {g['state'].upper():<9}{g['tray']} {g['bdf']} (accelerator {g['accelerator'] or '?'}, {g['phase'] or '?'}): {g['cause']}")
        lines.append(f"{'':11}next: {g['action']}")
    nc = _not_checked(res)
    sw_missing = [n for n, r, _e, _h in nc if r == "switch"]
    if nc:
        lines.append("")
        lines.append("NOT CHECKED - the scan could not read these, so their links are missing or incomplete:")
        lines += [f"  {r} {n}: {e[:140]}\n      -> {h}" for n, r, e, h in nc]
    if not links:
        lines.append("\nNo link was checked." + (" Fix the access above and scan again." if nc else
                                                  " No switch port is described as cabled to a compute tray."))
    elif not groups:
        lines.append("No problem found among the links checked." if sw_missing else "All links ok.")
    if getattr(a, "compare", None):
        prev = json.loads(Path(a.compare).read_text())
        diff = linkdiag.compare(prev.get("links") or [], links)
        lines.append("")
        lines.append(f"compared with {a.compare} ({prev.get('time_utc', '?')} UTC): {len(diff['new_problems'])} new problem(s), "
                     f"{len(diff['recovered'])} recovered, {diff['still_bad']} still bad ({len(diff['changed'])} with another cause)")
        lines += [f"  new:       {x}" for x in diff["new_problems"]] + [f"  recovered: {x}" for x in diff["recovered"]] + \
                 [f"  changed:   {x}" for x in diff["changed"]]
        res["compare"] = diff
    lines.append(f"\nreport: {out / 'report.html'}")
    print("\n".join(lines))
    (out / "report.txt").write_text("\n".join(lines) + "\n")
    import gzip
    for name, data in (("switches", res["switches"]), ("trays", res["trays"])):   # gzip: ~7 MB a scan uncompressed
        with gzip.open(out / "raw" / f"{name}.json.gz", "wt") as fh:
            json.dump(data, fh, default=str)
    (out / "link_check.json").write_text(json.dumps({
        "time_utc": stamp, "rack": inv.rack, "interval_s": res["interval_s"], "learned": res["learned"],
        "optics_reported": res["optics_reported"], "gpus": res.get("gpus") or [], "links": [linkdiag.link_dict(x) for x in links], "compare": res.get("compare"), "patterns": res.get("suspects"),
        "root_causes": [{k: v for k, v in g.items() if k != "links"} | {"links": [f"{x.switch} {x.sw_port}" for x in g["links"]]}
                        for g in groups]}, indent=1, default=str))
    write_html(out / "report.html", inv.rack or "rack", time.strftime("%Y-%m-%d %H:%M", time.gmtime()), res, groups,
               cmdlog, a.log_keep)
    return 2 if (sw_missing or not links) else 1 if groups else 0


def pingmap_cmd(a) -> int:
    from heliosdbg import linkdiag
    inv, rack = _filtered_rack(a)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out = a.out or ROOT / "results" / "link-check" / (inv.rack or "rack") / f"pingmap-{stamp}"
    _OUTS.append(out)
    _room(out, 10)
    out.mkdir(parents=True, exist_ok=True)
    try:
        sw = [linkdiag.collect_switch(x) for x in rack.switches.values()]
        owner = linkdiag.plane_owner([x for x in sw if not x.get("error")])
        pm = linkdiag.ping_map(list(rack.computes.values()), a.rounds, a.wait)
    finally:
        rack.close()
    reading = linkdiag.judge_ping_map(pm, owner)
    lines = [f"Scale-up ping map {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC  rack {inv.rack}",
             f"{a.rounds} rounds, {a.wait:.0f} s apart, {len(pm['pairs'])} GPU pairs (each GPU to the same position on the next tray)", ""]
    lines += reading
    lines.append("")
    lines.append(f"{'port':>4}  {'switch ASIC':<12} {'failed / pings':>14}  checks")
    for p, v in sorted(pm["ports"].items()):
        lines.append(f"{p:>4}  {owner.get(p, '?'):<12} {v['fails']:>6} / {v['pings']:<6}  {v['checks'] or ''}")
    print("\n".join(lines))
    (out / "report.txt").write_text("\n".join(lines) + "\n")
    (out / "pingmap.json").write_text(json.dumps({"time_utc": stamp, "rack": inv.rack, "plane_owner": owner, **pm,
                                                  "reading": reading}, indent=1, default=str))
    rows = "".join(f"<tr><td>{p}</td><td>{esc(owner.get(p, '?'))}</td><td>{v['fails']} / {v['pings']}</td>"
                   f"<td>{esc(', '.join(f'{k} {n}' for k, n in v['checks'].items()))}</td><td>{esc('; '.join(v['pairs'][:6]))}</td></tr>"
                   for p, v in sorted(pm["ports"].items()) if v["fails"])
    (out / "report.html").write_text(f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Scale-up ping map - {esc(inv.rack)}</title><style>body{{font:14px/1.5 -apple-system,'Segoe UI',Arial,sans-serif;margin:0;padding:24px max(16px,4vw);background:#f6f7f9;color:#1b2129}}
@media (prefers-color-scheme:dark){{body{{background:#12161b;color:#e6eaef}}}}table{{border-collapse:collapse;min-width:700px}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #8884}}.wrap{{overflow-x:auto}}</style></head><body>
<h1>Scale-up ping map: {esc(inv.rack)}</h1><p>{esc(time.strftime('%Y-%m-%d %H:%M', time.gmtime()))} UTC · {a.rounds} rounds, {a.wait:.0f} s apart · {len(pm['pairs'])} GPU pairs</p>
{''.join(f'<p>{esc(x)}</p>' for x in reading)}
<div class='wrap'><table><tr><th>GPU port</th><th>Switch ASIC</th><th>Failed / pings</th><th>Checks</th><th>Pairs (first 6)</th></tr>{rows or "<tr><td colspan=5>No loss.</td></tr>"}</table></div>
</body></html>
""")
    return 1 if any(v["fails"] for v in pm["ports"].values()) else 0


def bcm_cmd(a) -> int:
    """Broadcom shell view of switch ports, lane by lane: signal detect, lock, SNR, eye, FEC codeword histogram."""
    from heliosdbg import bcm
    from heliosdbg.afmctl import parse_port_description
    from heliosdbg.linkdiag import ns_flag
    inv = load_inventory(a.inventory)
    rack = Rack(inv)
    names = [x.strip() for x in (a.switch or "").split(",") if x.strip()] or sorted(rack.switches)
    unknown = [n for n in names if n not in rack.switches]
    if unknown:
        raise SystemExit(f"unknown switch {unknown} (inventory: {sorted(rack.switches)})")
    want = {x.strip() for x in (a.ports or "").split(",") if x.strip()}
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    out = a.out or ROOT / "results" / "link-check" / (inv.rack or "rack") / f"bcm-{stamp}"
    _OUTS.append(out)
    _room(out, 5)
    what = "chosen ports" if want else "every cabled trunk port" if a.all else "oper-down trunk ports"
    lines, raw, bad, seen = [f"Broadcom view {', '.join(names)} ({what})  {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC", ""], {}, 0, set()
    try:
        for swn in names:
            sw = rack.switches[swn]
            for ns in sw.namespaces():
                rows = {r.get("Interface"): r for r in parse_table(sw.sh(f"show interfaces status{ns_flag(ns)} -d all"))}
                desc = sw.port_descriptions(ns) if a.all and not want else {}
                ports = {p: r.get("Lanes", "") for p, r in rows.items()
                         if (p in want) or (not want and r.get("Vlan") == "trunk" and
                                            (parse_port_description(desc.get(p, "")) if a.all else str(r.get("Oper")).lower() != "up"))}
                if not ports:
                    continue
                seen |= set(ports)
                ref = bcm.reference_port(rows, set(ports))
                res = bcm.read_ports(sw, ns, ports | ({ref[0]: ref[1]} if ref else {}))
                refv = res.pop(ref[0], None) if ref and ref[0] not in ports else None
                if refv is None:                       # every port read: the first healthy one is the reference
                    refv = next((v for p, v in res.items() if str((rows.get(p) or {}).get("Oper")).lower() == "up"
                                 and not v.get("error") and not bcm.judge(v)[0]), None)
                for port in sorted(res, key=lambda x: int(re.sub(r"\D", "", x) or 0)):
                    v = res[port]
                    raw[f"{swn}/{ns or ''}/{port}"] = {k: x for k, x in v.items() if k != "raw"}
                    oper = (rows.get(port) or {}).get("Oper")
                    finding, ev = bcm.judge(v, refv, oper_down=str(oper).lower() != "up")
                    if a.all and not want and not finding:
                        lines.append(f"{swn} {ns or ''} {port} (oper {oper}) ok - {bcm.brief(v)}")
                    else:
                        lines.append(f"{swn} {ns or ''} {port} (oper {oper}): {finding or 'nothing wrong seen by the ASIC'}")
                        lines += [f"    {e}" for e in ev]
                    bad += bool(finding)
    finally:
        rack.close()
    missing = want - seen
    if missing:
        lines.append(f"not found on {', '.join(names)}: {', '.join(sorted(missing))}")
    if not raw:
        lines.append("no ports to read" + ("" if want or a.all else " - no oper-down trunk port (use --all for every cabled port)"))
    else:
        lines.append(f"\n{len(raw)} ports read, {bad} with a finding")
    out.mkdir(parents=True, exist_ok=True)
    (out / "bcm.txt").write_text("\n".join(lines) + "\n")
    (out / "bcm.json").write_text(json.dumps(raw, indent=1, default=str))
    print("\n".join(lines))
    print(f"\nevidence: {out}")
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv_kw = dict(default=os.environ.get("HELIOS_INVENTORY"), required=not os.environ.get("HELIOS_INVENTORY"),
                  help="the rack's inventory (or $HELIOS_INVENTORY)")
    s = sub.add_parser("scan", help="every GPU link of the rack: state and root cause")
    s.add_argument("--inventory", **inv_kw)
    s.add_argument("--interval", type=float, default=30.0, help="seconds between the two counter samples (default 30)")
    s.add_argument("--out", type=Path, help="report folder (default results/link-check/<rack>/scan-<UTC time>)")
    s.add_argument("--compare", type=Path, help="an earlier scan's link_check.json: list what changed since")
    s.add_argument("--no-bcm", action="store_true", help="skip the Broadcom shell view of physical-layer problem links")
    s.add_argument("--log-keep", type=int, default=200, help="lines of each command's output shown in report.html (200; "
                                                           "raw/commands.log.gz keeps all)")
    s.add_argument("--no-afm", action="store_true", help="skip the AFM view (GPU vPOD membership / accelerator ids / AFM "
                   "port state); it is used when the inventory has afm.url and the afm.auth.password_env variable is set")
    s.add_argument("--bcm-max", type=int, default=64, help="at most this many problem ports read in the Broadcom shell (64)")
    for x in (s,):
        x.add_argument("--switches", help="only these switches (comma-separated inventory names)")
        x.add_argument("--trays", help="only these compute trays (comma-separated inventory names)")
    m = sub.add_parser("pingmap", help="repeat a ring of L2 pings and map the loss to GPU port numbers / switch ASICs")
    m.add_argument("--inventory", **inv_kw)
    m.add_argument("--rounds", type=int, default=3, help="rounds (default 3)")
    m.add_argument("--wait", type=float, default=60, help="seconds between rounds (default 60)")
    m.add_argument("--switches", help="only these switches")
    m.add_argument("--trays", help="only these compute trays")
    m.add_argument("--out", type=Path, help="report folder (default results/link-check/<rack>/pingmap-<UTC time>)")
    p = sub.add_parser("path", help="one GPU-to-GPU path, port by port, with an L2 ping")
    p.add_argument("--inventory", **inv_kw)
    p.add_argument("--src", required=True, help="source compute tray (inventory name)")
    p.add_argument("--src-bdf", required=True, help="source GPU BDF, e.g. 0004:01:00.1 (afmctl show device)")
    p.add_argument("--dst", help="destination tray (default: the source tray)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--dst-acc", help="destination accelerator id (afmctl spec.accelerator_id on the destination tray)")
    g.add_argument("--dst-bdf", help="destination GPU BDF on --dst")
    p.add_argument("--ports", help="GPU ports, e.g. 25,26 (default: every port enabled + LINK_UP on both GPUs)")
    p.add_argument("--count", type=int, default=1, help="pings per port set (default 1)")
    p.add_argument("--no-ping", action="store_true", help="check everything except the L2 ping")
    p.add_argument("--out", type=Path, help="evidence folder (default results/link-check/<rack>/<UTC time>)")
    b = sub.add_parser("bcm", help="what one switch's Broadcom ASIC sees on given ports, lane by lane (read-only)")
    b.add_argument("--inventory", **inv_kw)
    b.add_argument("--switch", help="switch tray(s), comma-separated inventory names (default: every switch)")
    b.add_argument("--ports", help="SONiC ports, e.g. Ethernet257,Ethernet261 (default: every oper-down trunk port)")
    b.add_argument("--all", action="store_true", help="every trunk port cabled to a GPU, healthy ones too (one line each)")
    b.add_argument("--out", type=Path, help="evidence folder (default results/link-check/<rack>/bcm-<UTC time>)")
    a = ap.parse_args(argv)
    fn = {"scan": scan_cmd, "pingmap": pingmap_cmd, "path": path_cmd, "bcm": bcm_cmd}[a.cmd]
    if a.cmd == "scan":                                  # the scan keeps its log in raw/ and in report.html
        return fn(a)
    log = CommandLog()
    try:
        with log:
            return fn(a)
    finally:
        for out in _OUTS[-1:]:
            if out.exists():
                log.save(out)
                print(f"command log: {out / 'commands.log.gz'}")


if __name__ == "__main__":
    sys.exit(main())
