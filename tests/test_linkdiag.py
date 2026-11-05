"""heliosdbg.linkdiag: joining switch ports to GPU ports by MAC / description, and one root cause per problem link."""
from __future__ import annotations

import copy

from heliosdbg import linkdiag as ld

MAC = "02:00:00:02:03:19"


def _switch(oper="up", admin="up", fdb=True, desc="To ComputeTray Slot2/GPU3[11]/Port25", fec=None, fec2=None):
    a = {"status": {"Ethernet25": {"Interface": "Ethernet25", "Oper": oper, "Admin": admin}},
         "desc": {"Ethernet25": desc}, "fdb": [{"Vlan": "100", "MacAddress": MAC, "Port": "Ethernet25", "Type": "Static"}] if fdb else [],
         "counters": {"Ethernet25": {"RX_ERR": "0"}}, "fec": {"Ethernet25": fec or {"FEC_UNCORR": "10"}}, "presence": {"Ethernet25": "Not present"}}
    return {"name": "st3", "asics": {"asic0": a}, "error": None}


def _tray(link="LINK_UP", admin="enabled", up_ms=1000, ll_up="yes", peer_enabled="yes", error=None, slot=None):
    port = {"port": 25, "station": 12, "mac": MAC, "admin": admin, "link": link, "fault": "no" if link == "LINK_UP" else "yes",
            "up_ms": up_ms, "down_ms": 5000, "fec_mode": "rs-int", "loopback": "none",
            "ifcp": {"ll_up": ll_up, "peer_enabled": peer_enabled, "in_error": "no", "peer_in_error": "no"}}
    return {"name": "ct03", "host": "10.0.0.3", "slot": slot, "error": error,
            "gpus": [{"bdf": "0001:01:00.1", "accelerator": "8", "config_phase": "ACTIVE", "ports": [port]}]}


def _one(sw, tr, quarantined=None, deltas=None):
    links, learned = ld.join([sw], [tr] if tr else [], quarantined)
    assert len(links) == 1
    ln = links[0]
    ln.deltas = deltas or {}
    return ld.diagnose(ln, {t["name"]: t for t in ([tr] if tr else [])}, False, 30), learned


def test_healthy_link_joined_by_mac_and_slot_learned():
    ln, learned = _one(_switch(), _tray())
    assert ln.state == "ok" and ln.matched_by == "mac" and ln.tray == "ct03" and ln.gpu_port == 25
    assert learned["slots"] == {"ct03": 2} and learned["gpu_map"] == {"ct03:GPU3": "0001:01:00.1"}


def test_down_link_without_fdb_is_joined_by_description_once_learned():
    # a second, healthy port of the same GPU teaches slot + GPU numbering; the down port has no FDB entry
    sw, tr = _switch(), _tray()
    sw["asics"]["asic0"]["status"]["Ethernet26"] = {"Oper": "down", "Admin": "up"}
    sw["asics"]["asic0"]["desc"]["Ethernet26"] = "To ComputeTray Slot2/GPU3[11]/Port26"
    p26 = copy.deepcopy(tr["gpus"][0]["ports"][0]) | {"port": 26, "mac": "02:00:00:02:03:1a", "link": "NO_PHY_LINK, PCS_NO_BLOCK_LOCK", "up_ms": 0}
    tr["gpus"][0]["ports"].append(p26)
    links, _ = ld.join([sw], [tr])
    down = next(x for x in links if x.sw_port == "Ethernet26")
    assert down.matched_by == "description" and down.bdf == "0001:01:00.1" and down.gpu_port == 26
    ld.diagnose(down, {"ct03": tr}, False, 30)
    assert down.state == "down" and down.kind == "phys_never_up"


def test_never_up_and_went_down():
    assert _one(_switch(oper="down"), _tray(link="NO_PHY_LINK", up_ms=0))[0].kind == "phys_never_up"
    ln = _one(_switch(oper="down"), _tray(link="NO_PHY_LINK", up_ms=12345))[0]
    assert ln.kind == "phys_went_down" and "was up" in ln.cause


def test_admin_states_come_first():
    assert _one(_switch(oper="down", admin="down"), _tray(link="NO_PHY_LINK"))[0].kind == "sw_admin_down"
    ln = _one(_switch(oper="down"), _tray(link="NO_PHY_LINK", admin="idle"))[0]
    assert ln.kind == "gpu_admin" and "--admin-state enable" in ln.action and "-s 12 -p 25" in ln.action


def test_one_sided_bit_errors_ifcp_not_programmed():
    assert _one(_switch(oper="up"), _tray(link="NO_PHY_LINK"))[0].kind == "one_sided"
    assert _one(_switch(), _tray(), deltas={"FEC_UNCORR": 4})[0].kind == "bit_errors"
    assert _one(_switch(), _tray(), deltas={"FEC_CORR": 900})[0].state == "ok"      # corrected errors alone: fine
    assert _one(_switch(), _tray(ll_up="no"))[0].kind == "ifcp"
    # no FDB entry: matched by description only when the tray was learned from another link, else no tray
    sw = _switch(fdb=False)
    ln = _one(sw, _tray(slot=2))[0]
    assert ln.kind == "not_programmed"


def test_tray_unreachable_and_quarantined():
    tr = _tray(error="TimeoutError: ssh", slot=2)
    tr["gpus"] = []
    ln = _one(_switch(oper="down", fdb=False), tr)[0]
    assert ln.kind == "tray_unreachable" and ln.owner == ld.SITE
    ln = _one(_switch(oper="up", fdb=False), tr)[0]       # g02-g17 ct10: switch end up - powered and cabled, not cabling
    assert ln.kind == "tray_unreachable" and ln.owner == ld.OPERATOR and "powered and cabled" in ln.cause
    ln = _one(_switch(oper="down", fdb=False), None, quarantined={2: ("ct05", "Down")})[0]
    assert ln.kind == "tray_quarantined" and "ct05" in ln.cause
    g = ld.group_causes([ln])
    assert g[0]["cause"].endswith(": ct05") and g[0]["count"] == 1


def test_vpod_change_in_progress_is_not_a_fault():
    links, _ = ld.join([_switch(fdb=False)], [_tray(slot=2)])
    ln = links[0]
    ln.fdb_static_late = True                     # the second read found the entry
    assert ld.diagnose(ln, {"ct03": _tray(slot=2)}, False, 30).state == "ok"
    links, _ = ld.join([_switch(fdb=False)], [_tray(slot=2)])
    ln = links[0]
    ln.fdb_static_late, ln.vpod_accelerators = False, 0   # GPU in no vPOD: nothing to program
    assert ld.diagnose(ln, {"ct03": _tray(slot=2)}, False, 30).state == "ok"


def test_ifcp_peer_check_learns_mapping_and_flags_a_miscabled_port():
    tr = _tray()
    tr["gpus"][0]["ports"][0]["ifcp"] |= {"peer_device_id": "3", "peer_port_id": "25"}
    links, _ = ld.join([_switch()], [tr])
    m = ld.learn_ifcp(links)
    assert m == {"device": {"st3": "3"}, "port_is_ethernet": True, "checked_links": 1}
    assert ld.diagnose(links[0], {"ct03": tr}, False, 30, m).state == "ok"
    tr2 = copy.deepcopy(tr)
    tr2["gpus"][0]["ports"][0]["ifcp"]["peer_port_id"] = "29"          # the cable really lands on Ethernet29
    links2, _ = ld.join([_switch()], [tr2])
    ln = ld.diagnose(links2[0], {"ct03": tr2}, False, 30, m)
    assert ln.kind == "miscabled" and "st3 Ethernet29" in ln.cause


def test_ping_map_tells_sticky_from_moving_loss():
    from types import SimpleNamespace
    from heliosdbg.afmctl import Device, PingResult, Port
    calls = {"n": 0}

    class FakeAfmctl:
        def __init__(self, tray):
            self.t = tray.host.name

        def vpod_accels(self):
            base = {"ct01": 0, "ct02": 4}[self.t]
            return {"0001:01:00.1": (str(base), set())}

        def devices(self):
            return [Device("0001:01:00.1", "x", "ACTIVE")]

        def ports(self, bdf):
            return [Port(p, "enabled", "LINK_UP") for p in (0, 1, 2)]

        def ping(self, bdf, acc, ports):
            calls["n"] += 1
            res = PingResult(port_checks={"1": ["req"]})            # port 1 always fails (sticky)
            if self.t == "ct02" and calls["n"] <= 2:
                res.port_checks["2"] = ["rsp"]                      # port 2 fails in the first round only (moving)
            return res, SimpleNamespace(stdout="")
    trays = [SimpleNamespace(host=SimpleNamespace(name=n)) for n in ("ct01", "ct02")]
    pm = ld.ping_map(trays, rounds=2, wait_s=0, afmctl=FakeAfmctl, log=lambda *a: None, sleep=lambda s: None)
    assert pm["ports"][1]["fails"] == 4 and pm["ports"][0]["fails"] == 0
    text = " ".join(ld.judge_ping_map(pm, {0: "st6 asic1", 1: "st5 asic1", 2: "st6 asic1"}))
    assert "Sticky" in text and "port 1" in text and "Moving" in text and "st5 asic1" in text


def test_compare_lists_new_recovered_and_changed():
    prev = [{"switch": "st3", "asic": "asic0", "sw_port": "Ethernet25", "state": "down", "kind": "phys_went_down", "cause": "x"},
            {"switch": "st3", "asic": "asic0", "sw_port": "Ethernet26", "state": "ok", "kind": "", "cause": ""}]
    a = ld.Link("st3", "asic0", "Ethernet25", tray="ct03", gpu_port=25, state="ok")
    b = ld.Link("st3", "asic0", "Ethernet26", tray="ct03", gpu_port=26, state="down", kind="phys_went_down", cause="no link")
    d = ld.compare(prev, [a, b])
    assert len(d["recovered"]) == 1 and "Ethernet25" in d["recovered"][0]
    assert len(d["new_problems"]) == 1 and "Ethernet26" in d["new_problems"][0]
    c = ld.Link("st1", "asic0", "Ethernet1", tray="ct01", gpu_port=1, state="down", kind="phys_went_down")
    d = ld.compare(prev, [a, b, c])                      # st1 was not in the earlier (partial) scan: not 'new'
    assert len(d["new_problems"]) == 1 and d["not_in_earlier"] == 1


def test_suspects_point_at_a_gpu_with_several_down_links():
    mk = lambda sw, port: ld.Link(sw, "asic0", f"Ethernet{port}", tray="ct17", bdf="0002:01:00.1", gpu_port=port,  # noqa: E731
                                  state="down", kind="phys_went_down")
    s = ld.suspects([mk("st4", 24), mk("st4", 28), mk("st3", 25), ld.Link("st1", "asic0", "Ethernet1", state="ok")])
    assert "ct17 0002:01:00.1: 3 problem links" in s[0] and "GPU / tray side" in s[0]
    assert any("st4 asic0: 2" in x for x in s) is False          # 2 links on one ASIC is not yet a pattern


def test_suspects_same_gpu_position_on_many_trays_and_adjacent_ports():
    mk = lambda tray, sw, port, gp: ld.Link(sw, "asic0", f"Ethernet{port}", tray=tray, bdf="0002:01:00.1",  # noqa: E731
                                            gpu_port=gp, state="down", kind="phys_went_down")
    s = ld.suspects([mk("ct17", "st4", 70, 24), mk("ct18", "st4", 66, 28), mk("ct17", "st4", 69, 28), mk("ct13", "st6", 261, 0)])
    text = " | ".join(s)
    assert "GPU position 0002:01:00.1: problem links on 3 trays" in text and "shared by that GPU position" in text
    assert "st4 asic0: 3 problem links (Ethernet66, Ethernet69, Ethernet70) on adjacent ports" in text


def test_trays_filter_keeps_only_links_of_the_selected_trays():
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import link_check
    rack = SimpleNamespace(computes={"ct13": SimpleNamespace(host=SimpleNamespace(extra={"slot": 12}))})
    mk = lambda port, slot, tray=None: ld.Link("st6", "asic1", f"Ethernet{port}", tray=tray,  # noqa: E731
                                               desc=f"To ComputeTray Slot{slot}/GPU1[1]/Port0")
    res = {"links": [mk(261, 12, "ct13"), mk(262, 12), mk(170, 3), mk(171, 4)], "learned": {"slots": {"ct13": 12}}}
    assert [x.sw_port for x in link_check._only_selected_trays(res, rack)] == ["Ethernet261", "Ethernet262"]


def test_ifcp_not_running_on_the_rack_is_one_note_not_degraded_links():
    # MR2 18 Oct: every LINK_UP port ll_up no / no peer, yet the L2 ping passed on every port
    t = _tray(ll_up="no", peer_enabled=None)
    assert ld.ifcp_running({"ct03": t}) is False
    assert ld.ifcp_running({"ct03": _tray()}) is True                 # one session = IFCP in use
    links, _ = ld.join([_switch()], [t])
    ln = ld.diagnose(links[0], {"ct03": t}, False, 30, None, ifcp_in_use=False)
    assert ln.state == "ok" and any("IFCP not judged" in e for e in ln.evidence)


def test_one_cause_on_every_link_is_reported_rack_wide():
    mk = lambda i: ld.Link("st1", f"asic{i % 2}", f"Ethernet{i}", tray=f"c{i % 2 + 1}", bdf=f"000{i % 4 + 1}:01:00.1",  # noqa: E731
                           gpu_port=i % 36, state="degraded", kind="ifcp")
    s = ld.suspects([mk(i) for i in range(288)])
    assert len(s) == 1 and s[0].startswith("rack-wide: 288 of 288 links have the same cause")


def test_path_verdict_lets_a_passing_ping_win_over_ifcp_down():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import link_check
    port = {"admin": "enabled", "link": "LINK_UP", "ll_up": "no", "peer_enabled": None}
    e = {"hit": {"switch": "st1", "asic": "asic1", "port": "Ethernet422"}, "problem": None, "mac": "x"}
    ok = link_check.judge(0, port, port, e, e, {"failed": []}, {})
    assert ok.startswith("ok (L2 ping passes") and "IFCP down" in ok
    assert link_check.judge(0, port, port, e, e, {"failed": ["IFoE Req"]}, {}).startswith("IFCP")


def test_asic_gpu_map_and_ranges():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import link_check
    assert link_check._ranges([18, 19, 20, 22, 35, 34]) == "18-20, 22, 34-35"
    assert link_check._plural(1, "switch") == "1 switch" and link_check._plural(6, "switch") == "6 switches"
    mk = lambda asic, tray, bdf, p, st="ok": ld.Link("st1", asic, f"Ethernet{p}", tray=tray, bdf=bdf, gpu_port=p, state=st)  # noqa: E731
    links = [mk("asic0", "c1", "0001:01:00.1", p) for p in range(18, 36)] + [mk("asic1", "c1", "0001:01:00.1", 3, "down")]
    m = link_check.asic_gpu_map(links)
    assert m["st1 asic0"]["c1"]["0001:01:00.1"]["ok"] == 18 and m["st1 asic1"]["c1"]["0001:01:00.1"]["worst"] == "down"
    assert link_check.map_lines(links)[0] == "  st1 asic0: 18/18 links ok - c1 1 GPU x ports 18-35"


def test_command_log_records_every_command_and_trims_the_html():
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import link_check
    from heliosdbg import transport
    log = link_check.CommandLog()
    with log:
        transport._record("st1", "show interfaces status", SimpleNamespace(rc=0, duration=0.5, stdout="a\nb\nc", stderr=""), None, 0)
        transport._record("c1", "afmctl show device --json", None, "AuthenticationException: Authentication failed.", 1)
    transport._record("st1", "after the scan", SimpleNamespace(rc=0, duration=0, stdout="", stderr=""), None, 2)
    assert len(log.entries) == 2                                   # nothing recorded after the with block
    h = log.html(["st1", "c1"], keep=2)
    assert "Command log: <b>st1</b> (1 commands, 3 lines)" in h and "1 more lines" in h
    assert "AuthenticationException" in h and "1 failed" in h
    assert "$ show interfaces status" in log.text()


def _rack(descs: dict, macs: dict):
    """One switch ASIC with ports {EthernetN: description} and static entries {EthernetN: (slot, gpu, port)}; two trays
    (slot 0 / 1) with 2 GPUs x ports 1..3 whose MACs encode (slot, gpu, port)."""
    mac = lambda s, g, p: f"02:00:00:{s:02x}:{g:02x}:{p:02x}"  # noqa: E731
    a = {"status": {p: {"Interface": p, "Oper": "up", "Admin": "up"} for p in descs}, "desc": dict(descs),
         "fdb": [{"Vlan": "100", "MacAddress": mac(*macs[p]), "Port": p, "Type": "Static"} for p in macs],
         "counters": {}, "fec": {}, "presence": {}}
    trays = [{"name": f"ct0{s + 1}", "host": "x", "slot": None, "error": None, "gpus": [
        {"bdf": f"000{g + 1}:01:00.1", "accelerator": str(s * 4 + g), "config_phase": "ACTIVE", "ports": [
            {"port": p, "station": p // 2, "mac": mac(s, g, p), "admin": "enabled", "link": "LINK_UP", "fault": "no",
             "up_ms": 1000, "down_ms": 0, "ifcp": {"ll_up": "yes", "peer_enabled": "yes", "in_error": "no",
                                                   "peer_in_error": "no"}} for p in (1, 2, 3)]} for g in (0, 1)]}
        for s in (0, 1)]
    return {"name": "st1", "asics": {"asic0": a}, "error": None}, trays


def _cabled(off=0):
    """Every (slot, gpu, port) on its own port, described as cabled (acc number shifted by ``off``)."""
    descs, macs, n = {}, {}, 0
    for s in (0, 1):
        for g in (0, 1):
            for p in (1, 2, 3):
                descs[f"Ethernet{n}"] = f"To ComputeTray Slot{s}/GPU{g}[{s * 4 + g + off}]/Port{p}"
                macs[f"Ethernet{n}"] = (s, g, p)
                n += 1
    return descs, macs


def test_description_naming_another_gpu_or_port_is_miscabled():
    descs, macs = _cabled()
    # two cables of one GPU port number swapped between trays, and two ports of one GPU swapped (other port number)
    descs["Ethernet0"], descs["Ethernet6"] = descs["Ethernet6"], descs["Ethernet0"]      # ct01 GPU0 p1 <-> ct02 GPU0 p1
    descs["Ethernet3"], descs["Ethernet4"] = descs["Ethernet4"], descs["Ethernet3"]      # ct01 GPU1 p1 <-> GPU1 p2
    sw, trays = _rack(descs, macs)
    links, learned = ld.join([sw], trays)
    by = {ln.sw_port: ld.diagnose(ln, {t["name"]: t for t in trays}, False, 30) for ln in links}
    bad = sorted(p for p, ln in by.items() if ln.state != "ok")
    assert bad == ["Ethernet0", "Ethernet3", "Ethernet4", "Ethernet6"]
    e0 = by["Ethernet0"]
    assert e0.kind == "miscabled" and e0.tray == "ct01" and e0.matched_by == "mac"
    assert "Slot1/GPU0/Port1" in e0.cause and "ct01 (slot 0) GPU0" in e0.cause and "st1 Ethernet6" in e0.cause
    e3 = by["Ethernet3"]                    # holds GPU1 port 1's cable, described as port 2
    assert e3.gpu_port == 1 and "Slot0/GPU1/Port2" in e3.cause and "port 1" in e3.cause and "st1 Ethernet4" in e3.cause
    assert learned["gpu_map"] == {"ct01:GPU0": "0001:01:00.1", "ct01:GPU1": "0002:01:00.1",       # swap outvoted
                                  "ct02:GPU0": "0001:01:00.1", "ct02:GPU1": "0002:01:00.1"}


def test_accelerator_number_alone_is_not_miscabled():
    """g02-g17 describes AFM acc 0 as acc 3 (and the vrack fault desc_acc_off_by_one shifts it by one): only the
    slot / GPU / port of a description are compared with the cable."""
    descs, macs = _cabled(off=1)
    sw, trays = _rack(descs, macs)
    links, _ = ld.join([sw], trays)
    assert all(ld.diagnose(ln, {t["name"]: t for t in trays}, False, 30).state == "ok" for ln in links)


def test_numbering_convention_on_most_links_is_not_reported_as_cabling():
    descs, macs = _cabled()
    for k, p in enumerate(descs):          # every description names the other GPU: a convention, not 12 bad cables
        descs[p] = descs[p].replace("/GPU0[", "/GPUx[").replace("/GPU1[", "/GPU0[").replace("/GPUx[", "/GPU1[")
    sw, trays = _rack(descs, macs)
    links, _ = ld.join([sw], trays)
    assert all(not getattr(ln, "_desc_off", None) for ln in links)


def test_flap_counts_read_per_asic_and_shown_on_the_link():
    class Sw:
        def sh(self, cmd, **kw):
            assert "APPL_DB keys 'PORT_TABLE:Ethernet*'" in cmd and kw.get("sudo")
            return ("Ethernet25|{'admin_status': 'up', 'flap_count': '9', 'last_down_time': 'Sat Oct 25 08:55:15 2026'}\n"
                    "Ethernet26|{'admin_status': 'up'}\n")
    fl = ld.read_flaps(Sw(), "asic0")
    assert fl == {"Ethernet25": (9, "Sat Oct 25 08:55:15 2026"), "Ethernet26": (None, None)}
    sw = _switch()
    sw["asics"]["asic0"]["flaps"] = fl
    ln, _ = _one(sw, _tray())
    assert (ln.flap_count, ln.state) == (9, "ok") and "flap count 9, last down Sat Oct 25 08:55:15 2026" in ln.evidence[0]
    from heliosdbg import ai
    ev, _ = ai.link_context({"links": [ld.link_dict(ln)]}, "st3 Ethernet25")
    assert any("Switch port: admin up, oper up, flap count 9, last down Sat Oct 25" in x["text"] for x in ev.items)


def test_compare_with_unknown_before():
    """Audit 4 Nov: links 'unknown' in a check saved from Live were 'recovered' when ok, 'still bad' when down."""
    from heliosdbg.linkdiag import Link, compare
    prev = [{"switch": "st1", "asic": "asic0", "sw_port": "Ethernet1", "state": "unknown"},
            {"switch": "st1", "asic": "asic0", "sw_port": "Ethernet2", "state": "unknown"}]
    a = Link("st1", "asic0", "Ethernet1", tray="c1", state="ok")
    b = Link("st1", "asic0", "Ethernet2", tray="c1", state="down", cause="x")
    c = compare(prev, [a, b])
    assert c["recovered"] == [] and c["still_bad"] == 0 and len(c["new_problems"]) == 1 and "not read before" in c["new_problems"][0]


def test_tray_that_answers_but_afmctl_fails_is_not_unreachable():
    tr = _tray(error="CommandError: [ct03] afmctl: error: cannot connect to agent (rc=1: afmctl show device --json)", slot=2)
    tr["gpus"] = []
    ln = _one(_switch(oper="up", fdb=False), tr)[0]
    assert ln.kind == "tray_unreachable" and "answered, but its GPU ports could not be read" in ln.cause


def _d(sw, tray, state, kind="", port="Ethernet1"):
    return {"switch": sw, "sw_port": port, "tray": tray, "state": state, "kind": kind, "owner": "x"}


def test_switch_wide_ifcp_is_one_finding():
    ls = [_d("st4", f"ct{t:02}", "degraded", "ifcp", f"Ethernet{t}{p}") for t in range(1, 5) for p in range(3)]
    ls += [_d("st1", f"ct{t:02}", "ok") for t in range(1, 5)] + [_d("st1", "ct09", "down", "phys_went_down")]
    g = ld.group_causes(ls)
    assert [x["kind"] for x in g] == ["phys_went_down", "switch_ifcp"]
    assert g[1]["switch"] == "st4" and g[1]["count"] == 12 and "4 trays" in g[1]["cause"]
    ls2 = [x for x in ls if x["switch"] == "st4"]                 # no other switch with those GPUs fine: per-link IFCP
    assert [x["kind"] for x in ld.group_causes(ls2)] == ["ifcp"]
    ls3 = ls + [_d("st4", "ct01", "down", "phys_never_up")]       # another cause on the switch: not switch-wide
    assert "switch_ifcp" not in [x["kind"] for x in ld.group_causes(ls3)]
