"""GPU-level state and the AFM view of the link check (heliosdbg.linkdiag check_gpus / afm_pairs / check_afm_ports)."""
from __future__ import annotations

import pytest

from heliosdbg import afm as afm_mod
from heliosdbg.linkdiag import Link, afm_pairs, check_afm_ports, check_gpus


def _tray(name, gpus):
    return {"name": name, "gpus": [{"bdf": b, "accelerator": a, "config_phase": ph, "ports": []} for b, a, ph in gpus]}


# MR3 19 Oct: after afmctl reset device -b 0001:01:00.1 on c2 the GPU stayed accelerator 0 / PROVIDER (AFM: 7)
TRAYS = {"c1": _tray("c1", [("0001:01:00.1", "3", "ACTIVE"), ("0002:01:00.1", "2", "ACTIVE")]),
         "c2": _tray("c2", [("0001:01:00.1", "0", "PROVIDER"), ("0002:01:00.1", "6", "ACTIVE")])}


def _node(name, slot, gpus):
    return {"meta": {"name": name}, "spec": {"slot-id": slot}, "status": {"scale-up-info": {"gpu-info": {
        f"u{slot}{i}": {"index": i, "acc-id": acc, "vpod-membership": vp,
                        "ports": [{"id": p, "oper-state": st} for p, st in enumerate(ports)]}
        for i, (acc, vp, ports) in enumerate(gpus)}}}}


NODES = [_node("pod-1-0-ComputeTray", 0, [(3, "pod-1.system", ["PortReady"] * 2), (2, "pod-1.system", ["PortReady"] * 2)]),
         _node("pod-1-1-ComputeTray", 1, [(7, "pod-1.system", ["PortReady"] * 2), (6, "pod-1.system", ["PortFailed", "PortReady"])])]


def _link(tray, bdf, port, state="ok"):
    return Link(switch="st1", asic="asic0", sw_port=f"Ethernet{port}", tray=tray, bdf=bdf, gpu_port=port, state=state)


def test_pairs_by_slot_and_accelerator_and_elimination():
    pairs, node_of = afm_pairs(TRAYS, {"c1": 0, "c2": 1}, NODES, {})
    assert node_of == {"c1": "pod-1-0-ComputeTray", "c2": "pod-1-1-ComputeTray"}
    assert pairs[("c2", "0002:01:00.1")][1]["acc-id"] == 6
    node, a = pairs[("c2", "0001:01:00.1")]         # accelerator 0 vs AFM 7: the one left on each side
    assert a["acc-id"] == 7 and a["_paired"] == "elimination"


def test_afm_name_wins_over_slot():
    _pairs, node_of = afm_pairs(TRAYS, {"c1": 1, "c2": 0}, NODES, {"c1": "pod-1-0-ComputeTray", "c2": "pod-1-1-ComputeTray"})
    assert node_of["c1"] == "pod-1-0-ComputeTray"


def test_unprogrammed_gpu_with_afm_is_down_and_its_links_follow():
    pairs, _ = afm_pairs(TRAYS, {"c1": 0, "c2": 1}, NODES, {})
    links = [_link("c2", "0001:01:00.1", 0), _link("c2", "0002:01:00.1", 1)]
    found = check_gpus(TRAYS, links, pairs)
    assert [(f["tray"], f["bdf"], f["kind"], f["state"]) for f in found] == [("c2", "0001:01:00.1", "gpu_not_programmed", "down")]
    assert "accelerator 7" in found[0]["cause"] and "pod-1.system" in found[0]["cause"]
    assert links[0].state == "down" and links[0].kind == "gpu_not_programmed"
    assert links[1].state == "ok"


def test_without_afm_flagged_only_when_other_gpus_are_active():
    links = [_link("c2", "0001:01:00.1", 0)]
    found = check_gpus(TRAYS, links, None)
    assert [(f["bdf"], f["kind"], f["state"]) for f in found] == [("0001:01:00.1", "gpu_not_active", "degraded")]
    idle = {"c1": _tray("c1", [("0001:01:00.1", "0", "PROVIDER"), ("0002:01:00.1", "1", "PROVIDER")])}
    assert check_gpus(idle, [], None) == []           # no vPOD anywhere: PROVIDER is normal


def test_provider_gpu_in_no_vpod_is_fine_with_afm():
    nodes = [_node("pod-1-1-ComputeTray", 1, [(7, "", ["PortReady"]), (6, "pod-1.system", ["PortReady"])])]
    trays = {"c2": TRAYS["c2"]}
    pairs, _ = afm_pairs(trays, {"c2": 1}, nodes, {})
    assert check_gpus(trays, [], pairs) == []


def test_afm_port_state_against_the_link():
    pairs, _ = afm_pairs(TRAYS, {"c1": 0, "c2": 1}, NODES, {})
    up_failed = _link("c2", "0002:01:00.1", 0)                  # AFM PortFailed, link ok
    down_ready = _link("c1", "0001:01:00.1", 1, state="down")    # AFM PortReady, link down
    down_ready.kind, down_ready.cause = "phys_went_down", "no physical link"
    fine = _link("c1", "0002:01:00.1", 0)
    check_afm_ports([up_failed, down_ready, fine], pairs)
    assert up_failed.state == "degraded" and up_failed.kind == "afm_port_failed" and up_failed.afm_port == "PortFailed"
    assert "AFM still reports the port PortReady" in down_ready.cause and down_ready.kind == "phys_went_down"
    assert fine.state == "ok" and fine.afm_port == "PortReady"


def test_afm_view_skipped_without_url_or_password(monkeypatch):
    with pytest.raises(afm_mod.AfmUnavailable, match="no afm.url"):
        afm_mod.Afm({})
    monkeypatch.delenv("HELIOS_AFM_PASSWORD", raising=False)
    with pytest.raises(afm_mod.AfmUnavailable, match="export HELIOS_AFM_PASSWORD"):
        afm_mod.Afm({"url": "https://afm.example"})


def test_tray_not_programmed_named():
    from heliosdbg.linkdiag import mark_unprogrammed_trays
    a = Link("st1", "asic0", "Ethernet1", tray="c1", bdf="0001:01:00.1", gpu_port=1, matched_by="mac")
    b = Link("st1", "asic0", "Ethernet46", tray="c2", sw_oper="up", matched_by="", kind="gpu_missing", state="degraded")
    trays = {"c1": {"gpus": [{}]}, "c2": {"gpus": [{}], "error": None}}
    assert mark_unprogrammed_trays([a, b], trays) == ["c2"]
    assert b.kind == "tray_not_programmed" and "AFM is not programming c2" in b.cause and a.kind == ""
