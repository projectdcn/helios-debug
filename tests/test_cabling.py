"""Cabling plan check (heliosdbg/cabling.py)."""
from __future__ import annotations

import pytest

from heliosdbg import cabling

LINKS = [
    {"switch": "st1", "sw_port": "Ethernet1", "desc": "To ComputeTray Slot0/GPU3[3]/Port33", "tray": "c1",
     "bdf": "0004:01:00.1", "gpu_port": 33, "matched_by": "mac", "kind": ""},
    {"switch": "st1", "sw_port": "Ethernet2", "desc": "To ComputeTray Slot0/GPU3[3]/Port35", "tray": "c1",
     "bdf": "0004:01:00.1", "gpu_port": 34, "matched_by": "mac", "kind": ""},      # really reaches port 34
    {"switch": "st1", "sw_port": "Ethernet3", "desc": "To ComputeTray Slot1/GPU0[4]/Port1", "tray": None, "bdf": None,
     "gpu_port": None, "matched_by": "description", "kind": "tray_unreachable"},
    {"switch": "st1", "sw_port": "Ethernet9", "desc": "To ComputeTray Slot1/GPU0[4]/Port2", "tray": "c2", "bdf": "0001:01:00.1",
     "gpu_port": 2, "matched_by": "mac", "kind": ""},
]
SLOTS, GMAP = {"c1": 0, "c2": 1}, {"c1:GPU3": "0004:01:00.1", "c2:GPU0": "0001:01:00.1"}


def test_check_finds_each_kind():
    plan = cabling.read_plan("switch,port,slot,gpu,gpu_port\n# comment\nst1,Ethernet1,0,3,33\nst1,Ethernet2,0,3,35\n"
                             "st1,Ethernet3,1,0,9\nst1,Ethernet7,1,1,1\n")
    r = cabling.check(plan, LINKS, SLOTS, GMAP)
    kinds = sorted((p["kind"], p["port"]) for p in r["problems"])
    assert kinds == [("cabled_elsewhere", "Ethernet2"), ("description", "Ethernet3"), ("not_found", "Ethernet7"),
                     ("not_in_plan", "Ethernet9")]
    assert r["ok"] == 1
    moved = next(p for p in r["problems"] if p["kind"] == "cabled_elsewhere")
    assert "reaches c1 0004:01:00.1 port 34" in moved["detail"] and "move the far end to c1 GPU3 port 35" in moved["detail"]


def test_tray_names_and_bad_plans():
    assert cabling.read_plan("Switch,Port,Tray,GPU,GPU_Port\nst1,Ethernet1,c2,0,1\n", SLOTS)[0]["slot"] == 1
    with pytest.raises(ValueError, match="header"):
        cabling.read_plan("a,b\n1,2\n")
    with pytest.raises(ValueError, match="slot of tray"):
        cabling.read_plan("switch,port,tray,gpu,gpu_port\nst1,Ethernet1,c9,0,1\n", SLOTS)


def test_export_round_trip():
    text = cabling.export(LINKS)
    plan = cabling.read_plan(text)
    assert len(plan) == 4 and cabling.check(plan, LINKS[:1], SLOTS, GMAP)["problems"][0]["kind"] == "not_found"
