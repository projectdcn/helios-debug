"""One link from any identifier (heliosdbg/linkone.py)."""
from __future__ import annotations

import pytest

from heliosdbg import linkone

SW, CT = ["st1", "st6"], ["c1", "c2", "ct13"]
PREV = [{"switch": "st1", "sw_port": "Ethernet33", "tray": "c2", "bdf": "0002:01:00.1", "gpu_port": 33,
         "desc": "To ComputeTray Slot1/GPU2[6]/Port33"},
        {"switch": "st1", "sw_port": "Ethernet466", "tray": "c2", "bdf": "0001:01:00.1", "gpu_port": 5,
         "desc": "To ComputeTray Slot1/GPU3[7]/Port5"}]


@pytest.mark.parametrize("text,kind", [
    ("st1 Ethernet33", "switch"), ("st6/asic1/Ethernet257", "switch"), ("ST1:ethernet33", "switch"),
    ("c2 0002:01:00.1 33", "bdf"), ("c2/0002:01:00.1/port33", "bdf"),
    ("ct13 gpu1 port33", "traygpu"), ("c2 GPU2[6] Port33", "traygpu"),
    ("slot17/gpu3/port33", "slot"), ("To ComputeTray Slot1/GPU2[6]/Port33", "slot"),
    ("Port 00000005-0000 (acc-id: 5, port-id: 32) link is down", "acc"), ("acc-id: 6, port-id: 10", "acc"),
])
def test_forms(text, kind):
    assert linkone.parse(text, SW, CT).kind == kind


@pytest.mark.parametrize("text,msg", [("st9 Ethernet1", "no switch st9"), ("ct99 gpu1 port3", "no compute tray"),
                                      ("hello", "cannot read"), ("", "give a switch port")])
def test_bad(text, msg):
    with pytest.raises(linkone.TargetError, match=msg):
        linkone.parse(text, SW, CT)


def test_resolve_from_the_latest_scan():
    t = linkone.resolve(linkone.parse("c2 0001:01:00.1 5", SW, CT), PREV, {})
    assert (t.switch, t.sw_port, t.tray) == ("st1", "Ethernet466", "c2") and "latest scan" in t.how
    t = linkone.resolve(linkone.parse("slot1/gpu2/port33", SW, CT), PREV, {})
    assert (t.switch, t.sw_port) == ("st1", "Ethernet33")


def test_resolve_without_a_scan():
    desc = lambda: {"st1": {"Ethernet33": "To ComputeTray Slot1/GPU2[6]/Port33"}}  # noqa: E731
    t = linkone.resolve(linkone.parse("slot1/gpu2/port33", SW, CT), None, {"c2": 1}, read_desc=desc)
    assert (t.switch, t.sw_port, t.tray) == ("st1", "Ethernet33", "c2")
    devs = lambda: {"c2": {"0002:01:00.1": "6"}}  # noqa: E731
    t = linkone.resolve(linkone.parse("acc-id: 6, port-id: 10", SW, CT), None, {}, read_devices=devs)
    assert (t.tray, t.bdf, t.gpu_port) == ("c2", "0002:01:00.1", 10)
    with pytest.raises(linkone.TargetError, match="slot of ct13 unknown"):
        linkone.resolve(linkone.parse("ct13 gpu1 port33", SW, CT), None, {})


def test_matches_link_objects():
    t = linkone.parse("st1 Ethernet33", SW, CT)
    assert t.matches(PREV[0]) and not t.matches(PREV[1])
