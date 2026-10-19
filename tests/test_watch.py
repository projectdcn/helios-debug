"""Watch mode (heliosdbg/watch.py) with stand-in reads."""
from __future__ import annotations

from heliosdbg import watch
from heliosdbg.linkdiag import Link


def test_changes_and_summary(monkeypatch):
    ln = Link("st1", "asic0", "Ethernet1", tray="c1", bdf="0001:01:00.1", gpu_port=33)
    seq = iter([
        {"sw_oper": "up", "sw_admin": "up", "gpu_link": "LINK_UP", "ll_up": "yes", "counters": {"RX_ERR": 0, "FEC_CORR": 10, "FEC_UNCORR": 0}},
        {"sw_oper": "down", "sw_admin": "up", "gpu_link": "LINK_DOWN", "ll_up": "no", "counters": {"RX_ERR": 0, "FEC_CORR": 12, "FEC_UNCORR": 0}},
        {"error": "switch: TimeoutError"},
        {"sw_oper": "up", "sw_admin": "up", "gpu_link": "LINK_UP", "ll_up": "yes", "counters": {"RX_ERR": 3, "FEC_CORR": 15, "FEC_UNCORR": 1}},
    ])
    monkeypatch.setattr(watch, "read_round", lambda rack, links: {"st1 Ethernet1": next(seq)})
    monkeypatch.setattr(watch.time, "sleep", lambda s: None)
    n = {"i": 0}

    def stop():
        n["i"] += 1
        return n["i"] >= 4
    w = watch.run(None, [ln], 1, 3600, log=lambda *_: None, stop=stop)
    pl = w["per_link"]["st1 Ethernet1"]
    assert [r["links"]["st1 Ethernet1"]["state"] for r in w["rounds"]] == ["up", "down", "unread", "up"]
    assert pl["link_changes"] == 4 and pl["errors_grew"] == {"RX_ERR": 3, "FEC_UNCORR": 1}
    assert pl["counters_grew"] == {"FEC_CORR": 5}
    assert any(c["what"] == "ll_up" and c["to"] == "no" for c in w["changes"])
