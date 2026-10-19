"""Around-the-link checks (heliosdbg/linkctx.py) with stand-in nodes."""
from __future__ import annotations

import time
from types import SimpleNamespace

from heliosdbg import linkctx
from heliosdbg.linkdiag import Link


class Node:
    def __init__(self, name, ps="", ntp="yes", skew=0.0):
        self.host, self.ps, self.ntp, self.skew = SimpleNamespace(name=name), ps, ntp, skew

    def sh(self, cmd, timeout=60):
        if "timedatectl" in cmd:
            return f"{self.ntp}\n{time.time() + self.skew:.6f}\n"
        return "Up 3 hours\n@@\n" + self.ps


PS = "  20  9354 /switch-agent\n  21  8701 /sb-node-agent -slot-id 1 -controllers 10.153.80.83\n"


def test_all_good():
    ln = Link("st1", "asic0", "Ethernet33", sw_oper="up", fdb_static=True, gpu={"ifcp": {"ll_up": "yes"}})
    c = {x["check"]: x for x in linkctx.collect(Node("st1", PS), Node("c2"), 1, ln)}
    assert c["node agent of slot 1"]["ok"] and "controllers 10.153.80.83" in c["node agent of slot 1"]["detail"]
    assert c["clock offset between the ends"]["ok"] and c["IFCP session"]["ok"] and c["static forwarding entry"]["ok"]


def test_problems_named():
    ln = Link("st1", "asic0", "Ethernet33", sw_oper="up", fdb_static=False, gpu={"ifcp": {"ll_up": "no"}})
    c = {x["check"]: x for x in linkctx.collect(Node("st1", PS, ntp="no"), Node("c2", skew=-16.4), 0, ln)}
    assert c["node agent of slot 0"]["ok"] is None and "not on st1" in c["node agent of slot 0"]["detail"]
    assert c["clock of st1"]["ok"] is False and c["clock offset between the ends"]["ok"] is False
    assert "-16" in c["clock offset between the ends"]["detail"] and c["IFCP session"]["ok"] is False
