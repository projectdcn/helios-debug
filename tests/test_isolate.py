"""Guided isolation (heliosdbg/isolate.py): guards, always-restore, collateral - with stand-in nodes only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from heliosdbg import isolate
from heliosdbg.linkdiag import Link
from heliosdbg.transport import CmdResult


class Sw:
    """Ports up/down by the commands it receives; 'coupled' takes a neighbour down with the port, 'stuck' stays down."""
    def __init__(self, coupled=None, stuck=False, fail_down=False):
        self.up = {"Ethernet257": True, "Ethernet261": True, "Ethernet1": True}
        self.coupled, self.stuck, self.fail_down, self.cmds = coupled, stuck, fail_down, []
        self.host = SimpleNamespace(name="st1")

    def run(self, cmd, sudo=False, timeout=120):
        self.cmds.append(cmd)
        port = cmd.split()[-1]
        if "shutdown" in cmd:
            if self.fail_down:
                return CmdResult("st1", cmd, 1, "", "error")
            self.up[port] = False
            if self.coupled:
                self.up[self.coupled] = False
        elif "startup" in cmd and not self.stuck:
            self.up[port] = True
        return CmdResult("st1", cmd, 0, "", "")

    def interfaces_status(self, ns):
        return [{"Interface": p, "Oper": "up" if u else "down"} for p, u in self.up.items()]


def link(port="Ethernet257", desc="To ComputeTray Slot0/GPU2[2]/Port13"):
    return Link("st1", "asic1", port, desc=desc, tray="c1", bdf="0003:01:00.1", gpu_port=13)


def run(sw, ln, **kw):
    return isolate.run(sw, None, ln, "switch-flap", 5, kw.pop("avoid", set()), log=lambda *_: None, sleep=lambda s: None,
                       wait_up_s=0.05, collateral_s=0.05, **kw)


def test_flap_and_restore():
    sw = Sw()
    r = run(sw, link())
    assert r["up_after"] and not r["collateral"] and r["restored"]
    assert sw.cmds[0] == "config interface -n asic1 shutdown Ethernet257" and sw.cmds[1].endswith("startup Ethernet257")


def test_collateral_reported():
    r = run(Sw(coupled="Ethernet261"), link())
    assert r["collateral"] == ["Ethernet261"] and "avoid_ports" in r["verdict"]


def test_not_back_reflaps_once():
    r = run(Sw(stuck=True), link())
    assert r["reflapped"] and not r["up_after"]


def test_restored_even_when_the_down_fails():
    sw = Sw(fail_down=True)
    with pytest.raises(RuntimeError):
        run(sw, link())
    assert sw.cmds[-1].endswith("startup Ethernet257")


@pytest.mark.parametrize("ln,avoid,msg", [
    (link(desc="uplink to spine"), set(), "only GPU links"),
    (link(), {"st1:Ethernet257"}, "avoid list"),
])
def test_guards(ln, avoid, msg):
    sw = Sw()
    with pytest.raises(isolate.Refused, match=msg):
        run(sw, ln, avoid=avoid)
    assert sw.cmds == []


def test_ui_needs_the_typed_confirmation(tmp_path):
    from ui import server
    (tmp_path / "lab.local.yaml").write_text("rack: lab\nswitches:\n  - {name: st1, host: 10.0.0.1}\ncomputes: []\n")
    st = server.State(tmp_path, tmp_path / "res")
    req = {"tool": "isolate", "inventory": "lab.local.yaml", "target": "st1 Ethernet257", "action": "switch-flap"}
    with pytest.raises(server.BadRequest, match="type the link"):
        server.build_args(st, req | {"confirm": "st1 Ethernet25"})
    a, _out, _rack = server.build_args(st, req | {"confirm": "st1  Ethernet257", "hold": 999 if False else 20})
    assert "--yes-disruptive" in a and a[1] == "st1 Ethernet257"


def test_restore_is_retried_when_the_connection_drops():
    class Flaky(Sw):
        def __init__(self):
            super().__init__()
            self.fails = 1

        def run(self, cmd, sudo=False, timeout=120):
            if "startup" in cmd and self.fails:
                self.fails -= 1
                raise OSError("Socket is closed")
            return super().run(cmd, sudo, timeout)
    sw = Flaky()
    r = run(sw, link())
    assert r["restored"] and sw.up["Ethernet257"]
    assert any(s["what"] == "restore failed" for s in r["steps"])


def test_reflap_restores_even_if_its_down_raises():
    class Stuck(Sw):
        def __init__(self):
            super().__init__(stuck=True)
            self.n = 0

        def run(self, cmd, sudo=False, timeout=120):
            if "shutdown" in cmd:
                self.n += 1
                if self.n == 2:                              # the switch took it, then the connection dropped
                    super().run(cmd, sudo, timeout)
                    raise OSError("dropped")
            return super().run(cmd, sudo, timeout)
    sw = Stuck()
    with pytest.raises(OSError):
        run(sw, link())
    assert sw.cmds[-1].endswith("startup Ethernet257")       # the last word to the switch: enable it
