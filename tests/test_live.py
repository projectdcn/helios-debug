"""Live mode (heliosdbg/live.py) with stand-in streams, nodes and afmctl."""
from __future__ import annotations

import queue
import time
from types import SimpleNamespace

import pytest

from heliosdbg import live

LINKS = [{"switch": "st1", "asic": "asic0", "sw_port": "Ethernet1", "tray": "c1", "bdf": "0001:01:00.1", "gpu_port": 33,
          "state": "ok", "kind": ""},
         {"switch": "st1", "asic": "asic1", "sw_port": "Ethernet292", "tray": "c2", "bdf": "0003:01:00.1", "gpu_port": 12,
          "state": "down", "kind": "phys_no_optic"}]
GPU = {"c1": {"link": "LINK_UP"}, "c2": {"link": "LINK_DOWN"}}


class Sw:
    def __init__(self):
        self.host = SimpleNamespace(name="st1", extra={})
        self.oper = {"Ethernet1": "up", "Ethernet292": "down"}

    def interfaces_status(self, ns):
        return [{"Interface": p, "Oper": o, "Admin": "up"} for p, o in self.oper.items()]


class Ct:
    def __init__(self, name):
        self.host = SimpleNamespace(name=name, extra={})


class FakeAfmctl:
    def __init__(self, tray):
        self.tray = tray.host.name

    def ports_raw(self, bdf):
        port = 33 if self.tray == "c1" else 12
        return [{"id": port, "status": {"link_status": GPU[self.tray]["link"], "ifcp": {"ll_up": "no"}}, "spec": {"admin_state": "enabled"}}]


class Q:
    """Stream stand-in: lines pushed by the test."""
    queues: dict = {}

    def __init__(self, node, cmd, max_s):
        self.q = Q.queues.setdefault(node.host.name, queue.Queue())

    @property
    def lines(self):
        while True:
            x = self.q.get()
            if x is None:
                return
            yield x

    def close(self):
        self.q.put(None)


@pytest.fixture
def lr(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "Afmctl", FakeAfmctl)
    Q.queues = {}
    rack = SimpleNamespace(switches={"st1": Sw()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, LINKS, rack_name="lab", reconcile_s=3600, log_dir=tmp_path, stream_cls=Q)
    yield r
    r.stop("test end")


def wait(cond, t=5):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_first_read_then_switch_and_tray_events(lr, tmp_path):
    lr.start()
    assert wait(lambda: lr.reconciles >= 1)
    s = lr.status()
    assert s["links"]["st1 Ethernet1"]["state"] == "ok" and s["links"]["st1 Ethernet292"]["state"] == "down"
    assert not [c for c in s["changes"] if c["link"]]                  # first fill agrees with the check: no change
    assert wait(lambda: "st1" in Q.queues and "c1" in Q.queues)
    Q.queues["st1"].put("2026 Oct 19 03:06:37.1 sw NOTICE swss0#orchagent: :- updatePortOperStatus: Port Ethernet1 oper state set from up to down")
    assert wait(lambda: lr.status()["links"]["st1 Ethernet1"]["state"] == "down")
    GPU["c2"]["link"] = "LINK_UP"
    lr.rack.switches["st1"].oper["Ethernet292"] = "up"
    Q.queues["st1"].put("x swss1#orchagent: :- updatePortOperStatus: Port Ethernet292 oper state set from down to up")
    Q.queues["c2"].put("2026-10-19T03:03:26+00:00 c2 kernel: ifoe 0003:01:00.1: port 104: link up event (seq 7)")
    assert wait(lambda: lr.status()["links"]["st1 Ethernet292"]["state"] == "ok", 8)
    ch = [(c["link"], c["what"], c["to"], c["source"]) for c in lr.status()["changes"] if c["link"]]
    assert ("st1 Ethernet1", "state", "down", "switch log") in ch
    assert ("st1 Ethernet292", "gpu_link", "LINK_UP", "tray log") in ch
    assert (tmp_path / f"lab-{time.strftime('%Y%m%d', time.gmtime())}.jsonl").read_text().count('"link"') >= 3
    GPU["c2"]["link"] = "LINK_DOWN"


def test_reconcile_catches_what_a_stream_missed(lr):
    lr.reconcile("first read")
    lr.rack.switches["st1"].oper["Ethernet1"] = "down"
    lr.reconcile()
    c = [x for x in lr.status()["changes"] if x["link"] == "st1 Ethernet1" and x["what"] == "state"]
    assert c and c[-1]["to"] == "down" and c[-1]["source"] == "re-read"


def test_stops_by_itself_when_nobody_looks(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "Afmctl", FakeAfmctl)
    rack = SimpleNamespace(switches={"st1": Sw()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, LINKS, rack_name="lab", idle_s=0.5, last_view=lambda: time.time() - 10, stream_cls=Q,
                      jump_limited=True)
    r.start()
    assert wait(lambda: not r.status()["running"])
    assert "nobody looked" in r.status()["stop_reason"] and r.status()["jump_limited"]


def test_link_state_rules():
    assert live.link_state({"sw_oper": "up", "gpu_link": "LINK_UP", "ll_up": "no"}, ifcp_in_use=False) == "ok"
    assert live.link_state({"sw_oper": "up", "gpu_link": "LINK_UP", "ll_up": "no"}, ifcp_in_use=True) == "degraded"
    assert live.link_state({"sw_oper": "down"}, False) == "down"
    assert live.link_state({"sw_oper": "up", "gpu_link": "LINK_UP", "scan_state": "degraded", "scan_kind": "tray_not_programmed"}, False) == "degraded"


@pytest.mark.skipif(__import__("shutil").which("setsid") is None, reason="setsid not here (macOS); the racks are Linux")
def test_local_stream_ends_its_whole_pipeline(tmp_path):
    """The wrapper kills the pipeline's process group when its stdin closes (MR3 c1: an orphaned journalctl -kf)."""
    import subprocess as sp
    marker = tmp_path / "alive"
    cmd = f"while true; do date >> {marker}; sleep 0.2; done | cat"
    proc = sp.Popen(["bash", "-c", live.wrap(cmd, 60).replace("sudo -n ", "")], stdin=sp.PIPE, stdout=sp.PIPE, text=True,
                    start_new_session=True)
    time.sleep(1)
    proc.stdin.close()
    proc.wait(timeout=5)
    n = marker.read_text().count("\n")
    time.sleep(1)
    assert marker.read_text().count("\n") <= n + 1          # nothing writes any more


def test_gpu_end_never_read_is_unknown_not_ok():
    assert live.link_state({"sw_oper": "up", "scan_state": "down", "scan_kind": "tray_unreachable"}, False) == "unknown"
    assert live.link_state({"sw_oper": "down", "scan_kind": "tray_unreachable"}, False) == "down"
    assert live.link_state({"sw_oper": "up", "scan_kind": "tray_not_programmed"}, False) == "degraded"



def test_until_turned_off_and_with_no_page_open(tmp_path, monkeypatch):
    """max_s None = no time limit, idle_s None = keeps running with no page open; the status says so."""
    monkeypatch.setattr(live, "Afmctl", FakeAfmctl)
    rack = SimpleNamespace(switches={"st1": Sw()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, LINKS, rack_name="lab", max_s=None, idle_s=None, last_view=lambda: time.time() - 10 ** 6,
                      stream_cls=Q, jump_limited=True)
    r.start()
    try:
        time.sleep(1.5)
        st = r.status()
        assert st["running"] and st["max_s"] is None and st["idle_s"] is None
    finally:
        r.stop()
    assert r.status()["stop_reason"] == "turned off"


def test_change_log_pauses_on_a_nearly_full_disk(tmp_path, monkeypatch):
    """Below LOG_MIN_FREE the change log stops writing (Live goes on in memory) and says so once."""
    monkeypatch.setattr(live, "Afmctl", FakeAfmctl)
    rack = SimpleNamespace(switches={"st1": Sw()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, LINKS, rack_name="lab", log_dir=tmp_path, stream_cls=Q, jump_limited=True)
    monkeypatch.setattr(live.shutil, "disk_usage", lambda p: SimpleNamespace(free=10 << 20))
    for i in range(3):
        r.note(f"n{i}", "test")
    assert r.log_paused and not r.log_path.exists()
    assert [c["to"] for c in r.changes if "paused" in str(c["to"])] and len(r.changes) == 4   # 3 notes in memory + the pause note


def test_ifcp_problem_at_the_check_gives_way_to_the_trays_reading():
    lk = {"gpu_link": "LINK_UP", "bdf": "x", "scan_state": "degraded", "scan_kind": "ifcp"}
    assert live.link_state(dict(lk, ll_up="yes"), True) == "ok"          # g02-g17 st6: the session is up now
    assert live.link_state(dict(lk, ll_up=None), True) == "degraded"     # not read: the check's word stands


def test_links_not_read_are_not_known_not_the_checks_state(tmp_path, monkeypatch):
    """g02-g17 2 Nov: st6 and ct10 off the network; their links kept a 9-day-old check's 'ok' / 'degraded'."""
    monkeypatch.setattr(live, "Afmctl", FakeAfmctl)

    class Off(Sw):
        def interfaces_status(self, ns):
            raise RuntimeError("ssh: connect to host 10.0.0.6 port 22: No route to host")
    links = LINKS + [{"switch": "st1", "asic": "asic0", "sw_port": "Ethernet9", "tray": "c9", "bdf": "0009:01:00.1",
                      "gpu_port": 1, "state": "ok", "kind": ""},
                     {"switch": "st1", "asic": "asic0", "sw_port": "Ethernet10", "tray": "c5", "bdf": None,
                      "gpu_port": None, "state": "degraded", "kind": "tray_quarantined"}]
    rack = SimpleNamespace(switches={"st1": Off()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, links, rack_name="lab", log_dir=tmp_path, stream_cls=Q, check_time="20261024-071833")
    r.reconcile("first read")
    st = r.status()
    assert st["links"]["st1 Ethernet9"]["state"] == "unknown" and st["links"]["st1 Ethernet9"]["unread"]
    assert st["links"]["st1 Ethernet1"]["state"] != "unknown"           # its tray was read
    assert st["links"]["st1 Ethernet10"]["state"] == "degraded"         # quarantined: the check's reason stays
    assert st["check_time"] == "20261024-071833"
    assert any("1 links not read" in str(c["to"]) for c in st["changes"])
    assert st["followers"]["st1 re-read"]["error"].startswith("no route to host")


def test_tray_unreachable_since_the_check_is_not_green(tmp_path, monkeypatch):
    """3 Nov audit: BDF known from the check, tray unreachable now - the switch side alone showed the link 'ok'."""
    class Down(FakeAfmctl):
        def ports_raw(self, bdf):
            raise RuntimeError("ssh: connect to host 10.0.0.9 port 22: No route to host")
    monkeypatch.setattr(live, "Afmctl", Down)
    rack = SimpleNamespace(switches={"st1": Sw()}, computes={"c1": Ct("c1"), "c2": Ct("c2")}, close=lambda: None)
    r = live.LiveRack(rack, LINKS, rack_name="lab", log_dir=tmp_path, stream_cls=Q)
    r.reconcile("first read")
    assert r.status()["links"]["st1 Ethernet1"]["state"] == "unknown"          # switch port up, GPU end not read
    assert r.status()["links"]["st1 Ethernet292"]["state"] == "down"           # the switch says down: that stands
