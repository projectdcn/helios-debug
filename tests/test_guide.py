"""Guided debugging and tickets: the read-only allow-list refuses anything that could change the rack, the steps
loop works with a stand-in model, and a ticket's facts come from the check (not the model)."""
from __future__ import annotations

import pytest

from heliosdbg import ai, guide, ticket


@pytest.mark.parametrize("cmd,role", [
    ("show interfaces status -n asic0 Ethernet8", "switch"),
    ("show interfaces counters -n asic1 -i Ethernet170", "switch"),
    ("sudo show mac -n asic0 | grep Ethernet8", "switch"),
    ("show logging | tail -200", "switch"),
    ("sudo sonic-db-cli -n asic0 APPL_DB keys 'FDB_TABLE:*'", "switch"),
    ("docker ps", "switch"),
    ("sudo afmctl show port -b 0004:01:00.1 --json", "compute"),
    ("afmctl show device --json", "compute"),
    ("dmesg | tail -100", "compute"),
])
def test_allowed(cmd, role):
    c, _sudo = guide.check(cmd, role)
    assert not c.startswith("sudo")


@pytest.mark.parametrize("cmd,role", [
    ("config interface shutdown Ethernet8", "switch"),           # changes the rack
    ("sudo sonic-clear fdb all", "switch"),
    ("sudo sonic-db-cli -n asic0 APPL_DB del FDB_TABLE:Vlan100:00:11:22:33:44:55", "switch"),
    ("show mac; reboot", "switch"),                               # chaining
    ("show mac && reboot", "switch"),
    ("show mac $(reboot)", "switch"),
    ("show mac `reboot`", "switch"),
    ("show logging > /tmp/x", "switch"),
    ("show mac | sh", "switch"),
    ("show mac | grep x | sh", "switch"),
    ("afmctl reset device -b 0001:01:00.1", "compute"),
    ("sudo afmctl show port -b 0004:01:00.1 --json", "switch"),    # wrong kind of node
    ("show interfaces status", "compute"),
    ("sudo reboot", "compute"),
    ("rm -rf /", "compute"),
])
def test_refused(cmd, role):
    with pytest.raises(guide.GuideError):
        guide.check(cmd, role)


def test_propose_and_conclude_with_a_stand_in_model(monkeypatch):
    ev = ai.Evidence()
    ev.add("Verdict: degraded, kind ifcp", "link")
    replies = ['{"done": false, "node": "ct02", "command": "sudo afmctl show port -b 0004:01:00.1 --json", "why": "IFCP"}',
               '{"done": false, "node": "st6", "command": "sudo config interface shutdown Ethernet170", "why": "x"}',
               '{"done": false, "node": "st6", "command": "show interfaces status -n asic0", "why": "the port"}',
               '{"done": false, "node": "st6", "command": "show system-health detail -n asic0 -d all", "why": "x"}',
               '{"done": false, "node": "st6", "command": "show system-health detail -n asic0", "why": "x"}',
               'Here: {"done": true, "conclusion": "st6 asic0 has no IFCP [S1]", "next": "AMD"}']
    seen = []
    monkeypatch.setattr(ai, "chat", lambda msgs, env=None, max_tokens=900: (seen.append(msgs) or replies.pop(0), "m"))
    nodes = {"st6": "switch", "ct02": "compute"}
    p = guide.propose(ai, ev, "link st6 Ethernet170", [], nodes)
    assert p["allowed"] and p["command"] == "afmctl show port -b 0004:01:00.1 --json"
    p = guide.propose(ai, ev, "link st6 Ethernet170", [{"node": "ct02", "command": p["command"], "rc": 0, "output": "x"}], nodes)
    assert p["allowed"] and p["retried"] and p["command"] == "show interfaces status -n asic0"    # refused, told why, asked again
    assert "Refused:" in seen[-1][-1]["content"] and "watchdogutil status" in seen[-1][-1]["content"]
    p = guide.propose(ai, ev, "link st6 Ethernet170", [], nodes)
    assert not p["allowed"] and "read-only" in p["refused"] and p["retried"]                     # refused twice: shown so
    p = guide.propose(ai, ev, "link st6 Ethernet170", [], nodes)
    assert p["done"] and "[S1]" in p["conclusion"]


def test_ticket_facts_come_from_the_check():
    scan = {"rack": "r", "time_utc": "20261024-071833", "afm_names": {"st6": "pod-1-5-SwitchTray", "st1": "pod-1-0-SwitchTray"},
            "links": [{"switch": "st6", "asic": "asic0", "sw_port": f"Ethernet{i}", "tray": "ct02", "bdf": "b", "gpu_port": i,
                       "state": "degraded", "ifcp": {"ll": "no"}} for i in range(20)],
            "fdb_broken": [{"switch": "st1", "ns": "asic0", "vlan": "100", "mac": "00:11:22:33:44:55", "port": "Ethernet8",
                            "type": "static", "source": "APPL_DB FDB_TABLE - added at runtime"}]}
    probs = ticket.problems(scan)
    assert [p["audience"] for p in probs] == ["amd", "switch"]
    md = ticket.render(scan, "all", probs, None, "results/x/report.html")
    assert "20 of 20 GPU links up without an IFCP session" in md and "00:11:22:33:44:55 -> Ethernet8" in md
    assert "not written - no AI model connected" in md and "2026-10-24 07:18 UTC" in md
    one = ticket.render(scan, "switch", probs, {"summary": "S", "ask": "- A", "model": "m"})
    assert "## 1. pod-1-0-SwitchTray (st1)" in one and "IFCP" not in one.split("## What")[0].split("## 1.")[1]   # only its own, numbered from 1


def test_docsearch_and_chat_context(tmp_path, monkeypatch):
    """The debug guide is always searchable, helios-slm indexes are added from HELIOS_AI_DOCS; a chat question gets
    the check, facts about the nodes / ports it names, Live changes and matching documentation [D..]."""
    import json as _j
    from heliosdbg import docsearch
    d = tmp_path / "sonic"
    d.mkdir()
    (d / "chunks.jsonl").write_text(_j.dumps({"title": "BCM", "section": "BCM shell", "url": "https://x/#b",
                                               "text": "Use sudo bcmsh -n 1 for the second ASIC shell."}) + "\n")
    (d / "meta.json").write_text('{"name": "sonic", "url": "https://x/"}')
    monkeypatch.setenv("HELIOS_AI_DOCS", str(tmp_path))
    docsearch._CACHE.clear()
    idx = docsearch.load()
    assert {s["source"] for s in docsearch.sources()} >= {"debug guide", "sonic"}
    assert idx.search("bcm shell second asic")[0]["source"] == "sonic"
    # a test case id named: its own passage first; otherwise no one source fills every slot
    rows = [{"title": f"Test plan TC-AFM-00{i}", "section": "s", "text": f"Test case TC-AFM-00{i}: IFCP session check "
             + ("mentions TC-AFM-002" if i == 3 else ""), "source": "testplan"} for i in range(1, 7)]
    small = docsearch.Index(rows + [{"title": "Guide", "section": "IFCP", "text": "IFCP session: how to read it", "source": "guide"}])
    assert [h["title"] for h in small.search("did TC-AFM-002 pass?", k=2)] == ["Test plan TC-AFM-002", "Test plan TC-AFM-003"]
    assert [h["source"] for h in small.search("IFCP session check", k=3, min_score=0.01)].count("testplan") == 2
    plan = docsearch.Index([{"title": "Test plan TC-AFM-002", "section": "TransferBench In-Domain", "source": "testplan",
                             "text": "Test case TC-AFM-002 (L1): TransferBench In-Domain. LATEST execution status: PARTIAL on SONiC.x. "
                                     "Latest run: [16 Oct] PARTIAL: passed on every reachable tray. Access needed: SSH."}])
    assert ai.plan_facts(plan, "did tc-afm-002 pass?") == [
        "TC-AFM-002 (TransferBench In-Domain): latest status PARTIAL on SONiC.x - [16 Oct] PARTIAL: passed on every reachable tray."]
    assert ai.plan_facts(plan, "why is st6 degraded?") == []
    scan = {"rack": "r", "time_utc": "t", "afm_names": {"st6": "pod-1-5-SwitchTray"},
            "links": [{"switch": "st6", "asic": "asic0", "sw_port": "Ethernet170", "tray": "ct02", "bdf": "b", "gpu_port": 20,
                       "state": "degraded", "kind": "ifcp", "cause": "no IFCP session", "ifcp": {"ll": "no"}, "vlans": [["Vlan200", "pt"]]},
                      {"switch": "st1", "asic": "asic0", "sw_port": "Ethernet8", "tray": "ct01", "state": "ok"}]}
    ev, subject = ai.chat_context(scan, "why has pod-1-5-SwitchTray Ethernet170 no IFCP? and the bcm shell?",
                                  live=[{"t": "t1", "link": "st6 Ethernet170", "what": "state", "from": "ok", "to": "degraded", "source": "log"}],
                                  docs=idx)
    txt = ev.block()
    assert subject == "the rack (chat)" and "pod-1-5-SwitchTray (st6): 1 links" in txt and "up without an IFCP session" in txt
    assert "Ethernet170 <-> ct02" in txt and "Live change t1" in txt and "[D1] BCM - BCM shell" in txt
    msgs = ai.build_messages(ev, subject, "q")
    assert "open chat" in msgs[0]["content"] and "### Problem" not in msgs[0]["content"].split("open chat")[1][:50]
    r = ai.review("See [E1] and [D1], not [D7].", ev)
    assert "D1" in r["cited"] and r["unknown_citations"] == ["D7"]


def test_chat_smalltalk_is_answered_without_the_model():
    from ui import server
    assert server.SMALLTALK_RX.fullmatch("hi") and server.SMALLTALK_RX.fullmatch("Thanks!") and server.SMALLTALK_RX.fullmatch(" hello ")
    assert not server.SMALLTALK_RX.fullmatch("hi, why is st6 asic0 degraded?")
    r = server.smalltalk("hi", {"time_utc": "t", "links": [{"state": "ok"}, {"state": "down"}]}, "g02-g17", "p")
    assert r["answer"].startswith("Hi.") and "2 GPU links - 1 down, 1 ok" in r["answer"] and r["model"] == "(no model needed)"


def test_rackmap_facts():
    """GPU port -> switch port by GPU number / PCI / acc id, the path between two GPUs, MAC lookups, unread switches."""
    from heliosdbg import rackmap
    links = []
    for tray, base, acc in (("ct02", 0, 7), ("ct13", 100, 51)):
        for p in range(4):
            links.append({"switch": "st6" if p % 2 else "st5", "asic": "asic0", "sw_port": f"Ethernet{base + p}", "tray": tray,
                          "bdf": "0004:01:00.1", "gpu_port": p, "state": "ok", "vlans": [["Vlan100", "pt"]]})
    scan = {"links": links, "afm_names": {"ct02": "pod-1-1-ComputeTray", "st6": "pod-1-5-SwitchTray"},
            "gpu_map": {"ct02:GPU0": "0004:01:00.1", "ct13:GPU0": "0004:01:00.1"}, "gpu_acc": {"ct02:0004:01:00.1": 7, "ct13:0004:01:00.1": 51},
            "not_checked": [{"node": "st1", "role": "switch"}]}
    f = rackmap.facts(scan, "Which switch ports is pod-1-1-ComputeTray GPU0 connected to?")
    assert any("GPU0 (0004:01:00.1, acc 7): 4 links" in x and "st6 asic0: GPU ports 1/3 -> Ethernet1/Ethernet3" in x for x in f)
    assert any("could not read switch(es) st1" in x for x in f)
    f = rackmap.facts(scan, "path from ct02 GPU0 to acc 51")
    assert any(x.startswith("Path ct02") for x in f) and any("port 1: Ethernet1 -> Ethernet101" in x for x in f)
    assert any("--dst-accelerator 51" in x for x in f)
    assert "Summary: 4 of 4 common ports have both ends ok; every chip on the path is fully ok" in f
    links[5]["state"] = "down"                                  # ct13 port 1 (st6)
    f = rackmap.facts(scan, "path from ct02 GPU0 to acc 51")
    assert "Summary: 3 of 4 common ports have both ends ok; not fully ok: st6 asic0 (1 of 2)" in f
    links[5]["state"] = "ok"
    f = rackmap.facts(scan, "which switch port is ct05 GPU1 connected to?")
    assert any(x.startswith("ct05: no GPU link of it in this check") for x in f)
    f = rackmap.facts(scan, "what is on st6 Ethernet3 and MAC 02:00:00:07:00:03?", {"02:00:00:07:00:03": {"switch": "st6", "ns": "asic0", "port": "Ethernet3", "vlan": "100"}})
    assert any("MAC 02:00:00:07:00:03: static forwarding entry on st6 asic0 Ethernet3" in x for x in f)
    assert any("st6 asic0 Ethernet3 <-> ct02 GPU0" in x and "forwarding entry MAC 02:00:00:07:00:03" in x for x in f)
    assert rackmap.facts(scan, "why is the rack degraded?") == []


def test_compact_afmctl_json_for_the_model():
    """afmctl --json port listings become one line per port (36 ports of one-line JSON were cut after a dozen)."""
    import json as _j
    from heliosdbg import guide
    ports = [{"id": str(p), "spec": {"admin_state": "idle" if p == 25 else "enabled"},
              "status": {"link_status": "LINK_DOWN" if p == 25 else "LINK_UP",
                         "ifcp": {"ll_up": "no" if p == 25 else "yes", "peer_enabled": "yes", "peer_device_id": "3",
                                  "peer_port_id": str(100 + p), "in_error": "no", "peer_in_error": "no"}}} for p in range(36)]
    out = guide.compact(_j.dumps({"device": [{"bdf": "0001:01:00.1", "port": ports}]}))
    assert out.splitlines()[0] == "GPU 0001:01:00.1:" and len(out.splitlines()) == 37 and len(out) < 3000
    assert " port 25: LINK_DOWN, admin idle, IFCP ll_up no peer_enabled yes peer 3/125" in out
    dev = guide.compact(_j.dumps({"device": [{"bdf": "0002:01:00.1", "spec": {"accelerator_id": "5", "config_phase": "ACTIVE",
                                                                                   "vpod_accelerators": ["1", "2"]}}]}))
    assert dev == "GPU 0002:01:00.1: accelerator 5, config_phase ACTIVE, vPOD accelerators 2"
    assert guide.compact("Ethernet170 down up") == "Ethernet170 down up" and guide.compact("{not json") == "{not json"
    assert "port 35:" in guide.steps_block([{"node": "ct02", "command": "x", "rc": 0, "output": _j.dumps({"device": [{"bdf": "b", "port": ports}]})}])


def test_same_moment_ties_ports_that_dropped_together():
    """A down link names the switch's other ports that went down at the same second (coupled ports, a restart)."""
    from heliosdbg import ai
    mk = lambda p, admin, st, t: {"switch": "st2", "asic": "asic1", "sw_port": p, "sw_admin": admin, "sw_oper": "down",
                                  "state": st, "last_down_time": t, "tray": "ct12", "bdf": "0003:01:00.1", "gpu_port": 16}
    scan = {"rack": "r", "time_utc": "t", "links": [mk("Ethernet269", "down", "down", "2026-10-25 09:18:01"),
                                                    mk("Ethernet270", "up", "down", "2026-10-25 09:18:01"),
                                                    mk("Ethernet300", "up", "down", "2026-10-24 01:00:00"),
                                                    dict(mk("Ethernet301", "up", "ok", ""), sw_oper="up")]}
    ev, _s = ai.link_context(scan, "st2 Ethernet270")
    t = ev.block()
    assert "Went down at the same second (2026-10-25 09:18:01) as 1 other port(s) of st2: asic1 Ethernet269 (admin down" in t
    assert "Ethernet300" not in t.split("same second")[1].split("\n")[0]
    ev, _s = ai.link_context(scan, "st2 Ethernet300")
    assert "same second" not in ev.block()


def test_grep_tail_cannot_glob_root_files_and_runs_without_sudo():
    """Audit 4 Nov: 'docker ps | grep -v /etc/[gs]hadow' ran as root and grep printed /etc/shadow."""
    import pytest
    from heliosdbg import guide
    for bad in ("docker ps | grep -v /etc/[gs]hadow", "dmesg | grep -v /root/.ssh/[ai]*", "docker ps | grep -f/etc/shadow",
                "docker ps | grep -v -/etc/shadow"):
        with pytest.raises(guide.GuideError):
            guide.check(bad, "switch")
    assert guide.check("docker ps | grep swss", "switch") == ("docker ps | grep swss", True)
    sent = []

    class T:
        def run(self, cmd, timeout=90, sudo=False):
            sent.append((cmd, sudo))
            return type("R", (), {"rc": 0, "stdout": "", "stderr": ""})()
    guide.run(type("H", (), {"name": "st5"})(), T(), "docker ps | grep swss", "switch")
    assert sent == [("sudo -n bash -c 'docker ps' | grep swss", False)]
    assert guide.check("show platform leak status", "switch")[1] is False
    assert guide.check("sudo bmc-manager health", "switch")[1] is True
    for bad in ("bmc-manager power-cycle --yes", "sonic-installer install x.bin", "show logging -f"):
        with pytest.raises(guide.GuideError):
            guide.check(bad, "switch")
