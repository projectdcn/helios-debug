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


def test_grep_flag_after_pattern_and_placeholder_bdf():
    """g02-g17 4 Nov: 'show logging | grep pfc -i' was refused; the model ran afmctl on a made-up 0000:00:00.0."""
    assert guide.check("show logging | grep pfc -i", "switch")[0] == "show logging | grep pfc -i"
    assert guide.check("show logging | grep -i pfc -c", "switch")[0] == "show logging | grep -i pfc -c"
    for bad in ("show logging | grep pfc -f /etc/shadow", "show logging | grep pfc /etc/shadow", "show logging | grep pfc -i | sh"):
        with pytest.raises(guide.GuideError):
            guide.check(bad, "switch")
    with pytest.raises(guide.GuideError, match="placeholder"):
        guide.check("sudo afmctl show port -b 0000:00:00.0 --json", "compute")
    assert guide.check("sudo afmctl show port -b 0004:01:00.1 --json", "compute")[1] is True


def test_a_node_that_cannot_be_reached_is_said_and_not_proposed_again():
    """g02-g17 4 Nov: st6 is off the management network; S1 showed only ssh's 'No route to host'."""
    s1 = {"node": "st6", "command": "show interfaces status -n asic0", "rc": 255,
          "output": "[stderr] ssh: connect to host 10.255.4.76 port 22: No route to host"}
    assert guide.unreachable(s1)["kind"] == "no_route"
    assert guide.unreachable(s1 | {"rc": 1}) is None
    assert "NOT RUN - could not log in to st6" in guide.steps_block([s1])

    class AI:
        def __init__(self, texts):
            self.texts = list(texts)

        def build_messages(self, ev, subject):
            return [{"role": "system", "content": ""}, {"role": "user", "content": "x\n\nQuestion: q"}]

        def chat(self, msgs, env=None, max_tokens=500):
            return self.texts.pop(0), "stand-in"
    ai_ = AI(['{"done": false, "node": "st6", "command": "show platform fan", "why": "w"}',
              '{"done": false, "node": "st5", "command": "show platform fan", "why": "w"}'])
    out = guide.propose(ai_, None, "s", [s1], {"st5": "switch", "st6": "switch"})
    assert out["allowed"] and out["node"] == "st5" and out.get("retried")

    class T:
        def run(self, cmd, timeout=90, sudo=False):
            return type("R", (), {"rc": 255, "stdout": "", "stderr": "ssh: connect to host 10.255.4.76 port 22: No route to host"})()
    r = guide.run(type("H", (), {"name": "st6"})(), T(), "show platform fan", "switch")
    assert r["output"].startswith("Could not log in to st6: no route to host")


def test_step_facts_and_tray_restart_flagged():
    """mr2 4 Nov: GPU port 13 NO_PHY_LINK and st1 Ethernet257 down/up - the model said to power st1 off and on."""
    gpu = "GPU 0002:01:00.1:\n" + "".join(f" port {i}: LINK_UP, admin enabled, IFCP ll_up yes peer_enabled yes peer 1/2{i:02d}\n" for i in range(13)) \
        + " port 13: NO_PHY_LINK, PCS_NO_BLOCK_LOCK, admin enabled, IFCP ll_up no peer_enabled None peer None/None\n" \
        + " port 14: LINK_UP, admin enabled, IFCP ll_up yes peer_enabled yes peer 1/262\n"
    sw = ("Ethernet257          193,194     400G   9100    N/A  Ethernet449/1   trunk    down       up     N/A         N/A\n"
          "Ethernet473              1,2     400G   9100    N/A  Ethernet257/1   trunk      up       up     N/A         N/A\n")
    steps = [{"node": "c1", "command": "afmctl show port -b 0002:01:00.1 --json", "rc": 0, "output": gpu},
             {"node": "st1", "command": "show interfaces status -n asic1 -d all | grep Ethernet257", "rc": 0, "output": sw}]
    f = guide.step_facts(steps)
    assert any("port(s) 13 NO_PHY_LINK/PCS_NO_BLOCK_LOCK" in x and "other 14 ports" in x for x in f)
    assert any("st1 Ethernet257: admin up, oper down" in x for x in f)
    assert "Ethernet473" not in " ".join(f) and f[-1].startswith("Together: one link has no signal")
    assert ai.unsafe_text("one change: start the switch tray again. Next: start the switch tray st1 from the power of the rack")
    assert ai.unsafe_text("reseat the cable between st1 Ethernet257 and the GPU port") is None


def test_a_general_how_to_is_not_answered_with_the_open_problem():
    """mr2 4 Nov: 'how can i debug link failures or port down issues' got the root cause of the open link again."""
    assert ai.generic_howto("how can i debug link failures or port down issues")
    assert ai.generic_howto("how do I read the IFCP state of a GPU port?")
    for q in ("why is this link down ?", "how can I check st1 Ethernet257", "how do I fix it", "what is wrong here"):
        assert not ai.generic_howto(q), q
    ev = ai.Evidence()
    ev.add("st1 asic1 Ethernet257 <-> c1 GPU2 port 13 down")
    assert "general how-to" not in ai.build_messages(ev, "x", "how can i debug port down issues")[-1]["content"]
    ev.howto = True
    assert "general how-to" in ai.build_messages(ev, "x", "how can i debug port down issues")[-1]["content"]


def test_commands_suggested_in_an_answer_are_runnable_and_runs_are_evidence():
    """mr2 4 Nov: the answer's 'Debug next' commands can be run from the answer; what was run feeds the next question."""
    roles = {"st1": "switch", "c1": "compute"}
    text = ("1. on st1: `show interfaces status -n asic1 Ethernet257`\n"
            "2. on pod-1-0-ComputeTray (c1): `sudo afmctl show port -b 0002:01:00.1 --json`\n"
            "3. on pod-1-0-ComputeTray: `sudo afmctl show port -b <bdf> --json`\n"
            "4. on st1: `config interface shutdown Ethernet257`\n5. on st9: `show version`\n")
    rs = guide.runnable(text, roles, {"pod-1-0-ComputeTray": "c1"})
    assert [(r["node"], r["allowed"]) for r in rs] == [("st1", True), ("c1", True), ("c1", False), ("st1", False)]
    assert rs[1]["command"] == "afmctl show port -b 0002:01:00.1 --json"
    assert "placeholder" in rs[2]["refused"]
    ev = ai.Evidence()
    guide.steps_evidence(ev, [
        {"node": "st1", "command": "show interfaces status -n asic1", "rc": 0,
         "output": "Ethernet257          193,194     400G   9100    N/A  Ethernet449/1   trunk    down       up     N/A         N/A\n"},
        {"node": "c2", "command": "x", "rc": "skipped", "output": "(skipped)"},
        {"node": "st6", "command": "show version", "rc": 255, "output": "ssh: connect to host 1.2.3.4 port 22: No route to host"}])
    t = [x["text"] for x in ev.items]
    assert any("st1 Ethernet257: admin up, oper down" in x for x in t)
    assert any(x.startswith("Command S1 run on st1") for x in t) and not any("S2" in x for x in t)
    assert any("Command S3 run on st6" in x and "could not log in" in x for x in t)
