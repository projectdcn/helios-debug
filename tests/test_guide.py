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
    assert "sonic" in [h["source"] for h in idx.search("bcm shell second asic")]   # the guide's Broadcom section may lead
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
    assert "Ethernet170 <-> ct02" in txt and "Live change t1" in txt and "] BCM - BCM shell" in txt
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
    assert "26-35:" in guide.steps_block([{"node": "ct02", "command": "x", "rc": 0, "output": _j.dumps({"device": [{"bdf": "b", "port": ports}]})}])


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
    assert [(r["node"], r["command"], r["allowed"]) for r in rs] == [
        ("st1", "show interfaces status -n asic1 Ethernet257", True), ("st1", "bcm-view -n asic1 Ethernet257", True),
        ("c1", "afmctl show port -b 0002:01:00.1 --json", True), ("c1", "sudo afmctl show port -b <bdf> --json", False),
        ("st1", "config interface shutdown Ethernet257", False)]
    assert "placeholder" in rs[3]["refused"]
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



def test_broadcom_reads_are_allowed_read_only_and_bcm_view_reads_the_asic(monkeypatch):
    """4 Nov: no Broadcom-level debug in the AI / step by step - bcm-view and the guide's bcmcmd reads now run."""
    for ok in ("bcm-view -n asic1 Ethernet257", "bcm-view Ethernet8", "sudo bcmcmd -n 1 'show pmap'",
               "bcmcmd -n 1 'show pmap' | grep 193",
               "sudo bcmcmd -n 1 'bsh -c \"lt PC_PORT_STATUS lookup PORT_ID=220 STATUS=STATUS_ALL\"'",
               "sudo bcmcmd -n 1 'bsh -c \"lt PC_PHY_STATUS_2 lookup PORT_ID=220 LANE_INDEX=1 STATUS=STATUS_2_ALL\"'",
               "sudo bcmcmd -n 0 'bsh -c \"PortStatus 220\"'"):
        guide.check(ok, "switch")
    for bad in ("bcmcmd -n 1 'phy diag cd100 prbs set'", "bcmcmd -n 1 'port cd100 en=0'", "bcmcmd -n 1 'eyescan'",
                "bcmcmd -n 1 'bsh -c \"lt PC_PORT update PORT_ID=220 ENABLE=0\"'", "bcmcmd 'show pmap'; reboot",
                "bcm-view -n asic1 Ethernet257 | sh"):
        with pytest.raises(guide.GuideError):
            guide.check(bad, "switch")
    with pytest.raises(guide.GuideError):
        guide.check("bcm-view Ethernet8", "compute")

    status = ("Ethernet257          193,194     400G   9100    N/A  Ethernet449/1   trunk    down       up     N/A         N/A\n"
              "Ethernet473              1,2     400G   9100    N/A  Ethernet257/1   trunk      up       up     N/A         N/A\n")
    sent = []

    class T:
        def run(self, cmd, timeout=90, sudo=False):
            sent.append(cmd)
            return type("R", (), {"rc": 0, "stdout": status if cmd.startswith("show interfaces") else "", "stderr": ""})()
    from heliosdbg import bcm
    monkeypatch.setattr(bcm, "read_ports", lambda sw, ns, ports, pmap=None: {
        "Ethernet257": {"bcm_port": "cd100", "logical": 220, "lanes_sonic": [193, 194],
                        "port": {"PMD_RX_LOCK": 0, "PMD_LANE_RX_LOCK": 0, "LINK_TRAINING_DONE": 0, "LOCAL_FAULT": 1, "REMOTE_FAULT": 0},
                        "lane": [{"RX_SIGNAL_DETECT": 0, "TX_SQUELCH": 0, "RX_SNR": 99900}] * 2, "fec_bins": [], "fec": {}},
        "Ethernet473": {"error": "x"}})
    r = guide.run(type("H", (), {"name": "st1"})(), T(), "bcm-view -n asic1 Ethernet257", "switch")
    assert sent == ["show interfaces status -n asic1"]
    assert r["rc"] == 0 and "Broadcom view of Ethernet257 (asic1)" in r["output"] and "Verdict (code" in r["output"]
    assert "sudo bcmcmd -n 1 'show pmap'" in r["output"] and "PORT_ID=220" in r["output"]
    sent.clear()
    guide.run(type("H", (), {"name": "st1"})(), T(), "sudo bcmcmd -n 1 'show pmap' | grep 193", "switch")
    assert sent == ["sudo -n bash -c 'timeout 60 bcmcmd -n 1 '\"'\"'show pmap'\"'\"' </dev/null 2>&1' | grep 193"]


def test_placeholders_filled_from_the_evidence_and_commands_without_a_node():
    """mr2 4 Nov: '<bdf>' with E3 naming 0002:01:00.1, and a Broadcom list with '<logical>' / '-n N' after S1 read 216."""
    roles = {"st1": "switch", "c1": "compute", "c2": "compute"}
    ctx = ("st1 asic1 Ethernet257 <-> pod-1-0-ComputeTray (c1) GPU2 (0002:01:00.1) port 13 down\n"
           "Broadcom cd96 (logical 216): PMD_RX_LOCK 0")
    ans = ("1. on pod-1-0-ComputeTray: `sudo afmctl show port -b <bdf> --json`\n"
           "2. `sudo bcmcmd -n N 'show pmap'`\n"
           "3. `sudo bcmcmd -n N 'bsh -c \"lt PC_PORT_STATUS lookup PORT_ID=<logical> STATUS=STATUS_ALL\"'`\n"
           "4. `bcm-view -n asicN EthernetX` - the chip's view\n5. never `prbs`")
    rs = guide.runnable(ans, roles, {"pod-1-0-ComputeTray": "c1"}, ctx)
    got = [(r["node"], r["command"], r["allowed"]) for r in rs]
    assert got == [("c1", "afmctl show port -b 0002:01:00.1 --json", True),
                   ("st1", "bcmcmd -n 1 'show pmap'", True),
                   ("st1", "bcmcmd -n 1 'bsh -c \"lt PC_PORT_STATUS lookup PORT_ID=216 STATUS=STATUS_ALL\"'", True),
                   ("st1", "bcm-view -n asic1 Ethernet257", True)]
    assert "bdf 0002:01:00.1" in rs[0]["why"]
    two = ctx + "\nst1 asic0 Ethernet8 <-> (c2) GPU0 (0001:01:00.1) port 1 down"
    assert all(not r["allowed"] for r in guide.runnable("on c1: `sudo afmctl show port -b <bdf> --json`", roles, None, two))
    assert ai.generic_howto("list the broadcom commands to troubleshooting link issues")



def test_unit_placeholder_forms():
    v = guide.context_values("st1 asic1 Ethernet257 <-> (c1) GPU2 (0002:01:00.1) port 13\nBroadcom cd96 (logical 216)")
    for raw in ("sudo bcmcmd -n <N> 'show pmap'", "sudo bcmcmd -n N 'show pmap'", "sudo bcmcmd -n <unit> 'show pmap'"):
        assert guide._fill(raw, v)[0] == "sudo bcmcmd -n 1 'show pmap'", raw
    assert guide._fill("bcmcmd -n <N> 'bsh -c \"lt PC_PHY_STATUS lookup PORT_ID=<logical> LANE_INDEX=<n>\"'", v)[0] == \
        "bcmcmd -n 1 'bsh -c \"lt PC_PHY_STATUS lookup PORT_ID=216 LANE_INDEX=0\"'"


def test_the_model_gets_the_odd_ports_first_and_the_code_facts():
    """mr2 4 Nov: the model read port 13 NO_PHY_LINK among 35 LINK_UP lines as 'the GPU port is up'; Ask cut it off."""
    gpu = "GPU 0002:01:00.1:\n" + "".join(f" port {i}: LINK_UP, admin enabled, IFCP ll_up yes peer_enabled yes peer 1/2{i:02d}\n" for i in range(13)) \
        + " port 13: NO_PHY_LINK, PCS_NO_BLOCK_LOCK, admin enabled, IFCP ll_up no peer_enabled None peer None/None\n" \
        + "".join(f" port {i}: LINK_UP, admin enabled, IFCP ll_up no peer_enabled None peer None/None\n" for i in range(14, 36))
    m = guide.for_model(gpu)
    assert m.splitlines()[1] == " port 13: NO_PHY_LINK, PCS_NO_BLOCK_LOCK, admin enabled, IFCP ll_up no peer_enabled None"
    assert " ports 0-12: LINK_UP, admin enabled, IFCP ll_up yes peer_enabled yes" in m and " ports 14-35:" in m
    bv = ("Broadcom view of Ethernet257 (asic1): SONiC lanes 193,194, oper down, admin up\n"
          "Verdict (code, heliosdbg/bcm.py): the switch receives no signal on any of its 2 lanes (RX_SIGNAL_DETECT 0) while its own transmitter is on\n")
    steps = [{"node": "c1", "command": "afmctl show port -b 0002:01:00.1 --json", "rc": 0, "output": gpu},
             {"node": "st1", "command": "bcm-view -n asic1 Ethernet257", "rc": 0, "output": bv}]
    f = guide.step_facts(steps)
    assert any("Broadcom (switch ASIC): the switch receives no signal" in x for x in f)
    assert f[-1].startswith("Together: the GPU port has no link (NO_PHY_LINK) and the switch receives no signal")

    class AI:
        def build_messages(self, ev, subject):
            return [{"role": "system", "content": ""}, {"role": "user", "content": "x\n\nQuestion: q"}]
    q = guide.messages(AI(), None, "s", steps, {"c1": "compute", "st1": "switch"})[-1]["content"]
    assert "What code read in these outputs" in q and "neither end sees the other" in q
    ev = ai.Evidence()
    guide.steps_evidence(ev, steps)
    assert any("Command S1" in x["text"] and "port 13: NO_PHY_LINK" in x["text"] for x in ev.items)


def test_new_broadcom_reads_allowed_and_both_ends_facts():
    for c in ['bcmcmd -n 1 \'bsh -c "lt LM_LINK_STATE traverse"\'', 'bcmcmd -n 1 \'bsh -c "lt PC_PORT lookup PORT_ID=216"\'',
              'bcmcmd -n 1 \'bsh -c "lt PC_FDR_STATS lookup PORT_ID=216"\'', 'bcmcmd -n 1 \'bsh -c "lt CTR_MAC_ERR lookup PORT_ID=216"\'']:
        assert guide.check(c, "switch")[0]
    with pytest.raises(ValueError):
        guide.check('bcmcmd -n 1 \'bsh -c "lt PC_PORT update PORT_ID=216 ENABLE=0"\'', "switch")
    gpu = "GPU 0002:01:00.1:\n port 12: LINK_UP, admin enabled\n port 13: NO_PHY_LINK, PCS_NO_BLOCK_LOCK, admin enabled\n"
    remote = ("Broadcom view of Ethernet257 (asic1): SONiC lanes 193,194, oper down, admin up\nVerdict (code, heliosdbg/bcm.py): "
              "remote fault: the switch receives the GPU and locks\n")
    f = guide.step_facts([{"node": "c1", "output": gpu}, {"node": "st1", "output": remote}])
    assert any("only the switch-to-GPU direction" in x for x in f)


def test_afm_agent_logs_readable_on_switch_only_as_tails():
    for cmd in ("tail -n 100 /opt/amd/afm/agent/logs/ifcp-err.log", "ls -lt /opt/amd/afm/agent/logs/"):
        guide.check(cmd, "switch")
    for cmd in ("tail -f /opt/amd/afm/agent/logs/ifcp.log", "tail -n 100 /etc/shadow",
                "tail -n 100 /opt/amd/afm/agent/logs/../../../../etc/shadow", "sudo systemctl restart afm-agent"):
        with pytest.raises(Exception):
            guide.check(cmd, "switch")


def _scan_two_problems():
    """st4: no IFCP on any link (switch-wide); st5: a tray AFM did not program; ct06 unreadable; a GPU in PROVIDER."""
    links = [{"switch": "st4", "asic": "asic1", "sw_port": f"Ethernet{i}", "tray": f"ct0{1 + i % 4}", "state": "degraded",
              "kind": "ifcp", "ifcp": {"ll": "no"}} for i in range(12)]
    links += [{"switch": "st5", "asic": "asic0", "sw_port": f"Ethernet{100 + i}", "tray": "ct03", "state": "degraded",
               "kind": "tray_not_programmed"} for i in range(4)]
    return {"rack": "g02-g17", "time_utc": "20261104-225936", "links": links,
            "root_causes": [{"kind": "switch_ifcp", "title": "switch_ifcp", "switch": "st4", "owner": "operator",
                             "cause": "st4: no IFCP session on any of its problem links", "links": [f"st4 Ethernet{i}" for i in range(12)]},
                            {"kind": "tray_not_programmed", "title": "tray_not_programmed", "owner": "operator",
                             "cause": "no forwarding entry matches the tray", "links": [f"st5 Ethernet{100 + i}" for i in range(4)]}],
            "not_checked": [{"node": "ct06", "error": "rc=112: afmctl show port"}],
            "gpus": [{"tray": "ct01", "bdf": "0001:01:00.1", "state": "degraded", "kind": "gpu_not_active", "cause": "PROVIDER"}]}


def test_a_question_about_one_problem_gets_only_its_evidence():
    scan = _scan_two_problems()
    ev, _s = ai.chat_context(scan, "why IFCP session is down ?", live=[
        {"t": "x", "link": "st6 Ethernet302", "what": "state", "from": "degraded", "to": "ok", "source": "re-read"},
        {"t": "y", "link": "st4 Ethernet3", "what": "ll_up", "from": "no", "to": "yes", "source": "re-read"}])
    text = "\n".join(x["text"] for x in ev.items)
    assert "switch_ifcp" in text and "ip -n asicN -s -o link show" in text
    assert "st5" not in text and "PROVIDER" not in text and "ct06" not in text and "st6 Ethernet302" not in text
    assert "st4 Ethernet3" in text and "left out" in text and ev.focus == ["st4"]
    ev, _s = ai.chat_context(scan, "what is wrong with ct06?")              # a node named: that node's problems
    assert ev.focus == ["ct06"] and "rc=112" in "\n".join(x["text"] for x in ev.items)
    ev, _s = ai.chat_context(scan, "What is wrong with this rack?")         # the whole rack: everything, as before
    text = "\n".join(x["text"] for x in ev.items)
    assert "st5" in text and "ct06" in text and not getattr(ev, "focus", None)


def test_a_reading_the_evidence_does_not_show_is_flagged():
    ev = ai.Evidence()
    ev.add("[Problem 1: switch_ifcp] st4: no IFCP session on any of its 384 links (ll_up no)")
    r = ai.review("The session is down because status.ifcp.peer_enabled = no [E1]; ll_up is no.", ev)
    assert r["not_in_evidence"] == ["status.ifcp.peer_enabled no"]
    assert ai.review("ll_up is no on every link [E1]", ev)["not_in_evidence"] == []


def test_step_by_step_stays_on_the_problem_and_asks_again_for_json(monkeypatch):
    ev = ai.Evidence()
    ev.add("[Problem 1: switch_ifcp] st4: no IFCP session")
    replies = ['{"done": false, "node": "ct03", "command": "sudo afmctl show device --json", "why": "another tray"}',
               '{"done": false, "node": "st4", "command": "sudo ip -n asic1 -s -o link show", "why": "CPU"}',
               "The CPU receives nothing, so ...",
               '{"done": true, "conclusion": "st4 receives nothing on the CPU [S1]; peer_enabled is no", "next": "switch owner"}']
    seen = []
    monkeypatch.setattr(ai, "chat", lambda msgs, env=None, max_tokens=900: (seen.append(msgs) or replies.pop(0), "m"))
    nodes = {"st4": "switch", "ct03": "compute"}
    p = guide.propose(ai, ev, "this check of the rack", [], nodes, stay={"st4"})
    assert p["allowed"] and p["node"] == "st4" and p["retried"] and "stay on st4" in seen[-1][-1]["content"]
    p = guide.propose(ai, ev, "this check of the rack", [{"node": "st4", "command": p["command"], "rc": 0,
                                                          "output": "CPU receive asic1: 257 Ethernet ports, 216 with link; 0 of those have received packets on the CPU, 216 none; 216 have sent"}],
                      nodes, stay={"st4"})
    assert p["done"] and p["retried"] and "JSON object" in seen[-1][-1]["content"]
    assert p["not_in_evidence"] == ["peer_enabled no"]
    assert any("none of its 216 ports" in f for f in p["facts"])


def test_cpu_receive_listing_is_read_and_judged():
    from heliosdbg.platforms import sonic
    row = ("{n}: Ethernet{n}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9100 qdisc mq state UP\\    link/ether 12:34\\    "
           "RX:  bytes packets errors dropped  missed   mcast           \\    {b} {p} 0 0 0 0 \\    "
           "TX:  bytes packets errors dropped carrier collsns           \\    900 9 0 0 0 0 ")
    dead = "\n".join(row.format(n=i, b=0, p=0) for i in range(1, 11))
    alive = "\n".join(row.format(n=i, b=440, p=9) for i in range(1, 11))
    assert sonic.cpu_rx(dead) == {"ports": 10, "up": 10, "rx": 0, "tx": 10, "quiet": [f"Ethernet{i}" for i in range(1, 7)]}
    F = sonic.judge("st4", {"cpu_rx:asic1": {"cmd": "ip -n asic1 -s -o link show", "rc": 0, "out": dead, "err": ""}})
    assert [f["check"] for f in F] == ["cpu_rx"] and "none of the 10 ports" in F[0]["what"]
    assert not sonic.judge("st6", {"cpu_rx:asic1": {"cmd": "x", "rc": 0, "out": alive, "err": ""}})
    assert guide.compact(dead).startswith("CPU receive: 10 Ethernet ports, 10 with link; 0 of those")
    assert guide.check("sudo ip -n asic0 -s -o link show", "switch") == ("ip -n asic0 -s -o link show", True)
    with pytest.raises(guide.GuideError):
        guide.check("ip -n asic0 link set Ethernet1 down", "switch")


def test_ifcp_error_log_age_is_read_by_code():
    import datetime as dt
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%S.123Z")
    line = '{"level":"error","ts":"%s","caller":"ll.go:635","pid":"1","msg":"Ethernet%d: Error sending discover message: x"}'
    out = "\n".join(line % (old, n) for n in (475, 476))
    f = guide.step_facts([{"node": "st4", "command": "tail -n 100 /opt/amd/afm/agent/logs/ifcp-err.log", "rc": 0, "output": out}])
    assert "40 min before" in f[0] and "2 port(s)" in f[0] and "cleared" in f[0]


def test_an_mtu_called_low_that_is_not_is_caught_and_asked_again():
    """helios-slm v28-v33: stuck IFCP links concluded as 'reads MTU 9100 [S1], below the fabric's 9100'."""
    bad = "st2 Ethernet465 reads MTU 9100 [S1], below the fabric's 9100, so it is a switch port setting, not the cable."
    assert ai.mtu_contradiction(bad).startswith("MTU 9100")
    assert ai.mtu_contradiction("st6 Ethernet29 has an MTU of 9100, below the fabric's MTU, so IFCP cannot come up")
    for ok in ("st2 Ethernet465 reads MTU 1500 [S1], below the fabric's 9100: a port setting.",
               "st4 Ethernet153 reads MTU 9100 [S2], the normal value, so it is not a port setting.",
               "MTU 9100 is below nothing; the link counters below show errors.",
               "no IFCP session (ll_up no) while the MTU is 9100"):
        assert ai.mtu_contradiction(ok) is None, ok
    assert ai.review(bad, ai.Evidence())["contradiction"]

    class AI:
        def __init__(self, texts):
            self.texts, self.seen = list(texts), []

        def build_messages(self, ev, subject):
            return [{"role": "system", "content": ""}, {"role": "user", "content": "x\n\nQuestion: q"}]

        def chat(self, msgs, env=None, max_tokens=500):
            self.seen.append(msgs)
            return self.texts.pop(0), "stand-in"

        def remember(self, msgs, text, model, subject):
            return "id"
    good = "st2 Ethernet465: physical link up, no IFCP session (ll_up no) [S1], MTU 9100 normal - the GPU port's IFCP."
    ai_ = AI(['{"done": true, "conclusion": "%s", "next": "n"}' % bad, '{"done": true, "conclusion": "%s", "next": "n"}' % good])
    s1 = {"node": "st2", "command": "show interfaces status -n asic1", "rc": 0, "output": "Ethernet465 ... 9100 ... up up"}
    out = guide.propose(ai_, None, "s", [s1], {"st2": "switch"})
    assert out["done"] and out["conclusion"] == good and out["contradiction"] is None
    assert out["retried"] and out["contradiction_before"].startswith("MTU 9100") and "_text" not in out
    assert "not below the fabric's 9100" in ai_.seen[1][-1]["content"]
