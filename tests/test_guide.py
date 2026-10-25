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
               'Here: {"done": true, "conclusion": "st6 asic0 has no IFCP [S1]", "next": "AMD"}']
    monkeypatch.setattr(ai, "chat", lambda msgs, env=None, max_tokens=900: (replies.pop(0), "m"))
    nodes = {"st6": "switch", "ct02": "compute"}
    p = guide.propose(ai, ev, "link st6 Ethernet170", [], nodes)
    assert p["allowed"] and p["command"] == "afmctl show port -b 0004:01:00.1 --json"
    p = guide.propose(ai, ev, "link st6 Ethernet170", [{"node": "ct02", "command": p["command"], "rc": 0, "output": "x"}], nodes)
    assert not p["allowed"] and "read-only" in p["refused"]
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
    scan = {"rack": "r", "time_utc": "t", "afm_names": {"st6": "pod-1-5-SwitchTray"},
            "links": [{"switch": "st6", "asic": "asic0", "sw_port": "Ethernet170", "tray": "ct02", "bdf": "b", "gpu_port": 20,
                       "state": "degraded", "kind": "ifcp", "cause": "no IFCP session", "ifcp": {"ll": "no"}, "vlans": [["Vlan200", "pt"]]},
                      {"switch": "st1", "asic": "asic0", "sw_port": "Ethernet8", "tray": "ct01", "state": "ok"}]}
    ev, subject = ai.chat_context(scan, "why has pod-1-5-SwitchTray Ethernet170 no IFCP? and the bcm shell?",
                                  live=[{"t": "t1", "link": "st6 Ethernet170", "what": "state", "from": "ok", "to": "degraded", "source": "log"}],
                                  docs=idx)
    txt = ev.block()
    assert subject == "the rack (chat)" and "pod-1-5-SwitchTray (st6): 1 links" in txt and "up without an IFCP session" in txt
    assert "Ethernet170 <-> ct02" in txt and "Live change t1" in txt and "[D1] sonic: BCM shell" in txt
    msgs = ai.build_messages(ev, subject, "q")
    assert "open chat" in msgs[0]["content"] and "### Problem" not in msgs[0]["content"].split("open chat")[1][:50]
    r = ai.review("See [E1] and [D1], not [D7].", ev)
    assert "D1" in r["cited"] and r["unknown_citations"] == ["D7"]
