"""The chat's counting questions: exact lines from the newest link and health checks, the model only explains them
(rackfacts.py) - and every question is logged (results/ai/chat.jsonl) with the facts it was answered from."""
import json
import time

import pytest

from heliosdbg import ai, rackfacts
from ui import server

INV = """rack: lab
switches:
  - {name: st1, host: a}
  - {name: st2, host: b}
computes:
  - {name: ct01, host: c}
  - {name: ct02, host: d}
  - {name: ct03, host: e, quarantine: PSU out}
"""
SCAN = "link-check/lab/scan-20261104-225936"


def _link(sw, port, tray, bdf, state, kind="", cause="", ifcp=None):
    return {"switch": sw, "asic": "asic0", "sw_port": port, "tray": tray, "bdf": bdf, "gpu_port": 1, "state": state,
            "kind": kind, "cause": cause, "ifcp": ifcp}


@pytest.fixture
def rack(tmp_path, monkeypatch):
    (tmp_path / "inv").mkdir()
    (tmp_path / "inv" / "lab.local.yaml").write_text(INV)
    d = tmp_path / "results" / SCAN
    d.mkdir(parents=True)
    (d / "link_check.json").write_text(json.dumps({
        "time_utc": "20261104-225936", "rack": "lab", "learned": {"slots": {"ct01": 0, "ct02": 1}},
        "links": [_link("st1", "Ethernet1", "ct01", "0001:01:00.1", "ok"),
                  _link("st1", "Ethernet2", "ct01", "0002:01:00.1", "down", "phys_down", "no light on the optic"),
                  _link("st2", "Ethernet3", "ct02", "0001:01:00.1", "degraded", "ifcp", "no IFCP session", {"ll": "no"}),
                  _link("st2", "Ethernet4", None, None, "unknown", "tray_quarantined", "compute tray ct03 is quarantined")],
        "gpus": [{"tray": "ct02", "bdf": "0001:01:00.1", "state": "degraded", "kind": "gpu_not_active", "phase": "PROVIDER"}],
        "not_checked": [{"node": "ct02", "error": "CommandError: [ct02] rc=112: afmctl show port"}]}))
    h = tmp_path / "results" / "link-check" / "lab" / "health-20261105-043843"
    h.mkdir(parents=True)
    (h / "health.json").write_text(json.dumps({
        "rack": "lab", "time": "2026-11-05 04:42", "unreachable": ["st2"], "quarantined": ["ct03"],
        "nodes": {"st1": {"role": "switch", "not_run": []}, "st2": {"role": "switch", "not_run": []},
                  "ct01": {"role": "compute", "not_run": []}, "ct02": {"role": "compute", "not_run": ["afmctl"]}},
        "findings": [{"node": "ct02", "severity": "critical", "what": "0 of 4 GPUs visible to amd-smi"},
                     {"node": "2 trays", "severity": "warning", "what": "vulcano NIC firmware differs between trays"},
                     {"node": "st1", "severity": "warning", "what": "clock not synchronised to NTP"}]}))
    sent = []

    def chat(msgs, env=None, **kw):
        sent.append(msgs)
        return replies.pop(0) if replies else "Fine.", "stand-in"
    replies: list[str] = []
    monkeypatch.setattr(ai, "chat", chat)
    st = server.State(tmp_path / "inv", tmp_path / "results")
    return st, replies, sent


def ask(st, q, **kw):
    return server.ai_chat(st, {"inventory": "lab.local.yaml", "path": SCAN, "question": q} | kw)


@pytest.mark.parametrize("q,kinds,want", [
    ("how many switches are reachable", ["reach"], "1 of 2 switches reachable (NOT reached: st2)"),
    ("which compute tray is not reachable", ["reach"], "ct02 (afmctl did not run)"),
    ("how many links are down", ["links"], "4 GPU links - 1 ok, 1 degraded, 1 down, 1 unknown"),
    ("how many links are down", ["links"], "down: st1 asic0 Ethernet2 <-> ct01"),
    ("which links on st2 have no IFCP session?", ["links"], "no IFCP session: st2 asic0 Ethernet3"),
    ("which GPUs are not active", ["gpus"], "1 degraded (gpu_not_active, config_phase PROVIDER)"),
    ("which trays are quarantined", ["quarantine"], "ct03 (PSU out)"),
    ("which trays are quarantined", ["quarantine"], "1 links of quarantined trays (ct03)"),
    ("any critical findings?", ["health"], "3 findings - 1 critical, 2 warning"),
    ("what firmware differs between trays", ["health"], "1 findings about firmware - 1 warning"),
    ("what did the health check find", ["health"], "critical: ct02: 0 of 4 GPUs visible"),
    ("when was the last check", ["when"], "Newest health check: 2026-11-05 04:42 UTC"),
])
def test_counting_questions_get_exact_lines(rack, q, kinds, want):
    st, replies, sent = rack
    a = ask(st, q)
    assert a["context"]["kinds"] == kinds
    assert any(want in t for t in a["check_facts"]), a["check_facts"]
    assert a["check_facts"][-1].startswith("These are the newest checks")
    assert "From the newest checks, exactly:" in sent[-1][-1]["content"]
    assert a["docs"] == [] and a["map_facts"] == []             # not the guide's older known-issue table


@pytest.mark.parametrize("q", ["why is st1 degraded?", "how do I read the IFCP state of a GPU port?",
                               "what is wrong with this rack, and in what order should it be fixed?"])
def test_why_and_how_questions_are_left_to_the_model(rack, q):
    st, _, sent = rack
    a = ask(st, q)
    assert a["check_facts"] == [] and a["context"]["kinds"] == []
    assert "From the newest checks" not in sent[-1][-1]["content"]


def test_a_number_the_lines_do_not_have_is_flagged(rack):
    st, replies, _ = rack
    replies.append("16 switches are reachable [E2].")
    a = ask(st, "how many switches are reachable")
    assert a["off_facts"] == ["16 is not in the exact lines"]
    replies.append("1 of 2 switches is reachable; st2 did not answer at 04:42 UTC.")
    assert ask(st, "how many switches are reachable")["off_facts"] == []


def test_every_question_is_logged(rack):
    st, replies, _ = rack
    replies.append("1 link is down: st1 Ethernet2 [E3].")
    ask(st, "how many links are down")
    ask(st, "why is st1 degraded?")
    rows = [json.loads(x) for x in (st.results_dir / "ai" / "chat.jsonl").read_text().splitlines()]
    assert [r["question"] for r in rows] == ["how many links are down", "why is st1 degraded?"]
    assert rows[0]["path"] == SCAN and rows[0]["health"] == "health-20261105-043843" and rows[0]["kinds"] == ["links"]
    assert rows[0]["answer"].startswith("1 link is down") and rows[0]["model"] == "stand-in" and rows[0]["check_facts"]
    assert rows[1]["check_facts"] == []


def test_without_a_model_the_exact_lines_still_answer(rack, monkeypatch):
    st, _, _ = rack

    def off(*a, **kw):
        raise ai.AIError("the AI is turned off")
    monkeypatch.setattr(ai, "chat", off)
    a = ask(st, "how many links are down")
    assert a["model"] == "none" and "turned off" in a["answer"] and a["check_facts"]


def test_answers_say_how_old_the_checks_are(rack):
    st, _, _ = rack
    g = ask(st, "why is st1 degraded?")["context"]["ages"]
    assert g["link_check_utc"] == "20261104-225936" and g["health_utc"] == "2026-11-05 04:42"
    assert g["link_check_h"] > 24 and g["stale"]                    # these fixtures are days old
    now = rackfacts.parse_time("2026-11-05 05:42")
    fresh = rackfacts.ages({"time_utc": "20261105-044000"}, {"time": "2026-11-05 04:42"}, now)
    assert fresh["health_h"] == 1.0 and not fresh["stale"]


def test_parse_time_is_utc():
    assert rackfacts.parse_time("20261105-000000") == rackfacts.parse_time("2026-11-05 00:00")
    assert time.gmtime(rackfacts.parse_time("2026-11-05 04:42"))[3:5] == (4, 42)


def test_a_rack_map_lookup_keeps_its_own_exact_lines(rack):
    st, _, _ = rack
    a = ask(st, "which switch port is ct01 0002:01:00.1 connected to?")
    assert a["map_facts"] and not a["check_facts"]


@pytest.mark.parametrize("answer,want", [
    ("ct02 is not reachable (its reads failed) - checked 04:42 UTC.", "calls ct02 unreachable - the exact lines say it answered"),
    ("st2 is not reachable at 04:42 UTC.", None),                                   # st2 really was not reached
    ("ct03: the count or names the question asks for, and the time.", "copies the instructions instead of answering"),
])
def test_review_catches_a_contradiction(rack, answer, want):
    st, replies, _ = rack
    replies.append(answer)
    got = ask(st, "which compute tray is not reachable")["off_facts"]
    assert (want in got) if want else got == []


def test_a_failed_command_is_not_called_unreachable_in_the_evidence(rack):
    st, _, sent = rack
    ask(st, "what should I check first on ct02")
    user = sent[-1][-1]["content"]
    assert "ct02 answered over SSH, but a command failed on it (not a reachability problem)" in user


@pytest.mark.parametrize("q", ["which switches are not synchronised to NTP", "any container restarts on st2"])
def test_health_topics_route_to_the_health_lines(rack, q):
    st, _, _ = rack
    assert "health" in ask(st, q)["context"]["kinds"]


def test_a_named_node_says_whether_it_answered(rack):
    st, _, sent = rack
    ask(st, "what should I check first on ct02")
    assert "ct02 answered over SSH at the health check of 2026-11-05 04:42 UTC (reachable); on it afmctl did not run" in sent[-1][-1]["content"]
    ask(st, "what should I check first on st2")
    assert "st2 did NOT answer over SSH" in sent[-1][-1]["content"]
    ask(st, "what should I check first on ct02")
    assert "Health finding on ct02 (critical): 0 of 4 GPUs visible to amd-smi" in sent[-1][-1]["content"]


def test_version_says_whether_the_ui_is_busy(tmp_path):
    st = server.State(tmp_path, tmp_path)
    v = server.version_info(st)
    assert v["version"] and v["idle"] and v["busy"] == {"jobs": 0, "live": False, "terminals": 0}
    st.jobs["x"] = {"status": "running"}
    assert not server.version_info(st)["idle"]
