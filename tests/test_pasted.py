"""Pasted outputs (Any problem): the node health rules judge commands typed the way people type them; test results in
any format become their failed cases; commands no rule reads are said, not judged."""
from __future__ import annotations

from pathlib import Path

from heliosdbg import cases, pasted
from tests.test_qfx_tray import LEAK_OK, NTP

FX = Path(__file__).parent / "fixtures" / "health"


def test_typed_commands_find_their_checks():
    assert pasted.checks_of("sudo show platform psustatus") == [("sonic", "psu")]
    assert pasted.checks_of("show ntp | grep -i leap") == [("sonic", "ntp")]
    assert pasted.checks_of("sudo amd-smi metric --ecc --json") == [("amd-gpu", "ecc"), ("amd-gpu", "pcie")]
    assert ("amd-gpu", "metric") in pasted.checks_of("sudo amd-smi metric --json")
    assert pasted.checks_of("amd-smi metric") == []                   # no --json: the rule cannot read it
    assert pasted.checks_of("dmesg -T 2>/dev/null | tail -200") == [("linux", "kernel")]
    assert pasted.checks_of("sudo nicctl show port -j") == [("rdma", "nic_ports")]
    assert pasted.checks_of("show interfaces status") == []


def test_pasted_outputs_get_the_health_rules_findings():
    fan_bad = (FX / "platform_fan.txt").read_text()
    blocks = [{"node": "st5", "command": "show ntp", "output": NTP},
              {"node": "st5", "command": "show platform leak status", "output": LEAK_OK},
              {"node": "st5", "command": "show platform psustatus",
               "output": (FX / "psustatus.txt").read_text().replace("OK      green", "N/A     off", 1)},
              {"node": "st5", "command": "show platform fan", "output": fan_bad},
              {"node": "ct07", "command": "show interfaces status", "output": "Ethernet0 up"}]
    F, seen = pasted.judge_blocks(blocks)
    whats = " | ".join(f["what"] for f in F)
    assert "NTP" in whats or "clock" in whats.lower()
    assert any(f["check"] == "psu" for f in F) and all(f["node"] == "st5" for f in F)
    assert seen[-1]["checks"] == []                                   # not a health-check command: said, not judged
    ev, _subj, _rack = cases.blocks_context(blocks, "st5 alarms")
    assert any(x["source"] == "rules" and x["text"].startswith("Health rule on st5") for x in ev.items)


def test_healthy_outputs_give_no_finding():
    F, seen = pasted.judge_blocks([{"node": "st5", "command": "show platform leak status", "output": LEAK_OK},
                                   {"node": "ct01", "command": "sudo amd-smi list --json",
                                    "output": (FX / "amd_smi_list.json").read_text()}])
    assert F == [] and all(s["checks"] for s in seen)


def test_test_results_in_junit_or_csv():
    junit = """<testsuite name="rccl" tests="3"><testcase classname="rccl" name="allreduce_8gpu"><failure message="bus bw 12 GB/s below 300"/></testcase>
<testcase classname="rccl" name="allgather"/><testcase classname="rccl" name="alltoall"><error message="timeout after 600 s"/></testcase></testsuite>"""
    F, seen = pasted.judge_blocks([{"node": "ct07", "command": "rccl.xml", "output": junit}])
    assert len(F) == 1 and F[0]["what"].startswith("2 of 3 test case(s) failed") and seen[0]["checks"] == ["test result"]
    csvt = "case,status,reason\nTC-1,PASS,\nTC-2,FAIL,link down\nTC-3,passed,\n"
    F, _ = pasted.judge_blocks([{"node": "", "command": "", "output": csvt}])
    assert F[0]["what"] == "1 of 3 test case(s) failed: TC-2" and "TC-2: FAIL - link down" in F[0]["evidence"]
    assert pasted.test_failures('<!DOCTYPE x [<!ENTITY a "b">]><testsuite><testcase name="a"/></testsuite>') is None
    assert pasted.test_failures("just a log line\nanother") is None
