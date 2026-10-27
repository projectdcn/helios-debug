"""heliosdbg.cases: evidence for any problem (tool reports, helios-tests results, outputs collected by hand), the
any-problem prompt, the wider read-only allow-list, and a step-by-step conclusion rated 👎 with a correction."""
from __future__ import annotations

import json

import pytest

from heliosdbg import ai, cases, feedback, guide


def test_blocks_keep_what_matters_of_a_long_output():
    pad = " normal reading, nothing to see here" * 2
    out = "\n".join([f"line {i} fine{pad}" for i in range(400)] + ["GPU 2: ECC error count 17 - FAILED"] + [f"tail {i}{pad}" for i in range(400)])
    ev, subject, rack = cases.blocks_context([{"node": "ct07", "command": "sudo amd-smi metric", "output": out},
                                              {"node": "", "command": "", "output": "  "}], "ct07 GPU2", "g02-g17")
    text = ev.block()
    assert subject == "ct07 GPU2" and rack == "g02-g17" and ev.mode == "general"
    assert "On ct07: `sudo amd-smi metric`: 801 lines" in text and "ECC error count 17 - FAILED" in text
    assert "line 0 fine" in text and "tail 399" in text and "line 200 fine" not in text and "..." in text
    with pytest.raises(ai.AIError):
        cases.blocks_context([{"output": " "}])


def test_any_problem_prompt_and_spec():
    ev, subject, _r = cases.blocks_context([{"node": "ct07-bmc", "command": "ipmitool sel list", "output": "PSU2 Failure detected"}])
    m = ai.build_messages(ev, subject)
    assert "not only about links" in m[0]["content"] and "PSU2 Failure detected" in m[1]["content"]
    assert cases.spec_of({"path": "link-check/mr2/scan-20261019-054931"}) is None              # the link builders
    assert cases.spec_of({"path": "link-check/mr2/bcm-20261019-000056"}) == {"path": "link-check/mr2/bcm-20261019-000056"}
    assert cases.spec_of({"blocks": [], "rack": "mr2", "link": "x"}) == {"blocks": [], "rack": "mr2"}


def test_report_and_test_results(tmp_path, monkeypatch):
    d = tmp_path / "link-check" / "mr2" / "bcm-20261019-000056"
    d.mkdir(parents=True)
    (d / "bcm.txt").write_text("Broadcom view st1\nEthernet8: link down, signal lost\n")
    assert cases.reports(tmp_path)[0]["tool"] == "bcm"
    ev, subject, rack = cases.report_context(tmp_path, "link-check/mr2/bcm-20261019-000056")
    assert rack == "mr2" and "signal lost" in ev.block() and "bcm" in subject
    with pytest.raises(ai.AIError):
        cases.report_context(tmp_path, "../../etc")
    r = tmp_path / "tests"
    (r / "runs" / "g" / "run1" / "logs").mkdir(parents=True)
    (r / "runs" / "g" / "run1" / "logs" / "001.log").write_text("connect ct07\nrccl: timeout after 300 s\n")
    (r / "index.csv").write_text("rack,run,started,tc_id,test,outcome,duration_s,message,log\n"
                                 "g02-g17,run1,2026-10-22 05:29:01 UTC,TC-RCCL-003,test_allreduce,failed,301,hang,runs/g/run1/logs/001.log\n"
                                 "g02-g17,run1,2026-10-22 05:20:01 UTC,TC-GPU-001,test_count,passed,1,,\n")
    monkeypatch.setenv("HELIOS_TESTS_RESULTS", str(r))
    assert [t["tc_id"] for t in cases.tests(outcome="failed")] == ["TC-RCCL-003"]
    ev, subject, rack = cases.context({"test": {"run": "run1", "tc_id": "TC-RCCL-003"}}, tmp_path)
    assert "outcome FAILED" in ev.block() and "rccl: timeout after 300 s" in ev.block() and rack == "g02-g17"
    ev, _s, _r = cases.context({"test": {"run": "run1", "tc_id": "TC-GPU-001"}}, tmp_path)
    assert ev.verdict == "ok"


@pytest.mark.parametrize("cmd,role,ok", [
    ("sudo amd-smi metric -g 2", "compute", True), ("rocm-smi --showtemp --json", "compute", True),
    ("rocm-smi -r", "compute", False), ("sudo ipmitool sel elist", "compute", True),
    ("ipmitool chassis power cycle", "compute", False), ("ethtool -S eth0", "compute", True),
    ("ethtool -s eth0 speed 100", "compute", False), ("systemctl status afm-agent", "compute", True),
    ("systemctl restart afm-agent", "compute", False), ("show platform psustatus", "switch", True),
    ("show pfc counters -n asic0", "switch", True), ("config pfcwd stop", "switch", False)])
def test_wider_read_only_list(cmd, role, ok):
    if ok:
        guide.check(cmd, role)
    else:
        with pytest.raises(guide.GuideError):
            guide.check(cmd, role)


def test_step_by_step_correction_is_saved_as_a_conclusion(tmp_path):
    msgs = [{"role": "system", "content": "x\nYou are now guiding an investigation step by step. Answer ONLY ..."},
            {"role": "user", "content": "Evidence"}]
    r = feedback.record(tmp_path, {"answer_id": "a1", "rating": "down",
                                   "correction": "PSU2 of ct07 failed [S1].\nNext: site replaces PSU2"},
                        {"a1": {"messages": msgs, "answer": '{"done": true}', "model": "m", "subject": "s"}})
    assert json.loads(r["correction"]) == {"done": True, "conclusion": "PSU2 of ct07 failed [S1].", "next": "site replaces PSU2"}
