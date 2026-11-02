"""A node health finding as a ticket for its owner and as an evidence zip with only its node's outputs."""
import gzip
import io
import json
import zipfile

import pytest

from heliosdbg import bundle, ticket

F = {"node": "ct12", "role": "compute", "check": "failed", "area": "os", "severity": "warning",
     "what": "2 failed systemd unit(s): a.service, b.service", "cause": "services failed", "owner": "compute",
     "next": "read 'systemctl status <unit>'", "evidence": ["a.service loaded failed failed A"], "command": "systemctl --failed"}
RES = {"rack": "lab", "time": "2026-11-02 18:37", "findings": [F],
       "nodes": {"ct12": {"role": "compute", "not_run": ["rdma"]}, "ct11": {"role": "compute", "not_run": []}},
       "changes": {"since": "2026-11-02 18:35", "new": [F], "gone": [], "grew": []}}


def test_ticket_has_the_facts_and_no_other_node():
    md = ticket.health_finding(RES, 0, "results/x/report.html")
    assert md.startswith("# [lab] ct12: 2 failed systemd unit(s)") and "For: the compute tray / GPU owner" in md
    assert "a.service loaded failed failed A" in md and "`systemctl --failed` on ct12" in md
    assert "this finding is NEW since then" in md and "- ct12: rdma" in md and "ct11" not in md
    with pytest.raises(IndexError):
        ticket.health_finding(RES, 3)
    other = dict(RES, changes={"since": "t0", "new": [], "gone": [], "grew": [], "compared": ["ct11"]})
    assert "not part of it (not compared)" in ticket.health_finding(other, 0)
    there = dict(RES, changes={"since": "t0", "new": [], "gone": [], "grew": [], "compared": ["ct12"]})
    assert "was there already" in ticket.health_finding(there, 0)


def test_finding_zip_keeps_only_its_nodes_outputs(tmp_path):
    run = tmp_path / "health-20261102-183758"
    (run / "raw").mkdir(parents=True)
    (run / "health.json").write_text(json.dumps(RES))
    (run / "report.html").write_text("<p>report</p>")
    outs = {"ct12": {"failed": {"out": "a.service password=hunter2"}}, "ct11": {"failed": {"out": "other"}}}
    (run / "raw" / "outputs.json.gz").write_bytes(gzip.compress(json.dumps(outs).encode()))
    data, stats = bundle.build_finding(run, 0)
    z = zipfile.ZipFile(io.BytesIO(data))
    root = "health-20261102-183758-finding-1/"
    assert sorted(z.namelist()) == sorted(root + n for n in ("ticket.md", "finding.json", "outputs.json", "report.html"))
    got = json.loads(z.read(root + "outputs.json"))
    assert list(got) == ["ct12"] and "hunter2" not in z.read(root + "outputs.json").decode() and stats["redacted"] == 1


def test_run_bundle_json_stays_json_after_redaction(tmp_path):
    run = tmp_path / "scan-20261102-180000"
    run.mkdir()
    (run / "link_check.json").write_text(json.dumps({"x": "token=abc123", "y": [1, 2]}))
    (run / "notes.json").write_text("not json token=abc")
    data, stats = bundle.build(run)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert json.loads(z.read("scan-20261102-180000/link_check.json")) == {"x": "token: <REDACTED>", "y": [1, 2]}
    assert b"abc" not in z.read("scan-20261102-180000/notes.json") and stats["redacted"] == 2


def test_health_results_get_the_health_prompt(tmp_path):
    from heliosdbg import ai, cases
    d = tmp_path / "health-20261102-183758"
    d.mkdir()
    (d / "health.json").write_text(json.dumps(RES))
    ev, subject, _rack = cases.health_context(d, "lab", d.name, "ct12")
    system = ai.build_messages(ev, subject)[0]["content"]
    assert "This is a node health result" in system and "sudo amd-smi metric --ecc --json" in system
    other = cases.general(ai.Evidence())
    assert "This is a node health result" not in ai.build_messages(other, "a test result")[0]["content"]
