"""The low audit items of 4 Nov: unreadable amd-smi / nicctl output is said, not passed as healthy; a quoted
sonic-db-cli 'TABLE|key' is not a pipe; old UI run logs are pruned."""
from __future__ import annotations

import os

from heliosdbg import guide
from heliosdbg.platforms import amd_gpu, rdma
from ui import server


def _r(out, rc=0, cmd="x"):
    return {"out": out, "rc": rc, "cmd": cmd}


GPUS = '[{"gpu": 0, "bdf": "0000:05:00.0"}, {"gpu": 1}, {"gpu": 2}, {"gpu": 3}]'


def test_amd_smi_metric_output_that_cannot_be_read_is_a_warning():
    F = amd_gpu.judge("ct01", {"gpus": _r(GPUS), "ecc": _r("Error: field not supported"), "pcie": _r("[]"),
                               "metric": _r(GPUS)})
    assert any("no readable GPU data" in f["what"] and "ecc" in f["what"] and "pcie" in f["what"] for f in F)
    assert not any("no readable" in f["what"] for f in amd_gpu.judge("ct01", {"gpus": _r(GPUS), "ecc": _r(GPUS)}))


def test_nicctl_output_that_cannot_be_read_and_nics_without_rdma_ports():
    F = rdma.judge("ct01", {"nic_ports": _r("@@card 0000:01:00.0 vulcano/x/1.2\n@@port 0000:01:00.0\nnot json"),
                            "rdma": _r("")})
    titles = " | ".join(f["what"] for f in F)
    assert "nicctl gave no readable port data for card(s) 0000:01:00.0" in titles
    assert "no RDMA ports listed, but nicctl sees 1 NIC card" in titles
    assert not rdma.judge("ct01", {"rdma": _r("")})          # no NIC card known: nothing to say


def test_a_quoted_table_key_is_not_a_pipe():
    c, sudo = guide.check("sudo sonic-db-cli -n asic0 CONFIG_DB keys 'MGMT_INTERFACE|*'", "switch")
    assert sudo and guide._pipe(c) == -1
    c, _ = guide.check("sonic-db-cli APPL_DB hgetall 'PORT_TABLE|Ethernet0' | grep speed", "switch")
    assert c[guide._pipe(c) + 1:].strip() == "grep speed"
    for bad in ("sonic-db-cli CONFIG_DB keys 'A|*' | grep a | tail -3", "sonic-db-cli CONFIG_DB keys a | cat /etc/shadow"):
        try:
            guide.check(bad, "switch")
            raise AssertionError(bad)
        except guide.GuideError:
            pass


def test_old_run_logs_are_pruned_but_not_a_kept_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "JOBS_LOGS_KEEP", 3)
    for i in range(6):
        f = tmp_path / f"j{i}.log"
        f.write_text("x")
        os.utime(f, (i, i))
    server._prune_job_files(tmp_path, {"j0": {}})
    assert sorted(p.name for p in tmp_path.glob("*.log")) == ["j0.log", "j3.log", "j4.log", "j5.log"]
