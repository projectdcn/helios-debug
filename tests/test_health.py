"""heliosdbg.health: node health rules on recorded outputs (helios-tests' replay of a healthy switch and tray): a
healthy node has no finding, each fault one finding with the right area, owner and evidence."""
from __future__ import annotations

import json
import time
from pathlib import Path

from heliosdbg import guide, health

FX = Path(__file__).parent / "fixtures" / "health"
HEALTH_OK = "System status summary\n\n  System status LED  green\n  Services:\n    Status: OK\n  Hardware:\n    Status: OK\n"
CONTAINERS = "\n".join(f"{c}\tUp 3 days" for c in ("database", "pmon", "lldp0", "swss0", "syncd0", "bgp0", "afm-agent"))
CRIT_SWSS = "program:orchagent\nprogram:portsyncd\nprogram:neighsyncd\n===\n" + (FX / "supervisor_swss0.txt").read_text()


def r(out: str, rc: int = 0, cmd: str = "cmd", err: str = "") -> dict:
    return {"cmd": cmd, "rc": rc, "out": out, "err": err}


def switch_ok() -> dict:
    started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 3 * 86400))
    return {
        "health": r(HEALTH_OK), "containers": r(CONTAINERS),
        "restarts": r("\n".join(f"/{c} 0 {started}.11Z" for c in ("database", "pmon", "swss0", "syncd0", "afm-agent"))),
        "uptime": r(f"{3 * 86400 + 600}.0 1000.0"), "crm": r((FX / "crm.txt").read_text()),
        "disk": r((FX / "df.txt").read_text()), "memory": r((FX / "meminfo.txt").read_text()), "cores": r(""),
        "reboot": r("User issued 'reboot' command [User: admin, Time: Tue Oct 13 12:01:12 AM UTC 2026]"),
        "psu": r((FX / "psustatus.txt").read_text()), "fan": r((FX / "platform_fan.txt").read_text()),
        "temperature": r((FX / "temperature.txt").read_text()), "voltage": r((FX / "voltage.txt").read_text()),
        "watchdog": r((FX / "watchdog.txt").read_text()), "syslog": r("", rc=1), "afm_agent": r("active"),
        "critical:swss0": r(CRIT_SWSS),
    }


def compute_ok() -> dict:
    dev = {"device": [{"bdf": f"000{i}:01:00.1", "spec": {"accelerator_id": str(i), "config_phase": "ACTIVE"}} for i in range(4)]}
    return {"gpus": r((FX / "amd_smi_list.json").read_text()), "ecc": r((FX / "amd_smi_ecc.json").read_text()),
            "metric": r((FX / "amd_smi_metric.json").read_text()), "processes": r((FX / "amd_smi_process.json").read_text()),
            "afmctl": r(json.dumps(dev)), "disk": r((FX / "compute_df.txt").read_text()), "memory": r((FX / "meminfo.txt").read_text()),
            "kernel": r(""), "rdma": r((FX / "rdma_link.txt").read_text()), "failed": r("")}


def one(fs, check):
    got = [f for f in fs if f["check"] == check]
    assert len(got) == 1, fs
    return got[0]


def test_healthy_nodes_have_no_finding():
    assert health.judge_switch("st1", switch_ok()) == []
    assert health.judge_compute("ct01", compute_ok()) == []


def test_switch_faults_each_give_one_finding_with_area_and_owner():
    o = switch_ok()
    o["critical:pmon"] = r("program:xcvrd\nprogram:psud\nprogram:thermalctld\n===\nxcvrd   RUNNING   pid 1\n"
                           "psud    EXITED    Oct 21 09:31 AM\nthermalctld RUNNING pid 3\n")
    o["psu"] = r((FX / "psustatus.txt").read_text().replace("OK      green", "N/A     off", 1))
    o["watchdog"] = r("Status: Unarmed\n")
    o["crm"] = r((FX / "crm.txt").read_text().replace("fdb_entry             204             7987", "fdb_entry            8186                5", 1))
    o["containers"] = r(CONTAINERS.replace("syncd0\tUp 3 days", "syncd0\tExited (139) 2 minutes ago"))
    fs = health.judge_switch("st2", o)
    crit = one(fs, "critical")
    assert crit["area"] == "sonic" and crit["owner"] == "network" and "psud" in crit["what"] and "psud:EXITED" in crit["evidence"]
    assert one(fs, "psu")["area"] == "power" and "N/A" in one(fs, "psu")["what"]
    assert one(fs, "watchdog")["what"] == "hardware watchdog not armed"
    crm = one(fs, "crm")
    assert crm["severity"] == health.CRITICAL and "fdb_entry" in crm["what"] and "asic0" in crm["what"]
    c = one(fs, "containers")
    assert "syncd0" in c["what"] and c["severity"] == health.CRITICAL and "CHANGES THE SWITCH" in c["next"]


def test_platform_disk_memory_reboot_restarts_syslog_and_cores():
    o = switch_ok()
    o["fan"] = r((FX / "platform_fan.txt").read_text().replace("Present   OK", "Present   Not OK", 1))
    o["temperature"] = r((FX / "temperature.txt").read_text().replace("52.0    105.0     N/A         115.0          N/A  False",
                                                                       "108.0    105.0     N/A         115.0          N/A  True"))
    o["disk"] = r((FX / "df.txt").read_text().replace("2% /var/log", "97% /var/log"))
    o["memory"] = r("MemTotal:       32581108 kB\nMemAvailable:     981108 kB\n")
    o["reboot"] = r("Kernel Panic [Time: Wed Oct 21 03:12:00 AM UTC 2026]")
    recent = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 1800))
    o["restarts"] = r(f"/swss0 0 {recent}.1Z\n/pmon 2 2026-10-13T00:02:50.1Z")
    o["syslog"] = r("Oct 21 09:31 st2 ERR swss0#orchagent: :- addFdbEntry: SAI_STATUS_TABLE_FULL\n" * 3)
    o["cores"] = r("orchagent.1729500000.123.core.gz\n")
    fs = health.judge_switch("st2", o)
    assert one(fs, "fan")["area"] == "thermal" and one(fs, "temperature")["severity"] == health.WARNING
    assert "/var/log is 97 %" in one(fs, "disk")["what"] and one(fs, "disk")["severity"] == health.CRITICAL
    assert one(fs, "memory")["severity"] == health.CRITICAL and one(fs, "reboot")["area"] == "switch"
    assert {f["what"].split(" ")[1] for f in fs if f["check"] == "restarts"} == {"swss0", "pmon"}
    s = one(fs, "syslog")
    assert "3 syslog error line(s), 1 distinct message(s): 3x swss0#orchagent" in s["what"] and "orchagent" in one(fs, "cores")["what"]
    assert s["severity"] == health.CRITICAL and "TABLE_FULL" in s["cause"]


def test_one_repeated_syslog_message_is_one_warning_and_pmon_daemons_count():
    """g02-g17 st1, 2 Nov 2026: 400 lines, all orchagent 'PHY ... failed to get TEMP_LIST' from both ASICs; pmon has no
    critical_processes list."""
    o = switch_ok()
    msg = "2026 Nov  2 05:48:{s:02d}.616054 st1 ERR swss{a}#orchagent: :- doTask: PHY 0x3821010000000038 sensors : failed to get TEMP_LIST: -2"
    o["syslog"] = r("\n".join(msg.format(s=i % 60, a=i % 2) for i in range(400)))
    o["critical:pmon"] = r("===\nchassis_db_init   EXITED    Oct 29 05:25 AM\npsud   RUNNING   pid 30\nxcvrd   FATAL   Exited too quickly\n"
                           "ledd   BACKOFF   Exited too quickly\n")
    fs = health.judge_switch("st1", o)
    s = one(fs, "syslog")
    assert s["severity"] == health.WARNING and "2 distinct message(s): 200x swss" in s["what"]
    c = one(fs, "critical")
    assert "xcvrd:FATAL" in c["evidence"] and "ledd:BACKOFF" in c["evidence"] and "chassis_db_init" not in c["what"]


def test_drift_and_afm_on_the_switch():
    o = switch_ok()
    run = {"PORT": {"Ethernet0": {"admin_status": "up", "mtu": "9100"}}, "VLAN": {"Vlan10": {"vlanid": "10"}}}
    saved = {"PORT": {"Ethernet0": {"admin_status": "up", "mtu": "1500"}}, "VLAN": {}}
    o["running:asic0"], o["saved:asic0"] = r(json.dumps(run)), r(json.dumps(saved))
    o["afm_agent"] = r("inactive", rc=3)
    o["agent_certs"] = r("/opt/amd/afm/agent/sysconfig/config0/agent.pem notAfter=Oct  1 00:00:00 2026 GMT")
    fs = health.judge_switch("st1", o)
    d = one(fs, "drift")
    assert "2 entries" in d["what"] and any("mtu running '9100' saved '1500'" in e for e in d["evidence"])
    assert one(fs, "afm_agent")["owner"] == "AFM" and "expired" in one(fs, "agent_certs")["what"]


def test_compute_faults():
    o = compute_ok()
    o["gpus"] = r(json.dumps([{"gpu": i, "bdf": f"0000:1{i}:00.0"} for i in range(3)]))
    ecc = json.loads(o["ecc"]["out"])
    ecc["gpu_data"][2]["ecc"]["total_uncorrectable_count"] = 4
    o["ecc"] = r(json.dumps(ecc))
    o["afmctl"] = r(json.dumps({"device": [{"bdf": "0001:01:00.1", "spec": {"accelerator_id": "", "config_phase": "INIT"}},
                                           {"bdf": "0002:01:00.1", "spec": {"accelerator_id": "5", "config_phase": "ACTIVE"}}]}))
    o["kernel"] = r("Oct 21 09:30 ct07 kernel: amdgpu 0000:13:00.0: amdgpu: GPU reset begin!\n")
    o["rdma"] = r((FX / "rdma_link.txt").read_text().replace("ionic_2/1 state ACTIVE physical_state LINK_UP",
                                                              "ionic_2/1 state DOWN physical_state LINK_DOWN"))
    o["failed"] = r("amdgpu-init.service loaded failed failed AMD GPU init\n")
    o["processes"] = r(json.dumps([{"gpu": 1, "process_list": [{"process_info": {"name": "python3", "pid": 4242}}]}]))
    fs = health.judge_compute("ct07", o)
    assert "3 of 4 GPUs" in one(fs, "gpus")["what"] and one(fs, "ecc")["severity"] == health.CRITICAL
    assert one(fs, "afmctl")["owner"] == "AFM" and "INIT" in one(fs, "afmctl")["what"]
    assert one(fs, "kernel")["area"] == "gpu" and one(fs, "rdma")["area"] == "rdma"
    assert "amdgpu-init.service" in one(fs, "failed")["what"] and "python3" in one(fs, "processes")["what"]


def test_a_missing_command_is_not_checked_not_healthy():
    o = switch_ok()
    o["voltage"] = r("", rc=2, err="Error: No such command \"voltage\".")
    o["watchdog"] = r("", rc=127, err="watchdogutil: command not found")
    assert health.judge_switch("st1", o) == []
    assert health.not_run(o) == ["voltage", "watchdog"]
    assert health.not_run({"x": r("ok")}) == []


def test_afm_view():
    fs = health.judge_afm([{"metadata": {"name": "ct05"}, "status": {"health": "unreachable"}},
                           {"metadata": {"name": "ct06"}, "status": {"health": "healthy"}}])
    assert len(fs) == 1 and fs[0]["node"] == "AFM ct05" and fs[0]["area"] == "afm"


def test_report_text_lists_findings_by_severity():
    o = switch_ok()
    o["watchdog"] = r("Status: Unarmed\n")
    fs = health.judge_switch("st2", o)
    res = {"rack": "g02-g17", "time": "2026-11-02 06:00", "nodes": {"st2": {"role": "switch", "not_run": ["voltage"]}},
           "findings": fs, "summary": health.summary(fs)}
    t = health.report_text(res)
    assert "0 critical, 1 warning" in t and "== WARNING (1)" in t and "st2: hardware watchdog not armed" in t
    assert "NOT CHECKED" in t and "st2: voltage" in t


def test_every_next_step_command_is_read_only_or_marked():
    """A next step that names a disruptive action says so (CHANGES THE ...); the guided steps it suggests are read-only."""
    o = switch_ok()
    o["containers"] = r(CONTAINERS.replace("pmon\tUp 3 days", "pmon\tRestarting (1) 5 seconds ago"))
    o["watchdog"] = r("Status: Unarmed\n")
    for f in health.judge_switch("st2", o):
        if any(w in f["next"].lower() for w in ("starting it", "arming", "cleaning", "config save")):
            assert "CHANGES THE" in f["next"]


def test_the_health_commands_pass_the_guides_read_only_list():
    for cmd in ("show system-health summary", "crm show resources all", "watchdogutil status", "show platform voltage",
                "show reboot-cause history", "docker exec pmon supervisorctl status", "docker logs --tail 100 swss0",
                "show system-health detail"):
        guide.check(cmd, "switch")
    for cmd in ("amd-smi metric --ecc --json", "amd-smi bad-pages -g 2", "rdma link show", "journalctl -k -p err -n 200 --no-pager",
                "systemctl --failed --no-pager"):
        guide.check(cmd, "compute")


def test_real_formats_seen_on_g02_g17():
    """2 Nov 2026, g02-g17 ct01: amd-smi list prints the GPUs and then the AI NICs as two JSON arrays; the kernel log has
    corrected machine-check events (6 lines each); unused NIC ports are administratively DISABLED."""
    gpus = json.dumps([{"gpu": i, "bdf": f"0001:0{i}:00.0"} for i in range(4)], indent=4) + "\n" + \
        json.dumps([{"ai_nic": 0, "bdf": "0000:01:00.0", "product_name": "Salina DPU"}], indent=4)
    o = compute_ok()
    o["gpus"] = r(gpus)
    ev = ("Nov 01 23:40:38 ct01 kernel: [Hardware Error]: Corrected error, no action required.\n"
          "Nov 01 23:40:38 ct01 kernel: [Hardware Error]: CPU:8 (1a:c0:0) MC60_STATUS[Over|CE|MiscV|-|-\n"
          "Nov 01 23:40:38 ct01 kernel: [Hardware Error]: cache level: L3/GEN\n")
    o["kernel"] = r(ev * 3)
    o["rdma"] = r("link ionic_0/1 state ACTIVE physical_state LINK_UP netdev enp4s0np0\n"
                  "link ionic_1/1 state DOWN physical_state DISABLED netdev enP3p68s0\n")
    fs = health.judge_compute("ct01", o)
    assert len(fs) == 1 and fs[0]["check"] == "kernel" and fs[0]["what"].startswith("3 kernel error line(s)")
    assert fs[0]["severity"] == health.WARNING and fs[0]["area"] == "compute"
    assert len(health._gpu_list(gpus)) == 4


def test_amd_smi_failing_is_its_own_finding_and_busy_gpus_are_one():
    o = compute_ok()
    o["gpus"] = r("amdsmi_cli_exceptions.AmdSmiCommandNotSupportedException: {\"error\": \"Command 'list' is not supported on "
                  "the system. Run '--help' for more info.\", \"code\": -7}\n", rc=7)
    o["processes"] = r(json.dumps([{"gpu": i, "process_list": [{"process_info": {"name": "/var/tmp/x/bin/reduce_scatter_perf"}}]}
                                   for i in range(4)]))
    fs = health.judge_compute("ct16", o)
    g = one(fs, "gpus")
    assert g["what"] == "amd-smi cannot read the GPUs on this tray" and "not supported" in g["evidence"][0]
    p = one(fs, "processes")
    assert "reduce_scatter_perf on GPU 0, 1, 2, 3" in p["what"]


def test_the_same_finding_on_many_nodes_is_one_rack_wide_finding():
    fs = [health.finding(f"ct{i:02d}", "compute", "kernel", "compute", health.WARNING,
                         f"{10 + i} kernel error line(s) in the last hour: corrected machine-check errors", "c", "n", ["x"])
          for i in range(1, 6)] + [health.finding("ct09", "compute", "rdma", "rdma", health.WARNING, "8 RDMA NIC port(s) down", "c", "n", ["y"])]
    out = health.rack_wide(fs, {"compute": 17})
    k = [f for f in out if f["check"] == "kernel"]
    assert len(k) == 1 and k[0]["node"] == "5 of 17 trays" and k[0]["nodes"] == [f"ct0{i}" for i in range(1, 6)]
    assert k[0]["what"].startswith("on 5 of 17 trays (ct01, ct02, ct03, ct04, ct05): kernel error line(s)")
    assert "ct03: 13 kernel error" in k[0]["evidence"][2] and [f["node"] for f in out if f["check"] == "rdma"] == ["ct09"]
