"""heliosdbg.health: node health rules on recorded outputs (helios-tests' replay of a healthy switch and tray): a
healthy node has no finding, each fault one finding with the right area, owner and evidence."""
from __future__ import annotations

import json
import time
from pathlib import Path

from heliosdbg import checks, guide, health

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
        "watchdog": r((FX / "watchdog.txt").read_text()), "syslog": r("", rc=1, cmd="grep -hE ' (ERR|CRIT|ALERT|EMERG) ' /var/log/syslog"), "afm_agent": r("active"),
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
    assert fs[0]["severity"] == health.INFO and fs[0]["area"] == "compute"     # 3 an hour: noted (5 Nov)
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


def test_sudo_refused_is_not_healthy():
    """3 Nov audit: sudo -n refused = rc 1, no output - read as 'grep: no match', the tray reported healthy."""
    from heliosdbg import checks
    r = {"cmd": "sudo -n amd-smi metric", "rc": 1, "out": "", "err": "sudo: a password is required\n"}
    assert checks.missing(r) and not checks.missing({"rc": 1, "out": "", "err": ""})
    fs = health.judge_compute("ct01", {"gpu_ecc": r}, expect_gpus=0)
    s = [f for f in fs if f["check"] == "sudo"]
    assert s and "1 check(s) not run (gpu_ecc)" in s[0]["what"] and s[0]["owner"] == "operator"
    assert health.not_run({"gpu_ecc": r}) == ["gpu_ecc"]


def test_rc1_without_output_is_an_answer_only_for_grep():
    """Audit 4 Nov: amd-smi / afmctl failing with rc 1 and no output was read as healthy."""
    assert checks.missing({"cmd": "amd-smi metric --ecc --json", "rc": 1, "out": "", "err": "AMDSMI_STATUS_NO_PERM"})
    assert not checks.missing({"cmd": "grep -hE ' (ERR|CRIT) ' /var/log/syslog", "rc": 1, "out": "", "err": ""})


def test_memory_without_memavailable_is_not_critical():
    F = []
    checks._memory("ct01", "compute", {"memory": {"cmd": "grep", "rc": 0, "out": "MemTotal: 16000000 kB\n", "err": ""}},
                   F, "os")
    assert F == []


def test_bmc_curl_not_run_is_not_a_power_loss():
    import pytest
    from heliosdbg import bmc
    with pytest.raises(RuntimeError, match="BMC not checked"):
        bmc._split("bash: curl: command not found\n", "https://10.0.0.1", ["/redfish/v1/"])


def test_unsafe_advice_after_a_read_is_still_flagged():
    from heliosdbg import ai
    for t in ("Run cat /var/log/syslog, then reboot the switch.", "grep the log for errors and then run config reload on st5.",
              "No need to wait, reboot the switch now.", "sudo docker kill swss", "sudo rm -r /var/core", "sonic-clear counters"):
        assert ai.unsafe_text(t), t
    for t in ("grep reboot /var/log/syslog", "show reboot-cause history", "do not reboot the switch"):
        assert not ai.unsafe_text(t), t


def _ip_rows(n: int, rx: int) -> str:
    return "\n".join(f"{i + 2}: Ethernet{i}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9100 qdisc mq state UP mode DEFAULT\\    "
                     f"link/ether 12:34:56:78:01:00 brd ff:ff:ff:ff:ff:ff\\    RX:  bytes packets errors dropped  missed   mcast"
                     f"           \\    {rx * 64} {rx} 0 0 0 0 \\    TX:  bytes packets errors dropped carrier collsns"
                     f"           \\    6400 100 0 0 0 0 " for i in range(n))


def _restarted(o: dict, at: float, names=("bgp0", "swss0", "syncd0", "teamd0")) -> dict:
    old = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 3 * 86400))
    new = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(at))
    o["restarts"] = r("\n".join([f"/{c} 0 {new}.11Z" for c in names] +
                                [f"/{c} 0 {old}.11Z" for c in ("database", "pmon", "swss1", "syncd1", "afm-agent")]))
    return o


def test_services_restarted_together_are_one_finding_not_one_per_container():
    """g02-g17 5 Nov: swss0, syncd0, bgp0, teamd0, radv and snmp of asic0 started at once - six warnings per switch for one
    restart, each saying 'restarted (0 restart(s))'."""
    o = _restarted(switch_ok(), time.time() - 1800)
    f = one(health.judge_switch("st1", o), "restarts")
    assert f["what"] == "asic0's services started again together: bgp0, swss0, syncd0, teamd0"
    assert "not crash-looping" in f["cause"] and "0 restart(s)" not in f["what"] and f["started"]


def test_restart_run_switch_by_switch_reads_as_a_procedure():
    now = time.time()
    fs = []
    for i in range(6):
        fs += health.judge_switch(f"st{i + 1}", _restarted(switch_ok(), now - 3000 + i * 300))
    g = one(health.rack_wide(fs, {"switch": 6, "compute": 18}), "restarts")
    assert g["node"] == "6 of 6 switches" and "one switch after another, st1 at" in g["cause"]
    assert "about every 5 min" in g["cause"] and " UTC (" in g["evidence"][0]


def test_dead_cpu_receive_names_the_restart_of_its_chip_and_the_chip_that_works():
    o = _restarted(switch_ok(), time.time() - 2400)
    o["cpu_rx:asic0"], o["cpu_rx:asic1"] = r(_ip_rows(20, 0)), r(_ip_rows(20, 50))
    f = one(health.judge_switch("st1", o), "cpu_rx")
    assert f["what"].startswith("asic0: none of the 20 ports") and "swss0, syncd0) were started again 40 min" in f["cause"]
    assert "asic1 receives on all 20" in " ".join(f["evidence"]) and "ask who restarted asic0" in f["next"]


def test_no_gpu_at_all_shows_the_amd_smi_error_from_stderr():
    o = compute_ok()
    o["gpus"] = r("AMDSMI Tool: 27.1.0 | ROCm version: 10.2.0\n", rc=255,
                  err="ERROR:root:Unable to detect any GPU devices, check amdgpu version and module status\n")
    f = one(health.judge_compute("ct06", o), "gpus")
    assert f["what"] == "amd-smi cannot read the GPUs on this tray" and "Unable to detect any GPU" in f["evidence"][0]
    assert "driver" in f["cause"]


def test_clip_never_cuts_mid_word():
    s = "84x SfpGeneric: Port #: bus resolve failed for '$ref:cbfpga_optic': FPGA I2C adapter(s) missing"
    assert checks.clip(s, 80).endswith(" ...") and "adapter(s" not in checks.clip(s, 80) and checks.clip("ab", 80) == "ab"


def test_many_corrected_machine_checks_are_a_warning_few_are_noted():
    o = compute_ok()
    o["kernel"] = r("Nov 01 23:40:38 ct01 kernel: [Hardware Error]: Corrected error, no action required.\n" * 70)
    assert one(health.judge_compute("ct01", o), "kernel")["severity"] == health.WARNING
    o["kernel"] = r("Nov 01 23:40:38 ct01 kernel: [Hardware Error]: Corrected error, no action required.\n" * 12)
    f = one(health.judge_compute("ct01", o), "kernel")
    assert f["severity"] == health.INFO and health.summary([f]) == {"critical": 0, "warning": 0, "info": 1, "by_area": {}}


def test_info_findings_are_not_sent_as_incidents():
    from heliosdbg import incidents
    fs = [{"node": "ct01", "check": "kernel", "severity": "info"}, {"node": "ct02", "check": "gpus", "severity": "critical"}]
    assert [f["node"] for f in incidents.pick({"findings": fs})[0]] == ["ct02"]
