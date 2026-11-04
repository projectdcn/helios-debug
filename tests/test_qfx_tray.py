"""QFX5252 switch tray checks (leak, SSD, NTP, BMC through bmc-manager, images, management) - outputs as g02-g17 st5
printed them on 4 Nov 2026."""
from heliosdbg.platforms import sonic

LEAK_OK = """Field                      Value
-------------------------  -----------------
Device leak status         Normal
Hardware comparator alert  No
FPGA access                Good
ADC access                 Good
"""
CHANNELS = """  Channel  Name    Location                          Voltage-mV    Raw    Low-mV    High-mV  Thresholds    Masked    Disabled    Data-status    Last-update
---------  ------  ------------------------------  ------------  -----  --------  ---------  ------------  --------  ----------  -------------  -----------------
        0  IN0     Inlet manifold                          2539   3152         0          0  No            Yes       No          Good           20261104 07:14:29
        2  IN2     Right Top Cold plate (SWB1)             2548   3162         0          0  No            Yes       No          Bad            20261104 07:14:29
"""
NTP = """MGMT_VRF_CONFIG is not present.
Stratum         : 0
Leap status     : Not synchronised
MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^? 216.239.35.0                  1   6     0    6d   -726us[ -726us] +/- 5488us
"""
BMC_HEALTH_OK = """Critical Services:
  bmcweb               active
  dbus-broker          active
╔══════════════════════════════════════╗
║       BMC STATUS: HEALTHY            ║
╚══════════════════════════════════════╝
"""


def _o(**kw):
    return {k: {"cmd": k, "rc": 0, "out": v if isinstance(v, str) else v[0], "err": "" if isinstance(v, str) else v[1]}
            for k, v in kw.items()}


def _run(outs):
    F = []
    sonic._tray("st5", outs, F)
    return {(f["check"], f["severity"]): f for f in F}


def test_healthy_tray_has_no_findings_but_ntp_and_bmc_watchdog_are_named():
    F = _run(_o(leak=LEAK_OK, ssd="Disk Type    : NVME\nHealth       : 100.0%\n", bmc_health=BMC_HEALTH_OK,
                images="Current: SONiC-OS-202505-X100-1027.2\nNext: SONiC-OS-202505-X100-1027.2\n", mgmt="",
                ntp=NTP, bmc_power=("BMC_STAT_REG (0x544): 0x00000011\n",
                                    "[PASS] Power:   ON  (PWR_EN=0x6)\n[WARN] WDT reset status asserted (BMC_STAT bit4)\n")))
    assert set(F) == {("ntp", "warning"), ("bmc", "warning")}
    assert "reach 0" in F[("ntp", "warning")]["cause"] and "watchdog" in F[("bmc", "warning")]["cause"]


def test_leak_ssd_image_and_mgmt_problems():
    F = _run(_o(leak=LEAK_OK.replace("Normal", "Leak detected").replace("comparator alert  No", "comparator alert  Yes"),
                leak_channels=CHANNELS, ssd="Health       : 42.0%\n",
                images="Current: SONiC-OS-A\nNext: SONiC-OS-B\nAvailable:\nSONiC-OS-A\nSONiC-OS-B\n",
                mgmt="MGMT_INTERFACE|eth0|10.0.0.5/24\nMGMT_INTERFACE|eth1|10.0.1.5/24\n",
                bmc_health=BMC_HEALTH_OK.replace("HEALTHY", "DEGRADED").replace("dbus-broker          active",
                                                                               "dbus-broker          failed")))
    assert F[("leak", "critical")]["what"].startswith("leak detection: device leak status Leak detected")
    assert "IN2" in F[("leak", "warning")]["what"]
    assert F[("ssd", "critical")]["what"] == "SSD health 42 %"
    assert "boots SONiC-OS-B" in F[("image", "warning")]["what"]
    assert F[("mgmt", "warning")]["what"] == "2 management interfaces configured"
    assert "degraded" in F[("bmc", "warning")]["what"] and "dbus-broker" in F[("bmc", "warning")]["what"]


def test_commands_missing_on_other_platforms_are_not_findings():
    F = _run({k: {"cmd": k, "rc": 127, "out": "", "err": "bmc-manager: command not found"}
              for k in ("leak", "ssd", "ntp", "bmc_health", "bmc_power", "images", "mgmt")})
    assert F == {}


def test_a_critical_program_supervisord_does_not_run_at_all_is_not_down():
    outs = {"critical:radv": {"cmd": "x", "rc": 3, "err": "", "out": "program:radvd\n===\ndependent-startup  EXITED  Oct 29\n"
                              "rsyslogd   RUNNING   pid 22, uptime 6 days\n"},
            "critical:bgp": {"cmd": "x", "rc": 3, "err": "", "out": "program:bgpd\n===\nbgpd   EXITED   Oct 29\n"}}
    F = []
    sonic._critical("st5", outs, F)
    assert len(F) == 1 and "bgpd" in F[0]["what"] and "radv" not in F[0]["what"]
