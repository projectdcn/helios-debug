"""A tray that booted a kernel its AMD driver was not built for (g02-g17, 7 Nov: 7 trays after an unattended kernel
upgrade): Node health and the link check say so, instead of 'GPU ports could not be read'. The outputs are real."""
from pathlib import Path

from heliosdbg import gpudriver
from heliosdbg.guide import check
from heliosdbg.platforms import amd_gpu

D = Path(__file__).parent / "data" / "gpudriver"


def out(name):
    return (D / f"{name}.txt").read_text()


def test_booted_a_kernel_with_no_driver():
    d = gpudriver.diagnose(out("booted-42-no-driver"))
    assert d["severity"] == "down" and "7.0.0-42-generic" in d["what"]
    assert "built only for 7.0.0-38-generic" in d["cause"] and "ifoe-drv, ionic" in d["cause"]
    assert "7.0.0-38-generic" in d["next"] and "CHANGES THE TRAY" in d["next"]


def test_a_healthy_tray_whose_next_boot_has_no_driver_is_warned():
    d = gpudriver.diagnose(out("running-38-next-42"))
    assert d["severity"] == "next_boot" and "7.0.0-42-generic is installed but has no AMD GPU driver" in d["what"]


def test_a_tray_with_the_driver_built_for_its_kernel_is_fine():
    assert gpudriver.diagnose(out("running-42-built")) is None
    assert gpudriver.diagnose("") is None and gpudriver.diagnose("not this command") is None


def test_node_health_gives_the_reason_not_the_symptom():
    outs = {"driver": {"out": out("booted-42-no-driver"), "rc": 0, "cmd": gpudriver.COMMAND},
            "gpus": {"out": "", "err": "ERROR:root:Unable to detect any GPU devices", "rc": 1, "cmd": "amd-smi list --json"}}
    f = amd_gpu.judge("ct02", outs)
    assert f[0]["check"] == "driver" and f[0]["severity"] == "critical"
    assert not any(x["check"] == "gpus" for x in f)        # 'amd-smi cannot read the GPUs' adds nothing to the reason


def test_the_link_check_names_the_driver():
    from tests.test_linkdiag import _one, _switch, _tray
    tr = _tray(error="CommandError: [ct03] rc=2: afmctl show device --json", slot=2)
    tr["gpus"], tr["driver"] = [], gpudriver.diagnose(out("booted-42-no-driver"))
    ln = _one(_switch(oper="up", fdb=False), tr)[0]
    assert ln.kind == "tray_not_read" and "has no GPU driver" in ln.cause and "7.0.0-42-generic" in ln.cause
    assert ln.action.startswith("Boot the kernel the driver was built for")


def test_debug_a_node_may_read_kernel_and_driver_state():
    for c in ("uname -r", "dkms status", "lspci -k -d 1002:", "ls /boot", "grep linux-image /var/log/dpkg.log*"):
        assert check(c, "compute")[0] == c
