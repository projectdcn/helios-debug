"""Node health: what is wrong on each switch tray, compute tray and AFM of a rack beyond the GPU links - SONiC (health,
containers, critical processes, CRM tables, disk, memory, cores, reboot cause, syslog errors, saved configuration),
the switch platform (PSUs, fans, temperatures, voltages, watchdog), the compute trays (GPUs, ECC, PCIe, GPU
configuration, kernel errors, OS disk / memory, RDMA NICs, failed services) and AFM (agent, controller and agent
certificates; with the AFM password, AFM's view of every compute node).

Read-only: every command only reads. Each problem becomes one finding with the evidence lines it rests on, the area of
its cause (the incident brain's areas: sonic, switch, power, thermal, bmc, afm, gpu, compute, os, rdma), who owns the
fix and the next step - as a link check's root causes do.

The core (findings, reading outputs, thresholds, grouping, report) is heliosdbg/checks.py; what is checked per kind of
node is heliosdbg/platforms/ (sonic, afm, amd_gpu, linux, rdma). This module keeps the names the tools use:
collect_switch / collect_compute and judge_switch / judge_compute over a node's platforms. The rules read the outputs
only, so they are tested on recorded outputs without a rack.
"""
from __future__ import annotations

from . import checks
from .checks import (CRITICAL, LIMITS, MISSING_RX, OWNERS, TRANSIENT, WARNING, Platform, _cmd, _num,  # noqa: F401
                     _out, _run, finding, missing, not_run, rack_wide, report_text, summary)  # noqa: F401
from .platforms import DEFAULTS, PLATFORMS, for_node  # noqa: F401
from .platforms.afm import judge_afm  # noqa: F401
from .platforms.amd_gpu import _gpu_list  # noqa: F401

SWITCH_CMDS = [c for n in DEFAULTS["switch"] for c in PLATFORMS[n].commands]
COMPUTE_CMDS = [c for n in DEFAULTS["compute"] for c in PLATFORMS[n].commands]


def _host(node):
    return getattr(node, "host", None)


def collect_switch(sw, drift: bool = True) -> dict:
    """Every switch check's output: {check: {cmd, rc, out, err}}."""
    return checks.collect(sw, for_node("switch", _host(sw)), {"drift": drift})


def collect_compute(tray) -> dict:
    return checks.collect(tray, for_node("compute", _host(tray)))


def judge_switch(node: str, outs: dict, platforms: list | None = None) -> list[dict]:
    return checks.judge(node, outs, platforms or for_node("switch"), {"role": "switch"})


def judge_compute(node: str, outs: dict, expect_gpus: int = 4, platforms: list | None = None) -> list[dict]:
    return checks.judge(node, outs, platforms or for_node("compute"), {"gpus": expect_gpus, "role": "compute"})


def judge_rack(raw: dict[str, dict], roles: dict[str, str], hosts: dict | None = None) -> list[dict]:
    """The platforms' checks across nodes ({node: outs}, {node: role}): e.g. NIC firmware that differs between trays."""
    F: list[dict] = []
    by_platform: dict[str, dict[str, dict]] = {}
    for node, outs in raw.items():
        if node not in roles:
            continue
        for p in for_node(roles[node], (hosts or {}).get(node)):
            if p.judge_rack:
                by_platform.setdefault(p.name, {})[node] = outs
    for name, outs_by_node in by_platform.items():
        if len(outs_by_node) > 1:
            F += PLATFORMS[name].judge_rack(outs_by_node)
    return F
