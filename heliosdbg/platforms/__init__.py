"""Platforms: what is checked on each kind of node. A node gets the default list of its role, or the inventory's
``platforms: [...]`` for that node (or under defaults); a new kind of node (another GPU vendor, another switch OS, a
plain server) is a new module here with a Platform, nothing else changes.

    switch:  sonic, afm-switch
    compute: amd-gpu, afm-compute, linux, rdma

The link check of the Helios scale-up fabric (IFoE / IFCP links, heliosdbg/linkdiag.py) and the BMC view
(heliosdbg/bmc.py, Redfish) are not command lists and stay where they are.
"""
from __future__ import annotations

from ..checks import Platform
from . import afm, amd_gpu, linux, rdma, sonic

PLATFORMS: dict[str, Platform] = {p.name: p for p in (sonic.PLATFORM, afm.SWITCH, amd_gpu.PLATFORM, afm.COMPUTE,
                                                      linux.PLATFORM, rdma.PLATFORM)}
DEFAULTS = {"switch": ["sonic", "afm-switch"], "compute": ["amd-gpu", "afm-compute", "linux", "rdma"]}


def for_node(role: str, host=None) -> list[Platform]:
    """The platforms of one node: the inventory's platforms: for it, else its role's defaults."""
    names = (getattr(host, "extra", None) or {}).get("platforms") or DEFAULTS.get(role, [])
    if isinstance(names, str):
        names = [x.strip() for x in names.split(",") if x.strip()]
    unknown = [n for n in names if n not in PLATFORMS]
    if unknown:
        raise ValueError(f"unknown platform(s) {unknown} - known: {sorted(PLATFORMS)}")
    return [PLATFORMS[n] for n in names]


def read_only(role: str) -> list:
    """[(pattern, needs sudo)] Debug a node may run on that kind of node: its default platforms' READ_ONLY, in order."""
    out: list = []
    for n in DEFAULTS.get(role, []):
        out += [x for x in PLATFORMS[n].read_only if x not in out]
    return out
