"""The scale-out network of a compute tray: its RDMA NIC ports. Read-only."""
from __future__ import annotations

from ..checks import WARNING, Platform, _cmd, _out, finding
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (r"ibv_devinfo(?:\s+-[vl])?(?:\s+-d\s+[A-Za-z0-9_]+)?|rdma\s+(?:link|dev)(?:\s+show)?", False),
]

COMMANDS = [
    ('rdma', 'rdma link show', False),
]


def judge(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    t = _out(outs, "rdma")
    if t:
        bad = [ln for ln in t.splitlines() if ln.startswith("link") and ("state ACTIVE" not in ln or "LINK_UP" not in ln)
               and "physical_state DISABLED" not in ln]   # an administratively disabled (unused) port is not a fault
        if bad:
            F.append(finding(node, "compute", "rdma", "rdma", WARNING, f"{len(bad)} RDMA NIC port(s) not ACTIVE / LINK_UP",
                             "a scale-out NIC port is down - its cable, the leaf switch port, or the NIC",
                             "read 'ip -br link' and the NIC's leaf switch port; the cable / optic next",
                             bad[:6], _cmd(outs, "rdma")))
    return F


PLATFORM = Platform("rdma", "compute", "the scale-out RDMA NICs of a compute tray", COMMANDS, judge,
                    read_only=READ_ONLY)
