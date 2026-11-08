"""Any Linux node: OS disk and memory, kernel errors of the last hour (machine checks, GPU driver, PCIe, disk, NIC,
out of memory), failed systemd units. Read-only."""
from __future__ import annotations

import re

from ..checks import CRITICAL, INFO, LIMITS, WARNING, Platform, _cmd, _disk, _memory, _out, finding
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (r"dmesg(?:\s+-T)?", True),
    (r"ip\s+-br\s+(?:link|addr)", False),
    (r"uptime|free\s+-[mh]|df\s+-h|uname\s+-a", False),
    (r"journalctl\s+(?:-k|-u\s+[A-Za-z0-9@_.-]+|-p\s+(?:err|warning|crit))(?:\s+-p\s+(?:err|warning|crit))?(?:\s+-n\s+\d+)?"
         r"(?:\s+--since\s+-?\d+[hm]|\s+--since\s+'-\d+\s+min')?(?:\s+--no-pager)?(?:\s+-q)?", True),
    (r"df\s+-[Ph](?:\s+/[a-z/]*)*|cat\s+/proc/(?:meminfo|loadavg|uptime)|rdma\s+link\s+show|lspci\s+-d\s+1002:", False),
    (r"ipmitool\s+(?:sel\s+(?:list|elist|info)|sdr(?:\s+list|\s+elist)?|fru(?:\s+print)?|sensor(?:\s+list)?|"
         r"chassis\s+status|mc\s+info|lan\s+print)", True),
    (r"systemctl\s+status\s+[A-Za-z0-9@_.-]+(?:\s+--no-pager)?|systemctl\s+--failed(?:\s+--no-pager)?", False),
    (r"lsmod|sensors|nvme\s+list|ethtool(?:\s+-[Sim])?\s+[A-Za-z0-9_.-]+", False),
    # the kernel and its drivers (g02-g17 7 Nov: 7 trays booted a kernel with no AMD DKMS build - none of these could be
    # asked for): which kernel runs and which are installed, what DKMS built for which, which driver holds the GPUs,
    # when a kernel was installed
    (r"uname(?:\s+-[asrv]+)?|cat\s+/proc/(?:cmdline|version)|ls(?:\s+-l)?\s+/boot/?|dkms\s+status|"
     r"cat\s+/sys/module/[a-z_]+/version|ls\s+/sys/bus/pci/drivers/amdgpu/?|"
     r"lspci(?:\s+-[nvkD]+)*\s+-d\s+1002:(?:\s+-[nvkD]+)*|"
     r"grep\s+(?:-h\s+)?(?:'|\")?(?:linux-image|linux-headers|amdgpu|dkms)(?:'|\")?\s+/var/log/(?:dpkg\.log\*?|apt/history\.log)", False),
]

COMMANDS = [
    ('disk', 'df -P /', False),
    ('memory', "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo", False),
    ('kernel', "journalctl -k -p err --since '-60 min' --no-pager -q", True),
    ('failed', 'systemctl --failed --no-pager --plain --no-legend', False),
]
BENIGN_UNITS = {"systemd-networkd-wait-online.service"}   # fails on most servers with an unplugged port: not a fault
KERNEL_SIGNS = [
    (re.compile(r"\[Hardware Error\]: (Uncorrected|Fatal|Deferred)", re.I), "compute", "uncorrected machine-check errors"),
    (re.compile(r"\[Hardware Error\]: Corrected error", re.I), "compute", "corrected machine-check errors (CPU / cache / memory)"),
    (re.compile(r"\[Hardware Error\]:", re.I), None, ""),           # the detail lines of the events above: counted with them
    (re.compile(r"amdgpu.*(fault|timeout|reset|ras|error)|gpu.*(hang|reset)", re.I), "gpu", "GPU driver errors"),
    (re.compile(r"(MCE|machine check|EDAC|mce:)", re.I), "compute", "machine-check / memory errors"),
    (re.compile(r"(AER|pcieport|PCIe Bus Error)", re.I), "gpu", "PCIe errors"),
    (re.compile(r"(nvme|I/O error|ext4.*error|XFS)", re.I), "os", "disk / filesystem errors"),
    (re.compile(r"(ionic|mlx5|bnxt|rdma).*(error|fail|down|timeout)", re.I), "rdma", "RDMA NIC errors"),
    (re.compile(r"Out of memory|oom-kill|Killed process", re.I), "os", "out of memory"),
]


def judge(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    _disk(node, "compute", outs, F, "os")
    _memory(node, "compute", outs, F, "os")
    t = _out(outs, "kernel")
    if t:
        lines = [ln for ln in t.splitlines() if ln.strip() and "-- No entries --" not in ln]
        groups: dict[str, tuple[str, list[str]]] = {}
        for ln in lines:
            for rx, area, what in KERNEL_SIGNS:
                if rx.search(ln):
                    if area:
                        groups.setdefault(what, (area, []))[1].append(ln)
                    break
        for what, (area, ls) in groups.items():
            sev = CRITICAL if what.startswith("uncorrected") or len(ls) >= 10 and not what.startswith("corrected") else WARNING
            cause = f"the tray's kernel logged {what}"
            if what.startswith("corrected") and len(ls) < LIMITS["mce_corrected_warn"]:
                # g02-g17: 6-22 an hour on every tray, for days - the platform's normal; noted, a warning when it climbs
                sev = INFO
                cause += (f" - the hardware corrected them ('no action required'); below {LIMITS['mce_corrected_warn']} "
                          "an hour this is noted, not a problem: a rate that climbs, or one uncorrected error, is")
            F.append(finding(node, "compute", "kernel", area, sev,
                             f"{len(ls)} kernel error line(s) in the last hour: {what}", cause,
                             "read 'sudo journalctl -k -p err --since -2h' around these lines; GPU / PCIe errors -> "
                             "'sudo amd-smi ras'", ls[-5:], _cmd(outs, "kernel")))
    t = _out(outs, "failed")
    if t:
        units = [ln.split()[0] for ln in t.splitlines() if ln.strip() and ".service" in ln and ln.split()[0] not in BENIGN_UNITS]
        if units:
            F.append(finding(node, "compute", "failed", "os", WARNING, f"{len(units)} failed systemd unit(s): {', '.join(units[:5])}",
                             "services on the tray failed to start or crashed", "read 'systemctl status <unit>' and "
                             "'journalctl -u <unit> -n 50' for each", t.splitlines()[:6], _cmd(outs, "failed")))
    return F


PLATFORM = Platform("linux", "compute", "the OS of a Linux node (disk, memory, kernel errors, failed services)",
                    COMMANDS, judge,
                    read_only=READ_ONLY)
