"""AMD Instinct GPUs on a compute tray (amd-smi): GPUs visible, memory ECC, PCIe width / speed, temperature, the
processes on them. Read-only. Another GPU vendor is another module with the same shape."""
from __future__ import annotations

import json
import re

from ..checks import CRITICAL, LIMITS, WARNING, Platform, _cmd, _num, _out, finding
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (r"lspci(?:\s+-[nvkD]+)?(?:\s+-s\s+[0-9a-f:.]+)?", False),
    (r"amd-smi\s+(?:list|static|metric|firmware|topology|xgmi|process|bad-pages|ras)(?:\s+-[A-Za-z]+|\s+--[a-z-]+|\s+-g\s+\d+)*", True),
    (r"rocm-smi(?:\s+--show[a-z]+|\s+-[itucfPa]|\s+--json)*", True),
]

COMMANDS = [
    ('gpus', 'amd-smi list --json', True),
    ('ecc', 'amd-smi metric --ecc --json', True),
    ('pcie', 'amd-smi metric --pcie --json', True),
    ('metric', 'amd-smi metric --usage --power --temperature --mem-usage --json', True),
    ('processes', 'amd-smi process --json', True),
]


def _gpu_list(text: str | None) -> list[dict]:
    """amd-smi --json output in either shape ({gpu_data: [...]} or [...]) -> the per-GPU dicts."""
    if not text:
        return []
    rows, dec, i = [], json.JSONDecoder(), 0
    while True:                           # several JSON documents one after another (g02-g17: the GPUs, then the AI NICs)
        j = min([k for k in (text.find("[", i), text.find("{", i)) if k >= 0], default=-1)
        if j < 0:
            break
        try:
            d, i = dec.raw_decode(text, j)
        except ValueError:
            i = j + 1
            continue
        part = d.get("gpu_data") if isinstance(d, dict) else d
        rows += [r for r in part or [] if isinstance(r, dict) and "gpu" in r]
    return rows


def _val(x):
    return x.get("value") if isinstance(x, dict) else x


def judge(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    expect_gpus = (ctx or {}).get("gpus", 4)
    gpus = _gpu_list(_out(outs, "gpus"))
    g_out = outs.get("gpus") or {}
    said = (g_out.get("out") or "") + "\n" + (g_out.get("err") or "")   # amd-smi puts its error on stderr (ct06 5 Nov)
    smi_err = g_out.get("rc") not in (0, None) and not gpus and re.search(r"Exception|not supported|error|Unable to detect", said, re.I)
    if smi_err:
        bad = [ln for ln in said.splitlines() if re.search(r"Exception|not supported|error|Unable", ln, re.I)]
        msg = re.sub(r"\s+", " ", " ".join(bad) or said).strip()[:240]
        F.append(finding(node, "compute", "gpus", "gpu", CRITICAL, "amd-smi cannot read the GPUs on this tray",
                         "amd-smi fails (the amdgpu driver is not loaded, the GPUs are not initialised, or amd-smi does not "
                         "match the driver) - nothing on the tray can use the GPUs as they are", "read 'sudo dmesg | grep -i "
                         "amdgpu | tail -30' and 'lsmod | grep amdgpu'; the GPU owner reloads the driver or reboots the tray "
                         "(CHANGES THE TRAY)", [msg], _cmd(outs, "gpus")))
    elif _out(outs, "gpus") is not None and len(gpus) < expect_gpus:
        F.append(finding(node, "compute", "gpus", "gpu", CRITICAL, f"{len(gpus)} of {expect_gpus} GPUs visible to amd-smi",
                         "no GPU at all: the amdgpu driver is not loaded or failed at boot more likely than every GPU failing"
                         " - read 'lsmod | grep amdgpu' and 'sudo dmesg | grep -i amdgpu'" if not gpus else
                         "a GPU is missing from the OS - not seated, failed, or lost on the PCIe bus",
                         "read 'sudo lspci -d 1002:' and 'sudo dmesg | grep -i amdgpu' for the missing one; the BMC event log "
                         "next (hardware owner)", [f"GPU {g.get('gpu')}: {g.get('bdf', '')}" for g in gpus],
                         _cmd(outs, "gpus")))
    if gpus:                              # amd-smi answered for the GPUs but a metric read gave nothing usable: not "fine"
        unread = [c for c in ("ecc", "pcie", "metric") if _out(outs, c) is not None and not _gpu_list(_out(outs, c))]
        if unread:
            F.append(finding(node, "compute", unread[0], "gpu", WARNING,
                             f"amd-smi gave no readable GPU data for: {', '.join(unread)}",
                             "these GPU checks were not made (empty or non-JSON output - an amd-smi version that "
                             "prints other fields, or an error text) - so no problem found there means nothing",
                             "read 'sudo amd-smi metric --ecc --pcie --json' by hand",
                             [re.sub(r"\s+", " ", _out(outs, c) or "(empty)")[:160] for c in unread],
                             _cmd(outs, unread[0])))
    for g in _gpu_list(_out(outs, "ecc")):
        e = g.get("ecc") or {}
        unc, corr = _num(e.get("total_uncorrectable_count")), _num(e.get("total_correctable_count"))
        if unc:
            F.append(finding(node, "compute", "ecc", "gpu", CRITICAL, f"GPU {g.get('gpu')}: {int(unc)} uncorrectable ECC error(s)",
                             "the GPU's memory has uncorrectable errors - jobs on it crash; pages may be retired",
                             f"read 'sudo amd-smi bad-pages -g {g.get('gpu')}' and 'sudo amd-smi ras'; the GPU owner decides on a "
                             "reset / RMA", [json.dumps(e)[:250]], _cmd(outs, "ecc")))
        elif corr and corr >= 100:
            F.append(finding(node, "compute", "ecc", "gpu", WARNING, f"GPU {g.get('gpu')}: {int(corr)} correctable ECC errors",
                             "the GPU's memory corrects many errors - it may be degrading", "watch whether the count grows; "
                             f"'sudo amd-smi bad-pages -g {g.get('gpu')}'", [json.dumps(e)[:250]], _cmd(outs, "ecc")))
    for g in _gpu_list(_out(outs, "pcie")):
        p = g.get("pcie") or {}
        w, mw = _num(_val(p.get("width"))), _num(_val(p.get("max_width") or p.get("max_pcie_width")))
        s, ms = _num(_val(p.get("speed"))), _num(_val(p.get("max_speed") or p.get("max_pcie_speed")))
        if (w and mw and w < mw) or (s and ms and s < ms):
            F.append(finding(node, "compute", "pcie", "gpu", WARNING, f"GPU {g.get('gpu')}: PCIe link x{w:.0f} at {s} "
                             f"(max x{mw or 0:.0f} at {ms})", "the GPU's PCIe link trained below its maximum - a riser, "
                             "seating or the slot", "read 'sudo lspci -vv -s <bdf> | grep -i lnk'; hardware owner reseats",
                             [json.dumps(p)[:250]], _cmd(outs, "pcie")))
    for g in _gpu_list(_out(outs, "metric")):
        temp = _num(_val(((g.get("temperature") or {}).get("hotspot"))))
        if temp is not None and temp >= LIMITS["gpu_hot"]:
            F.append(finding(node, "compute", "metric", "thermal", WARNING, f"GPU {g.get('gpu')} hotspot at {temp:.0f} C",
                             "the GPU runs hot - airflow, a fan, or its cooling", "read the tray's BMC thermal sensors and "
                             "fans; site checks cooling", [json.dumps(g.get("temperature"))[:200]], _cmd(outs, "metric")))
    busy = {}
    for g in _gpu_list(_out(outs, "processes")):
        procs = [p for p in g.get("process_list") or [] if isinstance(p, dict) and "No running" not in str(p.get("process_info", ""))]
        for p in procs:
            info = p.get("process_info") if isinstance(p.get("process_info"), dict) else p
            busy.setdefault(str(info.get("name") or "?"), []).append(str(g.get("gpu")))
    if busy:
        F.append(finding(node, "compute", "processes", "compute", WARNING,
                         "GPU(s) in use: " + "; ".join(f"{n.split('/')[-1][:50]} on GPU {', '.join(gs)}" for n, gs in busy.items())[:240],
                         "a workload runs on these GPUs - tests and jobs share them (results and timings are affected)",
                         "read 'sudo amd-smi process' for the owner and its PID; stopping it CHANGES THE TRAY - for its owner",
                         [f"{n} on GPU {', '.join(gs)}" for n, gs in busy.items()], _cmd(outs, "processes")))
    return F


PLATFORM = Platform("amd-gpu", "compute", "AMD GPUs (amd-smi)", COMMANDS, judge,
                    read_only=READ_ONLY)
