"""Is the AMD GPU driver there for the kernel the tray runs? One read-only command, read by Node health (amd_gpu) and,
when a tray answers SSH but afmctl fails, by the link check - so the map says why the tray end is 'not known'.

g02-g17 7 Nov: an unattended upgrade (4 Nov) installed kernel 7.0.0-42 on 7 trays without building the DKMS modules
(amdgpu, ifoe-drv, ionic) for it; each tray that rebooted came up with no GPU driver - GPUs on PCI, none bound,
amd-smi 0 GPUs, afmctl 'No such file or directory' for every GPU. A reboot boots the same kernel again.
8 Nov: booted back into -38 (ct02), the GPUs were still unbound - this rack blacklists amdgpu at boot
(modprobe.blacklist=amdgpu) and loads it by hand after each boot: sudo modprobe amdgpu gpu_recovery=0.
"""
from __future__ import annotations

import re

# read-only, no sudo: the running kernel, how many GPUs the amdgpu driver holds, the AMD GPUs on PCI, the installed
# kernels, and what DKMS built for which kernel
COMMAND = ('echo "running $(uname -r)"; '
           'echo "bound $(ls -d /sys/bus/pci/drivers/amdgpu/0* 2>/dev/null | wc -l)"; '
           'echo "pci $(lspci -d 1002: 2>/dev/null | grep -ciE "display|processing")"; '
           'for k in /boot/vmlinuz-*; do echo "kernel ${k#/boot/vmlinuz-}"; done; '
           'dkms status 2>/dev/null | sed "s/^/dkms /"; '
           'echo "loaded $(test -d /sys/module/amdgpu && echo yes || echo no)"; '
           'echo "blacklist $(grep -c modprobe.blacklist=amdgpu /proc/cmdline)"')
WATCH = ("amdgpu", "ifoe-drv", "ionic")      # the GPU driver, the GPU fabric NIC driver, the RDMA NIC driver


def _kver(k: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", k))


def parse(text: str | None) -> dict | None:
    """{running, bound, pci, kernels, built: {module: {kernel, ...}}} or None when the output is not this command's."""
    if not text or "running " not in text:
        return None
    d: dict = {"running": "", "bound": None, "pci": None, "kernels": [], "built": {}, "loaded": None, "blacklisted": None}
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.startswith("running "):
            d["running"] = ln.split(None, 1)[1].strip() if " " in ln else ""
        elif ln.startswith(("bound ", "pci ")):
            k, v = ln.split(None, 1)
            d[k] = int(v) if v.strip().isdigit() else None
        elif ln.startswith("loaded "):                  # older outputs have no such line: None, not judged
            d["loaded"] = ln.split(None, 1)[1].strip() == "yes" if " " in ln else None
        elif ln.startswith("blacklist "):
            d["blacklisted"] = ln.split(None, 1)[1].strip() not in ("", "0") if " " in ln else None
        elif ln.startswith("kernel ") and "*" not in ln:
            d["kernels"].append(ln.split(None, 1)[1].strip())
        elif ln.startswith("dkms "):
            # 'amdgpu/7.1.0-2410483.26.04, 7.0.0-38-generic, x86_64: installed (Original modules exist)'
            m = re.match(r"dkms\s+([\w.-]+)/[^,]+,\s*([^,]+),\s*[^:]+:\s*installed", ln)
            if m:
                d["built"].setdefault(m.group(1), set()).add(m.group(2).strip())
    return d


def diagnose(text: str | None, expect: int = 4) -> dict | None:
    """What is wrong with the GPU driver, or None: {severity: 'down' | 'next_boot', what, cause, next, evidence}.
    'down': GPUs on PCI but the driver holds fewer than expected, and DKMS has no amdgpu for the running kernel (or
    holds too few for another reason). 'next_boot': all fine now, but a newer installed kernel has no amdgpu built -
    the next reboot is likely to come up without GPUs."""
    d = parse(text)
    if not d or not d["running"]:
        return None
    run, built = d["running"], d["built"]
    missing_now = [m for m in WATCH if built.get(m) and run not in built[m]]   # built for another kernel, not this one
    ev = [f"running kernel {run}; amdgpu holds {d['bound']} GPU(s), {d['pci']} AMD GPU(s) on PCI",
          *(f"DKMS {m}: built for {', '.join(sorted(built[m]))}" for m in WATCH if built.get(m))]
    good = sorted({k for k in built.get("amdgpu", set())}, key=_kver)
    if d["bound"] is not None and d["bound"] < expect and (d["pci"] or 0) > (d["bound"] or 0):
        if "amdgpu" in missing_now:
            return {"severity": "down",
                    "what": f"no AMD GPU driver for the running kernel {run}",
                    "cause": (f"the tray booted kernel {run}, but the AMD driver (DKMS) was built only for "
                              f"{', '.join(good)} - its {d['pci']} GPUs are on PCI with no driver"
                              + (f" (also not built for it: {', '.join(m for m in missing_now if m != 'amdgpu')})"
                                 if len(missing_now) > 1 else "")
                              + "; a reboot boots the same kernel again"),
                    # read-only commands in quotes (an answer lists those as next steps), the changes unquoted
                    "next": (f"compare 'uname -r' with 'dkms status'; then boot the kernel the driver was built for "
                             f"({good[-1]}: set it as the GRUB default, reboot) or build the DKMS modules for {run} "
                             "(dkms autoinstall, needs its headers) and reboot, then load amdgpu as after any boot here "
                             "(sudo modprobe amdgpu gpu_recovery=0) - CHANGES THE TRAY; and hold the kernel "
                             "packages so an unattended upgrade cannot do it again") if good else
                            f"read 'dkms status'; build the AMD DKMS modules for {run} and reboot - CHANGES THE TRAY",
                    "evidence": ev}
        if d["loaded"] is False:
            return {"severity": "down",
                    "what": "the amdgpu driver is not loaded",
                    "cause": (f"the driver is built for the running kernel {run}, but the module is not loaded - "
                              + ("this rack blacklists it at boot (modprobe.blacklist=amdgpu) and loads it by hand "
                                 "after each boot" if d["blacklisted"] else "nothing loaded it")
                              + f"; its {d['pci']} GPUs are on PCI with no driver"),
                    "next": "check 'cat /proc/cmdline' (the blacklist); load it the rack's way: sudo modprobe amdgpu "
                            "gpu_recovery=0 - CHANGES THE TRAY",
                    "evidence": ev + [f"amdgpu module loaded: no; blacklisted at boot: {'yes' if d['blacklisted'] else 'no'}"]}
        return {"severity": "down",
                "what": f"the amdgpu driver holds {d['bound']} of {d['pci']} GPUs on PCI",
                "cause": f"the driver is built for the running kernel {run}, but did not take every GPU - it failed to "
                         "initialise them (or was not loaded)",
                "next": "read 'sudo dmesg | grep -i amdgpu' for the GPUs it did not take; the GPU owner reloads the "
                        "driver or reboots the tray (CHANGES THE TRAY)",
                "evidence": ev}
    newest = max(d["kernels"], key=_kver, default="")
    if newest and newest != run and good and newest not in built.get("amdgpu", set()) and _kver(newest) > _kver(run):
        return {"severity": "next_boot",
                "what": f"kernel {newest} is installed but has no AMD GPU driver",
                "cause": f"the tray runs {run} (driver built), but the newer {newest} - likely the next boot - has no "
                         "amdgpu DKMS build: after a reboot the tray would come up without GPUs",
                "next": f"read 'ls /boot' and 'dkms status'; before the next reboot keep {run} as the GRUB default and hold "
                        f"the kernel packages (apt-mark hold), or build the DKMS modules for {newest} - CHANGES THE TRAY",
                "evidence": ev}
    return None
