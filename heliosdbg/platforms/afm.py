"""AFM on the nodes: the afm-agent service and the AFM certificates on the switches, each GPU's configuration phase
on the compute trays (afmctl), and with the AFM password AFM's own view of every compute node. Read-only."""
from __future__ import annotations

import json
import re
import time

from ..checks import CRITICAL, LIMITS, WARNING, Platform, _cmd, _out, _run, finding
from ..checks import _NS, _WORD  # noqa: F401 - the allow-list patterns

COMPUTE_READ_ONLY = [   # (pattern, needs sudo): what Debug a node may run on this platform (heliosdbg/guide.py)
    (r"afmctl\s+show\s+(?:device|port|port\s+accelerator-addr|vpod|version|stats)(?:\s+-b\s+[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d)?(?:\s+--json)?", True),
]

SWITCH_COMMANDS = [
    ('afm_agent', 'systemctl is-active afm-agent', False),
]
COMPUTE_COMMANDS = [
    ('afmctl', 'afmctl show device --json 2>/dev/null', True),
]
CONTROLLER_CERT_CMD = "echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -enddate"
AGENT_CERT_CMD = ("sh -c 'for f in /opt/amd/afm/agent/sysconfig/config*/*.pem; do e=$(openssl x509 -noout -enddate -in \"$f\" "
                  "2>/dev/null) && echo \"$f $e\"; done'")


def _afm_switch(node, outs, F):
    t = _out(outs, "afm_agent")
    if t is not None and t.strip() in ("inactive", "failed", "activating", "deactivating"):
        F.append(finding(node, "switch", "afm_agent", "afm", CRITICAL, f"afm-agent service is {t.strip()}",
                         "the AFM agent on this switch is not running - AFM loses this switch and its node agents",
                         "read 'systemctl status afm-agent' and 'docker logs --tail 100 afm-agent'; starting it again "
                         "CHANGES THE SWITCH - for the AFM owner", [t.strip()], _cmd(outs, "afm_agent")))
    for key in ("controller_cert", "agent_certs"):
        c = _out(outs, key)
        if not c:
            continue
        for ln in c.splitlines():
            m = re.search(r"notAfter=(.+)$", ln)
            if not m:
                continue
            try:
                import calendar
                end = calendar.timegm(time.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            except ValueError:
                continue
            days = (end - time.time()) / 86400
            if days < LIMITS["cert_days"]:
                what = ln.split(" notAfter=")[0].strip() or "AFM controller (port 443)"
                F.append(finding(node, "switch", key, "afm", CRITICAL if days < 0 else WARNING,
                                 f"certificate {'expired' if days < 0 else 'expires in %d days' % days}: {what}",
                                 "an AFM certificate is " + ("expired - TLS between AFM and its agents fails" if days < 0
                                                             else "about to expire"),
                                 "renew it as the AFM guide says (CHANGES THE RACK - for the AFM owner)", [ln.strip()],
                                 _cmd(outs, key)))


def judge_switch(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    _afm_switch(node, outs, F)
    return F


def collect_switch(sw, outs: dict, opts: dict) -> None:
    names = [ln.split("\t")[0].strip() for ln in ((outs.get("containers") or {}).get("out") or "").splitlines()
             if "\tUp" in ln]
    if "afm-controller" in names:
        _run(sw, "controller_cert", CONTROLLER_CERT_CMD, True, outs, timeout=30)
    if "afm-agent" in names:
        _run(sw, "agent_certs", AGENT_CERT_CMD, True, outs, timeout=60)


def judge_compute(node: str, outs: dict, ctx: dict | None = None) -> list[dict]:
    F: list[dict] = []
    t = _out(outs, "afmctl")
    if t:
        try:
            from ..afmctl import parse_show_device
            devs = parse_show_device(t)
        except Exception:  # noqa: BLE001 - a non-JSON answer: afmctl is not there or failed - said, not 'healthy'
            devs = []
            F.append(finding(node, "compute", "afmctl", "afm", WARNING, "afmctl's GPU list could not be read",
                             "afmctl answered something that is not its JSON (its agent not running, or an error) - the "
                             "GPUs' AFM state is unknown", "run 'sudo afmctl show device --json' on the tray and read the "
                             "message", t.splitlines()[:3], _cmd(outs, "afmctl")))
        bad = [d for d in devs if str(d.config_phase).upper() != "ACTIVE"]
        if bad:
            F.append(finding(node, "compute", "afmctl", "afm", CRITICAL if len(bad) == len(devs) else WARNING,
                             f"{len(bad)} of {len(devs)} GPU(s) not ACTIVE in afmctl ({', '.join(sorted({d.config_phase or '?' for d in bad}))})",
                             "AFM has not programmed these GPUs on the tray (not in a vPOD, the node agent did not apply it, "
                             "or the GPU failed its setup) - their links carry no traffic",
                             "check the tray in AFM (compute node state, vPOD) and the node agent of this tray on its switch",
                             [f"{d.bdf} acc {d.accel_id or '-'} {d.config_phase}" for d in bad], _cmd(outs, "afmctl")))
    return F


def judge_afm(computes: list[dict]) -> list[dict]:
    """AFM's view of every compute node (GET computenodes): not admitted / not healthy / GPUs not ready."""
    F = []
    for n in computes or []:
        md, st = n.get("metadata") or {}, n.get("status") or {}
        name = md.get("name") or n.get("name") or "?"
        flat = json.dumps(st).lower()
        bad = [k for k in ("unhealthy", "unreachable", "notready", "not_ready", "failed", "degraded", "unknown")
               if re.search(rf'"{k}"|: "{k}', flat)]
        if bad:
            F.append(finding(f"AFM {name}", "afm", "afm_nodes", "afm", WARNING, f"AFM reports compute node {name}: {', '.join(bad)}",
                             "AFM sees this compute node as not healthy (its agent, its GPUs or its admission)",
                             "open the node in AFM and its node agent's log on the switch that serves it",
                             [json.dumps(st)[:280]], "GET /configs/cluster/v1/computenodes"))
    return F


SWITCH = Platform("afm-switch", "switch", "AFM agent and certificates on a switch", SWITCH_COMMANDS, judge_switch,
                  collect_switch)
COMPUTE = Platform("afm-compute", "compute", "each GPU's AFM configuration on a compute tray (afmctl)",
                   COMPUTE_COMMANDS, judge_compute, read_only=COMPUTE_READ_ONLY)
