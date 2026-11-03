"""Guided isolation of ONE GPU link - DISRUPTIVE, opt-in (link_check.py isolate --yes-disruptive, the UI's Isolate
tab with the link typed to confirm). Takes one end down for a short hold and brings it back, to tell which end a
fault follows, with guards from the test automation's experience:

  * only a GPU link: a switch port described 'To ComputeTray ...' in trunk mode - never a management / uplink port
  * never a port in the inventory's avoid list (thresholds.afm.avoid_ports / thresholds.isolate.avoid_ports,
    '<switch>:<port>'): coupled ports such as g02-g17 st6 / MR3 st1 Ethernet257 + Ethernet261
  * hold at most 300 s; the end is ALWAYS brought back (finally - also on Stop / Ctrl-C / SIGTERM)
  * after the restore: the link must come up (one re-flap if it does not), and every port of that switch ASIC that
    was up before must be up again within collateral_wait_s (90) - anything else is reported as collateral
Actions: switch-flap (config interface shutdown / startup), gpu-flap (afmctl update port idle / enable).
"""
from __future__ import annotations

import signal
import time
from datetime import datetime, timezone

ACTIONS = ("switch-flap", "gpu-flap")
MAX_HOLD_S = 300


class Refused(Exception):
    pass


def _interrupt(*_):
    raise KeyboardInterrupt("stopped")         # the finally below brings the end back


RESTORE_TRIES = 3


def _restore(node, up_cmd: str, step, sleep) -> bool:
    """Enable the end again - retried (a jump-host session refused, a dropped connection, a timeout must not leave the
    link administratively down); every attempt is a step."""
    for i in range(1, RESTORE_TRIES + 1):
        try:
            r = node.run(up_cmd, sudo=True, timeout=120)
            step("brought back", cmd=up_cmd, rc=r.rc, attempt=i)
            if r.rc == 0:
                return True
        except Exception as e:  # noqa: BLE001 - recorded; tried again on a fresh connection
            step("restore failed", cmd=up_cmd, error=f"{type(e).__name__}: {str(e)[:200]}", attempt=i)
            try:
                getattr(getattr(node, "t", None), "reset", lambda: None)()
            except Exception:  # noqa: BLE001
                pass
        if i < RESTORE_TRIES:
            sleep(5)
    step("RESTORE FAILED - enable it by hand", cmd=up_cmd)
    return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check_allowed(ln, avoid: set[str], action: str) -> None:
    if action not in ACTIONS:
        raise Refused(f"action must be one of {', '.join(ACTIONS)}")
    if "computetray" not in (ln.desc or "").lower().replace(" ", ""):
        raise Refused(f"{ln.switch} {ln.sw_port} is not described as cabled to a compute tray ('{ln.desc}') - only GPU links")
    if f"{ln.switch}:{ln.sw_port}" in avoid:
        raise Refused(f"{ln.switch} {ln.sw_port} is in the inventory's avoid list (coupled ports / known collateral)")
    if action == "gpu-flap" and not (ln.tray and ln.bdf and ln.gpu_port is not None):
        raise Refused("the GPU end of this link is not known (tray not read?) - cannot flap it")


def _up_ports(sw, ns) -> set[str]:
    return {r.get("Interface") for r in sw.interfaces_status(ns) if str(r.get("Oper", "")).lower() == "up"}


def _sw_oper(sw, ns, port) -> str:
    return next((str(r.get("Oper", "")).lower() for r in sw.interfaces_status(ns) if r.get("Interface") == port), "?")


def run(sw, tray, ln, action: str, hold_s: float, avoid: set[str], log=print, wait_up_s: float = 120,
        collateral_s: float = 90, sleep=time.sleep) -> dict:
    check_allowed(ln, avoid, action)
    hold_s = max(1.0, min(float(hold_s), MAX_HOLD_S))
    ns = ln.asic or None
    steps: list[dict] = []

    def step(what, **kw):
        steps.append({"t": _now(), "what": what, **kw})
        log(f"{steps[-1]['t']}  {what}" + (f"  {kw}" if kw else ""))

    flag = f" -n {ln.asic}" if ln.asic else ""
    st = (ln.gpu_port // 2) if ln.gpu_port is not None else None
    down_cmd = (f"config interface{flag} shutdown {ln.sw_port}" if action == "switch-flap" else
                f"env AFMCTL_FORCE_UPDATE=1 afmctl update port -b {ln.bdf} -s {st} -p {ln.gpu_port} --admin-state idle")
    up_cmd = (f"config interface{flag} startup {ln.sw_port}" if action == "switch-flap" else
              f"env AFMCTL_FORCE_UPDATE=1 afmctl update port -b {ln.bdf} -s {st} -p {ln.gpu_port} --admin-state enable")
    node = sw if action == "switch-flap" else tray
    before = _up_ports(sw, ns)
    step("before", link=_sw_oper(sw, ns, ln.sw_port), asic_ports_up=len(before))
    old = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, _interrupt)
    except ValueError:                           # not the main thread (tests): Ctrl-C / errors still restore
        old = None
    restored = False
    try:
        r = node.run(down_cmd, sudo=True, timeout=120)
        step("taken down", cmd=down_cmd, rc=r.rc)
        if r.rc != 0:
            raise RuntimeError(f"{down_cmd} failed rc {r.rc}: {(r.stdout + r.stderr).strip()[:200]}")
        sleep(hold_s)
        step("held", seconds=hold_s, link=_sw_oper(sw, ns, ln.sw_port))
    finally:
        if old is not None:                      # a second Stop must not interrupt the restore
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            restored = _restore(node, up_cmd, step, sleep)
            t0, up = time.monotonic(), False
            reflapped = False
            while time.monotonic() - t0 < wait_up_s:
                if _sw_oper(sw, ns, ln.sw_port) == "up":
                    up = True
                    break
                sleep(5)
            if not up and restored:
                step("not up after the restore - flapping once more")
                try:
                    r = node.run(down_cmd, sudo=True, timeout=120)
                    step("taken down again", cmd=down_cmd, rc=r.rc)
                    sleep(5)
                finally:                         # whatever happened, the link is enabled again
                    restored = _restore(node, up_cmd, step, sleep)
                reflapped = True
                t1 = time.monotonic()
                while time.monotonic() - t1 < wait_up_s:
                    if _sw_oper(sw, ns, ln.sw_port) == "up":
                        up = True
                        break
                    sleep(5)
        finally:
            if old is not None:
                signal.signal(signal.SIGTERM, old)
    step("link after the restore", up=up, reflapped=reflapped)
    lost: list[str] = []
    t2 = time.monotonic()
    while True:
        lost = sorted(before - _up_ports(sw, ns) - {ln.sw_port})
        if not lost or time.monotonic() - t2 >= collateral_s:
            break
        sleep(10)
    step("neighbours", collateral=lost)
    return {"action": action, "link": f"{ln.switch} {ln.asic} {ln.sw_port}", "hold_s": hold_s, "restored": restored,
            "up_after": up, "reflapped": reflapped, "collateral": lost, "steps": steps,
            "verdict": ("ok: the link came back" if up and not lost else
                        f"collateral: {', '.join(lost)} up before, still down - add them to avoid_ports and check the "
                        f"cabling / connector they share" if lost else
                        "the link did not come back after the restore (and one re-flap) - the fault stays with this link")}
