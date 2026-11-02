"""A node's BMC over Redfish (HTTPS GETs only): what a tray that does not answer over SSH is doing.

Without SSH, health could only say 'not reachable' (g02-g17 2 Nov: ct12, ct15). The BMC answers on its own network
and tells the rest: powered off, powered on but the OS does not answer (hung, booting, or its management link), or
the BMC itself gone too (no power to the tray, or the management network). With the BMC password it also reads the
system / manager health, the sensors over their thresholds and the newest event log entries.

Where it is reached from:
- transport.jump with via: exec (the BMCs are on the rack network): `curl` runs ON the jump host; the login goes in
  as a curl config on stdin (`-K -`), never on a command line (other users of the jump host see command lines);
- otherwise: urllib from this machine.

Inventory: a node's ``bmc:`` address (``https://`` and a port allowed) and ``bmc_user:`` (or ``defaults: compute:
bmc_user:``); the password from $HELIOS_BMC_PASSWORD_<NODE> or $HELIOS_BMC_PASSWORD (the UI's BMC view field) -
never in the inventory. Without a password only the unauthenticated service root is read: reachable or not.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shlex
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

PASSWORD_ENV = "HELIOS_BMC_PASSWORD"
MARK = "@@helios-http "                       # curl --write-out marker after each body: '@@helios-http 200 <url>'
LOG_MAX, SENSORS_MAX, LOG_WINDOW_H = 60, 200, 24


class BmcError(RuntimeError):
    pass


def password_env(name: str) -> str:
    return f"{PASSWORD_ENV}_{re.sub(r'[^A-Za-z0-9]', '_', name).upper()}"


def credentials(host, environ=None) -> tuple[str, str, str]:
    """(bmc address, user, password) of an inventory Host; empty strings for what is not given."""
    env = os.environ if environ is None else environ
    bmc = str(host.extra.get("bmc") or "").strip()
    user = str(host.extra.get("bmc_user") or "").strip()
    return bmc, user, (env.get(password_env(host.name)) or env.get(PASSWORD_ENV) or "") if user else ""


def _base(address: str) -> str:
    return (address if address.startswith(("http://", "https://")) else f"https://{address}").rstrip("/")


class Redfish:
    """GETs of one BMC; get_many() fetches several paths in one round (one curl on the jump host)."""

    def __init__(self, address: str, user: str = "", password: str = "", jump: dict | None = None,
                 timeout: float = 15):
        self.address, self.base, self.user, self.password = address, _base(address), user, password
        self.jump, self.timeout = jump if (jump or {}).get("via") == "exec" else None, timeout

    def get_many(self, paths: list[str], auth: bool = True) -> dict[str, tuple[int, dict | None]]:
        """{path: (HTTP status, JSON or None)}; status 0 = no answer at all."""
        paths = list(dict.fromkeys(p for p in paths if p))
        if not paths:
            return {}
        return self._curl(paths, auth) if self.jump else {p: self._urllib(p, auth) for p in paths}

    def get(self, path: str, auth: bool = True) -> dict:
        code, body = self.get_many([path], auth)[path]
        if code in (401, 403):
            raise BmcError(f"{self.address}: login refused (HTTP {code}) - check bmc_user / the BMC password")
        if code != 200 or body is None:
            raise BmcError(f"{self.address}: GET {path} -> " + (f"HTTP {code}" if code else "no answer"))
        return body

    def _urllib(self, path: str, auth: bool) -> tuple[int, dict | None]:
        req = urllib.request.Request(self.base + path, headers={"Accept": "application/json"})
        if auth and self.user:
            tok = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE      # BMCs have self-signed certificates
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                return r.status, _json(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:  # noqa: BLE001 - refused / timeout / TLS: no answer
            return 0, None

    def _curl(self, paths: list[str], auth: bool) -> dict[str, tuple[int, dict | None]]:
        from .transport import _JUMP_SEMS, _jump_client
        urls = [self.base + p for p in paths]
        cmd = (f"curl -sk --max-time {int(self.timeout)} --connect-timeout {min(int(self.timeout), 8)} "
               f"-H 'Accept: application/json' {'-K - ' if auth and self.user else ''}"
               f"-w {shlex.quote(chr(10) + MARK + '%{http_code} %{url_effective}' + chr(10))} "
               + " ".join(shlex.quote(u) for u in urls))
        client = _jump_client(self.jump, max(self.timeout, 60))
        sem = _JUMP_SEMS.get(id(client))
        if sem:
            sem.acquire()
        try:
            chan = client.get_transport().open_session(timeout=30)
            try:
                chan.exec_command(cmd)
                if auth and self.user:
                    user = (self.user + ":" + self.password).replace("\\", "\\\\").replace('"', '\\"')
                    chan.sendall(f'user = "{user}"\n'.encode())
                chan.shutdown_write()
                out, deadline = bytearray(), time.monotonic() + self.timeout * len(urls) + 30
                while not (chan.exit_status_ready() and not chan.recv_ready()):
                    if chan.recv_ready():
                        out += chan.recv(65536)
                    elif time.monotonic() > deadline:
                        break
                    else:
                        time.sleep(0.02)
                while chan.recv_ready():
                    out += chan.recv(65536)
            finally:
                chan.close()
        finally:
            if sem:
                sem.release()
        return _split(out.decode(errors="replace"), self.base, paths)


def _json(raw) -> dict | None:
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else None
    except (ValueError, TypeError):
        return None


def _split(text: str, base: str, paths: list[str]) -> dict[str, tuple[int, dict | None]]:
    """curl's bodies, each followed by the MARK line, back to {path: (status, JSON)}."""
    out = {p: (0, None) for p in paths}
    body: list[str] = []
    for line in text.split("\n"):
        if line.startswith(MARK):
            code, _, url = line[len(MARK):].partition(" ")
            path = url[len(base):] if url.startswith(base) else url
            if path in out:
                out[path] = (int(code) if code.isdigit() else 0, _json("\n".join(body)))
            body = []
        else:
            body.append(line)
    return out


def _members(d: dict | None) -> list[str]:
    return [m["@odata.id"] for m in (d or {}).get("Members") or [] if isinstance(m, dict) and m.get("@odata.id")]


def _health(o: dict | None) -> str:
    return str(((o or {}).get("Status") or {}).get("Health") or "")


def snapshot(rf: Redfish, authed: bool) -> dict:
    """{reachable, product, auth: ok | refused | none, systems, managers, sensors, log, errors} from GETs only."""
    snap = {"address": rf.address, "reachable": False, "auth": "none", "product": "", "systems": [], "managers": [],
            "sensors": [], "log": [], "errors": []}
    code, root = rf.get_many(["/redfish/v1/"], auth=False)["/redfish/v1/"]
    if not code:
        return snap
    snap["reachable"] = True
    snap["product"] = " ".join(str((root or {}).get(k) or "") for k in ("Vendor", "Product")).strip()
    if not authed:
        return snap
    tops = rf.get_many(["/redfish/v1/Systems", "/redfish/v1/Managers", "/redfish/v1/Chassis"])
    if any(c in (401, 403) for c, _ in tops.values()):
        snap["auth"] = "refused"
        return snap
    snap["auth"] = "ok"
    sys_p, mgr_p, ch_p = (_members(tops[p][1]) for p in ("/redfish/v1/Systems", "/redfish/v1/Managers", "/redfish/v1/Chassis"))
    got = rf.get_many(sys_p + mgr_p + ch_p)
    for p in sys_p:
        s = got[p][1] or {}
        snap["systems"].append({"id": s.get("Id") or p.rsplit("/", 1)[-1], "power": s.get("PowerState"),
                                "health": _health(s), "path": p})
    for p in mgr_p:
        m = got[p][1] or {}
        snap["managers"].append({"id": m.get("Id") or p.rsplit("/", 1)[-1], "health": _health(m),
                                 "firmware": m.get("FirmwareVersion"), "path": p})
    thermal = {p: ((got[p][1] or {}).get("Thermal") or {}).get("@odata.id") for p in ch_p}
    power = {p: ((got[p][1] or {}).get("Power") or {}).get("@odata.id") for p in ch_p}
    legacy = rf.get_many([v for v in [*thermal.values(), *power.values()] if v])
    for p in ch_p:
        cid = p.rstrip("/").rsplit("/", 1)[-1]
        for ref, groups in ((thermal[p], ("Temperatures", "Fans")), (power[p], ("Voltages", "PowerSupplies"))):
            d = legacy.get(ref, (0, None))[1] if ref else None
            for g in groups:
                for o in (d or {}).get(g) or []:
                    reading = next((o[k] for k in ("ReadingCelsius", "Reading", "ReadingVolts", "LineInputVoltage")
                                    if isinstance(o.get(k), (int, float))), None)
                    snap["sensors"].append({"name": f"{cid}/{o.get('Name') or o.get('MemberId')}", "group": g,
                                            "reading": reading, "health": _health(o),
                                            "state": str((o.get("Status") or {}).get("State") or ""),
                                            "upper_crit": o.get("UpperThresholdCritical"),
                                            "lower_crit": o.get("LowerThresholdCritical")})
    snap["sensors"] = snap["sensors"][:SENSORS_MAX]
    svcs = rf.get_many([p.rstrip("/") + "/LogServices" for p in sys_p + mgr_p])
    svc_paths = [m for _c, d in svcs.values() for m in _members(d)]
    entries = {(s.get("Entries") or {}).get("@odata.id") for _c, s in rf.get_many(svc_paths).values() if s}
    for ref, (code, col) in rf.get_many(sorted(e for e in entries if e)).items():
        for m in ((col or {}).get("Members") or [])[-LOG_MAX:]:
            if isinstance(m, dict):
                snap["log"].append({"log": ref.rstrip("/").rsplit("/", 2)[-2], "severity": m.get("Severity"),
                                    "created": m.get("Created"), "message": str(m.get("Message") or "")[:200]})
    return snap


def _recent(created: str, hours: int, now: datetime) -> bool:
    try:
        t = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return True                                    # unknown time: kept, the newest entries are at the end
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now - t <= timedelta(hours=hours)


def judge(node: str, role: str, snap: dict, ssh_ok: bool | None, finding, critical: str, warning: str,
          now: datetime | None = None) -> list[dict]:
    """Findings from one BMC snapshot. ssh_ok: did the node answer over SSH (None: not tried)."""
    now = now or datetime.now(timezone.utc)
    F, cmd = [], f"Redfish GET https://{snap['address']}/redfish/v1/..."
    down = ssh_ok is False
    if not snap["reachable"]:
        if down:
            F.append(finding(node, role, "bmc", "power", critical, "the node and its BMC both do not answer",
                             "no power to the tray (PDU / power shelf / its PSUs) or its management network is down: "
                             "the BMC runs on standby power and would answer otherwise",
                             "check the tray's power feed and the management switch port of its BMC on site",
                             [f"BMC {snap['address']}: no answer to /redfish/v1/"], cmd))
        else:
            F.append(finding(node, role, "bmc", "bmc", warning, f"BMC {snap['address']} does not answer",
                             "the BMC is hung or its management link is down - the node itself is up",
                             "check the BMC's network port; a BMC reset is a change for the hardware owner",
                             [f"BMC {snap['address']}: no answer to /redfish/v1/"], cmd))
        return F
    if snap["auth"] == "refused":
        F.append(finding(node, role, "bmc", "bmc", warning, f"BMC {snap['address']} refused the login",
                         "the BMC user / password given for this run is not accepted",
                         "check bmc_user in the inventory and the BMC password typed for the run",
                         [f"BMC {snap['address']}: HTTP 401 on /redfish/v1/Systems"], cmd))
    if snap["auth"] != "ok":
        if down:
            F.append(finding(node, role, "bmc", "compute", critical, "the node does not answer over SSH, its BMC does",
                             "the tray has standby power and a working management network; the host is powered off, "
                             "hung or booting, or its OS network is down",
                             "give the BMC password (health: BMC view) to read the power state and event log, or open "
                             "the BMC's web console", [f"BMC {snap['address']} answers ({snap['product'] or 'Redfish'})"], cmd))
        return F
    for s in snap["systems"]:
        power = str(s["power"] or "?")
        if power.lower() != "on":
            F.append(finding(node, role, "bmc", "power", critical, f"powered {power.lower()} (BMC: system {s['id']})",
                             "the host is not powered on - someone powered it off, a power fault, or a protective "
                             "shutdown (thermal, PSU); the BMC event log says which",
                             "read the BMC event log entries below before powering it on; powering on CHANGES THE RACK "
                             "- for the lab team", [f"PowerState {power}, health {s['health'] or '?'}"], cmd))
        elif down:
            F.append(finding(node, role, "bmc", "compute", critical, "powered on, but the OS does not answer over SSH",
                             "the host is on: the OS hung, is still booting, or its network (management link, IP) is "
                             "down", "open the host console on the BMC (web console / serial over LAN) to see where it "
                             "stopped; the event log below", [f"PowerState On, health {s['health'] or '?'}"], cmd))
        if s["health"] in ("Critical", "Warning"):
            F.append(finding(node, role, "bmc", "compute", critical if s["health"] == "Critical" else warning,
                             f"BMC reports system {s['id']} health {s['health']}",
                             "the BMC sees a hardware fault on the host (the event log and sensors say which)",
                             "read the event log entries and the sensors in the BMC", [json.dumps(s)[:200]], cmd))
    for m in snap["managers"]:
        if m["health"] in ("Critical", "Warning"):
            F.append(finding(node, role, "bmc", "bmc", warning, f"BMC {m['id']} health {m['health']}",
                             "the BMC reports a fault of its own", "read the BMC's own log; firmware "
                             f"{m['firmware'] or '?'}", [json.dumps(m)[:200]], cmd))
    bad = []
    for x in snap["sensors"]:
        r, hi, lo = x["reading"], x["upper_crit"], x["lower_crit"]
        if x["state"] in ("Absent", "Disabled"):
            continue
        over = isinstance(r, (int, float)) and ((isinstance(hi, (int, float)) and r >= hi)
                                                or (isinstance(lo, (int, float)) and r <= lo))
        if over or x["health"] == "Critical":
            bad.append(x)
    if bad:
        area = "thermal" if any(b["group"] in ("Temperatures", "Fans") for b in bad) else "power"
        F.append(finding(node, role, "bmc", area, critical, f"{len(bad)} BMC sensor(s) critical: "
                         + ", ".join(f"{b['name']} {b['reading']}" for b in bad[:4]),
                         "a temperature, fan, voltage or PSU is past its critical threshold",
                         "hardware owner: the part named; site checks cooling / power",
                         [json.dumps(b)[:160] for b in bad[:6]], cmd))
    serious = [e for e in snap["log"] if str(e["severity"]) in ("Critical", "Warning")
               and _recent(e["created"], LOG_WINDOW_H, now)]
    if serious:
        groups: dict[str, list] = {}
        for e in serious:
            groups.setdefault(re.sub(r"\d+", "#", e["message"])[:90], []).append(e)
        crit = any(str(e["severity"]) == "Critical" for e in serious)
        F.append(finding(node, role, "bmc", "compute", critical if crit else warning,
                         f"{len(serious)} BMC event log entr{'y' if len(serious) == 1 else 'ies'} (warning / critical) in "
                         f"the last {LOG_WINDOW_H} h, {len(groups)} distinct",
                         "the BMC logged hardware events (power, thermal, memory, PCIe) - the newest are below",
                         "match their times with when the node stopped answering; the hardware owner reads the full log",
                         [f"{g[-1]['created']} {g[-1]['severity']}: {g[-1]['message']} (x{len(g)})"
                          for g in sorted(groups.values(), key=lambda g: str(g[-1]['created']))[-6:]], cmd))
    return F
