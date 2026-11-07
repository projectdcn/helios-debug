"""Why a node could not be reached - one answer for every tool (scan, health, Live, the UI).

An SSH failure used to reach the user as 'rc=255' (via: exec ran `ssh -q` on the jump host, which hides the reason):
g02-g17 2 Nov, Live listed st3 / st5 / st6 and ct12 / ct15 the same way although the switches refused the login and
the trays were off the network. classify() reads the error text (ssh's own message, a paramiko exception) and names
the kind of failure, what it means and the next step; describe() is the one-line form.
"""
from __future__ import annotations

import re

OPERATOR, SITE, JUMP = "operator", "site", "jump host"

# (kind, pattern, what, owner, next) - first match wins; {user} / {host} are filled in when known
KINDS = [
    ("login_refused", r"Permission denied|Authentication failed|AuthenticationException|Too many authentication failures",
     "login refused for {user}", OPERATOR,
     "the node answers but rejects this key for {user} (the key was removed, the account changed, or the inventory names "
     "the wrong user): install the key again (SSH access tab: Install key) or set the right user in the inventory"),
    ("host_key", r"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|BadHostKeyException",
     "host key changed (reinstalled?)", OPERATOR,
     "the node's SSH host key is not the one known: if it was reinstalled, remove the old key with `ssh-keygen -R {host}` "
     "on the machine that logs in (the jump host with via: exec) and check again"),
    ("sudo", r"sudo: a password is required|is not in the sudoers|sudo: a terminal is required|sudo: no tty",
     "sudo asks for a password for {user}", OPERATOR,
     "logged in, but these read-only commands need sudo without a password for {user}"),
    ("dns", r"Could not resolve hostname|Name or service not known|nodename nor servname|Temporary failure in name resolution",
     "name not resolved", OPERATOR, "check the address of {host} in the inventory (or the DNS of the machine that logs in)"),
    ("no_route", r"No route to host|Network is unreachable|Host is unreachable|Destination Host Unreachable",
     "no route to host: off the network", SITE,
     "the node is not on the network (powered off, OS down, or its management link): check its power and console on its "
     "BMC (health with the BMC view), then the cable / switch port of its management link"),
    ("ssh_refused", r"Connection refused|ECONNREFUSED|Errno 111",
     "SSH refused: the node answers but SSH is not listening", SITE,
     "the node is booting or its SSH server stopped: wait a few minutes, else check it on the console (BMC)"),
    ("jump_session", r"Secsh channel \d* ?open FAILED|administratively prohibited|ChannelException|open failed",
     "the jump host did not open a session to it", JUMP,
     "usually the jump host's limit on sessions at once (retried); if it stays, the jump host cannot reach {host}: "
     "test `ssh {host}` on the jump host itself"),
    ("timeout", r"timed out|Timeout|Operation timed out|Errno 110|NoValidConnectionsError|Unable to connect",
     "no answer (timed out)", SITE,
     "nothing answered at {host}: powered off, hung, or a firewall in the way - check its power and console on its BMC"),
    ("dropped", r"Connection closed by|Connection reset|kex_exchange_identification|Broken pipe|EOFError|SSHException",
     "connection dropped", JUMP, "transient, or the node limits SSH logins (MaxStartups): check again; if it stays, read "
     "the node's auth.log"),
]
_RX = [(k, re.compile(p, re.I), w, o, n) for k, p, w, o, n in KINDS]
HUNG_RX = re.compile(r"\] timed out after \d+(?:\.\d+)?s:")     # transport.CommandTimeout


def classify(err, user: str = "", host: str = "") -> dict | None:
    """{kind, what, owner, next, line} for an access failure in `err` (text or exception), None when it is not one."""
    text = err if isinstance(err, str) else f"{type(err).__name__}: {err}"
    res = getattr(err, "result", None)
    rc = res.rc if res is not None else next((int(m) for m in re.findall(r"\brc=(\d+)", text or "")), None)
    if rc is not None and rc != 255:
        return None          # logged in, the command failed: its 'Permission denied' / 'Connection refused' is redis's
    if HUNG_RX.search(text or ""):
        return {"kind": "cmd_timeout", "what": "a command hung (the login worked)", "owner": SITE,
                "next": f"{host or 'the node'} answered SSH but the command did not finish in time: the node is "
                        "overloaded or the tool is stuck (a GPU in a bad state?) - run it by hand there",
                "line": next((ln.strip() for ln in text.splitlines() if HUNG_RX.search(ln)), "")[:200]}
    if res is not None:
        text = res.stderr or ""                      # ssh's own message, not our wrapper's
    for kind, rx, what, owner, nxt in _RX:
        m = rx.search(text or "")
        if m:
            line = next((ln.strip() for ln in text.splitlines() if rx.search(ln)), m.group(0))
            who = re.search(r"([\w.-]+)@([\w.:-]+): Permission denied", text or "")   # ssh names user@host itself
            fill = {"user": user or (who and who.group(1)) or "this user", "host": host or (who and who.group(2)) or "the node"}
            return {"kind": kind, "what": what.format(**fill), "owner": owner, "next": nxt.format(**fill),
                    "line": line[:200]}
    return None


def describe(err, user: str = "", host: str = "") -> str:
    """'login refused for tenant_hpe (tenant_hpe@10.0.0.73: Permission denied (publickey,password).)' or the error."""
    c = classify(err, user, host)
    text = err if isinstance(err, str) else str(err)
    return f"{c['what']} ({c['line']})" if c else text.strip()[:300]


# a chat question about which nodes answer ('how many switches are reachable', 'which compute tray is not reachable'):
# 6 Nov the model answered it from the guide's 2 Nov known-issues table ('16 of 17 reachable trays' - as switches)
ASK_RX = re.compile(r"\b(?:reach\w*|unreachable|ping\w*|ssh\b|offline|online|not answer\w*|answer\w*|"
                    r"powered (?:off|on)|off the network|login)", re.I)
NODES_RX = re.compile(r"\b(?:switch\w*|trays?|nodes?|compute|hosts?|servers?|ct\d+|st\d+)\b", re.I)


def is_question(q: str) -> bool:
    return bool(ASK_RX.search(q or "") and NODES_RX.search(q or ""))


def facts(switches: list[str], computes: list[str], quarantined: list[str], health: dict | None, health_dir: str,
          scan: dict | None, scan_dir: str) -> list[str]:
    """Who answered, exactly: the newest health check (every node of the inventory, read-only) and the link check, each
    with its time - shown to the person as they are; the model only explains them."""
    out = [f"Inventory: {len(switches)} switches ({', '.join(switches)}), {len(computes)} compute trays "
           f"({', '.join(computes)})" + (f"; quarantined (not read): {', '.join(quarantined)}" if quarantined else "")]
    summary = []
    if health:
        nodes, un = health.get("nodes") or {}, set(health.get("unreachable") or [])
        for role, names in (("switch", switches), ("compute", computes)):
            read = [n for n in names if n in nodes and n not in un]
            miss = [n for n in names if n in un or n not in nodes]
            what = "switches" if role == "switch" else "compute trays"
            out.append(f"Health check {health.get('time')} UTC ({health_dir}): {len(read)} of {len(names)} {what} reached"
                       + (f"; NOT reached: {', '.join(miss)}" if miss else " - every one answered"))
            summary.append(f"{len(read)} of {len(names)} {what} reachable" + (f" (NOT reached: {', '.join(miss)})" if miss else ""))
        part = [f"{n} ({', '.join(x['not_run'])} did not run)" for n, x in sorted(nodes.items()) if x.get("not_run")]
        if part:                                    # 6 Nov: ct06's failed afmctl read was answered as 'not reachable'
            out.append("Reachable (answered over SSH), but a read failed on it - not a reachability problem: " + "; ".join(part))
    else:
        out.append("No health check of this rack yet (Health: reads every node, read-only)")
    if scan is not None:
        bad = scan.get("not_checked") or []
        acc = [x for x in bad if classify(x.get("error"))]
        tool = [x for x in bad if not classify(x.get("error"))]
        out.append(f"Link check {scan.get('time_utc')} UTC ({scan_dir}): "
                   + ("every switch and tray was read" if not bad else "; ".join(
                       [f"NOT reached: {x.get('node')} - {describe(x.get('error'))[:160]}" for x in acc]
                       + [f"{x.get('node')} answered, but a read failed ({str(x.get('error') or '').strip()[:120]}) - not a "
                          f"reachability problem" for x in tool])))
    if summary:
        out.insert(0, f"Summary: {' and '.join(summary)} at the health check of {health.get('time')} UTC")
    out.append("These are the newest checks, not this minute: run Health again to see who answers now")
    return out
