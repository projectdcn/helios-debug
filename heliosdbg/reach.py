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


def classify(err, user: str = "", host: str = "") -> dict | None:
    """{kind, what, owner, next, line} for an access failure in `err` (text or exception), None when it is not one."""
    text = err if isinstance(err, str) else f"{type(err).__name__}: {err}"
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
