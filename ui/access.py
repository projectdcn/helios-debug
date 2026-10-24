"""SSH access from the debug UI: which key each node is reached with, a key-only login + sudo check, and installing
that key on a node with its password once (what ssh-copy-id does, through the jump host when the inventory has one).

The key per node is the one the tools themselves offer (heliosdbg.transport.resolve_keys): $HELIOS_SSH_KEY (the
switch-tray install sets it), the inventory's key_file, ~/.ssh/config, else the default ~/.ssh/id_* keys - so a key
installed here is the one the next scan uses. A password typed in the UI is used for that one login and kept
nowhere: not in the job list, the logs, or the command log (only the commands are recorded, never a password).
"""
from __future__ import annotations

import dataclasses
import os
import shlex
import subprocess
from pathlib import Path

from heliosdbg.rack import fan_out
from heliosdbg.transport import SshTransport, is_local, resolve_keys

DEFAULT_KEYS = ("~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_rsa")
NEW_KEY = "~/.ssh/id_ed25519"


class AccessError(Exception):
    pass


def node_key(h) -> tuple[str | None, str]:
    """(private key file this node is reached with, where it comes from); (None, why) when only the agent / no key."""
    try:
        files, src = resolve_keys(h.key_file, h.name, h.host)
    except FileNotFoundError as e:
        return None, str(e)
    if files:
        return os.path.expanduser(files[0]), src
    for k in DEFAULT_KEYS:
        p = os.path.expanduser(k)
        if os.path.isfile(p):
            return p, "default SSH key"
    return None, "no SSH key on this machine (create one)"


def public_key(path: str) -> str:
    pub = Path(path + ".pub")
    if pub.is_file():
        return pub.read_text().strip()
    r = subprocess.run(["ssh-keygen", "-y", "-f", path], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise AccessError(f"cannot read the public half of {path} (passphrase-protected? {r.stderr.strip()[:120]})")
    return r.stdout.strip()


def hosts(inv) -> list:
    return [*inv.switches, *inv.computes]


def _via_exec(inv) -> bool:
    return ((inv.transport or {}).get("jump") or {}).get("via") == "exec"


def describe(inv) -> dict:
    out, keys = [], {}
    via = _via_exec(inv)
    for h in hosts(inv):
        local = is_local(h)
        path, src = ((None, "this machine (read directly)") if local else
                     (None, "the jump host's own SSH setup (transport.jump via: exec) - no key needed on this machine")
                     if via else node_key(h))
        if path and path not in keys:
            try:
                keys[path] = {"path": path, "public": public_key(path)}
            except AccessError as e:
                keys[path] = {"path": path, "error": str(e)}
        out.append({"name": h.name, "role": h.role, "user": h.user, "host": h.host, "local": local, "key": path,
                    "key_from": src, "password_env": bool(h.password)})
    return {"hosts": out, "keys": list(keys.values()),
            "can_create": not via and any(not x["local"] and not x["key"] for x in out)
                          and not os.path.isfile(os.path.expanduser(NEW_KEY)),
            "via_jump_exec": via}


def _transport(inv, h, password: str | None):
    hh = dataclasses.replace(h, password=password) if password is not None else dataclasses.replace(h, password=None)
    return SshTransport(hh, connect_timeout=float(inv.transport.get("connect_timeout", 15)), jump=inv.transport.get("jump"))


def check_one(inv, h) -> dict:
    """Key-only login (no password, whatever the inventory says) and sudo without a prompt."""
    if is_local(h):
        return {"name": h.name, "login": "local", "sudo": None, "detail": "this machine: read directly"}
    t = _transport(inv, h, None)
    try:
        r = t.run("sudo -n true && echo SUDO_OK || echo SUDO_NO", timeout=30)
        sudo = "SUDO_OK" in r.stdout
        return {"name": h.name, "login": "ok", "sudo": sudo,
                "detail": "key login and sudo ok" if sudo else "key login ok, but sudo asks for a password (needs NOPASSWD)"}
    except Exception as e:  # noqa: BLE001 - reported per node
        return {"name": h.name, "login": "failed", "sudo": None, "detail": f"{type(e).__name__}: {str(e)[:200]}"}
    finally:
        t.close()


def check(inv, names: list[str] | None = None) -> list[dict]:
    sel = [h for h in hosts(inv) if not names or h.name in names]
    return [v if v else {"name": h.name, "login": "failed", "detail": f"{type(e).__name__}: {e}"}
            for h, v, e in fan_out(lambda h: check_one(inv, h), sel)]


def install(inv, name: str, password: str) -> dict:
    """Log in once with ``password`` and add this node's key to ~/.ssh/authorized_keys (no duplicate), then check a
    key-only login. The password is not kept."""
    h = next((x for x in hosts(inv) if x.name == name), None)
    if h is None:
        raise AccessError(f"no node {name} in this inventory")
    if is_local(h):
        raise AccessError(f"{name} is this machine - nothing to install")
    if not password:
        raise AccessError("type the node's password to install the key")
    if _via_exec(inv):
        raise AccessError(f"{name} is reached through the jump host's own SSH setup (transport.jump via: exec): install "
                          "the key there (on the jump host: ssh-copy-id <user>@<node>), not from this machine")
    path, src = node_key(h)
    if not path:
        raise AccessError(src)
    pub = public_key(path)
    q = shlex.quote(pub)
    cmd = ("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh && "
           f"chmod 600 ~/.ssh/authorized_keys && (grep -qxF {q} ~/.ssh/authorized_keys && echo ALREADY || "
           f"(echo {q} >> ~/.ssh/authorized_keys && echo ADDED))")
    t = _transport(inv, h, password)
    password = None
    try:
        r = t.run(cmd, timeout=30)
    except Exception as e:  # noqa: BLE001
        msg = str(e)[:200]
        raise AccessError(f"{name}: login with the password failed ({type(e).__name__}: {msg})") from None
    finally:
        t.close()
    if r.rc != 0 or not ({"ADDED", "ALREADY"} & set(r.stdout.split())):
        raise AccessError(f"{name}: could not write ~/.ssh/authorized_keys (rc {r.rc}): {(r.stdout + r.stderr).strip()[:200]}")
    done = "already there" if "ALREADY" in r.stdout else "added"
    after = check_one(inv, h)
    return {"name": name, "key": path, "key_from": src, "result": done, "check": after}


def create_key() -> dict:
    """Create ~/.ssh/id_ed25519 (no passphrase) when this machine has no SSH key at all. Never overwrites."""
    p = os.path.expanduser(NEW_KEY)
    if os.path.exists(p):
        raise AccessError(f"{p} already exists - not overwritten")
    Path(p).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"helios-debug@{os.uname().nodename}",
                        "-f", p], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise AccessError(f"ssh-keygen failed: {r.stderr.strip()[:200]}")
    return {"path": p, "public": public_key(p)}
