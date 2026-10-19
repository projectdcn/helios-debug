"""SSH access from the UI (ui/access.py): the key each node uses, key-only check, installing the key with a password."""
from __future__ import annotations

import json
import subprocess

import pytest

from heliosdbg.inventory import load_inventory
from heliosdbg.transport import CmdResult
from ui import access

INV = """rack: lab
transport: {kind: ssh}
defaults: {switch: {user: admin}, compute: {user: u}}
switches:
  - {name: st1, host: 10.0.0.1}
computes:
  - {name: c1, host: 10.0.0.2}
"""


@pytest.fixture
def key(tmp_path, monkeypatch):
    k = tmp_path / "id_test"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
    monkeypatch.setenv("HELIOS_SSH_KEY", str(k))
    monkeypatch.delenv("HELIOS_DEBUG_AUTO_LOCAL", raising=False)
    return k


@pytest.fixture
def inv(tmp_path):
    f = tmp_path / "lab.local.yaml"
    f.write_text(INV)
    return load_inventory(f)


class FakeSsh:
    """Records what would run; key login works only after the key was 'installed' with the right password."""
    installed: set = set()
    seen: list = []

    def __init__(self, host, connect_timeout=15, jump=None):
        self.h = host

    def run(self, cmd, timeout=120, sudo=False, env=None):
        FakeSsh.seen.append((self.h.name, self.h.password is not None, cmd))
        if self.h.password is not None:
            if self.h.password != "right":
                raise RuntimeError("AuthenticationException: Authentication failed.")
            already = self.h.name in FakeSsh.installed
            FakeSsh.installed.add(self.h.name)
            return CmdResult(self.h.name, cmd, 0, "ALREADY\n" if already else "ADDED\n", "")
        if self.h.name not in FakeSsh.installed:
            raise RuntimeError("AuthenticationException: Authentication failed.")
        return CmdResult(self.h.name, cmd, 0, "SUDO_OK\n", "")

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_ssh(monkeypatch):
    FakeSsh.installed, FakeSsh.seen = set(), []
    monkeypatch.setattr(access, "SshTransport", FakeSsh)


def test_describe_uses_the_tools_key(key, inv):
    d = access.describe(inv)
    assert [h["key"] for h in d["hosts"]] == [str(key), str(key)]
    assert d["keys"][0]["public"].startswith("ssh-ed25519 ")


def test_check_then_install_then_check(key, inv):
    assert {r["name"]: r["login"] for r in access.check(inv)} == {"st1": "failed", "c1": "failed"}
    r = access.install(inv, "c1", "right")
    assert r["result"] == "added" and r["check"]["login"] == "ok" and r["check"]["sudo"] is True
    assert access.install(inv, "c1", "right")["result"] == "already there"
    pub = (key.parent / "id_test.pub").read_text().split()[1]
    cmds = [c for n, pw, c in FakeSsh.seen if pw]
    assert cmds and pub in cmds[0] and "right" not in " ".join(c for _n, _p, c in FakeSsh.seen)
    assert {r["name"]: r["login"] for r in access.check(inv)} == {"st1": "failed", "c1": "ok"}


def test_install_refusals(key, inv):
    with pytest.raises(access.AccessError, match="password"):
        access.install(inv, "c1", "")
    with pytest.raises(access.AccessError, match="login with the password failed"):
        access.install(inv, "c1", "wrong")
    with pytest.raises(access.AccessError, match="no node"):
        access.install(inv, "c9", "right")


def test_local_node_is_not_touched(key, inv, monkeypatch):
    monkeypatch.setenv("HELIOS_DEBUG_AUTO_LOCAL", "1")
    monkeypatch.setattr("heliosdbg.transport.local_addresses", lambda: {"10.0.0.1"})
    assert access.check(inv, ["st1"])[0]["login"] == "local"
    with pytest.raises(access.AccessError, match="this machine"):
        access.install(inv, "st1", "right")


def test_create_key_never_overwrites(tmp_path, monkeypatch):
    monkeypatch.setattr(access, "NEW_KEY", str(tmp_path / "ssh" / "id_ed25519"))
    k = access.create_key()
    assert k["public"].startswith("ssh-ed25519 ")
    with pytest.raises(access.AccessError, match="not overwritten"):
        access.create_key()


def test_api_install_password_not_echoed(key, tmp_path, monkeypatch):
    import threading
    import urllib.request
    from ui import server
    (tmp_path / "inv").mkdir()
    (tmp_path / "inv" / "lab.local.yaml").write_text(INV)
    srv = server.make_server(0, tmp_path / "inv", tmp_path / "res")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    r = urllib.request.Request(base + "/api/access/install", method="POST",
                               data=json.dumps({"inventory": "lab.local.yaml", "host": "c1", "password": "right"}).encode(),
                               headers={"Content-Type": "application/json", "X-Helios-Debug": "1"})
    body = urllib.request.urlopen(r, timeout=10).read().decode()
    srv.shutdown()
    assert '"result": "added"' in body and "right" not in body.replace('"login": "ok"', "")
