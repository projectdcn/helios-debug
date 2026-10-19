"""helios-debug web UI (ui/server.py): request checks, the localhost / header guards, result files, one job end to end."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ui import server

INV = """rack: lab
transport: {kind: ssh}
defaults: {switch: {user: admin}, compute: {user: u}}
switches:
  - {name: st1, host: 10.0.0.1}
computes:
  - {name: c1, host: 10.0.0.2}
  - {name: c2, host: 10.0.0.3}
afm:
  url: https://10.0.0.1
  auth: {username: admin, password_env: LAB_AFM_PW}
"""

FAKE_TOOL = """import os, sys, pathlib
a = sys.argv[1:]
out = pathlib.Path(a[a.index('--out') + 1]); out.mkdir(parents=True, exist_ok=True)
(out / 'report.txt').write_text('Scale-up link scan\\n4 GPU links: 4 ok, 0 degraded, 0 down\\n')
(out / 'report.html').write_text('<html>ok</html>')
(out / 'link_check.json').write_text('{}')
print('args', ' '.join(a)); print('afm env set:', bool(os.environ.get('LAB_AFM_PW')))
sys.exit(0)
"""


@pytest.fixture
def ui(tmp_path, monkeypatch):
    (tmp_path / "inv").mkdir()
    (tmp_path / "inv" / "lab.local.yaml").write_text(INV)
    tool = tmp_path / "fake_tool.py"
    tool.write_text(FAKE_TOOL)
    monkeypatch.setattr(server, "TOOL", tool)
    srv = server.make_server(0, tmp_path / "inv", tmp_path / "results")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()


def call(base, path, body=None, headers=None):
    h = {"Content-Type": "application/json", "X-Helios-Debug": "1"} if body is not None else {}
    h.update(headers or {})
    r = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=h,
                               method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_state_lists_the_inventory(ui):
    base, _ = ui
    code, body = call(base, "/api/state")
    inv = json.loads(body)["inventories"][0]
    assert code == 200 and inv["rack"] == "lab" and inv["computes"] == ["c1", "c2"] and inv["afm"] is True


def test_post_needs_the_header_and_json(ui):
    base, _ = ui
    r = urllib.request.Request(base + "/api/run", data=b"tool=scan", method="POST",
                               headers={"Content-Type": "text/plain"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(r, timeout=10)
    assert e.value.code == 403


def test_foreign_host_header_refused(ui):
    base, _ = ui
    code, _ = call(base, "/api/state", headers={"Host": "evil.example:8780"})
    assert code == 403


@pytest.mark.parametrize("req,msg", [
    ({"tool": "rm"}, "tool must be"),
    ({"tool": "scan", "inventory": "../etc.yaml"}, "unknown inventory"),
    ({"tool": "scan", "inventory": "lab.local.yaml", "trays": ["c9"]}, "unknown compute tray"),
    ({"tool": "bcm", "inventory": "lab.local.yaml", "ports": "Ethernet1;reboot"}, "ports:"),
    ({"tool": "path", "inventory": "lab.local.yaml", "src": "c1", "src_bdf": "x"}, "BDF"),
    ({"tool": "path", "inventory": "lab.local.yaml", "src": "c1", "src_bdf": "0001:01:00.1"}, "destination GPU"),
    ({"tool": "pingmap", "inventory": "lab.local.yaml", "rounds": 1000}, "rounds must be"),
])
def test_bad_requests_refused(ui, req, msg):
    base, _ = ui
    code, body = call(base, "/api/run", req)
    assert code == 400 and msg in json.loads(body)["error"]


def test_result_paths_stay_inside_results(ui):
    base, tmp = ui
    (tmp / "secret.txt").write_text("x")
    code, _ = call(base, "/results/../secret.txt")
    assert code in (400, 404)
    code, _ = call(base, "/results/%2e%2e/secret.txt")
    assert code == 400


def test_scan_job_end_to_end_password_only_in_the_child_env(ui):
    base, tmp = ui
    code, body = call(base, "/api/run", {"tool": "scan", "inventory": "lab.local.yaml", "trays": ["c2"], "interval": 5,
                                         "afm": True, "afm_password": "pw-not-logged"})
    job = json.loads(body)
    assert code == 200 and job["status"] == "running" and "pw-not-logged" not in json.dumps(job)
    assert job["argv"][:1] == ["scan"] and "--trays" in job["argv"] and "--no-afm" not in job["argv"]
    for _ in range(100):
        j = json.loads(call(base, f"/api/job/{job['id']}")[1])
        if j["status"] != "running":
            break
        time.sleep(0.1)
    assert j["status"] == "ok" and "afm env set: True" in j["log"] and "pw-not-logged" not in j["log"]
    log = (tmp / "results" / "ui-jobs" / f"{job['id']}.log").read_text()
    assert "pw-not-logged" not in log
    res = json.loads(call(base, "/api/results")[1])["results"]
    assert res and res[0]["tool"] == "scan" and "report.html" in res[0]["files"] and "4 GPU links" in res[0]["summary"]
    code, html = call(base, f"/results/{res[0]['path']}/report.html")
    assert code == 200 and html == b"<html>ok</html>"


def test_one_run_at_a_time(ui, monkeypatch, tmp_path):
    base, tmp = ui
    slow = tmp / "slow.py"
    slow.write_text("import time; time.sleep(5)")
    monkeypatch.setattr(server, "TOOL", slow)
    j = json.loads(call(base, "/api/run", {"tool": "pingmap", "inventory": "lab.local.yaml"})[1])
    code, body = call(base, "/api/run", {"tool": "scan", "inventory": "lab.local.yaml"})
    assert code == 400 and "already running" in json.loads(body)["error"]
    st = json.loads(call(base, f"/api/job/{j['id']}/stop", {})[1])
    assert st["status"] == "stopped"


def test_binding_other_than_localhost_refused(tmp_path):
    with pytest.raises(SystemExit):
        server.make_server(0, tmp_path, tmp_path, bind="0.0.0.0")


def test_local_transport_for_this_machine(monkeypatch):
    from heliosdbg import transport
    from heliosdbg.inventory import Host
    h = Host(name="st1", host="127.0.0.1", role="switch")
    monkeypatch.delenv("HELIOS_DEBUG_AUTO_LOCAL", raising=False)
    assert not transport.is_local(h)
    monkeypatch.setenv("HELIOS_DEBUG_AUTO_LOCAL", "1")
    assert isinstance(transport.make_transport(h, {"kind": "ssh"}), transport.LocalTransport)
    assert transport.is_local(Host(name="x", host="10.9.9.9", role="switch", extra={"local": True}))
