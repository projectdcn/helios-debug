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


def test_link_tool_args_and_target_check(ui):
    base, _ = ui
    st = server.Handler.state
    a, out, rack = server.build_args(st, {"tool": "link", "inventory": "lab.local.yaml", "target": "st1  Ethernet33",
                                          "interval": 5})
    assert a[:2] == ["link", "st1 Ethernet33"] and "--no-afm" in a and out.name.startswith("link-")
    code, body = call(base, "/api/run", {"tool": "link", "inventory": "lab.local.yaml", "target": "st1 Ethernet33; reboot"})
    assert code == 400 and "link:" in json.loads(body)["error"]


def test_scan_view_for_the_rack_map(ui):
    base, tmp = ui
    d = tmp / "results" / "link-check" / "lab" / "scan-20261019-000000"
    d.mkdir(parents=True)
    (d / "link_check.json").write_text(json.dumps({"time_utc": "x", "rack": "lab", "learned": {"slots": {"c1": 0}},
        "gpus": [{"tray": "c1", "bdf": "0001:01:00.1", "phase": "PROVIDER"}],
        "links": [{"switch": "st1", "asic": "asic0", "sw_port": "Ethernet0", "tray": "c1", "bdf": "0001:01:00.1",
                   "gpu_port": 0, "state": "down", "kind": "phys_went_down", "cause": "c", "evidence": list("abcdefghij"),
                   "gpu": {"big": "x" * 1000}}]}))
    code, body = call(base, "/api/scan?path=link-check/lab/scan-20261019-000000")
    v = json.loads(body)
    assert code == 200 and v["links"][0]["state"] == "down" and len(v["links"][0]["evidence"]) == 8 and "gpu" not in v["links"][0]
    assert v["gpus"][0]["phase"] == "PROVIDER" and v["slots"] == {"c1": 0}
    assert call(base, "/api/scan?path=../../etc")[0] == 400


def test_overview_counts_the_latest_scan(ui):
    base, tmp = ui
    for stamp, states in (("20261018-000000", ["ok", "ok"]), ("20261019-000000", ["ok", "down"])):
        d = tmp / "results" / "link-check" / "lab" / f"scan-{stamp}"
        d.mkdir(parents=True)
        (d / "link_check.json").write_text(json.dumps({"time_utc": stamp, "links": [{"state": x} for x in states],
                                                       "gpus": [{"tray": "c1"}]}))
    r = json.loads(call(base, "/api/overview")[1])["racks"][0]
    assert (r["rack"], r["scans"], r["ok"], r["down"], r["gpus_not_right"]) == ("lab", 2, 1, 1, 1)
    assert r["latest"].endswith("scan-20261019-000000")


def test_page_script_parses(tmp_path):
    """The page's script must parse (19 Oct: one broken quote stopped the whole UI; caught only in a browser)."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    html = (server.STATIC / "index.html").read_text()
    js = html[html.index("<script>") + 8:html.rindex("</script>")]
    f = tmp_path / "ui.js"
    f.write_text(js)
    r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_page_is_the_one_the_server_started_with(ui, monkeypatch):
    base, _ = ui
    first = call(base, "/")[1]
    monkeypatch.setattr(server, "STATIC", server.STATIC.parent / "nowhere")   # a newer page on disk is not served
    assert call(base, "/")[1] == first and b"Diagnose a link" in first


def test_gpus_view_for_the_path_pickers(ui):
    import gzip
    base, tmp = ui
    d = tmp / "results" / "link-check" / "lab" / "scan-20261019-000000"
    (d / "raw").mkdir(parents=True)
    (d / "link_check.json").write_text(json.dumps({"time_utc": "20261019-000000", "learned": {"slots": {"c1": 0}}, "links": []}))
    with gzip.open(d / "raw" / "trays.json.gz", "wt") as fh:
        json.dump({"c1": {"gpus": [{"bdf": "0001:01:00.1", "accelerator": "3", "config_phase": "ACTIVE", "ports": [
            {"port": 0, "link": "LINK_UP", "admin": "enabled"}, {"port": 1, "link": "LINK_DOWN", "admin": "enabled"},
            {"port": 2, "link": "LINK_UP", "admin": "idle"}]}]}, "c2": {"gpus": [], "error": "AuthenticationException"}}, fh)
    v = json.loads(call(base, "/api/gpus?inventory=lab.local.yaml")[1])
    assert v["trays"]["c1"]["slot"] == 0 and v["trays"]["c1"]["gpus"][0]["up"] == [0] and v["trays"]["c2"]["error"]
