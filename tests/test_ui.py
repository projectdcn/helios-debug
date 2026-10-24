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
    assert v["switch_ids"] == {"st1": 0}             # AFM numbers switch trays from 0: st1 = pod-1-0-SwitchTray
    assert v["gpu_map"] == {} and v["gpu_acc"] == {}  # no raw tray read in this scan
    assert call(base, "/api/scan?path=../../etc")[0] == 400


def test_afm_switch_ids(tmp_path):
    """st<n> = AFM n-1 unless the inventory says otherwise (slot: or afm_name: pod-1-<id>-SwitchTray)."""
    (tmp_path / "r.yaml").write_text("rack: r\nswitches:\n  - {name: st1, host: a}\n  - {name: st2, host: b, slot: 5}\n"
                                     "  - {name: sw-x, host: c, afm_name: pod-1-3-SwitchTray}\n  - {name: spare, host: d}\n"
                                     "computes:\n  - {name: c1, host: e}\n")
    st = server.State(tmp_path, tmp_path)
    assert server.afm_switch_ids(st, "r") == {"st1": 0, "st2": 5, "sw-x": 3, "spare": 3}
    assert server.afm_switch_ids(st, "nope") == {}


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


def test_guide_and_topology_pages_served(ui):
    base, _ = ui
    for path, words in (("/guide", b"Debug Guide"), ("/topology", b"Scale-up")):
        r = urllib.request.urlopen(base + path, timeout=10)
        body = r.read()
        assert r.status == 200 and words in body and "frame-ancestors" in r.headers["Content-Security-Policy"]
        assert "frame-ancestors 'self'" in r.headers["Content-Security-Policy"]     # shown inside the UI's tabs only
    page = call(base, "/")[1]
    assert b'data-t="topology"' in page and b'data-t="guide"' in page and b'target="_blank" rel="noopener">Debug guide' not in page and b'target="_blank" rel="noopener" title="How the GPUs' not in page


def test_port_view_both_ends_and_history(ui):
    import gzip
    base, tmp = ui
    rack = tmp / "results" / "link-check" / "lab"
    for stamp, state in (("20261018-000000", "ok"), ("20261019-000000", "down")):
        d = rack / f"scan-{stamp}"
        (d / "raw").mkdir(parents=True)
        (d / "link_check.json").write_text(json.dumps({"time_utc": stamp, "links": [
            {"switch": "st1", "asic": "asic1", "sw_port": "Ethernet292", "tray": "c2", "bdf": "0003:01:00.1", "gpu_port": 12,
             "state": state, "kind": "" if state == "ok" else "phys_went_down"}]}))
        with gzip.open(d / "raw" / "switches.json.gz", "wt") as fh:
            json.dump({"st1": {"asics": {"asic1": {"status": {"Ethernet292": {"Oper": state if state != "ok" else "up"}},
                                                  "counters": {}, "fec": {}, "presence": {"Ethernet292": "Not present"},
                                                  "fdb": [{"Port": "Ethernet292", "MacAddress": "02:00"}]}}}}, fh)
        with gzip.open(d / "raw" / "trays.json.gz", "wt") as fh:
            json.dump({"c2": {"gpus": [{"bdf": "0003:01:00.1", "accelerator": "5", "config_phase": "ACTIVE",
                                        "ports": [{"port": 12, "link": "LINK_DOWN", "ifcp": {"ll_up": "no"}}]}]}}, fh)
    v = json.loads(call(base, "/api/port?path=link-check/lab/scan-20261019-000000&key=st1%20Ethernet292")[1])
    assert v["switch"]["status"]["Oper"] == "down" and v["switch"]["fdb"] and v["gpu"]["link"] == "LINK_DOWN"
    assert v["gpu_device"]["accelerator"] == "5" and [h["state"] for h in v["history"]] == ["down", "ok"]
    assert call(base, "/api/port?path=link-check/lab/scan-20261019-000000&key=st1%20Ethernet9")[0] == 400


def test_quarantined_tray_named_on_the_map():
    """g02-g17 19 Oct: ct05's 144 links had no tray name and the rack map showed them under '?'."""
    from ui.server import name_unread_trays
    links = [{"tray": None, "desc": "To ComputeTray Slot4/GPU3[19]/Port35", "cause": "compute tray ct05 is quarantined in the inventory (Down)"},
             {"tray": None, "desc": "To ComputeTray Slot1/GPU0[4]/Port2", "cause": ""},
             {"tray": "ct01", "desc": "To ComputeTray Slot0/GPU0[0]/Port1"},
             {"tray": None, "desc": "", "cause": ""}]
    slots = {"ct01": 0, "ct02": 1}
    name_unread_trays(links, slots)
    assert [x["tray"] for x in links] == ["ct05", "ct02", "ct01", None]
    assert slots["ct05"] == 4


def test_afm_names_and_ifcp_cabling(tmp_path):
    """Trays named as AFM shows them (inventory afm_name wins, else pod-<n>-<id>-<kind>); a cable is confirmed when
    the GPU port's IFCP peer is the link's switch port, miscabled when it is another one."""
    (tmp_path / "r.yaml").write_text("rack: r\nswitches:\n  - {name: st1, host: a}\n  - {name: st2, host: b}\n"
                                     "computes:\n  - {name: ct01, host: c, afm_name: pod-2-0-ComputeTray}\n"
                                     "  - {name: ct02, host: d}\n")
    st = server.State(tmp_path, tmp_path)
    ids = server.afm_switch_ids(st, "r")
    assert server.afm_names(st, "r", {"ct01": 0, "ct02": 1}, ids) == {
        "st1": "pod-2-0-SwitchTray", "st2": "pod-2-1-SwitchTray", "ct01": "pod-2-0-ComputeTray", "ct02": "pod-2-1-ComputeTray"}
    trays = {"ct01": {"gpus": [{"bdf": "0004:01:00.1", "ports": [
        {"port": 31, "ifcp": {"peer_device_id": "1", "peer_port_id": "164", "ll_up": "yes", "in_error": "no"}},
        {"port": 33, "ifcp": {"peer_device_id": "2", "peer_port_id": "8"}},
        {"port": 35, "ifcp": {}}]}]}}
    links = [{"switch": "st1", "sw_port": "Ethernet164", "tray": "ct01", "bdf": "0004:01:00.1", "gpu_port": 31},
             {"switch": "st1", "sw_port": "Ethernet172", "tray": "ct01", "bdf": "0004:01:00.1", "gpu_port": 33},
             {"switch": "st1", "sw_port": "Ethernet180", "tray": "ct01", "bdf": "0004:01:00.1", "gpu_port": 35}]
    n = server.ifcp_cabling(links, trays, {"device": {"st1": "1", "st2": "2"}, "port_is_ethernet": True})
    assert (n["confirmed"], n["miscabled"], n["unconfirmed"]) == (1, 1, 1)
    assert links[0]["cable"] == "confirmed" and links[1]["cable"] == "miscabled: the cable reaches st2 Ethernet8"
    assert "cable" not in links[2]
    assert links[0]["ifcp"] == {"ll": "yes", "pe": None, "err": False} and "ifcp" not in links[2]   # Topology IFCP view; no IFCP data = none
    assert server.ifcp_cabling(links[:1], trays, {})["unconfirmed"] == 1     # IFCP naming not learned: no verdict


def test_live_start_duration_choices(ui, monkeypatch):
    """max_h 0 = until turned off, keep_unwatched = no idle stop; out-of-range refused."""
    base, tmp = ui
    seen = {}

    class FakeLive:
        def __init__(self, *a, **k):
            seen.update(k)

        def start(self):
            pass

        def stop(self, reason=""):
            pass
    import heliosdbg.live
    monkeypatch.setattr(heliosdbg.live, "LiveRack", FakeLive)
    d = tmp / "results" / "link-check" / "lab" / "scan-20261019-000000"
    d.mkdir(parents=True)
    (d / "link_check.json").write_text(json.dumps({"links": [{"switch": "st1", "sw_port": "Ethernet0"}]}))
    assert call(base, "/api/live/start", {"inventory": "lab.local.yaml", "max_h": 0, "keep_unwatched": True})[0] == 200
    assert seen["max_s"] is None and seen["idle_s"] is None
    assert call(base, "/api/live/start", {"inventory": "lab.local.yaml", "max_h": 24})[0] == 200
    assert seen["max_s"] == 24 * 3600 and seen["idle_s"] == 1800
    assert call(base, "/api/live/start", {"inventory": "lab.local.yaml", "max_h": 999})[0] == 400


def test_topology_uses_the_latest_full_check(tmp_path):
    """A newer one-switch / empty check does not replace the picture; it is reported with its switch problem."""
    import json as _j
    base = tmp_path / "link-check" / "r"
    for name, body in (("scan-20261019-000000", {"time_utc": "20261019-000000", "links": [{"switch": "st1"}], "scope": {}}),
                       ("scan-20261024-055727", {"time_utc": "20261024-055727", "links": [], "scope": {"switches": "st1"},
                                                 "fdb_broken": [{"switch": "st1", "mac": "00:11:22:33:44:55"}]})):
        (base / name).mkdir(parents=True)
        (base / name / "link_check.json").write_text(_j.dumps(body))
    runs = sorted(base.glob("scan-*/link_check.json"), reverse=True)
    v = server.latest_full("r", runs)
    assert v["latest_full"] == "link-check/r/scan-20261019-000000"
    assert v["newer_partial"]["only"] == "st1" and v["newer_partial"]["links"] == 0
    assert v["newer_partial"]["fdb_broken"][0]["mac"] == "00:11:22:33:44:55"
    assert "newer_partial" not in server.latest_full("r", runs[1:])     # the full one is the newest: nothing to say


def test_terminal_local_shell_and_config_route(ui, monkeypatch):
    """A terminal on a node marked local runs a shell under a pseudo-terminal: what is written comes back, resize
    works, close ends it; unknown nodes / sessions are refused. The vendored terminal emulator is served."""
    import base64
    base, tmp = ui
    (tmp / "inv" / "loc.local.yaml").write_text("rack: loc\nswitches:\n  - {name: st1, host: 127.0.0.1, local: true}\n"
                                               "computes:\n  - {name: c1, host: 10.0.0.9}\n")
    monkeypatch.setenv("SHELL", "/bin/sh")
    code, body = call(base, "/api/term/open", {"inventory": "loc.local.yaml", "node": "st1", "cols": 80, "rows": 24})
    assert code == 200, body
    sid = json.loads(body)["id"]
    assert call(base, "/api/term/write", {"id": sid, "data": "echo hd-$((40+2))\n"})[0] == 200
    out, nxt = b"", 0
    for _ in range(10):
        r = json.loads(call(base, f"/api/term/read?id={sid}&since={nxt}")[1])
        out += base64.b64decode(r["data"])
        nxt = r["next"]
        if b"hd-42" in out:
            break
    assert b"hd-42" in out
    assert call(base, "/api/term/resize", {"id": sid, "cols": 100, "rows": 30})[0] == 200
    assert call(base, "/api/term/close", {"id": sid})[0] == 200
    assert call(base, f"/api/term/read?id={sid}&since=0")[0] == 400
    assert call(base, "/api/term/open", {"inventory": "loc.local.yaml", "node": "nope"})[0] == 400
    assert call(base, "/api/term/write", {"id": sid}, headers={"X-Helios-Debug": "0"})[0] == 403
    log = (tmp / "results" / "term" / "sessions.log").read_text()
    assert "open st1" in log and "close" in log and "hd-" not in log          # what is typed is never logged
    assert call(base, "/static/vendor/xterm/xterm.js")[0] == 200
    assert call(base, "/static/vendor/../server.py")[0] == 404


def test_ai_status_and_ask_with_a_stand_in_model(ui, monkeypatch):
    """The AI reads the saved check, numbers the evidence, calls the OpenAI-compatible server, flags a step that
    changes the rack, and checks citations; no model = a clear message; bad paths refused."""
    import threading as _t
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    base, tmp = ui
    seen, replies = [], []

    class M(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b'{"data": [{"id": "stand-in"}]}')

        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200); self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": replies.pop(0)}}]}).encode())

        def log_message(self, *a):
            pass
    m = ThreadingHTTPServer(("127.0.0.1", 0), M)
    _t.Thread(target=m.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("HELIOS_AI_URL", f"http://127.0.0.1:{m.server_address[1]}/v1")
        st = json.loads(call(base, "/api/ai/status")[1])
        assert st["reachable"] and st["model"] == "stand-in"
        d = tmp / "results" / "link-check" / "lab" / "scan-20261024-000000"
        d.mkdir(parents=True)
        (d / "link_check.json").write_text(json.dumps({"time_utc": "20261024-000000", "rack": "lab", "learned": {"slots": {"c1": 0}},
            "links": [{"switch": "st1", "asic": "asic0", "sw_port": "Ethernet8", "tray": "c1", "bdf": "0004:01:00.1", "gpu_port": 31,
                       "state": "degraded", "kind": "ifcp_down", "cause": "no IFCP session", "evidence": ["ll_up no"]}],
            "fdb_broken": [{"switch": "st1", "ns": "asic0", "mac": "00:11:22:33:44:55", "vlan": "100", "port": "Ethernet8",
                            "source": "APPL_DB FDB_TABLE - added at runtime"}]}))
        replies.append("### Root cause\nThe test entry [E5] breaks show mac [E9]. Reboot the switch.")
        code, body = call(base, "/api/ai/ask", {"path": "link-check/lab/scan-20261024-000000", "link": "st1 Ethernet8"})
        a = json.loads(body)
        assert code == 200 and a["model"] == "stand-in" and a["unsafe"].lower().startswith("reboot")
        user = seen[-1]["messages"][1]["content"]
        assert "[E1]" in user and "00:11:22:33:44:55" in user and "no IFCP session" in user
        assert "E9" in a["unknown_citations"] or "E9" in a["cited"]
        replies.append("Do not reboot it; check `show mac` [E1].")
        a = json.loads(call(base, "/api/ai/ask", {"path": "link-check/lab/scan-20261024-000000"})[1])
        assert a["unsafe"] is None and a["subject"] == "this check of the rack"
        assert call(base, "/api/ai/ask", {"path": "../etc"})[0] == 400
        monkeypatch.setenv("HELIOS_AI_URL", "off")
        assert "turned off" in json.loads(call(base, "/api/ai/ask", {"path": "link-check/lab/scan-20261024-000000"})[1])["error"]
    finally:
        m.shutdown()


def test_review_fixes_cable_unknown_device_truncated_raw_and_latest_full(ui, tmp_path):
    """IFCP peer on a device the check could not name = unconfirmed (not miscabled); a truncated raw gzip does not
    break the scan view; an old unscoped check that read few trays is partial; the newer note keeps the role."""
    import gzip as _gz
    import json as _j
    base, tmp = ui
    trays = {"c1": {"gpus": [{"bdf": "b", "ports": [{"port": 1, "ifcp": {"peer_device_id": "9", "peer_port_id": "4"}},
                                                     {"port": 2, "ifcp": {"peer_device_id": "1", "peer_port_id": None}}]}]}}
    links = [{"switch": "st1", "sw_port": "Ethernet4", "tray": "c1", "bdf": "b", "gpu_port": 1},
             {"switch": "st1", "sw_port": "Ethernet5", "tray": "c1", "bdf": "b", "gpu_port": 2}]
    n = server.ifcp_cabling(links, trays, {"device": {"st1": "1"}, "port_is_ethernet": True})
    assert (n["confirmed"], n["miscabled"], n["unconfirmed"]) == (0, 0, 2)
    d = tmp / "results" / "link-check" / "lab" / "scan-20261024-000000"
    (d / "raw").mkdir(parents=True)
    (d / "link_check.json").write_text(_j.dumps({"time_utc": "x", "rack": "lab", "links": [{"switch": "st1", "sw_port": "E1"}]}))
    (d / "raw" / "trays.json.gz").write_bytes(_gz.compress(b'{"c1": {"gpus": []}}')[:12])     # truncated
    code, body = call(base, "/api/scan?path=link-check/lab/scan-20261024-000000")
    assert code == 200 and _j.loads(body)["links"]
    r = tmp_path / "lc" / "r"
    for name, body in (("scan-20261018-000000", {"links": [{"tray": f"c{i}"} for i in range(18)]}),
                       ("scan-20261019-000000", {"links": [{"tray": "c1"}]}),
                       ("scan-20261024-000000", {"links": [], "scope": {"switches": "st1"},
                                                 "not_checked": [{"node": "ct06", "role": "tray", "error": "x"}]})):
        (r / name).mkdir(parents=True)
        (r / name / "link_check.json").write_text(_j.dumps(body))
    v = server.latest_full("r", sorted(r.glob("scan-*/link_check.json"), reverse=True), computes=18)
    assert v["latest_full"].endswith("scan-20261018-000000")            # the one-tray old scan is partial
    assert v["newer_partial"]["not_checked"][0]["role"] == "tray"
