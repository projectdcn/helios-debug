"""history + incidents: what changed since the last health check (new / gone / grew), the run log and pruning; the
findings sent to the AIOps incident API with ids that stay the same from run to run."""
import http.server
import json
import threading

from heliosdbg import history, incidents


def f(node, check, what, sev="warning", area="os"):
    return {"node": node, "role": "compute", "check": check, "area": area, "severity": sev, "what": what,
            "cause": "c", "owner": "compute", "next": "n", "evidence": ["line 1"], "command": "cmd"}


def run(d, stamp, findings, unreachable=()):
    p = d / f"health-{stamp}"
    p.mkdir(parents=True)
    res = {"time": stamp, "findings": findings, "summary": {}, "unreachable": list(unreachable)}
    (p / "health.json").write_text(json.dumps(res))
    (p / "report.html").write_text("x")
    return p, res


def test_changes_new_gone_grew(tmp_path):
    run(tmp_path, "20261102-100000", [f("ct01", "disk", "/ is 86 % full"), f("ct02", "failed", "1 failed unit"),
                                      f("ct03", "kernel", "3 kernel error line(s)")])
    cur = {"time": "now", "unreachable": ["ct03"],
           "findings": [f("ct01", "disk", "/ is 91 % full"), f("ct04", "ecc", "GPU 2: 5 uncorrectable", "critical", "gpu")]}
    ch = history.compare(history.previous(tmp_path), cur)
    assert ch["since"] == "20261102-100000" and ch["same"] == 1
    assert [x["node"] for x in ch["new"]] == ["ct04"] and [x["node"] for x in ch["gone"]] == ["ct02"]   # ct03 not reached
    assert ch["grew"][0]["now"] == "/ is 91 % full"
    lines = history.text(ch)
    assert lines[0].startswith("== CHANGES since 20261102-100000 UTC: 1 new, 1 gone, 1 grew") and any("+ NEW critical" in x for x in lines)
    assert history.compare(None, cur)["since"] is None


def test_only_nodes_checked_both_times_are_compared(tmp_path):
    prev = {"time": "t0", "nodes": {"ct01": {}, "ct02": {}, "ct03": {}},
            "findings": [f("ct01", "disk", "a 1"), f("ct02", "failed", "b"), f("ct03", "kernel", "c")]}
    cur = {"time": "t1", "nodes": {"ct01": {}, "ct09": {}}, "findings": [f("ct01", "disk", "a 1"), f("ct09", "ecc", "d")]}
    ch = history.compare(prev, cur)
    assert ch["gone"] == [] and ch["new"] == [] and ch["same"] == 1 and ch["not_compared"] == 1


def test_rack_wide_grouping_does_not_hide_a_node():
    one = f("ct11", "rdma", "8 RDMA NIC port(s) down")
    prev = {"time": "t0", "nodes": {"ct11": {}}, "findings": [one], "node_findings": [one]}
    group = dict(one, node="10 of 17 trays", nodes=["ct10", "ct11"], what="on 10 of 17 trays (ct10, ct11): RDMA down")
    cur = {"time": "t1", "nodes": {"ct10": {}, "ct11": {}}, "findings": [group],
           "node_findings": [one, f("ct10", "rdma", "8 RDMA NIC port(s) down")]}
    ch = history.compare(prev, cur)
    assert ch["gone"] == [] and ch["new"] == [] and ch["same"] == 1 and ch["not_compared"] == 1


def test_rack_wide_keys_ignore_the_count():
    a = history.key(f("3 of 18 trays", "rdma", "on 3 of 18 trays (ct01, ct02, ct03): RDMA ports down"))
    b = history.key(f("4 of 18 trays", "rdma", "on 4 of 18 trays (ct01, ct02, ct03, ct04): RDMA ports down"))
    assert a.split("|")[0] == b.split("|")[0] == "# of # trays"


def test_record_and_prune(tmp_path):
    dirs = [run(tmp_path, f"20261102-1{i}0000", [])[0] for i in range(4)]
    history.record(tmp_path, {"time": "t", "summary": {"critical": 0}, "findings": [f("ct01", "disk", "x 1")],
                              "changes": {"new": [1], "gone": [], "grew": [], "same": 0, "since": "s"}}, dirs[-1])
    line = json.loads((tmp_path / history.HISTORY).read_text())
    assert line["changes"] == {"new": 1, "gone": 0, "grew": 0, "same": 0} and line["findings"] == ["ct01|disk|os|x #"]
    assert history.prune(tmp_path, 2) == [dirs[0].name, dirs[1].name]
    assert [p.name for p in dirs[0].iterdir()] == ["health.json"] and (dirs[3] / "report.html").exists()
    assert history.previous(tmp_path) is not None


class Api(http.server.BaseHTTPRequestHandler):
    got: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Api.got.append((self.path, body))
        if body["id"].endswith("bad"):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "nope"}')
            return
        out = {"id": body["id"], "explanation": {"area": "os", "summary": "disk filling"}, "checks": {"problems": []}}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(out).encode())

    def log_message(self, *a):
        pass


def test_incidents_ids_payload_and_send():
    fd = f("ct01", "disk", "/ is 91 % full")
    i1, i2 = incidents.to_incident(fd, "g02-g17", "t"), incidents.to_incident(f("ct01", "disk", "/ is 95 % full"), "g02-g17", "t")
    assert i1["id"] == i2["id"] and i1["id"].startswith("hd-g02-g17-")            # same finding: same incident
    assert i1["alerts"][0]["labels"] == {"node": "ct01", "check": "disk", "area": "os", "owner": "compute", "rack": "g02-g17"}
    assert i1["evidence"][0] == {"source": "ct01", "title": "cmd", "text": "line 1"}
    srv = http.server.HTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        res = incidents.send(url, [i1, dict(i1, id="x-bad")])
        assert Api.got[0][0] == incidents.PATH and res[0]["ok"] and res[0]["summary"] == "disk filling"
        assert not res[1]["ok"] and res[1]["error"].startswith("HTTP 400")
        assert not incidents.send("http://127.0.0.1:1", [i1], timeout=2)[0]["ok"]
    finally:
        srv.shutdown()


def test_pick_new_first_critical_first():
    a, b, c = f("ct01", "disk", "x"), f("ct02", "ecc", "y", "critical"), f("ct03", "failed", "z")
    res = {"findings": [a, b, c], "changes": {"since": "s", "new": [c, b]}}
    assert incidents.pick(res) == ([b, c], 0)
    assert incidents.pick(res, every=True, max_n=2) == ([b, a], 1)
    assert incidents.pick({"findings": [a], "changes": {"since": None}})[0] == [a]
