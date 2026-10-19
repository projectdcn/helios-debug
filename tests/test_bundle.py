"""Evidence bundle (heliosdbg/bundle.py) and its UI endpoint."""
from __future__ import annotations

import gzip
import io
import json
import zipfile

from heliosdbg import bundle


def _run(tmp_path):
    run = tmp_path / "results" / "link-check" / "lab" / "link-20261019-060000"
    (run / "raw").mkdir(parents=True)
    (run / "report.txt").write_text("DOWN  st1 asic1 Ethernet292 <-> c2 0003:01:00.1 port 12\ncause: no physical link\n")
    (run / "link.json").write_text(json.dumps({"link": {"switch": "st1", "sw_port": "Ethernet292", "state": "down",
                                                         "cause": "no physical link", "owner": "site (cabling)"}}))
    (run / "raw" / "commands.log.gz").write_bytes(gzip.compress(b"$ login password: hunter2\nok\n"))
    (run / "report.html").write_text("<html>token=abc123</html>")
    return run


def test_bundle_redacts_and_has_a_ticket(tmp_path):
    data, stats = bundle.build(_run(tmp_path))
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "link-20261019-060000/ticket.txt" in names and "link-20261019-060000/raw/commands.log.gz" in names
    assert stats["redacted"] == 2
    log = gzip.decompress(z.read("link-20261019-060000/raw/commands.log.gz")).decode()
    assert "hunter2" not in log and "<REDACTED>" in log and "abc123" not in z.read("link-20261019-060000/report.html").decode()
    t = z.read("link-20261019-060000/ticket.txt").decode()
    assert "Ethernet292" in t and "Owner: site (cabling)" in t


def test_bundle_endpoint(tmp_path):
    import threading
    import urllib.request
    from ui import server
    _run(tmp_path)
    (tmp_path / "inv").mkdir()
    srv = server.make_server(0, tmp_path / "inv", tmp_path / "results")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    r = urllib.request.urlopen(base + "/api/bundle?path=link-check/lab/link-20261019-060000", timeout=10)
    assert r.headers["Content-Type"] == "application/zip" and zipfile.ZipFile(io.BytesIO(r.read())).testzip() is None
    try:
        urllib.request.urlopen(base + "/api/bundle?path=../../", timeout=10)
        raise AssertionError("traversal not refused")
    except urllib.error.HTTPError as e:
        assert e.code == 400
    srv.shutdown()
