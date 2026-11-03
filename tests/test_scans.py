"""heliosdbg.scans: the newest check that read links, of the whole rack when asked."""
import json

from heliosdbg import scans


def put(d, name, links, scope=None):
    p = d / name
    p.mkdir(parents=True)
    (p / "link_check.json").write_text(json.dumps({"links": links, "scope": scope or {}}))


def test_newest_skips_empty_and_partial(tmp_path):
    put(tmp_path, "scan-20261019-000000", [{"switch": "st1"}])
    put(tmp_path, "scan-20261024-000000", [{"switch": "st3"}], {"trays": "ct13"})
    put(tmp_path, "scan-20261103-000000", [])
    assert scans.newest(tmp_path)[1].name == "scan-20261024-000000"
    assert scans.newest(tmp_path, full=True)[1].name == "scan-20261019-000000"
    assert scans.newest(tmp_path / "none") == (None, None)
