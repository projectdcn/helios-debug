"""A low disk where the checks write: the UI says so (/api/version 'disk') and starts no check below DISK_STOP_MB."""
import pytest

from ui import server


@pytest.fixture
def st(tmp_path):
    (tmp_path / "lab.local.yaml").write_text("rack: lab\nswitches:\n  - {name: st1, host: a}\ncomputes:\n  - {name: ct01, host: c}\n")
    return server.State(tmp_path, tmp_path / "results")


def test_a_check_does_not_start_on_a_full_disk(st, monkeypatch):
    monkeypatch.setattr(server.shutil, "disk_usage", lambda p: type("U", (), {"free": 20_000_000, "total": 4_900_000_000})())
    assert server.version_info(st)["disk"]["low"] is True
    with pytest.raises(server.BadRequest, match="only 20 MB free"):
        server.build_args(st, {"tool": "scan", "inventory": "lab.local.yaml"})


def test_enough_space_is_not_low(st):
    d = server.version_info(st)["disk"]
    assert d["free_mb"] > 0 and d["low"] is (d["free_mb"] < server.DISK_LOW_MB)
