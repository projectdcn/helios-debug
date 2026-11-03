"""New-rack discovery draft and saving (heliosdbg/discover.py, ui/server.py)."""
from __future__ import annotations

import pytest

from heliosdbg import discover
from heliosdbg.inventory import load_inventory
from ui import server

SW = {"address": "10.0.0.1", "hostname": "lab-sw", "asics": ["asic0", "asic1"], "slots": {0: 144, 1: 144},
      "gpus_per_slot": {0: 4, 1: 4}}


def test_draft_loads_and_has_no_password(tmp_path):
    text = discover.draft("lab", [SW], "admin", "hpeadmin1", "https://10.0.0.1",
                          {1: {"afm_name": "pod-1-1-ComputeTray", "ip": "10.0.0.9"}})
    f = tmp_path / "lab.local.yaml"
    f.write_text(text)
    inv = load_inventory(f)
    assert [h.host for h in inv.computes] == ["FILL-ME-slot0-address", "10.0.0.9"]
    assert inv.computes[1].extra["afm_name"] == "pod-1-1-ComputeTray" and "password:" not in text


def test_afm_trays_picks_the_tray_address():
    class A:
        def computes(self):
            return [{"meta": {"name": "pod-1-0-ComputeTray"}, "spec": {"slot-id": 0},
                     "status": {"controllers": ["10.0.0.83"], "ip-config": {"mgmt": "10.0.0.83, 10.0.0.81/28"}}}]
    assert discover.afm_trays(A(), {"10.0.0.1"}) == {0: {"afm_name": "pod-1-0-ComputeTray", "ip": "10.0.0.81"}}


def test_save_inventory_checks(tmp_path):
    st = server.State(tmp_path, tmp_path / "res")
    good = discover.draft("lab", [SW], "admin", "u", None, None)
    assert server.save_inventory(st, {"name": "lab", "yaml": good})["fill_me"] == 2
    with pytest.raises(server.BadRequest, match="exists"):
        server.save_inventory(st, {"name": "lab", "yaml": good})
    with pytest.raises(server.BadRequest, match="password"):
        server.save_inventory(st, {"name": "lab2", "yaml": good + "\npassword: x\n"})
    with pytest.raises(server.BadRequest, match="not a valid"):
        server.save_inventory(st, {"name": "lab3", "yaml": "rack: [unclosed"})
    with pytest.raises(server.BadRequest, match="file name"):
        server.save_inventory(st, {"name": "../x", "yaml": good})


def test_discover_request_checks():
    with pytest.raises(server.BadRequest, match="rack name"):
        server.discover_rack({"rack": "MR 4", "switches": "10.0.0.1"})
    with pytest.raises(server.BadRequest, match="switch addresses"):
        server.discover_rack({"rack": "mr4", "switches": "10.0.0.1;reboot"})


def test_draft_through_a_jump_host_and_discover_passes_it(monkeypatch, tmp_path):
    jump = {"host": "165.204.38.103", "port": 8059, "user": "tenant-hpe", "via": "exec"}
    f = tmp_path / "g.local.yaml"
    f.write_text(discover.draft("g", [SW], "admin", "u", None, None, jump=jump))
    assert load_inventory(f).transport["jump"] == jump
    seen = {}
    monkeypatch.setattr(discover, "read_switch", lambda a, u, key_file=None, jump=None: seen.update(jump=jump) or SW)
    out = server.discover_rack({"rack": "g", "switches": "10.0.0.1", "jump_host": "165.204.38.103", "jump_port": 8059,
                                "jump_user": "tenant-hpe"})
    assert seen["jump"] == jump and "165.204.38.103" in out["yaml"]
    with pytest.raises(server.BadRequest, match="jump host"):
        server.discover_rack({"rack": "g", "switches": "10.0.0.1", "jump_host": "a;b"})


def test_edit_an_inventory_keeps_the_previous_file(tmp_path):
    st = server.State(tmp_path, tmp_path / "res")
    good = "# my notes\n" + discover.draft("lab", [SW], "admin", "u", None, None)
    server.save_inventory(st, {"name": "lab", "yaml": good})
    t = server.inventory_text(st, "lab.local.yaml")
    assert t["name"] == "lab" and t["yaml"] == good                   # comments kept
    r = server.save_inventory(st, {"name": "lab", "yaml": good.replace("user: u", "user: hpe"), "overwrite": True})
    assert r["backup"] and (tmp_path / r["backup"]).read_text() == good
    assert "user: hpe" in (tmp_path / "lab.local.yaml").read_text()
    assert server.save_inventory(st, {"name": "lab", "yaml": (tmp_path / "lab.local.yaml").read_text(), "overwrite": True})["backup"] is None
    with pytest.raises(server.BadRequest):
        server.inventory_text(st, "../etc/passwd.yaml")


def test_secret_in_a_flow_map_is_refused(tmp_path):
    st = server.State(tmp_path, tmp_path / "res")
    good = discover.draft("lab", [SW], "admin", "u", None, None)
    bad = good.replace("- name: st1", "- password: hunter2\n  name: st1")
    with pytest.raises(server.BadRequest, match="password"):
        server.save_inventory(st, {"name": "lab", "yaml": "rack: lab\nswitches:\n  - {name: st1, host: x, password: hunter2}\n"})
    with pytest.raises(server.BadRequest, match="password"):
        server.save_inventory(st, {"name": "lab", "yaml": bad})
    assert server.save_inventory(st, {"name": "lab", "yaml": good + "afm: {auth: {password_env: X}}\n"})["file"]
