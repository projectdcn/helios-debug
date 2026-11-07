"""Lift a quarantine in one click (the rack map): only the node's 'quarantine:' leaves the inventory, comments and the
other entries stay, the previous file is kept as a backup."""
import pytest

from ui import server

INV = """rack: lab   # the lab rack
switches:
  - {name: st1, host: a}
computes:
  - {name: ct01, host: c, slot: 0}
  # ct05 was down 16-19 Oct
  - {name: ct05, host: d, slot: 4, quarantine: {reason: Down, since: '2026-10-16', until: '2026-10-19'}}   # pod-1-4
  - name: ct06
    host: e
    quarantine:
      reason: PSU out
    slot: 5
"""


@pytest.fixture
def st(tmp_path):
    (tmp_path / "lab.local.yaml").write_text(INV)
    return server.State(tmp_path, tmp_path / "results")


@pytest.mark.parametrize("node", ["ct05", "ct06"])
def test_one_click_lifts_only_that_quarantine(st, node):
    assert node in st.inventories()[0]["quarantined"]
    r = server.lift_quarantine(st, {"inventory": "lab.local.yaml", "node": node})
    assert r["node"] == node and r["backup"].startswith("lab.local.yaml.bak-")
    text = (st.inventory_dir / "lab.local.yaml").read_text()
    assert "# ct05 was down 16-19 Oct" in text and "# the lab rack" in text
    _, inv = st.inventory("lab.local.yaml")
    assert node in [h.name for h in inv.computes]
    other = {"ct05": "ct06", "ct06": "ct05"}[node]
    assert list(inv.quarantine_summary()) == [other]
    assert (st.inventory_dir / r["backup"]).read_text() == INV


def test_a_node_that_is_not_quarantined_is_refused(st):
    with pytest.raises(server.BadRequest, match="not quarantined"):
        server.lift_quarantine(st, {"inventory": "lab.local.yaml", "node": "ct01"})


def test_an_entry_it_cannot_edit_safely_is_left_alone(st):
    f = st.inventory_dir / "lab.local.yaml"
    f.write_text(INV.replace("  - {name: ct05, host: d, slot: 4, quarantine:", "  - {name: ct05, host: d, slot: 4,\n     quarantine:"))
    before = f.read_text()
    with pytest.raises(server.BadRequest, match="Add / edit a rack"):
        server.lift_quarantine(st, {"inventory": "lab.local.yaml", "node": "ct05"})
    assert f.read_text() == before
