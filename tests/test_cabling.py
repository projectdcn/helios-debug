"""Cabling plan check (heliosdbg/cabling.py)."""
from __future__ import annotations

import pytest

from heliosdbg import cabling

LINKS = [
    {"switch": "st1", "sw_port": "Ethernet1", "desc": "To ComputeTray Slot0/GPU3[3]/Port33", "tray": "c1",
     "bdf": "0004:01:00.1", "gpu_port": 33, "matched_by": "mac", "kind": ""},
    {"switch": "st1", "sw_port": "Ethernet2", "desc": "To ComputeTray Slot0/GPU3[3]/Port35", "tray": "c1",
     "bdf": "0004:01:00.1", "gpu_port": 34, "matched_by": "mac", "kind": ""},      # really reaches port 34
    {"switch": "st1", "sw_port": "Ethernet3", "desc": "To ComputeTray Slot1/GPU0[4]/Port1", "tray": None, "bdf": None,
     "gpu_port": None, "matched_by": "description", "kind": "tray_unreachable"},
    {"switch": "st1", "sw_port": "Ethernet9", "desc": "To ComputeTray Slot1/GPU0[4]/Port2", "tray": "c2", "bdf": "0001:01:00.1",
     "gpu_port": 2, "matched_by": "mac", "kind": ""},
]
SLOTS, GMAP = {"c1": 0, "c2": 1}, {"c1:GPU3": "0004:01:00.1", "c2:GPU0": "0001:01:00.1"}


def test_check_finds_each_kind():
    plan = cabling.read_plan("switch,port,slot,gpu,gpu_port\n# comment\nst1,Ethernet1,0,3,33\nst1,Ethernet2,0,3,35\n"
                             "st1,Ethernet3,1,0,9\nst1,Ethernet7,1,1,1\n")
    r = cabling.check(plan, LINKS, SLOTS, GMAP)
    kinds = sorted((p["kind"], p["port"]) for p in r["problems"])
    assert kinds == [("cabled_elsewhere", "Ethernet2"), ("description", "Ethernet3"), ("not_found", "Ethernet7"),
                     ("not_in_plan", "Ethernet9")]
    assert r["ok"] == 1
    moved = next(p for p in r["problems"] if p["kind"] == "cabled_elsewhere")
    assert "reaches c1 0004:01:00.1 port 34" in moved["detail"] and "move the far end to c1 GPU3 port 35" in moved["detail"]


def test_tray_names_and_bad_plans():
    assert cabling.read_plan("Switch,Port,Tray,GPU,GPU_Port\nst1,Ethernet1,c2,0,1\n", SLOTS)[0]["slot"] == 1
    with pytest.raises(ValueError, match="header"):
        cabling.read_plan("a,b\n1,2\n")
    with pytest.raises(ValueError, match="slot of tray"):
        cabling.read_plan("switch,port,tray,gpu,gpu_port\nst1,Ethernet1,c9,0,1\n", SLOTS)


def test_export_round_trip():
    text = cabling.export(LINKS)
    plan = cabling.read_plan(text)
    assert len(plan) == 4 and cabling.check(plan, LINKS[:1], SLOTS, GMAP)["problems"][0]["kind"] == "not_found"


def test_known_hosts_with_a_broken_line(tmp_path):
    """A truncated known_hosts line (g02-g17 jump host, 22 Oct) is skipped, the good keys still load."""
    import paramiko
    from heliosdbg.transport import load_known_hosts
    k = paramiko.RSAKey.generate(1024).get_base64()
    kh = tmp_path / "known_hosts"
    kh.write_text(f"10.0.0.1 ssh-rsa {k}\n10.0.0.2 ssh-rsa {k[:41]}\n")
    c = paramiko.SSHClient()
    load_known_hosts(c, str(kh))
    keys = c._system_host_keys                       # load_system_host_keys() fills these, not get_host_keys()
    assert "10.0.0.1" in keys and "10.0.0.2" not in keys


def test_show_mac_failure_is_named_as_broken_forwarding_entries():
    """g02-g17 st1 23 Oct: `show mac` fails with KeyError 'SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID'; the scan names the
    entries without a switch port (and where they came from) instead of a bare KeyError."""
    from types import SimpleNamespace
    from heliosdbg import linkdiag

    class Sw:
        host = SimpleNamespace(name="st1")

        def sh(self, cmd, **kw):
            if cmd.startswith("show mac"):
                raise RuntimeError("[st1] rc=1: show mac -n asic0\n'SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID'")
            if cmd.startswith("bash -c"):
                return 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26","mac":"00:11:22:33:44:55","switch_id":"oid:0x21"}\n'
            if "APPL_DB keys" in cmd:
                return "FDB_TABLE:Vlan100:00:11:22:33:44:55\n"
            if "APPL_DB hgetall" in cmd:
                return "{'port': 'Ethernet8', 'type': 'static'}"
            return ""
    try:
        linkdiag.read_fdb(Sw(), "asic0")
        raise AssertionError("expected FdbBrokenEntries")
    except linkdiag.FdbBrokenEntries as e:
        assert e.entries == [{"mac": "00:11:22:33:44:55", "vlan": "100", "port": "Ethernet8", "type": "static",
                              "source": "APPL_DB FDB_TABLE - added at runtime"}]
        assert "without a switch port on st1 asic0" in str(e) and "Vlan100 00:11:22:33:44:55 -> Ethernet8" in str(e)

    class Other(Sw):
        def sh(self, cmd, **kw):
            raise RuntimeError("[st1] rc=255: connection refused")
    try:
        linkdiag.read_fdb(Other(), "asic0")
    except RuntimeError as e:
        assert not isinstance(e, linkdiag.FdbBrokenEntries)     # other failures are not relabelled


def test_vlans_read_and_checked():
    """read_vlans parses the one-command dump; vlan_findings flags a GPU port in no VLAN, a port whose VLAN differs
    from the chip's other GPUs on that port number, a static entry off its port's VLAN, and a chip with other VLANs."""
    from types import SimpleNamespace
    from heliosdbg import linkdiag
    sw = SimpleNamespace(sh=lambda cmd, **kw: "V Vlan2\nV Vlan100\nM Vlan100|Ethernet8 priority_tagged\nM Vlan200|Ethernet9 \n")
    v = linkdiag.read_vlans(sw, "asic0")
    assert v == {"vlans": ["Vlan2", "Vlan100", "Vlan200"], "members": {"Ethernet8": [["Vlan100", "priority_tagged"]],
                                                                    "Ethernet9": [["Vlan200", ""]]}}

    def link(port, gport, vl):
        ln = linkdiag.Link("st1", "asic0", port, f"To ComputeTray Slot0/GPU0[0]/Port{gport}", vlans=vl)
        ln._cab = (0, 0, 0, gport)
        return ln
    pt = [["Vlan100", "priority_tagged"]]
    links = [link("Ethernet1", 31, pt), link("Ethernet2", 31, pt), link("Ethernet3", 31, [["Vlan300", "priority_tagged"]]),
             link("Ethernet4", 33, []), link("Ethernet5", 35, None)]
    switches = [{"name": "st1", "asics": {"asic0": {"vlan": {"vlans": ["Vlan100", "Vlan300"], "members": {
                    "Ethernet1": pt, "Ethernet2": pt, "Ethernet3": [["Vlan300", "priority_tagged"]]}},
                    "fdb": [{"Vlan": "200", "MacAddress": "00:11:22:33:44:55", "Port": "Ethernet1", "Type": "Static"}]}}},
                {"name": "st2", "asics": {"asic0": {"vlan": {"vlans": ["Vlan100"], "members": {"Ethernet1": pt}}, "fdb": []},
                                          "asic1": {"vlan": {"vlans": ["Vlan100"], "members": {"Ethernet1": pt}}, "fdb": []}}}]
    f = linkdiag.vlan_findings(switches, links)
    kinds = sorted((x["kind"], x["switch"], x["port"]) for x in f)
    assert ("not_in_vlan", "st1", "Ethernet4") in kinds and ("vlan_mismatch", "st1", "Ethernet3") in kinds
    assert ("fdb_off_vlan", "st1", "Ethernet1") in kinds and ("vlan_set", "st1", None) in kinds
    assert not any(x["port"] in ("Ethernet1", "Ethernet2") and x["kind"] == "vlan_mismatch" for x in f)
    assert not any(x["port"] == "Ethernet5" for x in f)               # VLANs not read: no verdict


def test_expired_quarantine_stays_but_says_so():
    """An inventory quarantine whose 'until' has passed still applies (as in helios-tests), and the reason says it ended."""
    from types import SimpleNamespace
    from heliosdbg import linkdiag
    h = lambda until: SimpleNamespace(role="compute", name="ct05", extra={"slot": 4},
                                      quarantine={"reason": "Down", "until": until})
    old = linkdiag.quarantined_slots(SimpleNamespace(quarantined=[h("2026-10-19")]))
    assert old[4][0] == "ct05" and "quarantine ended 2026-10-19" in old[4][1]
    assert linkdiag.quarantined_slots(SimpleNamespace(quarantined=[h("2999-01-01")]))[4] == ("ct05", "Down")
