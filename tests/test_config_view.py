"""Config tab: GPU summary, factory MACs, forwarding entries against the trays, odd ones out (g02-g17 3 Nov)."""
from heliosdbg import config_view as cv


def _tray(phase="ACTIVE", mode="bare-metal", mac="02:00:00:02:00:00", fw="0.24.2", ll="yes", vpod="1"):
    port = {"id": "0", "spec": {"nw_mac_addr": mac}, "status": {"link_status": "LINK_UP", "ifcp": {"ll_up": ll}}}
    dev = {"bdf": "0001:01:00.1", "spec": {"accelerator_id": "8", "config_phase": phase, "virtualization_mode": mode,
           "failover_mode": "disabled", "scaleup_fabric": {"virtual_pod": {"id": vpod}} if vpod else {"stations": ""}},
           "status": {"firmware_version": fw}}
    return {"kind": "compute", "sections": {"devices": {"data": {"device": [dev]}},
                                            "ports": {"data": {"0001:01:00.1": {"device": [dict(dev, port=[port])]}}}}}


def _switch(fdb_macs, mtu="9100"):
    port = {"Ethernet1": {"mtu": mtu, "fec": "rs", "speed": "400000", "description": "To ComputeTray Slot2/GPU0[8]/Port0"},
            "Ethernet2": {"mtu": "9100", "fec": "rs", "speed": "400000", "description": "To ComputeTray Slot0/GPU0[0]/Port0"}}
    fdb = {f"Vlan100|{m}": {"port": p, "type": "static"} for m, p in fdb_macs}
    return {"kind": "switch", "sections": {"host": {"data": {"DEVICE_METADATA": {"localhost": {"hwsku": "x"}}}},
                                           "asic0": {"data": {"PORT": port, "FDB": fdb, "VLAN": {"Vlan100": {}}}}}}


def test_summary_flags_provider_and_factory_macs():
    g = cv.compute_summary(_tray(phase="PROVIDER", mode="hypervisor", mac="00:1f:0e:00:00:00", vpod=""))[0]
    assert (g["phase"], g["mode"], g["vpod"], g["factory_mac"]) == ("PROVIDER", "hypervisor", "", True)
    assert (g["ports"], g["link_up"], g["ifcp_up"]) == (1, 1, 1)
    assert cv.compute_summary(_tray())[0]["factory_mac"] is False
    s = cv.switch_summary(_switch([("02:00:00:02:00:00", "Ethernet1")]))
    assert s["asic0"]["fdb"] == 1 and s["asic0"]["mtu"] == {"9100": 2}


def test_fdb_check_names_the_tray_whose_gpus_lost_their_macs():
    sw = _switch([("02:00:00:02:00:00", "Ethernet1"), ("02:00:00:00:00:00", "Ethernet2")])
    trays = {"ct03": _tray(), "ct01": _tray(phase="PROVIDER", mac="00:1f:0e:00:00:00")}
    r = cv.fdb_check({"st5": sw}, trays, {2: "ct03", 0: "ct01"})["switches"]["st5 asic0"]
    assert r["matched"] == 1 and r["no_gpu_port"] == {"ct01": 1}
    # a tray not read is not judged
    r = cv.fdb_check({"st5": sw}, {"ct03": _tray()}, {2: "ct03", 0: "ct01"})["switches"]["st5 asic0"]
    assert r["no_gpu_port"] == {}


def test_odd_ones_by_tray_and_switch_port():
    cfgs = {f"ct0{i}": _tray() for i in range(2, 6)} | {"ct01": _tray(phase="PROVIDER", mac="00:1f:0e:00:00:00")}
    cfgs |= {"st5": _switch([]), "st6": _switch([]), "st3": _switch([], mtu="1500")}
    odd = {(o["what"], o["value"]): o for o in cv.odd_ones(cfgs)}
    assert odd[("GPU phase", "PROVIDER")]["nodes"] == ["ct01"] and odd[("GPU phase", "PROVIDER")]["others"] == "ACTIVE"
    assert odd[("GPU factory_mac", "True")]["nodes"] == ["ct01"]
    assert odd[("PORT mtu", "1500")]["nodes"] == ["st3 asic0 Ethernet1"]
    assert not any(o["what"] == "GPU firmware" for o in odd.values())


def test_unreachable_tray_is_not_read_with_empty_parts():
    class Off:
        def run(self, *a, **k):
            raise RuntimeError("[ct06] no route to host: off the network (rc=255: afmctl show device --json)")
    r = cv.compute_config(Off())
    assert all(x["error"] and "no route" in x["error"] for x in r["sections"].values())


def test_fdb_check_per_expected_tray_and_unknown_slots_skipped():
    """Audit 4 Nov: an entry whose MAC belongs to another tray than its port leads to is not 'matched'; a port whose
    slot maps to no tray, or to a tray not read, is not judged; a tray whose ports were not read is not used."""
    sw = _switch([("02:00:00:00:00:00", "Ethernet1"),            # Slot2 -> ct03, but the MAC is ct01's
                  ("02:00:00:09:00:00", "Ethernet2")])           # Slot0 -> no tray in slots
    trays = {"ct03": _tray(mac="02:00:00:02:00:00"), "ct01": _tray(mac="02:00:00:00:00:00")}
    r = cv.fdb_check({"st5": sw}, trays, {2: "ct03"})["switches"]["st5 asic0"]
    assert r["matched"] == 0 and r["other_tray"] == {"ct03": 1} and r["no_gpu_port"] == {}
    dead = _tray()
    dead["sections"]["ports"] = {"data": None, "error": "no route to host"}
    assert cv.ports_read(_tray()) and not cv.ports_read(dead)
