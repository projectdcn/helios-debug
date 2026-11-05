"""platforms.rdma: the scale-out NICs - why a port is down from the NIC's own tool (g02-g17 2 Nov: 'Transceiver
removed' behind every POLLING port), flaps, hot optics, drop counters, mixed firmware on a tray and across trays."""
import json

from heliosdbg import health
from heliosdbg.platforms import rdma


def port(oper="DOWN", reason="Transceiver removed", events=0, temp=0, xcvr="REMOVED"):
    return {"nic": [{"port": [{"spec": {"name": "eth1/1", "admin_state": "UP"},
                               "status": {"operational_status": oper, "port_down_reason": reason, "transceiver_state": xcvr,
                                          "transceiver_pid": "QSFP-800G", "transceiver_temperature": str(temp),
                                          "transceiver_warning_temperature": "70", "transceiver_alarm_temperature": "75",
                                          "number_of_link_down_events": str(events)}}]}]}


def nicctl(cards):
    """cards: [(bdf, firmware, port JSON)] -> NICCTL_PORTS' output."""
    text = "".join(f"@@card {b} vulcano/rudra/pulsar/{fw}\n" for b, fw, _ in cards)
    return text + "".join(f"@@port {b}\n{json.dumps(p, indent=1)}\n" for b, _, p in cards)


def outs(rdma_text, nic_text, counters=""):
    o = {"rdma": {"cmd": "rdma link show", "rc": 0, "out": rdma_text, "err": ""},
         "nic_ports": {"cmd": "nicctl show port", "rc": 0, "out": nic_text, "err": ""}}
    if counters:
        o["nic_counters"] = {"cmd": "ethtool -S", "rc": 0, "out": counters, "err": ""}
    return o


POLLING = ("link ionic_0/1 state ACTIVE physical_state LINK_UP netdev eth0 \n"
           "link ionic_1/1 state DOWN physical_state POLLING netdev eth1 \n"
           "link ionic_2/1 state DOWN physical_state POLLING netdev eth2 \n")


def test_polling_ports_without_optics_are_for_the_site():
    o = outs(POLLING, nicctl([("0001:41:00.0", "1.130.5-a-7", port()), ("0001:45:00.0", "1.130.5-a-7", port())]))
    f = next(x for x in rdma.judge("ct11", o) if x["check"] == "rdma")
    assert "Transceiver removed" in f["cause"] and f["owner"] == "site" and "plug in" in f["next"]
    assert any("REMOVED" in e for e in f["evidence"])


def test_empty_cage_with_reason_none_is_no_optic_too():
    o = outs(POLLING, nicctl([("0000:01:00.0", "1.130.6-a-11", port(reason="None")),
                              ("0001:41:00.0", "1.130.5-a-7", port())]))
    f = rdma.judge("ct10", o)[0]
    assert "Transceiver removed' for every one" in f["cause"] and f["owner"] == "site"


def test_other_down_reasons_and_no_nicctl():
    o = outs(POLLING, nicctl([("0001:41:00.0", "1.130.5-a-7", port(reason="No signal", xcvr="SPROM-READ"))]))
    f = rdma.judge("ct11", o)[0]
    assert "No signal (1)" in f["cause"] and f["owner"] != "site"
    plain = rdma.judge("ct11", {"rdma": {"cmd": "rdma link show", "rc": 0, "out": POLLING, "err": ""}})
    assert plain[0]["cause"].startswith("a scale-out NIC port is down")


def test_flaps_hot_optic_counters_and_mixed_firmware():
    cards = [("0001:41:00.0", "1.130.5-a-7", port("UP", "None", events=9, temp=72, xcvr="SPROM-READ")),
             ("0003:41:00.0", "1.130.8-a-5", port("UP", "None", temp=76, xcvr="SPROM-READ"))]
    fs = {f["check"]: f for f in rdma.judge("ct11", outs("", nicctl(cards), "@@dev eth1\n     hw_rx_dropped: 12\n"
                                                                            "     rx_csum_error: 0\n"))}
    assert "went down 9 times" in fs["nic_flaps"]["what"]
    assert fs["nic_optic"]["severity"] == health.CRITICAL                 # the second optic is past its alarm
    assert fs["nic_firmware"]["what"] == "vulcano NICs run 2 firmware versions: 1.130.5-a-7 (1), 1.130.8-a-5 (1)"
    assert fs["nic_counters"]["evidence"] == ["eth1 hw_rx_dropped 12"]


def test_firmware_differs_between_trays():
    a = outs("", nicctl([("0001:41:00.0", "1.130.5-a-7", port("UP", "None"))]))
    b = outs("", nicctl([("0001:41:00.0", "1.130.8-a-5", port("UP", "None"))]))
    f = rdma.judge_rack({"ct01": a, "ct02": b, "ct03": b})
    assert f and f[0]["what"] == "vulcano NIC firmware differs between trays: 1.130.5-a-7 on 1; 1.130.8-a-5 on 2"
    assert rdma.judge_rack({"ct01": a, "ct02": a}) == []
    mix = outs("", nicctl([("0001:41:00.0", "1.130.5-a-7", port("UP", "None")),
                           ("0003:41:00.0", "1.130.8-a-5", port("UP", "None"))]))
    assert rdma.judge_rack({"ct01": mix, "ct02": mix}) == []           # the same mix everywhere: the per-tray finding
    assert "1.130.5-a-7 + 1.130.8-a-5 on 1" in rdma.judge_rack({"ct01": mix, "ct02": b})[0]["what"]
    got = health.judge_rack({"ct01": a, "ct02": b}, {"ct01": "compute", "ct02": "compute"})
    assert [x["check"] for x in got] == ["nic_firmware_rack"]


def test_rack_firmware_finding_takes_the_per_tray_mix_in():
    """g02-g17 5 Nov: 'differs between trays' and '9 of 18 trays: NICs run 2 firmware versions' said one thing twice."""
    mix = outs("", nicctl([("0001:41:00.0", "1.130.5-a-7", port("UP", "None")),
                           ("0003:41:00.0", "1.130.8-a-5", port("UP", "None"))]))
    b = outs("", nicctl([("0001:41:00.0", "1.130.8-a-5", port("UP", "None"))]))
    raw = {"ct01": mix, "ct02": mix, "ct03": mix, "ct04": b}
    fs = [f for n, o in raw.items() for f in rdma.judge(n, o)] + rdma.judge_rack(raw)
    got = health.rack_wide(fs, {"compute": 4})
    fw = [f for f in got if "firmware" in f["check"]]
    assert [f["check"] for f in fw] == ["nic_firmware_rack"] and "3 of them also mix versions" in fw[0]["cause"]
