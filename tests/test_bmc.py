"""bmc: a node's BMC over Redfish - what a tray that does not answer over SSH is doing (g02-g17 2 Nov: ct12 / ct15
off the network, their BMCs answering). A fake BMC stands in; the jump host's curl output is split back per URL."""
from datetime import datetime, timezone

from heliosdbg import bmc, health

NOW = datetime(2026, 11, 2, 18, 0, tzinfo=timezone.utc)


class FakeBmc:
    def __init__(self, tree: dict, refuse: bool = False, dead: bool = False):
        self.tree, self.refuse, self.dead, self.address = tree, refuse, dead, "10.0.0.40"

    def get_many(self, paths, auth=True):
        if self.dead:
            return {p: (0, None) for p in paths}
        if auth and self.refuse and p_needs_auth(paths):
            return {p: (401, None) for p in paths}
        return {p: ((200, self.tree[p]) if p in self.tree else (404, None)) for p in paths}


def p_needs_auth(paths):
    return any(p != "/redfish/v1/" for p in paths)


def tree(power="Off", health_="OK", log=None, temp=40):
    return {
        "/redfish/v1/": {"Vendor": "AMI", "Product": "OpenBMC"},
        "/redfish/v1/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/system"}]},
        "/redfish/v1/Managers": {"Members": [{"@odata.id": "/redfish/v1/Managers/bmc"}]},
        "/redfish/v1/Chassis": {"Members": [{"@odata.id": "/redfish/v1/Chassis/chassis"}]},
        "/redfish/v1/Systems/system": {"Id": "system", "PowerState": power, "Status": {"Health": health_}},
        "/redfish/v1/Managers/bmc": {"Id": "bmc", "Status": {"Health": "OK"}, "FirmwareVersion": "1.2"},
        "/redfish/v1/Chassis/chassis": {"Id": "chassis", "Thermal": {"@odata.id": "/redfish/v1/Chassis/chassis/Thermal"}},
        "/redfish/v1/Chassis/chassis/Thermal": {"Temperatures": [{"Name": "CPU0", "ReadingCelsius": temp,
                                                                   "UpperThresholdCritical": 95}]},
        "/redfish/v1/Systems/system/LogServices": {"Members": [{"@odata.id": "/redfish/v1/Systems/system/LogServices/EventLog"}]},
        "/redfish/v1/Systems/system/LogServices/EventLog": {"Entries": {"@odata.id": "/redfish/v1/Systems/system/LogServices/EventLog/Entries"}},
        "/redfish/v1/Systems/system/LogServices/EventLog/Entries": {"Members": log or []},
    }


def judge(snap, ssh_ok):
    return bmc.judge("ct12", "compute", snap, ssh_ok, health.finding, health.CRITICAL, health.WARNING, now=NOW)


def test_powered_off_with_the_event_log():
    log = [{"Severity": "Critical", "Created": "2026-11-02T15:51:00Z", "Message": "PSU 1 input lost"},
           {"Severity": "OK", "Created": "2026-11-02T15:52:00Z", "Message": "Host power off"}]
    snap = bmc.snapshot(FakeBmc(tree(log=log)), authed=True)
    assert snap["auth"] == "ok" and snap["systems"][0]["power"] == "Off" and snap["product"] == "AMI OpenBMC"
    fs = judge(snap, ssh_ok=False)
    what = [f["what"] for f in fs]
    assert "powered off (BMC: system system)" in what and any("event log" in w for w in what)
    off = next(f for f in fs if f["what"].startswith("powered off"))
    assert off["area"] == "power" and "CHANGES THE RACK" in off["next"]
    assert any("PSU 1 input lost" in e for f in fs for e in f["evidence"])


def test_on_but_ssh_dead_and_hot_sensor():
    fs = judge(bmc.snapshot(FakeBmc(tree(power="On", temp=97)), authed=True), ssh_ok=False)
    assert any(f["what"] == "powered on, but the OS does not answer over SSH" for f in fs)
    assert any(f["area"] == "thermal" and "CPU0 97" in f["what"] for f in fs)
    assert judge(bmc.snapshot(FakeBmc(tree(power="On")), authed=True), ssh_ok=True) == []


def test_without_password_and_unreachable():
    snap = bmc.snapshot(FakeBmc(tree()), authed=False)
    assert snap["reachable"] and snap["auth"] == "none" and snap["systems"] == []
    assert [f["what"] for f in judge(snap, ssh_ok=False)] == ["the node does not answer over SSH, its BMC does"]
    dead = bmc.snapshot(FakeBmc({}, dead=True), authed=True)
    f = judge(dead, ssh_ok=False)[0]
    assert f["area"] == "power" and "both do not answer" in f["what"]
    assert judge(bmc.snapshot(FakeBmc(tree(), refuse=True), authed=True), ssh_ok=True)[0]["what"].endswith("refused the login")


def test_curl_output_split_back_per_url():
    base = "https://10.0.0.40"
    text = ('{"Product": "OpenBMC"}\n' + bmc.MARK + "200 https://10.0.0.40/redfish/v1/\n"
            + "\n" + bmc.MARK + "000 https://10.0.0.40/redfish/v1/Systems\n")
    got = bmc._split(text, base, ["/redfish/v1/", "/redfish/v1/Systems"])
    assert got["/redfish/v1/"] == (200, {"Product": "OpenBMC"}) and got["/redfish/v1/Systems"] == (0, None)


def test_credentials_never_from_the_inventory():
    class H:
        name, extra = "ct12", {"bmc": "10.0.0.40", "bmc_user": "admin", "bmc_password": "nope"}
    assert bmc.credentials(H, {"HELIOS_BMC_PASSWORD_CT12": "x"}) == ("10.0.0.40", "admin", "x")
    assert bmc.credentials(H, {"HELIOS_BMC_PASSWORD": "y"})[2] == "y"
    assert bmc.credentials(H, {})[2] == ""
