"""Link timeline parsing (heliosdbg/timeline.py) on lines as MR3 st1 / c2 logged them, 19 Oct 2026."""
from __future__ import annotations

from datetime import datetime, timezone

from heliosdbg import timeline

SINCE = datetime(2026, 10, 18, tzinfo=timezone.utc)
SW = """2026 Oct 19 03:06:36.783772 blantons-mr3-sw NOTICE sudo:    admin : PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/bash -c 'config interface -n asic0 shutdown Ethernet1'
2026 Oct 19 03:06:37.042553 blantons-mr3-sw NOTICE swss0#portmgrd: :- doTask: Configure Ethernet1 admin status to down
2026 Oct 19 03:06:37.106265 blantons-mr3-sw NOTICE swss0#orchagent: :- doPortTask: Set port Ethernet1 admin status to down
2026 Oct 19 03:06:37.106321 blantons-mr3-sw NOTICE swss0#orchagent: :- updatePortOperStatus: Port Ethernet1 oper state set from up to down
2026 Oct 19 03:06:37.106983 blantons-mr3-sw WARNING pmon#DomInfoUpdateTask[29]: *** ('Ethernet1', 'APPL_DB', 'PORT_TABLE') handle_port_update_event() fvp {'index': '1', 'flap_count': '6', 'port_name': 'Ethernet1'}
2026 Oct 19 03:06:38.106983 blantons-mr3-sw WARNING pmon#DomInfoUpdateTask[29]: *** ('Ethernet1', 'APPL_DB', 'PORT_TABLE') handle_port_update_event() fvp {'index': '1', 'flap_count': '6', 'port_name': 'Ethernet1'}
2026 Oct 19 03:06:43.667615 blantons-mr3-sw ERR swss0#orchagent: :- getPortLinkTrainingFailure: Failed to get LT failure status for Ethernet1
2026 Oct 19 03:06:49.023368 blantons-mr3-sw NOTICE swss0#orchagent: :- updatePortOperStatus: Port Ethernet1 oper state set from down to up
2026 Oct 19 06:06:35.000000 blantons-mr3-sw NOTICE sudo:    admin : PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/zgrep -h -w Ethernet1 /var/log/syslog
2026 Oct 17 01:00:00.000000 blantons-mr3-sw NOTICE swss0#orchagent: :- updatePortOperStatus: Port Ethernet1 oper state set from up to down
@@NOW
"""
TRAY = """2026-10-19T03:03:26.123456+00:00 hpe-mr3-compute2 kernel: ifoe 0003:01:00.1: MC command 0x17e inlen 0 failed rc=-16 (raw 16)
2026-10-19T03:03:26.523456+00:00 hpe-mr3-compute2 kernel: ifoe 0003:01:00.1: MC command 0x17f inlen 0 failed rc=-16 (raw 16)
2026-10-19T04:34:39.000000+00:00 hpe-mr3-compute2 afmctl[523136]: phase=end kind=disruptive sub_cmd=reset status=0 user=hpeadmin1 ruid=0 euid=0 tty=none bdf=0001:01:00.1 cmd="afmctl reset device -b 0001:01:00.1"
"""


def test_switch_lines():
    ev = timeline.parse_switch(SW, SINCE)
    kinds = [e["kind"] for e in ev]
    assert kinds == ["command", "admin", "oper", "flap", "training", "oper"]
    assert "admin ran: /usr/bin/bash -c 'config interface -n asic0 shutdown Ethernet1'" in ev[0]["text"]
    assert ev[2]["text"] == "link up -> down" and ev[0]["t"].startswith("2026-10-19T03:06:36")


def test_tray_lines_collapsed():
    ev = timeline.parse_tray(TRAY, SINCE)
    assert [(e["kind"], e.get("count")) for e in ev] == [("error", 2), ("command", None)]
    assert "hpeadmin1 ran: afmctl reset device -b 0001:01:00.1 (status 0)" in ev[1]["text"]


def test_summary_flags_admin_changes_without_a_command():
    tl = {"hours": 24, "events": [e for e in timeline.parse_switch(SW, SINCE) if e["kind"] != "command"], "errors": {}}
    assert any("other than the CLI" in x for x in timeline.summary(tl))


def test_alternating_repeats_collapse():
    lines = "".join(f"2026-10-19T05:55:{i:02d}.000000+00:00 c1 kernel: ifoe 0004:01:00.1: "
                    + ("MC command 0xc7 inlen 4 failed rc=-38 (raw 38)\n" if i % 2 else "Unhandled mcdi_event subcode 0x2f [c002f000:00000001]\n")
                    for i in range(40))
    ev = timeline.parse_tray(lines, SINCE)
    assert len(ev) == 2 and sorted(e["count"] for e in ev) == [20, 20] and ev[0]["until"].startswith("2026-10-19T05:55:3")


def test_different_ports_not_merged():
    lines = ("2026-10-19T01:15:43.000000+00:00 c1 kernel: ifoe 0004:01:00.1: port 104: link down event (seq 6)\n"
             "2026-10-19T01:15:44.000000+00:00 c1 kernel: ifoe 0004:01:00.1: port 108: link down event (seq 6)\n"
             "2026-10-19T01:15:45.000000+00:00 c1 kernel: ifoe 0004:01:00.1: port 104: link down event (seq 7)\n")
    ev = timeline.parse_tray(lines, SINCE)
    import re
    assert [(re.search(r"port \d+", e["text"]).group(0), e.get("count")) for e in ev] == [("port 104", 2), ("port 108", None)]
