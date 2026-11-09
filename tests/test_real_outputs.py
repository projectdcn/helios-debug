"""Every parser against real outputs recorded on g02-g17 (QFX5252 switch trays, SONiC 202505; MI450X compute trays).

9 Nov 2026: two row parsers wanted 'Ethernet' at the start of the line - SONiC pads Ethernet1-99 with spaces, so 99 of
257 ports per chip were never read for weeks (bcm-view said Ethernet4 'is not in show interfaces status'), and
'afmctl show device health' was read as a GPU list (0 GPUs). Each parser is held to the rows the output really has.

The outputs are rack data (addresses, serials): they live git-ignored in helios-slm (data/nodeguide-src/*.json, the
same recordings its node-investigation training uses), or wherever HELIOS_REAL_OUTPUTS points; without them these
tests skip.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from heliosdbg import guide, l1
from heliosdbg.parsers import parse_table

SRC = Path(os.environ.get("HELIOS_REAL_OUTPUTS") or Path(__file__).resolve().parents[2] / "helios-slm" / "data" / "nodeguide-src")


def _outputs() -> list[tuple[str, str, str]]:
    got = []
    for f in sorted(SRC.glob("*.json")) if SRC.is_dir() else []:
        for node, cmds in json.loads(f.read_text()).get("nodes", {}).items():
            for cmd, v in cmds.items():
                if isinstance(v, dict) and isinstance(v.get("out"), str) and v.get("rc") in (0, "0"):
                    got.append((node, re.sub(r"^\s*sudo\s+", "", cmd), v["out"]))
    return got


OUTS = _outputs()
pytestmark = pytest.mark.skipif(not OUTS, reason=f"no recorded rack outputs in {SRC}")

_ETH = re.compile(r"^\s*Ethernet\d+\s", re.M)


def _of(rx: str) -> list[tuple[str, str, str]]:
    got = [x for x in OUTS if re.match(rx, x[1]) and "|" not in x[1]]
    if not got:
        pytest.skip(f"no recording of {rx}")
    return got


def test_interfaces_status_rows():
    for node, cmd, out in _of(r"show interfaces status -n asic\d$"):
        n = len(_ETH.findall(out))
        assert n > 200, (node, cmd)
        assert len(guide._SW_PORT.findall(out)) == n, (node, cmd, "guide._SW_PORT")
        assert len(guide._STATUS_ROW.findall(out)) == n, (node, cmd, "guide._STATUS_ROW")
        assert len(guide._STATUS_ROW_ALL.findall(out)) == n, (node, cmd, "guide._STATUS_ROW_ALL")
        assert len([r for r in parse_table(out) if str(r.get("Interface", "")).startswith("Ethernet")]) == n
        sl = guide.status_line(out)
        assert sl and sl.startswith(f"Port status: {n} ports")


def test_fec_stats_rows():
    for node, cmd, out in _of(r"(?:show interfaces counters fec-stats|portstat -f) -n asic\d$"):
        n = len(_ETH.findall(out))
        assert len(l1.fec_stats(out)) == n, (node, cmd)
        assert l1.fec_line(out).startswith(f"FEC counters: {n} ports")


def test_fec_histograms():
    for node, cmd, out in _of(r"show interfaces counters fec-histogram -n asic\d Ethernet\d+$"):
        h = l1.histograms(out)
        assert len(h) == 1 and len(h[0]["bins"]) == 16 and h[0]["bins"][0] > 0, (node, cmd)
    for node, cmd, out in _of(r"portstat -fh -n asic\d -i Ethernet\d+$"):
        h = l1.histograms(out)
        assert len(h) == 1 and h[0]["port"] == cmd.split()[-1] and len(h[0]["bins"]) == 16, (node, cmd)
    for node, cmd, out in _of(r"afmctl show port statistics fec -b \S+ -p \d+$"):
        h = l1.histograms(out)
        assert len(h) == 1 and h[0]["port"] == int(cmd.split()[-1]) and h[0]["link_up"] is not None, (node, cmd)


def test_flap_and_gearbox_rows():
    for node, cmd, out in _of(r"show interfaces flap -n asic\d$"):
        assert len(l1.flaps(out)) == len(_ETH.findall(out)) > 200, (node, cmd)
    for node, cmd, out in _of(r"ip netns exec asic\d gearboxutil interfaces status$"):
        rows = len(re.findall(r"^\s*\d+\s+Ethernet\d+\s", out, re.M))
        assert len(l1.gearbox(out)) == rows > 200, (node, cmd)


def test_counters_state_rows():
    for node, cmd, out in _of(r"show interfaces counters -n asic\d$"):
        assert len(guide._CTR_STATE.findall(out)) == len(_ETH.findall(out)) > 50, (node, cmd)   # a recording may be cut


def test_summaries_and_listings():
    for node, cmd, out in _of(r"show pfc counters -n asic\d$"):
        assert guide.pfc_line(out), (node, cmd)
    for node, cmd, out in _of(r"show vlan brief -n asic\d$"):
        assert guide.vlans_of(out) and guide.vlans_of(out)[0]["vlan"], (node, cmd)
    for node, cmd, out in _of(r"afmctl show device --json$"):
        assert guide.gpus_listed(guide.compact(out), cmd) is not None, (node, cmd)
    for node, cmd, out in _of(r"afmctl show device health\b.*"):
        assert guide.gpus_listed(out, cmd) is None, (node, cmd, "a health listing is not a GPU list")


def test_compact_never_cuts_a_whole_chip_table():
    """A whole chip's table is summarised in one line, never handed on raw (cut at the output limit, the model saw
    a fifth of it)."""
    for node, cmd, out in OUTS:
        if len(_ETH.findall(out)) > 200 and re.match(r"(?:show interfaces (?:status|counters fec-stats|flap)|portstat -f|"
                                                    r"show pfc counters|ip netns exec asic\d gearboxutil)\b", cmd):
            c = guide.compact(out)
            assert c != out and len(c) < 3000, (node, cmd)
