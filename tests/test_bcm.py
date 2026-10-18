"""heliosdbg.bcm: parsing bcmcmd output (captured on g02-g17 st6, 18 Oct 2026) and judging a port's lanes."""
from __future__ import annotations

from heliosdbg import bcm

PMAP = """show pmap
             pipe   logical  physical    mmu   UCQbase/Numq  MCQbase/Numq
      cpu0     0       0          0        17         0/0           0/48
      cd96    12     216        193       384         0/8           8/4
     cd100    12     220        201       388        48/8          56/4
drivshell>"""

PORT_DOWN = """Table PC_PORT_STATUS:
  lookup PORT_ID=0xdc STATUS=STATUS_ALL
    LINK_TRAINING_DONE=0
    LINK_TRAINING=1
    REMOTE_FAULT=0
    LOCAL_FAULT=0
    PMD_LANE_RX_LOCK=0
    PMD_RX_LOCK=0
    FEC_MODE=PC_FEC_RS544_2XN_IEEE
    PORT_ID=0xdc(220)"""

FEC = """    FEC_CODE_WORD_ERROR_COUNTERS[0]=0x1d65_9cc6f0e4,FEC_CODE_WORD_ERROR_COUNTERS[1]=0x5008(20488),FEC_CODE_WORD_ERROR_COUNTERS[2]=0x142(322),FEC_CODE_WORD_ERROR_COUNTERS[3]=1,FEC_CODE_WORD_ERROR_COUNTERS[4-5]=2,FEC_CODE_WORD_ERROR_COUNTERS[6-12]=0,FEC_CODE_WORD_ERROR_COUNTERS[13]=2,FEC_CODE_WORD_ERROR_COUNTERS[14-15]=0,FEC_CODE_WORD_ERROR_COUNTERS[16]=0x7b(123),FEC_CODE_WORD_ERROR_COUNTERS[17-31]=0
    FEC_UNCORRECTED_CODEWORDS=0x7b(123)
    FEC_CODEWORDS=0x1d65_9d503ed5"""


def lane(sig, snr, tx_squelch=0):
    return {"RX_SIGNAL_DETECT": sig, "TX_SQUELCH": tx_squelch, "RX_SQUELCH": 0, "RX_SNR": snr,
            "EYE_UP": [40, 42, 39], "EYE_DOWN": [40, 42, 39], "AM_LOCK_LIVE": [0], "LINK_TIME": 1}


def view(lanes, **port):
    p = {"PMD_RX_LOCK": 1, "PMD_LANE_RX_LOCK": 3, "LINK_TRAINING": 1, "LINK_TRAINING_DONE": 1, "LOCAL_FAULT": 0,
         "REMOTE_FAULT": 0} | port
    return {"bcm_port": "cd100", "logical": 220, "port": p, "lane": lanes, "fec_bins": None, "fec": {}}


def test_parse_pmap_and_lt():
    assert bcm.parse_pmap(PMAP) == {0: ("cpu0", 0), 193: ("cd96", 216), 201: ("cd100", 220)}
    st = bcm.parse_lt(PORT_DOWN)
    assert st["PMD_RX_LOCK"] == 0 and st["LINK_TRAINING"] == 1 and st["FEC_MODE"] == "PC_FEC_RS544_2XN_IEEE"
    f = bcm.parse_lt(FEC)
    b = f["FEC_CODE_WORD_ERROR_COUNTERS"]
    assert len(b) == 32 and b[1] == 20488 and b[4] == b[5] == 2 and b[13] == 2 and b[16] == 123
    assert f["FEC_CODEWORDS"] == 0x1d659d503ed5
    assert bcm.unit_flag("asic1") == " -n 1" and bcm.unit_flag(None) == ""


def test_judge_no_signal_any_lane_with_transmitter_on():
    finding, ev = bcm.judge(view([lane(0, bcm.SNR_INVALID), lane(0, bcm.SNR_INVALID)], PMD_RX_LOCK=0,
                                 PMD_LANE_RX_LOCK=0, LINK_TRAINING_DONE=0))
    assert "no signal on any of its 2 lanes" in finding and "transmitter is on" in finding
    assert "RX_SNR n/a" in ev[1]


def test_judge_one_lane_dark_and_no_lock_and_healthy():
    assert "lane(s) 1 of 2" in bcm.judge(view([lane(1, 2477), lane(0, bcm.SNR_INVALID)]))[0]
    assert "cannot lock" in bcm.judge(view([lane(1, 900), lane(1, 900)], PMD_RX_LOCK=0))[0]
    assert "training does not finish" in bcm.judge(view([lane(1, 2477), lane(1, 2515)], LINK_TRAINING_DONE=0))[0]
    finding, ev = bcm.judge(view([lane(1, 2477), lane(1, 2515)]) | {"fec_bins": bcm.parse_lt(FEC)["FEC_CODE_WORD_ERROR_COUNTERS"],
                                                                    "fec": {"FEC_UNCORRECTED_CODEWORDS": 123}})
    assert finding == "" and "worst corrected codeword had 13 symbol errors" in ev[-1] and "uncorrectable 123" in ev[-1]


def test_read_ports_one_ssh_call_per_port():
    from types import SimpleNamespace
    calls = []
    lt_phy = "    RX_SIGNAL_DETECT=0\n    TX_SQUELCH=0\n    RX_SQUELCH=0"
    lt_phy2 = "Warning: port is NOT locked!\n    RX_SNR=0x1863c(99900)\n    EYE_UP[0-2]=0"

    class Sw:
        def run(self, cmd, timeout=0):
            calls.append(cmd)
            if "show pmap" in cmd:
                return SimpleNamespace(stdout=PMAP + bcm.SEP, rc=0)
            body = [PORT_DOWN, FEC, lt_phy, lt_phy2, lt_phy, lt_phy2]
            return SimpleNamespace(stdout=bcm.SEP.join(body) + bcm.SEP, rc=0)
    res = bcm.read_ports(Sw(), "asic1", {"Ethernet261": "201,202", "Ethernet999": "999"})
    assert res["Ethernet999"]["error"].startswith("no Broadcom port")
    v = res["Ethernet261"]
    assert v["bcm_port"] == "cd100" and v["lane"][1]["RX_SNR"] == bcm.SNR_INVALID and v["fec_bins"][16] == 123
    assert len(calls) == 2 and "bcmcmd -n 1" in calls[1] and "</dev/null" in calls[1]
    assert "set" not in calls[1].replace("STATUS_ALL", "") and "prbs" not in calls[1] and "eyescan" not in calls[1]
