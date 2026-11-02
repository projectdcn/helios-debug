"""platforms: what is checked on each kind of node - the registry, a node's own platforms: from the inventory, and the
Debug-a-node allow-list made of the platforms' READ_ONLY rules."""
import pytest

from heliosdbg import checks, guide, health, platforms


class Host:
    def __init__(self, extra):
        self.extra = extra


def test_defaults_and_inventory_override():
    assert [p.name for p in platforms.for_node("switch")] == ["sonic", "afm-switch"]
    assert [p.name for p in platforms.for_node("compute")] == ["amd-gpu", "afm-compute", "linux", "rdma"]
    plain = platforms.for_node("compute", Host({"platforms": "linux, rdma"}))     # a server without GPUs or AFM
    assert [p.name for p in plain] == ["linux", "rdma"]
    with pytest.raises(ValueError, match="unknown platform"):
        platforms.for_node("compute", Host({"platforms": ["nvidia-gpu"]}))


def test_every_check_belongs_to_one_platform():
    seen = {}
    for p in platforms.PLATFORMS.values():
        assert p.role in ("switch", "compute") and p.judge and p.about
        for check, cmd, sudo in p.commands:
            assert (p.role, check) not in seen, f"{check} in {seen.get((p.role, check))} and {p.name}"
            seen[(p.role, check)] = p.name
    assert {c for c, _, _ in health.SWITCH_CMDS} >= {"health", "crm", "watchdog", "afm_agent"}
    assert {c for c, _, _ in health.COMPUTE_CMDS} >= {"gpus", "afmctl", "kernel", "rdma", "failed"}


def test_only_the_nodes_platforms_are_judged():
    outs = {"gpus": {"cmd": "amd-smi list --json", "rc": 0, "out": "[]", "err": ""},
            "failed": {"cmd": "systemctl --failed", "rc": 0, "out": "foo.service loaded failed failed Foo\n", "err": ""}}
    every = health.judge_compute("ct01", outs)
    assert {f["check"] for f in every} == {"gpus", "failed"}
    only_os = health.judge_compute("ct01", outs, platforms=platforms.for_node("compute", Host({"platforms": ["linux"]})))
    assert [f["check"] for f in only_os] == ["failed"]


def test_allow_list_is_the_platforms_read_only_rules():
    assert guide.SWITCH_RO == platforms.PLATFORMS["sonic"].read_only
    assert set(guide.COMPUTE_RO) == {r for n in platforms.DEFAULTS["compute"] for r in platforms.PLATFORMS[n].read_only}
    assert guide.check("sudo amd-smi metric --ecc --json", "compute") == ("amd-smi metric --ecc --json", True)
    assert guide.check("rdma link show", "compute")[1] is False
    with pytest.raises(guide.GuideError):
        guide.check("amd-smi reset -g 0", "compute")
    assert checks.Platform("x", "compute", "y").read_only == []
