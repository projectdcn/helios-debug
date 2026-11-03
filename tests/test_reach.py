"""reach: why a node could not be reached - the messages ssh prints with LogLevel=ERROR (g02-g17 2 Nov) and the
exceptions paramiko raises, each named with its next step."""
import pytest

from heliosdbg import ai, reach
from heliosdbg.transport import CmdResult, CommandError


def kind(text, **kw):
    c = reach.classify(text, **kw)
    return c and c["kind"]


def test_ssh_messages_from_the_jump_host():
    assert kind("tenant_hpe@10.0.0.73: Permission denied (publickey,password).") == "login_refused"
    assert kind("ssh: connect to host 10.0.0.58 port 22: No route to host") == "no_route"
    assert kind("ssh: connect to host 10.0.0.250 port 22: Connection timed out") == "timeout"
    assert kind("ssh: connect to host 10.0.0.9 port 22: Connection refused") == "ssh_refused"
    assert kind("ssh: Could not resolve hostname nosuch: Name or service not known") == "dns"
    assert kind("Host key verification failed.") == "host_key"
    assert kind("sudo: a password is required") == "sudo"
    assert kind("Secsh channel 19 open FAILED: open failed: Connect failed") == "jump_session"
    assert kind("ok: 3 links up") is None


def test_exceptions_and_filled_text():
    class AuthenticationException(Exception):
        pass
    c = reach.classify(AuthenticationException("Authentication failed."), user="tenant_hpe", host="st3")
    assert c["kind"] == "login_refused" and c["what"] == "login refused for tenant_hpe" and "tenant_hpe" in c["next"]
    assert reach.classify("No route to host")["owner"] == reach.SITE
    assert reach.describe("plain failure") == "plain failure"


def test_command_error_names_the_reason_only_when_ssh_failed():
    r = CmdResult("st3", "show interfaces status -n asic0 -d all", 255, "",
                  "tenant_hpe@10.0.0.73: Permission denied (publickey,password).\n")
    assert r.access["kind"] == "login_refused"
    assert str(CommandError(r)).startswith("[st3] login refused for tenant_hpe: tenant_hpe@10.0.0.73: Permission denied")
    other = CmdResult("st3", "false", 1, "", "Permission denied")        # a command's own rc: not an access failure
    assert other.access is None and str(CommandError(other)).startswith("[st3] rc=1")


def test_live_follower_error_carries_the_reason():
    from heliosdbg.live import _why
    w = _why(RuntimeError("[ct12] no route to host: off the network: ssh: connect to host 10.0.0.58 port 22: No route to host"))
    assert w["access"]["kind"] == "no_route" and w["error"].startswith("no route to host")


def test_unsafe_reads_are_not_steps():
    from heliosdbg import ai
    assert ai.unsafe_text("1. show reboot-cause history (on st4)") is None
    assert ai.unsafe_text("find why it rebooted (log, PSUs)") is None
    assert ai.unsafe_text("2. reboot the switch") == "reboot"
    assert ai.unsafe_text("2. config reload") == "config reload"
    assert ai.unsafe_text("1. config save (on st5)") == "config save"


def test_only_ssh_failures_are_access_problems():
    """3 Nov audit: a hung command read as 'no answer, powered off'; redis's 'Permission denied' as 'login refused'."""
    from heliosdbg.transport import CmdResult, CommandError, CommandTimeout
    redis = CommandError(CmdResult("st1", "show interfaces status", 1, "", "Permission denied: /var/run/redis/redis.sock"))
    assert reach.classify(redis) is None and reach.classify(str(redis)) is None
    ssh = CommandError(CmdResult("st1", "x", 255, "", "ssh: connect to host 10.0.0.1 port 22: No route to host\n"))
    assert reach.classify(ssh)["kind"] == "no_route" and reach.classify(str(ssh))["kind"] == "no_route"
    hung = CommandTimeout("[ct12] timed out after 60s: afmctl show port -b 0002:01:00.1")
    assert reach.classify(hung)["kind"] == "cmd_timeout"
    assert reach.classify("NoValidConnectionsError: Unable to connect to port 22")["kind"] == "timeout"


@pytest.mark.parametrize("text", ["config interface shutdown Ethernet8", "config interface -n asic0 startup Ethernet8",
                                  "ip link set dev eth0 down", "shutdown -r now", "ipmitool chassis power off",
                                  "amd-smi reset -g 0", "modprobe -r amdgpu", "nicctl reset card", "service swss restart",
                                  "sonic-installer install x.bin", "config vlan member del 100 Ethernet8",
                                  'bcmcmd "port ce0 en=0"', "afmctl update port --admin-state idle", "redis-cli DEL k"])
def test_unsafe_catches_real_changes(text):
    """3 Nov audit: each of these was missed (SONiC's own 'config interface shutdown <port>' order among them)."""
    assert ai.unsafe_text(text)


@pytest.mark.parametrize("text", ["last reboot", "grep -i reboot /var/log/syslog", "the reboot cause was a watchdog",
                                  "tail /var/log/reboot.log", "the tray was decommissioned",
                                  'show logging | grep "config reload"', "flap port count 5"])
def test_unsafe_leaves_reads_alone(text):
    assert ai.unsafe_text(text) is None
