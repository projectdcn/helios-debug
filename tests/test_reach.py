"""reach: why a node could not be reached - the messages ssh prints with LogLevel=ERROR (g02-g17 2 Nov) and the
exceptions paramiko raises, each named with its next step."""
from heliosdbg import reach
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
