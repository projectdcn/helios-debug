from heliosdbg import reach


def test_reach_questions_are_told_apart_from_link_questions():
    for q in ("how many switches are reachable", "which switch tray is not reachable ?",
              "which compute tray is not reachable ?", "can I ssh to ct06", "is st3 online"):
        assert reach.is_question(q), q
    for q in ("why is st4 Ethernet165 down", "which switch port is GPU 2 of ct05 cabled to", "what is IFCP"):
        assert not reach.is_question(q), q


def test_facts_name_who_answered_per_role_from_the_newest_checks():
    sw, ct = ["st1", "st2", "st3"], ["ct01", "ct02", "ct03", "ct04"]
    health = {"time": "2026-11-05 04:42", "unreachable": ["ct03"],
              "nodes": {n: {"role": "x", "not_run": ["afmctl"] if n == "ct02" else []} for n in sw + ["ct01", "ct02", "ct04"]}}
    scan = {"time_utc": "20261104-225936", "not_checked": [{"node": "ct03", "error": "ssh: connect to host 10.0.0.3 port 22: No route to host"}]}
    f = reach.facts(sw, ct, [], health, "health-20261105-043843", scan, "scan-20261104-225936-live")
    assert f[0] == ("Summary: 3 of 3 switches reachable and 3 of 4 compute trays reachable (NOT reached: ct03) at the "
                    "health check of 2026-11-05 04:42 UTC")
    assert "3 of 3 switches reached - every one answered" in f[2]
    assert "3 of 4 compute trays reached; NOT reached: ct03" in f[3]
    assert "not a reachability problem: ct02 (afmctl did not run)" in f[4]
    assert "NOT reached: ct03 - no route to host" in f[5] and "run Health again" in f[6]
    scan2 = {"time_utc": "x", "not_checked": [{"node": "ct06", "error": "CommandError: [ct06] rc=112: afmctl show port"}]}
    assert "ct06 answered, but a read failed" in reach.facts(sw, ct, [], health, "h", scan2, "s")[5]
    assert "No health check" in reach.facts(sw, ct, [], None, "", None, "")[1]
