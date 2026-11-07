#!/usr/bin/env python3
"""Upgrade a helios-debug copy elsewhere to this checkout's committed code - one command, the same checks each time.

    python tools/deploy.py <target> [--dry-run] [--ref HEAD]

The targets live in inventory/deploy.local.yaml (git-ignored: host names stay out of the repository):

    targets:
      jump:                                   # an installed UI (tools/switch_install/install.sh)
        kind: ui
        ssh: user@host                        # plus port: 22 when it is another one
        prefix: ~/helios-debug-ui
        python: ~/helios/venv/bin/python      # PYTHON= of install.sh
        key: ~/.ssh/id_cluster                # KEY= of install.sh
        ui_port: 8780
        min_free_mb: 300
      srv03:                                  # a library copy helios-slm imports (HELIOS_DEBUG), no UI
        kind: library
        ssh: root@host
        path: /root/helios-gpu/helios-debug
        python: /root/helios-gpu/venv/bin/python

Each upgrade: refuses uncommitted changes (only committed code goes out), checks the free space there, waits for
nothing - an installed UI that is busy (a running job, Live, an open terminal: /api/version) or a running
link_check.py is refused, not interrupted. A ui target: the bundle (build_switch_bundle.py, no inventories - the
installed ones are kept), install.sh keeps the old version as app.prev (rollback.sh), then /api/version must name the
new commit. A library target: the old heliosdbg/ui/tools go to <path>.bak-<UTC>, the new ones are unpacked, and
heliosdbg imports with the target's python. --dry-run runs the checks and changes nothing.
"""
from __future__ import annotations

import argparse
import io
import json
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONF = ROOT / "inventory" / "deploy.local.yaml"
LIBRARY = ["heliosdbg", "ui", "tools", "docs", "pyproject.toml", "README.md"]


class DeployError(Exception):
    pass


def git(*a: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *a], check=True, capture_output=True, text=True).stdout.strip()


def ssh_cmd(t: dict) -> list[str]:
    # one connection for every step (ControlMaster): a busy sshd (the jump host, 7 Nov: 'timed out during banner
    # exchange' on every other login) is asked for one login, not ten
    return ["ssh", "-o", "ConnectTimeout=30", "-o", "BatchMode=yes", "-o", "ControlMaster=auto",
            "-o", "ControlPath=~/.ssh/cm-deploy-%r@%h:%p", "-o", "ControlPersist=120"] + (
        ["-p", str(t["port"])] if t.get("port") else []) + [t["ssh"]]


def remote(t: dict, script: str, data: bytes | None = None, check: bool = True) -> str:
    for attempt in range(4):                       # rc 255 is ssh's own failure (no login), not the command's
        r = subprocess.run(ssh_cmd(t) + ["bash -s" if data is None else script], input=script.encode() if data is None else data,
                           capture_output=True, timeout=600)
        if r.returncode != 255 or attempt == 3:
            break
        time.sleep(10 * (attempt + 1))
    out = r.stdout.decode(errors="replace")
    if check and r.returncode:
        raise DeployError(f"on {t['ssh']}: rc={r.returncode}: {r.stderr.decode(errors='replace').strip()[-400:]}")
    return out


def free_mb(t: dict, path: str) -> int:
    out = remote(t, f"df -Pm {path} 2>/dev/null | tail -1")
    return int(out.split()[3])


def preflight(t: dict, need_mb: int) -> list[str]:
    """What stops the upgrade: too little space, a busy UI, a running link check."""
    stop = []
    where = t.get("prefix") or t.get("path")
    parent = f"$(d={where}; while [ ! -d \"$d\" ]; do d=$(dirname \"$d\"); done; echo \"$d\")"
    free = free_mb(t, parent)
    want = max(need_mb, int(t.get("min_free_mb", 0)))
    print(f"   free space: {free} MB (needs {want} MB)")
    if free < want:
        stop.append(f"only {free} MB free where it installs - free some first (needs {want} MB)")
    if t["kind"] == "ui":
        port = int(t.get("ui_port", 8780))
        v = remote(t, f"curl -s -m 5 http://127.0.0.1:{port}/api/version || true")
        try:
            info = json.loads(v)
        except ValueError:
            info = None
        if not isinstance(info, dict) or "version" not in info:
            print("   UI: no version reported (not running, or older than /api/version - it cannot say whether it is busy)")
        else:
            print(f"   UI: {info.get('version')} - busy {info.get('busy')}")
            if not info.get("idle", True):
                stop.append(f"the UI is busy: {info.get('busy')} - wait until no job, Live or terminal is open")
    runs = remote(t, "pgrep -af '[t]ools/link_check.py' || true").strip()
    if runs:
        stop.append(f"a link check is running there: {runs.splitlines()[0][:160]}")
    return stop


def deploy_ui(t: dict, ref: str, dry: bool) -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    import build_switch_bundle
    out = ROOT / "dist"
    before = set(out.glob("helios-debug-ui-*.tar.gz"))
    if build_switch_bundle.main(["--ref", ref, "--out", str(out)]):
        raise DeployError("the bundle did not build")
    tgz = max(set(out.glob("helios-debug-ui-*.tar.gz")) - before or out.glob("helios-debug-ui-*.tar.gz"),
              key=lambda p: p.stat().st_mtime)
    mb = tgz.stat().st_size // 1_000_000 + 1
    stop = preflight(t, mb * 4 + 20)               # tarball + unpacked + app.prev
    if stop:
        raise DeployError("not upgraded: " + "; ".join(stop))
    if dry:
        print(f"   dry run: would install {tgz.name} to {t['prefix']}")
        return
    name = tgz.name[:-len(".tar.gz")]
    env = " ".join(f"{k}={shlex.quote(str(t[c]))}" for k, c in (("PYTHON", "python"), ("KEY", "key")) if t.get(c))
    tmp = f"/tmp/{name}-{int(time.time())}"
    remote(t, f"mkdir -p {tmp} && tar -xzf - -C {tmp}", data=tgz.read_bytes())
    print(remote(t, f"PREFIX={t['prefix']} {env} {tmp}/{name}/install.sh; rc=$?; rm -rf {tmp}; exit $rc").strip()[-1200:])
    want = git("rev-parse", ref)
    time.sleep(2)
    v = remote(t, f"curl -s -m 10 http://127.0.0.1:{int(t.get('ui_port', 8780))}/api/version || true")
    try:
        got = json.loads(v).get("commit")
    except ValueError:
        got = None
    if got != want:
        raise DeployError(f"installed, but the UI reports commit {got!r}, not {want[:7]} - see {t['prefix']}/ui.log; "
                          f"{t['prefix']}/rollback.sh brings the old version back")
    print(f"   ok: the UI runs {want[:7]}")


def deploy_library(t: dict, ref: str, dry: bool) -> None:
    buf = io.BytesIO(subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", ref, *LIBRARY],
                                    check=True, capture_output=True).stdout)
    info = {"version": f"{time.strftime('%Y%m%d')}-{git('rev-parse', '--short', ref)}", "commit": git("rev-parse", ref),
            "built": time.strftime("%Y-%m-%d %H:%M:%S %z")}
    with tarfile.open(fileobj=buf, mode="a") as tf:
        b = (json.dumps(info, indent=1) + "\n").encode()
        ti = tarfile.TarInfo("BUILD_INFO.json")
        ti.size, ti.mtime = len(b), int(time.time())
        tf.addfile(ti, io.BytesIO(b))
    data = buf.getvalue()
    stop = preflight(t, len(data) // 1_000_000 * 3 + 20)
    if stop:
        raise DeployError("not upgraded: " + "; ".join(stop))
    p = t["path"]
    if dry:
        print(f"   dry run: would back up {p}/{{heliosdbg,ui,tools}} and unpack {info['version']} there")
        return
    bak = f"{p}.bak-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"
    remote(t, f"set -e; mkdir -p {bak}; cd {p}; for d in heliosdbg ui tools BUILD_INFO.json; do [ -e $d ] && cp -a $d {bak}/; done; "
              f"rm -rf heliosdbg ui tools; tar -xf - -C {p}", data=data)
    py = t.get("python") or "python3"
    out = remote(t, f"cd {p} && {py} -c 'import heliosdbg.ai, heliosdbg.rackfacts, heliosdbg.guide; print(\"imports ok\")'", check=False)
    if "imports ok" not in out:
        raise DeployError(f"unpacked, but heliosdbg does not import there: {out.strip()[-300:]} - the old copy is in {bak}")
    print(f"   ok: {p} is {info['version']} (old copy: {bak})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("target")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ref", default="HEAD")
    a = ap.parse_args(argv)
    import yaml
    if not CONF.is_file():
        print(f"no {CONF.relative_to(ROOT)} - see the top of this file for its format", file=sys.stderr)
        return 2
    targets = (yaml.safe_load(CONF.read_text()) or {}).get("targets") or {}
    t = targets.get(a.target)
    if not t:
        print(f"unknown target {a.target!r} - {CONF.name} has: {', '.join(targets) or 'none'}", file=sys.stderr)
        return 2
    if git("status", "--porcelain", "--untracked-files=no") and a.ref == "HEAD":
        print("uncommitted changes - commit them first (only committed code is deployed)", file=sys.stderr)
        return 2
    print(f"== {a.target} ({t['ssh']}, {t['kind']}): {git('log', '-1', '--format=%h %s', a.ref)[:100]}")
    try:
        (deploy_ui if t["kind"] == "ui" else deploy_library)(t, a.ref, a.dry_run)
    except (DeployError, subprocess.SubprocessError, OSError) as e:
        print(f"   {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
