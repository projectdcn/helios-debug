"""Build the helios-debug UI bundle for a switch tray (or any Linux host with python3 >= 3.10, PyYAML, paramiko).

    python3 tools/build_switch_bundle.py                                  # dist/helios-debug-ui-<date>-<commit>.tar.gz
    python3 tools/build_switch_bundle.py --inventory inventory/mr3.local.yaml   # + that inventory (no passwords in it)

Only committed code goes in (git archive of --ref, default HEAD). Install on the switch:

    scp dist/helios-debug-ui-<v>.tar.gz admin@<switch>: && ssh admin@<switch> 'tar -xzf helios-debug-ui-<v>.tar.gz && helios-debug-ui-<v>/install.sh'

No Python packages are bundled: SONiC's python3 has PyYAML and paramiko, and the bundle runs on them.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ["heliosdbg", "ui", "tools/link_check.py", "tools/md_to_html.py", "docs", "README.md", "pyproject.toml",
       "inventory/example.yaml", "inventory/example-fullrack.yaml"]
SECRET_RX = re.compile(r"^\s*(password|passwd|token|secret)\s*:\s*\S", re.I | re.M)


def git(*a: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *a], check=True, capture_output=True, text=True).stdout.strip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", default="HEAD", help="commit to package (default HEAD; only committed code goes in)")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--inventory", action="append", default=[], type=Path,
                    help="also bundle this inventory (repeatable); refused if it holds a password")
    a = ap.parse_args(argv)
    commit = git("rev-parse", "--short", a.ref)
    full = git("rev-parse", a.ref)
    version = f"{time.strftime('%Y%m%d')}-{commit}"
    name = f"helios-debug-ui-{version}"
    for inv in a.inventory:
        text = inv.read_text()
        if SECRET_RX.search(text):
            print(f"refusing {inv}: it holds a password / token - use password_env and key login", file=sys.stderr)
            return 2
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / name
        app = stage / "app"
        app.mkdir(parents=True)
        tar_bytes = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", a.ref, *APP],
                                   check=True, capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as t:
            t.extractall(app, filter="data") if sys.version_info >= (3, 12) else t.extractall(app)  # noqa: S202
        shutil.copy2(ROOT / "tools" / "switch_install" / "install.sh", stage / "install.sh")
        (stage / "install.sh").chmod(0o755)
        (stage / "inventory").mkdir()
        for inv in a.inventory:
            shutil.copy2(inv, stage / "inventory" / inv.name)
        info = {"version": version, "commit": full, "commit_date": git("show", "-s", "--format=%ci", a.ref),
                "built": time.strftime("%Y-%m-%d %H:%M:%S %z"), "inventories": [p.name for p in a.inventory]}
        (stage / "BUILD_INFO.json").write_text(json.dumps(info, indent=1) + "\n")
        a.out.mkdir(parents=True, exist_ok=True)
        dest = a.out / f"{name}.tar.gz"
        with tarfile.open(dest, "w:gz") as t:
            t.add(stage, arcname=name)
        n = sum(1 for p in stage.rglob("*") if p.is_file())
    print(f"{dest}  ({dest.stat().st_size / 1e6:.1f} MB, {n} files{', inventories: ' + ', '.join(info['inventories']) if a.inventory else ''})")
    print(f"install: scp {dest.name} admin@<switch>: && ssh admin@<switch> 'tar -xzf {dest.name} && {name}/install.sh'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
