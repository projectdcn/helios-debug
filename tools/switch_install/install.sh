#!/usr/bin/env bash
# helios-debug UI installer for a switch tray (SONiC) - or any Linux host with python3 >= 3.10, PyYAML and paramiko.
#
#   tar -xzf helios-debug-ui-<version>.tar.gz && helios-debug-ui-<version>/install.sh [--no-start]
#
# No sudo, nothing outside the user's home: installs to $PREFIX (default ~/helios-debug-ui), uses the system python3
# and its PyYAML / paramiko (SONiC ships both), keeps the previous version as app.prev (rollback.sh), keeps the
# inventories and results across upgrades. Creates an SSH key for reaching the compute trays (and other switches) if
# none exists; you copy it to them once. The UI listens on 127.0.0.1 only - open it through an SSH tunnel.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=${PREFIX:-$HOME/helios-debug-ui}
PORT=${PORT:-8780}
KEY=${KEY:-$HOME/.ssh/id_ed25519_heliosdbg}
START=1
for a in "$@"; do
  case "$a" in
    --no-start) START=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done

echo "== checking python3"
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    sys.exit(f"python3 {sys.version.split()[0]} is too old (3.10+ needed)")
missing = []
for m in ("yaml", "paramiko"):
    try:
        __import__(m)
    except ImportError:
        missing.append(m)
if missing:
    sys.exit("missing python modules: " + ", ".join(missing) + " (SONiC ships both; elsewhere: pip install --user PyYAML paramiko)")
import yaml, paramiko
print(f"   python {sys.version.split()[0]}, PyYAML {yaml.__version__}, paramiko {paramiko.__version__}")
PY

mkdir -p "$PREFIX/inventory" "$PREFIX/results"
if [ -x "$PREFIX/stop.sh" ]; then "$PREFIX/stop.sh" || true; fi

echo "== installing to $PREFIX"
if [ -d "$PREFIX/app" ]; then rm -rf "$PREFIX/app.prev"; mv "$PREFIX/app" "$PREFIX/app.prev"; fi
cp -a "$HERE/app" "$PREFIX/app"
cp "$HERE/BUILD_INFO.json" "$PREFIX/app/" 2>/dev/null || true
for f in "$HERE"/inventory/*.yaml; do               # bundled inventories: never overwrite one already there
  [ -e "$f" ] || continue
  if [ -e "$PREFIX/inventory/$(basename "$f")" ]; then echo "   kept inventory/$(basename "$f")"
  else cp "$f" "$PREFIX/inventory/"; echo "   added inventory/$(basename "$f")"; fi
done

if [ ! -f "$KEY" ]; then
  echo "== creating the SSH key $KEY (for the compute trays / other switches)"
  mkdir -p "$(dirname "$KEY")"; chmod 700 "$(dirname "$KEY")"
  ssh-keygen -q -t ed25519 -N "" -C "helios-debug-ui@$(hostname)" -f "$KEY"
fi

if [ ! -f "$PREFIX/ui.env" ]; then
  cat > "$PREFIX/ui.env" <<EOF
# helios-debug UI settings (read by start.sh). No passwords here.
HELIOS_SSH_KEY=$KEY
HELIOS_DEBUG_AUTO_LOCAL=1
HELIOS_DEBUG_UI_PORT=$PORT
HELIOS_DEBUG_INVENTORY_DIR=$PREFIX/inventory
HELIOS_DEBUG_RESULTS_DIR=$PREFIX/results
EOF
fi

cat > "$PREFIX/start.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
P=$(cd "$(dirname "$0")" && pwd)
if [ -f "$P/ui.pid" ] && kill -0 "$(cat "$P/ui.pid")" 2>/dev/null; then echo "already running (pid $(cat "$P/ui.pid"))"; exit 0; fi
set -a; . "$P/ui.env"; set +a
cd "$P/app"
nohup python3 -m ui >> "$P/ui.log" 2>&1 &
echo $! > "$P/ui.pid"
sleep 1
if kill -0 "$(cat "$P/ui.pid")" 2>/dev/null; then
  echo "helios-debug UI running (pid $(cat "$P/ui.pid")) on 127.0.0.1:$HELIOS_DEBUG_UI_PORT - log $P/ui.log"
else
  echo "did not start - see $P/ui.log"; tail -5 "$P/ui.log"; exit 1
fi
EOF
cat > "$PREFIX/stop.sh" <<'EOF'
#!/usr/bin/env bash
P=$(cd "$(dirname "$0")" && pwd)
if [ -f "$P/ui.pid" ] && kill -0 "$(cat "$P/ui.pid")" 2>/dev/null; then kill "$(cat "$P/ui.pid")"; echo "stopped"; else echo "not running"; fi
rm -f "$P/ui.pid"
EOF
cat > "$PREFIX/status.sh" <<'EOF'
#!/usr/bin/env bash
P=$(cd "$(dirname "$0")" && pwd)
if [ -f "$P/ui.pid" ] && kill -0 "$(cat "$P/ui.pid")" 2>/dev/null; then echo "running (pid $(cat "$P/ui.pid"))"; else echo "not running"; fi
python3 -c "import json;print('version', json.load(open('$P/app/BUILD_INFO.json'))['version'])" 2>/dev/null || true
EOF
cat > "$PREFIX/rollback.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
P=$(cd "$(dirname "$0")" && pwd)
[ -d "$P/app.prev" ] || { echo "no previous version to roll back to"; exit 1; }
"$P/stop.sh" || true
mv "$P/app" "$P/app.rollback-tmp"; mv "$P/app.prev" "$P/app"; mv "$P/app.rollback-tmp" "$P/app.prev"
"$P/start.sh"
EOF
chmod +x "$PREFIX"/start.sh "$PREFIX"/stop.sh "$PREFIX"/status.sh "$PREFIX"/rollback.sh

if [ "$START" = 1 ]; then "$PREFIX/start.sh"; fi

ME=$(whoami); HOSTN=$(hostname)
cat <<EOF

== done
Inventories: $PREFIX/inventory   (copy your rack's inventory there; the switch this runs on is read directly)
Results:     $PREFIX/results/link-check/<rack>/
Control:     $PREFIX/start.sh | stop.sh | status.sh | rollback.sh   (log: $PREFIX/ui.log)

1. Let the UI reach the compute trays (once per tray; and the other switches of a full rack): in the UI's
   SSH access tab (Check all, then the tray's password -> Install key), or from this switch:
     ssh-copy-id -i $KEY.pub <tray user>@<tray address>
   This key: $(cat "$KEY.pub")

2. Open the UI from your own machine through an SSH tunnel:
     ssh -L $PORT:localhost:$PORT $ME@<this switch's address>      ($HOSTN)
   then browse http://localhost:$PORT

The UI does not start by itself after a reboot: run $PREFIX/start.sh. A SONiC image upgrade may not keep \$HOME -
reinstall the bundle then.
EOF
