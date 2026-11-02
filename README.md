# helios-debug

Debug tools for AMD Helios racks - the scale-up fabric, SONiC switch trays, compute trays / GPUs and AFM - separate from the test-case automation (helios-tests).

- **Link check** (`tools/link_check.py` scan | link | watch | cabling | bcm | path | pingmap | isolate): every GPU link of a rack (switch port <-> GPU port), its state
  (ok / degraded / down) and, for each problem, one root cause with the evidence, who owns the fix and the next step.
  Also each GPU's state (`afmctl` config phase), and with the AFM password set (optional, `afm:` block in the
  inventory) AFM's view: vPOD membership, accelerator ids and port state. Read-only, SSH (+ AFM GETs). Runs on
  any rack described by an inventory.
- **Node health** (`tools/link_check.py health`, `heliosdbg/health.py`): every switch tray, compute tray and AFM beyond
  the links - SONiC (system health, containers and restarts, critical daemons, CRM tables, disk, memory, core files,
  reboot cause, syslog errors grouped by message, running vs saved configuration), the switch platform (PSUs, fans,
  temperatures, voltages, watchdog), the compute trays (amd-smi GPUs, ECC, PCIe, afmctl GPU state, kernel errors incl.
  machine checks, disk, memory, RDMA NIC ports, failed services) and AFM (agent, controller and agent certificates; with
  the password, AFM's view of the compute nodes). One finding per problem - area, owner, next step, evidence - and the
  same finding on many nodes as one rack-wide finding; a check whose command is missing or fails is listed as not
  checked, never as healthy. Read-only.
  Platforms (`heliosdbg/platforms/`): what is checked on a kind of node is one module - `sonic`, `afm` (switch + tray +
  AFM's API view), `amd_gpu`, `linux`, `rdma` (scale-out NICs: why a port is down from the NIC's own `nicctl`, optics,
  flaps, drop counters, firmware mixed on a tray or different between trays). A node gets its role's defaults or the
  inventory's `platforms: [linux, rdma]`; a new GPU vendor or switch OS is a new module. The core is `heliosdbg/checks.py`.
  A node SSH cannot reach is asked through its **BMC** (Redfish, `heliosdbg/bmc.py`): powered off with the event log,
  on but the OS silent, or the BMC silent too (no power / management network). Every access failure says why
  (`heliosdbg/reach.py`): login refused for the user, no route, timed out, SSH refused, host key changed, the jump host's
  session limit.
- **Debug a node** (web UI): describe a symptom on any node; the AI proposes one read-only command at a time (allow-list
  per kind of node, including the health commands), you click Run, it reads the output - until it names the cause.
- **Debug guide** (`docs/link-debug-guide.md`, `docs/link-debug-guide.html` to share; regenerate with `python3 tools/md_to_html.py docs/link-debug-guide.md`): how to isolate a link problem by hand, layer by layer, with every
  command, and the abbreviations.
- **Topology** (`docs/scaleup-topology.html`): how the GPUs / compute trays are cabled to the switch trays (planes,
  ports per switch, tray resources). The resource table is the g02-g17 rack's.

## Install

```bash
/opt/homebrew/bin/python3 -m venv .venv    # Python 3.10 or newer
.venv/bin/pip install -e .                  # paramiko, PyYAML
```

On macOS the system `python3` (`/usr/bin/python3`) is 3.9, too old: `pip install -e .` refuses it and the tool then
fails with `No module named 'yaml'`. Create the venv with a newer Python (Homebrew, python.org, pyenv). The YAML
package is called `PyYAML` on pip, not `yaml`.

## Inventory

The tool needs only the rack's switch trays and compute trays and how to log in to them:

| File | What |
| --- | --- |
| `inventory/example-fullrack.yaml` | full rack template: 6 switch trays + 18 compute trays (2,592 links) |
| `inventory/example.yaml` | minimal template with comments |
| `inventory/<rack>.local.yaml` | your rack (git-ignored); e.g. `g02-g17.local.yaml` |

Copy a template to `inventory/<rack>.local.yaml` and fill in the management addresses and users. `slot:` (the tray's
AFM slot) is optional: it is learned from the switch port descriptions and the GPU ports' MACs. Mark a tray that is
out of service with `quarantine:` so its links show as one cause. Logins use your SSH setup (`~/.ssh/config`,
ssh-agent, `key_file`); for passwords, `password_env` names an environment variable you set yourself. Never put a
password in the file. Rack behind a bastion: `transport.jump`. The compute tray user needs sudo without a prompt for
`afmctl`. `$HELIOS_INVENTORY` can replace `--inventory`.

## Run

```bash
.venv/bin/python tools/link_check.py scan --inventory inventory/<rack>.local.yaml
.venv/bin/python tools/link_check.py scan --inventory inv.yaml --interval 120 --compare <earlier>/link_check.json
.venv/bin/python tools/link_check.py pingmap --inventory inv.yaml --rounds 12 --wait 300
.venv/bin/python tools/link_check.py path --inventory inv.yaml --src ct03 --src-bdf 0004:01:00.1 --dst-acc 8 --ports 25,26
.venv/bin/python tools/link_check.py bcm --inventory inv.yaml --switch st6 --ports Ethernet257,Ethernet261
.venv/bin/python tools/link_check.py health --inventory inv.yaml [--only switches|trays] [--switches st1] [--trays ct07] [--no-drift]
.venv/bin/python tools/link_check.py health --inventory inv.yaml --every 30 --incidents http://10.83.2.15:8443
```

- `health`: report.html / report.txt / health.json + raw/outputs.json.gz under `results/link-check/<rack>/health-<time>/`;
  exit 1 when there are findings. Thresholds: `thresholds: {health: {disk_warn: 85, crm_warn: 85, gpu_hot: 100, ...}}`
  in the inventory. The AI (Ask / step by step) reads a health result as evidence, for the whole rack or one node, with
  a health prompt (each finding in its own area, the health commands).
  - BMC view: inventory `bmc:` (address) and `bmc_user:` per node or under `defaults:`; the password from
    `$HELIOS_BMC_PASSWORD` (or `_<NODE>`; the UI's BMC view field, this run only) - never in the inventory. Through a
    jump host `curl` runs there with the login on stdin. Without the password only the BMCs of nodes SSH did not reach
    are asked whether they answer. `--no-bmc` skips it.
  - Over time: each run is compared with the rack's previous one (new / gone / grew, per node, over nodes checked both
    times) in report.txt, report.html and the UI; `health-history.jsonl` keeps one line per run. `--every 30
    [--count N]` repeats it; `--keep 48` (default) thins older runs to their health.json - mind a small disk.
  - `--incidents http://10.83.2.15:8443` sends the new findings (critical first, `--incidents-max 10`, or all with
    `--incidents-all`) to the AIOps incident API (helios-slm): the finding as the alert, its outputs as evidence, an id
    from the rack and the finding so the next run replaces it.
  - Per finding in the UI: **ticket** (Markdown for its owner, every fact from the check) and **evidence.zip** (the
    ticket, the finding, its node's raw outputs only, report.html); `/api/health/ticket`, `/api/bundle?finding=N`.

- `scan`: every link; counters sampled twice (`--interval`, 30 s) so only growing errors count; patterns across
  problem links (several on one GPU, the same GPU position on many trays, adjacent ports on one ASIC); cabling checked
  against IFCP (miscabled). `--switches st6` checks one switch tray (432 links on a full rack: 72 GPUs x 6
  ports; every compute tray is still read, they are the other end); `--trays ct13,ct14` keeps only those trays' links.
- `scan` also reads the Broadcom shell (`bcmcmd`, read-only lookups) for physical-layer problem links: signal
  detect, receiver lock, link training, SNR / eye per lane - e.g. "no signal on any lane while transmitting" vs "one
  lane dark". `--no-bcm` skips it, `--bcm-max` (64) caps it.
- `bcm`: that Broadcom view for chosen ports of one switch (default: every oper-down trunk port).
- `pingmap`: a ring of L2 pings repeated N rounds; loss per GPU port number / switch ASIC, sticky or moving.
- `path`: one GPU-to-GPU path port by port: tray side, IFCP, forwarding entries, an L2 ping (`--no-ping` to skip)
  and the counters around it.

Output (`--out`, default `results/link-check/<rack>/<UTC time>/`): `report.html` (self-contained, to share: notes on
what was and was not checked, root causes, the switch ASIC to GPU map, every link with both ends' state, and a command
log per switch / tray - each command, its exit code and output, trimmed to `--log-keep` lines), `report.txt`,
`link_check.json`, raw outputs (`raw/*.json.gz`) and the full command log (`raw/commands.log.gz`; `commands.log.gz` for
`path`, `pingmap` and `bcm`). A scan needs ~50 MB free.

## Web UI on a switch tray

`ui/` is a small web UI for the same tools: Start here (rack, access, a check of all links, then what it found in
plain words), Simple / Expert mode, Overview of all racks, Rack map (by compute tray, by switch ASIC, or topology)
with drill down from rack to tray, GPU, port and link - each level with its connectivity picture, Topology tab for
the rack chosen at the top (drill down beside the drawing), Diagnose a link (with timeline and what is around it),
Watch links, Cabling plan, scan / Broadcom / GPU path / ping map, Isolate (disruptive, typed confirmation), History
with evidence bundles, SSH access with a browser terminal, Config (a node's configuration), Add a rack, the debug
guide, and AI advice (root cause / how to debug / what to do) on link pages, Diagnose results and the Topology tab -
and on any problem (*Any problem* tab): a helios-tests result with its log (`HELIOS_TESTS_RESULTS`, default
`~/dev/helios-tests/results`), a saved tool report, or command outputs / logs pasted from any node (`heliosdbg/cases.py`;
helios-slm's training hub builds its taught cases with the same code).
The views are a menu down the left. Standard library only: it installs on a SONiC switch tray and runs on the switch's own
python3, PyYAML and paramiko - no sudo, nothing outside the user's home.

```
python3 tools/build_switch_bundle.py [--inventory inventory/mr3.local.yaml]     # on your machine
scp dist/helios-debug-ui-<v>.tar.gz admin@<switch>:
ssh admin@<switch> 'tar -xzf helios-debug-ui-<v>.tar.gz && helios-debug-ui-<v>/install.sh'
```

- Installs to `~/helios-debug-ui` (`app/`, `inventory/`, `results/`, `start.sh` / `stop.sh` / `status.sh` /
  `rollback.sh`); the previous version is kept as `app.prev`; inventories and results survive upgrades.
- Creates `~/.ssh/id_ed25519_heliosdbg` if missing: copy it once to each compute tray (and the other switches of a
  full rack) with `ssh-copy-id -i ~/.ssh/id_ed25519_heliosdbg.pub <user>@<tray>`. The switch the UI runs on is
  read directly, not over SSH (its address is one of the machine's own).
- Listens on 127.0.0.1:8780 only. From your machine: `ssh -L 8780:localhost:8780 admin@<switch>`, then
  http://localhost:8780. Requests with another Host header, or a POST without the UI's own header, are refused.
- SSH access tab: checks a key login + sudo on every node of the inventory; where it fails, type that node's
  password once and the UI installs the key the tools use there (like ssh-copy-id, through the jump host if
  the inventory has one). The password is used for that one login and kept nowhere.
- Live mode (Rack map): off by default; follows the switch / tray logs and re-reads periodically so the map
  changes as links change; one rack at a time, stops by itself after 8 h / 24 h / 3 days or runs until turned off
  (your choice), and 30 min after no page is open unless 'keep on when no page is open' is ticked.
- The AFM password for a scan's AFM view is typed in the page, handed to that one run in its environment and kept
  nowhere else.
- Topology tab: Links / IFCP / VLAN views of the rack's newest full check (a newer one-switch or empty check is noted
  above it); switches a check could not judge are drawn dashed with why (e.g. forwarding entries without a switch
  port, which make SONiC's `show mac` fail); colour legend with the counts.
- Terminal (Access to the rack): a real shell on a switch / compute tray, logged in the way the checks are (inventory
  key; `ssh -tt` on the jump host for `transport.jump via: exec`; a local pty on the node the UI runs on). Not
  read-only. Only open / close is logged (`results/term/sessions.log`), never what is typed; at most 6, closed 5 min
  after their page is gone. The emulator is xterm.js 5.5.0 (MIT), vendored in `ui/static/vendor/xterm/`.
- Config tab (read only): a switch's SONiC CONFIG_DB of the host and each ASIC (`sonic-cfggen -d --print-data`) as
  filterable tables; a compute tray's GPUs and ports from afmctl and its OS basics; Download JSON.
- AI advice (`heliosdbg/ai.py`): an OpenAI-compatible model server - by default helios-slm's on this machine,
  `http://127.0.0.1:8090/v1` (`HELIOS_AI_URL`, `HELIOS_AI_MODEL`, `HELIOS_AI_KEY`; `HELIOS_AI_URL=off` disables).
  The model gets the saved result's evidence, numbered [E1].. (never the rack live), and answers root cause, read-only
  debug steps and remediation with citations. Advisory: steps that change the rack, commands on the wrong kind of
  node and citations to evidence it was not given are flagged. For the UI on a jump host, forward your model in the
  same SSH session as the UI: `ssh -N -L 8780:localhost:8780 -R 8090:127.0.0.1:8090 ...` (anyone who can log in to
  that jump host account can then use the model while the session is open).
- Not started at boot: run `~/helios-debug-ui/start.sh`. A SONiC image upgrade may not keep the home directory.

On your own machine: `python3 -m ui` in this repo (inventories from `inventory/`, results in `results/`).

## Tests

```bash
.venv/bin/pip install -e '.[test]' && .venv/bin/pytest tests
```

## Layout

```
heliosdbg/   health.py (node health) over checks.py (core) and platforms/ (sonic, afm, amd_gpu, linux, rdma), bmc.py (Redfish),
             reach.py (why a node could not be reached), history.py (health over time), incidents.py (to the incident API),
             ticket.py / bundle.py (tickets and evidence zips),
             linkdiag.py (join + root cause), bcm.py (Broadcom shell view), sonic.py / afmctl.py / parsers.py (read and parse), inventory.py,
             transport.py (SSH, jump host), rack.py, compute.py, afm.py (read-only AFM client, standard library),
             live.py (live mode), term.py (browser terminals), config_view.py (Config tab), ai.py (AI advice)
ui/          server.py (web UI, standard library), access.py, static/index.html, static/vendor/xterm/ (terminal emulator)
tools/       link_check.py
docs/        link-debug-guide.md, scaleup-topology.html
inventory/   templates (+ your git-ignored *.local.yaml)
```

Repository: [projectdcn/helios-debug](https://github.com/projectdcn/helios-debug). The test automation and its web UI
are in [projectdcn/helios-tests](https://github.com/projectdcn/helios-tests); its rack health check runs this repo's
scan as HC-012 and its UI installer bundles this repo.

`heliosdbg/{sonic,afmctl,parsers,inventory,transport,compute}.py` started as copies of helios-tests' `helios/`
modules (18 Oct 2026); the two repos are independent from here on.
