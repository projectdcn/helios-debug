# helios-debug

Debug tools for the AMD Helios scale-up fabric, separate from the test-case automation (helios-tests).

- **Link check** (`tools/link_check.py`): every GPU link of a rack (switch port <-> GPU port), its state
  (ok / degraded / down) and, for each problem, one root cause with the evidence, who owns the fix and the next step.
  Read-only, SSH only, no AFM password. Runs on any rack described by an inventory.
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
```

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

## Tests

```bash
.venv/bin/pip install -e '.[test]' && .venv/bin/pytest tests
```

## Layout

```
heliosdbg/   linkdiag.py (join + root cause), bcm.py (Broadcom shell view), sonic.py / afmctl.py / parsers.py (read and parse), inventory.py,
             transport.py (SSH, jump host), rack.py, compute.py
tools/       link_check.py
docs/        link-debug-guide.md, scaleup-topology.html
inventory/   templates (+ your git-ignored *.local.yaml)
```

`heliosdbg/{sonic,afmctl,parsers,inventory,transport,compute}.py` started as copies of helios-tests' `helios/`
modules (18 Oct 2026); the two repos are independent from here on.
