# Helios Debug Guide

4 Nov 2026

A scale-up link has three ends to check: the switch ASIC port, the cable and optics between, and the GPU's IFoE port on the compute tray, with AFM and IFCP layered on top. Work from the bottom up: physical link on both ends, then the IFCP session, then what AFM reports, then an L2 ping. Stop at the first layer that disagrees. Abbreviations are explained at the end, under Abbreviations and terms.

## Triage at a glance

1. **Is the physical link up on both ends?** Switch port oper up and GPU port LINK\_UP. No: Layer 1.
2. **Is the IFCP session up?** `ll_up` and `peer_enabled` yes, no errors. No: IFCP session.
3. **Does AFM agree?** PortReady on the switch node and the compute node. No: What AFM reports.
4. **Does an L2 ping pass on every port?** No: Data path.

Each question is one section below; a "no" sends you to the layer at fault, and only a link that passes all four is healthy.

When the problem is not one link (many links, a whole switch or tray, a failure with every link up), check the nodes first: Node health, then SONiC switch OS, Switch platform, Compute trays and GPUs, and AFM health below.

## Run the link check tool first

`tools/link_check.py` does this whole guide in one run: it checks every GPU link of a rack and names the root cause of each one that is down or degraded. It works on any rack described by an inventory (`inventory/example-fullrack.yaml`, see the README), needs SSH (with sudo) to the switch and compute trays; the AFM password is optional (see GPU state and the AFM view below). It only reads, except for one L2 ping in `path` mode.

```
python tools/link_check.py scan --inventory <inventory>
python tools/link_check.py path --inventory <inventory> --src <tray> --src-bdf 0004:01:00.1 --dst-acc 8 --ports 25,26
```

`scan` matches every switch port to the GPU port cabled to it by that GPU port's own MAC in the switch's forwarding table, so it needs no rack-specific naming. It reads the counters twice, 30 s apart by default (`--interval`), so errors count only when they grow. `path` checks one GPU-to-GPU path port by port, including both forwarding entries, the ping and the counters around it.

It writes `report.html` (self-contained, to share with a customer), `report.txt`, `link_check.json` and the raw outputs it read to `results/link-check/<rack>/`. The causes it reports, checked bottom layer first:

| Cause | State | Owner | Next step it gives |
| --- | --- | --- | --- |
| Compute tray not reachable, or quarantined in the inventory | down | operator / site | check tray power and BMC; one line for all of the tray's links |
| Switch port administratively down | down | operator | `config interface startup` |
| GPU port administratively disabled | down | operator | `afmctl update port ... --admin-state enable` |
| No physical link on either end, never up since the tray booted | down | site (cabling) | reseat or swap the cable; a fault that stays on the port belongs to that side |
| No physical link on either end, went down after being up (with how long) | down | site (cabling) | as above; check what changed at that time |
| One-sided link: the two ends disagree | down | site (cabling) | verify the cable lands where the description says |
| Bit errors growing on a link that is up | degraded | site (cabling) | reseat, sample again, swap if they follow the cable |
| Physical link up but no IFCP session | degraded | GPU / AFM vendor | collect the port's `afmctl` output and raise it |
| Link up but not programmed by AFM (still missing on a second read) | degraded | GPU / AFM vendor | check the GPU is in a vPOD and PortReady in AFM |
| GPU not configured on the tray (`config_phase` not ACTIVE while other GPUs are) | degraded | GPU / AFM vendor | check its vPOD membership in AFM; reconfigure the tray from AFM if it should be in one |
| GPU in a vPOD in AFM but not programmed on the tray (AFM view) | down | GPU / AFM vendor | reconfigure the compute tray from AFM; raise it if a GPU reset leaves it unprogrammed |
| AFM reports the GPU port failed although the link and IFCP are up (AFM view) | degraded | GPU / AFM vendor | compare with the AFM events for the port; raise it if the link stays up |

It also checks the cabling: each GPU port's IFCP session names the switch and port it really reaches, and a link whose IFCP peer is not its described switch port is reported as **miscabled**. On g02-g17 all 2,445 working links matched (18 Oct 07:12 UTC).

**GPU state and the AFM view.** Besides every link, `scan` checks each GPU as a whole. From the trays alone (`afmctl show device`): a GPU whose `config_phase` is not ACTIVE while other GPUs of the rack are ACTIVE is reported under **GPU state**, and its links are marked degraded with that cause. `PROVIDER` also means "in no vPOD", so from the trays alone the tool cannot tell a GPU left out of every vPOD from one that was reset and never re-programmed.

With the AFM view it can. When the inventory has an `afm:` block (`url`, `verify_tls`, `auth.username`, `auth.password_env`) and you set that variable in your shell, `scan` also reads AFM's compute nodes and pairs each tray GPU with AFM's (trays by `afm_name` or slot, GPUs by accelerator id, a single GPU left over on each side by elimination). It then reports:

- a GPU AFM has in a vPOD that the tray reports not ACTIVE, or with another accelerator id: **not programmed** (down)
- a GPU port AFM reports PortFailed / PortDown while the link and IFCP are up (degraded), and a down link that AFM still shows PortReady (noted on the link)
- the AFM port state of every link, in the All links table

```
read -s "HELIOS_AFM_PASSWORD?AFM admin password: " && export HELIOS_AFM_PASSWORD && echo
python tools/link_check.py scan --inventory <inventory>
unset HELIOS_AFM_PASSWORD
```

Without the variable, or with `--no-afm`, the scan says "AFM view not checked" and judges the GPUs from the trays alone. The password is read from the environment only and never written to the report. MR3 19 Oct: after a single-GPU `afmctl reset device -b 0001:01:00.1` on c2 the GPU stayed accelerator 0 / PROVIDER (AFM: 7); the scan reported it under GPU state and marked its 36 links degraded.

For loss that comes and goes, `pingmap` repeats a ring of L2 pings and maps the failures to GPU port numbers and so to switch ASICs, marking each as sticky (every round) or moving:

```
python tools/link_check.py pingmap --inventory <inventory> --rounds 12 --wait 300
```

**One switch tray or one compute tray.** A scan does not have to cover the whole rack. Name trays as the inventory names them; several are comma-separated (`--switches st4,st6`):

```
python tools/link_check.py scan --inventory <inventory> --switches st6
python tools/link_check.py scan --inventory <inventory> --trays ct13
python tools/link_check.py scan --inventory <inventory> --switches st6 --trays ct13,ct14
```

| Option | Checks | Links on a full rack | Still reads |
| --- | --- | --- | --- |
| `--switches st6` | every link of that switch tray | 432 (72 GPUs x 6 ports) | every compute tray, because they are the other ends |
| `--trays ct13` | every link of that compute tray | 144 (4 GPUs x 36 ports) | every switch tray, for the same reason |
| `--switches st6 --trays ct13,ct14` | only the links between them | 48 (2 trays x 4 GPUs x 6 ports) | only the named trays |

A partial scan is quicker and lighter on the jump host; links of trays left out are not reported. The patterns across trays (the same GPU position failing on several trays) need the full scan. `pingmap` takes the same two options.

**One link, end to end.** `link` takes whatever you have for a link and reads only its switch tray and its compute tray:

```
python tools/link_check.py link --inventory <inventory> "st6 Ethernet257"
python tools/link_check.py link --inventory <inventory> "ct13 0002:01:00.1 33"      # or: ct13 gpu1 port33, slot17/gpu3/port33,
                                                                                     # or an AFM event: "acc-id: 5, port-id: 32"
```

It gives the same diagnosis as the scan plus: the Broadcom lanes of the port next to a working port on the same ASIC; **around the link** (afm-agent, the node agent of the tray's slot, NTP and the clock offset between the two ends, the static forwarding entry, IFCP); and a **timeline** of the last 24 h (`--hours`): admin and link changes and the flap count from the switch syslog, who ran which command on the port (auth.log), the GPU's kernel / ifoe driver lines and afmctl's disruptive actions on the tray, and - with the AFM password - AFM's events and audit records for the link. Admin changes with no matching command mean something other than the CLI wrote CONFIG_DB (how the g02-g17 port bouncing showed). MR3 19 Oct: st1 and c2 NTP unsynchronised, c2 16.4 s behind st1 - read the two sides of a timeline with that offset.

**Links that come and go.** `watch` reads chosen links again and again and records every change (link, admin, IFCP, error and FEC counters):

```
python tools/link_check.py watch --inventory <inventory> "st6 Ethernet257; ct13 0002:01:00.1 33" --every 10 --duration 1800
```

**Cabling against the plan.** `cabling --export plan.csv` writes what the latest scan saw as a plan (switch, port, slot, gpu, gpu_port); correct it against the site's records and `cabling --plan plan.csv` lists ports missing, wrong descriptions, links that reach a different GPU port than planned (with the move to make) and links not in the plan. No login needed.

**Isolating a fault (DISRUPTIVE).** `isolate "<link>" --action switch-flap|gpu-flap --hold 10 --yes-disruptive` takes one end of ONE GPU link down and back: GPU links only, never a port in the inventory's `avoid_ports`, the end is always brought back, and every port of that ASIC that was up before must be up again (collateral is reported). Only with the people using the rack in the loop.

**Evidence for a ticket.** Every run folder can be zipped with its raw outputs and a `ticket.txt` (the UI's bundle.zip link); password-like text is redacted.

**From a browser: the web UI.** The same tools have a web UI. It runs on your own machine (`python -m ui` in the helios-debug repo, http://localhost:8780) or on a switch tray (see Installing the UI on a switch tray). On a switch it listens on localhost only: open it with `ssh -L 8780:localhost:8780 admin@<switch>`. Pick the rack at the top right.

- **Start here** (opens first): three steps with ticks - the rack, access to its trays (Check access now), a check of all links (Check all links now) - then what the last check found in plain words: each problem with what it means, what to do, who fixes it (operator, site team, AMD, switch vendor), and Show on the map / Diagnose buttons.
- **Simple and Expert mode** (top right). Simple: Start here, Check all links, Rack map, Diagnose a link, Earlier results, Access to the rack, Add / edit a rack, Topology, Debug guide. Expert adds All racks, Watch links, Cabling plan, Switch signal (Broadcom), GPU-to-GPU path, Ping map and Isolate (disruptive). Every tab has a "What is this?" (what, when, how long, safe?); the Glossary explains tray, BDF, plane, AFM, vPOD, IFCP, FEC.
- **Rack map**, three views of a check, with link counts on every compute tray, GPU, switch tray and ASIC (ok / degraded / down / not known): by compute tray (GPU x port squares), by switch ASIC, and **topology** - switch chips on top, compute trays and their GPUs below, one line per tray-to-chip bundle coloured by its worst link (red: a link is down). Find box, "what changed since" an earlier check, and Live mode (below).
- **Drill down**, from the map or the topology: click a tray, GPU, switch tray, ASIC or link. Every level has a connectivity picture (rack: trays to chips; switch tray: its chips and trays; chip: the GPUs on it; tray: its GPUs and the chips they reach; GPU: its 36 ports, one line per cable to its switch port; link: GPU port - cable - switch port with each end's checks), a table (rows open the next level), what is wrong and who fixes it, the problem links, and Diagnose / Watch / Highlight. Breadcrumbs (Rack > c2 > GPU1 > port 12, and the switch side) go back up. A link also shows both ends as the check saved them (link, admin, speed, FEC, lanes, optic, forwarding entries, errors, FEC counters; GPU link, fault, up / down time, IFCP, MAC), its state in every check of the rack, and related ports (the other port of the same GPU station, the switch ports next to it, the same port number on the tray's other GPUs).
- **Diagnose a link**: pick it from either end - compute tray, GPU, GPU port or switch tray, switch port; the other end follows - or type it. The result card says the verdict, what to do and what else around the link is wrong.
- **GPU-to-GPU path**: pick From and To (tray, then GPU with its accelerator id, ports up and a NOT ready warning), every shared port or ticked ones; a sentence says what will be sent where.
- **Topology** tab: the g02-g17 cabling drawing; click a GPU, a switch chip, an st / CT name or a row of a GPU's port table for the drill down of that item from g02-g17's latest check. For other racks use the Rack map's topology view.
- **Live mode** (Rack map; off by default - it keeps a connection open to every tray): the map follows link changes as they happen - the switch syslog (link up / down, admin changes) and each tray's kernel log (GPU port link events) followed as streams, everything re-read every 1 / 5 / 15 minutes, AFM's events polled with its password. A list of changes, a "went down just now" banner, a Live indicator in the header. One rack at a time; it stops by itself after the time chosen next to Turn live on (8 h, 24 h, 3 days, or until turned off) and 30 minutes after no page is open (unless *keep on when no page is open* is ticked); nothing is left running on the trays. The Live bar says when it will stop. A link whose GPU end could not be read shows as "not known", never as working.
- **Access to the rack**: checks a key login + sudo on every tray; where it fails, type that tray's password once to install the key. **Add / edit a rack** drafts an inventory from the switch trays (through a jump host when the rack is only reachable that way), or opens the chosen rack's file to change it - users, addresses, BMCs, a tray to quarantine; saving checks it (no passwords) and keeps the previous file as `<file>.bak-<time>`. **Earlier results** keeps every run with its reports and an evidence bundle (zip with a ticket.txt) for a ticket.

**As part of the rack health check.** The health check of the test automation (`tools/rack_health.py` in helios-tests) runs this scan as case HC-012, a warning next to HC-001 to HC-011: it calls `tools/link_check.py scan` from this repo as a separate program (found next to the test repo, in `~/helios-debug`, or where `thresholds.health.link_check.dir` points) and turns each root cause into a failure line. g02-g17 19 Oct 01:22 UTC: 2,592 links, 2,443 ok, 144 CT05 (quarantined), 5 real down links on GPU position `0002:01:00.1` - FAIL as expected; MR2: PASS, 288 / 288.

**What the switch ASIC sees.** For a down or degraded switch port, `bcm` reads the Broadcom shell lane by lane: whether any signal arrives, receiver lock, link training and signal quality (see Layer 1 from the Broadcom shell). `scan` already adds it to every physical-layer problem link, and reads one working port on the same ASIC as the reference for what a clean lane looks like on that rack.

```
python tools/link_check.py bcm --inventory <inventory> --switch st6 --ports Ethernet257,Ethernet261
```

Two more options help during a repair. `scan --compare <earlier link_check.json>` lists what changed since that scan: new problems, recovered links and causes that changed. The scan also names **patterns** across problem links:

- several problem links on one GPU point at that GPU or tray, or at either end when they all sit on one ASIC
- the same GPU position (BDF) failing on several trays points at something shared by that position, such as a cabling bundle or cartridge
- several problem links on one ASIC, especially adjacent ports, point at that ASIC or one connector

A scan needs about 50 MB free on the disk it writes to and stops with a clear message otherwise; the raw switch and tray tables are saved compressed, about 3 MB a scan. On a small shared host such as the g02-g17 jump host, copy the reports off and delete them after use.

On g02-g17 the switches report no transceiver presence or optic power, so the tool says when a cable fault cannot be told from a port fault without a swap.

First full scan, 18 Oct 06:51 UTC: 2,592 links, 2,445 ok, 147 down. 144 were CT05 (quarantined). The other 3 are listed under Known issues.

## Identify both ends of a link

Name both ends before touching anything. The switch port's description says which GPU port it is cabled to, and that is the key every other layer uses.

| Name | Example | Where it comes from |
| --- | --- | --- |
| Switch, ASIC, port | st6 / asic1 / Ethernet261 | `show interfaces status -n asic1 -d all` on the switch |
| Cabled peer | `To ComputeTray Slot12/GPU2[<acc>]/Port0` | the port description: `sonic-db-cli -n asic1 CONFIG_DB hget 'PORT\|Ethernet261' description` |
| Compute tray | slot 12 = pod-1-12-ComputeTray | AFM slot-id; on g02-g17, CT number = slot + 1 |
| GPU and accelerator | GPU2, acc \<n> | from the description; AFM may number accelerators differently within a tray (see Known issues) |
| GPU port | port 0 | from the description |
| IFoE station | station 0 | GPU port // 2 (ports 2k and 2k+1 share station k) |
| GPU PCI address | one per GPU, e.g. 0004:01:00.1 | `afmctl show device --json` on the tray |
| AFM switch port | asic1 / port \<id> | `GET /configs/cluster/v1/switchnodes/<switch>`: `status.asic-info.asics[].ports[]` with `peer.display` |

The ASIC and port numbers AFM uses are its own (port ids, not EthernetN), so match them through `peer.display` (`slot12/gpu2/port0`).

## Layer 1: physical link

Check both ends: a link is only up when the switch port and the GPU port both say so. All commands are read-only.

**Switch side** (SSH to the switch; each chip is a namespace, `asic0` or `asic1`):

| Check | Command | Healthy |
| --- | --- | --- |
| Admin / oper state | `show interfaces status -n asic1 -d all` | Admin up, Oper up, Vlan trunk |
| Optic present | `show interfaces transceiver presence -n asic1` | Present |
| Optic power and temperature | `show interfaces transceiver eeprom --dom -n asic1 Ethernet261` | Rx / Tx power inside the module's thresholds on every lane |
| FEC errors | `show interfaces counters fec-stats -n asic1` | Uncorrectable count not growing |
| Port errors | `show interfaces counters -n asic1 -d all` | RX\_ERR / TX\_ERR not growing |
| Error kinds and when last seen | `show interfaces errors Ethernet261` | every count 0, last timestamp `Never` (`fec sync loss`, `high ber error`, `mac local / remote fault`, `signal local error` name the layer) |
| Flap history | `show interfaces flap Ethernet261` | flap count steady; the last down / up timestamps (UTC) tell when it last dropped |
| FEC mode | `show interfaces fec status -n asic1 Ethernet261` | FEC Oper `rs` on the GPU ports |
| Optic identity | `show interfaces transceiver info -n asic1 Ethernet261` | vendor, part and serial as expected (for an RMA or a swap) |

**Tray side** (SSH to the compute tray, as root):

| Check | Command | Healthy |
| --- | --- | --- |
| GPUs present | `afmctl show device --json` | every GPU listed, config\_phase ACTIVE |
| GPU port state | `afmctl show port -b <bdf> --json` | `spec.admin_state` enabled, `status.link_status` LINK\_UP |

**Reading the two ends together:**

| Switch port | GPU port | Most likely cause |
| --- | --- | --- |
| Oper down, Admin up | NO\_PHY\_LINK | Cable, optic or seating: check DOM power on both ends, then reseat or swap |
| Oper down, Admin down | any | Someone shut it: check before starting it up |
| Oper up | NO\_PHY\_LINK | Port mapping is wrong (the description names another GPU port), or the tray side is idle |
| Oper down | LINK\_UP | Description points at the wrong switch port: compare `peer` in AFM |
| Flaps (oper changes, FEC errors grow) | LINK\_UP / down | Marginal optic or cable: watch DOM power and FEC counters over a few minutes |

To count changes on a Linux interface, `ip -s link show <iface>` with `cat /sys/class/net/<iface>/carrier_changes` shows how often the carrier dropped.

## Layer 1 from the Broadcom shell

SONiC only says a switch port is oper down. The switch ASIC's own shell says why, lane by lane: whether any signal arrives, whether the receiver locks, link training, faults, signal quality and how close the FEC runs to its limit. It is read-only and needs sudo on the switch.

**With the tool.** `scan` adds this automatically to every physical-layer problem link (up to 64 ports; `--no-bcm` skips it). For chosen ports, or every oper-down trunk port of one switch when `--ports` is left out:

```
python tools/link_check.py bcm --inventory <inventory> --switch st6 --ports Ethernet257,Ethernet261
```

**By hand.** Each ASIC is a unit of `bcmcmd` (`asic1` = `-n 1`). Find the Broadcom port first: the SONiC port's first lane is its physical port in the port map.

1. Lanes of the SONiC port: `show interfaces status -n asic1 | grep -w Ethernet261` gives Lanes `201,202`.
2. Broadcom name and logical port: `sudo bcmcmd -n 1 "show pmap"`, row with physical `201`: `cd100`, logical `220`.
3. Read the port (replace 220 and the lane index):

| What | Command | Healthy |
| --- | --- | --- |
| Link, lanes, speed, FEC | `sudo bcmcmd -n 1 'bsh -c "PortStatus 220"'` | link Up |
| Receiver lock, training, faults | `sudo bcmcmd -n 1 'bsh -c "lt PC_PORT_STATUS lookup PORT_ID=220 STATUS=STATUS_ALL"'` | `PMD_RX_LOCK=1`, `PMD_LANE_RX_LOCK` all lane bits set, `LINK_TRAINING_DONE=1`, no `LOCAL_FAULT` / `REMOTE_FAULT` |
| Signal per lane | `sudo bcmcmd -n 1 'bsh -c "lt PC_PHY_STATUS lookup PORT_ID=220 LANE_INDEX=0"'` | `RX_SIGNAL_DETECT=1`, `TX_SQUELCH=0` |
| Signal quality per lane | `sudo bcmcmd -n 1 'bsh -c "lt PC_PHY_STATUS_2 lookup PORT_ID=220 LANE_INDEX=0 STATUS=STATUS_2_ALL"'` | `RX_SNR` and `EYE_UP` / `EYE_DOWN` like a healthy neighbour port |
| FEC codeword histogram | `sudo bcmcmd -n 1 'bsh -c "lt PC_PORT_CUMULATIVE_DIAG_STATS lookup PORT_ID=220"'` | errors only in the low bins |

**Reading it:**

| The ASIC shows | Meaning |
| --- | --- |
| No signal on every lane, transmitter on, and the GPU port NO\_PHY\_LINK too | Neither direction gets through: the cable, connector or cartridge between them (or a GPU port whose transmitter and receiver both fail). Not the switch port's transmitter. |
| No signal on some lanes, signal on the others | One lane of the cable, connector or cartridge. |
| Signal on every lane but no receiver lock (`PMD_RX_LOCK=0`), SNR lower than a working port's | Signal too weak or distorted: marginal cable, dirty or damaged contact, a bad lane. |
| Signal on every lane that reads like a working port's (SNR, eyes), yet no receiver lock | Not a weak signal: check lane order, polarity and speed / FEC settings on both ends, or the GPU port's own PHY. st5 Ethernet494 (CT16 port 5), never up since boot, reads like this (18 Oct). |
| SONiC saw the port down, but the ASIC has it locked and trained a moment later | Flapping: the link drops and comes back. Scan again, watch the counters, check the cable seating. |
| Receiver locked, link training not done | Training does not converge between the two ends: raise it with both vendors, with this output. |
| `LOCAL_FAULT` / `REMOTE_FAULT` set | The link is up at the PHY but the PCS sees faults: local = this side's receive path, remote = reported by the far end. |
| Link up, low SNR or small eyes compared with neighbours, high FEC bins | Marginal link that still works: watch it, reseat at the next window. |

On g02-g17 healthy lanes read `RX_SNR` about 2,400 to 2,500 and `EYE_UP` about 34 to 43 (18 Oct). The units are Broadcom's and not given here: compare with a healthy port on the same switch rather than with an absolute number. `RX_SNR` 99900 means no signal. In the FEC histogram, bin k counts codewords that had k symbol errors; RS544 corrects up to 15, and bin 16 counts the uncorrectable ones. The histogram runs since the counters started, so compare two reads to see what is happening now.

Example, st6 18 Oct 13:45 UTC: Ethernet261 (CT13 port 0) has no signal on either lane while its transmitter is on, and Ethernet257 (CT14 port 2) has no signal on lane 0 only. Lane 1 reads SNR 2401, close to its healthy neighbour Ethernet258 (2473 / 2515). Both point at the cable path, and for Ethernet257 at one lane of it.

Only use the read commands above. `prbs`, `eyescan`, loopback and any `lt ... insert` / `update` / `delete` change the port and can drop a working link. `portmod` and `phy diag` do not exist on these chips (LTSW / SDKLT). In scripts, close stdin (`bcmcmd ... </dev/null`), because `bcmcmd` reads it.

## IFCP session

A GPU port can be LINK\_UP and still carry no traffic if its IFCP link-layer session never came up. The same `afmctl show port -b <bdf> --json` output holds it under `status.ifcp`:

| Field | Healthy | If not |
| --- | --- | --- |
| `status.link_status` | LINK\_UP | go back to Layer 1 |
| `status.ifcp.ll_up` | yes | the link-layer handshake did not complete: the peer switch port may not be in the vPOD's VLAN, or the far side is down |
| `status.ifcp.peer_enabled` | yes | the switch side is not taking part (port not programmed by AFM) |
| `status.ifcp.in_error`, `peer_in_error` | no | an error was reported on this side or the peer side |

A LINK\_UP port without a session is a real fault, not a cosmetic one: g02-g17 has two (see Known issues). The automated check is TC-001.

## What AFM reports

AFM shows each link from both sides, and the two should agree. Read them through the AFM API (log in first; the controller is only reachable from the jump host).

| What | API | Look at |
| --- | --- | --- |
| Switch side of every link | `GET /configs/cluster/v1/switchnodes/<switch>` | `status.asic-info.asics[].ports[]`: `oper-state` (PortReady / PortFailed), `admin-status`, `peer.display` e.g. `slot17/gpu3/port33` |
| GPU side of every link | `GET /configs/cluster/v1/computenodes/<compute>` | `status.scale-up-info.gpu-info.<gpu>.ports[]`: `oper-state`, `peer.display` e.g. `switch5/asic1/port122` |
| Effect on the fabric | `GET /configs/cluster/v1/vpods/pod-1.system` | `vpod-state` and available / effective / provisioned switch planes |
| What happened, when | `GET /events/v1/events` | `link_down`, `link_failed`, `ifoe_netport_link_down`, `ifoe_netport_link_failed`, `link_up` |

The link check compares the GPU side for you when the AFM password is set (GPU state and the AFM view, above). Three things to know when reading AFM:

- **Events come back unsorted.** AFM ignores `sort-by`, `sort-order` and `page-size` on the events list and returns it in uuid order; sort by `meta.creation-time` yourself before reading "the latest".
- **PortFailed comes before the link-fail threshold.** A shut port is PortFailed about 2 s later, even with a 30 s threshold; only the vPOD reconfiguration waits for the threshold (product issue 3 of the 17-18 Oct disruptive run). A port that flapped for a few seconds can therefore stay PortFailed.
- **A fully cut-off GPU is not always reported in full.** With all 36 ports of one GPU down, AFM left 2 (first run) and 6 (rerun) of them not PortFailed (product issue 4 of the same run). Check the switch side before trusting AFM's count.

## Data path: L2 ping

When every layer above looks healthy and traffic still fails, ping one GPU from another over specific ports. Run on the source tray, as root:

```
timeout 200 afmctl test ping -b <src bdf> -c 1 --dst-accelerator <dst acc> --port <p1,p2,...>
```

**Finding the arguments.** All three come from `afmctl` on the trays themselves, as TC-AFM-001 does it:

1. **Source BDF**: on the source tray, `sudo afmctl show device --json` lists each GPU's `bdf`. On g02-g17 the four GPUs of every tray are `0001:01:00.1` to `0004:01:00.1`.
2. **Destination accelerator**: on the destination tray, the same command gives each GPU's `spec.accelerator_id`; use the one of the GPU you want to reach. On g02-g17, tray CT n holds ids 4 x (n - 1) to 4 x (n - 1) + 3 in BDF order (CT01: 0 to 3, CT02: 4 to 7; checked 18 Oct). The source GPU's `spec.vpod_accelerators` lists every id it can reach (68 in the system vPOD); the destination must be in it.
3. **Ports**: use only ports that are enabled and LINK\_UP on both GPUs. This lists them for one GPU (run it on each tray with that GPU's BDF):

   ```
   sudo afmctl show port -b 0001:01:00.1 --json | python3 -c '
   import json, sys
   def walk(x):
       if isinstance(x, dict):
           if "port" in x and "bdf" in x: yield x
           for v in x.values(): yield from walk(v)
       elif isinstance(x, list):
           for v in x: yield from walk(v)
   for d in walk(json.load(sys.stdin)):
       print(",".join(str(p["id"]) for p in d["port"] if p.get("status", {}).get("link_status") == "LINK_UP" and p.get("spec", {}).get("admin_state") == "enabled"))'
   ```

   Ping only the port numbers in both lists. Port p of one GPU reaches port p of every other GPU through the one switch ASIC that carries plane p, so the same number is used at both ends.

Example: recheck the two ports that failed in the 16 Oct 13:37 UTC ping on CT03 (ids 8 to 11), from its GPU at `0004:01:00.1` (id 11) to id 8, the tray's own GPU at `0001:01:00.1`, on ports 25 and 26:

```
sudo timeout 200 afmctl test ping -b 0004:01:00.1 -c 1 --dst-accelerator 8 --port 25,26
```

The output has one row per port with three results, and a summary for each:

| Check | Tests | A FAIL usually means |
| --- | --- | --- |
| IFoE Request | the request reaching the destination over that port | the outbound direction of that link |
| IFoE Response | the reply coming back | the return direction, or the far GPU's port |
| Non-IFoE | plain (non-IFoE) frames over the port | the port's basic forwarding, independent of IFoE |

A port is only good when all three pass; a summary like `IFoE Request 35/36 PASS, 1/36 fail` names the count. "Device or resource busy" means another ping runs on that tray: wait about 20 s and retry. TC-AFM-001 runs this between every tray pair.

On g02-g17 the failing ports moved between runs (16 Oct: 05:38, 05:51, 13:37 UTC each hit different pairs), so ping the same pair two or three times before blaming one link: loss that moves points at the fabric or AFM, loss that stays on one port points at that link.

## Isolate by shutting one end

Shutting one end and watching what the other end and AFM report tells you which side is at fault. This changes the fabric: on the shared g02-g17 rack, do it only with a go-ahead, one port at a time, and always bring the port back.

1. Note the starting state of both ends (Layer 1 tables) and the system vPOD's planes.
2. Shut the **switch** end, fabric ports only (EthernetN, never eth0 / eth1 / mgmt):

   ```
   sudo config interface -n asic1 shutdown Ethernet261
   sudo config interface -n asic1 startup Ethernet261
   ```
3. Or shut the **GPU** end (station = port // 2):

   ```
   sudo env AFMCTL_FORCE_UPDATE=1 afmctl update port -b <bdf> -s <station> -p <port> --admin-state idle
   sudo env AFMCTL_FORCE_UPDATE=1 afmctl update port -b <bdf> -s <station> -p <port> --admin-state enable
   ```
4. After the startup, wait until the port is oper up on both ends and PortReady in AFM, and the planes are back.

Watch for three traps:

- **The value is `enable`, not `enabled`.** afmctl shows the state as "enabled" but refuses that word when setting it; a failed enable leaves the GPU port idle (MR3, 16 Oct).
- **A startup may not stick.** On the full rack, `interface startup` sometimes left the port down: shut and start it once more.
- **Some ports are coupled.** Shutting one can take its neighbour down too (st6 Ethernet257 took Ethernet261 down for 4 to 6 minutes). The ports listed under `thresholds.afm.avoid_ports` are never used by the tests for this reason.

## More ways to isolate a link problem

When the layer checks pass and traffic still fails, or a fault comes and goes, these narrow it down further.

| Method | How | What it tells you |
| --- | --- | --- |
| Map failures to switch ASICs | collect the failing GPU ports from many pings and look up each port number's ASIC in the rack topology's plane map | failures on a few port numbers point at those ASICs; scattered failures point at the GPU, tray or AFM |
| Check the forwarding entry of the failed pair | `link_check.py path` for that source, destination and port | a missing or wrong static entry is AFM programming; a correct one points back at the link |
| Counters around one ping | `link_check.py path` snapshots errors, drops and FEC on both switch ports before and after the ping | the counter that moves shows where the frame was lost |
| Repeat-ping map | link\_check.py pingmap --rounds 12 --wait 300 (one hour) | loss that stays on one port is that link; loss that moves is the fabric or AFM |
| Trend the error counters | `link_check.py scan --interval 300`, repeated | a marginal link shows growing corrected and then uncorrected FEC errors before it fails |
| Swap the cable or cartridge | move it to a known-good port pair (on site) | the fault follows the part, or stays with the port |
| GPU-side loopback | `afmctl show device` reports `loopback_mode`; ask AMD how to use it | isolates the GPU and tray from the cable and switch |

## Node health: beyond the links

A link can be fine while the node around it is not: a SONiC container that stopped, a full ASIC table, a failed fan, a GPU the OS cannot see, an expired AFM certificate. Check node health when a problem is not one link (several links, a whole switch or tray, a test that fails with every link up), or before you trust a rack for a run.

```
python tools/link_check.py health --inventory <inventory>
python tools/link_check.py health --inventory <inventory> --switches st1,st2 --trays ct13
python tools/link_check.py health --inventory <inventory> --only switches --no-drift
```

It runs the read-only commands of the four sections below on every switch tray and compute tray (on a QFX5252 switch tray also leak detection, SSD health, NTP, the switch BMC through `bmc-manager`, the image of the next boot and the management interfaces) (`--only switches|trays` to limit it, `--no-drift` to skip the running-vs-saved configuration compare, `--no-afm` to skip AFM's view), and writes `health.json`, `report.txt`, `report.html` and the raw outputs to `results/link-check/<rack>/health-<UTC time>/`. It exits 1 when it has findings. In the web UI it is the **Node health** tab.

How to read the report:

- **One finding per problem:** node, area, severity (critical / warning), what is wrong, the likely cause, the owner (network, hardware, compute, AFM), the next read-only step, the evidence lines and the command that showed them.
- **Rack-wide findings:** the same finding on 3 or more nodes (and at least a fifth of that kind of node) is reported once for the rack, with the nodes listed: it is a shared cause (an image, a setting, AFM), not that many separate faults.
- **Not checked is not healthy:** a command that is missing on that node, refused, or fails without output is listed under *not checked*, never counted as passing. A node where nothing could run is listed as *not reached*.
- **Thresholds:** disk 85 % warning / 95 % critical, memory available below 10 % / 5 %, CRM tables 85 % / 98 %, GPU hotspot 100 C, certificates expiring within 30 days. The inventory's `thresholds: health:` block overrides them.

Every command below is what the tool runs, so you can run the same one by hand on the node to look closer.

## The QFX5252 switch tray

What a Helios switch tray is, from the HPE switch tray configuration and management guide (draft of 3 Nov 2026), with what it means when debugging:

- **Two Tomahawk 6 chips per tray** (Broadcom BCM78914, 102.4 Tbps each), `asic0` and `asic1`, each a SONiC namespace: every `show interfaces ...`, `config interface ...` and `sonic-db-cli` command on a GPU port takes `-n asic0` or `-n asic1`. A rack has 6 switch trays, 12 chips, and 18 compute trays x 4 GPUs = 72 GPUs.
- **HPE Networking Enterprise SONiC (HPEN SONiC)**, built on community SONiC 2025.05, with secure boot, ONIE as the installer, and AMD's switch-tray components. `show version` and `sudo sonic-installer list` name the image running now (Current) and the one the next reboot starts (Next).
- **No MAC learning, no aging, no spanning tree.** The tray is a controlled fabric, not an Ethernet switch: every forwarding entry is static, written by AFM (through gNMI) for the MAC AFM gave each GPU port. A GPU that loses that MAC (a reset, a change of virtualization mode) keeps a working cable but its traffic matches no entry - see "GPU state" (PROVIDER, factory MACs 00:1f:0e:...) and the Config view's forwarding-entry check.
- **One 100G QSFP front-panel port per chip:** `Ethernet513` on asic0 and `Ethernet514` on asic1 (not GPU ports; 100G where the GPU ports run 400G). `show interfaces transceiver presence -n asic0` / `-n asic1` shows whether a module is in them.
- **Management:** `eth0` is the out-of-band management port; `eth1` is the host's side of the shared 1 GbE port whose other side (NC-SI) is the BMC. The BMC runs OpenBMC and stays on whenever the tray has power, even with SONiC down. See "When a node does not answer" below.
- **Console:** serial, 115200 baud, 8 data bits, no parity, 1 stop bit; or Serial-over-LAN from the BMC. ONIE's console is a root shell (press Enter, no login).
- **Firmware on the tray:** BIOS, BMC, SSD, FPGA (board control), retimers (keep the ASIC-to-port signals clean - a retimer firmware mismatch can look like a link problem), and the 1210 management Ethernet controller. Updates run from SONiC and cover the whole tray including the BMC; they take minutes and must not be interrupted.
- **sudo:** `config`, `sonic-installer`, firmware, LED and hardware access need sudo; most `show` commands, Linux status and CONFIG_DB reads run as admin without it; a few read-only hardware reads still need sudo.

**Changes, not debugging.** Installing or upgrading an image (`sonic-installer install`, ONIE `onie-nos-install`), `config interface ... shutdown / startup`, removing VLAN members, `config save -y`, management address changes and BMC firmware or power commands all CHANGE THE TRAY - for its owner, with the serial console connected. Two traps from the guide: `sonic-installer install --skip_migration` boots without the management address, hostname or CONFIG_DB (only the console reaches it afterwards), and a failed install must not be followed by a reboot.

## SONiC switch OS

Run on the switch tray (`ssh admin@<switch>`). Commands with `-n asicN` take each ASIC namespace (`asic0`, `asic1`).

| Check | Command | Healthy | If not |
| --- | --- | --- | --- |
| System health | `sudo show system-health summary` | `System status summary ... OK` | read `sudo show system-health detail` for the item it names; the other findings on the switch usually say why |
| Containers | `sudo docker ps -a --format '{{.Names}}\t{{.Status}}'` | every critical container (pmon, database, swss, syncd, lldp, bgp, teamd, radv, snmp, gnmi / telemetry, per ASIC where numbered) `Up` | a container `Exited` or `Restarting`: `sudo docker logs --tail 100 <name>`; what it serves is stale (swss / syncd: no new routes, FDB or port changes) |
| Restarts | `sudo docker inspect -f '{{.Name}} {{.RestartCount}} {{.State.StartedAt}}' $(sudo docker ps -q)` | restart count 0, started at boot | a container that started after the switch booted crashed or was restarted: match the time in the syslog |
| Critical processes | `sudo docker exec <container> sh -c 'cat /etc/supervisor/critical_processes; echo ===; supervisorctl status'` | every critical program `RUNNING`; in pmon the platform daemons (psud, thermalctld, xcvrd, ledd, syseepromd, pcied ...) running | a program `EXITED`, `FATAL` or `BACKOFF`: what it serves goes stale or N/A (psud: PSU status N/A, thermalctld: temperatures, xcvrd: transceivers, orchagent: no new ASIC programming) |
| CRM tables | `sudo crm show resources all` | every table well below full | a table at 85 % or more: new entries (routes, FDB, ACL, next hops) fail with `SAI_STATUS_TABLE_FULL`; find what fills it before adding more |
| Disk | `df -P / /var/log /host` | below 85 % | `sudo du -xh <mount> --max-depth=2 \| sort -h \| tail`; a full `/var/log` stops logging, a full `/host` blocks image installs |
| Memory | `grep -E '^(MemTotal\|MemAvailable):' /proc/meminfo` | 10 % or more available | a process leaks or the switch is overloaded: `top -o %MEM` |
| Core files | `sudo ls -1 /var/core` | empty | a process crashed (the file name says which and when): match the time with the reboot history and syslog; attach the core to a SONiC issue |
| Reboot cause | `show reboot-cause` and `show reboot-cause history` | user issued, warm / fast reboot, config reload | kernel panic, watchdog, power loss, hardware, thermal or unknown: the switch rebooted by itself; read the syslog before that time, and for a power loss the PSUs |
| Syslog | `sudo grep -hE ' (ERR\|CRIT\|ALERT\|EMERG) ' /var/log/syslog.1 /var/log/syslog \| tail -n 400` | few error lines | the tool groups the lines by message: orchagent / SAI errors, syncd failures, out of memory, platform daemon errors, platform alarms, hardware / disk errors. Crashes, `TABLE_FULL`, out-of-memory and kernel panics are critical; a repeated benign message is a warning |
| Configuration drift | `sonic-cfggen -n asicN -d --print-data` against `sonic-cfggen -n asicN -j /etc/sonic/config_dbN.json --print-data` | PORT, VLAN, VLAN\_MEMBER, PORT\_QOS\_MAP, PFC\_WD, BUFFER\_PG, BUFFER\_QUEUE the same | someone changed the running configuration and did not save it (lost on the next reload), or saved without applying; ask who changed it before saving or reloading |

## Switch platform

| Check | Command | Healthy | If not |
| --- | --- | --- | --- |
| Power supplies | `show platform psustatus` | every PSU `OK` | `NOT OK` / `NOT PRESENT`: a PSU failed, is unplugged or lost its input, and the switch runs without redundancy (hardware owner, on site). `N/A` on every PSU is usually psud stopped in pmon, not the PSUs |
| Fans | `show platform fan` | every fan present and `OK` | replace or reseat the fan on site; watch the temperatures meanwhile |
| Temperatures | `show platform temperature` | every sensor below its high threshold | above high: airflow, a fan, or the room; at critical the switch protects itself by shutting down |
| Voltages | `show platform voltage` | every rail within its thresholds | a PSU or the board's regulator: read `show platform psustatus`; hardware owner |
| Leak detection | `show platform leak status`, `show platform leak channels` | `Device leak status Normal`, `Hardware comparator alert No`; every channel `Data-status Good` | a leak: the location column names the manifold / cold plate - the site inspects the cooling NOW; a channel not Good: that sensor is blind (hardware owner) |
| SSD | `show platform ssdhealth` | Health 80 % or more | wearing out: plan its replacement; keep the configuration saved off the switch |
| Currents | `show platform current` | every `Warning` False | a rail draws out of range: hardware owner |
| PCIe devices | `show platform pcieinfo` | both TH6 chips (`BCM78914 ... Tomahawk6`), the BMC bridge, the HPE system devices and the NVMe listed | a chip missing from the list: SONiC cannot drive it (its links are all down); hardware owner |
| Identity | `show platform summary`, `show platform syseeprom` | platform `x86_64-juniper_qfx5252-r0`, HwSKU QFX5252, 2 ASICs; serial / base MAC | for the RMA / ticket |
| Clock | `show ntp` (or `chronyc tracking`, `chronyc sources -v`) | `Leap status : Normal`, a source marked `*` | `Not synchronised`, sources with Reach 0: no NTP server answers from the management network - log and event times cannot be lined up with the other nodes (g02-g17 st5, 4 Nov) |
| Image for the next boot | `sudo sonic-installer list` | Current = Next | different: someone installed or chose another image; the next reboot changes the software - confirm it is planned |
| Switch BMC | `sudo bmc-manager health`, `sudo bmc-manager status`, `sudo bmc-manager power-status`, `sudo bmc-manager version`, `sudo bmc-manager flash-info` | `BMC STATUS: HEALTHY`, its services active, power-status only `[PASS]` lines | `[WARN] WDT reset status asserted`: the BMC hung and its watchdog restarted it (g02-g17 st5, 4 Nov) - read `sudo bmc-manager journal errors` / `dmesg errors`; recovery (`bmc-manager power-cycle`) restarts only the BMC, not SONiC, but is still a change |
| Hardware watchdog | `sudo watchdogutil status` | `Armed` | not armed: if the switch OS hangs, nothing restarts it. Read `systemctl status watchdog-control` (or the platform's watchdog service); arming it is a change for the switch owner |

## Compute trays and GPUs

Run on the compute tray. The amd-smi and afmctl commands need sudo.

| Check | Command | Healthy | If not |
| --- | --- | --- | --- |
| GPUs visible | `sudo amd-smi list --json` | every GPU of the tray listed (four on these trays) | amd-smi fails: the amdgpu driver is not loaded, the GPUs are not initialised, or amd-smi does not match the driver (`sudo dmesg \| grep -i amdgpu`). Fewer GPUs: one is not seated, failed or lost on the PCIe bus (`sudo lspci -d 1002:`, then the BMC event log) |
| GPU memory ECC | `sudo amd-smi metric --ecc --json` | no uncorrectable errors, correctable not growing | uncorrectable: jobs on that GPU crash, pages may be retired (`sudo amd-smi bad-pages -g <n>`, `sudo amd-smi ras`); the GPU owner decides on a replacement. Many correctable: watch whether it grows |
| PCIe link | `sudo amd-smi metric --pcie --json` | width and speed at their maximum | trained below its maximum: a riser, seating or the slot (`sudo lspci -vv -s <bdf> \| grep -i lnk`); hardware owner reseats |
| Use, power, temperature | `sudo amd-smi metric --usage --power --temperature --mem-usage --json` | hotspot below 100 C | hot: airflow, a fan or cooling; read the tray's BMC thermal sensors |
| Processes | `sudo amd-smi process --json` | no process when the GPUs should be idle | a workload is on the GPUs: tests and jobs share them, so results and timings are affected; find its owner before a test run |
| AFM state on the tray | `sudo afmctl show device --json` | every GPU `config_phase` ACTIVE | not ACTIVE: AFM has not programmed it (not in a vPOD, or the node agent did not apply it); check its vPOD in AFM |
| Kernel errors | `sudo journalctl -k -p err --since '-60 min' --no-pager -q` | none | grouped as: uncorrected machine checks (critical), corrected machine checks (CPU / cache / memory), GPU driver errors, PCIe (AER) errors, disk / filesystem errors, RDMA NIC errors, out of memory |
| RDMA NIC ports | `rdma link show` | every port `ACTIVE` / `LINK_UP` (ports administratively disabled are ignored) | a scale-out NIC port is down or `POLLING`: its cable, the leaf switch port or the NIC (`ip -br link`, then the leaf port) |
| Disk, memory | `df -P /`, `grep -E '^(MemTotal\|MemAvailable):' /proc/meminfo` | below 85 %, 10 % or more available | as for the switch |
| Failed services | `systemctl --failed --no-pager --plain --no-legend` | none (`systemd-networkd-wait-online` is ignored: it fails on any server with an unplugged port) | `systemctl status <unit>` and `journalctl -u <unit> -n 50` |

## AFM health

| Check | Where | Healthy | If not |
| --- | --- | --- | --- |
| AFM agent | `systemctl is-active afm-agent` on each switch | `active` | AFM loses this switch and its node agents: `systemctl status afm-agent`, `sudo docker logs --tail 100 afm-agent`; starting it again is a change for the AFM owner |
| Controller certificate | `echo \| openssl s_client -connect 127.0.0.1:443 2>/dev/null \| openssl x509 -noout -enddate` on the AFM nodes | more than 30 days left | expiring or expired: TLS between AFM, its agents and the API fails when it expires; renew it before |
| Agent certificates | `openssl x509 -noout -enddate -in <pem>` for each `/opt/amd/afm/agent/sysconfig/config*/*.pem` | more than 30 days left | as above |
| AFM's view of the compute nodes | AFM API, only when the AFM password is given for the run | every compute node admitted and healthy | AFM sees the node as not healthy (its agent, its GPUs or its admission): open the node in AFM and read its node agent's log on the switch that serves it |

## When a node does not answer

A node health check (or a link check, or Live) that cannot log in to a node names why, from the SSH error itself:

| What it says | Means | Next |
| --- | --- | --- |
| login refused for &lt;user&gt; | the node answers but rejects the key for that user: the key was removed, the account changed, or the inventory names the wrong user | install the key again (Access to the rack: Install key) or set the right user in the inventory |
| no route to host: off the network | the node is not on the network: powered off, OS down, or its management link | its BMC (below), then the management cable / switch port |
| no answer (timed out) | nothing answered: powered off, hung, or a firewall | its BMC |
| SSH refused | it answers, SSH is not listening: booting, or sshd stopped | wait, else the console on the BMC |
| host key changed | reinstalled? the host key differs from the one known | `ssh-keygen -R <host>` on the machine that logs in (the jump host with via: exec) |
| the jump host did not open a session | usually its limit on sessions at once (retried) | run large checks on the jump host itself |

**A switch tray that is powered but does not answer** (its GPU links read up from the trays, SSH says no route / no answer - g02-g17 st1-st4, st6 on 3 Nov): the data plane is fine, the management path is not. From the serial console or the BMC's Serial-over-LAN, read-only:

| Check | Command | Healthy | If not |
| --- | --- | --- | --- |
| Management address | `ip -br -4 address show eth0` | UP with the address the inventory uses | no address: DHCP got none (below); another address: the inventory or DNS is stale |
| Default route | `ip route show default` | `default via <gateway> dev eth0` | none or via another device: the switch cannot answer anyone off its subnet |
| DHCP client | `pgrep -af 'dhclient.*eth0'` | a dhclient for eth0 (when no static address is configured) | none: `sudo dhclient eth0` gets an address back (a change, but the one SONiC itself would make) |
| Static management config | `sudo sonic-db-cli CONFIG_DB KEYS 'MGMT_INTERFACE\|*'` | empty (DHCP on eth0) or exactly one entry | two entries with gateways (eth0 and eth1): the default route flips between them and the switch drops off the management network - keep one |
| The shared port | `ip -br link show eth1`, `sudo ethtool eth1` | eth1 and the BMC have different addresses | the same address on host and BMC: neither answers reliably |
| The BMC from SONiC | `sudo bmc-manager status` | the BMC's eth0 address and `usb0` up | the BMC answers over the internal USB link even when its own address does not: its eth0 state says whether the shared port has link |

Do not edit `/etc/network/interfaces` (SONiC regenerates it) and do not use the namespaced `config interface -n asicN ...` commands for eth0 - they configure data ports. The checks above are also in **Node health** for a switch it can reach (management interfaces, BMC).

**Through the BMC.** A tray (or switch) that SSH cannot reach is asked through its BMC over Redfish (read-only GETs):
the BMC runs on standby power and answers on its own network. Without the BMC password health only asks whether the
BMC answers; with it (Node health: BMC view, this run only) it reads the power state, health, sensors and the event log:

| BMC | Node over SSH | Means |
| --- | --- | --- |
| does not answer | does not answer | no power to the tray (feed, power shelf, PSUs) or its management network |
| answers, power Off | does not answer | powered off - by someone, a power fault or a protective shutdown; the event log says which. Powering on CHANGES THE RACK |
| answers, power On | does not answer | the OS hung, is booting, or its network is down: open the console on the BMC |
| answers, login refused | - | the BMC user / password of the run is wrong |

Inventory: `bmc:` (address) and `bmc_user:` per node or under `defaults:`. The password is typed per run, never stored.

## Scale-out NICs (RDMA)

The compute tray's RDMA NICs (AMD Pensando `ionic` on g02-g17) are checked by health too, read-only:

| Check | Command | Healthy | If not |
| --- | --- | --- | --- |
| Port state | `rdma link show` | every port `ACTIVE` / `LINK_UP` (administratively disabled ports are ignored) | the NIC's own reason below |
| Why a port is down | `sudo nicctl show port -b <card> -j` (each card; the tool reads them all in one session) | oper UP | `Transceiver removed` (optic state REMOVED): no optic or cable plugged in - site, not a NIC fault; no light / signal: the optic or cable, then the leaf switch port |
| Link flaps, optics | the same | link-down events 3 or fewer, optic below its warning temperature | a marginal optic, cable or leaf port; airflow |
| Drops / errors | `ethtool -S <netdev>` (hw_rx/tx_dropped, rx_over / missed errors, tx_aborted, rx_csum) | 0 | counters since boot: read again in a few minutes - growing means a live problem (congestion without PFC / ECN, a bad link) |
| Firmware | `nicctl show port` (the card list) | one version per kind of NIC on a tray, the same on every tray | the NIC owner updates them to one version (CHANGES THE TRAY) |

## Health over time and the incident brain

- Each health run is compared with the rack's previous one: **new**, **gone**, and **grew** (the same finding with a
  bigger number: ECC count, disk %, CRM %), per node and only over nodes checked both times. The report, the UI and
  `health-history.jsonl` keep it.
- `link_check.py health --every 30` repeats the check every 30 minutes; `--keep 48` (default) keeps older runs as their
  health.json only.
- `--incidents http://10.83.2.15:8443` sends the new findings to the AIOps incident API (the incident brain explains,
  groups and keeps them); the same finding sent again replaces its incident.
- Each finding in the UI has a **ticket** for its owner (facts only) and an **evidence.zip** (the ticket, the finding and
  that node's raw outputs).

## Debug a node with the AI

For a problem the health check does not name, use **Debug a node** in the web UI (or the **Debug &lt;node&gt;** button on a health finding): describe the symptom and the node, and the helios model proposes one read-only command at a time. You click Run, the output goes back to the model, and it proposes the next command until it names the cause.

- Only commands on the read-only allow-list for that kind of node run: the commands of this guide (show ..., system-health, crm show, watchdogutil, `docker exec <c> supervisorctl status`, `docker logs --tail N`, journalctl -p err, df, rdma link show, lspci -d 1002:, systemctl is-active, amd-smi, afmctl show ...). A command that is not on it is refused with the reason, and the model is asked once more for a read-only one.
- Nothing that changes the node runs from there; a fix is for the owner the answer names.
- The model sees only the outputs of the commands you ran, so check its conclusion against them.

## Known node issues on g02-g17

From the read-only health checks of 2 Nov 2026. Check here first: a finding on this list is not new.

| Where | Finding | Status |
| --- | --- | --- |
| CT15 | not reachable (no ping, no SSH) in the morning check | answered again at 18:40 UTC (see below) |
| CT16 | amd-smi cannot read the GPUs | open: driver / amd-smi state on the tray |
| 16 of 17 reachable trays | corrected machine-check errors in the kernel log | rack-wide, corrected only: watch for uncorrected ones |
| CT10 to CT13, CT16 to CT18 | RDMA NIC ports `POLLING` (no link) | scale-out cabling or leaf ports; not the scale-up fabric |
| CT08, CT09 | GPUs in use (alltoall\_perf) | a test workload, not a fault; expect it to affect timings |
| st1 | hardware watchdog not armed | switch owner to decide |
| switches | orchagent PHY `TEMP_LIST` syslog messages repeated | known noisy message; grouped as a warning |
| st1 to st6 | new SSH logins as `tenant_hpe` refused (2 Nov ~17:10 UTC; `admin` works) | key or account changed on the switches: who changed it? until then switch checks fail with "login refused for tenant_hpe" |
| CT12, CT15 | no route to host at ~17:10 UTC 2 Nov, BMCs answering; both answered again at 18:40 UTC | came back - CT12 then had 2 failed units (sc-munged, sc-palsd) |
| CT10 to CT13, CT15 to CT18 | AI NIC ports POLLING: the NIC says `Transceiver removed` on every one | no optics in the scale-out ports - cabling not done; site |
| 10 of 17 trays | AI NICs on two firmware versions on the same tray (1.130.5-a-7 and 1.130.8-a-5, four each); 6 trays all 1.130.8-a-5 | NIC owner to pick one version |

## Known link issues on g02-g17

Check this list first: these are already known, so a new symptom on one of them is not a new fault.

**Pattern, 18 Oct 09:40 to 10:20 UTC:** every down link outside the quarantined CT05 is on GPU position `0002:01:00.1`, on five trays: at 10:20 UTC CT13 port 0, CT14 port 2, CT16 port 5, CT17 port 24 and CT18 port 28 were down. CT17's GPU at that position also lost ports 21, 25 and 28 for minutes at a time overnight. Two of them land on adjacent ports of st4 asic0 (Ethernet66 and 70), where Ethernet69 also dropped for a while. This points at something shared by that GPU position and at one connector on st4, more than at five separate cable faults. Remote recovery (switch-side flap, GPU-side retrain) did not bring them back, and flapping took coupled neighbours down; an on-site check is needed.

| Where | Symptom | Status |
| --- | --- | --- |
| st4 asic0 Ethernet70 = CT17 0002:01:00.1 port 24 | no physical link on either end, down since about 17:50 UTC 17 Oct | new, found by the link check 18 Oct; the time matches the batch 2 link tests, which shut and restored ports around 17:50 UTC: the link likely did not train again |
| st6 asic1 Ethernet261 = CT13 0002:01:00.1 port 0 | no physical link on either end, down since about 21:20 UTC 17 Oct | coupled to Ethernet257: did not come back after the TC-AFM-013 ([Link] Link flap (switch, both ASICs)) rerun flapped 257 (product issue 6: coupled switch ports) |
| st6 asic1 Ethernet257 = CT14 0002:01:00.1 port 2 | no physical link on either end, down since about 08:57 UTC 18 Oct | went down when we flapped its coupled neighbour Ethernet261 to recover it (product issue 12: down links do not recover remotely); not touched since. Broadcom view 18 Oct 13:45 UTC: no signal on lane 0 only, lane 1 has signal: one lane of the cable path |
| st4 asic0 Ethernet66 = CT18 0002:01:00.1 port 28 | no physical link on either end, down since about 08:57 UTC 18 Oct | went down when we flapped st4 Ethernet70 to recover it: 66 and 70 look coupled (product issue 12: down links do not recover remotely); not touched since |
| CT16 GPU port 5 = st5 asic1 Ethernet494 | NO\_PHY\_LINK, never up since the tray booted | AMD 16 Oct: mechanical inspection needed |
| CT14 GPU port 33 | NO\_PHY\_LINK on 16 Oct | LINK\_UP in the 18 Oct 06:51 link check |
| CT02 0004:01:00.1 port 30 | LINK\_UP, no IFCP session (16 Oct) | open with AMD; IFCP up in the 18 Oct link check |
| CT06 0002:01:00.1 port 12 | LINK\_UP, no IFCP session; one-way link-level control on accelerator 21 (TC-SBM-062) (16 Oct) | open with AMD; IFCP up in the 18 Oct link check |
| Any tray pair | L2 ping loss on 1 to 2 ports, moving between pairs (TC-AFM-001) | open with AMD |
| st6 asic1 Ethernet257 and Ethernet261 | shutting 257 takes 261 down | HPE switch, product issue 6 (coupled switch ports) |
| st4 Ethernet243 / 251, st4 Ethernet66 / 70 (seen 18 Oct), st2 Ethernet170 / 162 | coupled pairs | excluded from tests (`avoid_ports`) |
| CT05 (slot 4, pod-1-4) | tray down since 13 Oct: all 144 of its links down | quarantined in the inventory; expected |
| Every switch | stale Vlan2 + static FDB entries left from the ARC run | not AFM's; ignored by the tests (`non_afm_vlans`) |
| Accelerator numbers | port descriptions number a tray's accelerators differently from AFM | a naming convention, not a cabling fault; TC-SWH-048 checks it stays consistent |

## Automated checks that already cover links

Run these first; each names the failing port, so most of the work above is only needed to explain a failure. They are read-only; all but TC-SWH-048 and TC-SWH-050 are part of the rack health check (`tools/rack_health.py`) or by ID with `pytest tests --tc <ID>`.

The disruptive link flap / link down cases (34 of them, from a single port flap to all stations of one GPU and the link-fail threshold) are tagged **[Link]** in the title column of `full_rack_testplan.xlsx`: filter on `[Link]` to list them, e.g. TC-AFM-011 *[Link] Link flap (switch, one ASIC)* or TC-AFM-040 *[Link] Link-fail threshold, custom failover policy*. They shut and restore ports, so they are not part of the health check.

| Case | Checks | Layer |
| --- | --- | --- |
| TC-SWH-030 | every switch port's admin and oper state against the expected up ports | switch, Layer 1 |
| TC-BU-011 | every GPU ACTIVE and all its IFoE ports enabled and LINK\_UP | tray, Layer 1 |
| TC-001 | every LINK\_UP GPU port has an IFCP session (ll\_up, peer enabled, no errors) | IFCP |
| TC-CTL-090 | every compute admitted, healthy, GPUs Ready, GPU ports PortReady | AFM |
| TC-SWH-048 | the accelerators in the switch port descriptions match AFM's, one consistent mapping | cabling map |
| TC-SWH-050 | every static FDB entry is on a port cabled to an admitted compute and in the entry's VLAN | switch programming |
| TC-AFM-001 | L2 ping within and across every compute tray | data path |
| HC-012 | the link scan of this guide (`link_check.py scan`) run by the rack health check on the same inventory: one root cause per down / degraded link, trays quarantined in the inventory recorded but not failed; the report (ASIC to GPU map, every link, command logs) is kept with the run under `results/runs/<rack>/link-scans/` | every layer, with the cause |

## Evidence to collect before raising it

Send the same set every time, with UTC times: it lets AMD (GPU, IFCP, AFM) or HPE (switch, optics) act without asking back.

- [ ] Both ends named: switch / ASIC / EthernetN, tray, GPU PCI address, GPU port, station
- [ ] Switch: `show interfaces status` line, transceiver DOM for the port, FEC and error counters taken twice a few minutes apart
- [ ] Switch ASIC: `link_check.py bcm` output for the port (signal, lock and SNR per lane)
- [ ] Tray: `afmctl show port -b <bdf> --json` for the GPU (link\_status, admin\_state, the `ifcp` block)
- [ ] AFM: the port's `oper-state` on the switch node and the compute node, and the related events sorted by time
- [ ] L2 ping output for the pair, run two or three times
- [ ] What changed just before: a test, a restart, a reseat, a flap of a neighbouring port
- [ ] Whether it is on the Known issues list above
- [ ] Switch tray side for HPE: `show techsupport` on the switch (it writes a compressed archive and prints its path - copy that file off), `show version`, `show platform summary`, `sudo sonic-installer list`, `sudo bmc-manager status`
- [ ] Config of the nodes involved (Config tab: Download, or Read whole rack -> Download this read)

Owner of the fix: NO\_PHY\_LINK, optics and seating go to HPE (switch side) or AMD (tray side) depending on which end the DOM and the swap point to; IFCP sessions, PortFailed timing and ping loss go to AMD.

## Abbreviations and terms

Every abbreviation and status word used in this guide. AFM, IFoE and IFCP are not spelled out in the project's AMD documents; their expansions below are the common usage and should be confirmed with AMD.

| Term | Stands for | Meaning here |
| --- | --- | --- |
| acc | accelerator | A GPU's id in the scale-up fabric (AFM `acc-id`); switch port descriptions may number a tray's accelerators differently |
| Admin / Oper state | administrative / operational state | Admin = what the port is set to (up / down); Oper = what the link actually is |
| AFM (also AIFM) | AI Fabric Manager (to confirm with AMD) | AMD's controller for the scale-up fabric; runs as a 3-node cluster on st1 to st3 and is reached through its API |
| AM lock | alignment-marker lock | The PCS found the lane alignment markers (`AM_LOCK_LIVE`) |
| AMD | Advanced Micro Devices | Supplier of the GPUs, compute trays and AFM |
| API | application programming interface | AFM's HTTPS interface, e.g. `/configs/cluster/v1/...` |
| ARC | the name of an earlier test run on this rack | Left the stale Vlan2 entries on the switches |
| ASIC | application-specific integrated circuit | A switch chip; each switch has two, `asic0` and `asic1`, each its own SONiC namespace |
| bcmcmd, bsh, LTSW / SDKLT | Broadcom shell, its logical-table shell, the SDK generation of these chips | Read the ASIC's port state directly (`lt <TABLE> lookup`) |
| BDF | bus:device.function (PCI address, with domain) | A GPU's PCI address on the tray, e.g. `0004:01:00.1` |
| BMC | baseboard management controller | A node's own management chip on standby power, with its own network address |
| CONFIG\_DB | SONiC configuration database | Holds port descriptions and VLANs; read with `sonic-db-cli` |
| CRM | critical resource monitor | SONiC's count of the ASIC tables (routes, FDB, ACL, next hops): used and available |
| CT | compute tray | CT01 to CT18; CT n is AFM slot n - 1 (CT05 = slot 4) |
| DOM | digital optical monitoring | The optic's live readings: Rx / Tx power, temperature, voltage |
| ECC | error-correcting code | GPU memory error correction; corrected errors are counted, uncorrectable ones lose data |
| FDB | forwarding database | The switch's MAC address table |
| FEC | forward error correction | Corrects bit errors on the link; a growing uncorrectable count means a bad link |
| GPU | graphics processing unit | The accelerator; each tray has four |
| HPE | Hewlett Packard Enterprise | Supplier of the switches |
| IFCP | IFoE control protocol (to confirm with AMD) | The link-layer control session between a GPU port and its switch port (`status.ifcp`) |
| IFoE | Infinity Fabric over Ethernet (to confirm with AMD) | AMD's GPU-to-GPU scale-up traffic carried over Ethernet; GPU ports are named `ifoe_np_<n>` |
| L1 / L2 | layer 1 / layer 2 | Physical link / Ethernet frames (the L2 ping) |
| LINK\_UP, NO\_PHY\_LINK | afmctl link states | GPU port has a link / no physical link at all |
| ll\_up | link layer up | IFCP field: the link-layer handshake completed |
| MCE | machine-check exception | The CPU reporting a hardware error (`[Hardware Error]` in the kernel log), corrected or not |
| PAM4 | 4-level pulse amplitude modulation | The line coding of these 400G lanes; it has three eyes, hence three `EYE_UP` values |
| pmon | platform monitor (container) | Runs the platform daemons: psud (PSUs), thermalctld, xcvrd (transceivers), ledd, syseepromd, pcied |
| Redfish | the DMTF BMC API (HTTPS, JSON) | How health reads a BMC: power state, health, sensors, event log - GETs only |
| PSU | power supply unit | Two or more per switch, for redundancy |
| PCI | Peripheral Component Interconnect (Express) | The bus the GPUs sit on |
| PCS | physical coding sublayer | Above the SerDes: alignment, FEC framing; reports local / remote faults |
| PMD | physical medium dependent (sublayer) | The SerDes receiver; `PMD_RX_LOCK` = it locked on the incoming signal |
| PortReady, PortFailed | AFM port states | Port usable / port down as AFM sees it |
| RAS | reliability, availability, serviceability | The GPU's error reporting (`amd-smi ras`) |
| RDMA | remote direct memory access | The scale-out NICs on the compute trays (`rdma link show`), not the scale-up fabric |
| Rx / Tx, RX\_ERR / TX\_ERR | receive / transmit, and their error counters | Port counters in `show interfaces counters` |
| SEL | system event log | The BMC's log of hardware events (power, thermal, memory, PCIe) |
| SerDes | serializer / deserializer | The ASIC's high-speed transmitter and receiver per lane |
| SNR | signal-to-noise ratio | `RX_SNR` per lane in the Broadcom shell; compare with healthy ports |
| SONiC | Software for Open Networking in the Cloud | The switch operating system |
| SSH | Secure Shell | Remote login to switches, trays and the jump host |
| st1 to st6 | switch tray 1 to 6 | The six switches, 10.0.4.71 to 10.0.4.76 |
| station | IFoE station | Two GPU ports that belong together: ports 2k and 2k + 1 form station k |
| swss, syncd | switch state service, ASIC sync daemon | SONiC containers: swss (orchagent) turns configuration into ASIC programming, syncd talks to the ASIC SDK |
| TC- / HC- | test case / health check | Case IDs in `full_rack_testplan.xlsx` |
| UTC | Coordinated Universal Time | All times in this guide and in the logs |
| VLAN | virtual local area network | AFM puts each vPOD's switch ports in its own VLANs |
| vPOD | virtual pod | A set of GPUs AFM builds a scale-up fabric for; `pod-1.system` holds every GPU by default |

## Reading the rack map

- The map always shows every switch and tray of the inventory. A switch or tray the chosen check could not read is
  drawn **grey** from the newest earlier check that read it; hover a link for what that check said and why it is
  missing now. The summary line names them.
- A check that read no link at all (every switch off the network) is never the map's or Live's starting point; it is
  marked "no links read" in the Scan list.
- With Live off, the map is the check's picture - the bar says how old it is. With Live on, links whose switch and
  tray could not be re-read turn grey ("not known") instead of keeping the check's colour.

