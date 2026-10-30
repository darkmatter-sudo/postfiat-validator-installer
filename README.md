# Hardened Post Fiat Testnet Validator Installer

One command to deploy a Post Fiat testnet validator node on Ubuntu 22.04+ with Docker. Admin/RPC ports are locked to localhost, the firewall is default-deny with a rate-limited peer port, and the install finishes with a health check.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/main/install.sh | sudo bash
```

Custom SSH port or directory:

```bash
curl -fsSL https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/main/install.sh | sudo SSH_PORT=2222 POSTFIATD_DIR=/opt/postfiatd bash
```

Read the script before piping it to a shell.

## Prerequisites

- Ubuntu Server 22.04 LTS or newer
- 2 CPU cores, 4 GB RAM, 100 GB storage (official minimum)
- Root / sudo access
- Inbound TCP 2559 reachable from the internet (check your provider's cloud firewall too)
- Use a fresh or dedicated host: the installer sets UFW to default-deny incoming. It allows your SSH port first and does not reset existing rules, but other services on the box will need their own `ufw allow` rules.

## What it does

1. Installs Docker, Compose v2, UFW, curl, jq, python3
2. Firewall:
   - UFW: allow SSH, `limit` TCP 2559, default deny incoming / allow outgoing
   - `DOCKER-USER` iptables chain: per-IP connection cap (50) and new-connection rate limit (100/s, burst 50) on 2559, persisted by the `postfiat-docker-user` systemd unit
3. Downloads the official compose file from `postfiatorg/postfiatd`, rewrites admin/RPC ports to `127.0.0.1`, and verifies the resolved config before starting
4. Pulls and starts `agtipft/postfiatd:testnet-light-latest`, logging the resolved image digest
5. Installs `postfiat-health` and runs it

## Port map

| Port  | Purpose              | Binding        | Public |
|-------|----------------------|----------------|--------|
| 2559  | Peer protocol        | 0.0.0.0        | Yes (rate-limited) |
| 5005  | Admin JSON-RPC       | 127.0.0.1      | No |
| 6005  | WebSocket            | 127.0.0.1      | No |
| 6006  | Admin WebSocket      | 127.0.0.1      | No |
| 50051 | gRPC                 | 127.0.0.1      | No |
| SSH   | Remote access        | host           | Yes |

## Health check

```bash
sudo postfiat-health
```

Checks: container running; admin ports on 127.0.0.1 only; peer port listening; UFW active with a LIMIT rule on 2559; DOCKER-USER rate limit present; RPC responding with `server_state`, build version, peers and ledgers; build compared with the foundation RPC. Exits 0 when healthy, 1 otherwise, so it works in cron or monitoring.

A fresh node reports `full` or `syncing`. It reports `proposing` only after you add a validator token (next section).

## Monitoring add-on (ntfy alerts)

A systemd service + timer that runs `postfiat-health` every 5 minutes and pushes an alert to [ntfy](https://ntfy.sh) when the node is unhealthy, then a single recovery notice when it's back.

**Alert rules**
- Unhealthy = `postfiat-health` fails **or** `server_state` is not `full`/`proposing`
- One alert when it goes unhealthy; repeat cycles are suppressed (optional reminder via `REMIND_MINUTES`)
- One recovery alert when it returns to healthy, with approximate downtime

**Install** (requires the main installer above):

```bash
curl -fsSL https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/main/monitor/install-monitor.sh | sudo bash
```

Optional: `... | sudo NTFY_TOPIC=your-long-random-topic NODE_LABEL=pft-01 bash`. If no topic is given, a random one is generated. Get it with `sudo grep NTFY_TOPIC /etc/postfiat-monitor.env` and subscribe in the ntfy app. Topics on ntfy.sh are readable by anyone who knows the name, so keep it random and private.

**Config:** `/etc/postfiat-monitor.env` (mode 600). See [`monitor/postfiat-monitor.env.example`](monitor/postfiat-monitor.env.example) for `NTFY_TOPIC`, `NTFY_SERVER`, `NTFY_TOKEN`, `NODE_LABEL`, `HEALTHY_STATES`, `REMIND_MINUTES`.

**Files**

| Repo file | Installed to |
|-----------|--------------|
| `monitor/postfiat-monitor.sh` | `/usr/local/bin/postfiat-monitor` |
| `monitor/postfiat-monitor.service` | `/etc/systemd/system/postfiat-monitor.service` |
| `monitor/postfiat-monitor.timer` | `/etc/systemd/system/postfiat-monitor.timer` (every 5 min) |
| `monitor/postfiat-monitor.env.example` | `/etc/postfiat-monitor.env` |

**Use**

```bash
systemctl list-timers postfiat-monitor.timer   # next run
sudo systemctl start postfiat-monitor.service  # run a check now
tail -f /var/log/postfiat-monitor.log          # history
```

**Test end to end** (stops and restarts the container): `sudo bash monitor/test-monitor.sh 2>&1 | tee monitor-test.log`. See [`logs/monitor-test.log`](logs/monitor-test.log).

**Uninstall**

```bash
curl -fsSL https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/main/monitor/install-monitor.sh | sudo bash -s -- --uninstall
```

Removes the units, script and state; keeps `/etc/postfiat-monitor.env` and the log.

## Becoming a proposing validator

This installer sets up a hardened, synced node. Validator identity is deliberately left to you, so private keys are never handled by a script or written to logs. Follow steps 5–8 of the [official guide](https://postfiat.org/validator-setup/):

- generate keys and back up `validator-keys.json` offline
- run `set_domain` and inject the `[validator_token]` into `postfiatd.cfg`
- publish `/.well-known/pft-ledger.toml` on your domain

Never paste keys or tokens into chats or issues.

## Security notes

- **Why both UFW and DOCKER-USER?** Docker-published ports are routed through the FORWARD chain and bypass UFW's INPUT rules. The UFW `limit` rule covers host-level traffic; the DOCKER-USER rules are what actually rate-limit traffic to the container.
- **Image tag:** uses the official rolling `testnet-light-latest` tag, as the Post Fiat guide requires (version-pinned tags silently miss hotfixes). The installer refuses any other tag and logs the exact digest it ran.
- Admin ports are bound to loopback in the compose file itself, so they stay private even if the firewall is changed.
- Logs: `/var/log/postfiat-installer.log`. Node data: `/opt/postfiatd`.

## Backup and restore add-on

[`backup/`](backup/README.md): `pft-backup.sh` writes a timestamped tar.gz of the node config (postfiatd.cfg, validators.txt,
compose file, add-on units, firewall rules) with a SHA-256 manifest, retention pruning and a daily systemd timer. Secrets are
excluded unless you pass `--include-secrets`, which encrypts the archive with gpg. `pft-restore.sh` verifies the archive, restores it and
waits for `server_state: full`, and has a `--dry-run` mode. Restore drill onto a second host and tamper tests: [`logs/backup/`](logs/backup/).

```bash
sudo ./backup/pft-backup.sh && sudo ./backup/pft-restore.sh --dry-run /var/backups/postfiat/pft-backup-<UTC>.tar.gz
```

## Security audit add-on

[`audit/`](audit/README.md): `pft-audit.sh` is a read-only audit of a validator or sentry host: SSH hardening, loopback-only
admin ports, ufw and DOCKER-USER limits on 2559, Docker daemon/container posture, file permissions, patching, time sync,
node health and sentry/relay mode. One PASS/WARN/FAIL line per check with a fix hint, `--json` summary, exit codes 0/1/2.
Every check is documented in [`audit/README.md`](audit/README.md); FAIL-detection demos are in [`logs/audit/`](logs/audit/).

```bash
sudo ./audit/pft-audit.sh            # or: --json | jq .
```

## Secrets and config-exposure check add-on

[`secrets/`](secrets/README.md): `pft-secrets-check.sh` complements `audit/` with secret-leak and exposure checks.
It checks `postfiatd.cfg` admin roles and port exposure (via `docker port`), and `[validator_token]`/`[validation_seed]`
file modes, including stale copies. It scans `docker inspect` env/cmd, container logs, `debug.log`, shell history,
world-readable node files and backup archives for secret-format strings, printing counts only, never values.
A `--probe` mode runs from a second host and makes one TCP connect per admin/RPC port and the peer port.
Exit codes 0/1/2, `--json`. `positive-control.sh` plants dummy secrets and shows they are flagged.
Found → fixed → verified runs on both hosts: [`logs/secrets/`](logs/secrets/).

```bash
sudo ./secrets/pft-secrets-check.sh   # from another host: ./secrets/pft-secrets-check.sh --probe <node-ip>
```

## Integrity monitor add-on

[`integrity/`](integrity/README.md): `pft-integrity.sh` records a root-only 0600 manifest (hashes, modes, owners,
mtimes; never contents) of compose files, config-volume files, add-on units, `/usr/local/bin`, sshd config, UFW and
DOCKER-USER rules, the running image vs its registry digest, local image tags and the container's effective config.
`verify` reports added/removed/changed items with the changed fields (exit 0/1/2, `--json`). `accept --reason` re-baselines
and logs who/why. An optional hourly timer sends ntfy only when findings change. The four-change tamper drill on
both hosts is in [`logs/integrity/`](logs/integrity/).

```bash
sudo install -m 755 integrity/pft-integrity.sh /usr/local/bin/pft-integrity && sudo pft-integrity baseline
sudo pft-integrity verify
```

## Cross-host watchdog add-on

[`watchdog/`](watchdog/README.md): a dead-man's switch on a second host. `pft-heartbeat` (validator, 60s timer)
sends an HMAC-SHA256-signed status line (server_state, validated ledger, peers, build) over SSH to a forced-command
account on the sentry. `pft-watchdog` (sentry, 60s timer) reports `STALE` (no valid heartbeat), `LAGGING` (validated
ledger older than 60s by public-RPC close time; `unknown`, never LAGGING, when the public RPC is down), `BADSIG`
(forged/replayed/malformed) and `RECOVERED`, with one ntfy message per incident plus one recovery. Sandbox tests and
the live two-host drill are in [`logs/watchdog/`](logs/watchdog/).

```bash
sudo watchdog/install.sh heartbeat --relay <sentry-ip>                                  # validator
sudo watchdog/install.sh watchdog --pubkey F --hmac-key F --ntfy-env F                  # sentry
```

## Planned-maintenance add-on

[`maint/`](maint/README.md): `pft-maint start --ttl 30m --reason ...` writes a time-boxed, root-owned JSON flag and
pushes a signed copy to the sentry over the watchdog's restricted SSH channel. While the flag is valid and unexpired,
pft-watchdog (STALE/LAGGING; never BADSIG), postfiat-monitor and pft-integrity suppress and count their alerts;
expired or malformed flags are ignored (fail-open), and a non-OK state after the window is held for a
30-minute resync grace (`POST_MAINT_GRACE_SEC`), then alerted once if the node is still not OK. Exactly one `[MAINT]` message at start and one at end or expiry. `pft-maint restart-node` restarts postfiatd
only inside a window, with no data-collection lock held and the node `full`, then checks peers, sentry peering and
ledger progress and prints a one-line verdict. Tests: [`logs/maint/`](logs/maint/).

```bash
sudo maint/install.sh install --label validator                                         # each host (sentry: --label sentry)
sudo pft-maint start --ttl 30m --reason "config change" && sudo pft-maint restart-node && sudo pft-maint end
```

## Amendment and fee-voting status add-on

[`amendments/`](amendments/README.md): `pft-amendments.py` is a read-only report of every amendment's state
(enabled / supported / vetoed / pending majority with an activation ETA) and of the network fee settings
next to your node's `[voting]` vote. It uses only read-only admin RPC methods (`feature`, `server_info`,
`server_state`, `fee`, `ledger_entry`). Exit code `2` warns of amendment-blocked risk: an amendment that is
enabled or about to activate but is not supported by your build. `--json` writes snapshots and `--compare`
diffs against one. Live run and negative tests: [`logs/amendments/`](logs/amendments/).

```bash
sudo ./amendments/pft-amendments.py  # or: --json > snap.json; later --compare snap.json
```

## Peer diagnostics add-on

[`peers/`](peers/README.md): `pft-peers.py` checks your node's peers: count vs `[peers_max]`, inbound/outbound,
peer build versions (older than yours), latency p50/p90/max, connection age, ledger coverage, and whether a
validator's fixed sentry peer is connected. It uses only the read-only admin RPC methods `peers` and
`server_info`. Exit codes `0` OK, `1` WARN, `2` FAIL; `--json` for scripts. The output never contains peer IPs,
ports or public keys, only short salted-hash labels. Live run on both hosts and tests: [`logs/peers/`](logs/peers/).

```bash
sudo ./peers/pft-peers.py --read-config   # sentry host: --container postfiatd-sentry
```

## Validator-list (UNL) health add-on

[`vlwatch/`](vlwatch/README.md): `pft-vlwatch` is a read-only bash/curl/jq check of the node's validator list.
The monitor, alerts and watchdog add-ons watch server_state and peers, so they miss a slow loss of quorum from an
expired or stale publisher list. It checks each site's `last_refresh_status` and freshness, publisher-list
`available` and days to expiration, a sequence that never decreases (saved state file), trusted key count vs list
length and quorum, and `amendment_blocked`. Output is PASS/WARN/FAIL with exit codes `0/1/2` and `--json`, and an
optional 10-minute timer sends change-only ntfy (0600 env file). Offline tests, live runs on both hosts and the
throwaway-topic drill are in [`logs/vlwatch/`](logs/vlwatch/).

```bash
sudo bash vlwatch/pft-vlwatch.sh            # sentry host: --container postfiatd-sentry
sudo vlwatch/install.sh --timer --ntfy-env F  # optional change-only alerts
```

## Cold-resync RTO drill add-on

[`resync/`](resync/README.md): `pft-resync` measures how long a node takes to recover when its ledger DB is lost and
there is no backup. `plan` is read-only. `drill --yes` only runs inside an active [pft-maint](maint/README.md) window
with no data-collection lock. It renames the DB aside, starts the node empty, and times connected/syncing/full/first
validated/caught-up from 5 s `server_info` polls (JSON lines). It rolls back to the old DB on timeout or interrupt.
Run it on the sentry first. Two live sentry drills measured about 1 minute to `full` and caught up; the logs are
in [`resync/logs/`](resync/logs/).

```bash
sudo bash resync/pft-resync.sh plan --container postfiatd-sentry
cd resync && sudo bash drill-sentry.sh      # window + drill + notifiers on a throwaway topic
```

## Least-privilege container profile add-on

[`confine/`](confine/README.md): `pft-confine` drops every capability the postfiatd container does not need
(stock image: keeps only `SETGID SETUID` for cron), makes the root filesystem read-only with tmpfs for the five
directories it writes, and sets pids and memory limits sized from observed usage. `discover`/`plan` are read-only,
`probe` tests the profile in a throwaway container first, `apply --yes` runs only inside a pft-maint window and
rolls back if the node is not `full` within 15 minutes, `verify` checks every item. Run it on the sentry first.

```bash
sudo bash confine/pft-confine.sh plan --container postfiatd-sentry
sudo bash confine/pft-confine.sh probe --container postfiatd-sentry
```

## Default-deny container egress add-on

[`egress/`](egress/README.md): `pft-egress` blocks every new outbound connection from the postfiatd container
except DNS to its own resolvers, peer ports (2559 + `[ips]`/`[ips_fixed]` + ports seen in use) and the
validator-list site (443). Everything else is logged (rate-limited) and dropped. The rules live in a `PFT-EGRESS`
chain with one jump at `DOCKER-USER` position 1, so no restart is needed. `apply --yes` runs only inside a
pft-maint window, and a dead-man rolls back if the node leaves `full` or loses peers within 10 minutes.
A reapply timer restores the rules after a reboot or a container IP change. Run it on the sentry first.

```bash
sudo bash egress/pft-egress.sh plan --container postfiatd-sentry
sudo bash egress/pft-egress.sh apply --dry-run --container postfiatd-sentry
```

## Tamper-evident audit trail add-on

[`audittrail/`](audittrail/README.md): `pft-audittrail` adds real-time auditd watches (keyed: node config, validator
keys, sshd, sudoers, Docker, add-on units; execve of docker/systemctl/iptables with the login uid; time and module
changes) and persistent journald with Forward Secure Sealing, verification key kept off-host. `check` exits 1 on rule
or seal drift; `report` writes a Markdown summary with usernames hashed. Complements pft-integrity's hourly hash
compare with *when / who / which command*. No node restart. Run it on the sentry first.

```bash
sudo bash audittrail/pft-audittrail.sh plan
sudo bash audittrail/pft-audittrail.sh apply --dry-run
```

## Cross-host journal forwarding add-on

[`logship/`](logship/README.md): `pft-logship` forwards each host's systemd journal (auditd, journald and the
postfiatd container logs, copied from Docker's json-file log by a resumable bridge) to the other host of the
pair within seconds. It uses `systemd-journal-upload`/`-remote` with mutual TLS from a private two-host CA, where
keys never leave their host, plus a peer-only UFW rule and capped storage per sender. Deleting a host's local
journal then no longer deletes the evidence. `check` exits 1 on lag, a stalled cursor or a TLS failure. A
per-minute timer writes `pft_logship_up` / `pft_logship_lag_seconds`, and `PFTLogshipBroken` alerts on them
(promtool-tested). No node restart. Run it on the sentry first.

```bash
bash logship/pft-logship.sh plan
sudo bash logship/pft-logship.sh apply --dry-run
```

## Alert rules add-on

[`alerts/`](alerts/README.md): 16 Prometheus alert rules for the exporter's metrics. They cover node/RPC down,
not full or not proposing, peers, validated-ledger age and stall, complete_ledgers gaps, close-time drift,
load_factor, container restarts and disk. Each rule has a severity label, a `for:` duration and a runbook link to
its threshold rationale and operator response. The add-on includes promtool unit tests (firing and non-firing per
alert). `run-stack.sh` runs Prometheus and Alertmanager in Docker on loopback only, with optional ntfy delivery.
Live stop-the-node drill: [`logs/alerts/`](logs/alerts/).

```bash
cd alerts && DOCKER="sudo docker" ./run-stack.sh up   # optional: NTFY_ENV_FILE=~/.pft-ntfy.env
```

## SLO and error-budget add-on

[`slo/`](slo/README.md): an availability SLI (scrape up, RPC up, `server_state` full or better, validated
ledger younger than 10 s) recorded every 15 s, a 30-day objective (default 99.5 %) and multi-window burn-rate
alerts (`PFTSLOFastBurn` 14.4x over 1h and 5m, `PFTSLOSlowBurn` 6x over 6h and 30m) through the existing ntfy
bridge. Time inside a `pft-maint` window does not burn budget (`pft_maint_active` from the exporter).
`pft-slo-report` writes a Markdown report from Prometheus range queries: SLI, budget used, bad intervals with a
likely cause, maintenance excluded.

```bash
DOCKER="sudo docker" bash slo/check.sh                        # promtool + unit tests + mutation controls
python3 slo/pft_slo_report.py --window 7d --step 60s -o slo-report.md
```

## Diagnostics bundle add-on

[`bundle/`](bundle/README.md): `pft-bundle.sh collect` gathers what a helper asks for first (OS, image digest,
container state, `server_info`/`server_state`/`peers`/`validator_list_sites`/`feature`, the config, the last
2000 `debug.log` lines, disk/memory, UFW, `pft-*` units) into one 0600 `tar.gz` with a sha256 manifest. It is
read-only. Secret config sections are dropped, and IPs, hostnames and ntfy topics become stable tokens
(`<ip-N>`, `<host-N>`). If any seed, token or identity survives, no bundle is written. `verify` re-checks the
manifest, the optional ssh signature and the scan.

```bash
sudo bash bundle/pft-bundle.sh collect --container postfiatd-sentry --label sentry-host
bash bundle/pft-bundle.sh verify /var/tmp/pft-bundle-sentry-host-<UTC>.tar.gz
```

## Consensus-divergence monitor add-on

[`divergence/`](divergence/README.md): `pft-divergence` is a read-only, 1-minute timer check. It compares
`ledger_hash`, `account_hash` and `transaction_hash` at the newest common validated index, and at the index 200
below it, across the validator, the sentry (over ssh) and the public RPC. A node that is `full` but on another
chain shows up as `DIVERGED`. A mismatch only counts if it is still there after 2 re-queries, and RPC errors are
retried with backoff, so they end up as `UNKNOWN`, never `DIVERGED`. It writes a Prometheus textfile, which the
exporter now reads (`PFT_TEXTFILE_DIR`). `PFTLedgerDiverged` and `PFTDivergenceCheckStale` are in
`alerts/divergence.rules.yml`.

```bash
DOCKER="sudo docker" bash divergence/check.sh                 # shellcheck, fake-RPC suite + mutants, promtool
sudo bash divergence/install.sh --sources "validator=docker:postfiatd public=http:https://rpc.testnet.postfiat.org/"
sudo pft-divergence --json
```

## Systemd sandboxing for the add-on units (unitguard)

[`unitguard/`](unitguard/README.md): `pft-unitguard.sh` audits the add-on units with `systemd-analyze security`
and applies one drop-in per unit from a per-unit profile (`standard` / `docker` / `iptables` class, documented
exceptions), with a functional check right after apply and automatic rollback on failure. Live on both hosts:
22 units from 9.6 UNSAFE (exporter 8.1) to 0.5-2.6. pft-integrity now also tracks unit drop-ins.

```bash
sudo bash unitguard/pft-unitguard.sh audit --detail
sudo bash unitguard/pft-unitguard.sh apply pft-exporter.service && sudo pft-integrity accept --reason "unitguard: pft-exporter"
bash unitguard/tests/test-unitguard.sh && bash unitguard/tests/mutants-unitguard.sh
```

## Config linter add-on (cfglint)

[`cfglint/`](cfglint/README.md): `pft-cfglint.sh` flags `postfiatd.cfg` sections and keys the running build silently
ignores (unknown, typo'd, documented-but-unread like `[vl] enable`, empty values, duplicates). It checks against a
registry extracted from the postfiatd source at the node's exact commit, with file:line provenance. Read-only; never prints
values. Live: validator and sentry clean. Throwaway-node drill: `enable=0` is flagged and leaves `/vl` served
(HTTP 200); only `enabled=0` closes it (HTTP 403).

```bash
bash cfglint/pft-cfglint.sh                       # exit 0 clean, 1 findings, 2 error
bash cfglint/pft-cfglint.sh --file postfiatd.cfg --json
```

## Alert-pipeline dead-man add-on (alertpath)

[`alertpath/`](alertpath/README.md): checks that the alerting pipeline itself still works, from the sentry. An
always-firing `PFTAlertPipelineWatchdog` is routed only to a loopback sink (never to the operator topic). Every 30s
the validator sends an HMAC-signed snapshot (last delivery + Prometheus/Alertmanager self-metrics + bridge state) over
a forced-command SSH key. Every 60s `pft-alertpath check` on the sentry decides `OK` / `DEGRADED` / `STALE`
(exit 0/1/2, `--json`) and notifies through its own ntfy config.

```bash
sudo alertpath/install.sh validator --relay <sentry-ip>                                  # validator
sudo alertpath/install.sh sentry --pubkey F --hmac-key F --ntfy-env F                    # sentry
sudo pft-alertpath check --json                                                          # sentry
```

## Vulnerability audit add-on (vulnscan)

[`vulnscan/`](vulnscan/README.md): evaluates Canonical's Jammy USN OVAL feed against the installed packages with
OpenSCAP, once a day on each host. Lists every USN that still applies (priority, CVEs, packages, installed -> fixed,
and whether the fix is in the archive or only in Ubuntu Pro/ESM), detects a reboot owed, refuses stale (> 7 days),
tampered or truncated feeds (exit 2, `up 0`), and exports `pft_vulnscan_*` metrics with alerts
(`../alerts/vulnscan.rules.yml`). Complements `patch/`, which only sees what apt can install.

```bash
sudo vulnscan/install.sh                  # validator (sentry: --host sentry; validator pull: --pull)
sudo pft-vulnscan scan [--json]           # exit 0 clean, 1 findings/reboot owed, 2 scan error
```

## Upgrade

```bash
cd /opt/postfiatd && docker compose pull && docker compose up -d && sudo postfiat-health
```

## Uninstall

```bash
cd /opt/postfiatd && docker compose down
sudo systemctl disable --now postfiat-docker-user.service
sudo rm -f /etc/systemd/system/postfiat-docker-user.service /usr/local/sbin/postfiat-docker-user.sh /usr/local/bin/postfiat-health
sudo ufw delete limit 2559/tcp
```

Back up any validator keys before deleting `/opt/postfiatd`.

## Test run log

See [`logs/test-run.log`](logs/test-run.log) for a full run on a clean Ubuntu 22.04 host.

## Add-on inventory, version skew and pinned sync (fleet)

[`fleet/`](fleet/README.md): compares the installed bytes of every add-on file on the validator and the sentry with
this repo's git history. `inventory` lists each file's sha256, the commit those bytes came from and the unit states;
`skew` grades each add-on per host CURRENT / BEHIND / MODIFIED / MISSING / UNEXPECTED plus cross-host DIVERGED (exit
0/1/2) and exports `pft_fleet_*` metrics with a stale-drift alert (`../alerts/fleet.rules.yml`). `sync` installs one
add-on exactly as it is at a pinned commit: dry run by default, sentry first, only inside a `pft-maint` window,
health-gated per host with automatic rollback, and a reasoned `pft-integrity accept`.

```bash
sudo fleet/install.sh                                        # validator; needs /etc/pft-fleet/{fleet,hosts}.conf
sudo pft-fleet skew                                          # exit 0 current, 1 drift, 2 modified/missing/unreadable
sudo pft-fleet sync --addon statewatch --to <commit> [--apply]
```

## Dead-rule and stale-input checker (rulecheck)

[`rulecheck/`](rulecheck/README.md): finds alert rules that cannot fire and collector inputs that stopped updating.
For every rule in Prometheus it queries each PromQL selector (skipping `absent()` arguments and `ALERTS`) and grades
the rule LIVE / PARTIAL / DEAD / ERROR. For every file in the exporter's textfile dir it grades FRESH / STALE /
MISSING / LEFTOVER / UNCONFIGURED. Pulled copies are judged by the collector timestamp inside the file, so a sentry
collector that stopped shows up even though the validator re-copies the file every minute. Output is a table or
JSON with exit 0/1/2, plus `pft_rulecheck_*` metrics. Three alerts are defined in `../alerts/rulecheck.rules.yml`:
PFTRuleDead, PFTTextfileStale and PFTRulecheckNotRunning. An hourly sandboxed timer runs on both hosts, and the
validator pulls the sentry's result.

```bash
sudo rulecheck/install.sh                 # validator (Prometheus host)
sudo rulecheck/install.sh --no-prom       # sentry: textfile checks only
sudo rulecheck/install.sh --pull          # validator: pull the sentry's result (PEER_LABEL + PULL_SSH in /etc/pft-rulecheck.env)
sudo pft-rulecheck check [--json]         # exit 0 all LIVE/FRESH, 1 findings, 2 could not check
```

## SSH crypto-policy audit and safe hardening (sshcrypto)

[`sshcrypto/`](sshcrypto/README.md): grades every key exchange, cipher, MAC and host key algorithm sshd offers
(`sshd -T`) plus the host key sizes OK / WARN / FAIL against a written policy, and proves with loopback-only
handshakes that the running daemon negotiates exactly what its config says (a mismatch means a missed reload).
`apply` installs a hardened drop-in safely: `sshd -t` and an effective-value check first, a revert timer armed before
the `reload` (never a restart), then a new-session login check; if that check fails the timer rolls the change back
by itself. `rollback` is byte-identical (sha256 of every sshd config file and of `sshd -T`). Text/JSON output with
exit 0/1/2, `pft_sshcrypto_*` metrics, six alerts in `../alerts/sshcrypto.rules.yml`, hourly sandboxed audit on
both hosts, and the validator pulls the sentry's result.

```bash
sudo sshcrypto/install.sh                 # validator (sentry: --host sentry; validator pull: --pull). Changes no sshd setting
sudo pft-sshcrypto audit [--json]         # exit 0 all OK, 1 WARN/FAIL or probe mismatch, 2 audit error
sudo pft-sshcrypto apply                  # exit 0 confirmed, 3 not confirmed (auto-revert armed), 2 refused
sudo pft-sshcrypto rollback               # restore the pre-apply files byte-identically
```
