# pft-statewatch: postfiatd state and health counters

The pft exporter (`../exporter`) reads `server_info.server_state` when Prometheus scrapes it, so it only knows the
state at that instant. A node that drops out of `full` for 20 s between two scrapes, a job queue that overflows and
drops transactions, or a burst of peer disconnects leaves no trace there. `postfiatd` keeps cumulative counters for
all of these in `server_info` (`state_accounting`, `jq_trans_overflow`, `peer_disconnects*`, plus `io_latency_ms`).
`pft-statewatch.sh` exports them once a minute as `pft_statewatch_*` Prometheus textfile metrics, and
`../alerts/statewatch.rules.yml` alerts on them in a way that a `postfiatd` restart (which resets every counter)
cannot trigger.

Tested on Ubuntu 22.04.5, Docker, postfiatd 1.0.9, on a validator host and a sentry host.

**One Prometheus for both hosts** (same design as `../resources` and `../timesync`). The sentry runs no
Prometheus and no new listener. `pft-statewatch pull` on the validator copies the sentry's textfile over the
existing admin ssh link every minute (validated, all-or-nothing), and the validator's Prometheus scrapes and alerts
on both, with `container="postfiatd"` and `container="postfiatd-sentry"`.

## What it reads

`pft-statewatch collect` runs `docker exec CONTAINER curl ... server_info` against the admin RPC on the
**container's own loopback** (`127.0.0.1:5005` inside the container). That works the same on the validator and on
the sentry, which maps no admin port to the host. `statewatch_parse.py` (Python 3, stdlib) validates every field.

| server_info field | metric |
|---|---|
| `server_state` | `pft_statewatch_server_state{state}` (one-hot over the 7 states) |
| `server_state_duration_us` | `pft_statewatch_server_state_duration_seconds` |
| `state_accounting.<mode>.duration_us` | `pft_statewatch_state_duration_seconds_total{state}` (5 operating modes) |
| `state_accounting.<mode>.transitions` | `pft_statewatch_state_transitions_total{state}` |
| derived | `pft_statewatch_full_exits_total` = full transitions - (1 if in mode full now) |
| `io_latency_ms` | `pft_statewatch_io_latency_ms` |
| `jq_trans_overflow` | `pft_statewatch_jq_trans_overflow_total` |
| `peer_disconnects`, `peer_disconnects_resources` | `pft_statewatch_peer_disconnects_total`, `_peer_disconnects_resources_total` |
| `uptime`, `peers` | `pft_statewatch_node_uptime_seconds`, `pft_statewatch_peers` |
| run | `pft_statewatch_up`, `pft_statewatch_collect_timestamp_seconds` |

- **Operating modes vs states.** `state_accounting` counts the five operating modes (disconnected, connected,
  syncing, tracking, full). `validating` and `proposing` are `server_state` values of a node in mode full, so
  `full_exits` treats all three as full.
- **Why `full_exits`.** The raw transition counters are useless for alerting across a restart: a normal start
  enters disconnected, connected, syncing, tracking and full (7 transitions on these hosts), which looks exactly like
  flapping. `full_exits` counts only how often the running process LEFT full: it is 0 before the first full, 1 - 1 = 0
  after it, and only grows when the node drops out of full. A restart never increases it.
- **Fails closed.** Any failure (docker, curl, a 10 s RPC timeout, an outer timeout against a hung `docker exec`,
  non-JSON, an RPC error, a missing or malformed field, an unknown state, "full" with 0 full transitions) writes only
  `pft_statewatch_up 0` and the timestamp, never stale or partial values, and exits 1.
- **Atomic.** The textfile is written to a temp file in the same directory and renamed.
- **History.** With `--history FILE` (the unit uses `/var/lib/pft-statewatch/history-<container>.jsonl`) each
  successful run appends one JSON line for `report/report.py`. History is best-effort: a write error is logged and
  the metrics are still written.

## Alerts (`../alerts/statewatch.rules.yml`)

| alert | expression (short) | for | severity |
|---|---|---|---|
| PFTStatewatchCollectorFailing | `pft_statewatch_up == 0` | 5m | warning |
| PFTStatewatchStale | last collection older than 300 s | 2m | warning |
| PFTNodeBriefFullExit | `increase(full_exits[10m]) > 0` and every 1-minute sample of server_state in those 10 min was full | - | warning |
| PFTNodeStateFlapping | `increase(full_exits[1h]) >= 3` | - | critical |
| PFTJobQueueOverflow | `increase(jq_trans_overflow[15m]) > 0` | - | warning |
| PFTIOLatencyHigh | `io_latency_ms > 50` | 10m | warning |
| PFTPeerDisconnectRateHigh | `increase(peer_disconnects[1h]) > 30` | - | warning |

`PFTNodeBriefFullExit` is the exit that scrape-time monitoring cannot see; a longer exit (server_state sampled as
not full) is `PFTNodeNotFull`'s job in `../alerts/postfiat.rules.yml` and is not reported twice. Counter rules use
`increase()`, which treats a drop as a reset and only counts what came after it.

## Install

On each host (validator: `postfiatd`; sentry: `postfiatd-sentry`):

```
sudo ./install.sh --container postfiatd            # script, parser, units; one sandboxed run must give up 1
sudo pft-integrity accept --reason "pft-statewatch installed"
```

On the validator, for the sentry's metrics (needs `PULL_SSH` in `/etc/pft-statewatch.env`, root-owned 0600, see
`pft-statewatch.env.example`):

```
sudo ./install.sh --pull postfiatd-sentry
```

Then add `/etc/pft-alerts/statewatch.rules.yml` to `../alerts/prometheus.yml` (done in this repo) and reload
Prometheus without restarting it: `sudo docker kill -s HUP pft-prometheus`.

The units run as root (docker socket) inside a systemd sandbox: `ProtectSystem=strict`, `ProtectHome`, no
capabilities, `IPAddressDeny=any`, `RestrictAddressFamilies=AF_UNIX`, writes only to the textfile and history dirs.

## Tests

| suite | what | command |
|---|---|---|
| `tests/run-tests.sh` | collector + parser + validate + pull, stub docker/ssh, fixture with the real field shapes | `bash statewatch/tests/run-tests.sh` |
| `../alerts/statewatch.tests.yml` | promtool: fire, no-fire, counter reset, recovery for every rule | `promtool test rules statewatch.tests.yml` |
| `tests/gen_rule_tests.py` | generates the promtool file (hand-written series and values, annotation text from the rules) | `python3 statewatch/tests/gen_rule_tests.py > alerts/statewatch.tests.yml` |
| `tests/mutate.py` | mutation controls over the collector, the parser and the rules | `python3 -u statewatch/tests/mutate.py` |
| `report/test_report.py` | baseline report arithmetic (reset, gap, brief exit) | `python3 statewatch/report/test_report.py` |

## Baseline and thresholds

Pending: the 6-hour two-host baseline started 2026-10-29T14:16Z.

## Evidence (logs/)

Every log is the raw output of the command shown in it (redacted: host names, user name). The OS line is first.

| log | what |
|---|---|
| 01-tests.log | offline suite, build 1 (c60ee89): 86/86, shellcheck 0 |
| 02-install-sentry.log | first sentry install **failed**: under the unit's sandbox the docker CLI printed "Error loading config file" on stderr, which the collector had merged into the JSON answer (`2>&1`), so every run read "not JSON" and wrote up 0. Kept as found. |
| 03-tests.log | build 2 (2a0510b): stderr kept separate, `DOCKER_CONFIG=/tmp` in the unit, regression test; 87/87, and the same suite against the build 1 script fails exactly that test (86/87) |
| 04-install-sentry.log | sentry install of build 2: first sandboxed run up 1, timer enabled |
| 05-install-validator.log | validator install (collect + sentry pull), both containers served by the exporter |
| 06-integrity-accept.log | pft-integrity WARN on the new files, accepted with reason, PASS on both hosts |
| 07-tests.log | build 3 (aa4a265): shellcheck, ruff, offline suite 87/87, generated promtool file up to date, promtool check + test SUCCESS, full `run-stack.sh check` |
| 08-mutants.log | mutation run 1 @ aa4a265 over collector (14), parser (12) and rules (13): controls pass, 39/39 caught, 0 not applied, 0 broken, each with the FAIL lines / failed promtool cases it produced |
| 09-rules-live.log | rules loaded into the live Prometheus by SIGHUP (no container restart), 7 rules health ok, 0 alerts |

A trial mutation run before 08 (not recorded) found that the "hung ssh" pull test did not hang: a stub
`PULL_SSH="sleep 30 ;"` is word-split, so `;` became an argument and `sleep` failed at once, and mutant S12 (no
timeout around ssh) survived. The test now uses a stub that really sleeps and checks the elapsed time (aa4a265).
