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

Real values from both hosts, 2026-10-29T14:16Z .. 20:17Z (6.01 h), from the history files the units write
(`data/baseline-postfiatd.jsonl`, `data/baseline-postfiatd-sentry.jsonl`, 362 one-minute samples each, 0 gaps
> 90 s, 0 restarts), computed by `python3 report/report.py --json data/baseline-report.json data/*.jsonl`
(log 11). Per-mode time is the increase of `state_accounting` duration between samples.

| | validator (`postfiatd`) | sentry (`postfiatd-sentry`) |
|---|---|---|
| time share full / tracking / syncing / connected / disconnected | 100% / 0 / 0 / 0 / 0 | 100% / 0 / 0 / 0 / 0 |
| state transitions per hour (all modes) | 0.0 | 0.0 |
| full exits | 0 (0.0 per hour) | 0 (0.0 per hour) |
| io_latency_ms min / p50 / p90 / p99 / max | 1 / 1 / 1 / 2 / 8 | 1 / 1 / 1 / 6 / 13 |
| io_latency_ms value counts | 1: 353, 2: 7, 3: 1, 8: 1 | 1: 350, 2: 4, 3: 2, 5: 2, 6: 2, 11: 1, 13: 1 |
| peer_disconnects | +1 (0.17 per hour), max 0 in any of 5 full clock hours | +2 (0.33 per hour), max 0 in any of 5 full clock hours |
| peer_disconnects_resources / jq_trans_overflow | +0 / +0 | +0 / +0 |

Threshold rationale (each threshold against the baseline it is compared with):

| alert | threshold | baseline | why |
|---|---|---|---|
| PFTIOLatencyHigh | > 50 ms for 10 m | max 8 / 13 ms, p99 2 / 6 ms | ~4x the worst single sample seen; `for: 10m` ignores one-off spikes like the 11-13 ms sentry samples and fires only on a sustained job-queue IO stall |
| PFTPeerDisconnectRateHigh | > 30 per 1 h | 0.17 / 0.33 per hour, hourly max 0 | about twice the peer count (17 / 15): every peer dropping twice in an hour, i.e. churn, not the occasional single disconnect seen here |
| PFTNodeStateFlapping | >= 3 full exits per 1 h | 0 in 6 h on both | one exit is a warning (PFTNodeBriefFullExit); three in an hour is a pattern |
| PFTNodeBriefFullExit | any full exit in 10 m that every sample missed | 0 | the event scrape-time monitoring cannot see; never happened in the baseline, so any occurrence is news |
| PFTJobQueueOverflow | any increase in 15 m | +0 on both | a dropped transaction is never normal |
| PFTStatewatchCollectorFailing / Stale | up 0 for 5 m / no collection for 300 s + 2 m | 0 gaps > 90 s in 362 samples per host | five missed 1-minute runs in a row; a single slow `docker exec` does not page |

Limits: six quiet hours on two healthy nodes. The baseline shows the thresholds sit far above normal operation (no
false positives) but contains no real fault, so it cannot show how far below a real incident they are; the fault side
is covered by the promtool fire cases (log 07), the mutants (log 08) and the restart drill (log 12). The sentry restart
drill itself is excluded from the baseline window (it started at 20:18Z).

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
| 10-drillcheck-controls.log | drill/check.sh positive and negative controls against real Prometheus history (8 controls as expected) |
| 11-baseline-report.log | 6.01 h two-host baseline: history extraction, sha256 + line counts of the data files, report.py output |
| 12-sentry-restart-drill.log | live sentry restart drill (drill/live-run.sh), see below |

A trial mutation run before 08 (not recorded) found that the "hung ssh" pull test did not hang: a stub
`PULL_SSH="sleep 30 ;"` is word-split, so `;` became an argument and `sleep` failed at once, and mutant S12 (no
timeout around ssh) survived. The test now uses a stub that really sleeps and checks the elapsed time (aa4a265).

## Sentry restart drill (`drill/live-run.sh`, log 12)

`bash drill/live-run.sh 2>&1 | tee LOG` (agent user, from `statewatch/`). Before anything changes it checks both nodes
are full, no pft-maint window is open and statewatch series exist for the sentry, and runs the redaction positive
control. It then points every ntfy notifier on both hosts (postfiat-monitor, pft-integrity, pft-watchdog,
pft-alertpath) and the Alertmanager bridge at a random throwaway topic, and silences every alert EXCEPT the seven
statewatch rules and the pipeline watchdog: the statewatch rules stay live because they are the thing under test.
It restarts `postfiatd-sentry`, polls `pft-statewatch collect --stdout` every 5 s until full, holds 15 minutes
(longer than every statewatch window a restart touches), runs `drill/check.sh`, restores everything (sha256 compared,
bridge mount read back) and counts messages on the throwaway and every operator topic.

Result of run 20261029T201817Z (log 12): PASS, 0 checks failed.
- Restart 20:18:35Z, back to full 48 s later. The 5 s poll captured the progression: `up 0` while the RPC was down,
  then `connected` with transitions d/c/s/t/f = 2/2/0/0/0, then `full` with 2/2/1/1/1.
- Reset handling: `check.sh` C0-C5 all PASS (uptime resets 1, full_exits increase 0, back to full, up 1, no
  statewatch alert fired). Prometheus saw `resets()` 1 and `increase()` ~1 for syncing/tracking/full (the 1-minute
  collection caught the 0/0/0 intermediate); disconnected/connected came back at the same value 2, so Prometheus
  shows no increase there, as expected. `report.py` (uptime-aware) counts all 7 transitions of the new process.
- No statewatch alert fired on any container; the throwaway topic got 0 messages; both operator topics got 0
  messages; all five env files restored byte-identical and the bridge mounts the operator env again; pft-integrity
  PASS on both hosts (no rebaseline needed: no file changed). The unrelated-alert silence was kept until container
  start + 25 min (PFTContainerRestarted's tail) and then expired by itself.
