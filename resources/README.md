# pft-resources: container resource monitor (cgroup v2)

`postfiatd` runs in a Docker container with hard limits (on these hosts: memory 2.25 GiB / 2 GiB, pids 256, soft
`nofile` 1024). When it reaches one of them, the node stops doing its job: the kernel OOM-kills it, `accept()` fails
with EMFILE, or new threads cannot be created. The existing add-ons see the node only from the outside (RPC state,
peers, ledgers). `pft-resources.sh` reads the container's own cgroup v2 files once a minute and writes them as
`pft_resources_*` Prometheus textfile metrics, and `../alerts/resources.rules.yml` alerts before a limit is hit.

Tested on Ubuntu 22.04.5, kernel 5.15, Docker, on a validator host and a sentry host.

**One Prometheus for both hosts.** The card asks for "metrics scraped by Prometheus on both hosts". The sentry runs
no Prometheus by design (no second alert path, no new listener). `pft-resources-pull` copies the sentry's textfile
to the validator over the existing admin ssh link every minute, and the validator's Prometheus (`../alerts`) scrapes
and alerts on both hosts' metrics, with `container="postfiatd"` and `container="postfiatd-sentry"`.

## What it reads

`pft-resources collect` resolves the container's main PID (`docker inspect`), takes its cgroup v2 path from
`/proc/PID/cgroup` (the `0::` line only, v1 lines are ignored), and reads:

| source | metrics |
|---|---|
| `memory.current`, `memory.max`, `memory.peak` | `pft_resources_memory_current_bytes`, `_memory_max_bytes`, `_memory_peak_bytes` |
| `memory.events` | `pft_resources_memory_events_total{event="oom_kill|oom|max|high"}` |
| `memory.stat` | `pft_resources_memory_stat_bytes{item="anon|file|kernel_stack|sock|shmem"}` |
| `cpu.stat`, `cpu.max` | `pft_resources_cpu_usage_seconds_total`, `_cpu_periods_total`, `_cpu_throttled_periods_total`, `_cpu_throttled_seconds_total`, `_cpu_limit_cores` |
| `pids.current`, `pids.max` | `pft_resources_pids_current`, `_pids_max` |
| `{memory,cpu,io}.pressure` | `pft_resources_pressure_avg{10,60,300}_ratio{resource,kind="some|full"}`, `_pressure_stall_seconds_total` |
| `/proc/<PROC_NAME pid>/fd`, `/limits` | `pft_resources_fd_open`, `_fd_limit_soft` |
| `docker inspect` | `pft_resources_container_oom_killed`, `_container_restarts`, `_container_info{id}` |
| run | `pft_resources_up`, `_collect_timestamp_seconds`, `_file_supported{file}`, `_limit_set{resource}` |

- **Read-only.** It changes nothing on the host; the textfile is written atomically (temp file + rename).
- **Fails closed.** On any read or parse error of a required file it writes only `pft_resources_up 0` and the
  timestamp (no stale values) and exits 1. The offline suite found two ways the first build failed open (a reader
  error lost inside `$(...)`, and an empty error message that did not count as an error); both are fixed and have
  tests and mutants (logs 04-07).
- **Optional files are not errors.** `memory.peak` needs kernel >= 5.19 (absent on 5.15), PSI may be off:
  `pft_resources_file_supported{file="memory.peak"} 0`.
- **`max` limits.** `memory.max = max` is exported as host MemTotal, `pids.max = max` as `kernel.pid_max`, with
  `pft_resources_limit_set{resource=...} 0`, so the ratios stay meaningful.
- **OOM kills across restarts.** An OOM kill of the main process restarts the container into a NEW cgroup whose
  `memory.events` starts at 0, so the cgroup counter alone would miss exactly that kill. Docker's `State.OOMKilled`
  and `RestartCount` are exported too and the alert checks both.
- **History.** With `HISTORY=` set (here `/var/lib/pft-resources/history-<container>.jsonl`), each successful run
  appends one JSON line for the 24h report. Failed runs append nothing.

## Alerts (`../alerts/resources.rules.yml`)

| alert | expression (short) | for | severity |
|---|---|---|---|
| PFTResourcesCollectorFailing | `pft_resources_up == 0` | 5m | warning |
| PFTResourcesStale | last collection older than 300 s | 2m | warning |
| PFTMemoryNearLimit | memory.current / memory.max > 0.90 | 5m | critical |
| PFTMemoryGrowthToLimit | `predict_linear(...[1h], 6h)` > memory.max and usage > 50% of max | 30m | warning |
| PFTContainerOOMKill | `increase(oom_kill[10m]) > 0` or docker OOMKilled changed to 1 within 10 m | - | critical |
| PFTFdNearLimit | open fds / soft nofile > 0.80 | 5m | warning |
| PFTPidsNearLimit | pids.current / pids.max > 0.90 | 5m | warning |
| PFTCPUThrottled | throttled / total periods > 0.25 over 10m | 15m | warning |
| PFTMemoryPressure | memory PSI some avg60 > 10% | 10m | warning |
| PFTIOPressure | io PSI some avg60 > 30% | 15m | warning |

In each `A and B` the measured ratio is on the left, because the alert's `$value` (shown in the ntfy message) comes
from the left operand; the first draft had the guard on the left and showed fd use as "1.024e+05%" (log 10).

Docker sets `State.OOMKilled` for ANY OOM kill in the container's cgroup, also when only a child process was killed
and the main process lives on, and keeps it until the next start. A rule on `oom_killed == 1` would never resolve
(found by the drill smoke test, log 22). The rule therefore fires on a **change** of the flag within 10 min, or on a
cgroup `oom_kill` increase, and resolves 10 min after the kill.

`resources.tests.yml`: promtool unit tests at 1m intervals, firing and non-firing case for every rule, with the
expected annotation values computed by hand.

## Install

On each host (container name `postfiatd` on the validator, `postfiatd-sentry` on a sentry from `../sentry`):

```
sudo ./install.sh --container postfiatd           # validator
sudo ./install.sh --container postfiatd-sentry    # sentry
sudo pft-integrity accept --reason "pft-resources install"
```

This installs `/usr/local/bin/pft-resources`, `pft-resources@.service` (sandboxed: read-only, `CAP_DAC_READ_SEARCH`
and `CAP_SYS_PTRACE` only, `AF_UNIX`) and `pft-resources@.timer` (every minute), runs one collection in the
foreground (must exit 0), and enables the timer. Config: `/etc/pft-resources.env` (root-owned; `CONTAINER`,
`PROC_NAME`, `TEXTFILE_DIR`, `HISTORY`).

On the validator (the host that runs `../alerts`), pull the sentry's file and load the rules:

```
sudo install -m 0600 pft-resources-pull.env.example /etc/pft-resources-pull.env   # then set PULL_SSH
sudo ./install.sh --pull postfiatd-sentry
# add /etc/pft-alerts/resources.rules.yml to ../alerts/prometheus.yml rule_files, then
bash ../alerts/run-stack.sh check && sudo docker kill -s HUP pft-prometheus      # reload, no Alertmanager recreate
```

`pft-resources-pull` accepts the peer's file all-or-nothing: only `pft_resources_*` names, only the expected
container label, numeric values, `up` and timestamp present, size limit. On any failure it keeps the previous copy,
so a broken link shows up as `PFTResourcesStale` instead of wrong data.

Uninstall: `sudo ./install.sh --uninstall [--container NAME]` and `sudo ./install.sh --pull NAME --uninstall`
(history is kept), then remove the rules file from `prometheus.yml`.

## Tests

```
bash tests/run-tests.sh      # offline: fixture cgroup v2 + /proc trees, stub docker, no root
bash tests/check.sh          # mutants of pft-resources.sh, each must be CAUGHT by run-tests.sh
bash tests/test-pull.sh      # offline: stub PULL_SSH (fixture / fails / hangs)
bash tests/check-pull.sh     # mutants of pft-resources-pull.sh
bash tests/check-rules.sh    # promtool check + test rules, then rule mutants (docker, prom/prometheus:v3.5.0)
python3 drill/test_drill_verdict.py
python3 report/test_report.py && python3 report/mutate_report.py
shellcheck pft-resources.sh pft-resources-pull.sh install.sh drill/*.sh tests/*.sh
```

Fixtures: normal, no memory limit (`max`), missing PSI files, restarted container (new cgroup path), malformed
file, cgroup v1 lines in `/proc/PID/cgroup`. A mutant counts as caught only when the suite printed its `RESULT` line
and at least one `FAIL` (an aborted suite is not a catch, log 06).

Final runs: collector 52/52 + 16/16 mutants and shellcheck clean (log 17), rules promtool SUCCESS + 13/13 rule
mutants (log 24), drill checker 15/15 (log 27), report 19 tests + 11/11 mutants (log 31).

## Live drill (both hosts, log 28)

`drill/drill.sh` runs on the validator and drives the sentry over ssh. It never touches `postfiatd`: the load runs
in a throwaway container on each host (`python:3.12-alpine`, `--network none`, read-only, no capabilities, memory
128m without swap, pids 32, nofile 64). The alert bridge is pointed at a throwaway ntfy topic for the drill
(`../alerts/run-stack.sh bridge` recreates only the bridge, so Prometheus/Alertmanager state and silences survive)
and restored afterwards (mount source checked).

Phases: idle -> load (fds 87.5%, pids 94%, memory 93%) -> oom (one child OOM-killed inside the cgroup) -> calm
(until every drill alert has resolved and `[RESOLVED]` is on the topic). Every ~30 s it samples both nodes'
`server_state` and the Prometheus/Alertmanager state into `samples.jsonl`.

Result 2026-10-27 08:17:53Z-08:38:25Z: **DRILL PASS 29/29**. PFTFdNearLimit, PFTPidsNearLimit, PFTMemoryNearLimit
and PFTContainerOOMKill fired and resolved for both drill containers, with 8 `[FIRING]` and 8 `[RESOLVED]` messages on
the throwaway topic; both nodes were `full` in all 43 samples; no alert for a real container; drill containers,
textfiles and the sentry's pulled image removed; pft-integrity PASS on both hosts afterwards; the 24h history files
got 0 drill lines. PFTMemoryGrowthToLimit went *pending* during the load step (5% -> 93% in a minute extrapolates
past the limit) and its `for: 30m` kept it from firing, as intended.

## 24h baseline report

_Filled in after the window closes (2026-10-28T06:13Z): `report/report.py` over both hosts' history files ->
`REPORT-24h.md` (min/median/p95/max, growth rate, offline replay of the rules, recommended thresholds)._

## Logs

`logs/NN-*.log` are every recorded run of this task, in order, including the failed and superseded ones (each says
so in its first lines or in the run after it). Redactions: hostnames -> `validator-host`/`sentry-host`, the local
user and home path -> `<user>`/`<repo>`, ntfy topics -> `<redacted>`; nothing else was changed.
