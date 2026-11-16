# postfiatd internal-health metrics (`pft-internals`)

The exporter reads `server_info` basics (state, peers, load factor), `../statewatch` its state accounting and
disconnect counters, `../peerwatch` the peer set. None of them looks *inside* the node: how fast the NodeStore
answers, whether the ledger caches still hit, whether jobs queue up, which RPC methods are called and fail.
postfiatd reports all of that on two admin methods, `get_counts` and `server_info {"counters": true}`.
`pft-internals` samples both every minute, on the validator and on the sentry, validates every field it exports and
writes bounded `pft_internals_*` textfile metrics for Prometheus.

| Group | Metrics (`pft_internals_` prefix, first label `container`) | Source field |
|-------|------------------|--------------|
| node | `node_uptime_seconds`, `node_restarts_total`, `counter_anomalies_total` | `server_info.uptime`; restarts/anomalies are counted by the collector (below) |
| NodeStore | `nodestore_reads_total`, `nodestore_read_hits_total`, `nodestore_read_bytes_total`, `nodestore_writes_total`, `nodestore_written_bytes_total`, `nodestore_read_duration_seconds_total` (counters); `nodestore_read_queue`, `nodestore_read_threads`, `nodestore_read_threads_running`, `nodestore_read_request_bundle`, `nodestore_write_load`, `historical_fetches_per_minute` (gauges) | `get_counts` `node_*`, `read_*`, `write_load`, `historical_perminute` |
| caches | `cache_hit_ratio{cache=accepted_ledger\|ledger\|SLE}` (0..1), `cache_size{cache=accepted_ledger\|treenode\|treenode_track\|fullbelow}`, `cached_view_total{result=hit\|miss}` | `AL_hit_rate`, `ledger_hit_rate` (percent), `SLE_hit_rate` (fraction), `AL_size`, `treenode_*`, `fullbelow_size`, `CachedView::hit/miss` |
| database | `db_bytes{db=total\|ledger\|transaction}` | `dbKBTotal`, `dbKBLedger`, `dbKBTransaction` (x 1024) |
| objects | `objects{type=...}` | every `ripple::<Type>` count (prefix dropped) |
| job queue | `job_queued_total`, `job_started_total`, `job_finished_total`, `job_run_seconds_total`, `job_waiting` (queued - started); `job_queue_wait_seconds` is a **gauge** (see below) `{job_type}` | `server_info.counters.job_queue` (the `total` entry is left out: `sum()` it) |
| load | `load_threads`; `load_job_per_second`, `load_job_peak_ms`, `load_job_avg_ms`, `load_job_in_progress`, `load_job_over_target` `{job_type}` | `server_info.load` (the node omits zero fields: they are exported as 0) |
| RPC | `rpc_started_total`, `rpc_finished_total`, `rpc_errored_total`, `rpc_duration_seconds_total` `{method}` | `server_info.counters.rpc` (`total` left out) |
| collector | `up`, `collect_timestamp_seconds`, `last_success_timestamp_seconds`, `label_overflow{kind}` | |

The two hit-rate units differ in the node itself (`AL_hit_rate` 49.78 and `SLE_hit_rate` 0.8966 in the same
answer): both are normalised to a 0..1 ratio, and each is range-checked in its own unit before that.

## Restart safety, validation and bounds

- **Counters are cumulative since the node started** and are exported as `*_total` counters, so `rate()` and
  `increase()` handle the drop at a node restart. The collector keeps the previous sample's counters in
  `/var/lib/pft-internals/state-<container>.json` and compares: uptime went down -> `node_restarts_total` + 1; any
  counter went *down while uptime went up* -> `counter_anomalies_total` + 1 (broken counters, or another node answering
  on the admin port) and the names are kept in the state file (`pft-internals status`).
- **Found on the first install (logs/03): `job_queue.*.queued_duration_us` is not monotonic in postfiatd 1.0.9.**
  Within 25 minutes of the install the two collectors logged 10 "counter went down" names, all on that field
  (logs/05; the alert stayed silenced, the operator was not paged); the calibration data
  shows it going down in 7 of 39 30-second intervals (3.5 ms to 313 ms, six job types; logs/04). It is now exported as the
  gauge `job_queue_wait_seconds` (report: `delta()` floored at 0, not `rate()`) and left out of the comparison; every
  other counter stays checked (`test_queued_duration_decrease_is_not_an_anomaly`).
- **Fail closed.** Every exported field must be present with the right type: counts are JSON integers or decimal
  strings of at most 20 digits (the node sends 64-bit counters as strings), never booleans or negatives; hit rates
  are finite numbers in 0..100 (percent) or 0..1 (SLE); job counters must satisfy finished <= started <= queued;
  `over_target` must be a boolean; job types, RPC methods and object types must match strict name patterns (no quote
  or brace can reach a label). One bad field and the textfile holds only `pft_internals_up 0`, the collect timestamp
  and the last success time; the previous good file is kept as `/var/lib/pft-internals/last-good-<container>.prom`;
  the state file is not touched.
- **Bounded labels.** At most `MAX_JOB_TYPES` (28) job types (per source), `MAX_RPC_METHODS` (24) methods and
  `MAX_OBJECT_TYPES` (32) object types keep their own label (sorted by name); the rest are summed into `other` (peak
  and average times take the max) and counted in `label_overflow{kind}`. Measured 2026-11-16 (validator / sentry): 21 / 22
  job types, 15 / 11 load entries, 12 / 8 methods, 21 / 20 object types.
- **Size budget.** The exporter skips textfiles over 64 KiB. The parser refuses a body that does not fit
  `MAX_BYTES` (61440) with a 1024-byte reserve for the header lines, and the shell checks the final file again. The
  default caps are sized so the worst case (every cap full, longest legal names, 19-digit values) still fits; a real
  sample is about 33 KB (338 series).

## What it reads and what it writes

| Item | Detail |
|------|--------|
| access path | `docker exec <container> curl -s --max-time 8 -H 'Content-Type: application/json' -d '{"method":"get_counts","params":[{}]}' http://127.0.0.1:5005/` and the same with `{"method":"server_info","params":[{"counters":true}]}`: the admin port on the container's loopback, the exec shape `../statewatch` and `../peerwatch` already use under the node's AppArmor/seccomp profiles (curl is the exec'd binary). Two read-only methods, nothing else. |
| textfile | `/var/lib/pft-exporter/textfile/pft_internals_<container>.prom`, atomic rename, mode 0644 |
| state | `/var/lib/pft-internals/` (0700): `state-<container>.json` (last uptime + counters, restart/anomaly counts), `last-good-<container>.prom` |
| units | `pft-internals@<container>.timer` (every minute at :40, sandboxed oneshot service); validator: `pft-internals-pull@postfiatd-sentry.timer` (:52) copies the sentry's file over the existing ssh pull path, validated all-or-nothing |

## Commands and exit codes

```
sudo pft-internals collect [--container NAME] [--textfile-dir DIR] [--stdout]   0 ok, 1 failed (up 0 written), 3 usage
sudo pft-internals status [--container NAME] [--json]                           0 ok, 4 no state / stale
sudo pft-internals pull [--container NAME]                                      0 ok, 1 fetch, 2 validation, 3 usage
pft-internals validate FILE NAME                                                0 ok, 2 rejected (reason on stdout)
```

## Alerts (`../alerts/internals.rules.yml`, six rules)

Thresholds come from a 20-minute calibration on the validator (2026-11-16, 40 samples at 30 s through the
collector's own exec shape; `data/calibration-validator.jsonl`, `tests/calib_stats.py stats`, `logs/01-calibration.log`)
and are checked against the 24-hour two-host report.

| Alert | Fires when | Calibration (10-min windows unless noted) |
|-------|------------|-------------|
| `PFTInternalsNodeStoreSlow` | mean NodeStore read > 5 ms over 10m (and > 0.5 reads/s) for 15m | 0.034-0.302 ms, 7.8-49 reads/s |
| `PFTInternalsCacheCollapse` | CachedView hit ratio < 0.4 over 15m (and > 0.2 lookups/s, node up > 30 min) for 30m | 0.805-0.807 (15 min), 2.3-2.7 lookups/s |
| `PFTInternalsJobBacklog` | sum of `job_waiting` > 100 for 10m | max 5 |
| `PFTInternalsJobPeak` | a job type's `peak_time` > 5000 ms for 10m | max 634 ms |
| `PFTInternalsStale` | `up == 0` or the sample is older than 5 min, for 5m | |
| `PFTInternalsCounterAnomaly` | `increase(counter_anomalies_total[30m]) > 0` | 0 |

Why not the obvious cache signals: the node's `*_hit_rate` gauges are cumulative since start (they barely move after
a day of uptime), and the NodeStore hit ratio swings with the read mix (0.14-0.92 over 5-minute windows in the
calibration, 0.73 cumulative). `increase()`, not `changes()`, drives the anomaly rule so a reset of the collector's
own state (3 -> 0) does not fire it. All rules handle a node restart: `rate()` absorbs the counter reset, and the
cache rule waits for 30 min of uptime (cold caches).

## Runbook

- **NodeStoreSlow**: disk latency first (`iostat -x 5`, `sudo pft-resources audit`), then whether the node is
  fetching history (`historical_fetches_per_minute`, `nodestore_read_queue`).
- **CacheCollapse**: memory pressure (`sudo pft-resources audit`, container memory), a changed `node_size` or cache
  setting, or a node that is re-acquiring ledgers.
- **JobBacklog / JobPeak**: `sudo pft-internals collect --stdout | grep -E 'job_waiting|load_job_peak_ms'` names the
  job types; CPU and disk are the usual causes.
- **Stale**: `sudo pft-internals collect --container NAME --stdout` prints the reason; for the sentry also check
  `pft-internals-pull@postfiatd-sentry.timer` on the validator.
- **CounterAnomaly**: `sudo pft-internals status --container NAME` lists the counters that went down. Check that the
  admin port belongs to the expected container.

## Install

```
sudo ./install.sh                              # validator (container postfiatd)
sudo ./install.sh --container postfiatd-sentry # sentry
sudo ./install.sh --pull postfiatd-sentry      # validator: pull the sentry's file (PULL_SSH in /etc/pft-internals.env)
```

The first collection runs through the sandboxed unit and must give `up 1` before the timer is enabled (no ad-hoc
`docker exec` into the node). Afterwards: add `/etc/pft-alerts/internals.rules.yml` to `../alerts/prometheus.yml`
(same commit), `pft-integrity accept`, `pft-fleet sync`, `pft-schedaudit accept` + collect, `pft-jobwatch inventory`.

## Tests

```
TMPDIR=~/.cache python3 -I internals/tests/test_internals.py      # parser, shell (docker/ssh stubs), report
python3 internals/tests/gen_rule_tests.py > alerts/internals.tests.yml
promtool test rules alerts/internals.tests.yml                    # (cd alerts; prom/prometheus:v3.5.0)
TEST_TMPDIR=~/.cache python3 -u internals/tests/mutate.py         # mutants: every one must be CAUGHT
shellcheck internals/*.sh; ruff check internals; (cd internals && ruff check .)
```

Fixtures are real captures of both hosts (2026-11-16); `tests/redact_capture.py` keeps only the server_info fields
the collector reads, so host ids, node keys and the port list never reach the repo.

## Report

`report_internals.py capture` stores the raw `query_range` answers of a fixed query list for a window;
`report_internals.py build CAPTURE --md --json` turns a capture into min / p50 / p95 / max per query and container,
offline and byte-identically (no clock, no environment), so a fresh clone can rebuild the committed report and `cmp` it.

## Evidence (logs/)

| Log | What |
|-----|------|
| 01 | threshold calibration (40 samples, 30 s) from `data/calibration-validator.jsonl` |
| 02 | mutation run at the first install commit 68d4da2: 87/87 caught (superseded by 06) |
| 03a, 03, 03b | first two-host install at 68d4da2: preflight, install (stopped by the agent's tool time limit in step 12, after its restore), read-only tail of the unrun step-12 checks (PASS, operator topics 0 messages). Step 10 found the defect below |
| 04, 05 | found: `queued_duration_us` decreases in the calibration data (7 of 39 intervals) and in the live collectors' journals (10 names, both hosts) |
| 06 | mutation run at the fix 6c6425e: 89/89 caught |
| 07a, 07 | two-host upgrade to the fix at 19ccf0c: every install/verify check ok, operator topics 0 messages; its one FAIL is the drain check counting the two still-suppressed PFTInternalsCounterAnomaly alerts (pre-fix increments inside the rule's 30m window), which the next check shows suppressed |
| 08 | in-window check at 99699fd (`drill/window-check.sh`): both collectors OK, 0 restarts / 0 anomalies, PFTInternalsCounterAnomaly inactive; the defect silence is expired only after these gates, then 90 s with nothing but the watchdog active, integrity PASS both hosts, operator topics 0 messages since the window start |

The 24-hour two-host window starts after the upgrade's state re-baseline (2026-11-16T06:05Z); the report, the
throwaway-topic alert drill and the fresh-clone proof follow at its end.
