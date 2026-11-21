# budget/ — measured resource budgets for pft-* units

Every add-on in this repo ships its systemd units with a `MemoryMax` picked at install time, and many oneshots have
no cap at all. Nothing checked whether those caps still fit. On 2026-11-18 the daily `pft-histarchive` full verify
was OOM-killed at `MemoryMax=512M`: its peak had grown with the archive (593 MiB on day 10) until it crossed the cap.
`pft-budget` measures every pft-* unit's real peaks, compares them with the caps in force, projects them 30 and 90 days
ahead and right-sizes `MemoryMax` through drop-ins, only inside a `pft-maint` window.

| file | what |
|---|---|
| `pft-budget.sh` → `/usr/local/bin/pft-budget` | CLI: report, collect (textfile), status, plan/apply/rollback, pull, validate |
| `budget.py` → `/usr/local/lib/pft-budget/budget.py` | stdlib helper: sampler daemon, report, metrics, plan/apply/rollback |
| `systemd/pft-budget-sampler.service` | the sampler (user `pft-budget`, no capabilities, `MemoryMax=64M`, `CPUQuota=10%`) |
| `systemd/pft-budget-collect.{service,timer}` | report → `pft_budget_<host>.prom` every 5 min (:20) |
| `systemd/pft-budget-pull@.{service,timer}` | validator: copy the sentry's textfile every 5 min (:50) |
| `../alerts/budget.rules.yml` (+ `budget.tests.yml`) | PFTBudgetCapReached, PFTBudgetStale |
| `tests/test_budget.py`, `tests/mutate.py` | unit tests (fake cgroup tree, stub systemctl/pft-maint), mutation harness |

## How it measures

Ubuntu 22.04's kernel 5.15 has no `memory.peak`, and systemd 249 keeps no per-run peak, so the sampler polls. Every
`INTERVAL` (1 s) it lists `/sys/fs/cgroup/system.slice/pft-*.service` and reads each cgroup's `memory.current`,
`memory.stat`, `cpu.stat`, `io.stat`, `memory.events` (`oom_kill`) and `memory.max`/`memory.high`. Per (unit,
invocation id) it keeps:

* `peak_bytes`: the max of `memory.current` (includes page cache)
* `peak_unrecl_bytes`: the max of the part reclaim cannot free (`anon + shmem + kernel_stack + pagetables + percpu +
  sock + slab_unreclaimable`). The verdicts use this one. A streaming reader can sit at its cap on page cache alone
  without any OOM risk, because the kernel drops cache before it kills.
* the cumulative CPU seconds, IO bytes and OOM kills of the cgroup, and the caps in force.

The invocation id comes from `systemctl show -p InvocationID` when a new cgroup dir appears and is rechecked every 30 s.
The `trusted.invocation_id` xattr would need CAP_SYS_ADMIN, which the sampler does not get. When a cgroup disappears,
one `final` record is appended to `/var/lib/pft-budget/samples.jsonl` with systemd's `Result`, `ExecMainStatus` and
runtime for that invocation; a `Result` from a newer run is never attributed to it. Long-running services get a
`running` checkpoint every 15 min. Units that were already running when the sampler started are marked
`from_start: false` (their peak may predate it). The JSONL rotates at 4 MiB to `.1` … `.5`, about 24 MiB at most.
`report`/`metrics` stream that JSONL and keep one slim record per invocation (14 fields, interned strings), not the
parsed dicts: on a 24 MiB fixture peak RSS is 44 MiB (159 MiB with whole dicts, past the collector's own `MemoryMax=128M`),
with byte-identical reports (`logs/14-slim-loader-rss.log`, tests `test_report_matches_full_dict_loader`,
`test_peak_rss_on_24mib_fixture`).

Runs shorter than one poll interval can be missed, and a peak that lasts less than 1 s can be under-read. The sampler
reports what it saw, with a `samples` count per run.

## Report and verdicts

```
sudo pft-budget report [--json]        # exit 0 all OK/UNCAPPED, 2 some WARN, 1 some FAIL
```

Per unit over the last `WINDOW_DAYS` (30): runs, p50/max unreclaimable peak, max total peak, cap, headroom
(cap / max peak), 30/90-day projection (least-squares slope of the per-run peaks, clamped at >= 0, never below the
measured max; only with >= `MIN_RUNS` runs spanning >= `PROJ_MIN_SPAN_DAYS` (3) days: the first live
install fitted 5 runs over 12 minutes and projected a 7 MiB unit to 23 GiB), longest runtime, OOM-killed runs.

| verdict | when |
|---|---|
| FAIL | an OOM-killed run in the window, peak >= 0.9 × cap, or the 30-day projection >= cap |
| WARN | headroom < 2× (`WARN_HEADROOM`), or the 90-day projection >= cap |
| UNCAPPED | no `MemoryMax` (FAIL if it was OOM-killed); the report prints a recommended cap |
| OK | everything else |

The recommended / planned cap is `max(2 × peak, 1.25 × 90-day projection, 64 MiB)`, rounded up to 64 MiB steps.

## Right-sizing (plan / apply / rollback)

```
sudo pft-budget plan [--allow-lower]          # JSON lines: unit, action set|raise|lower, from, to
sudo pft-budget apply [--allow-lower]         # dry run: prints WOULD lines, writes nothing
sudo pft-maint start --ttl 30m --reason "pft-budget apply"
sudo pft-budget apply --yes                   # writes /etc/systemd/system/UNIT.d/60-pft-budget.conf, daemon-reload,
                                              # checks `systemctl show -p MemoryMax` per unit (exit 1 on mismatch)
sudo pft-budget rollback --yes                # restores what the last apply replaced (or removes it), re-checks
```

Guards (each has a test that asserts nothing was written and no systemctl call was made):

* `apply --yes` and `rollback --yes` refuse (exit 4) unless `pft-maint active` succeeds.
* `EXCLUDE` (default `postfiatd* docker* containerd* pft-budget-sampler.service`) is never planned. `apply` re-checks
  each unit against it before writing.
* `set` (an uncapped unit) and `lower` need at least `MIN_RUNS` measured runs. `lower` needs `--allow-lower` and an
  OK verdict, and an OOM run always makes the verdict FAIL. `raise` is planned only for WARN/FAIL units.
* Every apply saves the previous drop-in content in `/var/lib/pft-budget/applied/<UTC>.json`. Rollback consumes the
  newest record and renames it `.rolled-back`.

Drop-ins are new files under `/etc/systemd/system`, so run `sudo pft-integrity accept --reason ...` afterwards.

## Metrics and alerts

`pft-budget collect` writes `pft_budget_<host>.prom`. Every sample carries `host` (and `unit`); the file stays under
`TEXT_MAX_BYTES` (61440), and above that it degrades to `pft_budget_up 0`.

`pft_budget_up`, `pft_budget_sampler_heartbeat_timestamp_seconds`, `pft_budget_report_timestamp_seconds`,
`pft_budget_bad_lines`, and per unit `pft_budget_{peak_unrecl,peak_unrecl_p50,peak_total,cap,projected_30d,
projected_90d}_bytes`, `pft_budget_headroom_ratio`, `pft_budget_{runs,oom_runs,failed_runs}`,
`pft_budget_runtime_max_seconds`, `pft_budget_verdict` (0 OK, 1 WARN, 2 FAIL, 3 UNCAPPED).

### Alerts

* **PFTBudgetCapReached** (30m): peak >= 0.9 × cap, or the 30-day projection >= cap. The unit will be OOM-killed.
  Run `sudo pft-budget report` and `plan`, then `apply --yes` in a pft-maint window, or fix the unit.
* **PFTBudgetStale** (15m): `up 0`, a sampler heartbeat older than 15 min, or a report older than 30 min.

WARN (headroom under 2×) is report-only. OOM kills already page through kernwatch's PFTKernelCritical, and an OOM run
keeps the verdict FAIL for the whole window, so no rule keys on `oom_runs`: it would not resolve after the fix.

## Install

```
sudo ./install.sh --host validator     # or --host sentry
sudo ./install.sh --pull sentry        # validator: needs PULL_SSH in /etc/pft-budget.env
```

## Tests

```
TMPDIR=$HOME/.cache python3 -m pytest -q budget/tests        # or python3 budget/tests/test_budget.py
TEST_TMPDIR=$HOME/.cache python3 -u budget/tests/mutate.py   # single-mutant run, helper + shell + units + rules
promtool test rules alerts/budget.tests.yml                  # (cd alerts; prom/prometheus:v3.5.0)
shellcheck budget/*.sh && (cd budget && ruff check . && ruff format --check .)
promtool check rules alerts/budget.rules.yml
bash budget/drill/fresh-clone.sh SHA                         # anonymous clone + every offline check (log 13)
```

## Sample report

From the committed two-host snapshot (`logs/data/`, 3013 records taken 2026-11-18T14:10:05Z, about 2.5 h after
install), rebuilt offline with `python3 budget/budget.py --conf budget/pft-budget.env.example report --now $(cat
budget/logs/data/NOW) --data budget/logs/data/*-samples.jsonl` (full output: `logs/data/report-offline.txt`):

```
pft-budget report - 2026-11-18T14:10:05Z - window 30d, 2985 invocation(s), 0 unreadable line(s)
host       unit                                          runs       p50       max   max_tot       cap headroom    proj30    proj90   rt_max  oom verdict
sentry     pft-budget-collect.service                      27      1MiB      8MiB      8MiB    128MiB   16.30x         -         -       3s    0 OK
validator  pft-histarchive-periodic.service                29      4MiB     97MiB     97MiB    512MiB    5.30x         -         -      19s    0 OK
validator  pft-histarchive-verify-before-sealed.service     1    518MiB    518MiB    518MiB   1024MiB    1.98x         -         -      14s    0 WARN
                                                          - headroom 1.98x < 2x (peak 518MiB)
validator  pft-histarchive-verify-before.service            1    603MiB    603MiB    605MiB   1024MiB    1.70x         -         -      33s    0 WARN
                                                          - headroom 1.70x < 2x (peak 603MiB)
RESULT: 8 OK, 2 WARN, 0 FAIL, 79 UNCAPPED
```

(excerpt). The two WARN rows are the deliberate old-code runs of log 07 under the 1G stop-gap. 79 units are still
uncapped and get a recommended cap; nothing is applied until each has `MIN_RUNS` runs over `PROJ_MIN_SPAN_DAYS`.
No unit has 3 days of data yet, so no 30/90-day projection is printed.

## Histarchive OOM: before / after

The daily `pft-histarchive-periodic` full verify was OOM-killed at `MemoryMax=512M` on 2026-11-18 (593 MiB peak); a
`MemoryMax=1G` drop-in was the stop-gap. The column-store verify (`histarchive` `60dc70c`, see `histarchive/README.md`)
was shipped with `pft-fleet` in a `pft-maint` window by `drill/histarchive-run.sh` (log 07), measured by the sampler
on the live archive (same host, same data):

| run | code | cap | peak unreclaimable | headroom | result |
|---|---|---|---|---|---|
| full verify, before | old | 1G (stop-gap) | 602.5 MiB | 1.70x | ok, would FAIL at 512M |
| sealed-only verify, before | old | 1G | 517.6 MiB | 1.98x | ok |
| full verify, after | 60dc70c | 512M | 95.3 MiB | 5.37x | ok |
| sealed-only verify, after | 60dc70c | 512M | 95.4 MiB | 5.37x | `--json` byte-identical to before (cmp) |
| real periodic unit (log 11) | 60dc70c | 512M, no drop-in | 96.6 MiB | 5.30x | Result success, oom 0 |

The stop-gap was removed only after the after-run showed more than 2x headroom under 512M (the card's condition).

## Proof (logs in `logs/`)

| log | what | result |
|---|---|---|
| 01 | first single-mutant run (helper, shell, units, rules) | 79/79 caught |
| 02 | two-host install through pft-fleet (`drill/install-run.sh`) | 51/52: the live run found the short-span projection bug (PFTBudgetCapReached pending, silenced, not paged); fixed `8aef64d` |
| 03, 04 | mutants after the fix (03: one mutant no longer applied, retargeted) | 80/81, then 81/81 caught |
| 05 | two-host upgrade to the fix (`drill/upgrade-run.sh`) | 29/30: the runner's is-failed check misread the sampler's state; runner fixed `26904b4`; alerts inactive, operator topics 0 |
| 06 | histarchive single-mutant run at `60dc70c` | 77/77 caught |
| 07 | histarchive bounded-verify deploy (`drill/histarchive-run.sh`) | before/after table above; 3 FAIL, all runner: a record lookup race, and schedaudit not re-accepted after the drop-in removal, which paged the operator once (explained); fixed `5e6d079` |
| 08 | mutants incl. the sampler ENODEV fix `a97de5d` (live crash-loop on the sentry during cgroup teardown) | 83/83 caught |
| 09 | two-host upgrade to `a97de5d` | 2 FAIL: PFTRuleDead from the absent projection series, fixed `94cbac8` (rulecheck ignore-metric); silenced, not paged |
| 10 | recheck preflight stop: run 09's rollout silence still active | stopped before any change; `upgrade-run.sh` now expires its own silence |
| 11 | histarchive RECHECK (`RECHECK=1`): real periodic unit at 512M without the drop-in | **PASS, 0 failed**: 96.6 MiB, oom 0, integrity/skew/schedaudit clean, operator topics 0 |
| 12 | snapshot: both hosts' sampler JSONL (`logs/data/`), offline report, installed key-file sha256 on both hosts | installed = repo bytes on both hosts |
| 13 | fresh anonymous public clone at `4a3c294` (`drill/fresh-clone.sh`): sha256 of 6 key files vs both installs (log 12), JSONL sha256, shellcheck, ruff, both suites, promtool, offline report rebuild | **PASS, 0 failed**: 6/6 equal on both hosts, JSONL 2/2 OK, budget 60 passed, histarchive 121 OK, promtool SUCCESS, txt and `--json` report `cmp` exit 0 |
