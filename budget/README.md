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
```
