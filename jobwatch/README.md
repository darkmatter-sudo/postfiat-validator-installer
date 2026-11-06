# jobwatch — scheduled-job outcome monitor (pft-jobwatch)

Status: **in progress**: steps 1-3 done; installed on both hosts (log 02); the alert drill found a label bug (run 07,
fixed, see [Results](#results)); the fixed build is being redeployed and the drill re-run.

Every add-on in this repo reports through a systemd timer (47 `pft-*`/`postfiat*` timers on the validator, 25 on the
sentry). When a timer is disabled, removed, failing or no longer firing, its last textfile stays in place and its
numbers still look healthy; only `../rulecheck`'s staleness check notices, and only for textfiles it was told about.
`pft-jobwatch` watches the timers themselves. It is read-only: the only command it runs is `systemctl show` (it never
starts, stops, enables or resets a unit).

| File | What it is |
|---|---|
| `pft-jobwatch.sh` | CLI: `collect`, `inventory`, `forget`, `pull`, `validate`, `version` (usage in its header) |
| `jobwatch_lib.py` | stdlib helper: `systemctl show` parser, schedule/interval derivation, per-job state, textfile renderer |
| `tests/test_jobwatch.py` | offline suite: captured `systemctl show` fixtures + `tests/stub_systemctl.py` (101 checks) |
| `tests/mutate.py` | mutant harness: 50 helper/script/rule mutants; the suite or promtool must fail each |
| `tests/fixtures/` | `systemctl show` output captured on the validator (heartbeat = monotonic, kernwatch = calendar, vulnscan = calendar + 30 min RandomizedDelaySec, egress-reapply@ = template instance) and three variants with only the named fields changed (jwfail = exit 1, jwnever = never run, jwdis = `disable --now`) |
| `install.sh` | install/uninstall: collector (`--host NAME`) or the validator's pull of the sentry file (`--pull`) |
| `systemd/` | `pft-jobwatch.service/.timer` (both hosts, every 2 min at :40 of even minutes; sandboxed: no network, no capabilities) and `pft-jobwatch-pull.service/.timer` (validator, odd minutes at :10) |
| `pft-jobwatch.env.example` | `/etc/pft-jobwatch.env` (root-owned 0600): `HOST_LABEL`, `JOB_GLOBS`, `PULL_SSH` |
| `drill/checks-run.sh` | recorded lint + suite + promtool + mutants run at a pushed commit |
| `drill/install-run.sh` | recorded two-host install through pft-fleet in a pft-maint window (throwaway [MAINT] topic; keyescrow re-run + drift 0 check after the restore) |
| `drill/alert-run.sh` | step-4 alert drill: a runtime drill job (`/run/systemd/system`, outside pft-integrity's set) on both hosts at once, succeed -> fail -> disable -> hang (missed) -> remove; PFTJobFailed, PFTJobDisabled (x2), PFTJobMissed FIRING then RESOLVED for both hosts on a throwaway topic (bridge re-created on a temp env, alertpath paused, everything else silenced), operator topics read back; `PREFLIGHT_ONLY=1` changes nothing |

Rules: `../alerts/jobwatch.rules.yml`, tests `../alerts/jobwatch.tests.yml`; the rule file is listed in
`../alerts/prometheus.yml`; `../rulecheck/pft-rulecheck*.conf.example` grade `pft_jobwatch_*.prom` stale after 15 min.

## Usage

```
sudo pft-jobwatch collect             # the timer: inventory + derive + write pft_jobwatch_HOST.prom atomically
sudo pft-jobwatch collect --stdout    # same, print instead of writing
sudo pft-jobwatch inventory           # table: job, kind, interval, disabled, failed, consecutive, missed, present, spec
sudo pft-jobwatch inventory --format json
sudo pft-jobwatch forget pft-old.timer   # after removing a job on purpose: stop exporting it (clears PFTJobDisabled)
sudo pft-jobwatch pull --host sentry  # validator: copy + validate the sentry's file (pft-jobwatch-pull.timer)
```

Exit codes: 0 ok, 1 `systemctl` / fetch failed, 2 validation failed, 3 usage/config error.

## How jobs are derived

- **Inventory.** Loaded timers matching `JOB_GLOBS` (`pft-*.timer postfiat*.timer`) plus every job already in
  `/var/lib/pft-jobwatch/state.json` (0600, dir 0700). A timer that was disabled and garbage-collected by systemd, or
  deleted, therefore stays visible (`present 0`, `disabled 1`) until `pft-jobwatch forget`. Three `systemctl show`
  calls per run (globs -> Ids, timer properties, service properties), with `TZ=UTC --timestamp=us+utc`.
- **Schedule kind and interval.** `monotonic`: the smallest `OnUnitActiveSec`/`OnUnitInactiveSec` (`OnBootSec`,
  `OnStartupSec`, `OnActiveSec` fire once and give no interval). `calendar`: `systemctl show` gives no period, so the
  interval is learned as the smallest `NextElapseUSecRealtime - LastTriggerUSec` seen (a gap of two periods after a
  missed run is replaced by the next one-period gap; a changed `OnCalendar` spec resets it). `LastTriggerUSec` is the
  real, accuracy-delayed trigger, so a 2-minute timer with `AccuracySec=1s` learns 119 s. `mixed`: the smaller of both.
- **Failed.** The service's `Result` is not `success` or its `ActiveState` is `failed` (`Result` honours
  `SuccessExitStatus=`, so a configured non-zero success exit is not a failure; a signal, timeout or start-limit-hit is).
- **Consecutive failures and last success.** A finished run is identified by `ExecMainStartTimestampMonotonic` +
  `Result` + `ExecMainStatus` (start-limit-hit has no new start, so the result is part of the key). Each new finished
  run is counted once: a failure adds 1, a success resets to 0 and sets last success to `ExecMainExitTimestamp`.
  These are **observed** counts: with a 2-minute collector, a 1-minute job's runs between two collections are not seen
  (`journalctl -u` has the full history). On the first run the current last result is counted once.
- **Missed.** Enabled job, and either no trigger for longer than `interval + AccuracySec + 2 x RandomizedDelaySec +
  300 s` (reference: the last trigger, or the timer's activation if it never ran; a run still going counts, because a
  monotonic timer does not re-fire while its service runs), or a calendar job's next elapse is more than that grace in
  the past. Twice the randomized delay: the learned interval can be one delay short and a real gap one delay long.
- **Disabled.** The timer is not `active`, or its unit file state is not one of enabled, enabled-runtime, static,
  linked(-runtime), generated, transient (so `disable`, `mask`, `stop` and removal all count). A disabled job is never
  also reported missed.
- **Never run.** No `LastTriggerUSec` and the service never started.

## Metrics (`pft_jobwatch_HOST.prom`, label `host` = validator | sentry, never a hostname)

Per-job series carry `timer="<unit>.timer"`. Not `job`: Prometheus owns `job` (the scrape job), so a textfile `job`
label arrives renamed `exported_job`, and every `on (host, job)` join then matches all timers of a host (found in drill
run 07, see [Results](#results)).

| Metric | Meaning |
|---|---|
| `pft_jobwatch_up` | 1 if the last `systemctl show` inventory succeeded (0: only up/timestamp/version are written, state untouched) |
| `pft_jobwatch_collect_timestamp_seconds` | Unix time of the last collection attempt |
| `pft_jobwatch_jobs{state}` | watched timers: total, present, disabled, failed, missed |
| `pft_jobwatch_job_info{timer,service,kind}` | 1 per watched timer (kind monotonic, calendar, mixed, none) |
| `pft_jobwatch_job_present` / `_disabled` / `_running` / `_never_run` / `_failed` / `_missed` | per-job 0/1 flags (above) |
| `pft_jobwatch_job_consecutive_failures` | failed runs in a row, as observed |
| `pft_jobwatch_job_interval_seconds` | derived repeat interval (0 = none known) |
| `pft_jobwatch_job_last_trigger_timestamp_seconds` / `_last_success_timestamp_seconds` / `_next_elapse_timestamp_seconds` | Unix times (0 = never / none / monotonic) |
| `pft_jobwatch_job_runs_observed_total` / `_failed_runs_observed_total` | finished runs counted since the state was created |

## Alerts

| Alert | Expression (`../alerts/jobwatch.rules.yml`) | for |
|---|---|---|
| `PFTJobFailed` | `consecutive_failures and failed == 1 and present == 1` (value = runs in a row) | 3m |
| `PFTJobMissed` | `missed == 1` | 5m |
| `PFTJobDisabled` | `disabled == 1` (includes removed) | 5m |
| `PFTJobwatchStale` | `time() - collect_timestamp > 600 or up == 0` | 10m |

`for: 3m` on PFTJobFailed: a 1-minute job that fails once and succeeds on the next run clears within one collection and
does not page; a daily job that fails stays failed until its next run, so it pages. A removed job raises only
PFTJobDisabled (never PFTJobFailed).

## Scope limits

- Watches systemd timers and the service each one triggers; not cron, not in-container jobs (e.g. the container's own
  `cron.daily`), not services without a timer.
- Run counts are observed, not exhaustive (see above). Calendar intervals are learned, so the very first observation
  after a missed run can learn two periods until the next run corrects it (the next-elapse check still catches a
  timer that stops firing).
- A job that is meant to be removed must be `forget`-ed, or PFTJobDisabled stays active.

## Results

| Log | What | Result |
|---|---|---|
| `logs/01-checks.log` | checks @1421002 | shellcheck/ruff clean, promtool ok, suite 101/101, mutants 50/50 CAUGHT |
| `logs/02-install.log` | two-host install @a572ec6 via pft-fleet, pft-maint window on a throwaway topic | PASS 31/0; real inventory validator 47 + 2 own = 49 timers, sentry 25 + 1 = 26; 0 failed, 0 missed, 0 disabled on both |
| `logs/03-alert-preflight-run05.log` | drill preflight @3e42ab2 | ready, nothing changed |
| `logs/04-alert-drill-run06-stopped.log` | drill run 06 | stopped by hand in step 2: the checker read `systemctl show` output in `-p` order (systemd prints its own order) and failed a correct install; restore completed. Fixed @07fc9a4 (also: preflight now refuses an active silence naming PFTJob*, because the install's rollout silence was still active and would have muted the drill) |
| `logs/05-alert-drill-run07-stopped.log` | drill run 07 | **found**: PFTJobFailed fired for 27 sentry series when only the drill job failed, and for no validator series. Cause: the per-job label was `job`; the scrape renamed it `exported_job`, so `on (host, job)` joined every sentry timer to the one failed drill job. Notifications went only to the throwaway topic (operator topics: 0 messages). Stopped by hand; the stop also killed the restore, which was then completed by hand (drill units, flags and state entry removed on both hosts, bridge back on the operator env with alertpath paused around it, silence expired). **Fixed**: label renamed `timer`; suite check that no sample uses `job`/`instance`; promtool test with two timers on one host; mutants M33, R08 |

Verification of the fix on the hosts (redeploy + drill re-run) follows.
