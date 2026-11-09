# jobwatch — scheduled-job outcome monitor (pft-jobwatch)

Status: **done**: installed on both hosts (log 02, fixes rolled out in log 10); alert drill run 16 PASS (log 13). Two
bugs found by the drill and fixed before it passed (label collision, textfile size), see [Results](#results).

Every add-on in this repo reports through a systemd timer (47 `pft-*`/`postfiat*` timers on the validator, 25 on the
sentry). When a timer is disabled, removed, failing or no longer firing, its last textfile stays in place and its
numbers still look healthy; only `../rulecheck`'s staleness check notices, and only for textfiles it was told about.
`pft-jobwatch` watches the timers themselves. It is read-only: it runs only `systemctl show` and `systemd-analyze
calendar` (the period of an `OnCalendar` spec, a pure computation); it never starts, stops, enables or resets a unit.

| File | What it is |
|---|---|
| `pft-jobwatch.sh` | CLI: `collect`, `inventory`, `forget`, `pull`, `validate`, `version` (usage in its header) |
| `jobwatch_lib.py` | stdlib helper: `systemctl show` parser, schedule/interval derivation, per-job state, textfile renderer |
| `tests/test_jobwatch.py` | offline suite: captured `systemctl show` fixtures + `tests/stub_systemctl.py` (125 checks) |
| `tests/mutate.py` | mutant harness: 50 helper/script/rule mutants; the suite or promtool must fail each |
| `tests/fixtures/` | `systemctl show` output captured on the validator (heartbeat = monotonic, kernwatch = calendar, vulnscan = calendar + 30 min RandomizedDelaySec, egress-reapply@ = template instance) and three variants with only the named fields changed (jwfail = exit 1, jwnever = never run, jwdis = `disable --now`) |
| `install.sh` | install/uninstall: collector (`--host NAME`) or the validator's pull of the sentry file (`--pull`) |
| `systemd/` | `pft-jobwatch.service/.timer` (both hosts, every 2 min at :40 of even minutes; sandboxed: no network, no capabilities) and `pft-jobwatch-pull.service/.timer` (validator, odd minutes at :10) |
| `pft-jobwatch.env.example` | `/etc/pft-jobwatch.env` (root-owned 0600): `HOST_LABEL`, `JOB_GLOBS`, `PULL_SSH` |
| `drill/checks-run.sh` | recorded lint + suite + promtool + mutants run at a pushed commit |
| `drill/install-run.sh` | recorded two-host install through pft-fleet in a pft-maint window (throwaway [MAINT] topic; keyescrow re-run + drift 0 check after the restore) |
| `drill/update-run.sh` | recorded two-host update of the installed files through pft-fleet in a pft-maint window (throwaway [MAINT] topic), Prometheus rule reload, label check, keyescrow re-run |
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
  period comes from the spec: `systemd-analyze calendar --iterations=12` over every `OnCalendar` line of the timer,
  and the interval is the **longest** gap between consecutive elapses of their union (hourly `*:23:00` = 3600 s;
  `Mon,Thu` = 4 days, so the long gap never reads as missed). It is asked once per spec and kept in the state (a changed
  spec, or an unknown period, is asked again). Fallback, only if `systemd-analyze` fails: the smallest
  `NextElapseUSecRealtime - LastTriggerUSec` seen (the pre-2026-11-09 method). That gap is wrong for a `Persistent=yes`
  timer: on its first activation systemd stamps `LastTriggerUSec` with the activation time, and a boot catch-up run
  does the same, so the first gap is shorter than the period (see the 2026-11-09 row below). `mixed`: the smaller of
  the monotonic and calendar intervals.
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
  the past. Twice the randomized delay: a real gap can be one delay longer than the period (and the fallback's learned
  interval one delay short).
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
| `pft_jobwatch_job_last_trigger_timestamp_seconds` / `_last_success_timestamp_seconds` | Unix times, whole seconds (0 = never / none) |
| `pft_jobwatch_job_runs_observed_total` | finished runs counted since the state was created |

Next elapse and the failed-run counter are in `pft-jobwatch inventory --format json` only: the pft exporter skips a
textfile over 64 KiB whole, and with them 49 timers reached 66 KB (update run 09). `collect` refuses to write a file
over `TEXT_BUDGET` (61440 bytes) and writes `up 0` instead, so PFTJobwatchStale fires rather than every series
vanishing; `pull` validates against 65536.

## Alerts

| Alert | Expression (`../alerts/jobwatch.rules.yml`) | for |
|---|---|---|
| `PFTJobFailed` | `consecutive_failures > 0 and failed == 1 and present == 1` (value = runs in a row, never 0) | 3m |
| `PFTJobMissed` | `missed == 1` | 5m |
| `PFTJobDisabled` | `disabled == 1` (includes removed) | 5m |
| `PFTJobwatchStale` | `time() - collect_timestamp > 600 or up == 0` | 10m |

`for: 3m` on PFTJobFailed: a 1-minute job that fails once and succeeds on the next run clears within one collection and
does not page; a daily job that fails stays failed until its next run, so it pages. A removed job raises only
PFTJobDisabled (never PFTJobFailed).

A failed last run always counts as at least 1 in a row: the helper exports `consecutive_failures >= 1` whenever
`failed == 1`, even when that run is not counted yet (state reset, `Restart=` auto-restart), and the rule's `> 0`
guards against any exporter that does not. So no message ever says "failed (0 run(s) in a row)".

Phone delivery goes through `../alerts/ntfy_bridge.py`, which sends **one message per state change** per alert and folds
alerts of the same name and status in one webhook into one message (`[FIRING] PFTJobFailed x2`), see
[`../alerts/README.md`](../alerts/README.md#one-message-per-state-change).

## Scope limits

- Watches systemd timers and the service each one triggers; not cron, not in-container jobs (e.g. the container's own
  `cron.daily`), not services without a timer.
- Run counts are observed, not exhaustive (see above). Calendar intervals come from the spec; only when
  `systemd-analyze` is unavailable are they learned from observed gaps, with the limits described above (the
  next-elapse check still catches a timer that stops firing).
- A job that is meant to be removed must be `forget`-ed, or PFTJobDisabled stays active.
- Size: about 1.1 KB per timer; the validator's 49 timers give 55.6 KB, so roughly 5 more timers fit under
  `TEXT_BUDGET`. Past that, collect publishes `up 0` (PFTJobwatchStale) until JOB_GLOBS is narrowed or the exporter's
  64 KiB cap is raised.

## Results

| Log | What | Result |
|---|---|---|
| `logs/01-checks.log` | checks @1421002 | shellcheck/ruff clean, promtool ok, suite 101/101, mutants 50/50 CAUGHT |
| `logs/02-install.log` | two-host install @a572ec6 via pft-fleet, pft-maint window on a throwaway topic | PASS 31/0; real inventory validator 47 + 2 own = 49 timers, sentry 25 + 1 = 26; 0 failed, 0 missed, 0 disabled on both |
| `logs/03-alert-preflight-run05.log` | drill preflight @3e42ab2 | ready, nothing changed |
| `logs/04-alert-drill-run06-stopped.log` | drill run 06 | stopped by hand in step 2: the checker read `systemctl show` output in `-p` order (systemd prints its own order) and failed a correct install; restore completed. Fixed @07fc9a4 (also: preflight now refuses an active silence naming PFTJob*, because the install's rollout silence was still active and would have muted the drill) |
| `logs/05-alert-drill-run07-stopped.log` | drill run 07 | **found**: PFTJobFailed fired for 27 sentry series when only the drill job failed, and for no validator series. Cause: the per-job label was `job`; the scrape renamed it `exported_job`, so `on (host, job)` joined every sentry timer to the one failed drill job. Stopped by hand; the stop also killed the restore, which was then completed by hand (drill units, flags and state entry removed on both hosts, bridge back on the operator env with alertpath paused around it, silence expired). **Correction (2026-11-06T19:16Z):** an earlier version of this row said the operator topics got 0 messages. That is true only while the run was going. The hand restore put the bridge back on the operator env while the 27 mis-joined series were still firing (16:54-17:05Z in Prometheus), so their RESOLVED notifications reached the **operator** topic at 17:06Z, 16 messages reading "sentry: scheduled job postfiat failed (0 run(s) in a row)" (`postfiat` = the scrape `job` label, 0 = the joined count). Fixed in logs 15-18 below. **Fixed**: label renamed `timer`; suite check that no sample uses `job`/`instance`; promtool test with two timers on one host; mutants M33, R08 |

| `logs/06-checks.log` | checks @6b3087e (fix) | shellcheck/ruff clean, promtool ok (incl. the two-timer test), suite 102/102, mutants 52/52 CAUGHT |

| `logs/07-update-run09-failed.log` | fleet update @20caf12 (label fix) | label fix verified (0 `job=` labels, rules join on (host, timer), Prometheus 0 `exported_job` series, operator topics 0), but **found**: 2 checks FAIL, the validator's series were gone from Prometheus: its textfile grew to 66,071 bytes and the pft exporter skips files over 64 KiB whole. **Fixed**: two gauges moved to `inventory --format json`, whole-second timestamps (55,583 bytes for 49 timers), `TEXT_BUDGET` guard (writes up 0), pull limit 65536; tests + mutants S12, M34 |

| `logs/08-checks-m33-not-applied.log` | checks @c4f7e1a | FAIL: mutant M33's text no longer matched the changed render line (NOT APPLIED); fixed @3ec4c00 |
| `logs/09-checks.log` | checks @3ec4c00 | PASS: suite 105/105, mutants 54/54 CAUGHT, promtool ok |
| `logs/10-update-run10.log` | fleet update @87eb49f (size fix) | PASS 24/0: validator file back under 64 KiB, `pft_jobwatch_up 1` for both hosts in Prometheus (49/26 timer series, 0 `exported_job`), integrity PASS, fleet CURRENT, keyescrow drift 0, operator topics 0 |
| `logs/11-alert-preflight-run13.log` | drill preflight @87eb49f | ready |

| `logs/12-alert-drill-run14-stopped.log` | drill run 14 @87eb49f | **label fix verified live**: PFTJobFailed fired for exactly the two drill series (`host=sentry/validator, timer=pft-jobwatch-drill.timer`) 197 s after the fail flag and resolved; succeed phase quiet; the bridge delivered every [FIRING]/[RESOLVED] (HTTP 200). But the 4 throwaway-topic checks FAILed: a checker bug (`ok_if` evaluates `$1..$3` as its own arguments). Stopped in step 4 with SIGINT to the drill shell only; its restore completed (units, bridge, alertpath, silence), operator bridge sent 0 messages afterwards. Fixed @(next commit): named locals, tested on a synthetic positive/negative case |

| `logs/13-alert-drill-run16.log` | drill run 16 @2a81527, both hosts at once, throwaway topic | **PASS 59/0**: succeed quiet; every alert FIRING then RESOLVED for both hosts on the throwaway topic (16 messages), operator topics 0; final `pft_jobwatch_up 1` both, inventory validator 49 / sentry 26 (0 failed/missed/disabled), pft-integrity PASS both (176/103), `server_state` full both |
| `logs/14-final-lint.log` | lint at c0db5e8 (drill scripts changed after log 09) | shellcheck + ruff clean; tool, helper, tests, rules unchanged since 3ec4c00 (log 09) |
| `logs/15-checks-2-survived.log` | checks after the 17:06Z operator-topic incident, first try @996413c | FAIL: mutants M20 and R08 SURVIVED. The new `>= 1` clamp let the start-limit-hit check pass without counting the run, and `> 0` hid the host-only join. Tests tightened @adb6af2 (failed_runs must grow; the two-timer promtool test gets a re-running timer with count 3, failed 0) |
| `logs/16-checks.log` | checks @adb6af2 | PASS: the fixes are (1) `PFTJobFailed` needs `consecutive_failures > 0`, and the helper never exports 0 while `failed == 1` (unit test, promtool test, mutants M35, R09); (2) `../alerts/ntfy_bridge.py` sends one message per state change and folds bursts (10 unit tests, bridge mutants 11/11 CAUGHT); (3) `drill/alert-run.sh` + `drill/dedup-run.sh` restores drain first: they wait until no PFTJob* alert is pending/firing/active and its RESOLVED reached the throwaway topic (else silence PFTJob.* for 60 min) before the bridge goes back to the operator env. Suite 106/106, jobwatch mutants 56/56 CAUGHT |
| `logs/17-update-run17.log` | fleet update of `jobwatch_lib.py` on both hosts @adb6af2 (pft-maint window on a throwaway topic) + Prometheus rule reload | PASS: installed helper = repo bytes, rules healthy (`PFTJobFailed` query has `> 0`), integrity PASS, operator topics 0 |
| `logs/18-dedup-drill.log` | `drill/dedup-run.sh` @adb6af2, both hosts, throwaway topic | **PASS 0 failed**: staggered failure, Alertmanager re-sent the sentry alert inside the validator's webhook and the bridge logged `dedup: 1 of 2` and did not forward it; exactly one FIRING and one RESOLVED line per host; no "(0 run(s)"; no job on either host with failed 1 / count 0; drain before restore; operator topics 0; integrity PASS + `server_state` full on both |

| `logs/19-checks-m25-survived.log` | checks @874327b (calendar period fix, see below) | FAIL: RESULT: 60 caught, 1 survived. M25 (next-elapse check removed) survived because the spec period made the interval check fire in the fixtures that used to isolate the next-elapse path; two isolating tests added @8d9ec80 |
| `logs/20-checks.log` | checks @8d9ec80 | PASS: suite 125/125, mutants 61/61 CAUGHT (new M36-M40: spec period ignored, shortest gap, period kept across a spec change, asked every run, rc not checked), promtool ok, bridge 11/11 |
| `logs/21-update-run20.log` | fleet update of `jobwatch_lib.py` on both hosts @8d9ec80 (pft-maint window on a throwaway topic) | PASS 26/0: installed helper = repo bytes, `pft-kmod.timer` interval 3600 and missed 0 on both hosts, 0 missed jobs, integrity PASS, fleet CURRENT, operator topics 0 during the run |

**2026-11-09 found -> fixed -> verified (false PFTJobMissed).** Found: at 19:00Z the operator got `[FIRING] PFTJobMissed sentry: scheduled job pft-kmod.timer is overdue`, though the timer had run on schedule (18:25:51Z, next 19:23:05Z). Cause: `pft-kmod.timer` (`OnCalendar=*:23`, `Persistent=yes`) was installed at 18:14Z; systemd stamps a new persistent timer's `LastTriggerUSec` with its activation time, so the first `NextElapse - LastTrigger` gap was 700 s, and the smallest-gap rule kept it: the job read "missed" 1600 s after every hourly run. Fixed @874327b + @8d9ec80: the calendar period comes from the spec (`systemd-analyze calendar`), the learned gap is only a fallback; the incident is a regression test in the suite (old method: 700 s / missed 1; new: 3600 s / missed 0). Verified: logs 20 and 21.

Drill run 16 timeline (UTC, Prometheus `ALERTS` firing / throwaway-topic message times from the log):

| Phase | Alert | Firing in Prometheus | [FIRING] on topic | [RESOLVED] on topic | Cleared in Prometheus |
|---|---|---|---|---|---|
| fail flag | PFTJobFailed | 17:50:57 (196 s) | 17:51:02 / 17:51:03 | 17:53:03 | 17:53:13 |
| `disable --runtime --now` | PFTJobDisabled | 17:58:51 (332 s) | 17:58:47 / 17:58:48 | 17:59:47 / 17:59:48 | 18:00:07 |
| hang flag (timer stops re-firing) | PFTJobMissed | 18:12:51 (332 s; missed after 428 s) | 18:12:47 / 18:12:48 | 18:14:47 / 18:14:48 | 18:14:55 |
| remove unit files + `forget` | PFTJobDisabled | 18:20:23 (317 s) | 18:20:32 / 18:20:33 | 18:21:32 / 18:21:33 | 18:21:52 |

Topic times are sentry / validator. The drill's poll interval is coarser than Alertmanager's, so a topic message can
be a few seconds earlier than the poll that saw the alert in Prometheus. PFTJobwatchStale is covered by promtool tests
(`../alerts/jobwatch.tests.yml`) and the mutants, not by the live drill (it would mean stopping the collector).
