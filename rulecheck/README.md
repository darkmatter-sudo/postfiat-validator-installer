# pft-rulecheck: dead alert rules and stale textfile inputs

Monitoring can switch itself off without anyone noticing. A rule whose selectors match no series can never fire:
the metric was renamed, a label changed, or the collector was removed. A textfile collector that stopped writing
leaves its last values in place, so every alert built on them stays quiet. A pulled copy of a peer's textfile is
worse, because the pull keeps refreshing the file's mtime after the peer's collector has stopped. pft-rulecheck
makes all of these cases visible. It is read-only and writes only its own metrics file.

## What it checks

**Rules** (Prometheus host): every alerting and recording rule from `/api/v1/rules`. Each selector in the rule's
expression is extracted with a small PromQL tokenizer and queried as
`count(last_over_time(SELECTOR[LOOKBACK]))` (LOOKBACK defaults to 10m). Duplicate selectors are queried once.

| state | meaning |
|---|---|
| LIVE | every selector has series. Rules with no selector to check (`vector(1)`, `absent()`-only) are LIVE too |
| PARTIAL | some selectors have no series (the rule may still fire, but not for what it was written for) |
| DEAD | no selector has series: the rule cannot fire |
| ERROR | Prometheus reports the rule `health: err` (with its `lastError`), or the expression cannot be parsed |
| IGNORED | `ignore-rule GROUP/RULE REASON` in the config |

Some selectors are excluded on purpose. The arguments of `absent()` / `absent_over_time()` are empty when
healthy. `ALERTS` / `ALERTS_FOR_STATE` exist only while something fires. Metrics listed with
`ignore-metric METRIC REASON` are expected to be empty when healthy, for example a counter that first appears with
its first error. Label lists after `by`, `without`, `on`, `ignoring`, `group_left` and `group_right` are skipped, as
are strings, numbers, durations, `offset`, `@ start()/end()`, subquery ranges and comments. Prometheus 3 quoted
metric names (`{"my.metric"}`) are supported.

**Textfiles** (both hosts): every file in the exporter's textfile dir.

| state | meaning |
|---|---|
| FRESH | within the max age of the first matching `textfile GLOB MAX_AGE [TS_METRIC]` line |
| STALE | older than that. With TS_METRIC the age is the larger of the mtime age and `now - smallest TS_METRIC value in the file`. A pulled copy re-written every minute but carrying an old collector timestamp is STALE, and the source column then names the metric. A file without the metric is STALE too |
| MISSING | `require FILE` in the config, but the file is not there |
| LEFTOVER | a dot / temp / non-`.prom` file older than `leftover-age` (10m): an interrupted pull or collector |
| UNCONFIGURED | a `.prom` file no `textfile` line matches (its freshness would not be checked) |

Exit codes: **0** every rule LIVE (or IGNORED) and every file FRESH; **1** at least one finding; **2** the check
itself could not run. That covers Prometheus unreachable or answering an error / non-JSON / a malformed sample, an
unreadable textfile dir, a bad config line (named with its line number), an unknown env key, or a bad argument.
A query error is never reported as DEAD.

## Usage

```bash
sudo pft-rulecheck check            # table: one row per rule, one per textfile, a RESULT line
sudo pft-rulecheck check --json     # one object: exit, error, summary, rules[] (selectors, dead), textfiles[]
sudo pft-rulecheck check --no-prom  # textfiles only
pft-rulecheck selectors 'sum by (job) (rate(x_total[5m])) > on (job) group_left () y'   # what it would query
sudo pft-rulecheck run              # the timer: check + write pft_rulecheck_HOST.prom
sudo pft-rulecheck pull             # Prometheus host: copy the peer's pft_rulecheck_PEER.prom
```

Example (validator, after the fixes below; from `logs/04-sentry-pull-verify.log`):

```
RESULT OK - rules: LIVE 70 PARTIAL 0 DEAD 0 ERROR 0 IGNORED 0 | textfiles: FRESH 13 STALE 0 MISSING 0 LEFTOVER 0 UNCONFIGURED 0 -> exit 0
```

## Install

```bash
sudo rulecheck/install.sh                 # Prometheus host (validator)
sudo rulecheck/install.sh --no-prom       # host without Prometheus (sentry): textfile checks only
# Prometheus host: add PEER_LABEL=sentry and PULL_SSH="runuser -u OPERATOR -- ssh ... SENTRY" to /etc/pft-rulecheck.env
sudo rulecheck/install.sh --pull
sudo docker kill -s HUP pft-prometheus    # load ../alerts/rulecheck.rules.yml (listed in ../alerts/prometheus.yml)
sudo pft-integrity accept --reason "pft-rulecheck"
```

install.sh copies the script to `/usr/local/bin/pft-rulecheck` and the helper to
`/usr/local/lib/pft-rulecheck/rulecheck_lib.py`. If they do not exist yet, it writes `/etc/pft-rulecheck.env`
(HOST_LABEL, NO_PROM; root 0600) and `/etc/pft-rulecheck.conf` (from `pft-rulecheck.conf.example`, or
`pft-rulecheck.sentry.conf.example` with `--no-prom`). It runs one check through the sandboxed unit (exit 1 =
findings is a success for the unit; the file must say `up 1`) and only then enables the timer (hourly at :17).
With `--pull` it runs one pull (exit 0) before enabling `pft-rulecheck-pull.timer` (every 15 min).

`/etc/pft-rulecheck.env` holds KEY=VALUE lines only; nothing is evaluated and unknown keys are refused. The keys are
HOST_LABEL, PROM_URL (http(s) only), NO_PROM, CONF, TEXTFILE_DIR, LOOKBACK, PEER_LABEL, REMOTE_DIR, PULL_SSH and
PULL_TIMEOUT. pft-fleet tracks the installed files (`../fleet/manifest.tsv`).

**Sandbox** (`systemd/pft-rulecheck.service`): root without capabilities (`CapabilityBoundingSet=`) and
`NoNewPrivileges`. `ProtectSystem=strict` with only the textfile dir writable, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, kernel/clock/hostname/cgroup protections, `ProtectProc=invisible`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service ~@privileged @resources`. Network is limited to
`IPAddressAllow=localhost` (Prometheus on 127.0.0.1). The pull unit is the same as `../vulnscan`'s (its ssh runs
as the operator account named in PULL_SSH).

The pull validates the peer's file before renaming it into place. Only `pft_rulecheck_` samples with
`host="PEER"` as the first label are accepted, the file must be 256 KiB or smaller, and `up` and `last_run` must be
present. A failed fetch exits 1 and a failed validation exits 2. In both cases the old copy stays, so a dead peer
goes STALE here. A hanging ssh is stopped by PULL_TIMEOUT.

## Metrics

| metric | meaning |
|---|---|
| `pft_rulecheck_up{host}` | 1 if the last check could read Prometheus (unless --no-prom) and the textfile dir. On 0 no rule/textfile series are written, so a failed run can never read as "all fine" |
| `pft_rulecheck_last_run_timestamp_seconds{host}`, `pft_rulecheck_duration_seconds{host}` | last run |
| `pft_rulecheck_rules{host,state}`, `pft_rulecheck_textfiles{host,state}` | counts per state |
| `pft_rulecheck_selectors_checked{host}` | distinct selectors queried |
| `pft_rulecheck_rule_dead{host,group,rule,idx,state}` | 1 for DEAD / PARTIAL / ERROR, 0 for LIVE / IGNORED (every rule has a series) |
| `pft_rulecheck_textfile_stale{host,file,state}` | 1 for STALE / MISSING / LEFTOVER / UNCONFIGURED, 0 for FRESH |
| `pft_rulecheck_textfile_age_seconds{host,file}` | the age the verdict used |

## Alerts

`../alerts/rulecheck.rules.yml`, tested in `../alerts/rulecheck.tests.yml` (promtool):

| alert | fires when |
|---|---|
| `PFTRuleDead` | `pft_rulecheck_rule_dead == 1` for 5m. The labels name the group, rule and state; `sudo pft-rulecheck check` names the dead selector |
| `PFTTextfileStale` | `pft_rulecheck_textfile_stale == 1` for 5m. The labels name the host, file and state |
| `PFTRulecheckNotRunning` | no run for 3h, `up 0` for two hourly runs (65m), or the validator never wrote its file |

The promtool tests cover: a DEAD rule firing after 5m; LIVE (0) and a rule that recovered after 3m (stale series)
never firing; a STALE file resolving when the next run says FRESH; a LEFTOVER on the sentry; the timer stopping
(nothing at 3h and 4h, fires at 4h7m, while the other host keeps running); and one failed hourly run not firing
while a second one does.

## Tests

`tests/run-tests.sh` runs without root, network or a real Prometheus. `tests/stub_prom.py` serves
`tests/fixtures/prom-*.json` on a random 127.0.0.1 port and logs every query. Textfile dirs are temp dirs with
mtimes set by `touch -d`, and the clock is `PFT_RC_NOW`. The checks cover:

- 22 selector edge cases;
- every rule class: plain, constant, absent-only, ALERTS-only, recording, escaped-quote + regex matchers queried
  verbatim, duplicate selector, renamed metric, one-sided PARTIAL, health err, unparsable, ignore-rule,
  ignore-metric, the same rule name in two groups;
- the query cache (6 queries for the mixed fixture) and the exact query text;
- every textfile class, including the pulled copy with a fresh mtime and a 15-minute-old content timestamp, a
  missing timestamp metric, first-match-wins and a skipped symlink;
- exit 0 and every exit-2 path;
- JSON output, metrics content and mode;
- validate (wrong host, foreign metric, missing last_run, empty, oversize);
- pull success, ssh failure, invalid remote file and a hanging ssh stopped by the timeout (each keeps the old copy
  and leaves no temp file).

`tests/mutate.py` is the mutation table: 22 one-line mutants of the script and the helper, each of which must
apply exactly once. A control run on the unmodified copies must pass first, and a mutant counts as caught only if
the suite printed its RESULT line with at least one FAIL. The first development run had 2 survivors: M13 (a failed
run still writing rule series when Prometheus was fine but the textfile dir was unreadable) and M22 (the wrapper's
`--lookback` check, where the helper accepted `0m`). Both were test gaps; two tests were added, and the recorded
run is 22/22.

## Live proof (validator + sentry)

Logs in `logs/` come from real runs on the validator and the sentry (Ubuntu 22.04). The operator account name is
replaced by `<user>` with one uniform `sed`, and the drill output also went through `../peerexpose/drill/redact.py`
(topics, addresses, node keys). Every number below is taken from these logs.

**Step 1: found -> fixed -> verified** (`logs/03`, `logs/04`):

| finding (first live run, before any change) | cause | fix | verified |
|---|---|---|---|
| DEAD `pft-fleet/PFTFleetDriftStale`, selector `pft_fleet_drift_since_timestamp_seconds` with 0 series | pft-fleet wrote that series only while drift existed, so with no drift a renamed metric and "no drift" looked the same | `../fleet/fleet_lib.py` now writes the series for every host/add-on pair (0 = no drift), and the rule has a `> 0` guard (`../alerts/fleet.rules.yml`; promtool tests updated, fleet suite 93/93, fleet mutants 20/20) | LIVE 1/1 |
| LEFTOVER `.pull-postfiatd-sentry.<random>` in the textfile dir, 1d04h old, 0 bytes | a pft-resources pull was interrupted when the host rebooted (mtime 2026-10-29T02:56:30Z; the previous boot ended 02:56:32Z), so its EXIT trap never ran | removed; pft-rulecheck now reports any recurrence within 10 minutes | gone (LEFTOVER 0) |

The baseline in log 03 also shows `pft_rulecheck_sentry.prom` MISSING, because rulecheck was not installed yet.
In log 03 section A the `(exit 0)` belongs to the `grep -v` filter in that pipe. The helper's own verdict is its
RESULT line (exit 1). Final runs after install, the Prometheus reload and the sentry pull:

```
validator  RESULT OK - rules: LIVE 70 PARTIAL 0 DEAD 0 ERROR 0 IGNORED 0 | textfiles: FRESH 13 STALE 0 MISSING 0 LEFTOVER 0 UNCONFIGURED 0 -> exit 0
sentry     RESULT OK - rules: skipped | textfiles: FRESH 7 STALE 0 MISSING 0 LEFTOVER 0 UNCONFIGURED 0 -> exit 0
```

`pft-fleet skew`: rulecheck is CURRENT on both hosts, SUMMARY CURRENT=35 ... MISSING=0, exit 0.
pft-integrity accepts the new files with a reason, and verify then PASSes on both hosts (104 / 61 items, log 05).

**Two-host drill** (`drill/live-run.sh`, `logs/07-drill-run2-pass.log`: 24/24 checks ok). Inside one pft-maint
window, every ntfy notifier on both hosts and the Alertmanager bridge were pointed at a throwaway topic, and every
other alert was silenced:

1. The sentry's `pft-statewatch@postfiatd-sentry.timer` was stopped (stale collector) and a rule on a metric
   nobody exports was loaded through `/etc/pft-slo/*.rules.yml` (dead rule).
2. 264 s after the stop, the validator's pulled copy read STALE by its content timestamp (age 307 s, source
   `pft_statewatch_collect_timestamp_seconds`), while its mtime was still fresh: the pull kept re-copying it.
3. One run per host through the real units gave: sentry STALE 1; validator exactly DEAD 1 (the drill rule) and
   STALE 1 (the pulled copy). The sentry result was pulled to the validator.
4. PFTRuleDead and PFTTextfileStale (host=validator and host=sentry) were firing 321 s later (`for: 5m`), and
   `[FIRING]` messages for all three reached the throwaway topic.
5. Recovery: drill rule removed, collector restarted, both hosts back to RESULT OK, alerts gone from Prometheus,
   `[RESOLVED]` delivered. This took 155 s.
6. Restore: env files byte-identical (sha256), bridge back on the operator env, window ended. Operator topics got
   **0** messages (2 topics; re-read again after the run, still 0). pft-integrity PASS on both hosts, both nodes
   full.

Run 1 (`logs/06-drill-run1-check3b-failed.log`, kept) detected, alerted, delivered, recovered and restored the same
way, but check 3b failed (23/24). The check required the sentry's verdict to name `mtime` as the age source.
For a collector that stopped, the collect timestamp inside the file is about 1 s older than its mtime, so the tool
correctly named the timestamp metric. Only the harness check was changed (commit 9c9e180), and run 2 passed.

One difference between the runs: run 1 delivered `[RESOLVED]` for all three alerts. Run 2 delivered it for
PFTRuleDead and PFTTextfileStale host=validator before the read-back; the host=sentry resolution was not on the
throwaway topic yet when the harness restored the bridge. The restored bridge logged no webhook afterwards, and
the operator topics stayed at 0. Check 4f requires at least one `[RESOLVED]` per alert name.

| log | content |
|---|---|
| `logs/01-tests.log` | sha256 of the shipped files; `tests/run-tests.sh` 111/111; shellcheck 0; ruff clean; promtool check + test (rulecheck + changed fleet rules), check config; fleet suite 93/93 |
| `logs/02-mutants.log` | rulecheck mutants 22/22 caught (control pass first); fleet mutants 20/20 after the drift-series change |
| `logs/03-step1-validator.log` | baseline findings, both fixes, fleet reinstall, validator install, Prometheus reload with the rules healthy |
| `logs/04-sentry-pull-verify.log` | sentry install from the committed tree, pull setup, final runs on both hosts, metrics in Prometheus, fleet skew exit 0 |
| `logs/05-integrity.log` | pft-integrity accept + verify PASS on both hosts |
| `logs/06-drill-run1-check3b-failed.log` | drill run 1 (23/24, harness check 3b) |
| `logs/07-drill-run2-pass.log` | drill run 2 (24/24) |
| `logs/08-verify-sentry-resolution.log` | after run 2: the host=sentry PFTTextfileStale left Prometheus in the same evaluation as the others (last firing sample 08:15:00Z), current alerts on both hosts, 0 webhooks to the restored bridge |

## Limits

- Liveness means that series exist, not that the rule's condition is meaningful. A rule comparing the wrong metric
  that has series is LIVE.
- A selector that only has series on some hosts makes the rule PARTIAL by design. Use `ignore-metric` or
  `ignore-rule` with a reason for intentional cases.
- Freshness is per file. A file mixing several collectors' timestamps is judged by the stalest one (smallest
  TS_METRIC value).
- The sentry has no Prometheus, so its rules are not checked there; its textfiles are checked locally and through
  the validator's pulled copies.
