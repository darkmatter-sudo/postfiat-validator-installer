# alertstats: how the alert rules actually behaved

`pft-rulecheck` (../rulecheck) grades the ~115 alert rules statically: does every selector have data, is every
textfile fresh. It cannot say how a rule *behaved*: how often it went pending without firing, how often it fired,
resolved and fired again, how long it took to resolve, how much of its firing time was silenced, or how many
notifications it produced. `pft-alertstats` reconstructs that from Prometheus' own `ALERTS` history, so `for:`
durations and expressions can be tuned on evidence instead of guesses.

It is **read-only**: HTTP GETs to Prometheus and Alertmanager on loopback and `docker logs` of the ntfy bridge. It
never sends a notification, never creates or expires a silence, never `docker exec`s anything.

| file | what |
|---|---|
| `pft-alertstats.sh` | CLI and daily timer entry point (`run`, `collect`, `report --offline`, `version`) |
| `alertstats_build.py` | Python 3 stdlib helper: collect a bundle; build episodes, flaps, TTR, silences, hygiene; md/json/csv/textfile |
| `systemd/pft-alertstats.{service,timer}` | daily 05:23 UTC, sandboxed (no capabilities, loopback-only IP) |
| `install.sh` | install/uninstall on the validator (the host that runs ../alerts) |
| `../alerts/alertstats.rules.yml`, `.tests.yml` | `PFTAlertFlapping` and its promtool tests |
| `tests/` | pytest suite (synthetic hand-computed cases + real captures), CLI tests against a stub API, mutation harness |
| `logs/` | raw evidence logs of the runs described below |

## Usage

```bash
sudo pft-alertstats run                                  # what the timer does: bundle + md/json/csv + textfile
sudo pft-alertstats collect --since 7d --out b.json.gz   # capture only (cap 15d = Prometheus retention)
pft-alertstats report --offline b.json.gz --format md    # rebuild any report from a bundle, no host access
```

`run` keeps bundles in `/var/lib/pft-alertstats/bundles/` and reports in `/var/lib/pft-alertstats/reports/` for
`KEEP_DAYS` (15). Settings (all optional) go in root-owned `/etc/pft-alertstats.env`; see the header of
`pft-alertstats.sh`.

## Episode model

`collect` asks Prometheus for `ALERTS`, `ALERTS_FOR_STATE` and `count(present_over_time(up{job="postfiat"}[30s]))`
over the window on a 15 s grid (the rule evaluation interval), in chunks of at most 10000 points per series.
`report` then works only on that bundle:

* **episode**: consecutive samples of one series (ALERTS labels minus `alertstate`); samples more than 1.5 steps apart
  end it. No firing sample = **pending-only** (a near miss: `for:` absorbed it; the report shows the longest).
* **Prometheus gaps**: the presence query uses `present_over_time` over two steps, not plain `up`, because the 5 m
  query lookback hides any outage shorter than 5 minutes (the 4-minute validator reboot of 2026-11-12 is invisible
  in `count(up)` and shows as a 225 s gap here).
* **gap handling**: a series gap that lies inside a Prometheus gap (widened by the 5 m lookback) is a *data* gap, not
  a resolve. If `ALERTS_FOR_STATE` shows the same `activeAt` on both sides, Prometheus restored the alert and the
  episode continues (`gap_bridged`, gap seconds not counted as firing time); otherwise it is split and both halves
  carry `gap_split` (no TTR, never a flap). An outage short enough for the lookback to fill also counts as bridged.
* **TTR** = end - firing start, for closed episodes that started inside the window; resolution one step.
  Percentiles are nearest rank (`sorted[ceil(q*n)-1]`), so they can be checked by hand.
* **silenced seconds**: overlap of the firing interval with the union of Alertmanager silences whose matchers all
  match (regex anchored, `!=`/`!~` honoured, absent label = ""). Alertmanager keeps expired silences for its data
  retention (120 h by default), so older silences are not in the bundle.
* **flap**: a fired, mostly unsilenced episode that starts less than `FLAP_WINDOW` (1 h) after the previous one of
  the same series ended. An alertname is **flapping** when one series has `FLAP_MIN` (3) such episodes starting
  within one `FLAP_WINDOW` in the last `FLAP_RECENT` (24 h). Silenced episodes (drills, planned maintenance) never
  reached anyone and do not count.
* **notifications**: the bridge's own log lines (`ntfy [FIRING] NAME -> HTTP 200`), per UTC day. The log restarts with
  the bridge container, so the report says from when it is available.

## Rule hygiene (static, from `/api/v1/rules`)

| check | severity | meaning |
|---|---|---|
| `no_for` | warn | no `for:`: fires on the first evaluation (`ALLOW_NO_FOR` lists deliberate ones, default the watchdog) |
| `short_for` | warn | `for:` shorter than two evaluation intervals |
| `bad_severity` | warn | severity label missing or not critical/warning/info/none |
| `no_summary` | warn | summary annotation missing |
| `no_description` | info | description annotation missing |
| `unhealthy` | warn | rule health not ok (evaluation error) |
| `duplicate_name` | info | the same alertname in more than one rule |
| `always_firing` | warn | fired for >= 90 % of the window |
| `never_active` | info | never pending or firing in the window (untested in production) |
| `no_rule` | info | episodes in the window but no loaded rule (renamed or removed) |

## Metrics and alert

`/var/lib/pft-exporter/textfile/pft_alertstats.prom` (atomic rename, < 60000 bytes, else per-alert detail is dropped
and `pft_alertstats_truncated 1` is set): `pft_alertstats_up`, `_last_run_timestamp_seconds`, `_window_seconds`,
`_rules`, `_prometheus_gap_seconds`, `_notifications{result}`, `_hygiene_findings{check,severity}` (every check, 0 when
absent) and per alertname `_flapping` (0/1), `_flaps`, `_episodes_fired`, `_episodes_pending_only`,
`_ttr_p95_seconds`, `_silenced_seconds`. Label names are never `job`/`instance`.

### Alert

`PFTAlertFlapping` (warning, `for: 5m`), one alert per flapping alertname (in the `flapping_alert` label, because
an `alertname` label in a rule result is overwritten by the rule's own name), or `reason="report-error"` when the
last run could not capture Prometheus. Read the latest report (`sudo pft-alertstats report --offline
/var/lib/pft-alertstats/bundles/<latest>.json.gz`): per-alert flaps, TTR and the longest near miss show whether to
widen `for:`, add hysteresis to the expression, or fix the cause. Staleness of the textfile is graded by
pft-rulecheck (`textfile pft_alertstats.prom 30h`), not by a second alert.

## Tests

```bash
cd alertstats && TMPDIR=$HOME/.cache python3 -m pytest -q tests     # /tmp is noexec on the hosts
docker run --rm --entrypoint promtool -v "$PWD/../alerts":/w:ro -w /w prom/prometheus:v3.5.0 test rules alertstats.tests.yml
TEST_TMPDIR=$HOME/.cache python3 -u tests/mutate.py                 # mutation harness
```

## Evidence logs

| log | what |
|---|---|
| `logs/01-mutants-dev-5-survivors.log` | first (dev) mutation run: 57/62 caught; the 5 survivors (same-timestamp pending/firing, one-point Prometheus gap, split boundary inside a wide flap window, a 19.x public address, gzip mtime) each got a test that kills it |
| `logs/02-mutants.log` | mutation run on the committed code: 62 caught, 0 survived, 0 not applied, 0 broken; controls: unmutated baseline 73 passed + promtool SUCCESS, hang control killed at 60 s, 0 orphans |
| `logs/03-checks.log` | sha256 of every file, shellcheck, ruff, pytest (73 passed), promtool check + test (SUCCESS). `systemd-analyze verify` exits 1 here only because `/usr/local/bin/pft-alertstats` is not installed yet (plus unrelated host units); the install run re-verifies the installed units |
