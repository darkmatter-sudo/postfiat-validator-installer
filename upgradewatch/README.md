# upgradewatch: amendment-block risk and upgrade readiness

`pft-upgradewatch` is a read-only monitor that warns a Post Fiat node operator **before** the node becomes
amendment blocked. A 5-minute systemd timer reads the node's admin RPC and writes node_exporter textfile metrics:
amendments that this build does not support but that hold a majority of trusted validators, the time when they can
activate (derived from the postfiatd source, see [ETA derivation](#eta-derivation)), the `amendment_blocked` flag,
and how this build compares with the foundation RPC and with the node's peers. Five Prometheus alerts are built on
these metrics.

Why: `../amendments` is a one-shot check that an operator has to remember to run. Its ETA also assumes the 2-week
default hold time, but the Post Fiat testnet config (`cfg/postfiatd-testnet-light.cfg:1470`, and the live config on
both hosts here) sets `[amendment_majority_time] 3 days`. An unsupported amendment could therefore activate 11 days
before the date that check prints. `upgradewatch` reads the node's own setting, runs all the time, and alerts.

Read-only: on each run it makes four admin RPC reads on the node's own loopback (`server_info`, `feature`, `peers`,
`ledger_entry` of the Amendments object at the validated ledger), runs one `grep` of the node config inside the
container, and makes one public `server_info` call to the foundation RPC. It never submits a transaction.

## Files

| File | Role |
|---|---|
| `pft-upgradewatch.sh` | `collect` (RPC -> textfile), `pull` (validator copies the sentry's textfile), `replay` (drill: fixture files -> a `drill-*` textfile), `validate`, `version` |
| `upgradewatch_parse.py` | Python 3 stdlib parser: checks every field, derives the ETA and the version comparisons, renders the metrics |
| `systemd/pft-upgradewatch@.service/.timer` | sandboxed collector for container `%i`, every 5 min at :25 |
| `systemd/pft-upgradewatch-pull@.service/.timer` | validator only: pulls the sentry's textfile every 5 min at :50 |
| `install.sh` | install / uninstall (collector, or `--pull NAME`) |
| `pft-upgradewatch.env.example` | `/etc/pft-upgradewatch.env` (root-owned): `PULL_SSH`, `FOUNDATION_URL`, timeouts |
| `tests/capture_fixtures.sh`, `tests/fixtures/` | real answers from the validator, the sentry and the foundation RPC (addresses, keys and hashes scrubbed) |
| `tests/test_upgradewatch_parse.py` | parser unit tests on the real fixtures and on modified copies, with hand-computed ETAs |
| `tests/run-tests.sh` | offline suite for the collector: stub docker / curl / ssh, failure, hang, guard, replay, validate and pull cases |
| `tests/gen_promtool_tests.py` | generates `../alerts/upgradewatch.tests.yml` (hand-written series, times and values) |
| `tests/mutate.py` | mutation harness over the collector, the parser and the rules, with a timeout and an unmutated control run |
| `../alerts/upgradewatch.rules.yml`, `../alerts/upgradewatch.tests.yml` | the five alerts and their promtool unit tests |
| `drill/install-run.sh` | the recorded two-host install through `pft-fleet sync` in a `pft-maint` window |
| `drill/make_drill_fixtures.py` | builds the drill fixture sets (blocked, majority, soon, lag, failing, healthy) from the real validator answers |
| `drill/live-run.sh` | the alert drill: fixture replay -> Prometheus -> Alertmanager -> throwaway ntfy topic, then recovery and restore |
| `drill/live-values.sh` | read-only record of the live values on both nodes (timers, textfiles, Prometheus, alert state) |

## How the collector reads the node

`collect` runs `docker exec <container> curl ... http://127.0.0.1:5005/` on the container's own loopback admin port,
so it works the same way on a validator and on a sentry (the sentry maps no admin port to the host). The request
bodies come from a fixed allowlist (`body()`): nothing else can be sent. Each call has `curl --max-time RPC_TIMEOUT`
and an outer `timeout` for a hung `docker exec`. stderr is kept out of the parsed answer.

The majority hold time comes from the node config. Only lines that are section headers, or that look like a duration
(`<n> minutes|hours|days|weeks`), leave the container (`grep -E "$CFG_RE"`). The validator token and every other value
stay inside it. The parser then applies the node's own rules to those lines: comments and blank lines are skipped,
values of a repeated section add up, and exactly one value is used, otherwise the default applies.

On ANY node-side failure (docker, curl, timeout, non-JSON, an RPC error, a missing or malformed field) the textfile
holds only `pft_upgradewatch_up 0` and the collect timestamp, never stale values, and `collect` exits 1. If the
foundation RPC fails, the node data is still valid: only `foundation_known` becomes 0.

## Metrics

All metrics are gauges, and the first label is `container`. Every series that a rule reads is written on every
successful run (0 = none), so `../rulecheck` never grades these rules DEAD on a healthy node.

| Metric | Meaning |
|---|---|
| `pft_upgradewatch_up` | 1 if the last collection succeeded and every node field was valid |
| `pft_upgradewatch_collect_timestamp_seconds` | Unix time of the last attempt |
| `pft_upgradewatch_amendment_blocked` | 1 if `server_info.amendment_blocked` is true or warning 1002 is present |
| `pft_upgradewatch_unsupported_majority_warning` | 1 if `server_info` carries warning 1001 (admin answer) |
| `pft_upgradewatch_amendments_known`, `_amendments_enabled`, `_amendments_enabled_unsupported` | feature table size, enabled count (validated Amendments object), enabled but not supported by this build |
| `pft_upgradewatch_majority_amendments{supported="yes"\|"no"}` | not-yet-enabled amendments holding a ledger majority |
| `pft_upgradewatch_majority_activation_eta_seconds{amendment,supported}` | per majority amendment: earliest activation (Unix), at most 32 series; an amendment unknown to the build is labelled `unknown_<full hash>` |
| `pft_upgradewatch_unsupported_activation_eta_seconds` | earliest activation of an UNSUPPORTED majority amendment (0 = none) |
| `pft_upgradewatch_node_expected_date_seconds` | the node's own warning 1001 `expected_date` as Unix time (0 = no warning) |
| `pft_upgradewatch_eta_agrees_with_node` | written only when both exist: 1 if the derived ETA equals the node's `expected_date` |
| `pft_upgradewatch_majority_time_seconds`, `_majority_time_from_config` | hold time used for the ETA; 1 = from `[amendment_majority_time]`, 0 = the 2-week default |
| `pft_upgradewatch_build_info{version}` | this node's `build_version` |
| `pft_upgradewatch_foundation_known`, `_foundation_build_info{version}`, `_behind_foundation` | foundation RPC answer read this run; its version; 1 if this build is older (0 when unknown) |
| `pft_upgradewatch_peers_versioned`, `_peers_newer`, `_peers_newer_ratio` | peers that report a parseable postfiatd version, how many of them run a newer one, and the ratio |

Versions are ordered like postfiatd's BuildInfo: `1.0.10 > 1.0.9 > 1.0.9-rc2 > 1.0.9-rc1 > 1.0.9-b9`. An optional
`postfiatd-` prefix is accepted. Anything else (for example `rippled-2.3.0`) is not compared and not counted.

## Alerts

`../alerts/upgradewatch.rules.yml`, tested by `promtool test rules upgradewatch.tests.yml`:

| Alert | Condition | Severity |
|---|---|---|
| `PFTAmendmentBlocked` | `amendment_blocked == 1` for 2m | critical |
| `PFTUnsupportedAmendmentMajority` | an unsupported amendment holds a ledger majority, or the node's warning 1001 is present, for 10m | warning |
| `PFTUnsupportedAmendmentActivationSoon` | the unsupported ETA is less than 24 h away (or already past) for 5m; `$value` = time left | critical |
| `PFTNodeVersionLag` | older than the foundation RPC, or at least half of 5 or more version-reporting peers run a newer build, for 15m | warning |
| `PFTUpgradewatchStale` | last collection older than 15 min, or `up == 0` (two failed runs), for 10m | warning |

Each rule has positive cases (it fires at the exact minute, with exact labels and annotations) and negative cases
(boundaries, blips shorter than `for`, the "no ETA" value 0, supported majorities, too few peers) plus recovery.

## ETA derivation

This is how postfiatd 1.0.9 decides when an amendment activates (commit `32723c15e686a2088f2c83017a6ff909d93822cd`,
the build that runs on both hosts; the extracts are in `logs/01-source.log`):

1. When trusted validators vote for an amendment above the threshold, a flag ledger records a `Majority` entry with
   its `CloseTime` in the Amendments object (`AmendmentTable.cpp:902-908` `tfGotMajority`, applied in
   `Change.cpp:308-377`).
2. At a later flag ledger the amendment is enabled if `majorityTime + majorityTime_ <= closeTime` and the majority
   still holds (`AmendmentTable.cpp:916-920`, the test at `:918`). If the majority is lost first, the entry is
   removed (`:910-914` `tfLostMajority`, `Change.cpp:308-377`).
3. `majorityTime_` is `[amendment_majority_time]` (`Config.cpp:871-899`: `<n> minutes|hours|days|weeks`,
   case-sensitive unit, at least 15 minutes). It applies only when the section holds exactly one line
   (`getSingleSection`, `Config.cpp:226`). Otherwise the default `weeks{2}` applies (`SystemParameters.h:88`).
4. The node itself warns with warning 1001 and `expected_date = earliest unsupported majority + majorityTime_`
   (`AmendmentTable.cpp:971-988`, `NetworkOPs.cpp:2664-2677`).

So `ETA = Majority.CloseTime + 946684800 (Ripple epoch -> Unix) + majority time`. This is the same value as the
node's own `expected_date`, and `pft_upgradewatch_eta_agrees_with_node` checks that whenever both exist. The actual
switch happens at the first flag ledger (every 256 ledgers, `Ledger.h:426`) whose parent closes at or after the ETA.
That is at most 256 ledgers later (about 15 minutes at the testnet's close times), so the alert window of 24 h
covers it.

## Tests

```bash
python3 upgradewatch/tests/test_upgradewatch_parse.py         # parser: real fixtures + hand-computed ETAs
bash upgradewatch/tests/run-tests.sh                          # collector: stub docker/curl/ssh (no root, no network)
python3 upgradewatch/tests/gen_promtool_tests.py > alerts/upgradewatch.tests.yml
(cd alerts && promtool test rules upgradewatch.tests.yml)     # alert rules
python3 upgradewatch/tests/mutate.py -j 3                     # mutants over collector, parser and rules
```

The shell suite and the harness keep their temp files under `${TEST_TMPDIR:-~/.cache}`, because `/tmp` is `noexec`
on these hosts.

## Limitations

- The config filter passes only duration-shaped lines. If the section holds one valid value plus a second line that
  is not duration-shaped, the node uses the default (2 lines), but upgradewatch sees one line and uses that value.
  `eta_agrees_with_node` exposes such a mismatch whenever the node warns.
- The foundation comparison trusts one public endpoint (`FOUNDATION_URL`). When it is unreachable,
  `foundation_known` is 0, and the lag alert relies on the peer comparison alone.
- Peer versions are self-reported in the handshake. The peer rule needs at least 5 version-reporting peers, so that
  a few odd peers cannot trigger it.

## Install

```bash
sudo upgradewatch/install.sh --container postfiatd           # validator (sentry: --container postfiatd-sentry)
sudo install -m 600 upgradewatch/pft-upgradewatch.env.example /etc/pft-upgradewatch.env   # validator: set PULL_SSH
sudo upgradewatch/install.sh --pull postfiatd-sentry         # validator: pull the sentry's textfile
sudo pft-integrity accept --reason "pft-upgradewatch installed"
```

On these two hosts the install ran through `pft-fleet sync` inside a `pft-maint` window
([`drill/install-run.sh`](drill/install-run.sh), log 08). The rule line in `../alerts/prometheus.yml`, the six
`../fleet/manifest.tsv` lines and the rulecheck lines were committed together with that run, and not before it.

## Alert drill

`drill/live-run.sh` proves every alert end to end without touching either node. The inputs are **fixtures, not live
conditions**: at drill start `drill/make_drill_fixtures.py` copies the real validator answers from `tests/fixtures`
and changes one thing per set, and the INSTALLED `pft-upgradewatch replay` writes them as `drill-*` textfiles
(`replay` refuses any name that does not start with `drill-`, so it cannot overwrite a real node's file).

| Drill series | Fixture change | Alert(s) expected |
|---|---|---|
| `drill-blocked` | `amendment_blocked: true` + warning 1002 | `PFTAmendmentBlocked` |
| `drill-majority` | an amendment unknown to this build got a majority 1 day ago (ETA = +3 days - 1 day = now + 2 days) | `PFTUnsupportedAmendmentMajority` |
| `drill-soon` | the same amendment, majority 2.5 days ago (ETA = now + 12 h) | `...Majority` and `PFTUnsupportedAmendmentActivationSoon` |
| `drill-lag` | foundation RPC reports build 1.0.10 (node 1.0.9) | `PFTNodeVersionLag` |
| `drill-failing` | `server_info` is not JSON (`up 0`) | `PFTUpgradewatchStale` |
| `drill-stale` | healthy answers, collect timestamp 1000 s in the past | `PFTUpgradewatchStale` |

The harness is the feewatch drill's (`../feewatch/drill/live-run.sh`): every notifier env file on both hosts and the
Alertmanager-to-ntfy bridge point at a random throwaway topic for the drill (sha256 of each original recorded and
compared after the restore), one Alertmanager silence covers every alert except the five under test and the pipeline
watchdog, and a `pft-maint` window is open. It waits for every (alert, container) pair to be FIRING in Prometheus and
delivered as `[FIRING]`, switches every series to the healthy set, waits for every pair to leave Prometheus and be
delivered as `[RESOLVED]`, then restores and reads back the operator topics (count only, never printed).
`PREFLIGHT_ONLY=1` runs step 0 alone (nothing changed).

Recorded run (log 10): 19 checks ok, 0 failed. All 7 pairs fired (940 s after the first replay, the 15 min
`PFTNodeVersionLag` hold being the longest) and all 7 resolved 74 s after the healthy replay. The throwaway topic got
16 messages (7 `[FIRING]`, 7 `[RESOLVED]`, 2 `[MAINT]`); both operator topics got 0. The sentry runs no
Prometheus/Alertmanager: `host=sentry` alerts are evaluated on the validator from the pulled textfile, so the drill
runs there.

## Logs

Raw output of the commands run on the validator and the sentry (Ubuntu 22.04.5 LTS). IP addresses are replaced by
`<redacted-ip>` (in log 01 these are the public peers listed in the testnet config) and the home directory by `~`.

| Log | What | Result |
|---|---|---|
| [`01-source.log`](logs/01-source.log) | postfiatd source at the running build `32723c15`: majority time, enable rule, warnings, flag interval; `[amendment_majority_time]` on both live configs | `3 days` on both hosts, default `weeks{2}` |
| [`02-capture.log`](logs/02-capture.log) | `tests/capture_fixtures.sh`: real answers from both nodes and the foundation RPC | 101 features, 0 majorities, 19 / 16 peers, build 1.0.9 everywhere |
| [`03-smoke.log`](logs/03-smoke.log) | first live `collect --stdout` on the validator (dev, nothing written) | up 1 in 1.9 s |
| [`04-dev-mutants.log`](logs/04-dev-mutants.log) | dev mutant pass | 58/59; S15 survived (the conf test set a value that `--container` overrode) |
| [`05-dev-s15.log`](logs/05-dev-s15.log) | S15 after the test fix | killed |
| [`06-tests.log`](logs/06-tests.log) | recorded offline run at `0e80c1a`: shellcheck, ruff, parser suite, collector suite, generated == committed promtool tests, promtool | 22 tests OK, `RESULT: 98/98 passed`, promtool `SUCCESS` |
| [`07-mutants.log`](logs/07-mutants.log) | recorded mutant run at `0e80c1a` (control first) | `59 killed ... of 59, 0 survived` |
| [`08-install.log`](logs/08-install.log) | two-host install at `55bc1e5` through pft-fleet in a pft-maint window ([MAINT] to a throwaway topic) | 28 checks ok, 0 failed |
| [`09-drill-preflight.log`](logs/09-drill-preflight.log) | `PREFLIGHT_ONLY=1 drill/live-run.sh`: step 0 only, fixture dry run, redaction control. Smoke run before the commit: same `live-run.sh` sha256 as log 10; `make_drill_fixtures.py` was `ruff format`ted afterwards (sha256 `df16c489...` here, `9e76aee2...` in log 10) | 1 check ok, nothing changed |
| [`10-live-drill.log`](logs/10-live-drill.log) | recorded alert drill at `adfa4c4` | 7/7 pairs FIRING then RESOLVED, operator topics 0 messages, 19 checks ok, 0 failed |
| [`11-live-values.log`](logs/11-live-values.log) | `drill/live-values.sh` after the drill | `up 1`, not blocked, 0 unsupported majorities, majority time 259200 s, build 1.0.9 = foundation, 19 / 16 versioned peers, 0 newer; 0 upgradewatch alerts |
