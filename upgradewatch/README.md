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
