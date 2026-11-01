# feewatch: transaction queue, fee escalation and load-factor sources

`pft-feewatch` is a read-only monitor of a Post Fiat node's **transaction queue (TxQ)**, its **open-ledger fee
escalation** and **which source raised the load factor** (this server, the network, the cluster or the fee
escalation itself). A 60-second systemd timer reads the node's `fee` and `server_info` RPCs and writes
node_exporter textfile metrics. Four Prometheus alerts are built on them.

Why: the pft exporter (`../exporter`) only exports the total `load_factor`, and `../statewatch` covers state and IO
counters. Neither reads the `fee` RPC, so a queue filling towards `max_queue_size`, an open-ledger fee many times
the base fee, or a node that charges more than the network because it is overloaded itself are all invisible.

Read-only: two RPC reads per minute against the node's own admin port. The tool never submits a transaction and
never generates network load. The drill (below) uses recorded and synthetic answers instead of real load.

## Files

| File | Role |
|---|---|
| `pft-feewatch.sh` | `collect` (RPC -> textfile), `pull` (validator copies the sentry's textfile), `replay` (drill: fixture files -> a `drill-*` textfile), `validate`, `version` |
| `feewatch_parse.py` | Python 3 stdlib parser: checks every field, derives ratios, renders metrics, appends the history line |
| `systemd/pft-feewatch@.service/.timer` | sandboxed collector for container `%i`, every minute at :25 |
| `systemd/pft-feewatch-pull@.service/.timer` | validator only: pulls the sentry's textfile every minute at :50 |
| `install.sh` | install / uninstall (collector or `--pull NAME`) |
| `pft-feewatch.env.example` | `/etc/pft-feewatch.env` (root-owned): `ESCALATION_THRESHOLD`, `PULL_SSH`, timeouts |
| `tests/run-tests.sh` | offline suite with a stub docker that answers `fee` / `server_info` from fixtures |
| `tests/capture_fixtures.sh`, `tests/fixtures/` | real answers from the validator and the sentry, plus a real non-admin answer |
| `../alerts/feewatch.rules.yml`, `../alerts/feewatch.tests.yml` | the four alerts and their promtool unit tests |

## How the collector reads the node

`collect` runs `docker exec <container> curl ... http://127.0.0.1:5005/` for `fee` and then `server_info`. That is
the admin port on the container's own loopback, so it works the same way on a validator and on a sentry (which maps
no admin port to the host). Each call has `curl --max-time RPC_TIMEOUT` plus an outer `timeout` for a hung
`docker exec`. stderr is kept out of the parsed answer, because the docker CLI prints warnings there under the unit's
sandbox.

On **any** failure (container stopped, RPC down or hung, non-JSON, `status` not `success`, or a missing or
malformed field) the textfile holds only `pft_feewatch_up 0` and the collect timestamp. It never keeps stale
values. The write is atomic (temp file in the same directory, then rename).

### What absence means in `server_info` (postfiatd 1.0.9, commit 32723c15)

`NetworkOPs::getServerInfo` (human mode) **omits** a load-factor breakdown field when it equals its default. A
missing field is therefore a value, not missing data:

| field | omitted when | feewatch exports |
|---|---|---|
| `load_factor_server` | equal to `load_factor` | `load_factor` |
| `load_factor_fee_queue` | min level == reference level | 1 |
| `load_factor_local`, `_net`, `_cluster` | equal to the base (**admin answers only**) | 1 on admin answers, **not exported** on non-admin |
| `load_factor_fee_escalation` | open level == reference level (admin); on non-admin answers it is also omitted when it equals `load_factor` | 1 on admin answers, **not exported** on non-admin |

An answer counts as admin when `info.load` (the job queue, which only admins see) is present. On a non-admin answer
(`pft_feewatch_admin 0`) feewatch exports no guessed 1.0, so `PFTLocalLoadHigh` cannot fire on made-up data. The
test fixture `validator_server_info_nonadmin.json` is a real non-admin answer from the host-mapped port.

## Metrics (`pft_feewatch_*{container="..."}`)

| metric | meaning |
|---|---|
| `up`, `collect_timestamp_seconds` | last collection succeeded / when it ran |
| `admin` | 1 if `server_info` was an admin answer |
| `ledger_current_index`, `current_ledger_size`, `expected_ledger_size` | open ledger and its target size |
| `current_queue_size`, `max_queue_size`, `queue_limited` | TxQ size and capacity. `max_queue_size` is absent when the queue has no limit, and then `queue_limited` is 0 |
| `queue_fill_ratio` | `current_queue_size / max_queue_size` |
| `fee_drops{kind=base,median,minimum,open_ledger}` | `fee.drops.*` |
| `fee_level{kind=reference,minimum,median,open_ledger}` | `fee.levels.*` (reference = 256 at the base fee) |
| `escalation_multiple` | `open_ledger_fee / base_fee`. If `base_fee` is 0, `open_ledger_level / reference_level` is used, because postfiatd itself then treats the base as 1 drop |
| `escalation_alert_threshold` | `ESCALATION_THRESHOLD` (default 4), exported so the rule can read it per host |
| `load_factor{source=total,server,local,net,cluster,fee_escalation,fee_queue}` | `server_info` load factor and its breakdown (1 = no load) |
| `local_load_exceeds_net` | 1 if `load_factor_local > load_factor_net` (admin answers only) |

## Alerts

`../alerts/feewatch.rules.yml`, tested by `promtool test rules feewatch.tests.yml`. Each rule has positive cases
(fires, with exact labels and annotations) and negative cases (boundary values, bursts shorter than `for`, a higher
configured threshold, network-wide load, a non-admin answer, recovery).

| alert | condition |
|---|---|
| `PFTTxQueueNearFull` | `queue_fill_ratio > 0.8` for 10m |
| `PFTFeeEscalated` | `escalation_multiple >= escalation_alert_threshold` for 15m |
| `PFTLocalLoadHigh` | `load_factor{source="local"} > load_factor{source="net"}` for 10m: this node, not the network, is the bottleneck |
| `PFTFeewatchStale` | last collection older than 5 min, **or** `up == 0`, for 2m. A single failed minute does not page; failures in 3 consecutive evaluations do |

The validator runs the only Prometheus + Alertmanager. The sentry's textfile is pulled to the validator, so every
`container="postfiatd-sentry"` alert is evaluated there.

## Install

```bash
# on each host (sentry: --container postfiatd-sentry)
sudo feewatch/install.sh [--container NAME]
# on the validator, to pull the sentry's file: PULL_SSH in /etc/pft-feewatch.env (see the example), then
sudo feewatch/install.sh --pull postfiatd-sentry
# rules: list feewatch.rules.yml in ../alerts/prometheus.yml (done in this repo), reload Prometheus
sudo pft-integrity accept --reason "pft-feewatch installed"
```

Each install runs one collection through the sandboxed unit and refuses to enable the timer unless it gives `up 1`.
`fleet/manifest.tsv` lists the installed files, so `pft-fleet skew` reports drift.

## Tests

```bash
bash feewatch/tests/run-tests.sh                         # offline, no root, stub docker
(cd alerts && promtool test rules feewatch.tests.yml)    # alert rules
shellcheck feewatch/*.sh feewatch/tests/*.sh && ruff check feewatch
```

The offline suite covers real idle answers from both hosts, a real non-admin answer, synthetic loaded answers in
real field shapes, malformed JSON (truncated, HTML, list, empty), missing or malformed fields (including the
divisions by zero), RPC errors, a stopped container, a hung `docker exec` (bounded by the timeout), a docker CLI
warning on stderr, recovery after failure, `replay` (no RPC, refuses real node names), and `pull` validation.

## Live install (validator + sentry)

`drill/install-run.sh` installs on both hosts at a pushed, clean HEAD and checks every step
(`logs/04-install-two-hosts.log`: 22 checks ok, 0 failed). In order: integrity PASS before; pft-maint window with
its `[MAINT]` messages sent to a throwaway topic; an Alertmanager silence scoped to the feewatch, rulecheck and
fleet alerts; install on the sentry, then the validator (each twice, to show it is idempotent); the validator pulls
the sentry's file; rulecheck freshness lines on both hosts; Prometheus reload with 4 rules `ok`; `pft_feewatch_up 1`
scraped for both containers; `pft-integrity accept` + PASS on both hosts; `pft-fleet sync` of the manifest with
`feewatch CURRENT` on both hosts; rulecheck `RESULT OK` on both. At the end it restores the real pft-maint target
(read back by sha256 / absence), checks the throwaway topic got both `[MAINT]` messages, and expires the silence
once no covered alert is pending.

Offline tests on the same code: `logs/03-tests.log` (shellcheck and ruff clean, `RESULT: 151/151 passed`, promtool `SUCCESS`).
Fixture capture: `logs/01-fixture-capture.log`, and `logs/02-fixture-capture.log`, which re-captured the fixtures
after `ports` was added to the scrub list. Only the 02 fixtures are committed.

## Logs

`logs/` holds the raw runs, redacted (home directory -> `~`, user -> `<user>`, IPs -> `<redacted-ip>`, throwaway
ntfy topic -> `<throwaway-topic>`).
