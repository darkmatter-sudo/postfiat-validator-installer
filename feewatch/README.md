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
| `report_feewatch.py` | `report` (24h baseline JSON + Markdown), `crosscheck` (public RPC, `--negative`, `--offline`), `direct` (raw node answers vs the newest history line) |
| `tests/test_report_feewatch.py` | offline suite for `report_feewatch.py` (stub RPC server on loopback) |
| `baseline/run-baseline.sh` | the recorded, read-only 24h baseline run (`logs/07-baseline.log`) |
| `data/` | the two history files, the baseline report, the crosscheck results and the direct answers |

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
python3 -u feewatch/tests/test_report_feewatch.py          # report / crosscheck / --offline / direct, offline
shellcheck feewatch/*.sh feewatch/tests/*.sh feewatch/baseline/*.sh && ruff check feewatch
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

## Alert drill (no network load)

`drill/live-run.sh` proves every alert end to end without sending a single transaction. `drill/make_drill_fixtures.py`
builds the inputs from the real validator answers (`drill/fixtures/`). A refresher feeds them every 20 s to the
**installed** `pft-feewatch replay`, which writes drill-only textfiles (`container="drill-*"`; `replay` refuses any
other name):

| drill series | input | alert |
|---|---|---|
| `drill-queue` | `current_queue_size` 1800 of 2000 (fill 0.9) | `PFTTxQueueNearFull` |
| `drill-escalated` | open ledger 40 > 32 tx, `open_ledger_fee` 60 drops (6x) | `PFTFeeEscalated` |
| `drill-localload` | `load_factor_local` 3, net 1 | `PFTLocalLoadHigh` |
| `drill-failing` | `server_info` cut off mid-answer (up 0) | `PFTFeewatchStale` |
| `drill-stale` | healthy answers, collect timestamp 600 s old | `PFTFeewatchStale` |

Before any change the harness redirects every notifier on both hosts and the Alertmanager bridge to a throwaway ntfy
topic (sha256 of each env file recorded). It silences every other alert and opens a pft-maint window. It then waits
until exactly these five (alert, container) pairs fire, and none fire for the real nodes. Next it replays healthy
answers, waits for each pair to resolve, and removes the drill files. Finally it restores everything and reads it
back (env files sha256-identical, bridge mount source, window ended, silence expired), and reads every operator
topic.

`logs/06-live-drill.log`: 18 checks ok, 0 failed. The throwaway topic received 12 messages: `[MAINT]`
start/end, then `[FIRING]` and `[RESOLVED]` for all five pairs. Every operator topic received 0 messages. An
`ALERTS` query_range lists the five firing series with their first and last samples.

`logs/05-live-drill-aborted.log` is the first attempt, kept as evidence. All five pairs fired and were delivered
(2c-2f ok). Check 3a then read the files 5 s after the switch to healthy answers, before the refresher's next
20 s round, and failed. I saved the fix into the script while that run was still executing, and bash, which reads
scripts incrementally, stopped with a syntax error. Its EXIT trap restored everything (logged), and no drill
message reached an operator topic (checked separately). Run 06 is the fixed script (commit `e035ce9`), run
unmodified.

## 24-hour baseline (2026-11-01T00:21Z .. 2026-11-02T00:21Z)

Recorded by `baseline/run-baseline.sh 1793492460 1793578860` at commit `da24b1e6bbfb4d350cba8caf3827bb7dd3bbf868`,
log `logs/07-baseline.log` (19 checks ok, 0 failed). Read-only: no node was stopped and no notifier touched. Report:
`data/baseline-24h.md` / `.json`.

| | validator (`postfiatd`) | sentry (`postfiatd-sentry`) |
|---|---|---|
| samples in the window / coverage / gaps > 2 min | 1442 / 1.0000 / 0 | 1442 / 1.0000 / 0 |
| admin answers | 1.0000 | 1.0000 |
| queue size max (of `max_queue_size` 2000) | 0 | 0 |
| open ledger size p50 / p95 / max (expected 32) | 0 / 3 / 5 | 0 / 3 / 5 |
| minutes with escalation multiple > 1 | 0 | 0 |
| minutes with any load_factor source > 1 | 0 | 0 |
| base / median / minimum / open-ledger fee (drops) | 10 / 5000 / 10 / 10 | 10 / 5000 / 10 / 10 |

1442 samples in 1440 minutes: the first minute (00:21) holds three, the manual collects of the install run plus the
first timer run; every other minute holds one. The testnet was idle for fee purposes all day: no queue, no
escalation, every load factor 1. That is the baseline the four alerts compare against. The values come from the
history files `data/history-postfiatd.jsonl` (1444 lines, sha256
`ad3a89dcf727695d0cd90c49653d1b01d42c1d4b18aa45ace8fff9f7ced34110`) and `data/history-postfiatd-sentry.jsonl`
(1444 lines, sha256 `83fd1e4322d61681e06664018187f277b257bc3bc2e57d4d170aad1ed60aee27`); 2884 of the 2888 lines
fall in the window (the rest were written after 00:21Z, before the copy).

Crosschecks (all in `logs/07-baseline.log`):

- **Direct RPC, each node** (`direct`): `fee` + `server_info` fetched by hand from each node's admin RPC (not
  through pft-feewatch) and compared with the newest history line: 8/8 OK on both hosts (line age, base fee, queue
  limit, expected ledger size, reference and minimum level, load_factor, open-ledger index). Negative control
  (every recorded value altered): 0/8 OK on both. `server_info` carries host-identifying fields, so only
  `{result:{info:{load_factor}}}` is published (`data/direct-*-info-reduced.json`) and the check runs on that copy.
- **Public RPC** (`crosscheck`, `https://rpc.testnet.postfiat.org/`, seed 1, 30 samples: 15 per host): for each
  sampled line the closed ledger before it (index, close time 0..30 s before the sample) and the FeeSettings base
  fee at that ledger: 60/60 OK, 0 retries (`data/crosscheck-24h.json`). Negative control: 0/60 OK
  (`data/crosscheck-24h-negative.json`).
- **Offline** (`crosscheck --offline`): both recorded crosschecks re-drawn from (seed, committed history) and
  re-compared with no RPC: 0 differences each.

Queue size, open-ledger size and the load-factor sources are live values that no RPC returns for the past, so the
direct check at the end of the window is their crosscheck; the public RPC checks the ledger timeline and base fee
of 30 points spread over the whole day.

## Logs

`logs/` holds the raw runs, redacted (home directory -> `~`, user -> `<user>`, IPs -> `<redacted-ip>`, throwaway
ntfy topic -> `<throwaway-topic>`).
