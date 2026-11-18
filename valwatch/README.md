# pft-valwatch: UNL validator participation, validation delay and quorum margin

A node stays `full` as long as enough of its UNL keeps validating. When trusted validators go silent, fork or fall
behind one by one, nothing on the node changes until the last one that matters stops: then validation stalls for
everyone. `monitor/`, `statewatch/`, `slo/` and `divergence/` watch the node's own state; `vlwatch/` watches the
validator **list** (sites, expiry, sequence). None of them watches the validators **on** the list. `pft-valwatch`
records the node's `validations` and `ledger` streams and grades, per validated ledger and per UNL validator:

- **participation**: did the validator send a *full* validation for the hash that was validated?
- **delay**: how long after the first UNL validation of that ledger (on the same host) did it arrive?
- **quorum margin**: agreeing UNL validations minus `validation_quorum`.

Running it on the validator **and** the sentry tells a validator that is down for everyone (both hosts see it)
from a peering problem of one host (only that host sees it). `pft-valwatch compare` makes that explicit.

## What it reads and what it writes

| | |
|---|---|
| Network | the node's **public** WebSocket port (6005, wss with a self-signed certificate) on `127.0.0.1` when it is published there (validator), else the container's bridge IP (sentry: no host mapping). `valwatch.py` refuses any address that is not loopback or private, before connecting. The unit adds `IPAddressAllow=localhost` + RFC 1918 only. |
| Commands sent | `subscribe` (`validations`, `ledger`) and `server_info` (for `validation_quorum`, every 20 ledgers). Nothing else; the tests assert the stub node received only these two. |
| UNL | the node's own publisher-list cache `cache.<publisher>` in the volume mounted at `/var/lib/postfiatd/db` (path from `docker inspect`, read on the host). The list's 33-byte keys are converted to base58 `nH...` master keys, the same form the stream reports as `master_key`. No admin RPC, no `docker exec`, no third-party site. |
| Docker | `docker port` and `docker inspect` only (to resolve the endpoint and the volume). The node container is AppArmor/seccomp-confined; valwatch never enters it. |
| Writes | `DATA_DIR/<container>/valwatch-YYYYMMDDTHH.jsonl` (one compact record per line; validation `data`/`signature` blobs are not stored) and `pft_valwatch_<container>.prom` in the exporter's textfile dir. |
| Bounds | hourly files older than `RETAIN_HOURS` (24) are deleted, and the oldest beyond `MAX_DIR_BYTES` (512 MiB). Measured: ~14 MiB/h per host (25 UNL + 41 other validators on the testnet), so 24 h ~ 340 MiB. Readers open only the hour files that overlap their window (+2 h for the UNL/quorum carry-in) and drop validations of keys in no UNL while reading, so memory follows the window, not the retention. `report` and `textfile` read and sort one hour file at a time and keep only per-ledger state (hour files partition the receive time, so the order equals a global sort); measured on a synthetic 24 h directory (336 MB, `tests/gen_synthetic.py`): `report` 118 MiB peak RSS, `--detail` 176 MiB, 15-min `textfile` 23 MiB, with output byte-identical to the earlier load-everything version (`tests/memcmp.sh`, `logs/04-stream-equivalence.log`). Lines over 64 KiB and torn lines are counted as `bad_lines`, never fatal. |

Record types (`r` = receive time on this host, epoch ms):

```
{"t":"C","ev":"connect"|"disconnect"|"unl_error","why":"...","r":...}
{"t":"U","seq":30,"exp":891447293,"pub":"ED3F1E0DA736FCF9","keys":["nH...", ...],"r":...}   at start + hourly
{"t":"Q","q":17,"s":"full","r":...}                                                          every 20 ledgers
{"t":"L","i":8162757,"h":"<hash>","lt":848340670,"r":...}                                    ledgerClosed
{"t":"V","i":8162757,"h":"<hash>","k":"nH...","f":true,"r":...}                             validationReceived
```

## Grading

For every `L` record that has a UNL and a quorum before it, and that is at least `EDGE_MS` (5 s) away from both
ends of the window (validations for a ledger arrive just before and after its close, so edge ledgers would read
as missed):

- the UNL validators that sent `f=true` for the **same index and hash** agreed; wrong-hash and partial
  validations do not count;
- `margin = agreed - quorum`;
- each agreeing validator's delay = its `r` minus the earliest `r` of any agreeing UNL validation for that
  ledger. This is host-local, so clock offsets between hosts do not matter; it does include this host's
  network path, which is why `compare` uses a tolerance for delays.

Flags per validator: `low_participation` (< `MIN_PARTICIPATION`, 0.9), `silent` (0 agreed), `late`
(p95 > `WARN_DELAY_MS`, 3000). Percentiles are nearest-rank. Output is a pure function of the input files and the
options: the same directory gives byte-identical text and JSON (`report` never reads the clock).

## Commands and exit codes

```
sudo pft-valwatch run --container NAME        collector (pft-valwatch@NAME.service); RUN_DURATION for bounded runs
sudo pft-valwatch endpoint --container NAME   print host/port/UNL cache path that run would use
sudo pft-valwatch textfile --container NAME [--stdout]   grade the last WINDOW_SEC (900) -> pft_valwatch_NAME.prom
sudo pft-valwatch report --container NAME [--from EPOCH] [--to EPOCH] [--json | --detail]
pft-valwatch compare A.json B.json [--json] [--tolerance-part 0.02] [--tolerance-delay-ms 1000] [--tolerance-margin 1]
sudo pft-valwatch pull --container NAME       validator: copy the sentry's textfile (PULL_SSH)
pft-valwatch validate FILE NAME
```

Exit codes: 0 ok; 1 failed (textfile `up 0`, fetch failed, compare `DISAGREE`); 2 validation failed; 3 usage or
config error (including a refused host); 4 `report` found no graded ledger.

`compare` takes two `report --detail` files and grades only the ledger indexes **both** hosts graded:

- every common index must have the same validated hash on both hosts (`hash_mismatch` empty);
- quorum margin per ledger may differ by at most `--tolerance-margin` (1);
- per validator, participation over the common ledgers may differ by at most `--tolerance-part` (0.02) and the
  p50 delay by at most `--tolerance-delay-ms` (1000); a validator in one host's UNL only is `unl_differs`.

`AGREE` needs at least one common ledger and every check inside tolerance.

## Textfile metrics

`pft_valwatch_{up, collect_timestamp_seconds, window_seconds, last_record_age_seconds, ledgers, missing_ledgers,
reconnects, bad_lines, unl_size, unl_expiration_seconds, quorum, quorum_margin_min, quorum_margin_p50,
ledgers_below_margin, validators_truncated, validators_flagged}{node="NAME"}` and per UNL validator
`pft_valwatch_validator_participation_ratio` / `pft_valwatch_validator_delay_p95_ms{node, validator}`. At most 64
validators get per-validator series (`validators_truncated 1` beyond that); the file is refused over `MAX_BYTES`
(61440) and replaced by `up 0`. 25 validators ~ 7.3 KB.

## Alerts (`../alerts/valwatch.rules.yml`, six rules)

| alert | condition | for |
|---|---|---|
| PFTValwatchValidatorLow | a UNL validator's participation < 0.8 (node graded) | 15m |
| PFTValwatchValidatorLate | a UNL validator's p95 delay > 3000 ms | 15m |
| PFTValwatchQuorumMarginLow | worst margin in the window < 2 | 10m |
| PFTValwatchQuorumMarginCritical (critical) | median margin < 1 | 5m |
| PFTValwatchStale | `up 0`, textfile older than 5 min, or newest record older than 5 min | 10m |
| PFTValwatchReconnecting | more than 3 disconnects in the window | 15m |

Calibration (2026-11-18, both hosts): participation 0.975-1.0, p95 delay 9-1586 ms, margin 8 on every ledger
(UNL 25, quorum 17). Every rule is tested in `../alerts/valwatch.tests.yml` (generated by
`tests/gen_rule_tests.py`, exact labels and annotations, boundary values that must not fire, a recovery).

## Runbook

- **ValidatorLow / Late on one host only**: this host's peering. `sudo pft-peers` / `pft-peerwatch status`; the
  validator's validations reach this node through fewer hops on the other host.
- **ValidatorLow / Late on both hosts**: the validator itself (down, forked, overloaded). Nothing to fix locally;
  note it, and watch the margin.
- **QuorumMarginLow / Critical**: count the silent validators in `sudo pft-valwatch report --container NAME`.
  With 25 UNL and quorum 17, margin 1 means 7 are missing. Check `vlwatch` (a shrunk or stale list also lowers the
  margin) and the Post Fiat status channels.
- **Stale**: `systemctl status pft-valwatch@NAME`, `journalctl -u pft-valwatch@NAME --utc -n 20`,
  `sudo pft-valwatch endpoint --container NAME` (container IP changed? cache file missing?).
- **Reconnecting**: the node restarted or its public WebSocket is overloaded; `journalctl` shows the reason.

## Install

```bash
sudo valwatch/install.sh                                   # validator (container postfiatd)
sudo valwatch/install.sh --container postfiatd-sentry      # on the sentry
sudo valwatch/install.sh --pull postfiatd-sentry           # on the validator, with PULL_SSH in /etc/pft-valwatch.env
```

Fleet installs use `pft-fleet sync --addon valwatch` (rows in `../fleet/manifest.tsv`). Afterwards accept the new
files with `pft-integrity accept`, the new timers with `pft-schedaudit accept` + `collect`, and check
`pft-jobwatch inventory`.

## Tests

```bash
cd valwatch && TMPDIR=$HOME/.cache python3 -m pytest -q tests     # unit + shell + stub-node tests
promtool test rules ../alerts/valwatch.tests.yml                    # from ../alerts
shellcheck pft-valwatch.sh install.sh && ruff check . && ruff format --check .
```

Fixtures (`tests/fixtures/`) are real 240 s captures taken on the validator and the sentry at the same time
(2026-11-18T18:24:57Z) and the validator's publisher-list cache (the public, signed list). They contain only
public ledger data: validator keys, ledger hashes and indexes, and receive times.

## Logs

- `logs/02-memory.log`: peak RSS of the first (load-everything) reader on the synthetic 24 h directory.
- `logs/03-stream-equivalence.log`: first old-vs-new run. All 12 outputs identical, but the generator then wrote a
  UNL record only in its first copy, so the two `--from` windows and the textfile graded no ledger on either
  version (rc 4 / 1). That was a harness defect: the generator now repeats the UNL record hourly, as the collector does.
- `logs/04-stream-equivalence.log`: re-run with the fixed generator: all 12 outputs byte-identical, windowed
  cases graded (rc 0), PASS.
- `logs/05-mutants-dev.log`: first pass of `tests/mutate.py` (64 mutants): 45 caught, 19 survived; each survivor
  got a named test (commit message of be8e0f6).
- `logs/06-mutants.log`: 63/64; P18 (a `q=0` server_info sample replacing the known quorum) survived because its
  test compared only summary margins; the test now compares every ledger's quorum.
- `logs/07-mutants.log`: 64/64 caught, 0 survived/not applied/broken; baseline, hang and orphan controls PASS.
- `logs/08-install-preflight.log`: `PREFLIGHT_ONLY=1 bash valwatch/drill/install-run.sh` at ad849f2: all 11 preflight checks ok,
  nothing changed.
- `logs/09-install.log`: recorded two-host install through pft-fleet in a pft-maint window (throwaway [MAINT] topic):
  0 of 52 checks failed; collectors active from 20:24Z on both hosts, integrity/schedaudit/aptrust/rulecheck clean,
  0 AppArmor/seccomp denials, operator topics 0 messages.
