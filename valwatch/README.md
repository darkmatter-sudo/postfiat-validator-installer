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

## Alerts (`../alerts/valwatch.rules.yml`, eight rules)

| alert | condition | for | pages? |
|---|---|---|---|
| PFTValwatchValidatorLow | a UNL validator's participation < 0.8 (node graded) | 15m | no: `notify="digest"` |
| PFTValwatchValidatorLate | a UNL validator's p95 delay > 3000 ms | 15m | no: `notify="digest"` |
| PFTValwatchHostsDisagree | participation < 0.8 at one node, >= 0.95 at the other (both graded) | 15m | yes |
| PFTValwatchHostsDisagreeLate | p95 delay > 3000 ms at one node, <= 2000 ms at the other (both graded) | 15m | yes |
| PFTValwatchQuorumMarginLow | worst margin in the window < 2 | 10m | yes |
| PFTValwatchQuorumMarginCritical (critical) | median margin < 1 | 5m | yes |
| PFTValwatchStale | `up 0`, textfile older than 5 min, or newest record older than 5 min | 10m | yes |
| PFTValwatchReconnecting | more than 3 disconnects in the window | 15m | yes |

Paging policy (2026-11-19): another validator that is missing or late is the network's problem, so ValidatorLow /
Late carry `notify="digest"`, which `../alerts/alertmanager.yml` routes to the `digest` receiver (no integrations:
the alerts stay visible in Prometheus and Alertmanager, nothing reaches the ntfy bridge). What pages: our two nodes
seeing different results for the same validator (HostsDisagree*, a local peering fault), quorum at risk
(QuorumMargin*) and a blind or flapping collector. Our own validator is covered by PFTValidatorNotProposing
(`../alerts/postfiat.rules.yml`) once a validator token is configured; until then it is not on the UNL.
`sudo pft-valwatch digest [--dry-run]` sends at most one low ntfy summary a UTC day of the minutes each
digest-only alert fired per validator and node (nothing if none fired). `sudo valwatch/install.sh --digest` (validator
only) installs `systemd/pft-valwatch-digest.service/.timer`: daily at 07:05 UTC, `Persistent=false` so installing or
rebooting sends nothing, sandboxed (no capabilities, read-only system, writes only the day stamp in
`/var/lib/pft-valwatch`). `drill/digest-install-run.sh` is the recorded install with a send drill through the real
unit to a throwaway topic (`logs/19-digest-install.log`).
`drill/route-drill.sh` proves the routing end to end on a throwaway Prometheus + Alertmanager + bridge with a random
throwaway ntfy topic (`logs/13-route-drill.log`).

Calibration (2026-11-18, both hosts): participation 0.975-1.0, p95 delay 9-1586 ms, margin 8 on every ledger
(UNL 25, quorum 17). Every rule is tested in `../alerts/valwatch.tests.yml` (generated by
`tests/gen_rule_tests.py`, exact labels and annotations, boundary values that must not fire, a recovery).

## Two-host collection (2026-11-18)

Collectors installed through pft-fleet (`logs/09-install.log`) ran on the validator from 20:24:48Z and on the sentry
from 20:24:23Z (NRestarts 0). `drill/collect-run.sh` (`logs/11-collect.log`) reported the window
2026-11-18T20:26:00Z .. 22:30:00Z (124 min) on each host with the installed `pft-valwatch report --from --to`,
copied the hour files the window reads byte-exactly into `data/ROLE/` (gzip -n) and rebuilt every report offline.

| | validator | sentry |
|---|---|---|
| ledgers graded (missing) | 2453 (0), 8165157..8167609 | 2453 (0), 8165157..8167609 |
| UNL / quorum | 25 (seq 30) / 17 | 25 (seq 30) / 17 |
| quorum margin min / p50, ledgers below 2 | 8 / 8, 0 | 8 / 8, 0 |
| UNL validators flagged | 0 of 25 | 0 of 25 |
| max p50 / p95 delay | 740 / 1456 ms | 760 / 1486 ms |
| reconnects, bad lines | 0, 0 | 0, 0 |

`pft-valwatch compare reports/validator.detail.json reports/sentry.detail.json`: **AGREE**: 2453 common ledgers,
0 hash mismatches, margin equal on 2453/2453, participation diff 0 for all 25 validators, largest p50 delay
difference 25 ms (tolerance 1000 ms).

Reproduce offline (python3 + gzip only, no node): `bash valwatch/drill/offline-rebuild.sh` unpacks `data/`,
re-runs `report` with `data/window.env` and `cmp`s the six outputs with `reports/` (exit 0 = byte-identical).

## Runbook

- **HostsDisagree / HostsDisagreeLate** (paged): this host's peering. `sudo pft-peers` / `pft-peerwatch status`;
  the validator's validations reach the other node fine.
- **ValidatorLow / Late** (not paged, visible in Alertmanager): on both hosts it is the validator itself (down,
  forked, overloaded). Nothing to fix locally; watch the margin (QuorumMargin* pages if it gets thin).
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
sudo valwatch/install.sh --digest                          # on the validator: daily other-validators digest timer
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
- `logs/10-collect.log`: first window-close run, stopped at step 3: the snapshot check hashed the host file through an
  unprivileged redirect (root-only data dir: empty hash) and compared the whole file while the current hour was still
  being written. Found -> fixed in 12bcb60 (hash the host file's first N bytes as root, N = length of the copy);
  one local-timezone token in it is redacted as `<redacted-tz>`.
- `logs/11-collect.log`: `bash valwatch/drill/collect-run.sh` at 12bcb60: 0 checks failed. Live reports on both hosts,
  6 hour-file copies equal to the host files, offline rebuild 0 differences, compare AGREE, promtool SUCCESS.
- `logs/12-fresh-clone.log`: `bash valwatch/drill/fresh-clone.sh 161f14c` on an anonymous public clone: 0 checks
  failed. sha256 of script, helper and 3 units = installed on both hosts (10/10), shellcheck, ruff (both cwds),
  87 tests passed, promtool SUCCESS, offline rebuild 0 differences, compare byte-identical, files under mutation test
  unchanged since the 64/64 run (log 07), 12 pinned raw URLs + commit URL HTTP 200 with content = clone.
- `logs/13-route-drill.log`: `drill/route-drill.sh` at b8c03b1 (paging rule of 2026-11-19): PASS, 21/21 checks.
  Throwaway stack, external validator at 0 % on both nodes + one validator at 50 % on one node only: Prometheus fired
  ValidatorLow x3 (`notify=digest`) and HostsDisagree x1; Alertmanager put the 3 in `digest` and the 1 in `bridge`;
  the bridge forwarded only `[FIRING] PFTValwatchHostsDisagree` (1 message on the throwaway topic); both operator
  topics had no drill message. Two earlier attempts stopped at harness defects before any rule could fire, nothing
  outside the throwaway stack touched: the uid-65534 Prometheus could not write a root-owned tmpfs (fixed in
  67b9264), and Prometheus 3 refused the http.server `application/octet-stream` exposition (fixed in b8c03b1).
- `logs/14-rule-controls.log`: promtool on the new tests (baseline PASS) and 5 mutated rules (drop `notify`, other-node
  floor 0.95 -> 0.9, no other-node clause, late ceiling 2000 -> 2001, ignore the other node's `up`): all 5 caught;
  `amtool config routes test`: ValidatorLow/Late -> digest, HostsDisagree*/QuorumMarginCritical -> bridge.
- `logs/15-live-backtest.log`: the new HostsDisagree expressions over the live 24 h (1 m steps): 0 minutes on both,
  while the digest-only ValidatorLow/Late conditions held 62-83 min for the two external validators of 2026-11-19.
- `logs/16-live-reload.log`: live Prometheus reload (`docker kill -s HUP`): reloadConfigSuccess true, 149 rules ok,
  ValidatorLow/Late labelled `notify=digest`, HostsDisagree* inactive; 15 min later the live external-validator
  alerts fired into the `digest` receiver and the live bridge logged nothing.
- `logs/17-rule-mutants.log`: `tests/mutate.py --only R01..R19` after the paging change: R01-R03 re-anchored to
  their own `expr:` lines (the new HostsDisagree* expressions repeat the old text) and R13-R19 added (digest label
  dropped on Low / Late, other-node floor/ceiling, other-node clause, blind other node, late threshold): 19 caught,
  0 survived / not applied / broken; baseline, hang and orphan controls PASS.
- `logs/18-digest-mutants.log`: `tests/mutate.py --only D01..D08` on `pft-valwatch digest` (stamp, nothing fired,
  dry run, priority, stamp write, Prometheus failure, empty topic, query scope): 8 caught, controls PASS.
- `logs/19-digest-install.log`: `drill/digest-install-run.sh` @452856f (pft-maint window on a throwaway topic): fleet
  sync fleet/valwatch/aptrust, `install.sh --digest` (dry run, timer enabled for 07:05 UTC, service not run), send drill
  through the real sandboxed unit via a /run drop-in: exactly 1 low message on a throwaway topic, 2nd start "already
  sent"; schedaudit/integrity PASS both hosts, fleet CURRENT, operator topics 0 messages. **1 FAIL = runner bug**: the
  jobwatch check grepped `digest`, which also matched the existing `pft-authwatch-digest.timer` (6 lines, expected 3;
  every value printed is 0). Fixed in the runner (pattern `valwatch-digest`).
- `logs/20-digest-postcheck.log`: `drill/digest-postcheck.sh` (read-only) with the fixed pattern: PASS 5/0 (jobwatch
  86400 s, 0 failed/missed/disabled; timer next 07:05 UTC tomorrow, no drop-in/stamp left; schedaudit, integrity, fleet).

