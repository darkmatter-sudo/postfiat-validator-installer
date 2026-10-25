# pft-divergence: consensus-divergence monitor

The `monitor/`, `alerts/`, `watchdog/` and `slo/` add-ons catch a node that is down, lagging or not `full`. They
cannot see a node that is up, `full`, fresh and well peered while it validates a different ledger chain than the
network (a forked or stuck-on-the-wrong-branch node). `pft-divergence` checks for that case: it asks every source
for the same validated ledger index and compares the hashes.

It is read-only. It only sends `server_info` and `ledger` requests: through `docker exec <container> curl` on the
admin RPC inside the container, over `ssh` to a second host, or over HTTPS to the public RPC. It does not restart
or reconfigure postfiatd. It writes one Prometheus textfile and one small state file.

## How a check works

1. `server_info` on every source gives its newest validated ledger (`validated_ledger.seq`) and `complete_ledgers`.
2. **tip** = the lowest of those seqs, which is the newest index every source should hold. **deep** = tip - `DEPTH`
   (default 200).
3. At tip and at deep, `ledger` on every source gives `ledger_hash`, `account_hash` and `transaction_hash`. An
   answer only counts if `status=success`, `validated=true`, the returned `ledger_index` is the requested one and
   all three hashes are 64 hex characters. Anything else is an error.
4. Every failed request is retried after 2, 5 and 10 s (`BACKOFF`), and every retry is printed on stderr.
5. If the hash sets at an index differ, the whole index is queried again `CONFIRM` (2) times, spaced by the
   backoff. The check only reports a mismatch that is still there after the last re-query.

Two indexes are compared because a node that forked a while ago and one that is forking right now look different:
the deep index catches an old split even when the tip index happens to be inside a transient lag.

## States

| state | per source | metric value |
|---|---|---|
| `AGREE` | hashes at tip and deep match the other sources | `0` |
| `DIVERGED` | a hash differs from the majority, and still differs after `CONFIRM` re-queries. With no majority (two sources, or three different answers) every disagreeing source is `DIVERGED`. | `1` |
| `UNKNOWN` | no usable answer after all retries, the index is outside the source's `complete_ledgers`, the ledger is not validated, the wrong index came back, or there was nothing to compare against (fewer than two sources answered) | `2` |

Overall state is the worst of the per-source states: `DIVERGED` > `UNKNOWN` > `AGREE`. Exit codes: `0` AGREE, `1`
UNKNOWN, `2` DIVERGED, `3` usage error. The reason in brackets names the index (tip/deep), the field
(`ledger_hash`, `account_hash`, `transaction_hash`) and the first 16 hex characters on each side. When both
indexes diverge it names the last one compared (deep).

```
2026-10-25T13:20:35Z AGREE tip=7471503 deep=7471303 retries=0 validator=AGREE sentry=AGREE public=AGREE hash=7979580875CA9AA6
2026-10-25T13:34:15Z DIVERGED tip=7471771 deep=7471571 retries=0 validator=AGREE sentry=AGREE stub=DIVERGED(deep 7471571 ledger_hash 94AD72E7D0D750CE != majority 839C61D6CFC64FBD)
```

`--json` prints one object with `state`, `tip`, `deep`, `last_agree_ledger`, `retries` and per-source `state`,
`reason`, `validated_seq`, `tip_ledger_hash`, `deep_ledger_hash`.

## Install

Needs `jq` and `curl`. The textfile is read by [`../exporter`](../exporter/) (this add-on adds a textfile
collector to it, see below) and alerted on by [`../alerts`](../alerts/).

```bash
# validator host: validator + sentry (over ssh, as the user whose ~/.ssh/config has the "relay" alias) + public RPC
sudo bash divergence/install.sh \
  --sources "validator=docker:postfiatd sentry=ssh:relay:postfiatd-sentry public=http:https://rpc.testnet.postfiat.org/" \
  --ssh-runas "$USER"
# sentry host: it has no route to the validator's admin RPC, so it runs a two-way check
sudo bash divergence/install.sh --sources "sentry=docker:postfiatd-sentry public=http:https://rpc.testnet.postfiat.org/" --no-exporter

sudo pft-integrity accept --reason "pft-divergence installed"     # if ../integrity is installed
sudo docker kill -s HUP pft-prometheus                            # load alerts/divergence.rules.yml (no restart)
```

`install.sh` validates the source list (`pft-divergence --check-config`), installs `/usr/local/bin/pft-divergence`,
writes `/etc/pft-divergence/divergence.env` once from [`divergence.env.example`](divergence.env.example) (an
existing file is kept), installs the textfile-capable `pft_exporter.py` if the exporter is installed and differs
(and restarts `pft-exporter`, not the node), runs one check in the foreground, enables `pft-divergence.timer`
(every 60 s) and checks that the exporter shows `pft_divergence_*`. `--uninstall` removes the script, units, state
and `.prom` file and keeps `/etc/pft-divergence`.

Source kinds (`NAME=KIND:TARGET`, two or more): `docker:CONTAINER`, `ssh:HOST:CONTAINER` (runs
`ssh -o BatchMode=yes HOST sudo -n docker exec CONTAINER curl ...`), `http:URL`. Names, hosts and containers are
checked against `[A-Za-z0-9._-]`, so nothing from the config reaches a shell unquoted.

Manual run: `sudo pft-divergence` (or `--json`). Every option in the env file has a flag (`--sources`, `--depth`,
`--backoff`, `--confirm`, `--timeout`, `--ssh-runas`, `--textfile`/`--no-textfile`, `--state`/`--no-state`).

## Metrics and alerts

Written atomically (temp file + `mv`, mode 0644) to `/var/lib/pft-exporter/textfile/pft_divergence.prom`:

| metric | meaning |
|---|---|
| `pft_divergence_state{source}` | per-source state, `0` AGREE, `1` DIVERGED, `2` UNKNOWN |
| `pft_divergence_overall_state` | worst state over all sources |
| `pft_divergence_last_agree_ledger` | newest tip at which all sources agreed (kept in the state file across runs) |
| `pft_divergence_checked_ledger{depth="tip"/"deep"}` | the indexes compared |
| `pft_divergence_retries` | RPC retries the last check needed |
| `pft_divergence_check_timestamp` | Unix time of the last completed check |

The exporter (`../exporter/pft_exporter.py`) now reads every `*.prom` file in `PFT_TEXTFILE_DIR` (default
`/var/lib/pft-exporter/textfile`). Dotfiles (temp files) are ignored. A file is skipped whole if it is a symlink,
is over 64 KiB, or has any line that is not a comment or a plain sample. Skipped files are counted in
`pft_textfile_errors`, and `pft_textfile_mtime_seconds{file}` is exported per file.

[`../alerts/divergence.rules.yml`](../alerts/divergence.rules.yml):

| alert | expr | for | severity |
|---|---|---|---|
| `PFTLedgerDiverged` | `pft_divergence_state == 1` (per source) | 2m | critical |
| `PFTDivergenceCheckStale` | `time() - pft_divergence_check_timestamp > 600` | 5m | warning |

`UNKNOWN` never fires `PFTLedgerDiverged`. A dead timer leaves the last value in the textfile, so the stale alert
makes sure a stopped monitor does not read as a permanent AGREE. promtool tests are in
[`../alerts/divergence.tests.yml`](../alerts/divergence.tests.yml) (1m samples). They cover: fires after 2m only
for the diverged source, quiet on a 1-check blip, quiet on UNKNOWN for 30m, resolves, stale fires, stale quiet.

## False-positive handling

- A public-RPC hiccup (`lgrNotFound`, `internal`, timeouts, a half answer) is retried with backoff. If it does not
  recover, the source is `UNKNOWN`, never `DIVERGED`. The public RPC really does this sometimes (see the
  rewardflow notes in this repo's history).
- A wrong answer only counts if it is still there after 2 re-queries of the same index, so a one-off bad answer
  resolves itself (test case 6).
- The compared index is the lowest validated seq of all sources, so a source that is a few ledgers behind is not
  asked for a ledger it does not have yet. An index outside a source's `complete_ledgers` is `UNKNOWN` for that
  source, and that ledger is not requested from it at all (test case 5).
- Only `validated=true` ledgers count. An answer for a different index is an error (test case 10).
- The alert needs 2 minutes (2-3 consecutive checks) of confirmed `DIVERGED`.

## Limits

- With two sources a mismatch cannot say which side is wrong: both are `DIVERGED`. Use three sources where you can.
  The sentry host runs a two-way check (sentry vs public), because it has no route to the validator's admin RPC.
- The public RPC is one more opinion, not ground truth. If it is the one that forked, it is the minority and is
  reported as `DIVERGED`. That is correct for this check, but it is not a problem with your own nodes.
- Node retention bounds `DEPTH`: the testnet-light image keeps about 512-1024 ledgers (`online_delete=512`), so keep
  `DEPTH` well under 512. A deeper index is `UNKNOWN`, not checked.
- It catches a node on another chain. It does not catch a node that agrees but is slow (that is
  `PFTValidatedLedgerOld`/`Stalled`), or a validator whose validations are ignored by the network (that is
  `../validators`).
- Worst case, one run is about 9 requests x (4 attempts + backoff). The unit allows 170 s. If a check is killed,
  no textfile is written and `PFTDivergenceCheckStale` fires after 10 + 5 minutes.
- Only the validator host has Prometheus here. The sentry host writes the textfile, but nothing scrapes it.

## Tests

`bash divergence/check.sh` (with `DOCKER="sudo docker"` if needed) runs, offline:

- shellcheck on every script
- [`tests/run-tests.sh`](tests/run-tests.sh): the fake-RPC suite. Stub `curl`, `docker`, `ssh` and `sudo` on PATH
  answer from per-source fixture files, and the n-th call can get a different answer. The docker/ssh stubs run the
  real command line, so quoting is exercised. Cases: 1 AGREE, 2 confirmed DIVERGED, 3 transient public error that
  recovers (AGREE, `retries=1`), 4 persistent error (UNKNOWN), 5 index outside `complete_ledgers`, 6 transient
  wrong hash (AGREE after re-query), 7 two-source no-majority, 8 public timeout, 9 only one source answers,
  10 not-validated / wrong-index answers, 11 `--json`, 12 usage errors. Then two mutants must fail the suite:
  no re-query before DIVERGED (caught by case 6) and no RPC retries (caught by case 3).
- `python3 -m unittest`: exporter textfile collector, drill stub and drill verdict (positive and negative)
- ruff, promtool check + test rules, and a rule mutant (`PFTLedgerDiverged` without `for: 2m`) that must fail the
  blip test

The suite found a real bug before the first live run: the retry counter was incremented inside `$(...)`, so
`retries=` was always 0. It now counts retries in a temp file.

## Live alert drill

`sudo bash divergence/drill.sh` (validator host, no node restart) points `pft-alert-bridge` at a throwaway ntfy
topic, stops the timer, and starts [`drill_stub.py`](drill_stub.py). That is a loopback proxy to the public RPC
that rewrites every `ledger_hash` while a flag file exists. Checks run every 30 s with sources validator + sentry
+ stub until `PFTLedgerDiverged{source="stub"}` is firing and `[FIRING]` is on the topic. Then the stub passes
answers through again, and checks run until the alert is gone and `[RESOLVED]` is on the topic. Everything is
restored on any exit (trap): the bridge's mount source is compared with the real env file, the timer is
restarted, and a silence scoped to `source="stub"` is added if the alert is somehow still active.
[`drill_verdict.py`](drill_verdict.py) then checks the samples and the topic read-back.

## Logs

[`../logs/divergence/`](../logs/divergence/): offline checks, live trials, install on both hosts, rules reload,
the 60-check run log per host and the drill. Public IPs and the topic are redacted, and the operator user is shown
as `<operator-user>`.

60-check runs (2026-10-25 13:29-14:28Z, 60 s cadence, the installed binary, `live-run.sh`):
[`9-live60-validator.log`](../logs/divergence/9-live60-validator.log) (validator + sentry + public, 3-way) 60/60
AGREE, and [`9-live60-sentry.log`](../logs/divergence/9-live60-sentry.log) (sentry + public, 2-way) 60/60 AGREE.
Both runs had 0 UNKNOWN, 0 DIVERGED and 0 retries.
