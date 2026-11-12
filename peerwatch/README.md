# Continuous peer-quality monitoring (`pft-peerwatch`)

`../peers/pft-peers.py` is a one-shot peer diagnosis, and the exporter and alert rules only count peers. A node can
keep a healthy peer *count* while its peer set keeps turning over, its latency climbs, its outbound peers sit in one
provider's network, or it loses the one link that matters (the validator's sentry). `pft-peerwatch` samples the node's
`peers` and `server_info` answers every minute, on the validator and on the sentry, and grades:

| Check | What is measured | WARN | FAIL |
|-------|------------------|------|------|
| `count` | connected peers | `< MIN_PEERS_WARN` (5) | `< MIN_PEERS_FAIL` (1), i.e. 0 peers |
| `churn` | join + leave events **by node public key** in the last `CHURN_WINDOW_MIN` (60) min; peers that left twice or more | `> CHURN_WARN` (20), or `>= FLAP_WARN` (3) flapping peers | `> CHURN_FAIL` (60) |
| `latency` | nearest-rank p50 / p95 / max of postfiatd's per-peer `latency` | p95 `> LAT_P95_WARN_MS` (1000) | p95 `> LAT_P95_FAIL_MS` (3000) |
| `versions` | peers on the same / an older / a newer build than this node, unknown strings | older share `> OUTDATED_WARN_PCT` (25 %) | `> OUTDATED_FAIL_PCT` (75 %) |
| `direction` | inbound / outbound split | outbound `< MIN_OUTBOUND_WARN` (3) | outbound `< MIN_OUTBOUND_FAIL` (1) |
| `diversity` | distinct IPv4 /16 and /24 (IPv6 /32, /48) among routable **outbound** peers, share of the largest /16 | `< PREFIX16_MIN_WARN` (3) distinct /16, or largest /16 `> PREFIX16_MAX_SHARE_WARN_PCT` (50 %) | – |
| `ledgers` | share of peers whose newest complete ledger is within `MAX_LEDGER_LAG` (8) of our validated ledger (either side); peers on another `network_id` | agree `< AGREE_WARN_PCT` (70 %), or own node has no validated ledger | agree `< AGREE_FAIL_PCT` (30 %), or any peer on another network |
| `fixed` | every fixed/cluster link connected, matched by node public key | – | a link is down |

Defaults in brackets; all in `/etc/pft-peerwatch.env` (`pft-peerwatch.env.example`). Grades are strict: a value
exactly at a threshold is still PASS. Only outbound peers count for diversity: a node behind Docker's userland proxy
sees every inbound peer as the bridge gateway (the sentry here: 9 of 20 peers are `172.17.0.1`), and inbound peers
are chosen by others anyway. Churn is keyed by public key, so a peer that reconnects from a new port is not churn and a
new key on an old address is. The first sample, and any sample more than `GAP_SEC` (180 s) after the previous one
(collector stopped, node restarted), re-baselines churn instead of counting every peer as a join.

Fixed links default to the node's own cluster members (the `peers` answer's `cluster` object, with each member's
`tag`, see `../cluster`), so on this pair the validator watches `sentry` and the sentry watches `validator` without any
configuration. `FIXED_LINKS="TAG=NODE_PUBKEY ..."` overrides that.

## What it reads and what it writes

| Item | Detail |
|------|--------|
| access path | `docker exec <container> curl -s --max-time 8 -H 'Content-Type: application/json' -d '{"method":"peers"...}' http://127.0.0.1:5005/` and the same for `server_info`: the admin port on the container's own loopback, exactly the shape `../statewatch` already uses under the node's AppArmor/seccomp profiles (curl is the exec'd binary, no shell inside the container). Two read-only methods, nothing else. |
| textfile | `/var/lib/pft-exporter/textfile/pft_peerwatch_<container>.prom`, atomic rename, about 4 KB |
| state | `/var/lib/pft-peerwatch/state-<container>.json` (0700 dir): last public-key set, churn events of the window (bounded by the window), last check results |
| history | `/var/lib/pft-peerwatch/history-<container>.jsonl`: one summary line per sample, trimmed to `HISTORY_MAX` (1440 = 24 h) lines |

Metrics never carry an address or a public key: they are counts, ratios and the configured link tag. Addresses and keys
stay in the root-only state file. On any failure (container down, RPC error, malformed answer) the textfile holds only
`pft_peerwatch_up 0` and the collect timestamp, never stale values, and the state is left as it was.

Metrics (first label `container`): `up`, `collect_timestamp_seconds`, `peers{direction}`, `churn_events{kind}`,
`churn_flapping_peers`, `churn_rebaselined`, `latency_ms{quantile="0.5|0.95|1"}`, `version_peers{relation}`,
`outbound_prefixes{len="16|24"}`, `outbound_prefix16_max_share`, `ledger_agree_ratio`, `ledger_lag_max`,
`network_mismatch_peers`, `fixed_link_up{link}`, `local_full`, `check_status{check}` (0 PASS, 1 WARN, 2 FAIL), `status`.

## Commands and exit codes

```bash
sudo pft-peerwatch collect [--container NAME] [--stdout]   # one sample (the timer runs this every minute at :25)
sudo pft-peerwatch status [--container NAME] [--json]      # the checks of the last sample
sudo pft-peerwatch pull --container postfiatd-sentry       # validator: copy the sentry's textfile (timer at :55)
pft-peerwatch validate FILE NAME                           # all-or-nothing check of a textfile (used by pull)
```

| Command | 0 | 1 | 2 | 3 | 4 |
|---------|---|---|---|---|---|
| `collect`, `pull` | ok | collection / fetch failed | pulled file failed validation | usage / config error | – |
| `status` | PASS | WARN | FAIL | usage / config error | no state yet, or the last sample is older than `STALE_SEC` (300 s) |

## Alerts (`../alerts/peerwatch.rules.yml`, three rules)

| Alert | Expression | for | Severity |
|-------|------------|-----|----------|
| `PFTPeerFixedLinkDown` | `pft_peerwatch_fixed_link_up == 0` | 3m | critical |
| `PFTPeerQualityDegraded` | `pft_peerwatch_check_status{check!="fixed"} == 2` (one alert per failing check) | 15m | warning |
| `PFTPeerwatchStale` | `pft_peerwatch_up == 0 or (time() - pft_peerwatch_collect_timestamp_seconds > 300)` | 5m | warning |

WARN grades never page; they are for `pft-peerwatch status`. The sentry runs no Prometheus or Alertmanager: its
textfile is pulled to the validator every minute (`pft-peerwatch-pull@postfiatd-sentry.timer`, the same ssh path as
`../statewatch`), and every `container="postfiatd-sentry"` alert is evaluated there.

## Runbook

- **`PFTPeerFixedLinkDown`**: `sudo pft-peerwatch status --container <c>` names the link. Check the other node is up
  (`sudo postfiat-health`), then `sudo pft-cluster audit` (cluster key, `[ips_fixed]`), the firewall (`sudo iptables -S
  DOCKER-USER`: the installer's 2559 rate limit, pft-egress) and the peer's port 2559. postfiatd retries `[ips_fixed]`
  peers by itself; the link normally returns within a minute once the path is open.
- **`PFTPeerQualityDegraded check=churn`**: peers keep dropping. Look at `history-<c>.jsonl` (`joins`/`leaves` per
  minute) and the node's resource alerts; a node that is overloaded or behind drops peers first.
- **`check=latency`**: compare with the other host; one host high = local network or CPU, both high = network-wide.
  If p50 is normal and only p95/max is high, it is one or two slow remote peers (with few peers the nearest-rank p95 is
  the slowest one); it usually clears on its own, as on 2026-11-12 (results below).
- **`check=versions`**: most peers run an older build: check the official upgrade notes before assuming your build is
  the odd one (`../upgradewatch`).
- **`check=direction` / `count`**: no outbound peers usually means the node cannot reach out (egress policy, DNS,
  `[ips]`); check `../egress` and `sudo ./peers/pft-peers.py --read-config`.
- **`check=ledgers`**: peers disagree with our validated ledger: if *we* are behind, follow the divergence runbook
  (`../divergence`); a peer on another `network_id` points at a wrong `[network_id]` somewhere.
- **`PFTPeerwatchStale`**: `sudo pft-peerwatch collect --container <c> --stdout` shows the error; for the sentry also
  `systemctl status pft-peerwatch-pull@postfiatd-sentry` on the validator.

## Install

```bash
sudo ./peerwatch/install.sh                                # validator (container postfiatd)
sudo ./peerwatch/install.sh --container postfiatd-sentry   # sentry host
sudo ./peerwatch/install.sh --pull postfiatd-sentry        # validator: PULL_SSH in /etc/pft-peerwatch.env first
```

The installer copies the script, parser and units, creates `/etc/pft-peerwatch.env` from the example if absent, runs
one collection through the sandboxed unit (it must report `up 1`) and only then enables the timer. It never runs an
ad-hoc command inside the confined node container.

## Tests

| File | What | Run |
|------|------|-----|
| `tests/test_peerwatch.py` | parser and shell: real two-host fixtures, churn/gap/window/flapping, every grade at and around its threshold, bad input (state untouched), status exit codes, bounded history, stub-docker collect, validate, pull | `TEST_TMPDIR=~/.cache python3 -I peerwatch/tests/test_peerwatch.py` |
| `tests/fixtures/` | real `peers` / `server_info` answers of both hosts (2026-11-11), redacted by `tests/redact_capture.py` (addresses mapped into 10.x keeping every /16 and /24 grouping, keys replaced, server_info cut to the fields read) | – |
| `../alerts/peerwatch.tests.yml` | promtool: fire, no-fire, recovery for every rule, exact annotations; generated by `tests/gen_rule_tests.py` | `promtool test rules peerwatch.tests.yml` |
| `tests/mutate.py` | mutation run over parser, shell and rules with baseline, timeout and orphan controls | `TEST_TMPDIR=~/.cache python3 -u peerwatch/tests/mutate.py` |

`/tmp` is mounted `noexec` on these hosts, so test scratch lives under `TEST_TMPDIR` (default `~/.cache`).

## Evidence (logs/)

Raw logs, redacted (public addresses `<redacted-ip>`, host names `<host>`, ntfy topics, user name, home path).
Logs 01-05 were development captures and stay private (they hold unredacted peer addresses).

| Log | What | Result |
|-----|------|--------|
| `06-install-run.log` | two-host install through pft-fleet in a pft-maint window (`drill/install-run.sh` at 20c65d1) | 42 ok / 2 FAIL: FOUND pft-aptrust installs a copy of `fleet/manifest.tsv` as its add-on allowlist, so the new rows left aptrust BEHIND and its audit WARNed the new binary; the run-u check also counted login mounts |
| `07-aptrust-fixup.log` | FIXED: `drill/aptrust-fixup.sh` syncs aptrust's manifest copy in a window (d0d5cf5) | 17 ok / 1 FAIL: the check compared a per-host add-on file count that differs by role (44 vs 36); a25ccb3 asserts the audit verdict instead |
| `08-verify-installed.log` | VERIFIED (read-only, a25ccb3): aptrust PASS 0 warn both hosts, manifest copy has peerwatch, fleet skew CURRENT=73 BEHIND=0, status PASS both, integrity PASS both | PASS |
| `09-link-drill-preflight.log` | `PREFLIGHT_ONLY=1 drill/link-drill.sh` (changes nothing) | 0 failed |
| `10-link-drill.log` | fixed-link drill at 80880d7 (below) | 43 ok / 0 FAIL, PASS |
| `11-offline-suite-lint-promtool.log` | shellcheck, ruff, 49 unit tests, `promtool test rules peerwatch.tests.yml` | all exit 0 |
| `12-mutants.log` | `tests/mutate.py --jobs 2` at 80880d7: baseline + timeout + orphan controls | 75 caught, 0 survived, 0 not applied, 0 broken; harness exit 0 |
| `13-24h-start.log` | start of the 24-hour two-host run: pft-maint lock `peerwatch-24h`, timers, history line counts | lock held, timers active both hosts |
| `14-mutants.log` | recorded mutation run at 38be87e (final parser, shell and rules; the summarizer's in-range churn count added) | 78 caught, 0 survived; harness exit 0 |
| `15-24h-summary.log` | end of the run: both history files copied (sha256), `summarize_peerwatch.py` over them, Prometheus `ALERTS{alertname=~"PFTPeer.*"}` over the range, lock released | summary below; one alert `pending` only (8 points), nothing sent |
| `16-offline-suite-final.log` | shellcheck, ruff, 50 unit tests, promtool `test rules` + `check rules` at 190ad2d (clean tree) | all exit 0 |
| `17-verify-installed-final.log` | read-only installed-state check after the run (same script as 08) | aptrust PASS both, skew CURRENT=73 BEHIND=0, status PASS both, integrity PASS both |
| `18-fresh-clone.log` | anonymous public clone at 286eca1: static checks, 50 fixture tests, promtool, summary re-computed from `data/` and compared with `cmp`, mutation harness | all exit 0; summary identical; 78 caught, 0 survived |
| `data/` | the two history files of the run (aggregate per-minute samples only: no addresses or keys) and `summary-24h.md` | – |

### Fixed-link drill (`drill/link-drill.sh`, log 10)

Two REJECT rules on the validator's DOCKER-USER chain match only traffic between the validator container and the
sentry's address; a transient dead-man unit started before them deletes them after 600 s. Neither node is stopped.

| Time (UTC) | Event |
|------------|-------|
| 13:17:37 | dead-man started, rules inserted at DOCKER-USER 2-3 (after the pft-egress jump) |
| 13:18:59 | textfiles: `fixed_link_up` 0 on `postfiatd` (link sentry) and `postfiatd-sentry` (link validator); every other check PASS, both nodes full |
| 13:21:51 / 13:22:51 | `[FIRING] PFTPeerFixedLinkDown` for each container on the throwaway topic (`for: 3m`) |
| 13:27:37 | dead-man: "deleted 2 rule(s)"; DOCKER-USER identical to the pre-run snapshot |
| 13:30:06 | link reconnected by itself, `fixed_link_up` 1 both sides (this time the validator dialled the sentry: validator 3 inbound / 11 outbound) |
| 13:29:51 / 13:30:51 | `[RESOLVED]` for both on the throwaway topic |
| 13:34:10 | restore: window ended, bridge and pft-maint target back, keyescrow drift 0, silence expired; operator topics 0 messages; integrity PASS both; pft-egress check PASS; both containers full with unchanged `StartedAt` |

Prometheus `pft_peerwatch_fixed_link_up` per minute over the run: `111100000000000111` on both containers.
After run 10 the only change to `drill/link-drill.sh` is the echo of the dead-man's `systemd-run` argv (run 10 printed
the first four words only and so omitted `RuntimeMaxSec=720`; the DMCMD line it ran was printed in full).

### 24-hour two-host run (logs 13, 15; `data/summary-24h.md`)

The run started 2026-11-11T13:35Z under the pft-maint lock `peerwatch-24h` (log 13). Each history file holds the newest
`HISTORY_MAX` = 1440 samples; they were copied at 2026-11-12T13:39Z, by which time the first four minutes of the run
had rotated out. The summary therefore covers the 1440 samples held at copy time:
2026-11-11T13:39:25Z .. 2026-11-12T13:38:26Z (`--from 1794404365 --to 1794490706`), i.e. 24 h of one-minute samples.

| Item | validator (`postfiatd`) | sentry (`postfiatd-sentry`) |
|------|-------------------------|-----------------------------|
| samples / expected | 1440 / 1440 (100 %) | 1440 / 1440 (100 %) |
| gaps > 90 s, re-baselines, unparsed lines | 0, 0, 0 | 0, 0, 0 |
| overall PASS / WARN / FAIL samples | 1428 / 4 / 8 | 1430 / 10 / 0 |
| peers min / median / max | 14 / 14 / 14 | 22 / 22 / 22 |
| joins / leaves by public key (in range) | 1 / 1 | 0 / 0 |
| latency p50 (median), p95 median / max | 277 ms; 474 / 5060 ms | 276 ms; 422 / 2786 ms |
| ledger agreement min / median | 0.9286 / 1.0 | 1.0 / 1.0 |
| fixed link down samples | 0 / 1440 (`sentry`) | 0 / 1440 (`validator`) |
| checks other than `latency` | 1440 PASS each | 1440 PASS each |

Every non-PASS sample was the `latency` check. On the validator, p95 rose above 1000 ms at 12:07:26Z and above 3000 ms
from 12:08:26Z to 12:15:26Z (8 FAIL samples, peak 5060 ms), then fell back through WARN to PASS by 12:19Z, while p50
stayed at 238-279 ms, the peer count stayed at 14 and the sentry stayed PASS. With 14 peers the nearest-rank p95 is
the slowest peer, so this was one slow remote peer, not the host. `PFTPeerQualityDegraded` (`for: 15m`) was `pending`
for 8 one-minute points (12:09:25Z-12:16:25Z) and never fired: Prometheus `ALERTS` over the range has no `firing`
series for any `PFTPeer*` alert and nothing reached Alertmanager (log 15). The sentry's 10 WARN samples (09:49-09:58Z)
were the same check (p95 1009-2786 ms, falling minute by minute; no FAIL). The fixed validator-sentry link stayed up for all 2880 samples.
The collector's rolling churn gauge reads 2 at the start of the range on both hosts because it still held the drill's
leave/rejoin (13:18Z / 13:29Z, before the run); the summary's churn row counts in-range events only (38be87e).

### Deviations

- The summary range starts 4 minutes after the run started (history rotation before the copy, above); it still holds
  1440 consecutive one-minute samples per host.
- Development captures (logs 01-05) are not published: they hold unredacted peer addresses. The committed fixtures
  are redacted copies of those captures (`tests/redact_capture.py`).
- Logs 06 and 07 contain FAIL checks; they are the found -> fixed history of the install (aptrust manifest copy, a
  role-dependent file count). 08 and 17 are clean read-only verifications of the installed state.
- After run 10 the only change to `drill/link-drill.sh` is the full echo of the dead-man argv (above).
- In log 15 one Prometheus query step failed on a jq syntax error; it is annotated in place and re-run with the
  exact query on the next lines.
