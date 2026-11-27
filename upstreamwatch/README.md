# pft-upstreamwatch: quiet upstream feed vs broken local fetch, and postfiatd release watch

`../vulnscan` raises `PFTVulnFeedStale` when the USN OVAL feed's own timestamp is more than 3 days old. From
2026-11-19T19:11Z to 2026-11-23 Canonical did not republish that feed at all, so the alert fired on both hosts even
though both had already fetched upstream's latest copy. One timestamp cannot tell those two cases apart.
`pft-upstreamwatch` reads two clocks per feed:

* **local fetch clock**: when our fetcher (`../vulnscan`, `../imagescan`) last completed a download or a 304
  revalidation (`feed.meta` / `feeds.json`).
* **content clock**: the timestamp of the copy we hold (its `<oval:timestamp>`, the Debian tracker's
  Last-Modified, the Go DB's `index/db.json` `modified`), compared with upstream's current clock. That clock comes
  from a **conditional HEAD** (`If-None-Match` with our ETag, `Cache-Control: no-cache`) that reads
  `Last-Modified`/`ETag`/`Date`, plus a 35-byte GET of `index/db.json` for Go. Feeds are never downloaded.

It also watches for postfiatd releases without touching the container. It sends a registry `HEAD` of the running
container's tag (with an anonymous Bearer token when the registry asks for one) and compares the result with the
running image's `RepoDigest`. It also compares the foundation RPC `build_version` with this node's version, which
it reads from `../upgradewatch`'s textfile, so it never runs `docker exec`.

## Usage

```
sudo pft-upstreamwatch run [--textfile-dir DIR] [--no-heal]
                                                     collect + bounded heal + text report + textfile
                                                     (exit 0 / 1 paged state / 2 error)
pft-upstreamwatch report [--obs FILE] [--format text|json|prom]   offline re-render of saved observations
sudo pft-upstreamwatch pull                          validator: copy the sentry's textfile (validated)
pft-upstreamwatch validate FILE HOST
sudo pft-upstreamwatch digest [--dry-run] [--force]  one low ntfy a day of the digest-only alerts
```

`run` stores the raw observations in `/var/lib/pft-upstreamwatch/last-obs.json`. These are headers, epochs, hashes
and docker inspect fields, with no states. Every state comes from a pure function of that file, so
`report --obs` re-renders the text, JSON and Prometheus output byte for byte on any machine, with no network,
docker or clock.

## States

| state | meaning | alert |
|---|---|---|
| `ok` | our copy is upstream's latest and younger than `QUIET_AGE_HOURS` (72) | none |
| `upstream_quiet` | our copy is upstream's latest (304 to our ETag, equal ETag, or upstream content clock within `CONTENT_TOLERANCE_SECONDS` of ours), but upstream has not published for 72 h | `PFTUpstreamFeedQuiet`, `notify="digest"`, **never paged** |
| `local_lagging` | upstream published newer content that our copy lacks, **no longer than** `STALE_GRACE_HOURS` (30) ago: a cache served our fetcher an old copy, or the daily fetch ran before upstream published. `lag` = upstream `Date` minus upstream content clock (`pft_upstreamwatch_feed_lag_seconds`, LAG column). For `usn-host` the [bounded heal](#bounded-heal) refetches once the lag exceeds `LAG_HEAL_HOURS` | `PFTUpstreamFeedLagging`, `notify="digest"`, `for: 3h`, **never paged** |
| `local_stale` | upstream published newer content more than `STALE_GRACE_HOURS` (30) ago and we still lack it, **or** our copy is missing, truncated or replaced (sha256 differs from the fetcher's record, bz2 stream incomplete, zip unreadable, JSON cut off) | `PFTUpstreamFeedLocalStale` (**pages**) |
| `fetch_failing` | the fetcher has not downloaded or revalidated for `FETCH_MAX_AGE_HOURS` (50 h, two missed daily runs); this check comes before any upstream answer | `PFTUpstreamFeedFetchFailing` (**pages**) |
| `unreachable` | upstream could not be asked: network error, 5xx or 429 after `RETRIES` (3) with backoff (2 s, 4 s; `Retry-After` honoured up to 30 s), 4xx, a 200 without Last-Modified, or a Last-Modified in the future of upstream's own `Date` (> `SKEW_MAX_SECONDS`) | none: if it persists, the fetcher goes overdue and `fetch_failing` pages |

Order of checks (`evaluate_feed` in `upstreamwatch_lib.py`): unknown feed, then local copy unusable
(`local_stale`), then fetch overdue (`fetch_failing`), then upstream not usable (`unreachable`), then latest or not
(not latest: `local_lagging` while lag <= grace, `local_stale` after it). Before 2026-11-27 a lag within the grace
period was reported `ok`, so nothing showed that both hosts held an old USN feed (see below).
A 304 or an equal ETag proves "latest" only if the Last-Modified it carries is not newer than our copy: a content
cache can revalidate an old copy against our old ETag (the `../vulnscan` 304stale case).

**Clock skew:** upstream ages are measured on upstream's own `Date` header, so a wrong local clock does not shift
them. The skew is exported (`pft_upstreamwatch_feed_clock_skew_seconds`). Only the fetch clock uses local time,
because local time is what the fetcher wrote.

## Bounded heal

**Why.** On 2026-11-24 and again on 2026-11-27, `../vulnscan`'s daily fetch got an old USN OVAL copy from a Canonical
content cache. On 11-27 it fetched at 04:29Z, received the 26 Nov 08:55Z copy, and upstream had published
26 Nov 16:51Z twelve hours earlier. The copy was younger than `REFETCH_AGE_HOURS` (24), so vulnscan's own stale-copy
refetch did not trigger. upstreamwatch saw upstream's newer Last-Modified but called it `ok` ("within grace"), and the
next fetch was a day away (live capture: `tests/fixtures/obs-live-validator-20261127.json`). `local_lagging` makes the
lag visible. The heal fixes it without waiting for the next daily run:

1. `heal_plan` (pure, `upstreamwatch_lib.py`) picks every feed whose fetcher has a heal unit (`usn-host` ->
   `../vulnscan`) in `local_lagging` or `local_stale` with `lag > LAG_HEAL_HOURS`. In this order it then skips
   `disabled` (`LAG_HEAL_HOURS=0`), `rate_limited` (the last start for this feed was less than `HEAL_INTERVAL_HOURS`
   ago, whatever its result), `maint_window` (`pft-maint active` exits 0 or 2; only exit 1 = no window allows a heal,
   so a missing `pft-maint` also blocks) and `vulnscan_running` (`pft-vulnscan.service` or
   `pft-vulnscan-heal.service` active).
2. The shell takes `HEAL_LOCK` with `flock -n` (held -> `skip locked`). It records the start in `HEAL_STATE` **before**
   the unit runs, so a crash or timeout still counts against the rate limit. Then it runs
   `systemctl start pft-vulnscan-heal.service` (timeout `HEAL_TIMEOUT`).
3. `pft-vulnscan-heal.service` (same sandbox as `pft-vulnscan.service`, no timer) runs `pft-vulnscan scan --force-fetch`:
   one unconditional GET with no ETag, `Cache-Control: no-cache` and the cache-busting `?pft-vulnscan-nocache=EPOCH`
   query, then a full scan, so `pft_vulnscan_feed_timestamp_seconds` moves too. It holds vulnscan's cache lock
   (`CACHE_DIR/.lock`), like every other scan/fetch.
4. upstreamwatch collects again. The result is `healed` (lag 0), `still_lagging` (the refetch got an old copy again;
   the next try is `HEAL_INTERVAL_HOURS` later) or `failed` (the unit start failed). The result is written to
   `HEAL_STATE` and to the observation file, so `report --obs` re-renders it.

Every decision for an eligible feed (`skip` + reason, `start`) and every result is appended to `HEAL_JOURNAL` as one
JSON line (the last 1000 are kept) and printed to the unit's journal. At most `24 / HEAL_INTERVAL_HOURS` (4) refetches
per feed per day can reach Canonical. A lag that outlives `STALE_GRACE_HOURS` still turns into `local_stale` and
pages, so the heal can delay a page but never hide one.

| setting (`/etc/pft-upstreamwatch.env`) | default | meaning |
|---|---|---|
| `LAG_HEAL_HOURS` | `2` | heal a feed whose lag is **more** than this; `0` = never heal |
| `HEAL_INTERVAL_HOURS` | `6` | at most one heal start per feed in this many hours (counted from the last start) |
| `HEAL_TIMEOUT` | `1500` | seconds `systemctl start` may take (the heal unit's own `TimeoutStartSec` is 20 min; `pft-upstreamwatch.service` allows 40 min) |
| `HEAL_UNIT` | `pft-vulnscan-heal.service` | unit to start (`*.service` names only) |
| `HEAL_BUSY_UNITS` | `pft-vulnscan.service pft-vulnscan-heal.service` | an active one blocks the heal |
| `MAINT_CMD` | `pft-maint active` | exit 1 = no maintenance window; anything else blocks |
| `HEAL_STATE` / `HEAL_LOCK` / `HEAL_JOURNAL` | `DATA_DIR/heal-state.json` / `heal.lock` / `heal.jsonl` | persisted attempts + results / flock / JSON-lines journal |

`run --no-heal` reports without healing.

Metrics: `pft_upstreamwatch_feed_lag_seconds{feed}` (0 when our copy is the latest; absent when unknown),
`pft_upstreamwatch_heal_attempts{feed}`, `pft_upstreamwatch_heal_last_attempt_timestamp_seconds{feed}`, and
`pft_upstreamwatch_heal_last_result{feed,result=started|healed|still_lagging|failed}` (one-hot; heal series appear
once a feed has been healed).

## Feeds (`FEEDS`)

| name | local copy | upstream URL | content clock |
|---|---|---|---|
| `usn-host` | `../vulnscan` `/var/cache/pft-vulnscan` | `com.ubuntu.jammy.usn.oval.xml.bz2` | `<oval:timestamp>` vs Last-Modified (+ ETag) |
| `ubuntu-jammy`, `ubuntu-noble` | `../imagescan` `feeds.json` | `oci.com.ubuntu.<codename>.usn.oval.xml.bz2` | same |
| `debian` | `../imagescan` | security-tracker `data/json` | Last-Modified |
| `go` | `../imagescan` | `vuln.go.dev/vulndb.zip` | `index/db.json` `modified` (the zip's Last-Modified changes every day even with no new entry) |
| `debian-oval-bookworm` | none | `www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2` | upstream only (`ok`/`upstream_quiet`/`unreachable`) |

No tool on these hosts consumes a Debian OVAL copy (`../imagescan` matches Debian packages with the security
tracker JSON), so `debian-oval-*` is watched on the upstream clock only.

## Release watch

`pft_upstreamwatch_release_state{state=current|behind|unknown}` combines two checks
(`pft_upstreamwatch_release_check{check=...}`):

* `digest`: the registry tag's `Docker-Content-Digest` (HEAD, all manifest/index media types accepted) vs the
  running image's single RepoDigest for that repository. Registry 401 leads to an anonymous token from the
  challenge's realm (https only). 429 and 5xx are retried, then `unknown`. Docker is only asked
  `inspect --type container` and `image inspect`; the tests run the script against a docker stub that refuses
  every other verb.
* `version`: the foundation RPC `server_info` `build_version` vs this node's (`pft_upgradewatch_build_info`, refused
  if that file is older than 1 h), compared numerically (1.0.10 > 1.0.9).

`behind` on either check raises `PFTUpstreamReleaseAvailable` (`notify="digest"`, `for: 2h`). Nothing is pulled.

## Metrics (`/var/lib/pft-exporter/textfile/pft_upstreamwatch_<host>.prom`)

`pft_upstreamwatch_up`, `_last_run_timestamp_seconds`, `_feed_state{feed,state}` (one-hot),
`_feed_fetch_age_seconds`, `_feed_content_age_seconds`, `_feed_upstream_age_seconds`, `_feed_upstream_newer_seconds`,
`_feed_clock_skew_seconds`, `_feed_probe_attempts`, `_feed_lag_seconds`, `_heal_attempts`,
`_heal_last_attempt_timestamp_seconds`, `_heal_last_result{feed,result}`, `_release_state{container,state}`,
`_release_check{container,check,state}`, `_release_info{container,running,foundation}`. A collect error writes
`up 0`. Every textfile is validated (first label `host="<label>"`, sample syntax, up + last_run present, < 32 KiB)
before the atomic rename, and again by `pull`.

## Alerts

`../alerts/upstreamwatch.rules.yml`. Feed alerts use `for: 65m`, so the state must be seen by two consecutive hourly
runs; a single run cannot page (promtool case 3).

* `PFTUpstreamFeedLocalStale`, `PFTUpstreamFeedFetchFailing`: warning, **page**.
* `PFTUpstreamFeedQuiet`, `PFTUpstreamFeedLagging` (`for: 3h`: the lag outlived the heal window),
  `PFTUpstreamReleaseAvailable`: info, `notify="digest"`. Alertmanager routes them to the
  `digest` receiver, which has no integrations. `pft-upstreamwatch-digest.timer` (07:20 UTC) sends at most one low
  ntfy a day that lists them.
* `PFTUpstreamwatchFailing` (up 0 for 2 h), `PFTUpstreamwatchNotRunning` (no run for 3 h): the tool's own dead-man.
* **Retuned** `PFTVulnFeedStale` (`../alerts/vulnscan.rules.yml`): `... unless on (host)
  pft_upstreamwatch_feed_state{feed="usn-host", state="upstream_quiet"} == 1`. Without upstreamwatch series it
  behaves exactly as before (promtool controls: other host quiet, imagescan feed quiet, no series: all still page).
  `../vulnscan` still refuses to scan with a feed older than 7 days (`PFTVulnScanFailing`). That is deliberate:
  a week without new USNs is worth a look even when the cause is upstream.

## Install

```
sudo ./install.sh                                         # validator (HOST_LABEL validator, CONTAINER postfiatd)
sudo ./install.sh --host sentry --container postfiatd-sentry   # on the sentry
sudo ./install.sh --pull                                  # validator: pull the sentry textfile (PULL_SSH in the env)
sudo ./install.sh --digest                                # validator: daily digest timer
```

## Tests

```
cd upstreamwatch && TMPDIR=$HOME/.cache python3 -m pytest -q tests
TEST_TMPDIR=$HOME/.cache python3 -u upstreamwatch/tests/mutate.py      # mutants: lib, wrapper, rules, ../vulnscan
bash vulnscan/tests/run-tests.sh                                       # section 12: --force-fetch + cache lock
python3 upstreamwatch/tests/gen_rule_tests.py > alerts/upstreamwatch.tests.yml
cd alerts && promtool test rules upstreamwatch.tests.yml vulnscan.tests.yml
```

The suite runs fixture HTTP servers on 127.0.0.1 and uses the real capture
`tests/fixtures/obs-live-validator-20261123.json`, which holds the real headers of 2026-11-23T01:43Z: the USN feeds
are `upstream_quiet` and the release is `current`. It covers every state and boundary, 304 and ETag (including the
304-from-an-old-cache control), clock skew in both directions, a future Last-Modified, truncated bz2/zip/JSON with
and without a matching recorded hash, dead endpoints, retry/backoff/Retry-After, registry 401→token, token 401,
non-https realm and 429, version compare, and shell-level runs against a docker stub (only `inspect`/`image inspect`
logged). It also checks up-0 on a collect error, pull validation, digest send/once-a-day/nothing-to-send, and that
a dead or empty Prometheus fails closed.

## Drills and evidence (`drill/`, `logs/`)

All runs are recorded with `tee` on the validator; logs are redacted (home path, user, host names, IPs, topics).

| script | what it proves | log |
|---|---|---|
| `drill/install-run.sh` | two-host install through `../fleet` (integrity, schedaudit, jobwatch, rulecheck accepted; 0 AppArmor/seccomp denials); the live stale USN condition is reclassified `upstream_quiet` and `PFTVulnFeedStale` stops firing; no docker pull | `logs/00-preflight.log`, `logs/01-install.log` |
| `drill/stale-drill.sh` | throwaway stack (repo rules + Alertmanager config, bridge to a random throwaway ntfy topic): a truncated scratch copy of the USN feed is `local_stale`, `PFTUpstreamFeedLocalStale` fires after `for: 65m` and pages the throwaway topic once; restoring the copy resolves it ([RESOLVED]); `upstream_quiet` feeds in the same textfile go only to receiver `digest`. The live feed cache is only read | `logs/02-stale-drill.log` |
| `drill/quiet-check.sh` | on the live stack, after the 65 m `for`: the feed is still > 3 days old on both hosts, `PFTVulnFeedStale` is neither pending nor firing, `PFTUpstreamFeedQuiet` fires for exactly the quiet feeds, Alertmanager routes them to `digest` only, the bridge logged none, operator topics received 0 messages. Run 03 FAILED one check on the check's own bug (Alertmanager prints `receiver:` before `matchers:`; the config was right), fixed and re-run as 04 | `logs/03-quiet-check.log` (FAIL), `logs/04-quiet-check.log` |
| (inline) | shellcheck, ruff, full `pytest -v`, generated promtool tests unchanged, `promtool check` + `test` | `logs/05-tests.log` |
| `drill/reports.sh` | live text/JSON/Prometheus reports of both hosts in `reports/<host>/`, rendered offline from the committed `obs.json` | `logs/06-reports.log` |
| `drill/fresh-clone.sh SHA` | anonymous public clone at SHA: key-file sha256 = installed on both hosts (logs/01), static checks, full tests, promtool, every report re-rendered and compared with `cmp` (exit 0) | `logs/07-fresh-clone.log` |
| (inline) | **local_lagging + bounded heal (2026-11-27):** live reproduction of the blind spot, before the fix: both hosts' usn-host `ok` with upstream 7.9 h newer, published 21.9 h ago | `logs/09-lag-repro-live.log` |
| (inline) | the sandbox of `pft-upstreamwatch.service` allows `pft-maint active` (rc 1), `systemctl is-active`/`start` over D-Bus and the heal flock | `logs/10-sandbox-probe.log` |
| (inline) | shellcheck, ruff, full pytest (84), `../vulnscan` run-tests.sh (153), generated promtool tests unchanged, `promtool check` + `test` | `logs/11-tests.log` |
| `tests/mutate.py` | 41 mutants (lib P01-P19, wrapper S01-S12, rules R01-R03, `../vulnscan` V01-V07) all caught, with baseline/hang/orphan controls | `logs/12-mutants.log` |
| `drill/heal-install-run.sh` | install on both hosts through `../fleet` in one pft-maint window ([MAINT] to a throwaway topic). 13 is the install itself: every sync gate passed, but the skew gate failed because `../aptrust` keeps a copy of the fleet manifest. 14 synced it. 17 re-ran the whole install as a verification: every file kept, all gates PASS, 0 messages on both operator topics | `logs/13-install.log`, `logs/14-install-aptrust.log`, `logs/17-install-verify.log` |
| `drill/heal-proof.sh` | sentry, against the committed older feed `drill/fixtures/usn-jammy-20261126T0855Z.xml.bz2`: `local_lagging`, `pft_upstreamwatch_feed_lag_seconds` in the textfile and in Prometheus, exactly one heal through the real units (journal start + healed, attempts 1), the cache now holds upstream's copy (feed timestamp = upstream Last-Modified), back to `ok`/lag 0, a second run heals nothing, no paging alert, 0 messages on both operator topics | `logs/15-heal-proof.log` |
| (inline) | self-caused `PFTRuleDead` at the install: the new rule was loaded before any `local_lagging` series existed. Fixed by one `run --no-heal` (rule LIVE); its [RESOLVED] was silenced | `logs/16-ruledead-fix.log` |
| (inline) | `reports/<host>/report.*` re-rendered with the new renderer (LAG column, `local_lagging` one-hot rows) from the unchanged committed `obs.json`. Same states as before, so `drill/fresh-clone.sh` compares byte for byte again | `logs/18-reports-rerender.log` |
| (timer, no drill) | validator: the first `pft-upstreamwatch.timer` run of the new code met the live 2026-11-27 usn-host lag (23.9 h) and healed it once on its own: heal.jsonl start + healed, attempts 1, vulnscan feed timestamp = upstream, back to `ok`/lag 0 | `logs/19-validator-natural-heal.log` |
| `drill/fresh-clone-heal.sh SHA` | anonymous public clone at SHA: 5 key files sha256 = installed on both hosts, shellcheck, ruff, full pytest, `../vulnscan` run-tests.sh, generated promtool tests unchanged, `promtool check` + `test`, README state table/settings lines | `logs/20-fresh-clone-heal.log` |
