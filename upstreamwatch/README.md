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
sudo pft-upstreamwatch run [--textfile-dir DIR]      collect + text report + textfile (exit 0 / 1 paged state / 2 error)
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
| `local_stale` | upstream published newer content more than `STALE_GRACE_HOURS` (30) ago and we still lack it, **or** our copy is missing, truncated or replaced (sha256 differs from the fetcher's record, bz2 stream incomplete, zip unreadable, JSON cut off) | `PFTUpstreamFeedLocalStale` (**pages**) |
| `fetch_failing` | the fetcher has not downloaded or revalidated for `FETCH_MAX_AGE_HOURS` (50 h, two missed daily runs); this check comes before any upstream answer | `PFTUpstreamFeedFetchFailing` (**pages**) |
| `unreachable` | upstream could not be asked: network error, 5xx or 429 after `RETRIES` (3) with backoff (2 s, 4 s; `Retry-After` honoured up to 30 s), 4xx, a 200 without Last-Modified, or a Last-Modified in the future of upstream's own `Date` (> `SKEW_MAX_SECONDS`) | none: if it persists, the fetcher goes overdue and `fetch_failing` pages |

Order of checks (`evaluate_feed` in `upstreamwatch_lib.py`): unknown feed, then local copy unusable
(`local_stale`), then fetch overdue (`fetch_failing`), then upstream not usable (`unreachable`), then latest or not.
A 304 or an equal ETag proves "latest" only if the Last-Modified it carries is not newer than our copy: a content
cache can revalidate an old copy against our old ETag (the `../vulnscan` 304stale case).

**Clock skew:** upstream ages are measured on upstream's own `Date` header, so a wrong local clock does not shift
them. The skew is exported (`pft_upstreamwatch_feed_clock_skew_seconds`). Only the fetch clock uses local time,
because local time is what the fetcher wrote.

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
`_feed_clock_skew_seconds`, `_feed_probe_attempts`, `_release_state{container,state}`,
`_release_check{container,check,state}`, `_release_info{container,running,foundation}`. A collect error writes
`up 0`. Every textfile is validated (first label `host="<label>"`, sample syntax, up + last_run present, < 32 KiB)
before the atomic rename, and again by `pull`.

## Alerts

`../alerts/upstreamwatch.rules.yml`. Feed alerts use `for: 65m`, so the state must be seen by two consecutive hourly
runs; a single run cannot page (promtool case 3).

* `PFTUpstreamFeedLocalStale`, `PFTUpstreamFeedFetchFailing`: warning, **page**.
* `PFTUpstreamFeedQuiet`, `PFTUpstreamReleaseAvailable`: info, `notify="digest"`. Alertmanager routes them to the
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
