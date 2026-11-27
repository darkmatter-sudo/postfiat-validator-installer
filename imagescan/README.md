# pft-imagescan: offline vulnerability + provenance audit of the Docker images

`../vulnscan` checks the host's own packages against Canonical's USN feed, `../aptrust` checks where the host gets
packages and images from, `../integrity` checks the host's files. None of them looks inside the images that actually
run `postfiatd`, Prometheus and Alertmanager. `pft-imagescan.sh` does, without running them:

- every local image is read with `docker image save` (layers applied in order, whiteouts and opaque directories
  honoured, symlinked `os-release` followed): OS release, dpkg database, apk database, and every executable ELF file
  that carries Go build info (Go version, module dependencies, VCS revision, sha256);
- packages and Go modules are matched against **pinned offline feeds** (sha256 + download time + the feed's own
  timestamp in `feeds.json`): Canonical's OCI USN OVAL feed per Ubuntu release, the Debian security tracker, the Go
  vulnerability database (vuln.go.dev, OSV);
- provenance flags (no registry digest, no source label, Go binary built from a dirty tree, unreadable build info) and
  drift (a container runs an image other than the one its tag now names) are reported; a digest-pinned container
  (`image: repo:tag@sha256:...`) is matched by its tag and is not drift while the image it runs was scanned;
- results go to a text report, a JSON scan file, Prometheus textfile metrics and six alert rules.

Docker is only ever asked `ps`, `inspect`, `image ls`, `image inspect` and `image save`: no `exec`, `run`, `create`,
`start` or `pull` (the test suite runs the script against a docker stub that fails on anything else). An image ID
names immutable content, so inventories are cached per image ID and the 8 GB postfiatd image is read once per image
change (4 min 25 s on the validator), not once per day.

Tested on Ubuntu 22.04.5, Docker 29.1.3 (containerd image store), Python 3.10, on a validator host and a sentry host.

## Usage

```
pft-imagescan scan [--no-fetch] [--textfile-dir DIR] [--bundle DIR]   inventory + scan + report + metrics
pft-imagescan fetch                                                   refresh the pinned feeds only (+ outcome series)
pft-imagescan report --bundle DIR [--public] [--before SCAN.json] [--withheld FILE]
                                                                      rebuild a report offline (no docker, no network)
sudo pft-imagescan pull                                               validator: copy the sentry's textfile
pft-imagescan validate FILE HOST                                      check a textfile before it is served
```

| exit | meaning |
|---|---|
| 0 | no fixable high/critical finding in an image a container runs (except accepted ones), no drift |
| 1 | at least one such finding, or drift |
| 2 | scan error: stale or changed feed, docker error, unreadable image or layer, a version that cannot be compared |

## How a scan works, and when it refuses

1. **Fetch** (each feed in `FEEDS`): GET with `Cache-Control: no-cache` into a temp file, check it completely
   (bzip2 stream to the end / every zip CRC + `index/db.json` / tracker JSON with > 1000 source packages and a
   `Last-Modified` header), read the feed's own timestamp, and only then move it into place and record `file`,
   `sha256`, `url`, `timestamp_epoch`, `fetched_epoch` in `feeds.json` (atomic). A refused or failed download keeps
   the previous pinned copy; the age check below decides whether it is still usable.
2. **Inventory**: running containers (`docker ps` + `inspect`: name, configured ref, running image ID) and every
   local image (`image ls`; a running image ID that no tag points at any more is scanned by ID). Unknown inventory
   per image ID: `docker image save ID | imagescan_lib.py extract`. Layers are gzip/bzip2/xz/plain tar; a zstd layer
   or a layer listed in `manifest.json` but absent from the stream is an error, not a silent skip. Large non-layer
   blobs (in-toto/SBOM attestations, 15 MB in `rust:1.95.0-bookworm`) are skipped.
3. **Feeds pinned**: every feed file must match its `feeds.json` sha256; a feed downloaded more than
   `MAX_FEED_AGE_DAYS` (7) ago or whose own timestamp is older than `MAX_CONTENT_AGE_DAYS` (30) is refused, as is
   a feed whose own timestamp is after its download time. Two clocks because the Go DB's own timestamp only moves when
   an entry changes: vuln.go.dev answered `{"modified":"2026-11-11T02:51:11Z"}` on 2026-11-22, 11 days without a
   change, so "own timestamp < 7 days" would have refused a current feed.
4. **Matching**

   | image | feed | how |
   |---|---|---|
   | Ubuntu | `oci.com.ubuntu.<codename>.usn.oval.xml.bz2` | the feed's own `textfilecontent54` tests against a `manifest` of `package[:arch] version` lines, `debian_evr_string` "less than" (dpkg ordering, implemented in `imagescan_lib.py`). `fix=esm` = fixed only in Ubuntu Pro pockets (not fixable from the archive) |
   | Debian | security tracker JSON | per source package and release: `resolved` with `fixed_version` > installed = fixable; `open` = no fix; `fixed_version` "0" = never affected; `unimportant` open issues are dropped; `undetermined` is not reported. Severity = tracker urgency (`not yet assigned` -> `unrated`) |
   | any, Go binaries | vuln.go.dev `vulndb.zip` (OSV) | `stdlib` at the binary's Go version and every dependency (after `=>` replacements) against SEMVER ranges; withdrawn entries ignored. Severity `unrated`: the Go DB publishes none |
   | Alpine | none | apk inventory only (`scanner=none:apk-inventory-only`), reported as not scanned |
   | no package db | none | Go binaries only (`scanner=none:no-package-db`, e.g. the busybox-based prom images) |

   **Cross-check against OpenSCAP** (`tests/oscap_crosscheck.py`): the OCI feeds test a file named `manifest` in
   the working directory, so `oscap oval eval` run next to the same manifest evaluates exactly what imagescan does.
   On the same feed and manifest the two agree on every definition: host package list vs jammy (2665 definitions),
   the postfiatd image vs noble (1624), and the host package list with every version set to `0.1` vs jammy (616
   true, 2049 false). Counts only: the true definitions of a live host or image are open findings (see Public
   reports).

5. **Report + metrics**: text on stdout, JSON in `CACHE_DIR/last-scan.json`, textfile written atomically; a failed
   scan writes `pft_imagescan_up 0` and keeps the previous `last_success`.

## Accepting a finding you cannot fix

An upstream image you do not build (the postfiatd image, for example) can carry a fixable advisory that only its
maintainer can fix. Record the decision in `/etc/pft-imagescan.accept` (see `pft-imagescan.accept.example`):
`IMAGE_ID_PREFIX FINDING_ID REVIEW_DATE reason`, at most 90 days ahead, at least 12 hex characters of the image ID,
one finding per line. Accepted findings stay in the report (`ACCEPTED`) and in
`pft_imagescan_findings{accepted="true"}` but leave `pft_imagescan_fixable_high_critical`. A new image ID or a new
finding is never covered; an expired line is ignored and raises `PFTImagescanAcceptExpired`.

## Public reports

`report --public` prints feeds, containers, drift, provenance, per-image counts by source / severity / fixable /
accepted and the sha256 of the canonical JSON findings list (`findings_sha256`), but no package or advisory detail.
`--before SCAN.json` adds `FIXED` lines (advisories present before and gone now: found -> fixed -> verified is
publishable). `--withheld FILE` (from `imagescan_lib.py withhold --scan S --ref REGEX`) adds images whose inventory
is not published at all, as counts + `findings_sha256` only: the full list can be handed over privately and checked
against that hash.

## Fetch freshness (cache-busting retry)

On 2026-11-27 the ubuntu OCI feeds on both hosts stayed on 26 Nov copies after `fetch`: a content cache answered the
plain `Cache-Control: no-cache` GET with its old copy, and nothing compared it with upstream. `fetch` now does, per
feed, right after the download has passed its full check:

1. **Upstream clock.** ubuntu / debian: the later of this response's `Last-Modified` and a `HEAD` (no-cache)
   `Last-Modified` (`upstream_clock` `head_last_modified` / `response_last_modified`). go: `index/db.json`
   `"modified"` (`index_modified`), because `vulndb.zip`'s own `Last-Modified` moves on every rebuild while its content
   does not.
2. Own timestamp within `CONTENT_TOLERANCE_SECONDS` (21600, as `../upstreamwatch`) of that clock -> **`fresh`**, no
   second request.
3. Otherwise, and also when no upstream clock could be read, **one** retry: the URL with a unique `?pftcb=EPOCH-PID`
   query, `Cache-Control: no-cache`, `Pragma: no-cache`, and a conditional on the copy just received
   (`If-None-Match: <its ETag>`, else `If-Modified-Since: <its Last-Modified>`; a 304 means the cache still holds that
   copy). A retry copy is kept only if it passes the same full check **and** its own timestamp is newer; otherwise the
   first copy stays.
4. Within tolerance now -> **`retried_fresh`**; else **`still_behind`** (= not proven fresh: still older than
   upstream, or no upstream clock).
5. **Older-copy protection:** a download whose own timestamp is older than the installed copy never replaces it (shell
   check, and again in `imagescan_lib.py feedmerge`); the installed entry keeps file, sha256 and `fetched_epoch`, only
   its outcome becomes `still_behind`.

`feeds.json` (and the scan JSON) records per feed `outcome`, `upstream_epoch` (0 = unreadable), `upstream_clock`,
`outcome_note` (what happened, e.g. `retry HTTP 304 (the cache still holds that copy)`) and `outcome_epoch`. A failed
or refused download keeps the previous entry, as before. `fetch` run on its own (and `pft-imagescan-heal.service`)
replaces only the three fetch-outcome series in this host's textfile (validated before the rename; the scan series
stay as they are); a scan writes them with everything else.

`pft-imagescan-heal.service` (no timer) is that fetch in the scan unit's sandbox with the docker socket made
inaccessible. `../upstreamwatch` starts it when an imagescan feed has lagged upstream for more than `LAG_HEAL_HOURS`,
at most once per `HEAL_INTERVAL_HOURS`, never in a pft-maint window or while `pft-imagescan.service` /
`pft-imagescan-heal.service` runs (see its README, "Bounded heal").

## Metrics (`/var/lib/pft-exporter/textfile/pft_imagescan_<host>.prom`)

| metric | meaning |
|---|---|
| `pft_imagescan_up` | 1 if the last scan completed |
| `pft_imagescan_last_run_timestamp_seconds` / `_last_success_timestamp_seconds` / `_scan_duration_seconds` | run bookkeeping |
| `pft_imagescan_findings{image,source,severity,fixable,accepted}` | findings per image |
| `pft_imagescan_fixable_high_critical{image,in_use}` | fixable high/critical, accepted ones excluded (alert input) |
| `pft_imagescan_image_info{image,image_id,scanner,in_use}` | 1 per scanned image |
| `pft_imagescan_provenance_flag{image,flag}` | `no_registry_digest`, `no_source_label`, `go_dirty_vcs`, `go_buildinfo_unreadable` |
| `pft_imagescan_drift` | containers whose running image differs from their tag's image (or was not scanned) |
| `pft_imagescan_accept_expired` | expired accept lines |
| `pft_imagescan_feed_timestamp_seconds{feed}` / `_feed_fetched_timestamp_seconds{feed}` | the two feed clocks |
| `pft_imagescan_feed_fetch_outcome{feed,outcome=fresh\|retried_fresh\|still_behind}` | last fetch outcome (one-hot; absent for entries fetched before 1.1.0) |
| `pft_imagescan_feed_upstream_timestamp_seconds{feed}` / `_feed_outcome_timestamp_seconds{feed}` | upstream clock seen by the last fetch (0 = unreadable) / when the outcome was recorded |

## Alerts

`../alerts/imagescan.rules.yml` (unit tests: `../alerts/imagescan.tests.yml`, `promtool test rules`):
`PFTImagescanFailing` (up 0 for 10m), `PFTImagescanNotRunning` (no run for 2 days), `PFTImagescanFeedStale` (a feed
not downloaded for 3 days, 4 days before scans refuse it), `PFTImagescanFixableHighCritical` (an in-use image with a
fixable high/critical finding for 1h; idle images never page), `PFTImagescanDrift` (2h), `PFTImagescanAcceptExpired`.

## Install

```
sudo ./install.sh                  # validator (HOST_LABEL=validator)
sudo ./install.sh --host sentry    # sentry
sudo ./install.sh --pull           # validator: pull the sentry's textfile every 15 min (PULL_SSH in the env file)
```

`install.sh` appends the `textfile pft_imagescan_*.prom 36h ...` line and `require pft_imagescan_<host>.prom` to
`/etc/pft-rulecheck.conf` (once, before the first scan) when `../rulecheck` is installed. Then: alert rules into
Prometheus (`../alerts/prometheus.yml` lists `imagescan.rules.yml`), `pft-integrity accept`, `pft-schedaudit accept`
+ collect and `pft-jobwatch inventory` for the new timers.

The recorded two-host rollout is `drill/install-run.sh` (`PREFLIGHT_ONLY=1` first): files through `pft-fleet` (six
`imagescan` rows in `../fleet/manifest.tsv`) in a `pft-maint` window with `[MAINT]` messages on a throwaway topic,
sentry then validator install, rules loaded, schedaudit/jobwatch/integrity accepted, then checks of the textfiles,
Prometheus series, live `docker events` image streams on both hosts (saves only: no pull/push/load/import/tag/delete),
aptrust, AppArmor/seccomp denials, fleet skew and rulecheck, and a read-back of every operator topic (0 messages).
`UPGRADE=1` ships a new commit to installed hosts the same way: the preflight requires imagescan installed and BEHIND
in `pft-fleet skew` and the manifest copies equal to HEAD, then only the imagescan add-on is synced, the installed
units re-scan, and nothing is reloaded or newly accepted in schedaudit. Inventories are cached per image ID, so the
runner saves the smallest local image once per host (to stdout, never `-o`: the docker CLI renames a temp file onto
the `-o` target) as the event-stream presence control and requires exactly that one save per host.

`drill/public-bundle.sh` (run on a host, tar on stdout) makes the publishable input of a report: a `--no-fetch` scan
into scratch dirs, every inventory except the withheld upstream images (by default the in-use postfiatd, Prometheus
and Alertmanager images, whose open fixable advisories this module reports but does not remediate), containers, scan time, `feeds.json` + xz copies
of the pinned feed files, `withheld.json` (counts + `findings_sha256` only) and an optional before-scan reduced to the
remediated refs and to the findings the remediation removed (so its `fixed ... N of N` counts only those),
less any fixed ID still open in a withheld image (CVE ids are shared across distributions; the count is logged). It never copies the accept file (it names the withheld findings). `drill/fresh-clone.sh SHA` clones
the public repo at SHA and rebuilds each committed public report offline from that bundle (feed sha256 checked
against `feeds.json`), comparing with `cmp`.

## Limits

- Go: module-level matching (like `govulncheck -mode=binary` without symbol tables): an advisory for a function the
  binary never calls still counts. The main module is not matched (release builds record `(devel)` or a `v0.0.0`
  pseudo-version that would fall into every `introduced: 0` range; govulncheck skips it too).
- Debian severities are mostly `unrated` (the tracker assigns urgency late), so most Debian findings cannot trigger
  the high/critical alert; they are in `pft_imagescan_findings`.
- Alpine images are inventoried but not matched; software installed outside a package manager (e.g. a
  source-built Python in `python:*` images) is not seen, except Go binaries.
- Pre-Go-1.18 build info (pointer format) is reported as `go_buildinfo_unreadable`, not guessed.

## Tests

`cd imagescan && python3 -m pytest -q tests` (77 tests, no root, no network, no docker): synthetic OCI-layout save
streams with gzip layers, whiteouts, opaque dirs, a symlinked os-release, an attestation blob and the canonical empty
layer around **real Go build-info bytes** cut from `amtool` in `prom/alertmanager:v0.28.1`; dpkg / semver / Go
version edge tables; Ubuntu OVAL, Debian tracker and OSV controls (installed == fixed, `"0"`, ESM-only, withdrawn,
other release, main module); stale / future / changed feeds; accept-file rules; drift; public rendering; and the
shell script against a recording docker stub (only read-only verbs, second run served from the inventory cache,
failed scan -> up 0, an unwritable inventory cache named in the error, bundle report reproducible without docker, fetch refuses a truncated download), and the public rebuild of a bundle
without the withheld image's inventory (no drift when the container runs the withheld image, drift when it runs another), also with every image
withheld (an empty inventory set). Stubs go
under `TEST_TMPDIR` (default `~/.cache`) because `/tmp` is `noexec` on the hardened hosts.

`tests/test_fetch.py` (19 tests) runs the real `fetch` with real curl against a local stale-CDN origin (plain GET =
cached copy, `?pftcb=` GET = origin copy, optional 304 to `If-None-Match`, HEAD = origin `Last-Modified`): fresh on
the first try (no second request), the tolerance boundary, stale-then-fresh retry (query, `no-cache`, `Pragma`,
`If-None-Match` / `If-Modified-Since` checked on the wire), retry still behind, retry 304, a truncated first download
(refused, no retry) and a truncated retry copy (first kept), a failed download keeping the entry, older-copy
protection in the shell and in `feedmerge`, the debian HEAD clock, the go `index/db.json` clock (the zip's newer
`Last-Modified` must not count), no upstream clock = `still_behind`, the textfile rewrite (scan series untouched,
validated, an invalid textfile left alone), the scan textfile/JSON carrying the outcomes, and the heal unit
(fetch-only `ExecStart`, docker socket inaccessible, no timer, no `[Install]`).

`python3 -u tests/mutate.py` checks that the suite would notice a broken tool: it applies each of 62 one-line
mutants to a copy (fetch: retry skipped / boundary off by one / no cache-buster / no conditional / retry copy
kept unverified or when not newer / still_behind or no-clock reported fresh / both older-copy guards removed / go
zip clock / HEAD clock ignored / outcome series not stripped, unvalidated, not one-hot or missing from scan output;
heal unit running `scan` or reaching the docker socket; a `docker pull` / `exec` / `run` / `create` inserted into the script, the feed pin and both age
checks disabled, off-by-one version bounds in all three matchers, ESM or open CVEs counted fixable, accept-file prefix /
expiry / 90-day rules dropped, medium, unfixable or not-in-use findings alerting, whiteouts and missing layers ignored,
drift not reported, public reports printing details, feed age not clamped / fetch-ahead accepted, withheld images
turned into drift or hiding drift in the public rebuild), runs the suite against it and fails unless every mutant is
caught and the unmutated control passes. The first run found 5 gaps (Go `introduced` bound, three alert-input filters,
accept prefix); the tests that close them were added before the module was published.

## Results (task_76248c8a, 2026-11-22/23, validator + sentry)

Recorded runs in [`logs/`](logs/) (redacted: user, home path, IPs, throwaway topic):

| log | what | result |
|---|---|---|
| `01-tests.log`, `02-oscap-crosscheck.log` | first suite; own OVAL evaluator vs `oscap` on the same feed + manifests | 44 passed; 0 disagreements on 3 manifests |
| `03-mutate.log` | first mutation run | 34/34 caught |
| `05a`/`05b`/`06a` | pft-exporter rebuild (`exporter/Dockerfile`: apt upgrade + source label) | 05a refused flag (no change), 05b built, 06a after-scan failed on a root-owned dev cache -> fixed (writable-cache check + test) |
| `08-accept-check.log` | operator-approved 30-day accept file for the upstream postfiatd image | 17 findings, 10 accepted, 0 unaccepted fixable high/medium |
| `10a`, `10-install.log` (+ agent note) | recorded two-host install at 5db2bf1 | 56 ok, 0 FAIL; one manual stop of the event stream (sudo ignores a signal from its own process group) -> fixed in c0d8119 |
| `12-upgrade.log` | `UPGRADE=1` to dafb555 (feed-age clamp) | 55 ok, 0 FAIL |
| `13`, `14`, `14b-mutate.log` | mutants after c0d8119 / d5dfda9 | 36/36; 37/38 with 1 NOT APPLIED (L24's target line had changed: the harness refused it) -> retargeted f1c8912 -> 38/38 |
| `15-upgrade.log` | upgrade to f1c8912 (withheld-image drift fix) | 55 ok, 0 FAIL |
| `16-mutate.log` | final mutation run at a2138fc | 39/39 caught |
| `17a`, `17-upgrade.log` | upgrade to a2138fc (empty-inventory fix): the installed code of this submission | 55 ok, 0 FAIL |
| `18b-public-bundles.log` | public bundles of both hosts + public reports | PASS: findings_sha256 of every image = the host's full scan; no open advisory id, local offset or path in any published file |
| `19-fresh-clone-FAIL-empty-inv-dir.log` | first fresh clone (eb551b0) | validator cmp exit 0; sentry FAIL: git keeps no empty `inv/`, so the all-withheld sentry bundle was "not a bundle" -> `inv/.keep` (2bf8816) |
| `18c-public-bundles.log` | bundles + reports re-made with 2bf8816: the committed `reports/` | PASS, same checks as 18b (feed copies byte-identical) |
| `19b-fresh-clone.log` | fresh public clone of the submitted commit | see the submission |
| `*-commit-gate.log` | shellcheck, ruff, pytest, promtool, leak grep before each commit | clean |

Every install/upgrade run checks: integrity PASS before and after, nodes full, files = repo bytes on both hosts,
schedaudit 0 new/unexpected, jobwatch intervals, textfiles valid, Prometheus series, live `docker events` image
streams (saves only; no pull/push/load/import/tag/delete), aptrust 0 warn/fail, AppArmor + seccomp audits PASS with
0 DENIED events, fleet skew CURRENT, rulecheck OK, and 0 messages on every operator topic.

Found -> fixed -> verified: `pft-exporter:latest` (the one image built here) 266a6edb3c1f -> f05e3c62e06d,
18 fixable Debian findings -> 0 (`reports/validator/report-public.txt` lists the 11 of them whose ids are not also
open in a withheld image), provenance flag `no_source_label` -> none. Defects found and fixed during the rollout:
negative feed age (c0d8119), runner stream stop (c0d8119), public rebuild drift for withheld images (d5dfda9),
reports with every image withheld (a2138fc).

Not fixable here (published as counts + findings_sha256 only, details withheld): the upstream postfiatd image
(2 high + 8 medium fixable USNs, accepted for 30 days in `/etc/pft-imagescan.accept` by operator decision and
reported privately to its maintainer), and the in-use Prometheus/Alertmanager images (Go module advisories without a
severity rating, so they never reach the high/critical alert; fixed by upstream releases, a monitoring-stack
upgrade is outside this module).

Reproduce from a public clone: `bash imagescan/drill/fresh-clone.sh <SHA>` (key-file hashes vs `logs/17`, lint,
tests, promtool, feed sha256 vs `feeds.json`, offline public report rebuild + `cmp` for both hosts).
