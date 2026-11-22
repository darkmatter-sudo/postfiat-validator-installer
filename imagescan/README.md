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
  drift (a container runs an image other than the one its tag now names) are reported;
- results go to a text report, a JSON scan file, Prometheus textfile metrics and six alert rules.

Docker is only ever asked `ps`, `inspect`, `image ls`, `image inspect` and `image save`: no `exec`, `run`, `create`,
`start` or `pull` (the test suite runs the script against a docker stub that fails on anything else). An image ID
names immutable content, so inventories are cached per image ID and the 8 GB postfiatd image is read once per image
change (4 min 25 s on the validator), not once per day.

Tested on Ubuntu 22.04.5, Docker 29.1.3 (containerd image store), Python 3.10, on a validator host and a sentry host.

## Usage

```
pft-imagescan scan [--no-fetch] [--textfile-dir DIR] [--bundle DIR]   inventory + scan + report + metrics
pft-imagescan fetch                                                   refresh the pinned feeds only
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
into scratch dirs, every inventory except the withheld upstream image, containers, scan time, `feeds.json` + xz copies
of the pinned feed files, `withheld.json` (counts + `findings_sha256` only) and an optional before-scan reduced to the
remediated refs. It never copies the accept file (it names the withheld findings). `drill/fresh-clone.sh SHA` clones
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

`cd imagescan && python3 -m pytest -q tests` (54 tests, no root, no network, no docker): synthetic OCI-layout save
streams with gzip layers, whiteouts, opaque dirs, a symlinked os-release, an attestation blob and the canonical empty
layer around **real Go build-info bytes** cut from `amtool` in `prom/alertmanager:v0.28.1`; dpkg / semver / Go
version edge tables; Ubuntu OVAL, Debian tracker and OSV controls (installed == fixed, `"0"`, ESM-only, withdrawn,
other release, main module); stale / future / changed feeds; accept-file rules; drift; public rendering; and the
shell script against a recording docker stub (only read-only verbs, second run served from the inventory cache,
failed scan -> up 0, an unwritable inventory cache named in the error, bundle report reproducible without docker, fetch refuses a truncated download), and the public rebuild of a bundle
without the withheld image's inventory (no drift when the container runs the withheld image, drift when it runs another). Stubs go
under `TEST_TMPDIR` (default `~/.cache`) because `/tmp` is `noexec` on the hardened hosts.

`python3 -u tests/mutate.py` checks that the suite would notice a broken tool: it applies each of 38 one-line
mutants to a copy (a `docker pull` / `exec` / `run` / `create` inserted into the script, the feed pin and both age
checks disabled, off-by-one version bounds in all three matchers, ESM or open CVEs counted fixable, accept-file prefix /
expiry / 90-day rules dropped, medium, unfixable or not-in-use findings alerting, whiteouts and missing layers ignored,
drift not reported, public reports printing details, feed age not clamped / fetch-ahead accepted, withheld images
turned into drift or hiding drift in the public rebuild), runs the suite against it and fails unless every mutant is
caught and the unmutated control passes. The first run found 5 gaps (Go `introduced` bound, three alert-input filters,
accept prefix); the tests that close them were added before the module was published.
