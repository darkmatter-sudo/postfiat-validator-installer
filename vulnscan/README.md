# pft-vulnscan: USN/CVE exposure audit (OpenSCAP + Canonical OVAL)

`../patch` answers "which updates can apt install right now?". That is not the same as "which published Ubuntu
security notices still apply to this host?". A package whose fix exists only in the Ubuntu Pro (ESM) pockets never
shows up as a pending update, and a kernel update that is installed but not booted shows up nowhere.
`pft-vulnscan.sh` evaluates Canonical's Jammy USN OVAL feed against the installed packages with OpenSCAP, lists every
USN that still applies (priority, CVEs, binary packages, installed and fixed version, and whether apt can fix it),
checks for a reboot owed, and exports the result as Prometheus textfile metrics with alert rules.

Tested on Ubuntu 22.04.5, OpenSCAP 1.2.17 (`libopenscap8`), on a validator host and a sentry host.

**One Prometheus for both hosts** (same design as `../statewatch`, `../resources`, `../timesync`): each host scans
itself once a day; `pft-vulnscan pull` on the validator copies the sentry's textfile over the existing admin ssh link
(validated, all-or-nothing) and the validator's Prometheus alerts on both (`host="validator"`, `host="sentry"`).

## Usage

```
pft-vulnscan scan [--json] [--no-fetch] [--textfile-dir DIR]   fetch the feed if changed, evaluate, report
pft-vulnscan fetch                                             only refresh the cached feed
sudo pft-vulnscan pull                                         validator: copy the sentry's textfile
pft-vulnscan validate FILE HOST                                check a textfile before it is served
```

| exit | meaning |
|---|---|
| 0 | no USN applies, no reboot owed |
| 1 | at least one USN applies and/or a reboot is owed |
| 2 | scan error: no usable feed, stale feed, corrupt feed, oscap error, or a definition that could not be evaluated |

Example (validator, before the fix in log 06):

```
USN            SEVERITY   FIX      CVES  PACKAGES (installed -> fixed)
USN-8344-1     medium     esm      2     python3-pip 0:22.0.2+dfsg-1ubuntu0.7 -> 22.0.2+dfsg-1ubuntu0.7+esm1, ...
kernel   running 5.15.0-202-generic, newest installed 5.15.0-202-generic, reboot-required flag absent -> reboot owed: no
RESULT: 3 affected USNs (0 critical, 0 high, 2 medium, 0 low, 0 negligible, 1 none, 0 unknown; 3 fixable only via Ubuntu Pro/ESM), 3 CVEs; reboot owed: no -> exit 1
```

`--json` prints one object: `feed` (timestamp, age, definition counts), `feed_sha256`, `fetch`, `affected_usns`,
`affected_cves`, `by_severity` (severity x fix), `findings[]` (`usn`, `title`, `severity`, `issued`, `cves`,
`fix` = `archive` | `esm`, `packages[]` with `source`, `binary`, `installed`, `fixed`, `pocket`), `kernel`
(`running`, `newest_installed`, `reboot_required_flag`, `outdated`, `reboot_owed`), `exit_code`. On an error:
`{"ok": false, "error": "...", "exit_code": 2}`. Log 05 has a full findings-producing `--json` run.

## How a scan works, and when it refuses

1. **Fetch with caching.** `curl` with the saved ETag (`--etag-compare`): HTTP 304 keeps the cache; a 200 replaces
   it only if the download is a complete bzip2 stream. `/var/cache/pft-vulnscan/feed.meta` records the sha256 of the
   `.bz2`, `fetched_at` and `last_checked`. A failed download keeps the old cache and is shown in the output
   (`fetch: FAILED: ...`); the age check below decides whether the cache is still usable.
2. **Cache integrity.** The cached `.bz2` must match the sha256 in `feed.meta`, else exit 2.
3. **Freshness.** The feed's own `<oval:timestamp>` must be at most `MAX_FEED_AGE_DAYS` (7) old, else exit 2. A
   stale feed would silently miss every USN published since, so it is never used.
4. **Evaluation.** `oscap oval eval --results` on the decompressed feed, then `vulnscan_parse.py` (stdlib,
   `iterparse`; the results file is ~45 MB). It refuses (exit 2): an unparsable or truncated feed/results file,
   results that do not hold exactly one result per definition, any definition that evaluated to
   `error`/`unknown`/`not evaluated` (an unknown is never read as "not affected"), and a feed whose inventory
   definition ("Ubuntu 22.04 is installed") is not true (wrong release feed: every check would be skipped).
5. **Fix location.** Each affected criterion's comment names the pocket of the fix (`jammy` or `esm-apps/jammy`,
   `esm-infra/jammy`). `fix=esm` means apt on a host without Ubuntu Pro cannot fix it: remove the package, or
   enable Pro.
6. **Reboot owed.** Running `uname -r` vs the newest installed `linux-image-<release>` (dpkg status `ii`/`hi`,
   `sort -V`; removed packages in state `rc` are ignored), plus `/var/run/reboot-required`.

## Metrics (`/var/lib/pft-exporter/textfile/pft_vulnscan_<host>.prom`, written atomically on every run)

| metric | meaning |
|---|---|
| `pft_vulnscan_up` | 1 if the last scan completed |
| `pft_vulnscan_last_run_timestamp_seconds` | last scan (success or not) |
| `pft_vulnscan_last_success_timestamp_seconds` | last successful scan (carried over from the previous file on failure) |
| `pft_vulnscan_feed_timestamp_seconds` | `<oval:timestamp>` of the feed (0 = unknown) |
| `pft_vulnscan_scan_duration_seconds` | wall time |
| `pft_vulnscan_affected_usns{severity,fix}` | USNs that apply, 7 priorities x `archive`/`esm`/`unknown` (only when up 1) |
| `pft_vulnscan_affected_cves` | distinct CVEs of those USNs |
| `pft_vulnscan_reboot_owed` / `pft_vulnscan_kernel_outdated` | reboot owed (kernel or flag) / newer kernel installed |

## Alerts

`../alerts/vulnscan.rules.yml` (loaded by the validator's Prometheus; listed in `../alerts/prometheus.yml`):

| alert | fires when |
|---|---|
| `PFTVulnScanFailing` | `up == 0` for 10m (stale/corrupt feed, oscap error, ...) |
| `PFTVulnScanNotRunning` | last run older than 2 days for 10m (timer stopped or the sentry pull broken) |
| `PFTVulnFeedStale` | feed older than 3 days for 1h (the fetch is failing; scans refuse at 7 days) |
| `PFTVulnHighCriticalPersistent` | a high or critical USN (archive or esm) has applied for 48h (two daily scans), severity critical |
| `PFTVulnRebootOwed` | reboot owed for 72h |

A failed scan drops the `affected_usns` series, so the 48h clock restarts after a failure (`PFTVulnScanFailing`
covers the gap). The promtool tests (`../alerts/vulnscan.tests.yml`, generated by `tests/gen_rule_tests.py`) check
each rule one sample before and at the end of its `for:`, its recovery, that medium/low findings and an unknown feed
timestamp (0) never fire, and that a failed scan restarts the 48h clock.

## Install

```
sudo ./install.sh                  # validator: installs libopenscap8 if missing, script, units, first scan, timer
sudo ./install.sh --host sentry    # on the sentry
# validator, after adding PEER_LABEL and PULL_SSH to /etc/pft-vulnscan.env (see pft-vulnscan.env.example):
sudo ./install.sh --pull
sudo pft-integrity accept --reason "pft-vulnscan installed"     # both hosts
```

The first scan runs through the sandboxed unit (`ProtectSystem=strict`, no capabilities, `@system-service`
syscall filter, writes only the cache and textfile dirs) and install fails unless it gives `up 1`. OpenSCAP 1.2's
probes need `AF_NETLINK` in `RestrictAddressFamilies`; without it every scan fails with "Can't receive message: 125"
(found by the first sandboxed install, log 03, bisected in log 04). `pft-vulnscan.service` treats exit 1 (findings)
as success, so only real scan errors fail the unit. Timer: daily 04:20 UTC + up to 30 min, `Persistent=true`;
pull: every 15 min.

## Tests

`bash tests/run-tests.sh` (no root, nothing on the host changes; 119 assertions):

- stub `curl`/`oscap`/`dpkg-query` and a fake clock, with a feed built by `tests/make_fixture.py` in the exact shape of
  Canonical's (`oscap oval validate` passes on it);
- **positive controls:** a known-old package (high, archive fix, 2 CVEs, 2 binaries) and an ESM-only one are
  reported with the right table row, RESULT line, metrics and `--json`; a fixed package and an absent package are not;
- kernel: older running kernel, newer running kernel, `rc` (removed) packages, the reboot-required flag;
- ETag caching (`--etag-compare` only with a cache; 304 keeps it);
- **negative controls, each proving exit 2 + `up 0` + no affected series + `last_success` carried over + the
  specific message:** stale feed (8 days; exactly 7 is accepted), missing result, duplicate result, `error` and
  `unknown` results, inventory false, oscap failure, oscap missing, 1-byte tampered cache, valid bzip2 of a truncated
  XML, feed without timestamp, no cache + no network, first download not bzip2; a truncated download and a network
  failure keep the good cache;
- `validate` and `pull` (bad label, foreign metric, malformed value, missing `up`; failed pull keeps the old file);
- section 9 runs the **real oscap** on a fixture feed pointed at the installed `bash`: "bash < 99:1.0" must be
  reported, "bash < 0:1.0" (fixed) and a package that is not installed must not.

Live controls with the real oscap and the real Canonical feed (log 10): stale (clock + 8 days), 1-byte tampered
cache, and a half-length feed whose sha256 matches `feed.meta` all exit 2 with `up 0` and no affected series.

## Results on the two hosts (found -> fixed -> verified)

| host | found | fixed | verified |
|---|---|---|---|
| validator | 3 USNs (2 medium, 1 regression), 3 CVEs, all in source `python-pip` (`python3-pip`, `python3-pip-whl`), fix only in `esm-apps`; `pft-patch status`: 0 security updates pending (apt has no fix) | the system pip packages were not used by anything (no unit, the one project venv has its own pip): `apt-get remove python3-pip python3-pip-whl python3.10-venv python3-venv`, no service restart needed; the venv's own pip 22.0.2 (same vendored code, invisible to OVAL) upgraded from PyPI | rescan through the unit and directly: 0 USNs, exit 0 (log 06) |
| sentry | 0 USNs, 0 CVEs, no reboot owed; `pft-patch status` OK | nothing to fix | real-oscap controls pass on the sentry too (log 07) |

Both hosts: `pft-integrity` WARNed exactly the new binary and units, accepted with the task id, then PASS (log 08).
Both kernels are the newest installed (no reboot owed).

## Limits

- Only Ubuntu packages are checked. The `postfiatd` container image and the other Docker images are not.
- USN priority is Canonical's per-notice priority, not each CVE's CVSS score.
- The feed lists a USN as soon as Canonical publishes it, so a new finding can appear a day before
  `unattended-upgrades` installs the fix; `PFTVulnHighCriticalPersistent` waits 48h for that reason.

## Logs

| log | what |
|---|---|
| `01-tests.log` | first test run at 13231dd: shellcheck, 119/119, promtool check + test |
| `02-install-validator-failed.log` | first install: exited 2 silently (`conf_get` on a missing conf under `pipefail`), fixed in 659bbc9 |
| `03-install-validator-sandbox-failed.log` | second install: the sandboxed first scan failed (oscap probes), install stopped |
| `04-sandbox-bisect.log` | `systemd-run` bisect of the unit's directives: `RestrictAddressFamilies` without `AF_NETLINK` |
| `05-install-validator.log` | validator install through the unit, findings table and full findings-producing `--json` |
| `06-remediate-validator.log` | validator fix (package removal, venv pip upgrade) and verify rescan: 0 USNs |
| `07-install-sentry.log` | sentry: tests incl. real-oscap controls, install through the unit, 0 USNs |
| `08-pull-integrity-rules.log` | validator pull install, `pft-integrity` accept on both hosts, rules loaded (SIGHUP), 0 alerts |
| `09-live-negatives.log` | live stale/tampered/truncated feed controls (its `(exit)` lines are `tail`'s, see the NOTE) |
| `10-live-negatives-rc.log` | the same controls with the scan's own exit code: 0 / 2 / 2 / 2 / 0 |
| `11-tests-final.log` | final tests at the final code: sha256 of every file, installed copies identical, 119/119, promtool |
