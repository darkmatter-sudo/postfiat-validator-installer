# kernwatch — host kernel-log monitor (pft-kernwatch)

Status: **steps 1-3 of 5** (collector, catalogue, redaction, metrics, reports, rules + promtool tests, offline suite,
mutant harness; install on both hosts). The 24 h two-host baseline and the throwaway-topic drill follow; this README
gains a results table when they are done.

The existing monitors read postfiatd's debug.log, cgroup files and `server_info`. None of them sees the host kernel:
an OOM kill of a helper, a hung `jbd2`, an I/O error, a soft lockup, conntrack dropping peer packets, a NIC link loss,
a clocksource fallback or lost audit records. `pft-kernwatch` reads only `journalctl -k -o json` (read-only, bounded)
and turns it into Prometheus textfile metrics.

| File | What it is |
|---|---|
| `pft-kernwatch.sh` | CLI: `collect`, `report`, `pull`, `validate`, `check-catalogue`, `version` (usage in its header) |
| `kernwatch_parse.py` | stdlib helper: incremental cursor/boot-ID reader, classifier, redaction, textfile + JSON/TSV report |
| `catalogue.tsv` | versioned pattern catalogue (`id severity class regex`, first match wins); 40 patterns, 15 classes |
| `tests/test_kernwatch.py` | offline suite against `tests/stub_journalctl.py` (93 checks) |
| `tests/mutate.py` | mutant harness: 52 code/catalogue mutants against the suite + 8 rule mutants against promtool (M39 documented equivalent) |
| `tests/fixtures/positive.tsv`, `near_miss.tsv` | one or more real-format lines per pattern; noise that must match nothing |
| `drill/smoke-run.sh` | read-only two-host smoke (throwaway state dirs, no textfile written) |
| `install.sh` | install/uninstall: collector (`--host NAME`) or the validator's pull of the sentry file (`--pull`) |
| `systemd/` | `pft-kernwatch.service/.timer` (both hosts, every 2 min at :15 of even minutes, sandboxed: no network, no capabilities) and `pft-kernwatch-pull.service/.timer` (validator, odd minutes at :00) |
| `pft-kernwatch.env.example` | `/etc/pft-kernwatch.env` (root-owned 0600): `HOST_LABEL`, limits, `PULL_SSH` |
| `drill/install-run.sh` | recorded two-host install through pft-fleet in a pft-maint window (throwaway [MAINT] topic) |

Logs so far: `logs/01-smoke.log` (two-host read-only smoke), `logs/02-suite.log` (step-1 suite),
`logs/03-lint-suite-mutants.log` (shellcheck, ruff, promtool check + test, suite 93/93, mutants 60 caught / 0 survived / 0 orphans).

## Install

On each host, from a checkout: `sudo ./install.sh --host validator` (or `--host sentry`). The first run through the
sandboxed unit only seeds the cursor at the newest kernel record (no history counted, no alert at install) and must
export `pft_kernwatch_up 1`; then the timer is enabled. On the validator, put a `PULL_SSH` line in
`/etc/pft-kernwatch.env` and run `sudo ./install.sh --pull`. Every installed file is listed in `../fleet/manifest.tsv`;
`../rulecheck` grades `pft_kernwatch_*.prom` stale after 15 min and requires both hosts' files; the rule file is listed in
`../alerts/prometheus.yml`. Then `sudo pft-integrity accept --reason "..."` on each host.

## How collection works

- **Cursor + boot ID.** State lives in `/var/lib/pft-kernwatch/state.json` (0600, dir 0700): the journald cursor, the
  boot ID and the monotonic + wall time of the last record, plus the counters. It is written atomically and only after
  a complete read, so a failed run never moves the cursor.
- **Bounded.** At most `MAX_RECORDS` (20000) records per run; when that limit is hit `pft_kernwatch_backlog` is 1 and
  the next run continues from the cursor (tested: resume in 7-record steps ends with the same counters as one run).
- **Boot change.** The old boot is finished after its cursor first (a panic or lockup logged just before a reboot is
  still counted), then the new boot is read from its start. If journald no longer has the old boot, that is recorded
  (`old_boot_missing` in `--events-json`) and the new boot is still read.
- **Rotation.** If journald no longer knows the cursor ("Failed to seek to cursor"), the boot is re-read from one second
  before the last record and everything at or below its monotonic time is skipped: no double count.
  `pft_kernwatch_cursor_resets_total` counts it.
- **First run.** With no state, the cursor is seeded at the newest record and no history is counted, so an install never
  fires alerts for old events (`--from-boot-start` overrides this; `report` is the tool for history).
- **Malformed records** (not JSON, missing a field) are counted in `pft_kernwatch_malformed_total` and never classified.
  A `MESSAGE` that journald exports as a byte array (non-UTF-8) is decoded and classified.
- **Unreadable state** (garbage, wrong type, wrong version, negative counter) is replaced and counted in
  `pft_kernwatch_state_resets_total`; it is never read as "nothing seen yet".

## Metrics (`pft_kernwatch_HOST.prom`, label `host` = validator | sentry, never a hostname)

`pft_kernwatch_up`, `_collect_timestamp_seconds`, `_catalogue_info{version,sha256}`,
`_matches_total{pattern,class,severity}` (one series per catalogue pattern, zeros included),
`_last_match_timestamp_seconds{class,severity}`, `_records_total`, `_malformed_total`, `_cursor_resets_total`,
`_boot_changes_total`, `_state_resets_total`, `_run_records`, `_backlog`, `_seeded_timestamp_seconds`.
On a journal read failure the file holds only `up 0`, the timestamp and the catalogue info, never stale counters.

## Redaction

`report` prints, per pattern, the count, first/last time in UTC and one excerpt passed through `redact()`: IPv4/IPv6
(validated with `ipaddress`), MAC addresses, raw header byte dumps (`ll header:`), hex words, numbers of 4+ digits,
`/home/<user>` and `/root` paths, and the host's own name are replaced. No raw kernel line is printed. The suite checks
every replacement with a positive control (the raw input contains it).

## Severity

`crit` = the host is losing work now (OOM kill, hung task, lockup/stall, oops/panic, block I/O error, filesystem error
or read-only remount, uncorrected machine check, conntrack table full). `warn` = degraded or a precursor (OOM killer
invoked, allocation failure, I/O timeout, link down, clocksource unstable/fallback, audit backlog/lost, SYN flood,
segfault). `info` = counted for the baseline, never alerted (martian packets).

## Alerts

`../alerts/kernwatch.rules.yml` (promtool tests: `../alerts/kernwatch.tests.yml`), listed in `../alerts/prometheus.yml`
in the same commit as the live install (`drill/install-run.sh`), so no rule is loaded before its textfile exists.

| Alert | Fires when | Severity |
|---|---|---|
| `PFTKernelCritical` | any `crit` pattern counter increased in the last 15 min (one alert per host + class + pattern) | critical |
| `PFTKernelWarning` | any `warn` pattern counter increased in the last 30 min | warning |
| `PFTKernwatchStale` | for 10 min: last collection older than 10 min, `up 0`, or `backlog 1` | warning |

`info` patterns never alert. A counter reset (state reset) is not an event (tested).
