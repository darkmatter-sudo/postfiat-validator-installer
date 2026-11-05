# kernwatch — host kernel-log monitor (pft-kernwatch)

Status: **done (steps 1-5)**: collector, catalogue, redaction, metrics, reports, rules + promtool tests, offline suite,
mutant harness, install on both hosts, 24 h two-host baseline, throwaway-topic `/dev/kmsg` drill. Results: [below](#results).

The existing monitors read postfiatd's debug.log, cgroup files and `server_info`. None of them sees the host kernel:
an OOM kill of a helper, a hung `jbd2`, an I/O error, a soft lockup, conntrack dropping peer packets, a NIC link loss,
a clocksource fallback or lost audit records. `pft-kernwatch` reads only `journalctl -k -o json` (read-only, bounded)
and turns it into Prometheus textfile metrics.

| File | What it is |
|---|---|
| `pft-kernwatch.sh` | CLI: `collect`, `report`, `pull`, `validate`, `check-catalogue`, `version` (usage in its header) |
| `kernwatch_parse.py` | stdlib helper: incremental cursor/boot-ID reader, classifier, redaction, textfile + JSON/TSV report |
| `catalogue.tsv` | versioned pattern catalogue (`id severity class regex`, first match wins); 40 patterns, 15 classes |
| `tests/test_kernwatch.py` | offline suite against `tests/stub_journalctl.py` (98 checks) |
| `tests/mutate.py` | mutant harness: 62 code/catalogue/rule mutants (suite or promtool must fail each; M39 documented equivalent) |
| `tests/fixtures/positive.tsv`, `near_miss.tsv` | one or more real-format lines per pattern; noise that must match nothing |
| `drill/smoke-run.sh` | read-only two-host smoke (throwaway state dirs, no textfile written) |
| `install.sh` | install/uninstall: collector (`--host NAME`) or the validator's pull of the sentry file (`--pull`) |
| `systemd/` | `pft-kernwatch.service/.timer` (both hosts, every 2 min at :15 of even minutes, sandboxed: no network, no capabilities) and `pft-kernwatch-pull.service/.timer` (validator, odd minutes at :00) |
| `pft-kernwatch.env.example` | `/etc/pft-kernwatch.env` (root-owned 0600): `HOST_LABEL`, limits, `PULL_SSH` |
| `drill/install-run.sh` | recorded two-host install through pft-fleet in a pft-maint window (throwaway [MAINT] topic) |
| `drill/kmsg-run.sh` | step-4 alert drill (after the 24 h baseline): one marked `/dev/kmsg` record per alerting severity (crit `oom_global`, warn `segfault`) on each host -> PFTKernelCritical/Warning FIRING then RESOLVED for both hosts on a throwaway topic (bridge swap + silence of every other alert), operator topics read back; `PREFLIGHT_ONLY=1` changes nothing |
| `drill/baseline-run.sh`, `drill/baseline_shapes.py` | step-4 baseline, read-only: installed-file hashes, `pft-kernwatch report` over the 24 h window on both hosts, and every record in the window grouped by redacted shape (no raw kernel line, address, port or PID) |
| `drill/update-run.sh` | recorded two-host update of the installed files through pft-fleet in a pft-maint window |

Logs: `logs/01-smoke.log` (two-host read-only smoke), `logs/02-suite.log` (step-1 suite),
`logs/03-lint-suite-mutants.log` (shellcheck, ruff, promtool check + test, suite 93/93, mutants 60 caught / 0 survived / 0 orphans).
`logs/04-install.log` (recorded two-host install at 3cc9c28 through pft-fleet in a pft-maint window, throwaway [MAINT]
topic: 29 checks, 0 failed; both hosts `up 1`, 40 patterns each in Prometheus, 3 rules ok/inactive, fleet skew CURRENT,
rulecheck RESULT OK on both hosts, pft-integrity PASS on both after accept). Logs 05-11: see [Results](#results).

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

## Results

Every row is taken from a published log (`logs/NN-*.log:line`). Hosts are labelled validator and sentry; both run
Ubuntu 22.04.5 LTS (the first line of every log).

| Check | Result | Cited lines |
|---|---|---|
| Lint, promtool | shellcheck clean, ruff clean, `promtool check rules` SUCCESS: 3 rules, `promtool test rules` SUCCESS | `07-lint-suite-revert-mutants.log:52-72` |
| Offline suite | PASS, 98 checks, 0 failing | `07-…:190` |
| Fix-reverted control | old `kernwatch_parse.py` (from before `ca7d08c`): 3 FAIL, as designed | `07-…:193-202` |
| Mutants (timeout-bound) | 62 caught, 0 survived, 0 not applied, 0 broken (+1 documented equivalent, M39); 0 orphan processes | `07-…:274-275` |
| Script hashes | `pft-kernwatch.sh` 9581bd4d…, `kernwatch_parse.py` f09b6f08…, `catalogue.tsv` 54d05f90…, `kernwatch.rules.yml` b1a20ab7… in the headers of logs 07, 10 and 11; logs 10 and 11 were run from a clean checkout of the commit they name; the installed files on both hosts have the same hashes | `07-…:39-47`, `10-kmsg-drill-pass.log:2-7`, `11-baseline-24h.log:2-8,31-35,69-73` |
| Install (both hosts) | 29 checks, 0 failed; both hosts `up 1`; pft-integrity PASS after accept | `04-install.log:424` |
| Baseline window | 2026-11-04T07:17:00Z .. 2026-11-05T07:17:00Z (24 h, starts when the recorded install ends); 1 boot per host, 0 malformed, not truncated | `11-…:9,41-44,79-82` |
| Baseline, validator | 4579 kernel records, catalogue matches crit 0 / warn 0 / info 0 | `11-…:41,47` |
| Baseline, sentry | 4578 kernel records, catalogue matches crit 0 / warn 0 / info 0 | `11-…:79,85` |
| Baseline, unmatched records | all accounted for by shape (8 on the validator, 9 on the sentry), see findings below | `11-…:55-63,93-102` |
| Drill: records injected | one marked crit (`oom_global`) and one warn (`segfault`) record into `/dev/kmsg` on each host; `journalctl -k` sees them with `_TRANSPORT=kernel` | `10-…` step 2 |
| Drill: FIRING | PFTKernelCritical + PFTKernelWarning firing for both hosts; 4 `[FIRING]` messages on the throwaway topic | `10-…:125-136,155-158` |
| Drill: RESOLVED | 4 `[RESOLVED]` messages on the throwaway topic: Critical after its 15 min window, Warning after 30 min | `10-…:141-144,159-162` |
| Operator topics | 0 messages on both operator topics during the drill | `10-…:163-165` |
| Drill result | 0 checks failed, PASS; bridge back on the operator env, silence expired; pft-integrity PASS on both hosts | `10-…:153,171-178` |

### Baseline findings (24 h, both hosts)

No catalogued failure class was seen on either host: no OOM, hung task, lockup, I/O or filesystem error, link
loss, clocksource or audit problem. Each group of unmatched records, and what was found:

- **Firewall drop logging** (`[UFW BLOCK]`, about 98% of records; plus `[UFW LIMIT BLOCK]` on the sentry). This is
  unsolicited inbound traffic that the host firewall dropped, with the rate limit on the peer port working as
  intended. It is expected background noise, so it is deliberately not in the catalogue.
- **Container network churn** (`docker0: port … (veth…)`, `veth … renamed`, `ADDRCONF … veth`, `device veth …
  entered/left`): 5 recreations on the validator and 4 on the sentry. All of them line up with planned container
  recreations by the pft-seccomp live runs during the window, done in pft-maint windows. Expected; none alerted.
- **Hourly `drop_caches: 1`** (24 per host): a pre-existing hourly host job that drops the page cache. It is not part
  of Post Fiat tooling and was not changed by this work. It is harmless to correctness and is reported here as
  information for the operator.

### Deviations and disclosed issues

- **First drill attempt failed** (`logs/05-kmsg-drill-run06-failed.log`, kept as published). (1) `report --since
  -15min` exited with argparse rc 2. Found → fixed (`ca7d08c`, `join_dash_values` + a test + mutants M54/M55) →
  verified (suite 98/0, fix-reverted 3 FAIL, `07-…`). (2) Re-creating the alert bridge made the sentry's alert-path
  checker send 2 messages (DEGRADED, then RECOVERED one minute later) to one operator topic. Found → fixed
  (`cfce2a1`: the drill now pauses and resumes the alert-path checker around the bridge swap, with preflight guards)
  → verified (run in log 10: 0 operator-topic messages).
- **Textfile counters read 2** in log 10 step 3. The counters are cumulative since install and include the run-06
  records. The drill's own report for the last 15 min shows exactly 1 of each (`10-…` step 3).
- **Local UTC offset in commit metadata.** Several commits that touch this module (2026-11-04 and 2026-11-05)
  carry a +0100 author/committer offset. They are already published, and history is not rewritten. Since this
  change, commits are made with `TZ=UTC`. `pft-fleet` printed that offset in its sync line (`%cI`), so it is
  replaced by `<commit date redacted: local offset>` in the published logs 08 and 09 (3 lines). No other edits
  were made to any published log.
