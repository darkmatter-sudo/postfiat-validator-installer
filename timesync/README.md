# timesync/ — pft-timesync: authenticated, measured host clocks (chrony + NTS)

Validators sign ledger close times and fall out of agreement when their clock drifts; a sentry with a bad clock
mis-times its peers. Ubuntu 22.04 ships `systemd-timesyncd`: an SNTP client with **one unauthenticated source**
(`ntp.ubuntu.com`) and no exported offset. `NTPSynchronized=yes` therefore says little. `pft-timesync`:

* **audits** the time setup (read-only, exit 0 OK / 1 WARN / 2 CRIT, `--json`);
* **migrates** the host to chrony with **five NTS-authenticated sources** (no pool, no DHCP servers), clock
  steps **only at boot**, bounded slewing, and a **sync-gated apply with automatic byte-identical rollback**;
* exports **textfile metrics** and ships **Prometheus alert rules** (`../alerts/timesync.rules.yml`);
* never restarts or touches postfiatd: the apply gate requires the container's `StartedAt` to be unchanged and
  `server_state` full.

```
sudo ./install.sh                        # /usr/local/sbin/pft-timesync + pft-timesync.timer (metrics every minute)
sudo pft-timesync audit [--json]         # read-only (root: chronyc uses the unix socket, cmdport 0)
pft-timesync plan                        # the chrony.conf + drop-in apply would write
sudo pft-timesync apply --yes            # migrate (gated, auto-rollback)
sudo pft-timesync rollback --yes         # restore the newest backup by hand
sudo pft-integrity accept --reason "..." # new units/binary (and after apply)
```

## Audit checks

| check | PASS | WARN | CRIT |
|---|---|---|---|
| conflicting-daemons | exactly one of chrony, systemd-timesyncd, ntp, ntpsec, openntpd active | | two or more active |
| daemon | chrony | systemd-timesyncd (SNTP, no auth) or another daemon | none active |
| chronyd | | | chronyc gets no answer |
| sources | ≥ MIN_SOURCES (3) | fewer | |
| nts | ≥ MIN_NTS (4) sources that are NTS (`authdata` Mode NTS), have an established key (KLen > 0) **and** are reachable (Reach ≠ 0) | fewer (always under timesyncd) | |
| selected | a source is selected (`*`) / NTPSynchronized=yes | | none |
| offset | \|offset\| ≤ 50 ms | ≤ 250 ms | > 250 ms (timesyncd: INFO, not exported) |
| root-dispersion | ≤ 0.1 s | ≤ 1 s | > 1 s |
| stratum | 1..6 | 7..15 | 0 / 16 / unknown |
| leap | Normal | Insert/Delete second pending | Not synchronised |
| makestep | none, or only via the boot-gate | `makestep` in chrony.conf (steps any time) | |
| slew-bound | `maxslewrate` ≤ 1000 ppm | unset (chrony default 83333 ppm) or larger | |
| rtc | LocalRTC=no | LocalRTC=yes | |

The offset is chrony's `tracking` "System time" with the sign flipped to **clock minus NTP time** (chrony's CSV
reports a slow clock as positive; probe in `logs/05`).

## How apply works (and why)

1. **Preflight, nothing changed yet**: refuses (exit 4) without `--yes`, without root, before `install.sh`,
   with fewer servers than MIN_NTS, or if `/usr/sbin/policy-rc.d` already exists. Backs up every managed file
   (`/etc/systemd/timesyncd.conf`, `/etc/chrony/chrony.conf`, the chrony drop-in, the boot makestep file) with
   present/absent + sha256, **caches the installed systemd-timesyncd .deb** (`apt-get download` of the exact
   version: chrony conflicts with timesyncd, so apt removes it, and the rollback must not depend on the mirror)
   and downloads chrony.
2. **Change**: stops timesyncd, writes a `policy-rc.d` that returns 101, installs chrony, removes the policy.
   The package therefore never starts chronyd with Ubuntu's default config (pools + `makestep 1 3`, which may
   step a running clock). The candidate config must pass `chronyd -p` before it replaces chrony.conf
   (`logs/07`: exit 0 / exit 1 on an unknown directive). Then chrony is enabled and started.
3. **Sync gate** (SYNC_BUDGET 600 s): a selected source, ≥ 4 NTS-authenticated reachable sources, leap not
   unsynchronised, \|offset\| ≤ 50 ms, root dispersion ≤ 0.1 s, postfiatd `StartedAt` unchanged and
   `server_state` full. Any miss → **automatic rollback** (exit 1; exit 5 if the rollback itself fails).
4. **Rollback**: stop chrony, purge it (if it was not installed before), `dpkg -i` the cached timesyncd .deb,
   restore every file byte-identical (files absent before are removed), restart the daemon that was active,
   then verify sha256/absence of every file, both package versions and the active daemon.

**Makestep only at boot.** chrony's `makestep` applies to every chronyd start, not only boot. So chrony.conf has
no `makestep`; the drop-in `ExecStartPre=+/usr/local/sbin/pft-timesync boot-gate` writes
`/etc/chrony/conf.d/pft-boot-makestep.conf` (`makestep 1.0 3`) only when the host booted < 300 s ago and
removes it otherwise. The file is in `/etc/chrony` because Ubuntu's AppArmor profile lets chronyd read only
`/etc/chrony/**` there; `+` runs the gate outside chrony.service's `ProtectSystem=strict` sandbox.
**Bounded slewing**: `maxslewrate 500` (0.5 ms/s, chrony default 83333 ppm). `minsources 3`: one bad or
hijacked source cannot move the clock. `cmdport 0`: no UDP command port.

## Metrics and alerts

`pft-timesync.timer` writes `/var/lib/pft-exporter/textfile/pft_timesync.prom` every minute (atomic rename):
`pft_timesync_state` (0/1/2), `pft_timesync_check{check=...}`, `pft_timesync_daemon{daemon=...}`,
`pft_timesync_offset_seconds`, `pft_timesync_root_dispersion_seconds`, `pft_timesync_stratum`,
`pft_timesync_nts_sources`, `pft_timesync_sources`, `pft_timesync_reachable_sources`, `pft_timesync_synced`,
`pft_timesync_collect_timestamp_seconds`. The validator's exporter serves the textfile dir.

**Sentry clock in the same Prometheus.** The sentry runs no Prometheus and no exporter (no new listener), the same
design as `../resources`. On the validator, `pft-timesync-pull` (timer, every minute) runs
`$PULL_SSH cat -- /var/lib/pft-exporter/textfile/pft_timesync.prom` over the existing admin ssh link and writes
`pft_timesync_peer_sentry.prom` with `host="sentry"` as the first label of every sample. The relabel is
all-or-nothing: only `pft_timesync_*` samples and HELP/TYPE lines, well-formed labels, numeric values, no `host`
label from the peer (it cannot pose as another host), `pft_timesync_state` and the collect timestamp present,
<= 64 KiB. On any failure the previous copy stays, its timestamp ages, and `PFTTimesyncStale{host="sentry"}` fires.
Series without `host` are the validator's own; every alert summary starts with the host (`sentry: ...` /
`validator: ...`), because the ntfy message body is the summary.

```
sudo install -m 0600 -o root -g root pft-timesync-pull.env.example /etc/pft-timesync-pull.env   # then edit PULL_SSH
sudo ./install.sh --pull                 # /usr/local/sbin/pft-timesync-pull + pft-timesync-pull.timer, one pull first
sudo docker kill -s HUP pft-prometheus   # reload rules after git pull (no recreate: silences and for: timers survive)
```

### Alerts

`../alerts/timesync.rules.yml`: PFTClockNotSynchronised (synced 0 for 5m, critical), PFTClockOffsetHigh
(\|offset\| > 50 ms for 10m), PFTClockNTSSourcesLow (< 4 for 15m), PFTTimesyncAuditCritical (state 2 for 5m,
critical), PFTTimesyncStale (no collection for 5 + 2 min). `../alerts/timesync.tests.yml` has promtool tests
with a firing case and a non-firing control for each rule, plus a `host="sentry"` case that checks the label and the
summary; `tests/check-rules.sh` runs them plus 9 rule mutants.

`drill/alert-drill.sh OUTDIR` is the live alert drill. It runs on the validator as the operator user and stops
`pft-timesync.timer` (metrics only; chrony and postfiatd are not touched) until PFTTimesyncStale fires, then starts it
again. For the drill both notifiers that could fire point at a random throwaway ntfy topic: the bridge
(`alerts/run-stack.sh bridge`; Prometheus and Alertmanager are not recreated) and the sentry's
`/etc/pft-alertpath/ntfy.env`, because the ~2 s bridge recreate makes `../alertpath` report DEGRADED. A trap restores
both, checks the bridge mount source and the sentry file's sha256, and the verdict needs 0 messages on the operator
topics during the drill.

## Tests

```
bash tests/run-tests.sh      # offline: stub host (fake systemctl/chronyc/apt-get/dpkg/docker), chronyc CSV from a real run
bash tests/mutate.sh         # control run, then 32 mutants; each must make the suite fail
bash tests/pull-tests.sh     # offline: pft-timesync-pull relabel/rejections/atomic pull (stub transport), 53 tests
bash tests/pull-mutate.sh    # control run, then 16 mutants of pft-timesync-pull.sh
DOCKER="sudo docker" bash tests/check-rules.sh   # promtool check + test, 9 rule mutants
bash drill/live-run.sh ROLE  # LIVE (root): injected unreachable sources -> auto rollback, then the real apply
```

`offset_probe.py` measures the clock against three public NTP servers once a minute, independent of the daemon,
so the before (timesyncd) and after (chrony) windows are measured the same way; `offset_stats.py` gives median
and p95 of \|offset\| per server and of the per-round median. Path delays are 130-330 ms, so single samples carry
several ms of asymmetry noise; the per-round median is the comparable figure.

## Results

All from real runs on Ubuntu 22.04.5 (validator host + sentry host), 2026-10-28. Host names, addresses, the agent's
user name and ntfy topics are redacted in `logs/`; the repo path in run 26 is shown as `<repo>`.

| Claim | Result | Log |
|---|---|---|
| shellcheck clean | `shellcheck -x ./*.sh tests/*.sh drill/*.sh ../alerts/run-stack.sh` exit 0 | run-23 lines 6-7 |
| offline audit states, apply/rollback paths | 108 passed, 0 failed (`3289465`; `pft-timesync.sh` and `tests/` unchanged since) | run-14 line 120, run-22 line 99 |
| mutation controls (control run first) | control 108/108, then 32/32 mutants caught, 0 not applied | run-15 lines 38-39 |
| pft-timesync-pull tests + mutants | 53/53; control then 16/16 caught | run-22 lines 73, 77, 94 |
| promtool check + test, rule mutants | SUCCESS; 9/9 rule mutants caught | run-22 lines 116-186 |
| injected unreachable sources -> automatic rollback | sentry: gate FAIL after 123 s -> rollback, exit 1; validator: same | run-16 lines 31-67, run-18 lines 11-47 |
| rollback byte-identical | `timesyncd.conf` sha256 `ce491ba1...a11d7` equal after rollback, chrony files absent, timesyncd back | run-16 lines 58-65 and 138, run-18 line 118 |
| real apply passes the gate | sentry 79 s (5 NTS sources), validator 143 s (4 NTS reachable then; 5/5 at run 27) | run-16 line 98, run-18 line 78 |
| postfiatd untouched | `StartedAt` unchanged through injected + real apply on both hosts, `server_state` full; still the same at the end, `RestartCount` 0 | run-16 line 140, run-18 line 120, run-27 |
| alert drill on a throwaway topic only | validator `PFTTimesyncStale` FIRING + RESOLVED on the throwaway topic, operator topics 0 messages, env files restored byte-identical; same for the sentry's pulled copy | run-21 lines 40-74, run-25 lines 48-80 |
| integrity rebaseline + final PASS | accepted after install/apply (runs 12, 17, 24); final verify PASS 86/0/0 validator, 52/0/0 sentry | run-27 |
| final audit | OK on both hosts: chrony, 5/5 NTS sources reachable, offset 0.2 ms / 0.1 ms | run-27 |

**Offset, before (timesyncd, 1 SNTP source) vs after (chrony, 5 NTS sources)**: 75 one-minute rounds per window
and host (20:11-21:25Z before, 21:44-22:58Z after), same probe (`offset_probe.py` sha256 `b86862f0...4915`) against
the same three public servers. Figure: \|per-round median offset\| (runs 11 and 26; raw CSVs in `logs/`).

| host | before median | before p95 | after median | after p95 |
|---|---|---|---|---|
| validator | 5.065 ms | 13.250 ms | 7.030 ms | 9.713 ms |
| sentry | 7.670 ms | 24.060 ms | 7.555 ms | 14.821 ms |

The p95 (and max) dropped on both hosts; the median did not improve (validator +2 ms). With 130-330 ms paths to the
probe servers, a few ms of median is within the probe's path-asymmetry noise, so this probe cannot resolve sub-5 ms
differences. chrony's own estimate (audit `offset`, run 27) is 0.1-0.2 ms. The gain is mostly authentication,
source redundancy, the bounded tail and exported metrics, not a smaller median.

**Found during the live runs (fixed before the final proof):** run 13 (sentry, `017d20d`) passed its sync gate after
11 s while the tool's own after-audit graded root dispersion CRIT (2.77 s; a fresh chronyd reports huge skew until a
few clock updates). The gate now also requires root dispersion <= `DISP_WARN` (`3289465`, test + mutants M31/M32);
run 16 rolled back run 13's apply by hand and re-ran the whole drill on the fixed code.

### Log index (`logs/`)

Run 1 (discovery) is not published: its `timedatectl` output names the host's time zone.

| Run | What |
|---|---|
| 02, 20 | before / after window collector launch (transient units, both hosts) |
| 03 | NTS-KE handshake check from both hosts, 7 candidate servers |
| 04, 05 | chrony 4.2 output-format probe from an extracted deb, `chronyd -x` (04 failed on socket dir perms, 05 ok) |
| 06 | dev smoke: read-only audit + plan on both hosts (uncommitted code, sha256 in header) |
| 07 | `chronyd -p` validates the candidate config, rejects an unknown directive |
| 08 | `apt-get -s install chrony` on both hosts (simulation) |
| 09, 10 | offline 105/105 and mutants at `c29a017`; 10 stopped after M07, superseded by 15 |
| 11, 26 | before / after offset statistics; CSVs `*-before.csv`, `*-after.csv` |
| 12, 17 | install on the sentry / validator + integrity accept |
| 13 | sentry live run at `017d20d`: PASS verdict, but found the dispersion gate gap (above) |
| 14, 15 | offline 108/108 and mutants 32/32 at `3289465` |
| 16, 18 | sentry / validator live run at `3289465`: injected rollback + real apply, PASS |
| 19 | rules loaded into the validator's Prometheus (SIGHUP, no recreate) |
| 21, 25 | throwaway-topic alert drill: validator, then the sentry's pulled copy |
| 22, 23 | offline final (pull tests/mutants, rules, promtool, run-stack check) and shellcheck |
| 24 | pft-timesync-pull live on the validator + integrity accept |
| 27 | final state: integrity PASS, audit OK, postfiatd health and StartedAt, both hosts |
