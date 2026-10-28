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

### Alerts

`../alerts/timesync.rules.yml`: PFTClockNotSynchronised (synced 0 for 5m, critical), PFTClockOffsetHigh
(\|offset\| > 50 ms for 10m), PFTClockNTSSourcesLow (< 4 for 15m), PFTTimesyncAuditCritical (state 2 for 5m,
critical), PFTTimesyncStale (no collection for 5 + 2 min). `../alerts/timesync.tests.yml` has promtool tests
with a firing case and a non-firing control for each rule; `tests/check-rules.sh` runs them plus 8 rule mutants.

## Tests

```
bash tests/run-tests.sh      # offline: stub host (fake systemctl/chronyc/apt-get/dpkg/docker), chronyc CSV from a real run
bash tests/mutate.sh         # control run, then 32 mutants; each must make the suite fail
DOCKER="sudo docker" bash tests/check-rules.sh   # promtool check + test, 8 rule mutants
bash drill/live-run.sh ROLE  # LIVE (root): injected unreachable sources -> auto rollback, then the real apply
```

`offset_probe.py` measures the clock against three public NTP servers once a minute, independent of the daemon,
so the before (timesyncd) and after (chrony) windows are measured the same way; `offset_stats.py` gives median
and p95 of \|offset\| per server and of the per-round median. Path delays are 130-330 ms, so single samples carry
several ms of asymmetry noise; the per-round median is the comparable figure.

## Results

Filled in with the published logs (see the log index below).
