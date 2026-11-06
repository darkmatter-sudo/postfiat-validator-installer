# pft-apparmor: a tailored AppArmor profile for the postfiatd container

Docker starts every container under `docker-default`, a generic profile that allows **any** file access, any
capability the container holds and any executable. `pft-apparmor` replaces it for postfiatd with `pft-postfiatd`, a
profile learned from what the node really does, and keeps the confine/ runtime profile (cap_drop ALL + SETGID
SETUID, read-only root, noexec tmpfs, no-new-privileges) and the mounts/ host options. AppArmor is one more layer
under those: if one of them is ever lost (a re-create without `--read-only`, a tmpfs without noexec), the profile
still blocks writes to the image, execution from writable directories and anything outside the allow-list.

## Current state (2026-11-03T12:30Z): both hosts enforced with profile P2

Recorded re-apply run [`logs/16-live-reapply.log`](logs/16-live-reapply.log) (`PROFILE_FILE=... drill/live-run.sh`,
sentry first, then validator, commit 2d7378e950e853e1b0c6a3b2064f799a4708335e, clean tree, exit file `0`). Header
sha256 values (lines 3-6): `drill/live-run.sh` `de3592ba…ad9d`, `drill/host-run.sh` `21ce01ba…4824`,
`pft-apparmor.sh` `30397bba…466b`, `install.sh` `aecd1140…c8da`. The same `pft-apparmor.sh` sha256 is in the
validator learn log (11, line 2) and the P2 generate log (13, line 2), and each host-run prints it again (l.129,
l.424). P2 = `generate` over the sentry's P1 events + a recorded learn on the validator that also ran every host
add-on's in-container commands (log 11); diff vs P1 = 8 `ix` exec rules (`bash cat curl cut du ls tail wc`) and
`@{PROC}/@{pid}/mountinfo r` (log 13). P2 had sha256 `f3a023fc…0e34` (log 16 l.126, l.739). Since 2026-11-04 08:16Z
[`profile/pft-postfiatd`](profile/pft-postfiatd) is P2 + the cron.daily fix (Run 2 below), sha256 `a57315ab…adb3`,
reloaded in place on both hosts (logs 22-23).

| Host | Found | Fixed by | Verified (after) |
|---|---|---|---|
| validator | Run 1 (below) enforced P1, learned on the sentry only. ~10 min later `pft-retention sample` (validator-only timer) was blocked: 24 DENIED (`exec du/tail/ls`, `df` reading mountinfo), still visible in this run's before audit, l.439 (`RESULT: FAIL - 5 finding(s)`, l.440) | rolled back at once (logs 07-09: the first rollback refused, window too short, nothing changed; the second PASS, 0 DENIED); `pft-apparmor learn`/apply gate now run the host add-ons' read-only commands (commit 3dbd447); re-learn on the validator (log 11); P2 (log 13); `apply` (enforce), l.512-514 | every add-on unit that execs into the node ran under P2, Result=success (l.631-667); retention read the store, nudb_bytes > 0 (l.671); a **real timer tick** ran under the profile (l.678); 0 DENIED from add-ons + tick (l.679); audit PASS l.696, after enforced restart l.726 |
| validator | before audit: profile not loaded, container under `docker-default`, compose recreate drops it, no boot copy (l.431-438) | same P2 via compose override, l.512 | audit `RESULT: PASS` l.622, l.693, l.723 |
| sentry | before audit `RESULT: FAIL - 4 finding(s)` l.145 (run 1's apply rolled back by step 1b, l.66-72) | P2 `apply` (enforce), l.213-215 | audit `RESULT: PASS` l.323, l.377, l.407 |

| Control (enforced P2) | sentry (log 16) | validator (log 16) |
|---|---|---|
| positive: RPC, peers, cron identity switch, hourly run-parts, `logrotate -d`, log-volume write, `ps`; 0 DENIED | l.227-261 | l.526-560 |
| negative: new file in the `/etc/postfiatd` volume → fails + DENIED | l.268 | l.567 |
| negative: read `/etc/gshadow` → fails + DENIED | l.274 | l.573 |
| negative: exec unlisted `/usr/bin/id` → fails + DENIED | l.280 | l.579 |
| negative: exec a script copied into the log volume → fails + DENIED | l.290 | l.589 |
| earlier layers still in place: write to `/usr` (EROFS), exec from `/tmp` (noexec) | l.299, l.304 | l.598, l.603 |
| host add-on units under the profile, Result=success, 0 DENIED | l.333-363 | l.631-679 |
| enforced `docker restart`: still pft-postfiatd enforce, full, 0 DENIED | l.386-391 | l.702-707 |
| host-run result | l.416: 39 PASS, 0 FAIL | l.732: 43 PASS, 0 FAIL |

Injected-gate automatic rollback, the sentry complain window and the explicit rollback → re-apply on the sentry are
in run 1 (log 05, below); run 2 re-applied a finished profile and did not repeat them. Run-level: Prometheus
`pft_apparmor_findings 0` for both hosts, PFTAppArmorDrift neither pending nor firing (l.754-763); integrity diff
shown, then accepted (l.765-873); fleet skew CURRENT (l.860); rulecheck OK on both (l.864, l.868); operator topics
received nothing (l.898); both nodes full at the end (l.903-904); `live-run done ...: 0 check(s) failed -> PASS`
(l.906). The run's Alertmanager silence excluded PFTAlertPipelineWatchdog (l.57), so run 1's dead-man-switch leak
did not recur. After the run the live-only CPU/memory reservations were re-applied (log 17).

Logs: [07 rollback, refused](logs/07-validator-rollback-refused.log) · [08 rollback](logs/08-validator-rollback.log) ·
[09 validator audit parked](logs/09-validator-park.log) · [10 fleet sync of the fix](logs/10-fleet-sync.log) ·
[11 validator learn](logs/11-learn-validator.log) · [12 generate, superseded](logs/12-generate-p2-superseded.log)
(unprivileged redirects; files were fine, re-run as 13) · [13 generate P2](logs/13-generate-p2.log) ·
[14 preflight, not ready](logs/14-preflight-reapply-notready.log) (caught a `sudo sha256sum < FILE` bug, fixed in
fd9bbd8) · [15 preflight, ready](logs/15-preflight-reapply.log) · [16 live re-apply](logs/16-live-reapply.log) ·
[17 resources re-applied](logs/17-resources-reapply.log). The retention-side fix has its own proof in
[`../logs/retention/2-sandbox-readonly-cfg.log`](../logs/retention/2-sandbox-readonly-cfg.log).

## Run 2 (2026-11-04): cron.daily gap found → fixed → verified

**Found.** At 06:25Z the node container's own `cron.daily` run (`/etc/crontab`: `run-parts --report /etc/cron.daily`)
wrote 7 `DENIED` records for `pft-postfiatd` on both hosts and `PFTAppArmorDrift` fired: `apt-compat` was denied exec
of `apt-config`, `cksum` and `dd`, and `logrotate` was denied `open` of `/`. Cause: the learn's `cron.daily` loop skips
`apt-compat` (it sleeps up to 30 min, then runs `apt.systemd.daily`), and the profile made no decision for it; and
logrotate's daily run opens `/`, which no learn path reached. The probe below showed the second one also made the
container's daily logrotate job fail (`error: cannot open current directory: Permission denied`, exit 1). The
postfiatd log itself is rotated by the hourly crontab line and was not affected. Not an intrusion; the records were
acknowledged (`ack-denials`) after the investigation.

**Fixed** in `generate` (no new learn needed), profile sha256 `f3a023fc…0e34` → `a57315ab…adb3`:
- `QUIET_DENY_EXEC` (default `/etc/cron.daily/apt-compat /usr/lib/apt/apt.systemd.daily`): a quiet `deny PATH x,`
  block before the logged denials. The image is updated by pulling a new image, never by apt, so the job is refused
  before it runs anything and writes no audit record. Side effect: `run-parts` reports
  `failed to exec /etc/cron.daily/apt-compat: Permission denied` (exit 1) in cron's output, which is discarded
  (no MTA in the image).
- `EXTRA_FILE` (default `/:r`): `/ r,` (the root directory itself, not `/**`). It goes through the same
  overlap check as learned allows (an `EXTRA_FILE` that overlaps an audit deny exits 4).
- tests: 10 new checks (suite 269 passed, 0 failed).

**Verified.**

| Log | What it shows |
|---|---|
| [`logs/20-crondaily-probe-validator.log`](logs/20-crondaily-probe-validator.log) | `drill/crondaily-probe.sh` (printed at the top) loads the old and the new profile under throwaway names and runs the container's real `run-parts --report /etc/cron.daily` in a throwaway container from the live image with the live confine arguments, `--network none`. Old: the 06:25Z records reproduced (6 exec + `open /`) and logrotate exits 1 (l.113-114). New: 0 DENIED, apt-compat refused before it runs, dpkg + logrotate exit 0 (l.124-126). `RESULT: PASS - 0 failed` (l.129). An earlier run of the same probe without the two logrotate/other-job checks gave the same outputs. |
| [`logs/21-crondaily-probe-sentry.log`](logs/21-crondaily-probe-sentry.log) | the same script (sha256 `1f99849c…ad90`, l.2) on the sentry: same results, `RESULT: PASS - 0 failed` |
| [`logs/22-reload-validator.log`](logs/22-reload-validator.log), [`logs/23-reload-sentry.log`](logs/23-reload-sentry.log) | `drill/reload-run.sh`: in-place `apparmor_parser -r -W` of the new file (backup kept), no container re-create or restart (same container ID and start time, l.20), enforce, `server_state` full, `pft-integrity accept` + verify PASS, `pft-apparmor audit` PASS; `RESULT: PASS - 0 failed` (l.43). The script is not printed in these two logs; the committed file is the version that ran (sha256 `58d6a613…62a1`). |
| [`logs/24-fleet-sync.log`](logs/24-fleet-sync.log) | `pft-fleet sync --addon apparmor` to c1af4e941a3e210ee396cb3d7231dc775187013a in a `pft-maint` window ([MAINT] messages on a throwaway topic): CURRENT on both hosts, integrity PASS both, `fleet-run done ...: 0 check(s) failed -> PASS`. The installed `pft-apparmor generate` then reproduces `profile/pft-postfiatd` byte for byte. |

The next real proof is the container's own 06:25Z `cron.daily` run: the hourly `audit` (`denials` check) and
`PFTAppArmorDrift` show any DENIED record it writes.

## Run 1 (2026-11-03, 08:10Z): found → fixed → verified

> **Status 2026-11-03T09:15Z: the validator is back on `docker-default`; the sentry stays enforced.** About 10 min
> after the validator apply, its hourly audit showed new DENIED records (`exec /usr/bin/du`, `tail`, `ls`; `df`
> reading `/proc/*/mountinfo`): `pft-retention sample` (validator only, every 10 min) runs those inside the container.
> The profile was learned on the sentry, which runs no retention sampler, and the gate's DENIED window ended before
> the next sampler tick. The validator was rolled back with `pft-apparmor rollback --yes` in a pft-maint window
> (health PASS, retention sample working again, 0 DENIED), and its audit timer is paused until a profile that also
> covers the validator's own add-ons passes a gate that spans at least one tick of every timer that execs into the
> container. The table below is the recorded run as it happened; the validator rows are not the current state.

Recorded run [`logs/05-live-run.log`](logs/05-live-run.log) (`drill/live-run.sh`, sentry first, then validator,
commit 50ff6dec044f2f1c870472724edc07c71b8f8187, clean tree). Header sha256 values (lines 3-6): `pft-apparmor.sh`
`eaee2749…f468`, `install.sh` `aecd1140…c8da`, `drill/host-run.sh` `49408332…5dce`, `drill/live-run.sh`
`63403569…8674`. The same `pft-apparmor.sh` sha256 is in the learn log (03, line 2) and the suite + mutant log
(02, line 2): the tool did not change between learn, tests and the live run.

| Host | Found (before audit) | Fixed by | Verified (after) |
|---|---|---|---|
| sentry | `RESULT: FAIL - 4 finding(s)` (log 05 l.137): pft-postfiatd not loaded (l.128), container under `docker-default` (l.129), `docker run` container not created with the profile (l.131), no boot copy in `/etc/apparmor.d` (l.135) | `pft-apparmor apply --yes` (enforce) inside a pft-maint window, l.278 `apply (enforce) -> PASS` | audit `RESULT: PASS` l.386 (loaded enforce, container + mode + recreate + boot PASS l.377-384); again after the enforced restart, the explicit rollback and the re-apply: l.469 |
| validator | `RESULT: FAIL - 4 finding(s)` (l.507): same four, recreate = no compose file sets the profile (l.501) | same P1 profile (sha256 compared, l.488), applied through a compose override, l.552 | audit `RESULT: PASS` l.660, and after the enforced restart l.690 |

Controls (each host, enforced profile):

| Control | sentry (log 05) | validator (log 05) |
|---|---|---|
| positive: RPC, peers, cron identity switch, hourly run-parts, `logrotate -d`, log-volume write, `ps`; 0 DENIED | l.324 | l.598 |
| negative: new file in the `/etc/postfiatd` volume → fails + DENIED `mknod` | l.331 | l.605 |
| negative: read `/etc/gshadow` → fails + DENIED `open` | l.337 | l.611 |
| negative: exec unlisted `/usr/bin/id` → fails + DENIED `exec` | l.343 | l.617 |
| negative: exec a script copied into the log volume → fails + DENIED `exec` | l.353 | l.627 |
| earlier layers still in place: write to `/usr` (EROFS), exec from `/tmp` (noexec) | l.362, l.367 | l.636, l.641 |
| deliberate DENIED records acknowledged (`ack-denials`), audit PASS | l.372 | l.646 |
| enforced `docker restart`: still pft-postfiatd enforce, full, 0 DENIED | l.395 | l.669 |
| injected gate failure → automatic rollback to docker-default, full | l.172 | - (sentry only) |
| explicit rollback → audit shows the finding again; re-apply → PASS | l.411, l.419, l.452 | - (sentry only) |
| host-run result | l.481: 41 PASS, 0 FAIL | l.702: 29 PASS, 0 FAIL |

Run-level checks: boot copy identical on both hosts (l.706); textfiles and Prometheus `pft_apparmor_findings 0`
for both hosts, PFTAppArmorDrift neither pending nor firing (l.721-730); fleet skew apparmor CURRENT on both (l.837);
rulecheck OK on both (l.841, l.845); pft-integrity PASS on both after accept (l.850) and at the end (l.876, l.878);
both nodes full at the end (l.879-880); `live-run done ...: 0 check(s) failed -> PASS` (l.882, exit file `rc=0`).

Notes, stated up front:
- The 20-minute complain window on the live sentry recorded **0** new events (l.220), so P1 = the rules learned on
  the throwaway (340 distinct events, log 03 l.83-85) and nothing more. The published profile
  [`profile/pft-postfiatd`](profile/pft-postfiatd) is byte-identical to `/etc/apparmor.d/pft-postfiatd` on both
  hosts (log 01, sha256 `27d117bf…a200`).
- After the run: the re-create dropped the live-only `docker update --cpu-shares/--memory-reservation` tuning
  (an earlier, unrelated fix for CPU starvation that recreate paths do not copy); re-applied on both nodes, no
  restart (log 06).
- After the run (09:05Z), the run's catch-all Alertmanager silence, kept for PFTContainerRestarted after the
  node re-creates, also held the `../alertpath` watchdog heartbeat, so the sentry's dead-man switch sent one STALE
  and one RECOVERED message to the operator. That is a drill-harness issue, not a pft-apparmor one; the
  silence was narrowed to PFTContainerRestarted and the pipeline was OK again at 09:09Z. "Operator topics received
  nothing" (l.874) covers the run itself only.

Evidence logs: [01 lint, promtool, parser](logs/01-lint.log) · [02 suite 256/256 + mutants 85/85
caught](logs/02-suite-mutants.log) · [03 recorded sentry learn](logs/03-learn-sentry.log) ·
[04 preflight](logs/04-preflight.log) · [05 live run](logs/05-live-run.log) ·
[06 resource tuning re-applied](logs/06-resources-reapply.log). Logs are published as recorded; IPs, usernames,
hostnames, node keys and notification topics are redacted by the run itself (redaction control: log 04).

Pinned raw URLs (commit 44901a02e92fedd76df8e138204efd04a2fcce61, the commit that added the logs and the profile):

- `apparmor/pft-apparmor.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/pft-apparmor.sh
- `apparmor/install.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/install.sh
- `apparmor/profile/pft-postfiatd`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/profile/pft-postfiatd
- `alerts/apparmor.rules.yml`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/alerts/apparmor.rules.yml
- `alerts/apparmor.tests.yml`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/alerts/apparmor.tests.yml
- `apparmor/tests/run-tests.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/run-tests.sh
- `apparmor/tests/apply-tests.inc.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/apply-tests.inc.sh
- `apparmor/tests/ack-tests.inc.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/ack-tests.inc.sh
- `apparmor/tests/pull-install-tests.inc.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/pull-install-tests.inc.sh
- `apparmor/tests/stub_docker.py`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/stub_docker.py
- `apparmor/tests/mutate.py`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/tests/mutate.py
- `apparmor/drill/live-run.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/drill/live-run.sh
- `apparmor/drill/host-run.sh`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/drill/host-run.sh
- `apparmor/logs/01-lint.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/01-lint.log
- `apparmor/logs/02-suite-mutants.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/02-suite-mutants.log
- `apparmor/logs/03-learn-sentry.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/03-learn-sentry.log
- `apparmor/logs/04-preflight.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/04-preflight.log
- `apparmor/logs/05-live-run.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/05-live-run.log
- `apparmor/logs/05-live-run.log.exit`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/05-live-run.log.exit
- `apparmor/logs/06-resources-reapply.log`: https://raw.githubusercontent.com/darkmatter-sudo/postfiat-validator-installer/44901a02e92fedd76df8e138204efd04a2fcce61/apparmor/logs/06-resources-reapply.log


## Usage

```
pft-apparmor audit [--json] [--prom FILE | --textfile] [--since SEC]     # read-only
sudo pft-apparmor learn --out FILE [--minutes N]       # throwaway container under a complain profile
sudo pft-apparmor events [--since-epoch T] [--profile P]   # normalized learn events (TSV) from the audit log
pft-apparmor generate --events FILE [--caps "SETGID SETUID"] [--name P] > pft-postfiatd
pft-apparmor check FILE                                 # apparmor_parser -Q -K: compile, load nothing
sudo pft-apparmor apply --profile-file FILE [--complain] --yes   # inside a pft-maint window
sudo pft-apparmor rollback --yes                        # undo the last apply, inside a pft-maint window
sudo pft-apparmor pull                                  # validator: copy the sentry's textfile (install.sh --pull)
pft-apparmor validate FILE HOST                         # the check pull applies to a fetched textfile
sudo pft-apparmor ack-denials --reason TEXT [--until EPOCH] --yes   # after investigating DENIED records
```

Exit codes: 0 PASS/ok, 1 findings, 2 error, 3 usage, 4 refused. Config: `/etc/pft-apparmor.env`
(`HOST_LABEL`, `PROFILE`, `PEER_LABEL`, `PULL_SSH`; see `pft-apparmor.env.example`), read, never sourced.

### audit checks

| check | PASS when |
|---|---|
| `kernel` | `/sys/module/apparmor/parameters/enabled` is `Y` |
| `parser` | `apparmor_parser` is installed |
| `loaded` | `pft-postfiatd` is in the kernel's profile list |
| `container` | the container's `AppArmorProfile` is `pft-postfiatd` (docker-default / unconfined = FAIL) |
| `mode` | the profile is in enforce mode (complain = WARN: it logs, it blocks nothing) |
| `boot` | `/etc/apparmor.d/pft-postfiatd` defines the profile and compiles, and `apparmor.service` is enabled (it loads `/etc/apparmor.d` before docker starts the container at boot) |
| `recreate` | compose: a listed compose file sets `security_opt: apparmor=pft-postfiatd`; `docker run`: the container's own HostConfig (a restart keeps it) |
| `confine:*` | cap_drop ALL, read-only root and no-new-privileges are still set |
| `denials` | no `apparmor="DENIED"` event for the profile in `/var/log/audit/audit.log*` during `--since` (default 24 h); WARN lists the top three operation + path pairs |

Records carrying `namespace="root//..."` come from a **nested** AppArmor namespace, not from this host's container:
an LXD system container that loads a profile with the same name (the `rebuild/` drill applies `pft-postfiatd` inside
its sandbox) writes its DENIED records to the HOST `audit.log`. `denials`, the apply/rollback gate and `learn`'s event
normalisation skip them; `denials` prints how many it skipped. Records without a namespace field, or with
`namespace="root"`, still count. (Found 2026-11-06: rebuild drill runs 21-31 left 144 sandbox records in the
validator's audit log, `denials` graded them WARN and `PFTAppArmorDrift` fired, while the live container had 0.)
Fix commit `e536f3e1e3550f358956a64f87f2e194bb5911a7`: suite [`logs/25-nested-namespace-suite.log`](logs/25-nested-namespace-suite.log)
273 passed / 0 failed; the same suite against the previous `pft-apparmor.sh` (negative control, run as
`run-tests.sh OLD_COPY`, output tee'd without a header line) [`logs/26-nested-namespace-negative-control.log`](logs/26-nested-namespace-negative-control.log)
270 passed / 3 failed, exactly the 3 new nested-namespace cases; live audit on the validator after install
[`logs/27-nested-namespace-live-audit.log`](logs/27-nested-namespace-live-audit.log): `denials` PASS, 0 live records,
144 nested records not counted. The alert resolved at the next scrape.

`ack-denials` records in `/var/lib/pft-apparmor/denials-ack.json` that the DENIED records for the profile up to
`--until` (default now; never in the future, never before the previous ack) were investigated, with a required
reason that every later audit prints. Records after that time still count. It exists for the live drill: its
negative controls create DENIED records on purpose, and without an ack they would hold `denials` at WARN, and
`PFTAppArmorDrift` would fire, for 24 h. A malformed ack file, or one for another profile, is its own FAIL
(`denials-ack`) and hides nothing.

`--textfile` writes `pft_apparmor_check{host,check,status}`, `pft_apparmor_findings`, `pft_apparmor_denied_events`
and `pft_apparmor_last_run_timestamp_seconds`. Alert: `PFTAppArmorDrift` (`alerts/apparmor.rules.yml`), findings
> 0 for 30 min, so a bounded complain/learn window does not page.

## Install

```
sudo apparmor/install.sh                  # validator: tool, /etc/pft-apparmor.env, hourly audit timer
sudo apparmor/install.sh --host sentry    # sentry: same, HOST_LABEL=sentry
sudo apparmor/install.sh --pull           # validator: copy the sentry's textfile every 15 min (needs PULL_SSH)
sudo apparmor/install.sh [--pull] --uninstall   # refuses while an apply is in place (rollback first)
```

Installing loads no profile and re-creates no container; only `apply` does. The first audit runs through the
sandboxed unit (`systemd/pft-apparmor.service`: root with only `CAP_DAC_READ_SEARCH` for `/var/log/audit`,
`AF_UNIX` only, read-only filesystem except the textfile dir), and install stops (exit 1, timer not enabled) if
that run fails or its textfile does not pass `pft-apparmor validate`. A probe of the same sandbox on the validator
(private runlog, published with the live run) read the kernel profile list, the audit log, compiled a stock
profile with `apparmor_parser -Q -K` and got `systemctl is-enabled` answers, and gave the same 11 check lines as an
unsandboxed root run.

The sentry runs no Prometheus. `pft-apparmor pull` on the validator copies the sentry's
`pft_apparmor_sentry.prom` through `PULL_SSH` and keeps it only if it passes `validate` (nothing but
`pft_apparmor_*` samples for that host label, a `last_run` sample, ≤ 64 KiB); otherwise the last good copy stays
and the unit fails. `PFTAppArmorDrift` for `host="sentry"` is evaluated on the validator from that copy, and
pft-rulecheck's `textfile pft_apparmor_*.prom 3h` line (added by install) flags a copy that stops updating.

## How the profile is built

1. **learn** loads a seed profile `pft-postfiatd-learn` in complain mode (abstractions/base + sockets, nothing
   else) and starts a throwaway container with the live container's confine arguments (same image, caps, tmpfs,
   read-only, pids, memory), fresh anonymous volumes and no published ports. Once it is `full` it runs every code
   path the container has: RPC, cron's identity switch, the hourly cron line, every `cron.daily` job, the crontab
   logrotate line, a forced rotation (copytruncate + gzip), e2scrub's cron lines and a restart (the entrypoint's
   startup rotation); it stays up long enough for real cron ticks (cron's PAM stack only runs there). Every access
   the seed does not allow is logged as `apparmor="ALLOWED"`.
2. **events** turns those audit records into a sorted, unique TSV (`file`, `exec`, `cap`, `net` lines). Socket
   addresses are dropped, so the file holds no peer IPs.
3. **generate** writes the profile: paths under the data, log, config and tmpfs trees collapse to `DIR/{,**}`,
   `/proc/<pid>` becomes `@{PROC}/@{pid}`, masks are reduced to `r w k l m`, executables get `ix`, capabilities are
   the learned ones plus the container's cap_add. Then come the docker-default deny block (verbatim) and an explicit,
   logged `audit deny` block: writes to `/usr`, `/etc` (including the `/etc/postfiatd` volume), `/boot`, `/root`,
   `/home`; `/etc/gshadow`; execution from `/tmp`, `/run`, `/var`, `/dev/shm` and the volumes; `ptrace trace`,
   raw inet sockets, packet sockets, pivot_root, umount and the admin capabilities. `generate` refuses (exit 4) if
   any learned allow overlaps an explicit deny, so a deny can never silently break a path the node used.

## apply and rollback

`apply` changes nothing and exits 4 unless: `--yes` is given; a `pft-maint` window is active with room for an apply
**and** a rollback (`2 × HEALTH_BUDGET + MAINT_MARGIN`, 2100 s by default) and no data-collection lock is held; the
node is `full`; the container is confined (read-only root + no-new-privileges, i.e. confine/ was applied); the
profile file defines `pft-postfiatd` and compiles; and the previous apply is not still in place. Then:

1. **Profile.** An existing `/etc/apparmor.d/pft-postfiatd` is backed up; the new file is installed there (so
   `apparmor.service` loads it at boot, before docker starts the container) and loaded with `apparmor_parser -r -W`.
   `--complain` sets the complain flag for a bounded learn window on the live node; plain `apply` strips it.
2. **Re-create.** compose (validator): `docker-compose.apparmor.yml` with `security_opt: apparmor=pft-postfiatd`
   is added to `COMPOSE_FILE` in `.env` (backed up first), then `docker compose up -d`. Compose merges
   `security_opt` lists, so confine's `no-new-privileges:true` stays (checked with `docker compose config` on a
   scratch copy of the validator's compose files). `docker run` (sentry): the container is stopped and kept as
   `NAME-preaa-<id>` with restart=no, and a new one is started with the **old container's own arguments** read from
   `docker inspect` (confine/'s recreate set plus its runtime profile) and `apparmor=pft-postfiatd`.
3. **Gate.** Within `HEALTH_BUDGET` (900 s): the container was re-created, runs under the profile, the kernel has
   the profile in the wanted mode, `server_state` is `full`, peers ≥ `MIN_PEERS`, every pft-* service that was
   running is still active, and the **confine signature** is unchanged: image, cmd, entrypoint, user, env, caps,
   read-only, tmpfs, pids, memory, security_opt (minus the AppArmor entry), mounts, ports, network and logging.
   A recreate that loses one flag fails here and names the field. Then the live exercise (RPC, cron's identity
   switch, the hourly cron run, `ps`) and **0 DENIED** records for the profile since the start.
4. Any failed step, a failed gate or SIGINT/SIGTERM rolls back automatically (exit 1, or 6 when interrupted).
   On PASS, `pft-integrity accept` runs only if every changed item is `container:NAME` or the compose `.env` /
   override; anything else is left for the operator.

`rollback` restores the previous container (compose: `.env` byte-identical and the override removed; run: the
kept `NAME-preaa-<id>` renamed back with its restart policy), restores the previous profile file or removes and
unloads `pft-postfiatd`, and runs the same gate for the previous profile (exit 5 if it does not pass).
Commands printed by `apply` mask env values and IPv4 addresses. `PFT_AA_INJECT=health` makes the apply gate fail,
for a live automatic-rollback drill.

## Design notes (from probes on throwaway containers, 2026-11-02)

- **No separate sub-profile for the daemon.** The plan was to run `/usr/local/bin/postfiatd` in a child profile
  with no exec rights at all. With `no-new-privileges` (kept from confine/), a plain `px` transition is refused
  (`info="no new privs"`), and AppArmor 3.0.4 on the 5.15 kernel rejects a stacked `px -> &profile` target
  (`profile transition not found`). Dropping no-new-privileges would weaken confine/, so the profile is a single
  profile whose exec rules are an explicit allow-list (`ix`): cron, sh/dash, run-parts, logrotate, gzip, the
  coreutils the cron scripts call, ps, and postfiatd itself.
- **Complain mode logs every socket message.** A seed without network rules logged each `sendmsg`/`recvmsg` of a
  syncing node (23,367 of the 24,325 learn-profile records between the throwaway's start and the fix about two
  minutes later) and rotated the host's `/var/log/audit` set (5 x 8 MB) in about
  two minutes. The records were still in journald, so nothing was lost there. The seed now allows
  inet/inet6/unix/netlink sockets; `learn` documents why.
- **cron reads `/etc/shadow`.** pam_unix's account check opens it before every job (seen at the first real hourly
  tick in the learn window), so the profile allows reading the image's own `/etc/shadow` and still denies writes to
  it and all access to `/etc/gshadow`.
- **What the first enforced draft broke** (fixed in `generate`, each with a test and a mutant):
  `DIR/**` does not match the directory `DIR/` itself (`ls /var/log/postfiatd` and logrotate failed) → `DIR/{,**}`;
  `deny network raw` also denies **netlink** raw sockets (postfiatd's I/O threads open one) → only inet/inet6 raw
  are denied; `ps` needs `ptrace (read,readby)` on the same profile; `cron.daily/logrotate` calls `logger` only when
  logrotate fails, so a learn run never sees it → `EXTRA_EXEC` (default `/usr/bin/logger`).

## Live proof runner (`drill/`)

```
PREFLIGHT_ONLY=1 bash apparmor/drill/live-run.sh LEARN_EVENTS    # step 0 only, changes nothing (exit 0 ready, 4 not)
bash apparmor/drill/live-run.sh LEARN_EVENTS 2>&1 | tee LOG       # LEARN_EVENTS: the sentry's recorded learn output
```

`live-run.sh` (validator, agent user) points every notifier on both hosts at a throwaway topic, silences all alerts
until the last node start + 25 min, opens a `pft-maint` window, installs on both hosts, then runs `host-run.sh` as
root on each host, sentry first: before audit; P0 from the throwaway learn; an injected gate failure
(`PFT_AA_INJECT=health`) that must roll back by itself; a bounded complain window on the live sentry (`CMIN`, 20 min),
explicit rollback, P1 from learn + complain events; enforce; positive controls (RPC, peers, cron's identity switch,
hourly run-parts, `logrotate -d`, log-volume write, `ps`) with 0 DENIED; negative controls that only the profile can
stop, each of which must fail **and** log a matching DENIED record (new file in the `/etc/postfiatd` volume,
`/etc/gshadow`, the unlisted `/usr/bin/id`, exec of a script copied into the log volume); two controls reported as
blocked by an earlier layer (write to `/usr`: read-only root; exec from `/tmp`: noexec); `ack-denials`; an enforced
`docker restart`; and on the sentry an explicit rollback and re-apply. The validator applies the sentry's P1 (sha256
compared). Then metrics, integrity/fleet baselines, rulecheck, restore and a read-back of every operator topic.
It refuses while a data collector or a `pft-maint` lock is active. Dev probes of the exact control commands on a
network-less throwaway: runlog 17 showed `/bin/true` is not readable under the profile, so the exec controls copy a
0755 `cron.daily` script; runlog 21, with P0 from the recorded sentry learn (340 events), showed that profile also
denies `cat` and `ls` from a shell (the node never runs them), so the controls use only allowed tools (`grep`, `stat`,
`cp`, `rm`; `ls`/`ps` only as direct `docker exec` targets); runlog 22: all positive and negative controls PASS on P0.

## Tests

```
bash apparmor/tests/run-tests.sh            # offline suite: stub docker/parser/systemctl, fake /sys + audit logs
                                            # (apply/rollback: tests/stub_docker.py builds each new container from
                                            #  its `docker run` arguments, so a lost flag is caught by the gate;
                                            #  tests/pull-install-tests.inc.sh: validate, pull with a fake ssh
                                            #  that can fail or hang, install.sh against a fake root)
python3 -u apparmor/tests/mutate.py         # mutants of pft-apparmor.sh and install.sh (+1 documented equivalent),
                                            # each must make the suite fail (timeout = caught)
promtool test rules alerts/apparmor.tests.yml
```

The suite compiles every generated profile with the real `apparmor_parser -Q -K` when it is installed (nothing is
loaded), plus a broken-profile control. Temp files go under `TEST_TMPDIR` (default `~/.cache`) because `/tmp` is
noexec on hosts hardened by mounts/.

Recorded results on the final code (script sha256 in each log header = the live run 2 header, `logs/16`):

| log | result |
|---|---|
| `logs/18-suite-mutants.log` (git archive of `3dbd447`; `pft-apparmor.sh` / `install.sh` unchanged since) | suite `RESULT: 259 passed, 0 failed` (l.271), incl. `apparmor_parser -Q -K` of generated profiles + broken-profile control (l.130-132); mutant control PASS (l.274); `RESULT: 86 caught, 0 survived, 0 not applied of 86 (+ 2 documented equivalent: M32, M69)` (l.361) |
| `logs/19-lint-final.log` | `shellcheck -x` on every apparmor shell file exit 0; promtool `check rules` + `test rules` SUCCESS; `apparmor_parser -Q -K` of P2 exit 0; P2 sha256 `f3a023fc14cd46ae856dc3e118cdca7b233e2896be123f8ec9b3973180830e34` equal in the repo and in `/etc/apparmor.d` on both hosts |
