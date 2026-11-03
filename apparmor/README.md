# pft-apparmor: a tailored AppArmor profile for the postfiatd container

Docker starts every container under `docker-default`, a generic profile that allows **any** file access, any
capability the container holds and any executable. `pft-apparmor` replaces it for postfiatd with `pft-postfiatd`, a
profile learned from what the node really does, and keeps the confine/ runtime profile (cap_drop ALL + SETGID
SETUID, read-only root, noexec tmpfs, no-new-privileges) and the mounts/ host options. AppArmor is one more layer
under those: if one of them is ever lost (a re-create without `--read-only`, a tmpfs without noexec), the profile
still blocks writes to the image, execution from writable directories and anything outside the allow-list.

## Live proof (2026-11-03): found → fixed → verified

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
