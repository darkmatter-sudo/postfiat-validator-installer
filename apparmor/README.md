# pft-apparmor: a tailored AppArmor profile for the postfiatd container

> Work in progress. `audit`, `learn`, `events`, `generate`, `check`, `apply`, `rollback`, the offline suite, the
> mutant harness and the alert rule are in place. The two-host live proof (sentry first, then validator) comes next;
> this README gets the found → fixed → verified table with the live run.

Docker starts every container under `docker-default`, a generic profile that allows **any** file access, any
capability the container holds and any executable. `pft-apparmor` replaces it for postfiatd with `pft-postfiatd`, a
profile learned from what the node really does, and keeps the confine/ runtime profile (cap_drop ALL + SETGID
SETUID, read-only root, noexec tmpfs, no-new-privileges) and the mounts/ host options. AppArmor is one more layer
under those: if one of them is ever lost (a re-create without `--read-only`, a tmpfs without noexec), the profile
still blocks writes to the image, execution from writable directories and anything outside the allow-list.

## Usage

```
pft-apparmor audit [--json] [--prom FILE | --textfile] [--since SEC]     # read-only
sudo pft-apparmor learn --out FILE [--minutes N]       # throwaway container under a complain profile
sudo pft-apparmor events [--since-epoch T] [--profile P]   # normalized learn events (TSV) from the audit log
pft-apparmor generate --events FILE [--caps "SETGID SETUID"] [--name P] > pft-postfiatd
pft-apparmor check FILE                                 # apparmor_parser -Q -K: compile, load nothing
sudo pft-apparmor apply --profile-file FILE [--complain] --yes   # inside a pft-maint window
sudo pft-apparmor rollback --yes                        # undo the last apply, inside a pft-maint window
```

Exit codes: 0 PASS/ok, 1 findings, 2 error, 3 usage, 4 refused. Config: `/etc/pft-apparmor.env`
(`HOST_LABEL`, `PROFILE`), read, never sourced.

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

`--textfile` writes `pft_apparmor_check{host,check,status}`, `pft_apparmor_findings`, `pft_apparmor_denied_events`
and `pft_apparmor_last_run_timestamp_seconds`. Alert: `PFTAppArmorDrift` (`alerts/apparmor.rules.yml`), findings
> 0 for 30 min, so a bounded complain/learn window does not page.

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

## Tests

```
bash apparmor/tests/run-tests.sh            # offline suite: stub docker/parser/systemctl, fake /sys + audit logs
                                            # (apply/rollback: tests/stub_docker.py builds each new container from
                                            #  its `docker run` arguments, so a lost flag is caught by the gate)
python3 -u apparmor/tests/mutate.py         # 31 mutants (+1 documented equivalent), each must make the suite fail (timeout = caught)
promtool test rules alerts/apparmor.tests.yml
```

The suite compiles every generated profile with the real `apparmor_parser -Q -K` when it is installed (nothing is
loaded), plus a broken-profile control. Temp files go under `TEST_TMPDIR` (default `~/.cache`) because `/tmp` is
noexec on hosts hardened by mounts/.
