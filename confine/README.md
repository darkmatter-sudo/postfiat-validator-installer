# pft-confine: least-privilege runtime profile for postfiatd containers

The stock `postfiatd` container runs as root with Docker's default capability set (14 capabilities), a writable
root filesystem and no pids or memory limit. If postfiatd or anything else in the image is ever compromised, all of
that is available to the attacker. `pft-confine` works out what the container really needs, tests that profile in a
throwaway container, and then applies it to the live node with a maintenance window and automatic rollback:

| Item | Profile |
|---|---|
| capabilities | `cap_drop: ALL`, then add back only what is needed (stock image: `SETGID SETUID`, see below) |
| root filesystem | read-only; `tmpfs` (`rw,noexec,nosuid,size=64m`) only for the directories the container writes outside its volumes |
| pids | `pids_limit` = max(256, 4 x tasks seen in the container) |
| memory | limit = max(2048 MiB, 3 x postfiatd RSS) rounded up to 256 MiB, swap = same (no swap) |
| `no-new-privileges` | kept (added if missing) |

Run it on a **sentry first**, then on the validator.

## Usage

```
pft-confine discover [--container NAME] [--json]     # read-only
pft-confine plan     [--container NAME] [--json]     # read-only: profile + the exact compose file / docker run it would use
sudo pft-confine probe [--container NAME]            # profile in a throwaway container; live container untouched
sudo pft-confine apply --yes [--container NAME] [--timeout SEC]
pft-confine verify   [--container NAME] [--min-uptime SEC]
sudo pft-confine rollback --yes [--container NAME]
```

Exit codes: 0 ok/PASS, 1 check failed or timed out and rolled back, 3 usage/config error, 4 refused,
5 rollback failed, 6 interrupted (rolled back). Default container: `postfiatd` (sentry: `--container postfiatd-sentry`).

## How the plan is derived

`discover` reads `docker inspect` (CapAdd/CapDrop, ReadonlyRootfs, PidsLimit, Memory, NanoCpus, Tmpfs, User,
SecurityOpt, Mounts), `docker diff`, and from inside the container `/proc/1/status` (RSS, threads), the task count,
the process names and every file that a process holds open for writing (`/proc/*/fdinfo` flags).

- **tmpfs**: `/tmp`, plus for every `docker diff` "A" entry outside the volumes: the entry itself if it is a
  directory, else its parent; plus the parent of each file open for writing outside the volumes. Nested entries
  collapse into their parent. A write directly in `/` or a top-level directory (`/var`, `/etc` ...) is never
  mounted over (that would hide the image's files); it is listed as `UNRESOLVED` and `apply` refuses.
  On the stock image this gives `/run /tmp /var/backups /var/lib/apt /var/lib/logrotate`; the live validator
  container had also created `/var/opt/postfiat`, so its plan has that tmpfs too (see `validator-live-apply.log`).
- **capabilities**: if `cron` runs in the container (the stock entrypoint starts it for log rotation), add
  `SETGID SETUID`: cron calls `setgid`/`initgroups`/`setuid` before every job, even for root jobs, and
  `logrotate` from `cron.daily` switches its egid the same way. Nothing else is needed: postfiatd binds 2559 and
  the admin ports (all > 1024) and every file in the volumes is owned by root.
- Overrides: `CONFINE_CAP_ADD="..."` (`none` = no capabilities), `CONFINE_TMPFS="..."`, `CONFINE_MEMORY_MB`,
  `CONFINE_PIDS`, `CONFINE_TMPFS_OPTS`, `MEM_FLOOR_MB`, `PIDS_FLOOR`.

The derivation only sees what has happened since the container started, so `probe` exists to exercise the rest.

## probe: test before you touch the live node

`probe` starts the planned profile in a throwaway container (same image, `--network none`, fresh anonymous volumes,
removed afterwards) and checks: the container stays up, the capability set, cron's job identity switch
(`setpriv --init-groups`, which fails exactly like cron does when SETGID is missing), a write into every planned
tmpfs and every volume, every `/etc/cron.daily` job except `apt-compat` (it sleeps a random time up to 30 min; its
only write, `/var/lib/apt/daily_lock`, is covered by the tmpfs write check) and the crontab logrotate line.

What it found on the stock image ([`logs/validator-probe-2.log`](logs/validator-probe-2.log)):

1. `cap_drop ALL` + read-only + only `/tmp`: the container **exits at once**:
   `cron: can't open or create /var/run/crond.pid: Read-only file system` (the entrypoint uses `set -e`).
2. derived tmpfs list, still no capabilities: the container runs, but
   `setpriv: initgroups failed: Operation not permitted` (every cron job would fail, so debug.log would never be
   rotated again) and `cron.daily/logrotate`: `error switching euid from 0 to 0 and egid from 0 to 4`.
3. derived plan (tmpfs list + `SETGID SETUID`): all checks PASS.

[`logs/validator-probe-1.log`](logs/validator-probe-1.log) is the first run. It found a bug in `probe` itself: when
the container had already exited it printed `[PASS] capabilities in effect: Error response from daemon ...`.
Fixed (the check now requires a `CapEff:` line, and probe stops with the container's last log lines when the
container is not running); run 2 is with the fixed script.

## apply: guards and rollback

`apply` refuses (exit 4, nothing changed) unless **all** of these hold: `--yes`; a [`pft-maint`](../maint/README.md)
window is active with at least `TIMEOUT + 300` s left; no pft-maint data-collection lock; the node is `full`;
no `UNRESOLVED` path in the plan.

- **compose** containers (label `com.docker.compose.project.working_dir`, e.g. `/opt/postfiatd` from the installer):
  writes `docker-compose.confine.yml` next to the compose files, backs up `.env` to `.env.pre-confine-<id>` and
  adds `COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.confine.yml` to `.env`, so a
  plain `docker compose up -d` (and [`upgrade/`](../upgrade/)) keeps the profile. Runs `docker compose config -q`,
  then `docker compose up -d`.
- **docker run** containers (the [`sentry/`](../sentry/) node): stops the container, renames it to
  `NAME-preconfine-<id>` (kept, restart policy set to `no`), and recreates `NAME` with the same image, command,
  volumes (by name, anonymous ones included), ports, user, restart and log policy, network, security options and
  non-image env, plus the profile. `plan` prints the exact `docker run`. Re-running `sentry/sentry-node.sh` later
  recreates the sentry **without** the profile; run `apply` again afterwards.

Then it polls `server_info` every `POLL_SEC` (10) s. If the node is not `full` within `TIMEOUT` (900 s), or on
SIGINT/SIGTERM, it rolls back: compose: restore `.env` byte-for-byte, delete the confine file, `up -d`; run: remove
the new container, rename the old one back, restore its restart policy, start it. Both then wait for `full`.
State is kept in `/var/lib/pft-confine/<container>.json`; `rollback --yes` uses it to undo a successful apply later.

Recreating the container changes what [`pft-integrity`](../integrity/) records for it (`cap_add, cap_drop,
readonly_rootfs`), so accept the new baseline right after a successful apply:
`sudo pft-integrity accept --reason "pft-confine: least-privilege profile applied"`.

## verify

Re-reads HostConfig and checks each profile item (cap_drop ALL, cap_add exactly as planned, read-only rootfs,
tmpfs set, pids limit, memory limit, no-new-privileges), the container (running, `OOMKilled=false`, restart count 0,
uptime >= `--min-uptime`), postfiatd RSS and the task count under their limits, `server_state` full and
peers >= `MIN_PEERS` (1). `verify --min-uptime 3600` an hour after `apply` is the stability check.

## Live runs

| Log | What |
|---|---|
| [`logs/validator-probe-1.log`](logs/validator-probe-1.log), [`logs/validator-probe-2.log`](logs/validator-probe-2.log) | probe on the validator host's image: failed attempts and their fixes (above) |
| [`logs/sentry-live-apply.log`](logs/sentry-live-apply.log) | sentry: notifiers to a throwaway topic, guard proof without a window (exit 4 x2), discover, plan, probe, pft-maint window, apply (full after 52 s, before/after HostConfig), verify PASS, pft-integrity verify (FAIL on exactly the changed fields) -> accept -> PASS, notifier configs restored (sha256 match), throwaway topic read back (only `[MAINT]` start/end) |
| [`logs/unit-tests.log`](logs/unit-tests.log) | shellcheck + offline test suite |
| [`logs/validator-live-apply.log`](logs/validator-live-apply.log) | validator (compose): notifiers on both hosts to a throwaway topic + Alertmanager silence, guard proof (exit 4 x2), discover, plan, probe PASS, pft-maint window (flag pushed to the sentry), apply (full after 51 s, before/after HostConfig), verify 14/14 PASS, pft-integrity verify (exactly `compose:.env`, `compose:docker-compose.confine.yml`, `container:postfiatd`) -> accept -> PASS, notifier configs restored (sha256 match), throwaway topic read back (only `[MAINT]` start/end) |
| [`logs/sentry-stability-1h.log`](logs/sentry-stability-1h.log) | sentry 1-hour stability with [`stability-check.sh`](stability-check.sh): `verify --min-uptime 3600` PASS (uptime 3745 s, restart count 0, OOMKilled false, RSS under the 2048 MiB limit), docker stats, pft-integrity PASS |
| [`logs/validator-stability-1h.log`](logs/validator-stability-1h.log) | validator 1-hour stability with [`stability-check.sh`](stability-check.sh): `verify --min-uptime 3600` 14/14 PASS (uptime 3627 s, restart count 0, OOMKilled false, RSS 799 MiB < 2304 MiB limit, full, 11 peers), docker stats, pft-integrity PASS 49/49 |
| [`logs/sentry-stability-1h-run1.log`](logs/sentry-stability-1h-run1.log) | the same check about 30 s earlier from an ad-hoc command: PASS, but its `script sha256 on sentry:` line is empty because the script was piped over ssh from the local checkout and no copy exists on the sentry; `stability-check.sh` prints the sha of the piped file instead |
| (next) | validator `verify --min-uptime 3600` one hour after apply |

In `sentry-live-apply.log` section 2 the two refusal messages appear out of order (the `--yes` message after the
second command, the `REFUSED` message after the next `$` line): stderr and stdout travel separately over ssh and
the drill script did not merge them. Both exit codes are 4 as expected.

[`drill-sentry.sh`](drill-sentry.sh) is the wrapper used for the sentry run, [`drill-validator.sh`](drill-validator.sh) the one for
the validator. The validator also runs Prometheus/Alertmanager, whose bridge has no maintenance hook, so the validator
wrapper adds an Alertmanager silence and redirects the sentry's watchdog target too. It accepts the integrity baseline
only if every changed item is `compose:*` or `container:<name>`. Before the live run an ad-hoc check against synthetic
input showed that the first version of that filter (`container:NAME:` with a trailing colon) did not match the real
`pft-integrity` line format, so it would have refused a correct run; it was fixed before the run. The recorded test
([`tests/drill-validator-filter-check.sh`](tests/drill-validator-filter-check.sh),
[`logs/drill-validator-filter-check.log`](logs/drill-validator-filter-check.log)) evals the script's actual line and was
written after the run. In `validator-live-apply.log` the
two `docker compose` warning timestamps (host local time) are shown as `<redacted-local-time>`; nothing else is edited.

## Tests

`bash confine/tests/run-tests.sh`: no root, no node, no docker. The docker CLI, `server_info` and `pft-maint` are
stubs and the clock is fake. Covered: plan derivation (tmpfs rules, top-level dirs unresolved, capability rule,
memory floor and 3 x RSS sizing, pids, overrides, the recreate command), refusals (no `--yes`, no window, window too
short, data-collection lock, node not full: nothing changed), compose and run-mode apply, rollback when the node
never reaches full (compose `.env` restored byte-identical, run-mode old container back with its restart policy;
rollback starts at the 900 s timeout, not before), rollback when `docker run` fails, manual rollback, and verify
(PASS, uptime too short, unconfined container, OOMKilled/restarts/RSS over limit/not full).
