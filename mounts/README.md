# pft-mounts: host mount-option audit and reversible hardening

`../confine` hardens the postfiatd container profile and `../sysctl` the kernel. Neither looks at the **host's
mount options**, which decide whether a local foothold can run a dropped binary from a world-writable directory,
create device nodes, or use a SUID file planted in the ledger data. `pft-mounts.sh` grades the mounts that
CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0 section 1.1.2 covers, plus two Post Fiat specific ones, and fixes them
through `/etc/fstab` and live remounts: **no reboot, no postfiatd restart**. `/proc` hidepid is graded and applied
only when opted in (`HIDEPID=1`, [below](#proc-hidepid-opt-in)).

| check id | CIS | what |
|---|---|---|
| `/tmp:separate`, `:nodev`, `:nosuid`, `:noexec` | 1.1.2.1.1-4 | `/tmp` is its own mount with nodev,nosuid,noexec |
| `/dev/shm:separate`, `:nodev`, `:nosuid`, `:noexec` | 1.1.2.2.1-4 | same for `/dev/shm` |
| `/var/tmp:separate`, `:nodev`, `:nosuid`, `:noexec` | 1.1.2.5.1-4 | same for `/var/tmp` |
| `proc:hidepid` | - | `HIDEPID=1` only: `/proc` with `hidepid=invisible` (otherwise INFO with the live state) |
| `data:nodev`, `data:nosuid` | - | postfiatd's ledger directory (`/var/lib/postfiatd/db`) **as the container sees it** |
| `apt:tempdir` | - | with a noexec `/tmp`, apt's `APT::ExtractTemplates::TempDir` must point at an exec mount |
| `fstab-dup:<target>` | - | more than one fstab line for one mount point |
| `data:mount` | - | INFO: which host mount backs the data directory |

Grades: **PASS** (option set live and persistent), **FAIL** (option missing live), **WARN** (live but not persistent:
lost at the next boot, or at the next container start for the data dir; or a duplicate fstab target), **INFO**.
Persistence is read from `/etc/fstab` (last line wins for duplicates, comments ignored, `UUID=`/`LABEL=` sources and
`\040` escapes handled) or, for `/tmp`, from an **enabled** `/etc/systemd/system/tmp.mount`, which overrides fstab.
`/dev/shm` nodev/nosuid with no fstab line PASS (systemd always mounts it that way); its noexec does not.

## Usage

```
pft-mounts audit [--json] [--prom FILE | --textfile]   read-only (root: needs the container's mount table)
pft-mounts plan                                       read-only: the fstab block and live steps apply would do
sudo pft-mounts apply --yes [--dry-run]               fstab block + live remounts + health gate (auto rollback)
sudo pft-mounts rollback --yes                        restore the fstab backup byte-identical, undo the remounts
sudo pft-mounts pull                                  validator: copy the sentry's textfile (install.sh --pull)
pft-mounts validate FILE HOST                         the check pull applies to a fetched textfile
```

Exit codes: 0 PASS / applied, 1 findings / rolled back after a gate miss, 2 error, 3 usage, 4 refused (not root,
no `--yes`, candidate fstab rejected, unmanaged fstab line for a managed target), 5 rollback failed.

The audit reads the **host** mount table from `/proc/1/mountinfo`, not `/proc/self`: inside the sandboxed systemd
unit the process has its own namespace (private `/tmp`, read-only binds), which would grade the sandbox instead
of the host. Docker volume paths are printed as `<docker-volume:NAME>`, never as host paths.

## apply and rollback

`plan` prints exactly this (other fstab lines are kept byte-for-byte):

```
# BEGIN pft-mounts (managed; edit with pft-mounts, see mounts/README.md)
/tmp /tmp none bind,nodev,nosuid,noexec 0 0
/var/tmp /var/tmp none bind,nodev,nosuid,noexec 0 0
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
proc /proc proc defaults,hidepid=invisible,gid=<pft-procview> 0 0      (HIDEPID=1 only)
<docker-volume:NAME> <docker-volume:NAME> none bind,nodev,nosuid 0 0
# END pft-mounts
```

0. **Maintenance window.** `apply --yes` and `rollback --yes` refuse (exit 4, nothing changed) unless
   `pft-maint active` exits 0, so a planned mount change always runs inside a window and the alerters on both
   hosts suppress what it may trip. `--dry-run` needs no window. Open one with
   `sudo pft-maint start --ttl 30m --reason "pft-mounts apply"`.
1. **Refusals before any change.** An unmanaged fstab line for a managed target (exit 4: move it into the block by
   hand), or a candidate fstab that `findmnt --verify --tab-file` rejects (exit 4, installed fstab untouched).
2. **fstab**: backup to `/var/lib/pft-mounts/fstab.<UTC>`, install the candidate, `systemctl daemon-reload`.
   Re-running apply when the block is current and the audit passes does nothing (no mount calls).
3. **apt first**: `/etc/apt/apt.conf.d/50pft-mounts` sets `APT::ExtractTemplates::TempDir
   "/var/lib/pft-mounts/apt-tmp"` (0700). dpkg-preconfigure extracts each package's debconf `config` script to that
   directory and executes it; with the default `/tmp` and `noexec` the script fails with exit 126 and the package's
   questions are skipped. A pre-existing file of that name is saved and restored by rollback.
4. **live, no reboot**: `/tmp` and `/var/tmp` get a self-bind (contents stay on disk, unlike a tmpfs `tmp.mount`)
   and `remount,bind,nodev,nosuid,noexec`; `/dev/shm` `remount,...,nodev,nosuid,noexec`; with `HIDEPID=1`, `/proc`
   `remount,<current flags>,hidepid=invisible,gid=<pft-procview>` (the current nosuid,nodev,noexec are passed back:
   a `remount,hidepid=...` alone clears them); the data volume directory gets a host self-bind with nodev,nosuid
   (inherited by every later container start) **and** the same remount inside the running container's mount
   namespace (`nsenter -t <pid> -m`), so postfiatd gets it now without a restart.
5. **health gate** (budget `HEALTH_BUDGET`, 300 s): postfiatd `StartedAt` unchanged, `server_state` full, peer port
   listening, `sshd -t` + `:22` listening + a new SSH handshake, every timer-driven pft oneshot matching
   `GATE_PATTERN` re-run with `Result=success` under the new mounts (that is how a unit that breaks under hidepid or
   a noexec `/tmp` is caught), every running pft daemon still active. A miss or a failed live step rolls back
   automatically (exit 1).

`rollback` restores the newest fstab backup (sha256 compared) and runs `systemctl daemon-reload` **before** it
unmounts anything: while the managed block is loaded, systemd's fstab-generator has `tmp.mount`/`var-tmp.mount`, and a
unit start right after an umount (any `PrivateTmp=` unit pulls in `RequiresMountsFor=/tmp`) mounts them again. The
first live rollback on the sentry hit exactly that (log 07/08). Each unmounted self-bind is checked (still a mount
afterwards = exit 5). Then it reverts every live step from `live.state` in reverse
order (self-binds unmounted, remounted options put back, `/proc` back to `hidepid=off`, the container's data mount
back to its old flags), removes or restores the apt file, then runs the same gate minus the StartedAt check.

## /proc hidepid (opt-in)

`hidepid=invisible` hides other users' processes, and for **root** processes it also hides them from root processes
that hold fewer capabilities (the kernel's ptrace access check). Several sandboxed pft units run as root with a
reduced `CapabilityBoundingSet` and read other processes' `/proc` entries: on the hosts this was built on,
`pft-resources@.service` reads `/proc/<postfiatd pid>/cgroup` (2 capabilities) and `pft-privesc.service` runs
`ps -q` (1 capability). With hidepid on, they would lose that view. So the default does not change `/proc`, and
`proc:hidepid` is INFO. To enable it: give each such unit `SupplementaryGroups=pft-procview` (the member-less exempt
group apply creates) or `CAP_SYS_PTRACE`, set `HIDEPID=1` in `/etc/pft-mounts.env`, then run apply; the health gate
re-runs the timer oneshots matching `GATE_PATTERN` and rolls back if one of them fails. `pft-mounts.service` already
keeps `CAP_SYS_PTRACE` for this reason. To list candidates on a host:

```
for u in $(systemctl list-units --all --no-legend --plain 'pft-*.service' | awk '{print $1}'); do
  echo "$u caps=$(systemctl show -p CapabilityBoundingSet --value "$u" | wc -w)"; done
```

## Install, metrics, alert

```
sudo ./install.sh                       # validator: binary, /etc/pft-mounts.env (HOST_LABEL), hourly audit timer
sudo ./install.sh --host sentry         # sentry
sudo ./install.sh --pull                # validator: copy the sentry's textfile every 15 min (PULL_SSH in the env)
```

The hourly `pft-mounts.service` is sandboxed (ProtectSystem=strict, no network, `CAP_DAC_READ_SEARCH
CAP_SYS_PTRACE` only: the second keeps `/proc/1` and postfiatd's `/proc/<pid>` visible if hidepid is enabled). It writes
`pft_mounts_<host>.prom`:

```
pft_mounts_check{host,check,cis,status}          1 PASS, 0 FAIL/WARN (INFO not exported)
pft_mounts_findings{host}                        number of FAIL + WARN
pft_mounts_last_run_timestamp_seconds{host}
```

<a id="alert"></a>One alert, `../alerts/mounts.rules.yml`: **PFTMountHardeningDrift** (`pft_mounts_findings > 0` for
30 min, warning). A stopped audit is caught by pft-rulecheck (`textfile pft_mounts_*.prom 3h`, added by install.sh).
The sentry runs no Prometheus: its alert is evaluated on the validator from the pulled textfile.

## Tests

| what | command |
|---|---|
| lint | `shellcheck mounts/pft-mounts.sh mounts/install.sh mounts/tests/*.sh mounts/drill/*.sh`, `ruff check mounts/tests` |
| offline suite (fake hosts, no root, no real mounts) | `TMPDIR=$HOME/.cache/tmp bash mounts/tests/run-tests.sh` |
| mutants (every gate, live step and grading edge case) | `TMPDIR=$HOME/.cache/tmp python3 -I mounts/tests/mutate.py -j 4` |
| alert rule | `promtool test rules alerts/mounts.tests.yml` |

The suite builds fake hosts (`tests/stubs.sh`): `PFT_MOUNTS_ROOT` prefixes every file, `mount`/`umount`/`nsenter`
edit fake mountinfo files through `tests/fake_mount.py`, and the gate's commands are stubs whose faults fire only
while the fake `/tmp` is noexec (like a fault apply caused). Cases: absent tmpfs, self-binds, `tmp.mount`
enabled/disabled, duplicate/commented/`UUID=`/escaped fstab lines, hidepid variants, root-fs and dedicated-fs data
directories, container down, apt TempDir variants, `--json`, `--prom`, `--textfile`, validate and pull, plan,
apply/rollback byte-identity of fstab and both mount tables, every gate, and the default (`HIDEPID=0`: `/proc`
untouched, no group created). Most cases run with `HIDEPID=1` so the opt-in path is covered too. On a host where `/tmp` is already noexec, set
`TMPDIR` to an exec directory before running the suites (their stubs are executed from a temp dir).

## Live proof (validator + sentry, Ubuntu 22.04, postfiatd 1.0.9 in Docker)

Recorded with `drill/live-run.sh` (orchestrator, agent account on the validator) and `drill/host-run.sh` (root, on each
host), inside one pft-maint window, notifiers on a throwaway topic, an Alertmanager silence for the new add-on's
alerts. No reboot, no postfiatd restart. Final run: [`logs/09-live-run.log`](logs/09-live-run.log), 24 orchestrator
checks ok / 0 failed, sentry host-run 43 PASS / 0 FAIL, validator host-run 29 PASS / 0 FAIL.

**Found -> fixed -> verified** (both hosts had the same stock layout):

| check | before (both hosts) | after apply | verified by |
|---|---|---|---|
| `/tmp`, `/var/tmp` separate + nodev, nosuid, noexec (CIS 1.1.2.1.x, 1.1.2.5.x) | FAIL (8 checks: not a separate mount) | PASS | audit exit 0; exec of a copied `/bin/true` exits 126; a mknod'd char device cannot be opened |
| `/dev/shm` noexec (CIS 1.1.2.2.4) | FAIL | PASS | exec refused (126); nodev control |
| data dir `/var/lib/postfiatd/db` nodev, nosuid (inside the container) | FAIL (2) | PASS | container mount table shows nodev,nosuid; a SUID-root `id` run as uid 65534 from the volume keeps euid 65534 |
| total findings | 11 | 0 | `audit --json` findings 0; Prometheus `pft_mounts_findings` 0 for both hosts; PFTMountHardeningDrift neither pending nor firing |

Every negative control has a positive control in a root-fs directory without the option (same binary runs, same
device reads 1 byte, same SUID binary gives euid 0). Persistence without a reboot: `findmnt --verify` accepts
`/etc/fstab`; `findmnt -s` lists the block; systemd's fstab-generator units (`/run/systemd/generator/*.mount`, what the
next boot mounts) carry the options with `SourcePath=/etc/fstab`; `/dev/shm` (an API mount, handled at boot by
`systemd-remount-fs`) is proven by dropping noexec live and restoring it with an fstab-only `mount -o remount /dev/shm`.
Health: postfiatd `StartedAt` unchanged on both hosts, `server_state` full, sshd -t + :22, every gate oneshot
`Result=success`.

Sentry only (`--drill`): an injected gate miss (`PFT_MOUNTS_INJECT=health`) rolled back on its own (exit 1, fstab
sha256 and every live option as before, still so 75 s later), then apply, then an explicit `rollback --yes` (same
checks), then re-apply. Afterwards: pft-integrity accept on both hosts, `pft-fleet sync` of the manifest,
`pft-fleet skew` exit 0 (mounts CURRENT on both), pft-rulecheck RESULT OK on both, operator topics 0 messages.

The way there, kept as evidence: run 05 ([log](logs/05-live-run-stopped.log)) stopped on a checker bug (it expected
a `dev-shm.mount` unit and read live options from `systemctl show`); probe 06 established the real boot paths. Run 07
([log](logs/07-live-run-stopped.log)) found a **real rollback bug**: rollback unmounted the self-binds before restoring
fstab, and systemd mounted its generated `tmp.mount`/`var-tmp.mount` again 1 s later. Log 08 is the manual reset of the
sentry; the fix (fstab + daemon-reload first, each unmount verified, offline stub that models systemd's queued start,
mutants R1-R3) is in the commit before run 09. Run 09's integrity step filtered only `RESULT` lines, so it does not
name the items it accepted; they were the reinstalled `/usr/local/bin/pft-mounts` (content changed since run 05's
install: the only sha256 change, 1 FAIL item per host) and its units (mtime only: 4 WARN validator, 2 sentry).

| log | what |
|---|---|
| 01-lint, 02-tests, 03-mutants (03a: G9 not applied after the fix, retargeted), 04-promtool | shellcheck + ruff, offline suite, mutant harness, rule check + rule tests |
| 05, 05b, 06, 07, 08 | stopped runs, integrity rebaseline after 05, persistence probe, manual sentry reset |
| 09-live-run | the passing two-host run |

Offline: suite 104/104 (log 02); mutants 46 killed + 2 documented equivalent of 48, 0 survived or not applied (log 03).
