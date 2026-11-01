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

`rollback` restores the newest fstab backup (sha256 compared), reverts every live step from `live.state` in reverse
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
| lint | `shellcheck mounts/pft-mounts.sh mounts/install.sh mounts/tests/*.sh`, `ruff check mounts/tests` |
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

## Live proof

Pending: sentry first, then validator (see the commit that adds `mounts/logs/`).
