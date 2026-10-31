# pft-privesc: local privilege-escalation path audit and safe, reversible fixes

The other security add-ons each own one surface: `../audit` (SSH login settings, firewall, docker.sock mode, docker
group count, privileged containers), `../sysctl` (kernel), `../confine` (container profile), `../unitguard`
(sandboxing of the pft-* units), `../secrets` (key files), `../sshcrypto` (SSH crypto). None of them asks the
question an attacker with a local unprivileged shell asks: **which path gets me to root?** This add-on checks five:

1. **suid**: every SUID/SGID file and every file with capabilities on the root filesystem, against dpkg: unpackaged
   (FAIL), md5sum changed per `dpkg --verify` (FAIL), not root-owned or writable (FAIL), stock but not needed on a
   headless node (WARN: `pkexec`, `polkit-agent-helper-1`, `chfn`, `chsh`, `fusermount3`, `ssh-keysign`;
   `gst-ptp-helper` capabilities), needed (PASS).
2. **sudoers**: `visudo -c`, owner/mode of every file sudo reads (same include rules as sudo: names with a dot or a
   trailing `~` are skipped), commands that are relative or writable by non-root, NOPASSWD commands that can spawn a
   shell, wildcard arguments, `!env_reset` and `env_keep` of loader/interpreter variables (`LD_PRELOAD`, `PYTHONPATH`,
   ...), missing `secure_path`/`use_pty`.
3. **exec**: every loaded root unit (`User=` empty or root): each Exec* binary, script arguments (`/bin/sh /opt/x.sh`),
   the unit file and drop-ins; every cron file, run-parts script and absolute command a cron line runs. A path counts
   as writable if it **or any parent directory** is owned by a non-root uid, world-writable, or group-writable by a
   non-root group (sticky parents such as `/tmp` are fine); symlinks are resolved and the target checked too.
4. **path**: the root PATHs (systemd's built-in search path, sudo `secure_path`, `/etc/environment`): relative or
   empty entries, writable directories (or a writable parent of a missing one), and every file in them.
5. **rooteq**: root-equivalent access that bypasses sudo: members (supplementary or primary) of `docker`, `lxd`,
   `disk` who do not already have a full sudo rule (FAIL; with full sudo: INFO; no-login service accounts: INFO),
   the containerd/lxd sockets open to others, running containers that bind-mount a runtime socket, `/run` or `/`.

Not repeated here: `docker.sock` mode/group (`../audit` `docker.socket`), privileged containers and capabilities
(`../audit`), sandboxing of the pft-* units (`../unitguard`).

Target: Ubuntu 22.04.5 (sudo 1.9.9, systemd 249, dpkg 1.21.1) on a validator host and a sentry host. Live two-host
proof (install, audit, apply, re-audit, planted-fixture undo drill): [Live proof](#live-proof).

**One Prometheus for both hosts** (same design as `../sshcrypto`, `../vulnscan`): each host audits itself every
hour; `pft-privesc pull` on the validator copies the sentry's textfile over the existing admin ssh link (validated,
all-or-nothing) and the validator's Prometheus alerts on both (`host="validator"`, `host="sentry"`). The sentry runs
no Prometheus or Alertmanager of its own.

**Shareable output.** Account names are printed as `acct-<first 8 hex of sha256(machine-id:name)>` (also inside
`/home/<name>` paths; keyed by `/etc/machine-id`, because a bare hash of a short name is reversed by guessing) unless
`--show-names` is given, so an audit can be pasted into a ticket without user names. Metrics carry
counts only.

## Usage

```
sudo pft-privesc audit [--json] [--show-names] [--textfile-dir DIR]   read-only audit
sudo pft-privesc apply [--dry-run] [--only ID,ID]                     fix what apply may fix (below)
sudo pft-privesc undo                                                 restore every applied change
pft-privesc status                                                    recorded changes, last undo
sudo pft-privesc pull                                                 validator: copy the sentry's textfile
pft-privesc validate FILE HOST                                        check a textfile before it is served
pft-privesc ids                                                       print the check ID table below
```

| command | exit 0 | exit 1 | exit 2 | exit 3 |
|---|---|---|---|---|
| audit | no WARN or FAIL | at least one WARN or FAIL | collection error (dpkg-statoverride, systemctl show, getent or docker ps failed) | - |
| apply | applied (re-audit printed) or nothing to do | - | refused, nothing changed: `visudo -c` fails, `AGENT_USER` cannot `sudo -n true`, audit error | a change or a post-change check failed: every change of this run was undone at once |
| undo | every entry restored and verified | - | nothing to undo, or a verification failed (manifest kept) | - |

Text output: one line per finding (`GRADE ID subject: detail  -> hint`) and a `RESULT:` line. `--json` prints one
object with `result`, `exit`, `fail`, `warn`, `fixable`, `errors[]` and `findings[]` (`id`, `area`, `grade`,
`subject`, `detail`, `hint`).

**Search scope.** `find / -xdev` (the root filesystem; snaps are separate read-only mounts) without descending into
directories that no non-root user can traverse (root-owned, no `o+x`, and group root or no `g+x`: e.g.
`/var/lib/containerd`, `/var/lib/docker`, whose image layers hold copies of `su`/`passwd` that no local user can
reach). With usrmerge, dpkg knows some files as `/bin/x`, `/sbin/x` or `/lib/x`: the owner lookup tries both names,
and `/bin` and `/usr/bin` are checked once as a PATH dir.

## Check IDs

| ID | area | meaning |
|---|---|---|
| `PE-SUID-OK` | suid | dpkg-owned, unmodified, root-owned, not writable, needed (PASS) |
| `PE-SUID-UNNEEDED` | suid | dpkg-owned SUID/SGID with no use on a headless node (WARN; apply: statoverride) |
| `PE-SUID-REMOVED` | suid | unneeded bit already removed by a dpkg-statoverride (PASS) |
| `PE-SUID-REVIEW` | suid | dpkg-owned SUID/SGID not on the keep or unneeded list (WARN, review) |
| `PE-SUID-UNPKG` | suid | SUID/SGID file no package owns (FAIL; apply strips it only if in REMOVE_SUID) |
| `PE-SUID-MODIFIED` | suid | dpkg --verify: md5sum differs from the package (FAIL) |
| `PE-SUID-WRITABLE` | suid | SUID/SGID file or a parent dir writable by non-root (FAIL; apply: chmod go-w) |
| `PE-SUID-OWNER` | suid | SUID/SGID file not owned by root (FAIL; apply: chown root, only if dpkg-owned) |
| `PE-CAP-OK` | suid | file capabilities on an allowlisted dpkg-owned binary (PASS) |
| `PE-CAP-UNNEEDED` | suid | file capabilities with no use on a headless node (WARN; apply: setcap -r) |
| `PE-CAP-REVIEW` | suid | file capabilities on another dpkg-owned binary (WARN, review) |
| `PE-CAP-UNPKG` | suid | file capabilities on a file no package owns (FAIL) |
| `PE-SUDO-SYNTAX` | sudoers | visudo -c fails (FAIL) |
| `PE-SUDO-PERM` | sudoers | sudoers file not root:root or group/world-writable (FAIL; apply: chown + chmod 0440) |
| `PE-SUDO-CMD-WRITABLE` | sudoers | a sudo rule names a command whose path is writable by non-root (FAIL) |
| `PE-SUDO-CMD-RELATIVE` | sudoers | a sudo rule names a relative command (FAIL) |
| `PE-SUDO-SHELLESC` | sudoers | NOPASSWD rule for a command that can spawn a shell (WARN) |
| `PE-SUDO-WILDCARD` | sudoers | rule with a * wildcard in command arguments (WARN) |
| `PE-SUDO-ENV` | sudoers | env_keep/setenv lets a loader/interpreter variable through, or !env_reset (FAIL) |
| `PE-SUDO-DEFAULTS` | sudoers | Defaults secure_path / use_pty missing (WARN) |
| `PE-SUDO-ADMIN` | sudoers | full-root rule (ALL commands); names hashed unless --show-names (INFO) |
| `PE-SUDO-OK` | sudoers | visudo OK, every file root:root and not writable (PASS) |
| `PE-EXEC-UNIT` | exec | root unit runs a file (or a script argument) writable by non-root (FAIL; apply: chmod go-w) |
| `PE-EXEC-UNITFILE` | exec | unit file or drop-in of a root unit writable by non-root (FAIL; apply: chmod go-w) |
| `PE-EXEC-CRON` | exec | cron file, cron script or a command it runs writable by non-root (FAIL; apply: chmod go-w) |
| `PE-EXEC-OK` | exec | every root unit and cron exec chain checked clean (PASS) |
| `PE-PATH-REL` | path | empty or relative entry in a root PATH (FAIL) |
| `PE-PATH-DIR` | path | root PATH directory (or a parent) writable by non-root (FAIL; apply: chmod go-w) |
| `PE-PATH-FILE` | path | file in a root PATH directory writable by non-root (FAIL; apply: chmod go-w) |
| `PE-PATH-OK` | path | every root PATH entry and its files checked clean (PASS) |
| `PE-ROOTEQ-GROUP` | rooteq | member of docker/lxd/disk without a full sudo rule = hidden root (FAIL) |
| `PE-ROOTEQ-ADMIN` | rooteq | member of a root-equivalent group who already has full sudo (INFO) |
| `PE-ROOTEQ-SERVICE` | rooteq | no-login service account in a root-equivalent group, e.g. the lxd daemon user (INFO) |
| `PE-ROOTEQ-SOCK` | rooteq | containerd/lxd/docker runtime socket readable or writable by others (FAIL; apply: chmod o-rwx) |
| `PE-ROOTEQ-MOUNT` | rooteq | running container bind-mounts a runtime socket or the host root (FAIL) |
| `PE-ROOTEQ-OK` | rooteq | no hidden root-equivalent access (PASS) |

## apply and undo

`apply` changes only **permission metadata of the exact file a finding names**, never contents, accounts, group
membership or sudo rules:

| change | used for | how | undo |
|---|---|---|---|
| `chmod` | writable SUID file, unit/cron/PATH/sudo-command file or parent dir, runtime socket | drop group/other write (`o-rwx` on a socket) | old mode |
| `chown` | dpkg-owned SUID file owned by another uid | `chown 0:<gid>`, then the old mode again (chown clears SUID) | old uid:gid, then old mode |
| `sudoers-fix` | sudoers file not root:root 0440 | `chown 0:0` + `chmod 0440`, then `visudo -c` + agent check at once | old uid:gid + mode |
| `suid-remove` | unneeded dpkg-owned SUID/SGID | `dpkg-statoverride --update --add <owner> <group> <mode-without-s> <dpkg path>`: survives package upgrades; a replaced override is recorded | `dpkg-statoverride --remove`, re-add any replaced override, old mode |
| `suid-remove` | unpackaged SUID file listed in `REMOVE_SUID` | plain `chmod` | old mode |
| `cap-remove` | unneeded file capabilities | `setcap -r` (a package upgrade restores them: the audit WARNs again) | `setcap <recorded caps>` |

Guards:
- **Agent sudo is kept.** `AGENT_USER` (set by install.sh from `$SUDO_USER`) must pass `runuser -u AGENT -- sudo -n
  true` before apply starts, after every sudoers change, and at the end; otherwise every change of the run is undone
  and apply exits 3. apply refuses to start without `AGENT_USER`.
- **`visudo -c`** must pass before apply starts (else nothing changes) and after every sudoers change.
- **PROTECTED** (`/usr/bin/sudo`, `su`, `passwd`, `unix_chkpwd`) are never changed, also when a finding names
  them through an alias such as `/bin/sudo` (checked by resolved path). A problem there is a FAIL for a human.
- **Record first.** Each change is appended to `/var/lib/pft-privesc/backup/manifest.tsv` (root 0600) *before* it
  is made: old mode, uid, gid, statoverride or capabilities, sha256 of the file. `--dry-run` prints the plan and
  changes nothing; `--only ID,ID` limits the plan.
- **undo** walks the manifest newest-first and requires, for every entry, `stat` == recorded and sha256 unchanged
  (a file whose contents changed since apply is reported, not silently re-permissioned), then `visudo -c` and the
  agent sudo check. On success the manifest moves to `last-undo/`; on any failure it is kept and undo exits 2.

## Install

```
sudo privesc/install.sh                  # validator (sentry: --host sentry); AGENT_USER = $SUDO_USER (or --agent)
sudo privesc/install.sh --pull           # validator: needs PULL_SSH (+ PEER_LABEL) in /etc/pft-privesc.env
sudo cp alerts/privesc.rules.yml /etc/pft-alerts/  # listed in ../alerts/prometheus.yml
sudo pft-integrity accept --reason "pft-privesc installed"
```

`pft-privesc.service` runs the audit as root in a systemd sandbox: read-only filesystem except the textfile dir,
`CapabilityBoundingSet=CAP_DAC_READ_SEARCH` (search every directory, change nothing), `AF_UNIX` only (docker.sock),
idle I/O class. Hourly timer; the sentry copy is pulled every 15 minutes.

## Metrics

| metric | meaning |
|---|---|
| `pft_privesc_up{host}` | 1 if every fact was collected (0 = audit error, counts are not trustworthy) |
| `pft_privesc_last_run_timestamp_seconds{host}` | time of the last audit |
| `pft_privesc_findings{host,area,grade}` | findings per area (`suid`, `sudoers`, `exec`, `path`, `rooteq`) and grade (`pass`, `info`, `warn`, `fail`) |
| `pft_privesc_fixable{host}` | findings `apply` would fix |
| `pft_privesc_backup_entries{host}` | applied changes not yet undone |

## Alerts

`../alerts/privesc.rules.yml`, unit tests in `../alerts/privesc.tests.yml` (`promtool test rules`):

| alert | when | severity |
|---|---|---|
| `PFTPrivescFail` | any FAIL finding for 10 min | critical |
| `PFTPrivescWarn` | any WARN finding for 6 h | warning |
| `PFTPrivescAuditFailing` | `up == 0` for 10 min | warning |
| `PFTPrivescStale` | no audit for 3 h (timer stopped, sentry pull broken) | warning |

## Tests

```
tests/run-tests.sh        stubbed suite: fake root + stubs for dpkg, dpkg-statoverride, getcap/setcap, systemctl,
                          getent, docker, visudo, runuser, chown; no root needed, no host file touched
tests/test_owner.py       owner/group-based checks (files owned by another uid/gid), via a patched os.lstat
tests/mutate.py           mutation check: each mutant must make one of the suites FAIL (a hang counts as caught)
```

The test user stands in for root inside the fake root (`PFT_PE_ROOT_UID`), so ownership by another uid cannot be
built there; `test_owner.py` covers those cases by patching `os.lstat`/`os.stat`.

## Live proof

Run on 2026-10-31 on the validator and the sentry (Ubuntu 22.04.5), code as in commit `550d325` (installed
`pft-privesc` sha256 `3ae4146f...`, classifier `289bc9f2...`, the same digests as the offline logs 01-05; full
digests in the log headers). Logs in `logs/`; the runner scripts are in `drill/` byte-identical to what ran
(`install-run.sh` -> 06, `fleet-run.sh` -> 07, `host-run.sh` -> 08/09, `post-run.sh` -> 10). Logs 06, 07 and 10
pass every output line and echoed command through a redaction filter (home dir, user name, IPv4 addresses), which
also masks the loopback address `127.0.0.1` as `<redacted-ip>`.

| log | what | result |
|---|---|---|
| 06-install-two-hosts | rollout silence, install on sentry then validator (twice each), validator pull of the sentry file, rules loaded (HUP), Prometheus sees `pft_privesc_up` 1 for both hosts, integrity accept, rulecheck | 14 ok, **2 FAIL**: `pft-fleet sync` REFUSED (no pft-maint window), so skew stayed BEHIND for the fleet manifest |
| 07-fleet-sync | the fix: pft-maint window (its `[MAINT]` messages sent to a throwaway topic and read back), `pft-fleet sync --addon fleet`, skew exit 0 (privesc CURRENT on both hosts), real target restored | 7/7 ok |
| 08-drill-validator | `drill/host-run.sh` on the validator | 13/13 checks PASS |
| 09-drill-sentry | the same script on the sentry | 13/13 checks PASS |
| 10-post-drill | applied state on both hosts, agent sudo works, integrity PASS, fresh audits through the units + pull, Prometheus `fail 0 / warn 0` for both hosts, no privesc alert pending/firing, silence expired, both nodes `full` | 7/7 ok |
| 11-lint-runners | shellcheck of the tool + the four drill runners (the three new runners only report SC1091 info: sourcing `/etc/os-release`), `git diff --stat 550d325 HEAD` over the code, units, tests and rules = empty, ruff | clean |

**Found -> fixed -> verified** (identical on both hosts, logs 08 and 09 step 1-2): the first audit graded
`RESULT: WARN - 0 fail, 7 warn, 7 fixable by apply` (exit 1): SUID bits a headless node does not need on `chfn`,
`chsh`, `pkexec`, `fusermount3`, `ssh-keysign`, `polkit-agent-helper-1` (PE-SUID-UNNEEDED) and the file capabilities
of `gst-ptp-helper` (PE-CAP-UNNEEDED). No FAIL item on either host. `apply` removed them (SUID via
`dpkg-statoverride --update`, so package upgrades keep the change; `setcap -r` for the capability), and the
re-audit printed `RESULT: PASS - 0 fail, 0 warn` (exit 0). The applied state is kept on both hosts (log 10:
`applied changes: 7`, `apply --dry-run`: nothing to apply).

**Planted-fixture undo drill** (steps 3-8): an unpackaged SUID copy of `/usr/bin/true`, a world-writable
`/etc/cron.d` file (comment only) and a world-writable script in `/usr/local/bin` were each graded FAIL with the
expected ID (PE-SUID-UNPKG, PE-EXEC-CRON, PE-PATH-FILE; `3 fail, 2 fixable`: an unpackaged SUID file is only stripped
when listed in `REMOVE_SUID`, which the drill adds for step 5 only). apply fixed all three (PASS), `undo` restored
all 10 recorded changes, and the post-undo audit showed the original 7 WARN lines and the 3 fixtures again, with
mode, owner, capabilities and the statoverride list equal to step 1. Then the fixtures were removed, the real fixes
re-applied and the final state compared equal to the step-2 fixed state.

pft-integrity tracks none of the changed binaries (verify stayed PASS); log 10 still records an accept after the
apply. The alert rules were not drilled live: they are covered by `promtool test rules` (log 05); during the
rollout and both drills an Alertmanager silence covered `PFTPrivesc*`, `PFTRuleDead`, `PFTTextfileStale`,
`PFTRulecheck*` and `PFTFleet*` (expired in log 10).

