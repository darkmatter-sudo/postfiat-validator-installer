# acctpolicy: account and authentication-policy audit with guarded fixes

`pft-acctpolicy` audits the local account database, the PAM stacks, `login.defs` / `useradd` defaults and the node
container's own account files on a Post Fiat validator or sentry (Ubuntu 22.04, postfiatd 1.0.9 in Docker). It fills
the gap between [`privesc/`](../privesc) (sudoers, setuid binaries), [`sshcrypto/`](../sshcrypto) (sshd algorithms)
and [`authwatch/`](../authwatch) (login events): none of them read `/etc/shadow`, `pam.d` or `login.defs`.

A guarded `apply` fixes the safe subset (five checks, four files). It never changes a password, a hash, an SSH key,
an account's shell, home or groups, and never touches `sshd_config` or sudoers.

## Usage

```
pft-acctpolicy audit [--json]        read-only; exit 0 PASS, 1 findings, 2 error
pft-acctpolicy plan                  the fixes apply would make now, as unified diffs (read-only)
sudo pft-acctpolicy selftest         the access self-test apply runs before and after the change
sudo pft-acctpolicy apply --yes      back up, write, self-test; any self-test failure -> byte-identical restore, exit 1
sudo pft-acctpolicy rollback --yes   restore the last apply's files byte-identical (sha256 checked; exit 5 on mismatch)
pft-acctpolicy checks                the check table below
```

Exit codes: 0 ok, 1 findings / self-test failed and restored, 2 error, 3 usage, 4 refused (nothing written),
5 restore mismatch.

Output never contains a password hash or salt: the audit names only the scheme (`yescrypt`, `sha512`, `md5`, ...)
and counts. Account names are not printed either (system accounts are named by UID).

## Checks

| ID | Fix | Checks |
|---|---|---|
| `acct.uid0` | - | only root has UID 0 |
| `acct.dup-uid` | - | no two accounts share a UID |
| `acct.dup-name` | - | no duplicate user or group names |
| `acct.shadowed` | - | every passwd entry has `x` and a shadow entry |
| `acct.empty-password` | - | no empty shadow password field |
| `acct.hash-scheme` | - | every usable hash is yescrypt or sha512 |
| `acct.root-password` | - | a usable root password (console recovery) is only accepted when `sshd -T` has password and keyboard-interactive login off and `permitrootlogin` is not `yes` |
| `acct.system-shell` | - | system accounts (UID 1-999) with a login shell are locked and every key in their `authorized_keys` has `restrict` + `command=` |
| `acct.file-modes` | - | passwd/group (+ `-` backups) 0644 or stricter, shadow/gshadow 0640 or stricter, root-owned |
| `acct.home-modes` | - | human homes (UID >= 1000) are not group-writable or world-accessible |
| `pam.nullok` | `nullok` | `pam_unix` in `common-auth` without `nullok` / `nullok_secure` |
| `pam.permit` | - | `pam_permit.so` is never `sufficient` or a `success=` jump in any auth stack |
| `pam.faillock` | - | `pam_faillock` is configured, or there is no password path to lock out (sshd password + kbd-interactive off and no non-root account with a usable password) |
| `pam.su-wheel` | `su-wheel` | `su` requires membership of `SU_GROUP` (`pam_wheel use_uid`) |
| `login.encrypt` | `encrypt` | `ENCRYPT_METHOD` equals the `pam_unix` password hash (yescrypt or sha512) |
| `login.pass-max` | `passage` | `PASS_MAX_DAYS` <= 365 and `PASS_MIN_DAYS` >= 1 (new accounts only) |
| `login.umask` | - | `UMASK` 022 or stricter |
| `useradd.inactive` | `inactive` | `INACTIVE` in 1..30 |
| `ctr.uid0` | - | container root filesystem: only root has UID 0 |
| `ctr.empty-password` | - | container: no empty shadow field, no hash in passwd |
| `ctr.runtime` | - | container not privileged, `no-new-privileges`, cap-drop ALL |

The container checks read the container's files from the host through `/proc/<pid>/root` and its settings through
`docker inspect`. Nothing runs inside the container: its AppArmor profile denies shell tools, and every denial would
count against [`apparmor/`](../apparmor) and [`seccomp/`](../seccomp).

## Fixes and their guards

| Fix | File | Change | Precondition |
|---|---|---|---|
| `nullok` | `/etc/pam.d/common-auth` | drop `nullok` from `pam_unix` | `acct.empty-password` PASS |
| `su-wheel` | `/etc/pam.d/su` | `auth required pam_wheel.so use_uid group=SU_GROUP` on its own line after `pam_rootok` (root keeps su) | `SU_GROUP` (default `sudo`) exists, a `pam_rootok` line exists |
| `encrypt` | `/etc/login.defs` | `ENCRYPT_METHOD` = the `pam_unix` hash | that hash is yescrypt or sha512 |
| `passage` | `/etc/login.defs` | `PASS_MAX_DAYS 365`, `PASS_MIN_DAYS 1` | - (applies to accounts created later; existing accounts' aging is not touched, so no expiry can block sudo) |
| `inactive` | `/etc/default/useradd` | `INACTIVE=30` | the file exists |

`apply` refuses (exit 4, nothing written) without `--yes`, while a previous apply is still in place, when the node is
not `full` with at least `MIN_PEERS` peers, when a fix cannot be built for the file's shape, or when the self-test
already fails before any change. Then it backs up every target file (bytes, mode, owner, sha256) to
`/var/lib/pft-acctpolicy/backup/<id>/` (0700), writes the new files in place keeping mode and owner, and runs the
self-test again. Any failure restores every file byte-identical and exits 1.

The self-test (`selftest`):

1. `sshd -t` on the real configuration;
2. SSH-key login + `sudo -n true`: a throwaway sshd on `127.0.0.1:<random port>` with a minimal private config
   (`UsePAM yes`, so `/etc/pam.d/sshd` and the `common-*` stacks run account and session), the self-test key
   (`/var/lib/pft-acctpolicy/selftest_ed25519`, root 0600) in a private `AuthorizedKeysFile` and its log in a private
   file (`-E`). The real sshd is not restarted or reconfigured, no `authorized_keys` file is touched, and no
   `Accepted` line reaches the journal; `install.sh` also allowlists the key's fingerprint in authwatch;
3. root `su` to a system account (pam_rootok still passes);
4. the node is `full` with at least `MIN_PEERS` peers.

`VERIFY_INJECT=selftest` fails only the post-change self-test: the live automatic-restore drill.

## Install

```
sudo ./install.sh              # /usr/local/bin/pft-acctpolicy, /var/lib/pft-acctpolicy, self-test key + authwatch allowlist entry
sudo ./install.sh --uninstall  # refuses while an apply is in place
sudo pft-integrity accept --reason "acctpolicy install"
```

The script is in [`../fleet/manifest.tsv`](../fleet/manifest.tsv) (both roles).

## Tests

```
TMPDIR=$HOME/.cache bash acctpolicy/tests/run-tests.sh   # offline: fixture root, stub sshd/docker/sudo/self-test
python3 -I acctpolicy/tests/mutants.py -j 4              # every mutant must be caught
shellcheck acctpolicy/*.sh acctpolicy/tests/*.sh
```

`run-tests.sh` gives every check ID a PASS fixture and a non-PASS fixture, and every apply/rollback guard a test
whose input passes every other guard and asserts that no file was written (sha256 + mode of all four targets, no
state, no backup). `mutants.py` breaks one check or guard per mutant (one or more per check ID).

## Live results (validator + sentry, 2026-11-18)

Recorded with [`drill/live-run.sh`](drill/live-run.sh) at `5f42949` ([logs/03](logs/03-live-run-02.log), 0 checks
failed). Both hosts had the same five WARN findings and 0 FAIL before the run; all five are fixed and verified:

| Check | Found (both hosts) | Fixed | Verified |
|---|---|---|---|
| `pam.nullok` | `pam_unix ... nullok` in common-auth | `nullok` removed | PASS |
| `pam.su-wheel` | no `pam_wheel` in `/etc/pam.d/su` | `pam_wheel use_uid group=sudo` after `pam_rootok` | PASS |
| `login.encrypt` | `ENCRYPT_METHOD SHA512` vs pam_unix yescrypt | `ENCRYPT_METHOD YESCRYPT` | PASS |
| `login.pass-max` | `PASS_MAX_DAYS 99999`, `PASS_MIN_DAYS 0` | 365 / 1 (new accounts only) | PASS |
| `useradd.inactive` | `INACTIVE=-1` | `INACTIVE=30` | PASS |

The run also proves, on both hosts: the self-test before and after each apply (sshd -t, SSH-key login + `sudo -n`
through the throwaway sshd, root su, node full); the real access paths after the fixes (`sudo -n` on both hosts, the
sentry's real sshd taking the agent's key, `sshd -t`); `rollback` and a `VERIFY_INJECT=selftest` apply each leave the
four files byte-identical (sha256, mode, owner) to the pre-apply state; the final apply; `pft-integrity` PASS
(baseline accepted), schedaudit 0 new/removed, aptrust 0 warn/0 fail, `pft-fleet skew` CURRENT, no new
non-allowlisted login in authwatch and 0 `Accepted ... from 127.0.0.1` journal lines, 0 AppArmor/seccomp denials,
nodes full, and 0 messages on every operator topic (pft-maint's `[MAINT]` messages went to a throwaway topic).

| Log | What |
|---|---|
| [01](logs/01-mutants-c7edb98-baseline-fail.log) | mutation run at `c7edb98`: the unmutated suite failed one test under umask 022 (it compared with the fixture's own mode), so the run is not evidence; test fixed, and `mutants.py` now refuses to run mutants when the baseline fails |
| [02](logs/02-live-run-01-fleet-refused.log) | live run 01: pft-fleet refused a commit not yet in `main`; nothing was written on either host |
| [03](logs/03-live-run-02.log) | live run 02: found -> fixed -> verified, rollback + inject drills, baselines, operator topics 0 |
| [04](logs/04-fresh-clone.log) | anonymous public clone: script sha256 = installed on both hosts, shellcheck, ruff, suite (umask 022 + 002), mutants |
