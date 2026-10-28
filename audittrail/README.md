# pft-audittrail: real-time, tamper-evident audit trail

`pft-integrity` compares hashes once an hour. It tells you *what* changed, but not *when*, *by whom* or *with
which command*, and an intruder has up to an hour to change a file and put it back. `pft-audittrail` closes that
gap with two kernel/systemd features that ship with Ubuntu 22.04:

- **auditd** with keyed `-w` watches over the node's config, keys, sshd, sudoers, Docker and the add-on units,
  `execve` logging for `docker`, `systemctl` and `iptables` (`xtables-nft-multi`) run by a logged-in user
  (auid >= 1000 directly or through sudo, or a root login), and time-change and module-load rules. Every event
  carries the **auid** (the login uid, which survives `sudo`).
- **journald** with persistent storage and **Forward Secure Sealing** (FSS). The sealing key on the host evolves
  every `SEAL_INTERVAL` (15 min) and cannot be wound back, so someone who becomes root later cannot rewrite
  older journal entries without `journalctl --verify` noticing. The **verification key** never stays on the host.

It never restarts postfiatd. It restarts journald (apply, rollback) and loads audit rules with `augenrules`.

## Usage

```
pft-audittrail plan     [--container NAME] [--immutable]       # read-only: watched paths, rules file, journald drop-in
sudo pft-audittrail apply --dry-run [--container NAME]         # the same + diff against the installed files
sudo pft-audittrail apply --yes [--immutable] --key-out FILE   # FILE: 0600, receives the FSS verification key
sudo pft-audittrail check [--verify-key-file FILE]             # exit 0 = PASS, 1 = drift
sudo pft-audittrail rollback --yes [--dry-run]                 # exit 2 = immutable, reboot then re-run
sudo pft-audittrail report [--since today|recent|"YYYY-MM-DD HH:MM:SS"]   # Markdown summary
```

Install: `sudo install -m 0755 audittrail/pft-audittrail.sh /usr/local/sbin/pft-audittrail`.
Exit codes: 0 ok/PASS, 1 check failed, 2 rollback pending reboot, 3 usage/config error, 4 refused.
Host-specific settings (e.g. `AGENT_DIRS`, `EXTRA_WATCHES`) go in a root-owned `/etc/pft-audittrail.env`, never
in the repo. Run it on a **sentry first**.

### Watched paths and keys

Paths come from the installer defaults: the node config volume of the container (`postfiatd`, else
`postfiatd-sentry`), the compose files in `/opt/postfiatd`, sshd, sudoers, Docker, every `pft-*`/`postfiat-*`
unit, binary and add-on config that exists. Missing paths are skipped and listed in `plan`. An example rendered on
the validator is in [`pft-audittrail.rules.example`](pft-audittrail.rules.example) (48 rules). Generate the real file
per host with `plan`, do not copy the example.

| key | what |
|---|---|
| `pft-cfg` | node config volume, compose files, `.env` |
| `pft-keys` | validator key material (path printed as `<redacted>` everywhere) |
| `pft-ssh` / `pft-sudo` | `sshd_config(.d)`, root `authorized_keys`, `sudoers(.d)` |
| `pft-docker` | `/etc/docker`, docker/dockerd/containerd binaries |
| `pft-units` | `/etc/systemd/system`, pft-* binaries and env files, this tool itself |
| `pft-agent` | `AGENT_DIRS` (automation agents; redacted) |
| `pft-exec` | execve of docker / systemctl / iptables by auid 0 or auid >= 1000 |
| `pft-time` / `pft-modules` | `/etc/localtime`, `adjtimex`/`settimeofday`/`clock_settime`, `kmod`, module load/unload |
| `pft-canary` | `/var/lib/pft-audittrail/canary`, the test file the drills write to |

`--immutable` adds `zz-pft-audittrail-immutable.rules` (`-e 2`, sorts last). The kernel then refuses every rule
change until the next reboot, including by root. It is off unless you ask for it.

### Boot-time rule load (fixed 2026-10-28)

Ubuntu 22.04's `auditd.service` loads `rules.d` at boot with `ExecStartPost=-/sbin/augenrules --load` and runs with
`ProtectHome=true`, so `/root` is hidden from that load. The `-w /root/.ssh/authorized_keys` watch then fails with
`No such file or directory` and auditctl stops: the first sentry reboot after `apply --immutable` loaded 11 of 42
rules and never reached `-e 2`. A load from a shell (`augenrules --load`) works, so no live apply ever showed it.
`apply` now installs `/etc/systemd/system/auditd.service.d/pft-audittrail.conf` (`ProtectHome=read-only`) and runs
`systemctl daemon-reload`; `check` fails if the drop-in is missing or not loaded yet (`systemctl show -p ProtectHome
auditd` still `yes`) while a watch lives under `/root` or `/home`; `rollback` removes it. Tests: section 9 of
`tests/run-tests.sh` (a simulated boot load inside the sandboxed unit; with the pre-fix script it loads 11/28 rules).
`check` also counts only this tool's own keys now: `dockerd/` loads `-k pft-dockerd` watches, which the old
`pft-` prefix match counted as drift (section 10).
Live proof: a planned sentry reboot after the fix loaded every rule with `enabled 2`
(`dockerd/logs/run-22.log`; the failing boot loads are in `dockerd/logs/run-06.log` and `run-15.log`).

### apply and the verification key

`apply --yes` installs auditd if missing, writes the rules file, loads it, snapshots the loaded `pft-*` rules,
writes the journald drop-in (`Storage=persistent`, `Seal=yes`, **`Audit=yes`**), runs
`journalctl --setup-keys --interval 15min` once, restarts journald and rotates. The verification key goes **only**
to `--key-out FILE` (never stdout, so a `tee`'d log cannot leak it). Move that file to another host (root-only) or
to the operator, then `shred` it here. In the live proof each host's key is stored on the *other* host.

Keep **every** key, including rolled-back ones: each archived journal file verifies only with the key it was sealed
under (`drill-tamper.sh` accepts several `--key`).

### check

auditd active; `auditctl -s` enabled 1 (2 when the immutable file is installed), lost counter; the loaded `pft-*`
rules equal both the rules file and the apply snapshot (a diff of the missing/extra rules is printed, secret paths
redacted); journald drop-in and FSS key present; `journalctl --verify` of every file PASS. With
`--verify-key-file` the seals are verified as well (do that on the verifier host, not on the target).

### report

Counts per key, by auid, by command and by watched object. Usernames other than root/unset become
`u-<sha256(salt+name)[:8]>` (salt in a root-only file); objects under `pft-keys`/`pft-agent` are `<redacted>`;
fd-based events without a path (e.g. `install`'s `fchmod`) are named `(no path: <action>)`.

## Live proof (2026-10-26, sentry first, no postfiatd restart)

All logs are in [`logs/`](logs/README.md), including every failed run. Summary:

| step | sentry-host | validator-host |
|---|---|---|
| before apply: `check` | FAIL exit 1 (no rules, no seal) | FAIL exit 1 (7 checks) |
| apply -> `check` | PASS (36 rules) | PASS (48 rules) |
| pft-integrity accept after each install | 3 accepts (auditd package, apply, re-apply) | PASS 54, nothing to accept |
| drill 1: write to watched canary -> `ausearch -k pft-canary` with auid, counted by `report` | PASS | PASS |
| drill 2: byte-flip a COPY of a sealed journal -> `--verify` FAIL, live files PASS (off-host key) | PASS 7/7 | PASS 7/7 |
| drill 3: `auditctl -D` and `-W` refused while immutable (`-e 2`) | PASS 7/7 | not run (stays mutable) |
| rollback-and-re-apply | PASS 10/10 | not run |
| ruleset drift: drop one watch -> `check` exit 1 naming the rule; the removal itself audited; reload -> PASS | (immutable) | PASS 7/7 |

### What the live runs found (and fixed)

1. **journald switched kernel auditing off.** On systemd 249 `Audit=` defaults to `no`, so the first journald
   restart (to start sealing) logged `CONFIG_CHANGE audit_enabled=0` and `check` failed (sentry run 1). The drop-in
   now sets `Audit=yes`, apply and rollback re-check `auditctl -s` after every journald restart. Unit test: the old
   build fails it.
2. **`rollback` aborted on an empty root prefix** (`${R:?}`) and left auditing disabled (rollback run 1). Fixed,
   regression-tested.
3. **A key change sealed one journal file under two keys.** A journald restart with a new key appends to the
   active file sealed under the old one; that file then fails with *every* key ("Epoch sequence out of
   synchronization"). A restart without a key cannot reopen a sealed active file and journald stays on volatile
   `/run`. apply/rollback now run `journalctl --relinquish-var`, archive the sealed active file under journald's own
   name, restart and `--flush` (rollback run 3 + final). One sentry archive from before the fix remains
   unverifiable; its key is kept and the file is listed in the logs.
4. **Drill-checker bugs** (the checks are code too): a copy of the *active* `system.journal` can tear while
   journald writes (copy is retried, every retry printed); a "flipped copy FAILs" check passed vacuously on
   "Failed to open files"; under `-e 2`, `auditctl -W` prints the refusal but **exits 0**, so refusal is now judged
   by kernel state (rule still loaded), not exit code.
5. **report printed an empty object** for path-less fd events (first live report). Fixed with a real fixture.

## Limits (read before relying on it)

- **Root with physical or console access** can stop auditd, boot another kernel, or delete journal files. FSS
  makes *rewriting* sealed entries detectable, not impossible to delete: missing files and entries after the last
  seal (up to 15 min) are not protected. Ship the logs off-host (see `logship/` when available) for that.
- **Off-host key storage is the whole point.** A verification key left on the host lets an intruder re-seal
  forged files. Keep each key root-only on another machine, keep every old key, and verify there.
- **auditd disk-full behaviour.** Ubuntu's defaults (captured on the sentry) are `space_left_action = SYSLOG`,
  `admin_space_left_action = SUSPEND`, `disk_full_action = SUSPEND`, `disk_error_action = SUSPEND`: when the log
  partition fills, auditd **stops recording** (the node keeps running). `HALT` would stop the host instead, which
  is worse for a validator. pft-audittrail leaves these as they are: monitor disk (the alert rules' disk alert)
  and `lost` in `check`.
- **Immutable mode** needs a reboot for any rule change, including rollback (exit 2; unit-tested, not run live).
  The sentry was left immutable after the drill, on purpose.
- Watches see writes to *paths*: changes made inside a container's mount namespace to files that are not
  bind-mounted, or through a hard link outside the watched tree, are not seen. `pft-integrity` still covers content.
- `check` verifies seals only with `--verify-key-file`; without it, sealed files are counted, not proven.

## Tests

`bash audittrail/tests/run-tests.sh`: 52 offline tests, no root. auditctl, augenrules, ausearch, journalctl,
systemctl, dpkg, apt-get and docker are stateful stubs under a temp root; fixtures in `tests/fixtures/` are real
output captured on the sentry and the validator. `PFT_AT_SCRIPT=<old build>` runs the suite against another build
(used to show each regression test fails on the old code). shellcheck clean (`logs/unit-tests.log`).

Drill scripts: `live-apply.sh`, `drill-tamper.sh`, `drill-rollback.sh`, `drill-immutable.sh`, `drill-drift.sh`.
