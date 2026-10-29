# patch/ — controlled OS patching for a validator + sentry

`pft-patch.sh` moves Ubuntu updates and reboots on a Post Fiat node host out of the random daily
unattended-upgrades slot and into a planned, gated, sentry-first maintenance window.

Why: on a stock Ubuntu 22.04 node host, `unattended-upgrades` installs packages from
`${distro_codename}` and `${distro_codename}-security` every day at a random time, with an empty
`Package-Blacklist`. `docker.io`, `containerd` and `runc` come from the Ubuntu archive, so an unattended
upgrade of one of them restarts dockerd/containerd, i.e. restarts postfiatd at an unplanned moment,
outside any maintenance window and without a health gate. Reboots needed by kernel updates are never
taken at all unless someone notices `/var/run/reboot-required`.

> Status: build 5 (`status`, `policy`, `run`, offline tests and mutants, live drill wrapper). The live two-host proof and its
> logs are added to this README when they have run.

## Modes

| command | changes the host? | what it does |
|---|---|---|
| `pft-patch status [--json]` | no | pending updates by class, holds, reboot/kernel state, services on old libraries, unattended Docker-runtime exposure |
| `pft-patch policy show` | no | prints the apt drop-in `policy apply` would install |
| `sudo pft-patch policy apply --yes` | yes | installs `/etc/apt/apt.conf.d/52pft-patch`, checks the **effective** apt config, backs up first |
| `sudo pft-patch policy rollback --yes` | yes | restores the state before the newest apply, checks it byte for byte |
| `sudo pft-patch run --yes [--hosts sentry,validator] [--all] [--runtime]` | yes | patches the hosts one at a time, sentry first, with gates, windows and silences (below) |
| `sudo pft-patch upgrade --yes [--all] [--runtime]` | yes | the per-host step `run` calls on each host (over ssh for the sentry) |
| `pft-patch host-info` | no | `boot=<boot id> dpkg=<sha256 of dpkg.log> reboot=<0/1>`, used for reboot detection and the untouched proof |
| `sudo pft-patch resume` | yes | started at boot by `pft-patch-resume.service` after `run` rebooted the local host |

### status

`status` only reads: `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (a simulation that takes no lock),
`apt-mark showhold`, `/var/run/reboot-required(.pkgs)`, `needrestart -b -r l` (list mode, restarts
nothing), `apt-config dump` and `dpkg-query`. The offline suite checks that the fake host's files are
unchanged after `status` and that `apt-get` is only ever called with `-s`.

| item | OK | WARN (exit 1) | CRIT (exit 2) |
|---|---|---|---|
| updates | none pending | non-security updates pending (kernels counted) | any update whose candidate comes from a `*-security` pocket |
| holds | no holds | held packages, none with an update | a held package has an update waiting |
| reboot | no flag | | `/var/run/reboot-required` present (packages listed) |
| kernel | needrestart KSTA 1 | KSTA 2/3: a newer kernel is installed but not running | |
| services | none | services still running old libraries | |
| exposure | every installed runtime package is blacklisted | an installed Docker runtime package (`docker.io docker-ce docker-ce-cli containerd containerd.io runc`) is not in the effective `Unattended-Upgrade::Package-Blacklist` | |
| autoreboot | `Automatic-Reboot` false (default) | `Automatic-Reboot` true | |

An update counts as security when its candidate's origin list contains a `-security` pocket
(`Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security`); third-party repos are "other".
needrestart only reports the kernel state as root; run without root, `status` says so (INFO) instead of
reporting a clean kernel. `--json` gives the same data as one object (`result`, `exit`, `updates`,
`holds`, `reboot_required`, `needrestart`, `unattended`, `items`).

### policy

The drop-in keeps unattended **security** updates on for everything else and only takes out the two
things that touch postfiatd:

```
Unattended-Upgrade::Package-Blacklist {
    "docker.io"; "docker-ce"; "docker-ce-cli"; "containerd"; "containerd.io"; "runc";
};
Unattended-Upgrade::Automatic-Reboot "false";
```

- apt merges lists across `apt.conf.d` files and the last file wins for a scalar. A later file (say
  `99local` with `Automatic-Reboot "true"`) would silently beat ours, so `apply` re-reads the
  **effective** config with `apt-config dump` after installing the file. If any runtime package is not
  blacklisted or Automatic-Reboot is not false, it puts the previous state back and exits 4.
- unattended-upgrades matches blacklist entries as Python regexes with `re.match` (anchored at the
  start, not the end). `status` uses the same rule, so `docker` covers `docker.io` but `io` does not.
- Before writing, `apply` stores in `/var/lib/pft-patch/backup/<UTC stamp>/` the drop-in's previous
  bytes (or an `absent` marker) and the sha256 of the full `apt-config dump`. `rollback` restores the
  newest backup and requires both the drop-in sha256 and the `apt-config dump` sha256 to equal the
  recorded ones (exit 5 otherwise, backup kept). A second `apply` with the same content is a no-op and
  makes no backup.

Exit codes: `status` 0/1/2 as above. `policy`: 0 done or already applied, 2 error, 3 usage,
4 refused (not root, no `--yes`, not effective), 5 rollback mismatch.

### run

Install: `sudo ./install.sh` on the validator (binary, `/etc/pft-patch/hosts.conf`, resume unit) and
`sudo ./install.sh --host-only` on the sentry. `hosts.conf` lists the hosts in patch order, same format as
`rollout/` (`host LABEL local|ssh SSH_TARGET CONTAINER MIN_PEERS`, plus `post LABEL COMMAND` hooks run after a
reboot). The first line (the sentry) is always patched first, whatever order `--hosts` names; the local host
must be last because it may reboot.

```
preflight (nothing changes if any of it fails, exit 4)
  no other run (flock), no pending resume record, no pft-maint data-collection lock,
  every selected host reachable with pft-patch installed; record boot id, dpkg.log sha256, container StartedAt
per host, in order:
  STATUS before         pft-patch status --json (one line)
  GATE pre              node full|proposing, peers >= MIN_PEERS, validated ledger age <= 20 s;
                        pft-integrity verify exit 0; pft-audittrail check and pft-egress check (where installed)
  WINDOW                pft-maint start (validator flag, pushed to the sentry) + Alertmanager silence
                        (every alert except the pipeline watchdog, below)
  upgrade               apt-get update; install --only-upgrade of the selected packages (below)
  DECISION              reboot | restart <services> | none (below)
  REBOOT (if decided)   remote: systemd-run --on-active=5 systemctl reboot, wait for a NEW boot id,
                        run the host's post hooks (e.g. pft-egress reapply);
                        local: write resume.json, reboot in 15 s, exit 10; resume runs the rest at boot
  GATE post             the pre-gate checks, the node check waits up to GATE_TIMEOUT (1800 s) for full,
                        plus: no reboot-required flag left; the egress check is retried until GATE_TIMEOUT
                        (it also wants peers >= its apply-time baseline); after a reboot of THIS host, integrity items
                        that changed only their mtime are accepted (below), then a fresh verify decides
                        containers: every container running before the host step must run again; after a
                        reboot of THIS host each missing one gets ONE `docker start` (dockerd once left
                        pft-prometheus Exited (255), "layer not mounted", after a reboot in live drill B); without
                        a reboot nothing is started, the gate waits up to GATE_TIMEOUT and then fails
  STATUS after, WINDOW close
any failure -> STOP: window ended, silence expired (real alerts flow again), every later host is checked
  against its preflight record (UNTOUCHED / CHANGED), exit 1 (or 5 if a later host changed)
```

Every transition fails closed: an unreachable host, an ssh error, a failed `pft-maint start`, a silence the
Alertmanager did not confirm, an apt error, a failed service restart, a reboot that does not come back within
REBOOT_TIMEOUT (600 s), or any gate check stops the run before the next host. Installed packages are not rolled
back (apt cannot do that safely); the stop leaves the failed host as it is and alerting live.

**Security-only vs `--all`.** By default only packages whose candidate comes from `*-security` are installed,
the same set unattended-upgrades would install, just at a planned moment and gated. `--all` adds everything
else `apt-get -s dist-upgrade` would upgrade (jammy-updates, third-party repos, kernel meta packages). New
packages (e.g. the next kernel ABI) are never named; apt pulls them in as dependencies. Held packages are always
skipped (`SKIP pkg held`). The Docker runtime packages (`RUNTIME_PKGS`) are skipped unless `--runtime` is
given, because upgrading them restarts dockerd and therefore postfiatd; with `--runtime` the post-gate (node,
egress jump) covers that restart.

**Reload vs reboot.** After the install the host step decides, in this order:

| condition | decision | why |
|---|---|---|
| `/var/run/reboot-required` exists | reboot | Ubuntu packages (kernel, libc, systemd, linux-base) set it when only a reboot activates the update |
| needrestart kernel state KSTA 2 or 3 | reboot | a newer kernel is installed than the one running |
| needrestart lists services on old libraries | `systemctl restart` each | a library update (e.g. libssl3) needs only the processes using it restarted; the node keeps running |
| ... but the service matches `NO_RESTART_RE` | DEFERRED | docker/containerd (restarting them restarts postfiatd), dbus, logind, user/getty sessions: picked up at the next planned reboot |
| nothing | none | no restart |

**Integrity after a reboot.** A reboot rewrites some covered files with identical bytes: on the sentry,
cloud-init's init stage touches `/etc/ssh/sshd_config` at every boot (mtime changes, sha256 does not), so
`pft-integrity verify` WARNs `sshd:sshd_config changed mtime`. pft-integrity reports a content change as
`sha256` (FAIL), so a finding whose only detail is `mtime` means identical content. The post-gate of a host
that pft-patch itself rebooted in this run (or resumed after its local reboot) accepts such findings, and only
when every finding is a `[WARN] ITEM changed mtime` line: `pft-integrity accept --reason "pft-patch <run> <host>
reboot: mtime-only <items>"`, then verifies again and the gate uses that result. Never at the pre-gate, never
without a reboot, never when any other finding is present.

**Silence scope.** The silence matches `alertname=~".+"` and `alertname!="PFTAlertPipelineWatchdog"`
(`WATCHDOG_ALERT`). The always-firing pipeline watchdog (`../alertpath`) must keep arriving at the sentry's
sink: a silence that also matched it would make alertpath report STALE after 180 s and page the operator in
the middle of every run longer than three minutes. (Found while preparing the live drill, before any live run.)

The run's Alertmanager silence is expired when the host had no restart, and kept `SILENCE_TAIL` (900 s) longer
after a reboot or service restart, because restart-related rules (e.g. a container start) stay true for a while.

**Drill hooks.** `PFT_PATCH_INJECT=sentry-postgate` makes the sentry's post-gate fail AFTER all real checks ran,
with its own line `GATE post sentry INJECTED-FAILURE: drill ..., not a host fault`, so the stop path (validator
untouched) can be proven on live hosts without breaking anything. `PFT_PATCH_INJECT=<host>-reboot` replaces
that host's decision with a reboot (`DECISION <host>: host decided '<real decision>'; INJECTED reboot: drill`),
so the reboot path (wait for a new boot id, post hooks, post-gate after a reboot) can be proven when no update
needs one. Both name one host and change nothing else.

**Egress check after a reboot.** `pft-egress check` also requires peers >= the count recorded when the egress
policy was applied. A rebooted sentry is `full` with fewer peers for a minute or two, so a single check right
after the node gate fails although the egress rules are correct. The first live drill (log 15, build 3) hit
exactly this (`GATE post sentry egress: FAIL` with peers 10 < 11, the check passed 90 s later). Since build 4
the post-gate retries the egress check every POLL_SEC until GATE_TIMEOUT and prints the attempt count; the
pre-gate checks once.

Exit codes (`run`): 0 every host patched and gated, 1 a host failed (later hosts untouched), 3 usage/config,
4 refused before any change, 5 a later host changed during a failed run, 10 the local host is rebooting
(`resume` finishes it). Env: `CONF` `GATE_TIMEOUT` `POLL_SEC` `MAX_LEDGER_AGE` `REBOOT_TIMEOUT` `WINDOW_TTL`
(5400) `SILENCE_TAIL` `AM` (`none` = no silence) `WATCHDOG_ALERT` `MAINT_CMD` (`none` = no window) `NO_RESTART_RE` `STATE_DIR`.

## Tests

```bash
bash patch/tests/run-tests.sh        # 219 stubbed tests: no root, no apt, no network, no ssh
JOBS=3 bash patch/tests/mutate.sh    # 78 mutants; the unmutated control must pass first
shellcheck -x patch/pft-patch.sh patch/install.sh patch/drill/live-run.sh patch/tests/*.sh
```

The `run` tests use a two-host fake (`tests/run-stubs.sh`): the ssh stub runs the remote command with the
sentry's fake root and stub state, the validator's commands run locally, and `systemd-run ... systemctl
reboot` "reboots" a host at once (new boot id, flag cleared, container restarted). They cover order, every
gate failing on its own, window/silence failures, reboot wait and timeout, post hooks, the injected failure
with the untouched proof, a later host that does change (exit 5), the local reboot + resume path, the
mtime-only integrity accept after a reboot (and every case where it must not happen: pre-gate, no reboot,
content change, mixed findings, accept failure), the silence matchers, the egress retry after a reboot (and
no retry at the pre-gate), the injected reboot, the STATUS line for WARN/CRIT and garbage output, and the
security-only / `--all` / `--runtime` / held / new-dependency selection.

The stub `apt-config` parses the fake host's `apt.conf.d` files in name order the way apt does for the
two forms used here (lists append, the last scalar wins), so the override and rollback tests run
against a real effective-config computation rather than a canned answer.

## Live drill wrapper

`drill/live-run.sh` runs one `pft-patch run --yes ARGS` on the real hosts with every ntfy notifier on both
hosts (postfiat-monitor, pft-integrity, pft-watchdog, pft-alertpath, drill-only pft-maint ntfy.env) pointed at
throwaway topics, restored byte-identical on any exit; an outer Alertmanager silence (same scope as above) that
covers alerts outliving an injected failure (that path expires pft-patch's own silence at once, on purpose)
and is kept until the newest container start + 25 min only if a node container restarted. It records boot id,
dpkg.log sha256, container StartedAt and server_state per host before and after, checks auditd (enabled 2, all
compiled rules loaded) on any host that rebooted and the sentry's PFT-EGRESS jump, reads back both throwaway
topics, counts messages on every operator topic since the start (topics never printed), and runs
`pft-integrity verify` on both hosts. All output goes through `../peerexpose/drill/redact.py`.

```bash
INJECT=sentry-postgate WANT=1 bash patch/drill/live-run.sh --all 2>&1 | tee LOG   # injected sentry failure
bash patch/drill/live-run.sh --all 2>&1 | tee LOG                                  # full run, both hosts
```


## Results

Live runs on the real validator + sentry (Ubuntu 22.04.5 LTS, postfiatd 1.0.9), 2026-10-29. Every drill ran through
`drill/live-run.sh` with all notifiers on both hosts pointed at throwaway topics. Logs are raw output, redacted only as
described in [`logs/README.md`](logs/README.md).

| drill | command | what happened | log |
|---|---|---|---|
| A | `INJECT=sentry-postgate WANT=1 live-run.sh --all` (build 3) | sentry: 10 packages incl. kernel 5.15.0-202, **real reboot** (back in 63 s), node full; post-gate egress check FAILED for a real reason (the reboot dropped the PFT-EGRESS jump and the gate did not wait for the self-heal timer) and the injected failure followed; STOP, validator **UNTOUCHED**; operator topics 0 | [run-15](logs/run-15.log) |
| B | `INJECT=sentry-reboot WANT=0 live-run.sh --all` (build 4: egress retry) | sentry: nothing to install, injected reboot (back in 51 s), every post-gate PASS incl. egress; validator: 12 packages incl. kernel 5.15.0-202 -> **real local reboot** (exit 10 by design; the wrapper expected 0, so its CHECK says FAIL); `pft-patch-resume.service` ran the post-gate at boot: RESULT PASS | [run-19](logs/run-19.log), [run-28](logs/run-28.log) |
| C | `live-run.sh --all` (build 5) | both hosts already patched: every pre/post gate PASS on both hosts incl. the new containers gate, INSTALLED 0, DECISION none, **no reboot required, none taken**; boot ids, dpkg.log and container StartedAt unchanged; operator topics 0; integrity PASS 87/52 | [run-29](logs/run-29.log) |
| D | `INJECT=sentry-postgate WANT=1 live-run.sh` (build 5, security-only) | sentry: nothing to install, every real post-gate check PASS (node, integrity, audittrail, egress, containers, reboot flag), then the **injected** failure (labelled `INJECTED-FAILURE: drill ... not a host fault`); window closed, silence expired, STOP; validator **UNTOUCHED** (boot id, dpkg.log sha256, container StartedAt = run-start record); operator topics 0; integrity PASS 87/52 | [run-30](logs/run-30.log) |

Drill D is the clean injected-failure proof: in drill A the sentry post-gate had already failed for a real reason
(egress) before the injection, so A shows the STOP path on a real fault and D shows it on the injection alone.

Gaps the drills found, all fixed and re-tested before this README:

- drill A: egress gate did not wait for the post-reboot reapply -> build 4 retries the egress check until GATE_TIMEOUT
  (tests + mutants; live PASS in B, C, D).
- drill B: after the validator reboot dockerd left `pft-prometheus` Exited (255) ("layer not mounted") and the
  resume post-gate did not notice (started by hand at 03:09Z, ~10 min without Prometheus) -> build 5 containers gate
  (every container running before the host step must run again; one `docker start` after a reboot of that host).
  Live PASS in C and D; the failure path is proven offline (tests + mutants M73-M78), not live.
- drill B: the sentry's `pft-alertpath` monitor sent **one page to the operator's topic** at 02:59:17Z
  (`[alertpath] STALE`) while the validator rebooted, because the drill had already restored the real targets
  before the local reboot and alertpath ignored the pft-maint window -> alertpath 7c47394 holds state changes inside
  a pft-maint window + 300 s grace (44 tests, 35/35 mutants, [run-25](logs/run-25.log)). No later drill rebooted the
  validator, so the hold is proven offline only.

- run-26 (build 5 mutants): 75/78. M38 SURVIVED (no test left the reboot flag set after a reboot) and M37/M52 NOT APPLIED
  (their target lines had changed in builds 4/5) -> 87aa9db adds a `flag_stays` stub + 2 tests (219) and retargets M37/M52;
  re-run in [run-31](logs/run-31.log) @ 87aa9db: 219/219, shellcheck 0, control 219/219, **78/78 caught, 0 survived,
  0 not applied** (M37, M38 and M52 each caught).

Not done live: a security-only run that actually installed a security update (none were pending on either host
during the drills; A and B installed jammy-updates/kernel packages with `--all`), a `restart <services>` decision
(needrestart listed none after the installs) and the `--runtime` path.

### Evidence index

| acceptance item | where |
|---|---|
| `status [--json]`, exit 0/1/2, read-only | [status](#status), tests in `tests/run-tests.sh`; live STATUS before/after lines in run-15/19/29/30 |
| `policy apply/rollback --yes`, backups, byte-identical rollback, docker/containerd blacklist, Automatic-Reboot=false | [policy](#policy); live apply on both hosts [run-13](logs/run-13.log) |
| `run --yes [--hosts] [--all]`, windows, gates, conditional reboots, sentry-first abort | [run](#run); drills A-D above |
| stubbed tests, mutation control, shellcheck | [run-31](logs/run-31.log) @ 87aa9db: 219/219, shellcheck 0, control 219/219, 78/78 caught, 0 survived, 0 not applied (run-26 at 2625075: 75/78, see gaps) |
| security-only vs `--all`, reload vs reboot | [run](#run) (two paragraphs after the flow) |
| real reboots when required | sentry kernel reboot run-15; validator kernel reboot run-19 + resume run-28 |
| injected sentry post-gate failure, validator untouched | run-30 (clean), run-15 |
| throwaway topics, operator topic untouched | every drill's section 3; the one exception (B, 02:59:17Z) is disclosed above |
| integrity rebaseline and final PASS | run-14, run-18, run-27 (accepts with reason); final verify in run-30: PASS 87/52 |
| postfiatd full afterwards | `CHECK ok ... server_state full after the run` in every drill |
