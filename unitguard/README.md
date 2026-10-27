# pft-unitguard: systemd sandboxing for the add-on units

The installer's host-side add-ons (exporter, backup, heartbeat, logship, integrity, maint, watchdog, egress,
DOCKER-USER rules, ...) run as systemd services. Out of the box every one of them ran with systemd's defaults:
`systemd-analyze security` rated 13 units on the validator and 9 on the sentry **9.6 UNSAFE** (the exporter,
already on `DynamicUser=`, 8.1 EXPOSED). A bug or a compromised dependency in any of them had full root on the host.

`pft-unitguard.sh` adds one drop-in per unit, `<unit>.d/50-unitguard.conf`, built from a per-unit profile in
`profiles/`. It applies one unit at a time, runs the unit and a functional check straight away, and takes the
drop-in back out on any failure. It never edits the unit files themselves.

Tested on Ubuntu 22.04.5, systemd 249, on a validator host and a sentry host.

## Modes

```
pft-unitguard audit    [--units "U1 U2"] [--tsv] [--detail]   # read-only: exposure, rating, user, failed checks, drop-in, class, target, perms
pft-unitguard plan     UNIT                                   # print the drop-in, class, exceptions and check; changes nothing
sudo pft-unitguard apply    UNIT|--all [--skip "U1 U2"]       # write drop-in, daemon-reload, run unit + check, auto-rollback on failure
sudo pft-unitguard rollback UNIT|--all                        # remove the drop-in (restore an earlier one if saved), daemon-reload
```

Exit codes: 0 ok, 1 check failed / rolled back / target missed, 3 usage, 4 refused, 5 rollback failed.
Env: `PROFILE_DIR`, `DROPIN_ROOT` (/etc/systemd/system), `STATE_DIR` (/var/lib/pft-unitguard), `SETTLE_SEC` (10),
`HOLD_UNITS` (units to leave alone, e.g. a collector in the middle of a 24h data window).

**apply** in detail: the drop-in is written root-owned (dir 0755, file 0644), then `daemon-reload`. A oneshot unit is
started (restarted when `RemainAfterExit=yes`, because `start` on an active one runs nothing) and must end with
`Result=success`. A long-running unit is restarted and must stay active for `SETTLE_SEC` with `NRestarts` unchanged.
Then the profile's `#@ check:` command must exit 0, and the new exposure must meet the class target. If any step
fails, the drop-in that was there before is put back (including an earlier unitguard drop-in, so a bad profile
change never strips a working profile), the unit is re-run, and apply exits 1.

**audit** also checks that each unit's ExecStart binary, the drop-in dir and the drop-in are root-owned and not
group/world-writable (a writable parent dir would let anyone swap the binary or the drop-in). Both hosts: no findings.

## Profiles and classes

`profiles/<unit>.conf` (templates as `name@.service.conf`). `#@` lines are metadata, everything else is copied into
the drop-in verbatim:

```
#@ class: standard|docker|iptables
#@ exception: why a directive had to stay open (repeatable)
#@ check: shell command, exit 0 = the unit still does its job
#@ note: free text
#@ target: max exposure (default: standard 5.0; docker/iptables "<before", lower than before the first apply)
```

| class | units | what stays open (documented in each profile's `#@ exception:`) | target |
|---|---|---|---|
| standard | exporter, heartbeat, logship-vacuum, maint-tick, watchdog | nothing beyond its own state dir and the network families it uses | <= 5.0 |
| docker | backup, divergence, logship-check, logship-dockerlog@, retention-sample | `/var/run/docker.sock` (root-equivalent via the Docker API); divergence also `runuser` to its ssh user (needs pam_limits caps) | lower than before |
| iptables | postfiat-docker-user, egress-reapply@, integrity, postfiat-monitor | `CAP_NET_ADMIN`/`CAP_NET_RAW`, `AF_NETLINK`, host netns, `/run` (xtables lock); integrity/monitor read the docker socket too | lower than before |

Every profile still gets `ProtectSystem=strict`, `ProtectHome` (read-only for divergence's ssh key), `PrivateTmp`, `PrivateDevices`,
the kernel protections, `NoNewPrivileges`, a `SystemCallFilter`, a minimal `CapabilityBoundingSet` and
`RestrictAddressFamilies`, plus only the `ReadWritePaths` the tool writes.

## Results (both hosts, live)

| unit | validator before -> after | sentry before -> after |
|---|---|---|
| pft-backup | 9.6 -> 2.0 | - |
| pft-divergence | 9.6 -> 2.6 | 9.6 -> 2.6 |
| pft-egress-reapply@&lt;container&gt; | 9.6 -> 1.9 | 9.6 -> 1.9 |
| pft-exporter | 8.1 -> 1.1 | - |
| pft-heartbeat | 9.6 -> 1.6 | - |
| pft-integrity | 9.6 -> 2.4 | 9.6 -> 2.4 |
| pft-logship-check | 9.6 -> 2.1 | 9.6 -> 2.1 |
| pft-logship-dockerlog@&lt;container&gt; | 9.6 -> 1.5 | 9.6 -> 1.5 |
| pft-logship-vacuum | 9.6 -> 0.5 (SAFE) | 9.6 -> 0.5 (SAFE) |
| pft-maint-tick | 9.6 -> 1.6 | 9.6 -> 1.6 |
| pft-retention-sample | 9.6 -> 1.6 | - |
| pft-watchdog | - | 9.6 -> 1.8 |
| postfiat-docker-user | 9.6 -> 1.9 | 9.6 -> 1.9 |
| postfiat-monitor | 9.6 -> 2.2 | - |

Before: `logs/07-before-audit.log`. After: `logs/55-after-audit.log` (every unit `OK`, every class target met).
`pft-govern-collect` (a transient `systemd-run` collector from `govern/`, mid 24h window) is not an installed unit
and is out of scope. Some classes in the before-audit differ from the final ones: integrity, maint-tick and monitor
were reclassified after probing (below).

## What the probes found before any live apply

Every profile was first run against the tool's **real command** in a transient unit with the same properties
(`drill/probe.sh`, `systemd-run -p ...`), with scratch state dirs and ntfy redirected to a file or a throwaway
topic, plus a control (the earlier draft profile, or a missing address family) that had to fail visibly.
These drafts would have broken things and were fixed before apply:

- logship-vacuum: root with no caps cannot read the 0640 remote journals -> runs as `systemd-journal-remote` (0.5).
- divergence: `runuser` runs pam_limits; denying `@resources`/`CAP_SYS_RESOURCE` fails with "cannot open session".
- postfiat-monitor: as "standard" (no caps, no `AF_NETLINK`) `postfiat-health` reported a healthy node UNHEALTHY,
  which would have paged. Reclassified iptables.
- watchdog: the heartbeat spool is 0700 to its own user; without `CAP_DAC_OVERRIDE` it sees no heartbeat and pages STALE.
- egress-reapply@ check: `systemd-escape -u` turned `postfiatd-sentry` into `postfiatd/sentry` (caught on the sentry by
  auto-rollback); now plain prefix/suffix stripping.
- the tool itself: re-apply could delete a working unitguard drop-in on failure (now saved and restored), and
  `systemctl start` on an active `RemainAfterExit=yes` oneshot was a no-op (false PASS) -> restart.
- postfiat-docker-user: the script flushes `DOCKER-USER`, which also drops pft-egress's jump; its check re-runs every
  `pft-egress-reapply@` instance at once and runs `pft-egress check`. `ProtectKernelModules=yes` does not stop a rule
  that needs a match module not yet loaded (boot): the kernel loads it via `request_module` (xt_time probe, logs 48-50).

## Negative proofs and the rollback drill

- `drill/negative.sh` (log 06, 12/12): writes to `/etc` blocked (vacuum, exporter, heartbeat, docker-user in 48-50),
  TCP to the admin RPC blocked for vacuum (`AF_UNIX` only), exporter allowed to 127.0.0.1:5005 but dropped to a
  non-loopback address (`IPAddressDeny`), `/root` unreadable/empty (heartbeat, integrity). Each block has an
  unsandboxed control that must succeed.
- docker-user (48-50): the script without `AF_NETLINK` fails ("Failed to initialize nft"); with the profile it builds a
  scratch chain identical to the live `DOCKER-USER` rules.
- `drill/rollback-drill.sh` (log 17, 6/6): a deliberately broken vacuum profile (User/Group dropped) is applied live,
  apply exits 1, the working drop-in comes back byte-identical, the unit re-runs with `Result=success`.

## pft-integrity covers the drop-ins

A drop-in can undo a sandbox (or add an `ExecStartPre`), so `../integrity/pft-integrity.sh` now also tracks
`/etc/systemd/system/{pft,postfiat}-*.d/*.conf` as `dropin:<unit>.d/<file>` (sha256, mode, owner, mtime; a content
change is FAIL). Logs 52-54: install, accept (`pft-integrity accept --reason ...`), PASS; then a comment appended to one
drop-in -> FAIL; restored with mode/owner/mtime -> PASS. **After every `apply`/`rollback`, run
`sudo pft-integrity accept --reason "unitguard: <unit>"`**, or the next hourly run reports the change.

## Install / use

```
sudo install -d /opt/pft-unitguard && sudo cp -r pft-unitguard.sh profiles drill /opt/pft-unitguard/
sudo bash /opt/pft-unitguard/pft-unitguard.sh audit --detail
sudo bash /opt/pft-unitguard/pft-unitguard.sh plan pft-exporter.service
sudo bash /opt/pft-unitguard/pft-unitguard.sh apply pft-exporter.service      # one unit at a time
sudo pft-integrity accept --reason "unitguard: pft-exporter"
```

Before applying a profile to a unit that sends alerts (monitor, watchdog, integrity, maint-tick), point its ntfy
target at a test topic or add an `NTFY_OUTBOX` drop-in for the apply, and silence the related Alertmanager alerts
for units with Prometheus rules (exporter, divergence, logship). The live runs here did both.

## Tests

```
bash tests/test-unitguard.sh        # 31 offline tests, stub systemctl + systemd-analyze, temp dirs, no root
bash tests/mutants-unitguard.sh     # 16 mutants (no rollback, no daemon-reload, check skipped, ...), all must be caught
shellcheck pft-unitguard.sh drill/*.sh tests/*.sh tests/stubs/*
```

Final run: `logs/51-tests-mutants.log` (shellcheck exit 0, 31/31, U1-U16 all caught).

## Logs

`logs/NN-*.log` are every recorded run of this task, in order, including the failed and superseded ones (each says so
in its first lines or in the run after it). Live drivers print their own source with `cat` first. Redactions:
hostnames -> `validator-host`/`sentry-host`, the local user and home path -> `<agent-user>`/`<user>`/`<repo>`; nothing
else was changed. Key logs: 07 before audit, 55 after audit, 08/09/11/13/19/21/26/27/31/32/35/37/38/42/43/49/50 live
applies with functional checks, 04/06/10/18/20/23/25/30/34/41/48 probes and negatives, 17 rollback drill,
51 tests+mutants, 52-54 integrity coverage.
