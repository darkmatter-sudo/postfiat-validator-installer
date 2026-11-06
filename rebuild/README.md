# rebuild: prove this repo can rebuild the live validator host

`backup/` restores node **configuration** onto an existing host. Nothing so far showed that a pinned commit of this
repo can rebuild a whole validator host from scratch, with the node *and* the ~30 add-ons that run on it.
`pft-rebuild-drill.sh` does that in a throwaway sandbox on the same machine and compares the result with the live
host:

1. creates a fresh, resource-capped Ubuntu 22.04 LXD system container on its own NAT-only bridge,
2. clones this repo **inside the sandbox** from GitHub at the pinned commit,
3. runs every step of [`stack.list`](stack.list) in order, each timed and logged on its own, including a restore of
   the newest nightly `pft-backup` archive (secret-free, sentry peering stripped), and measures time to `full`,
4. diffs the sandbox's `pft-integrity` baseline (and `pft-fleet` inventory, when it can run) against the live host's:
   every item is **REPRODUCED**, **MISSING** (live only), **EXTRA** (sandbox only) or **DIFFERENT**,
5. tears everything down and proves it with a before/after host snapshot,
6. re-checks the live host: `server_state` full, `pft-integrity verify` PASS, zero messages on the operator's ntfy
   topics since the run started.

## Usage

```
pft-rebuild-drill.sh stack [--json]                        # the declared steps, validated (read-only)
sudo pft-rebuild-drill.sh preflight --commit SHA           # read-only host checks; exit 0 = a run may start
sudo pft-rebuild-drill.sh run --commit SHA --yes [--keep] [--continue] [--json-out FILE]
sudo pft-rebuild-drill.sh teardown --yes                   # remove every sandbox resource (idempotent)
sudo pft-rebuild-drill.sh limits --dir RUN_DIR             # re-check a run's SANDBOX_LIMIT lines on the live host
pft-rebuild-drill.sh diff LIVE_MANIFEST SANDBOX_MANIFEST [--live-fleet J --sandbox-fleet J] [--exceptions F] [--json]
```

Run it from a clean checkout of the same commit you pass with `--commit` (preflight checks this), so the host-side
tool and the sandbox use the same bytes. `--keep` leaves the sandbox up for inspection (then `teardown --yes`);
`--continue` runs the remaining steps after a failing one. Exit codes: 0 done and no open diff item, 1 open
MISSING/DIFFERENT items, 2 a step or check failed, 3 usage, 4 refused, 5 teardown incomplete.

Per-step logs and `timings.tsv` go to `/var/lib/pft-rebuild/<run-id>/` (0700 root).

## stack.list

`ORDER STEP AFTER COMMAND...`. ORDER strictly increases, STEP names are unique, AFTER lists **earlier** steps the
step needs, and the first step is `base` (the repo's `install.sh`); `rebuild_lib.py stack` refuses anything else.
Commands run as root in the sandbox with cwd = the checkout and `rebuild/bin` on PATH:

- `rb-restore`: the repo's `backup/pft-restore.sh` on the sanitized archive (refuses key material), prints
  `TIME_TO_FULL`.
- `rb-manifest ADDON`: installs ADDON's validator/both rows of `fleet/manifest.tsv` with `install -D -m MODE` and
  enables the timers it installed. That is the documented path for add-ons whose README installs files by hand.
- `rb-fleet-conf`: a validator-only `/etc/pft-fleet/fleet.conf` + `hosts.conf` for the sandbox's own checkout
  (REF = the pinned commit), before `fleet/install.sh`.
- `rb-limit LIMIT CMD`: a step that cannot fully work in an LXD system container. CMD's failure becomes
  `SANDBOX_LIMIT LIMIT: reason` (exit 0) only if we are in an lxc container AND the output has LIMIT's exact error
  signature; any other failure keeps its exit code. Three limits:
  - `kernel-log` (kernwatch): a system container has no kernel log, and a sandboxed unit sees the host's boot id.
  - `apparmor-nested` (`aaapply`): under `pft-postfiatd` the node never syncs inside the sandbox. The HOST audit log
    holds the denials, in the sandbox's own AppArmor namespace (`root//lxd-pftrb-sbx_...`): `file_mmap` of
    `/usr/bin/bash`, and with that allowed, `file_mprotect` of
    `/io.containerd.snapshotter.v1.overlayfs/snapshots/N/fs/.../libc.so.6`. Docker's data on an LXD custom volume
    makes the container's paths disconnected, so host-path rules cannot match (runs 21/22). The production profile is
    not reshaped to fit the sandbox. Signature: `apply: health FAIL ... server_state none` **and** the tool's own
    `rollback RESULT: PASS - postfiatd back under docker-default`.
  - `kernel-audit` (`scapply`): an LXD container has no kernel audit log, so pft-seccomp's denial gate fails closed
    (`apply: gate FAIL - audit log unreadable`) **and** must have rolled back (`rollback RESULT: PASS - postfiatd back
    under seccomp default`).

  A limit on a hardening step is accepted only if the **live host** shows that the same committed profile works
  there (drill section 5b, `limits --dir RUN_DIR` re-checks a run): the live profile file has the committed bytes
  (`cmp`), the live container runs it (`docker inspect`), and for `apparmor-nested`, `rebuild_lib.py aa-nested` over
  the host's `/var/log/audit/audit.log*` since the step start counts >= 1 DENIED record for `pft-postfiatd` in the
  sandbox namespace and **0** for the live node. Otherwise the run FAILs.
- `egressfix`: every container re-create drops pft-egress's `DOCKER-USER` jump until the 5-min
  `pft-egress-reapply@postfiatd` timer runs (run 22 dumps 7 rules before, 6 after), so this step runs that unit and
  requires the `-j PFT-EGRESS` jump before the diff reads the firewall.
- everything else: the add-on's own `install.sh` with the arguments the live host used. Prerequisites an add-on's
  README asks for by hand (the `age` package for keyescrow, an agent account for privesc: sandbox-only `rbagent`)
  are part of the step.
- `RB_STACK=FILE` runs another stack file (dev probes, e.g. [`probes/docker-storage.stack`](probes/docker-storage.stack));
  the run header prints the file and its sha256. Step commands reach the loop base64-encoded (`stack --rows`):
  `jq @tsv` had turned `\n` into `\\n` (probe 08).

The offline test checks that every add-on in `fleet/manifest.tsv` has a step, so a new add-on cannot be
forgotten here.

## Isolation (preflight, exit 4 on any refusal)

| Refused | Why |
|---|---|
| `security.privileged=true`, no `security.nesting`, missing `limits.cpu` / `limits.memory` | root on host / Docker cannot run / not capped |
| a custom-volume disk device from any pool other than the sandbox's own | the volume would outlive teardown or share state |
| a disk device sourced from `/var/lib/docker`, `/opt/postfiatd`, `/etc/postfiatd`, `/var/lib/pft-*`, `/etc/pft-*`, `/opt/pft-agent`, the Docker socket, `/home`, `/root` or `/` | shares live state |
| a proxy device listening on 2559, 5005 or 51235 | takes or exposes a live port |
| a NIC that is not on the sandbox bridge, host device passthrough | bypasses the sandbox network |
| a bridge that is not LXD-managed NAT-only IPv4 | the sandbox would be reachable from outside |
| any file the drill pushes containing a live ntfy topic, or any ntfy URL at all | sandbox alerts must go nowhere (`http://127.0.0.1:9/` blackhole) |

On the host the drill adds only: LVM loop pool `pftrb` (thin LV, ext4; btrfs breaks nested overlayfs, run 02) (`RB_DISK`, default 25GiB)
with two custom volumes on it for the sandbox's `/var/lib/docker` (4GiB) and `/var/lib/containerd` (16GiB) (`RB_VOLS`:
the LVM rootfs is an *idmapped* mount and overlayfs cannot stack on idmapped lower dirs on 5.15, probe 08), bridge `pftrb0`
(10.209.77.1/24), and two iptables chains scoped to that bridge: `PFT-REBUILD` (FORWARD: tcp 80/443/2559/51235 out,
replies in, LOG `pft-rebuild-drop:` + DROP for the rest) and `PFT-REBUILD-IN` (INPUT: DHCP and DNS to LXD's
dnsmasq, everything else dropped, so the sandbox cannot reach the host's sshd or the live node's admin ports;
the run checks both). The chains sit outside `DOCKER-USER` and UFW's rule set, so `pft-integrity`'s firewall
items do not change during a run. `teardown` deletes all of it and the image the run downloaded.
Defaults: 2 CPUs, 3GiB, 6000 processes, so the live node keeps headroom on a 4-CPU/8-GB host.

## Results

Recorded runs on the validator host (Ubuntu 22.04.5, 4 CPU / 8 GB, LXD 5.0); raw logs redacted in `logs/`.

| Run | Commit | Result | What it found / fixed |
|---|---|---|---|
| 01 | `9b64883` | FAIL (3 checks) | Isolation preflight, bridge, and "sandbox cannot reach host sshd / :5005" all ok; live host full, integrity PASS, 0 operator messages. **(a)** `install.sh` died at `rc=141` right after "Detected OS": `sshd -T \| awk '…{exit}'` under `set -euo pipefail` SIGPIPEs sshd once its output passes one 4 KiB write. A stock 22.04 sshd does; the hardened live sshd (3814 bytes) does not, so it never showed on the live host. Fixed in `install.sh` (awk reads all input; a missing sshd falls back to 22), repro in `logs/02-sshd-sigpipe.log`. **(b)** `lxc exec` read the step loop's stdin, so no step after `base` ran: `sx` now reads `/dev/null`. **(c)** teardown left LXD's empty `table inet lxd` (caught by the before/after snapshot): teardown now deletes it when the run created it and it is empty, and reports INCOMPLETE otherwise. |
| 02 | `51282f7` | FAIL (13 steps/checks) | (a)/(b)/(c) of run 01 confirmed fixed: base ran past the SSH-port step, all 34 steps ran, teardown CLEAN (host snapshot identical, `table inet lxd` removed). New: Docker inside the sandbox could not pull the node image, `failed to extract layer ... to overlayfs` (overlayfs on the btrfs pool in an unprivileged container), so base/restore failed and every node-dependent installer refused (resources/statewatch/feewatch/upgradewatch: container not running; backfill/kernwatch/cluster/rulecheck: first unit run failed). Pool is now LVM (ext4). Also: privesc needs `--agent`, keyescrow needs the `age` package, fleet needs `/etc/pft-fleet/fleet.conf`. Diff: REPRODUCED 60, MISSING 107, EXTRA 2, DIFFERENT 4 (most MISSING = node/container items). **Separate finding, fixed in `../backup`**: the nightly archive omitted the COMPOSE_FILE hardening overlays and `pft-restore` ran `-f docker-compose.yml` (dropping the override too), so a restore lost no-new-privileges + confine/AppArmor/seccomp: `logs/05-backup-overlays.log`. |
| 03 | `12ae972` | FAIL (13 steps/checks) | LVM pool: overlayfs still fails, so the cause is Docker 29's containerd snapshotter in an unprivileged container, not btrfs (superseded by probe 08: the real cause is the idmapped rootfs). The new restore deferred the AppArmor + seccomp overlays as designed (profiles absent in the sandbox) and kept confine, but `docker compose` resolved COMPOSE_FILE against the CWD (`stat /root/pfvi/docker-compose.yml`): fixed in `../backup/pft-restore.sh` (`env -C COMPOSE_DIR`), repro `logs/07-compose-cwd.log`. Teardown CLEAN; live host full, integrity PASS, 0 operator messages. |
| 08 (probe) | `2f164ff` | probe, `RB_STACK=probes/docker-storage.stack` | Sandbox `/proc/self/mountinfo`: rootfs `ext4 ... idmapped`. containerd snapshotter: `failed to mount ... overlay ... invalid argument` (rc 125). The overlay2 and fuse-overlayfs probes never started dockerd, because the probe's `printf '...\n'` reached the sandbox as `\\n` (invalid daemon.json): a drill bug, fixed by base64 step rows. Fix: Docker's data dirs on custom volumes of the sandbox pool (not idmapped); no daemon.json deviation from the live host. |
| 09 | `b4e3b8d` | FAIL (7 steps) | Volumes fix confirmed: base 545 s, node image pulled and running. privesc, keyescrow, fleet, cluster now pass. Restore refused (exit 3, correct): the newest nightly archive was made by the live host's pft-backup.sh from before `12ae972` (no overlays) -> live add-on synced and a fresh archive taken, `logs/11-backup-sync.log` (PASS 22/0, operator topics 0). feewatch/upgradewatch/backfill: node not synced (noNetwork) because restore had refused; alerts: exporter not answering, because **`fleet/manifest.tsv` did not list the exporter program** (`/opt/pft-exporter/pft_exporter.py`), so the unit was installed without it -> row added `d50e433` (live bytes = repo), live fleet manifest synced `logs/13-fleet-sync.log` (PASS 16/0). Diff REPRODUCED 251 / MISSING 114 / DIFFERENT 65; first `exceptions.list` lines added (sentry pulls, live-only items), applied from run 10. |
| 10 | `d50e433` | PASS, diff rc 1 (61 open) | **All 35 steps rc 0**: restore of the fresh archive 69 s, **TIME_TO_FULL 68 s**; alerts stack up after the exporter (192 s incl. image pulls); feewatch/upgradewatch/backfill/rulecheck first runs pass on the synced node; kernwatch = `SANDBOX_LIMIT kernel-log` (step log line appended to the log). Diff REPRODUCED 259 / MISSING 107 / EXTRA 1 / DIFFERENT 64, excepted 110, open 61: unitguard drop-ins, sshcrypto, egress reapply units, logship units, AppArmor/seccomp overlays (deferred by restore), keyescrow escrow units, add-on states; `pft_exporter.py` EXTRA and fleet manifest DIFFERENT because the live fleet inventory was taken before log 13 synced it. Teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 11 (attempt 1) | `31e9954` | refused at preflight (exit 4) | `logs/14-run-preflight-refused.log`: live `pft-integrity verify` was WARN (`image:local:alpine:latest added`), caused by an earlier manual probe on the host (`docker run alpine` with a mistyped volume name), which also created an empty named volume. Both removed (not accepted), verify PASS, run restarted. The refusal is the designed behavior. |
| 11 | `31e9954` | FAIL (unitguard rc 5), diff not reached | `logs/15-run-unitguard-order.log`. New steps pass: `sshharden` (`../audit/fixes/40-pft-hardening.conf`), `sshcrypto` install + apply (confirmed new session), `egress` apply inside a pft-maint window. Classifier: an `addon:X` state is excepted only when every differing file of X is excepted (17 add-ons were MISSING only through their excepted `-pull` units); replay on run-10 data: open 61 -> 26. unitguard `apply --all`: `pft-backup`/`pft-integrity` exit **226/NAMESPACE** under the drop-in because their `ReadWritePaths` dirs are created by their first run (the live host hid this), `pft-heartbeat` fails with or without the drop-in (needs the sentry). Fix `8856f16`: `baseline` + `firstrun` before unitguard, `--skip pft-heartbeat.service`, `rebaseline` accepts the drop-ins. TIME_TO_FULL 62 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 12 | `8856f16` | FAIL (unitguard rc 1), diff rc 1 (14 open) | `logs/16-run-unitguard-integrity-order.log`. backup's drop-in now PASSes. `pft-integrity`'s check needs RESULT PASS, but the drop-ins `apply --all` had already written (alphabetical: backup, divergence, egress, exporter) are new integrity items -> exit 1 -> rollback. Tool fix `bc01783`: `apply --all` applies `FIRST_UNITS` (default `pft-integrity.service`) first; unitguard tests 34/0, mutants 17/17 incl. new U17 (`logs/17-unitguard-tests.log`). Diff REPRODUCED 270 / MISSING 100 / DIFFERENT 61, excepted 147, open 14: 9 drop-ins (written, but the run stopped before `rebaseline`), AppArmor/seccomp overlays (.env, 2 compose files, container `security_opt`/labels), `fw:docker-user` sha256 (per-host /32 + bridge id -> exception, count compared). TIME_TO_FULL 50 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 13 | `bc01783` | FAIL (unitguard rc 1), diff rc 1 (13 open) | `logs/18-run-integrity-own-dropin.log`. FIRST_UNITS works: pft-integrity is applied first, and all 8 other drop-ins PASS. pft-integrity still exits 1 under its drop-in and 0 right after the rollback, with nothing else changed in between: its own new drop-in is a tracked `dropin:` item, so it WARNs on itself. On the live host the profile went in before integrity tracked drop-ins. Fix: the profile check passes exit 1 only if that invocation's single WARN/FAIL line is `dropin:pft-integrity.service.d/50-unitguard.conf added` (journal by InvocationID; the lines are printed into the unitguard log). Offline test 8/8, a mutant that accepts any WARN is caught 4x (`logs/19-integrity-check-tests.log`); drop-in bytes unchanged. Open: same 9 drop-ins (no rebaseline), AppArmor/seccomp overlays (4). TIME_TO_FULL 47 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 14 | `27e8676` | **PASS**, diff rc 1 (4 open) | `logs/20-run-unitguard-pass.log`. **All 40 steps rc 0**, including `unitguard apply --all` (9 drop-ins PASS, heartbeat held) and `rebaseline`. The integrity check printed its single line `[WARN] dropin:pft-integrity.service.d/50-unitguard.conf added`, which confirms the run-13 diagnosis. TIME_TO_FULL 58 s. Diff REPRODUCED 279 / MISSING 91 / DIFFERENT 61, excepted 148, **open 4**, all from the deferred AppArmor/seccomp overlays: `compose:.env` (COMPOSE_FILE), `docker-compose.apparmor.yml`, `docker-compose.seccomp.yml`, `container:postfiatd` labels/security_opt. Next: apply both in the sandbox or record a documented SANDBOX_LIMIT. Teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 21 | `db3d205` | FAIL (2 steps, both rolled back PASS), diff rc 1 | `logs/21-run-hardening-rollback.log`. New steps `aaapply`/`scapply` apply the committed AppArmor + seccomp profiles inside pft-maint windows. **aaapply**: `apply: health FAIL after 91 poll(s): server_state none` (15-min gate), then `rollback RESULT: PASS - postfiatd back under docker-default`; the HOST audit log held `file_mmap` DENIED records for `/usr/bin/bash` in the sandbox's AppArmor namespace `root//lxd-pftrb-sbx_...` (the live node, same profile bytes, has none). **scapply**: `apply: gate FAIL - audit log unreadable` (no kernel audit in an LXD container; the gate fails closed, as designed), rollback PASS. `fw:docker-user` rule count differed after the two re-creates. TIME_TO_FULL 58 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 22 (probe) | `7f5ed0e` | probe, `RB_STACK=probes/hardening.stack` | `logs/22-probe-apparmor-nested.log`. With `/usr/bin/bash mr` added (probe-only profile `probes/pft-postfiatd.bash-mr`), aaapply still fails; the host audit log now shows `file_mprotect` DENIED on the **disconnected** path `/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs/usr/lib/x86_64-linux-gnu/libc.so.6` (the profile already has `attach_disconnected`). Docker's data on the custom volume (the run-08 fix) makes paths disconnected in the nested namespace, so host-path rules cannot match: a sandbox limit, not a profile gap, and the production profile is left unchanged. DOCKER-USER dumps: each re-create drops pft-egress's jump (7 rules before, 6 after) until `pft-egress-reapply` runs. Teardown CLEAN, live full + integrity PASS, 0 operator messages. |
| 23, 24 (dev mutants) | working tree | FAIL (dev passes, fixed before the recorded pass) | New code: `rb-limit` limits `apparmor-nested` + `kernel-audit` (signature **and** the tool's own rollback PASS line), `rebuild_lib.py aa-nested` (host audit DENIED records: sandbox namespace vs live), drill section 5b / `limits --dir` (live profile bytes = committed, live container enforces them), step `egressfix`, 5 exceptions for the overlay items; suite 144 checks. Log 23: the mutant control failed, because the mutant copy had no `../apparmor` / `../seccomp` profiles next to it (lesson of the seccomp harness); `mutate.py` now copies them. Log 24: MUTANTS: 81 run: BROKEN=4 CAUGHT=76 NOT APPLIED=1 -> FAIL: M07/S01-S03 BROKEN (a new stack check indexed an empty list when parsing failed: now guarded), H01 NOT APPLIED (its target line had changed: updated). |
| 25 | `22a85ed` | FAIL (1 step: egressfix), diff rc 0 (**open 0**) | `logs/25-run-limits-confirmed-egressfix-fail.log`; tests `logs/27-checks.log` (shellcheck + ruff clean, 144 checks PASS), mutants `logs/26-mutants.log` (MUTANTS: 81 run: CAUGHT=81 -> PASS, 0 orphans). 42 of 43 steps rc 0. `aaapply` and `scapply` ended as `SANDBOX_LIMIT apparmor-nested` / `kernel-audit` after their own rollback PASS. Section 5b confirmed both on the live host: `AA_NESTED: CONFIRMED (sandbox namespace 24, live 0 DENIED for pft-postfiatd)`, live profile files = committed bytes, live container enforcing both. **egressfix exited 1 with no output**: `systemctl start` reported nothing and the `-j PFT-EGRESS` check failed, so the cause is not visible in this run. The loop stopped there, so `rebaseline2` did not run and the diff used the sandbox baseline from `rebaseline` (before the profile applies). SUMMARY: REPRODUCED=279 MISSING=91 EXTRA=0 DIFFERENT=61 excepted=152 open=0. TIME_TO_FULL 57 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. Next: egressfix prints the unit rc, its journal and DOCKER-USER before it checks (run 28). |
| 28 | `9331448` | FAIL (1 step: egressfix), diff rc 0 (open 0) | `logs/28-run-egress-deadman-rollback.log`; mutants `logs/29-mutants.log` (MUTANTS: 81 run: CAUGHT=81 -> PASS, 0 orphans; run at `9331448`). 42 of 43 steps rc 0. The new egressfix diagnostics show `reapply rc 0`, no log line from the last reapply and no `-j PFT-EGRESS` jump in DOCKER-USER. Cause (from the step durations and pft-egress's code; the sandbox was already torn down): pft-egress's own 10-min dead-man, started by `egress`, was still polling when `aaapply`'s gate held the node below full. It tripped and rolled the policy back (state file moved to `*.rolled-back`, reapply timer disabled), and `reapply` is a silent no-op without state. The diff missed it too: the sandbox manifest came from `rebaseline` (before aaapply), and the `fw:docker-user` rule count still matched. Fixed in `6f4d38a`: step `egresswait` waits for the dead-man to end and requires its `deadman_passed_at` mark before aaapply; egressfix lists the state dir; the drill re-collects the sandbox manifest before the diff. |
| 30 | `6f4d38a` | FAIL (1 check: manifest re-collect), **all 45 steps rc 0**, diff rc 0 (open 0) | `logs/30-run-all-steps-pass-recollect-fail.log`. `egresswait` rc 0 after 614 s (dead-man PASS). aaapply/scapply ended as their `SANDBOX_LIMIT` again (section 5b confirmed on the live host), then `egressfix` rc 0 and `rebaseline2` rc 0. SUMMARY: REPRODUCED=279 MISSING=91 EXTRA=0 DIFFERENT=61 excepted=152 open=0. TIME_TO_FULL 57 s, teardown CLEAN, live full + integrity PASS, 0 operator messages. The one FAIL is my new re-collect check: it ran `pft-integrity baseline`, which refuses an existing manifest with exit 3 (confirmed read-only on the live host). This diff is still of the final state, because `rebaseline2` accepted it right before. Fixed in the next commit (`accept` instead, plus a test that fails on the old line). |
| 31 | `3396c60` | FAIL (1 check: operator ntfy topics), **all steps rc 0**, diff rc 0 (open 0) | `logs/31-run-all-steps-pass-apparmor-drift-page.log`. Manifest re-collect now PASS (`accept`), egresswait/egressfix/rebaseline2 rc 0, aaapply/scapply ended as their `SANDBOX_LIMIT` again (section 5b confirmed on the live host). SUMMARY: REPRODUCED=279 MISSING=91 EXTRA=0 DIFFERENT=61 excepted=152 open=0. TIME_TO_FULL 63 s, teardown CLEAN, live full + integrity PASS. The FAIL is real: the operator topic got 1 message at 02:39:09Z, `[FIRING] PFTAppArmorDrift` (validator). Cause: aaapply's sandbox DENIED records (namespace `root//lxd-pftrb-sbx_...`) are written to the HOST audit.log, and the live hourly `pft-apparmor audit` counted them (144 records from runs 21-31, live container 0). Fixed in `pft-apparmor` itself (commit `e536f3e`, see `../apparmor/README.md`, installed on both hosts, alert resolved 03:14Z); the drill now also checks `live pft-apparmor audit PASS` in section 8. Checks at that commit: `logs/32-checks.log` (shellcheck + ruff clean, 146 PASS). |

## Limits

- The sandbox is one host. Cross-host parts (relay pulls, heartbeats, the sentry itself) cannot be rebuilt there;
  each such live item is listed in [`exceptions.list`](exceptions.list) with its reason.
- An LXD container shares the host kernel: kernel/sysctl/mount add-ons install but act on a namespaced view.
- The AppArmor and seccomp profiles are installed but cannot be **enforced** in the sandbox (`apparmor-nested`,
  `kernel-audit` above), so the drill proves those two steps only up to a clean rollback, plus the live-host check
  that the same committed bytes are enforced on the live node. Their 4 overlay items are documented exceptions.
- Time to full depends on the testnet's peers at the time; it is a measurement, not a guarantee.
