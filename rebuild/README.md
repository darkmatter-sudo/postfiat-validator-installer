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
  signature; any other failure keeps its exit code. One limit so far: `kernel-log` (kernwatch: a system container
  has no kernel log, and a sandboxed unit sees the host's boot id).
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

## Limits

- The sandbox is one host. Cross-host parts (relay pulls, heartbeats, the sentry itself) cannot be rebuilt there;
  each such live item is listed in [`exceptions.list`](exceptions.list) with its reason.
- An LXD container shares the host kernel: kernel/sysctl/mount add-ons install but act on a namespaced view.
- Time to full depends on the testnet's peers at the time; it is a measurement, not a guarantee.
