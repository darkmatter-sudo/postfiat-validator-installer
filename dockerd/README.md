# pft-dockerd: Docker daemon audit and safe hardening for Post Fiat hosts

The `audit/` and `confine/` add-ons check and harden the postfiatd **containers**. Nothing checked the Docker
**daemon** that runs them. A stock Ubuntu 22.04 + Docker 29 host has no `/etc/docker/daemon.json`, so:

- `live-restore` is off: any dockerd restart (a package upgrade, a crash, a config change) stops every container,
  postfiatd included;
- containers started later get no `no-new-privileges` and no log size limit unless their own compose file sets them;
- nothing tells you if dockerd starts listening on TCP, trusts an insecure registry, or joins a swarm;
- the auditd rules from `audittrail/` watch the docker binaries and `/etc/docker`, but not runc, the containerd
  shim, the systemd units or `/run/containerd`.

`pft-dockerd` audits all of that against the CIS Docker Benchmark v1.6.0, applies only the settings that cannot
break a running node, and rolls itself back automatically if the node is not healthy afterwards.

## Usage

```
pft-dockerd audit [--json]           # read-only; exit 0 = PASS, 1 = findings, 2 = error
pft-dockerd plan                     # read-only: daemon.json and auditd rules that apply would write
sudo pft-dockerd apply --dry-run     # candidate + dockerd --validate + rules; changes nothing
sudo pft-dockerd apply --yes
sudo pft-dockerd rollback --yes      # restore the last backup byte-for-byte, restart dockerd
```

Exit codes: 0 PASS / applied, 1 findings / rolled back, 2 error, 3 usage, 4 refused (failed validation, no
`--yes`, not root), 5 rollback failed.

## Checks

| CIS v1.6.0 | Check | Fixed by apply |
|---|---|---|
| 2.14 | `live-restore` enabled (from `docker info`, i.e. the running daemon) | yes |
| 2.18 | daemon default `no-new-privileges` | yes |
| (ops) | json-file default `log-opts.max-size` (disk exhaustion) | yes |
| 2.7 | no `tcp://` in `hosts` or on the dockerd command line, no dockerd TCP listener | no (FAIL to fix by hand) |
| 2.5 | no insecure registries besides the built-in loopback CIDRs | no |
| 2.4 | dockerd manages iptables (`iptables` not false) | no |
| 2.16, n/a | seccomp default profile and AppArmor in use | no |
| 2.17 | experimental off | no |
| 7.1 | swarm inactive | no |
| 1.1.2 | docker group: member **count** only (names are never printed) | INFO |
| 3.1-3.6, 3.15-3.20, 3.23-3.24 | owner and mode of docker.service, docker.socket, /etc/docker, docker.sock, daemon.json, /etc/default/docker, containerd.sock | no |
| 1.1.3-1.1.18 | auditd watch for dockerd, /run/containerd, /etc/docker, docker.service, containerd.sock, docker.socket, /etc/default/docker, daemon.json, /etc/containerd/config.toml, containerd, containerd-shim-runc-v2, runc | yes |

A watch on a directory covers the files below it (`/etc/docker` covers `daemon.json`), but a watch on a longer path
never counts for a shorter one (`/usr/bin/runcx` does not cover `/usr/bin/runc`).

## Documented decisions (not applied)

Some CIS recommendations break or change a working node. `audit` lists them as `DECISION`, which is not a finding.

| CIS | Recommendation | Why pft-dockerd does not apply it |
|---|---|---|
| 2.2 | `icc: false` | Affects only the default `docker0` bridge, and only containers started after a restart. The validator's postfiatd runs on its own compose network, so it would change nothing there; on the sentry it would silently change behaviour on the next recreate. |
| 2.15 | `userland-proxy: false` | Changes how published ports (2559) are delivered: hairpin NAT instead of docker-proxy, and inbound peers would show their real address instead of the bridge gateway. The existing DOCKER-USER rate limit and the peer checks of `sentry/` and `peerexpose/` were tested with the proxy; switching needs its own drill. |
| 2.9 | `userns-remap` | Remaps container root to a subordinate UID range. Every existing volume (the ledger DB, `postfiatd.cfg`, the validator keys) would become unreadable to the container until re-owned, and the host-network monitoring containers (Prometheus, Alertmanager) would need `--userns=host`. Not a safe in-place change. |
| 2.12 | authorization plugin | The socket is unix-only with mode 660 root:docker; anyone allowed to use it is an administrator by design. |
| 1.1.5 | auditd watch on `/var/lib/docker` | postfiatd writes its ledger database below it continuously; a recursive watch floods the audit log. Volume config dirs are watched by `audittrail/`. |

## How apply works

1. Builds a candidate `daemon.json`: the current file plus `live-restore: true`, `no-new-privileges: true`,
   `log-driver: json-file`, `log-opts: {max-size: 100m, max-file: 5}`. A key that already has a different value is
   **kept** and reported, never overwritten.
2. Runs `dockerd --validate --config-file <candidate>`. If validation fails (for example an unknown key), apply stops
   with exit 4 and `daemon.json` is untouched.
3. Backs the current file up to `/var/lib/pft-dockerd/` (or records that there was none).
4. If `live-restore` is off in the running daemon, it writes only that key and **reloads** dockerd (SIGHUP via
   `systemctl reload docker`; live-restore is a reloadable option) and confirms it in `docker info`. Nothing has
   restarted yet.
5. Installs the full candidate and **restarts** dockerd (the other keys are not reloadable). With live-restore on,
   containers keep running. The health gate then requires, within `HEALTH_BUDGET` (300 s): every container's
   `StartedAt` unchanged, `iptables -S DOCKER-USER` unchanged, the peer port listening, and postfiatd
   `server_state` = `full`. Any miss restores the backup (sha256-compared, byte-identical), restarts dockerd again,
   and exits 1. The rollback restart is gated too (DOCKER-USER as before apply, peer port, `full`); if the node is
   still unhealthy after the rollback, apply exits 5.
   Every dockerd restart rebuilds the `DOCKER-USER` chain without the `PFT-EGRESS` jump that `egress/` adds. When
   the gate sees `DOCKER-USER` differ and `/usr/local/sbin/pft-egress` exists, it runs `pft-egress reapply
   --container <c>` right away instead of waiting for egress's 5-minute reapply timer (the first live drill found
   a 3.5-minute window without the egress policy after an ungated rollback restart).
6. Writes the missing auditd watches to `/etc/audit/rules.d/pft-dockerd.rules` and loads them with
   `augenrules --load`. If auditd is immutable (`-e 2`, as `audittrail/` sets on the sentry), the rules are staged
   and take effect at the next boot; until then `audit` reports them as `staged ... next boot`.
   At boot, `augenrules --load` stops at the first watch whose parent directory does not exist yet, and nothing
   after it loads, including `-e 2`. `/run/containerd` is created by containerd after auditd starts, so a watch on
   `/run/containerd/containerd.sock` aborted the sentry's boot load in the drill. pft-dockerd never writes a watch
   that a directory watch already covers, counting the lines it is writing in the same file, so it stages
   `-w /run/containerd` (its parent `/run` always exists) and covers the socket through it.

Reload vs restart: only some dockerd options are reloadable (e.g. `live-restore`, `debug`, `labels`, registry
mirrors). `no-new-privileges` and `log-opts` are not; they need a restart and apply only to containers created
afterwards. That is why live-restore is switched on by a reload first: the restart that follows cannot stop the
node.

Rollback caveat: a rollback restores the pre-apply file. If that file has no `live-restore` (e.g. the first apply on
a host without `daemon.json`), the rollback restart runs with live-restore off and dockerd restarts the running
containers. This happens only on the failure path; `do_rollback` prints a WARNING line when it is about to happen.

Drill hooks (`PFT_DOCKERD_INJECT`): `bad-key` adds an unknown key, so `dockerd --validate` refuses the candidate
and nothing is touched (exit 4). `health` adds a valid engine label (`pft.dockerd-drill=1`) so the candidate differs
even on an already hardened host, installs it, restarts dockerd and then forces the health gate to miss, which
exercises the automatic rollback. Run the `health` drill after the real apply, so that the rollback target already
has live-restore and the containers keep running through both restarts.

Run a planned apply inside a `pft-maint` window with an Alertmanager silence, sentry first.

## Tests

```
tests/run-tests.sh      # offline, stub commands for docker/dockerd/systemctl/auditctl/ss/iptables/stat; no root
tests/mutate.sh         # mutation controls: control run first, then each mutant must fail the suite
shellcheck -x pft-dockerd.sh tests/*.sh
```

## Live drill

`drill/live-run.sh` runs the whole sequence per host, sentry first: audit + `--json` (before), `apply --dry-run`,
the bad-key drill (exit 4, `daemon.json` sha256 unchanged), `apply --yes`, the health drill (exit 1, rollback,
`daemon.json` byte-identical to the applied file), audit + `--json` (after), container `StartedAt` unchanged,
`server_state` full, the egress jump present once. It opens a `pft-maint` window on both hosts, silences
Alertmanager, points every notifier at throwaway topics (restored by sha256 on exit, then read back: the alert topic
must stay empty), and ends with `pft-integrity verify` on both hosts. `REBOOT_SENTRY=1` adds a planned sentry reboot
and checks auditd `enabled 2` and that every staged pft-dockerd watch loaded at boot. All output is redacted
(`peerexpose/drill/redact.py`). `DRY=1` runs only preflight, redirect, window, silence and restore.

## Results (found -> fixed -> verified, Ubuntu 22.04.5, Docker 29)

| Host | Before (logs/run-06.log) | After |
|---|---|---|
| sentry | FAIL, 9 findings: live-restore off (2.14), no default no-new-privileges (2.18), no default log max-size, 6 missing auditd watches (1.1.4/7/8/9/17/18) | apply exit 0; watches staged under `-e 2`, loaded at the planned reboot; `audit` PASS exit 0 after the reboot (run-22) |
| validator | FAIL, 9 findings (same set) | apply exit 0; watches loaded live; `audit` PASS exit 0 (run-06, run-10, run-23) |

Both hosts, every live run: bad-key drill refused with exit 4 and `daemon.json` unchanged; health drill rolled back
with `daemon.json` byte-identical to the applied file; postfiatd `StartedAt` unchanged through apply and both drills;
`server_state` full; alert throwaway topic empty; `pft-integrity verify` PASS (an mtime-only `sshd_config` WARN after
each planned sentry reboot is cloud-init's; sha256 equals the manifest, and it was accepted as its own logged step).

Found by the drills and fixed before publication:

| # | Found (run) | Fix (commit) | Verified (run) |
|---|---|---|---|
| 1 | Every dockerd restart drops the `DOCKER-USER -> PFT-EGRESS` jump from `egress/`; the apply gate only passed once egress's 5-min timer had healed it, and the ungated rollback restart left the validator without the jump for 3.5 min (run-06) | gate re-applies the jump, rollback is gated, exit 5 if still unhealthy (`2ac1f1f`) | run-10 both hosts, run-22, run-23: jump present once, rollback gate PASS |
| 2 | `audittrail/`: Ubuntu's `auditd.service` (`ProtectHome=true`) hid `/root` from the boot-time rule load, which aborted at 11 of 42 rules without `-e 2` (run-06) | `ProtectHome=read-only` drop-in (`f506217`), exact key match (`46a6919`) | run-14 (tests + deploy), run-15 (boot load passes the `/root` watch), run-22 |
| 3 | pft-dockerd's own `-w /run/containerd/containerd.sock` aborted the boot load (parent created after auditd starts) (run-15) | never stage a watch covered by a directory watch in the same file (`5f29f53`) | run-21 (installed file == fixed tool's output), run-22 (reboot: enabled 2, 5/5 staged watches loaded, audit PASS) |

Offline: `tests/run-tests.sh` 101/101 and shellcheck 0 (run-18), mutation controls run-24.

### Log index (`logs/`)

| Run | What |
|---|---|
| 01 | shellcheck + first offline suite (74/74) |
| 02 | mutation controls 24/24 |
| 03, 04 | tests 81/81 and mutants 26/26 after the health-drill label change |
| 05 | live-run `DRY=1` (preflight, redirect, window, silence, restore only) |
| 06 | first live run, both hosts + sentry reboot: dockerd checks ok, verdict FAIL (findings 1 and 2 above) |
| 07 | post-drill verification: both audits PASS, egress jumps present, integrity PASS |
| 08, 09 | tests 96/96 after the egress fix; mutant run 09 stopped early (time limit), superseded by 13 |
| 10 | live run both hosts on `2ac1f1f`: PASS, 0 failed |
| 11, 12, 14 | `audittrail/` fix: tests + revert controls; 12 superseded (file edited mid-run), 14 deploys the commit to both hosts |
| 13 | mutation controls on `2ac1f1f`: 29/31 caught, 2 NOT APPLIED (M15/M16 targeted the pre-fix gate text; retargeted in `5f29f53`) |
| 15 | sentry reboot proof: FAIL (finding 3) |
| 16 | mitigation: socket watch line removed on both hosts, rules reloaded |
| 17 | tests after the finding-3 fix: 1 FAIL in the new test's own threshold (annotated), re-run as 18 |
| 18 | shellcheck 0 + tests 101/101 on `5f29f53` |
| 19 | mutation controls on `5f29f53`: stopped by the agent after 6 mutants (annotated), superseded by 24 |
| 20, 21 | read-only: fixed tool's staged watches vs the sentry's installed file (20 used the wrong baseline, annotated; 21 equal) |
| 22 | sentry live run + planned reboot on `70dedef`: PASS, 0 failed |
| 23 | validator live run on `70dedef`: PASS, 0 failed; integrity PASS on both hosts |
| 24 | mutation controls on `70dedef` (same pft-dockerd.sh/tests sha256 as 18) |
