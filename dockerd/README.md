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
   and exits 1.
6. Writes the missing auditd watches to `/etc/audit/rules.d/pft-dockerd.rules` and loads them with
   `augenrules --load`. If auditd is immutable (`-e 2`, as `audittrail/` sets on the sentry), the rules are staged
   and take effect at the next boot; until then `audit` reports them as `staged ... next boot`.

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

## Results

Two-host results (found -> fixed -> verified) are added after the live drill.
