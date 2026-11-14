# fwaudit: declared inbound policy vs effective exposure

**Status: in progress (task_32d07e3a).** The read-only audit (`audit [--json]`), per-role policies, redacted
captures of both hosts, remediation (`plan/apply/rollback` with the dead-man) and their tests are in. The timer,
textfile metrics, the alert, fleet/integrity/schedaudit/jobwatch/rulecheck integration, mutation and promtool tests,
the drills and the results table follow.

## Why

`ufw status` does not say what is reachable. On a Docker host a published port is DNATed in `nat PREROUTING` and
travels the FORWARD path, so UFW's INPUT rules never see it (`DOCKER-USER` decides); docker-proxy serves a family
Docker did not DNAT on the INPUT path; `*` listeners are dual-stack while `[::]` ones are IPv6-only; and nftables
tables outside iptables-nft add hooks of their own. `pft-fwaudit` captures the rulesets and sockets once and walks
the real chains for each listener.

## Usage

```
sudo pft-fwaudit audit [--role validator|sentry] [--json] [--bundle FILE]   # 0 PASS, 1 WARN, 2 FAIL, 3 usage, 4 capture
sudo pft-fwaudit collect [--out FILE]                                        # capture bundle only
sudo pft-fwaudit plan [--role R] [--json] [--bundle FILE]     # 0 nothing to do, 1 actions, 2 manual items left
sudo pft-fwaudit apply --yes [--role R] [--dry-run] [--deadman MIN] [--foreground]
sudo pft-fwaudit rollback --yes
```

Policy (`policy/ROLE.policy`): `allow PROTO PORT FAMILY SOURCE [limit]  # purpose`, FAMILY `v4|v6|both`, SOURCE
`any`, a CIDR, or `@name` resolved from `/etc/pft-fwaudit.peers` (`name=CIDR[,CIDR]`, kept off the repo).

States per (family, proto, port): `open` (any source), `limited` (any source past a rate/conn limit), `sources`
(only listed CIDRs), `closed` (not shown).

| Finding | Verdict | Meaning |
|---|---|---|
| ufw-inactive, default-incoming-allow | FAIL | UFW off or default incoming not deny |
| undeclared-exposure | FAIL | reachable, not in the policy |
| source-too-broad | FAIL | declared for a peer/CIDR, reachable from more |
| missing-limit | FAIL | declared `limit`, reachable without one on the actual path |
| declared-unreachable | WARN | declared, but no listener on that family or filtered |
| stale-allow | WARN | UFW allows a port nothing listens on (a future listener is exposed at once) |
| loopback-dnat-unguarded | WARN | 127.0.0.1-published port without Docker's raw PREROUTING drop |
| nft-foreign-table | WARN | nftables table outside iptables-nft hooks input/forward/prerouting (not modelled) |
| ufw-rule-bypassed | INFO | port is published via DNAT: its UFW rule is not on the path |

## Remediation: plan / apply / rollback

`plan` only ever narrows UFW, one family at a time (`from 0.0.0.0/0` or `from ::/0`), and lists everything else as
MANUAL (it is never changed by the tool):

| Finding | Planned change |
|---|---|
| stale-allow; undeclared-exposure decided by a UFW user rule on the INPUT path | delete those UFW rules (that family only) |
| source-too-broad on the INPUT path | `ufw allow proto P from CIDR ... comment pft-fwaudit` per declared source, then delete every other allow for the port |
| missing-limit on the INPUT path | `ufw limit ... from 0.0.0.0/0` (or `::/0`), then delete the plain ALLOW from Anywhere |
| default-incoming-allow | `ufw default deny incoming` |
| ufw-inactive, Docker DNAT/DOCKER-USER paths, ACCEPTs outside UFW, nft tables, declared-unreachable, loopback DNAT | MANUAL |

`apply` (without `--dry-run`) refuses, changing nothing, unless: `--yes`; a `pft-maint` window is active with at least
`DEADMAN_MIN*60 + MAINT_MARGIN` seconds left and no data-collection lock; the node is `full` with `>= MIN_PEERS` peers
(host `RPC_URL`, or the same `docker exec CONTAINER curl` server_info call pft-selfheal makes); SSH `v4/tcp/22` is a
reachable declared exposure; no earlier apply is pending. It then snapshots `/etc/ufw/user.rules`, `user6.rules` and
`/etc/default/ufw` (sha256 recorded), runs adds before deletes (rule numbers re-read from `ufw status numbered` before
every delete), re-audits, and rolls back unless every planned finding is gone and every declared exposure is still
reachable. The dead-man (transient unit `fwaudit-deadman`, outside the `pft-*` namespace on purpose) polls every
`POLL_SEC` for `DEADMAN_MIN` minutes and rolls back after `BAD_POLLS` consecutive polls with the node not full, peers
below baseline minus `PEER_SLACK`, or a declared exposure (SSH included) gone. `rollback` copies the snapshot back,
runs `ufw reload` and checks the sha256 of every restored file. A UFW change moves the `pft-integrity` fw items: accept
the baseline with a reason after an intended apply.

## Found -> fixed -> verified

| Host | Found (capture 00:14Z) | Fix | Verified |
|---|---|---|---|
| sentry | stale-allow tcp/2559 IPv6: UFW allowed it, nginx listens on IPv4 only | removed the v6 rule (2026-11-14T00:45Z); `sentry/relay-setup.sh` now adds an IPv4-only rule | re-audit 00:46Z PASS, fixture `sentry-postfix.bundle` |

## Tests

`python3 -m pytest -q fwaudit/tests` runs over `tests/fixtures/*.bundle`, redacted real captures
(`tests/redact_capture.py`: global addresses to 203.0.113.0/24 / 2001:db8::/32, link-local interface ids to fe80::N).
Every finding class has an injected-fault test and a control that must not raise it.
`tests/test_plan.py` maps every class to its planned change or MANUAL; `tests/test_apply.py` runs the real script
against stubs (`tests/stubs`: ufw, capture, RPC, pft-maint, systemd) and, for every guard, asserts no mutating ufw
call was made and user.rules is unchanged; dead-man trips (node down, peer drop, lost SSH exposure, re-audit still
finding, failed ufw command) assert the restored sha256.
