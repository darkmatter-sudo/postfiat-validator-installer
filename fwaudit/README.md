# fwaudit: declared inbound policy vs effective exposure

**Status: in progress (task_32d07e3a).** The read-only audit (`audit [--json]`), per-role policies, redacted
captures of both hosts and the unit tests are in. Remediation (`plan/apply/rollback`), the timer, textfile metrics,
the alert, fleet/integrity/schedaudit/jobwatch/rulecheck integration, mutation and promtool tests, the drills and
the results table follow.

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

## Found -> fixed -> verified

| Host | Found (capture 00:14Z) | Fix | Verified |
|---|---|---|---|
| sentry | stale-allow tcp/2559 IPv6: UFW allowed it, nginx listens on IPv4 only | removed the v6 rule (2026-11-14T00:45Z); `sentry/relay-setup.sh` now adds an IPv4-only rule | re-audit 00:46Z PASS, fixture `sentry-postfix.bundle` |

## Tests

`python3 -m pytest -q fwaudit/tests` runs over `tests/fixtures/*.bundle`, redacted real captures
(`tests/redact_capture.py`: global addresses to 203.0.113.0/24 / 2001:db8::/32, link-local interface ids to fe80::N).
Every finding class has an injected-fault test and a control that must not raise it.
