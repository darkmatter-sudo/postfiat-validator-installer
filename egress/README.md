# pft-egress: default-deny outbound policy for postfiatd containers

By default a Docker container can open a connection to any address on any port. A compromised postfiatd (or any
other process in the image) could then send a validator key to an attacker's server, fetch a second-stage payload,
or join a botnet, and nothing on the host would stop it. A node needs very little outbound traffic: DNS, its peers,
and the validator-list site. `pft-egress` allows exactly that and logs and drops everything else. It does not
restart the container or the node.

| New outbound connection from the container | Policy |
|---|---|
| replies to inbound peers, and replies to allowed outbound connections (`ESTABLISHED,RELATED`) | allowed |
| DNS, udp+tcp 53, **only** to the nameservers in the container's `/etc/resolv.conf` | allowed |
| TCP to peer ports: 2559, the ports in `[ips]` / `[ips_fixed]`, and the remote ports of the node's current outbound peer connections (`ss` in its netns) | allowed |
| TCP to the `[validator_list_sites]` ports (https: 443) | allowed |
| anything else | `LOG` (rate-limited, prefix `pft-egress-drop: `) then `DROP` |

The rules live in their own chain, `PFT-EGRESS`. One jump at **position 1 of `DOCKER-USER`** matches only packets
that come from the container's IP on its bridge and leave the bridge (`-s IP/32 -i BRIDGE ! -o BRIDGE`). The
existing `DOCKER-USER` rules (for example the installer's 2559 rate limit) stay in place, in order, after the jump.
Allowed packets `RETURN`, so Docker's own chains still run afterwards, and pft-egress never accepts anything that
Docker or UFW would otherwise drop.

Run it on a **sentry first**, then on the validator.

## Usage

```
pft-egress plan     [--container NAME] [--json]          # read-only: allowlist + exact iptables-restore input
sudo pft-egress apply --dry-run [--container NAME]       # rendered rules + diff vs the live chain; changes nothing
sudo pft-egress apply --yes [--container NAME] [--deadman MIN] [--foreground]
sudo pft-egress check [--container NAME]                 # exit 0 = PASS
sudo pft-egress rollback --yes [--container NAME]
sudo pft-egress probe --container NAME --target HOST:PORT   # one TCP connect from inside the container, 5 s timeout
```

Exit codes: 0 ok/PASS, 1 check failed or the dead-man rolled back, 3 usage/config error, 4 refused, 5 rollback failed.

### apply

`apply --yes` refuses (exit 4) unless all of these are true:

- a `pft-maint` window is active with at least `DEADMAN*60 + MAINT_MARGIN` seconds left (default 900 s), and no
  data-collection lock is held;
- the node is `full` and has at least `MIN_PEERS` (3) peers;
- the container's `resolv.conf` lists at least one nameserver.

It then:

1. loads `PFT-EGRESS` with `iptables-restore --noflush`, so the chain is replaced in one step and no other chain
   is touched;
2. makes sure exactly one jump exists, at `DOCKER-USER` position 1, and removes stale or duplicate jumps;
3. writes `/var/lib/pft-egress/NAME.json`: the policy, the `iptables -S` snapshot and the baseline peer count;
4. installs itself as `/usr/local/sbin/pft-egress` and enables `pft-egress-reapply@NAME.timer`;
5. starts the **dead-man**. For `DEADMAN` minutes (default 10) it polls `server_info` every `POLL_SEC` (30 s).
   After `BAD_POLLS` (3) consecutive polls where `server_state` is not `full` or peers are below
   `baseline - PEER_SLACK` (slack 1, for normal one-peer churn), it rolls back. By default the dead-man runs as
   the transient unit `pft-egress-deadman@NAME`, so it survives a dropped SSH session. With `--foreground` it
   runs inline.

If you run `apply` again with an unchanged plan, it prints `no change` and leaves the firewall byte-identical.

### Persistence

iptables rules do not survive a reboot, and a container can get a new IP when it is recreated.
`pft-egress-reapply@NAME.timer` runs `pft-egress reapply` 60 s after boot and then every 5 minutes. Each run
re-renders the saved policy with the container's **current** IP. If the chain, the jump and the IP already match,
it does nothing and prints nothing. Otherwise it reloads the chain and fixes the jump.

### check

`check` verifies five things:

- the chain is byte-identical to the snapshot taken at apply;
- the container IP has not changed;
- there is exactly one jump, at `DOCKER-USER` position 1;
- the reapply timer is enabled;
- `server_state` is full and peers are at or above the baseline.

It also prints the DROP counter and the drop-log lines from the last hour, grouped by destination port. Use those
lines to spot a legitimate destination you forgot (see below).

## Before you apply

- **Peers on non-standard ports.** The plan includes every port in `[ips]` / `[ips_fixed]` and every remote port
  the node is connected to right now. If peer discovery later wants a peer on another port, that dial is dropped
  and logged (`DPT=`). Add the port with `EXTRA_TCP_PORTS="51235"` and re-run `apply`.
- **Validator-list mirrors.** Only the ports of the configured `[validator_list_sites]` are allowed, on any
  address. A site served from a CDN keeps working when its IP changes.
- **Docker's embedded DNS.** On a user-defined network the container's resolver is `127.0.0.11`. Those lookups
  are made by dockerd on the host and never reach this chain, so `plan` warns about them and does not add a rule.

## Limits

- **IPv4 only.** `plan` warns if the container has a global IPv6 address, because IPv6 egress is not filtered.
  The stock installer's containers have no IPv6.
- **Bridge networks only.** `network_mode: host`, `none` and `container:` are refused. A host-network container
  never crosses `FORWARD` and would need an `OUTPUT` owner match. Containers attached to several networks are
  also refused.
- **Port allowlist, not address allowlist.** Peers come and go, so peer ports (2559) and 443 are allowed to any
  address. An attacker could still reach a server they control that listens on 2559 or 443. The policy removes
  every other port and every non-configured DNS server, which blocks DNS tunnelling to third-party resolvers,
  plain HTTP, IRC/C2 ports and SMTP. It does not make exfiltration impossible. It is one layer on top of
  `confine/`. Treat it as such.
- **Kernel LOG lines are rate-limited** (6/min, burst 10). The DROP counter in `check` counts every packet.

## How it fits with the other add-ons

- `confine/` limits what a compromised process can do *inside* the container (capabilities, read-only rootfs).
  `egress/` limits where it can *connect*. They are independent, and apply order does not matter.
- `sysctl/` hardens the host network stack. pft-egress needs `net.ipv4.ip_forward=1`, which Docker sets anyway.
- `integrity/` tracks the normalized `DOCKER-USER` rules and the systemd units. After every `apply`, `reapply`
  that changed something, or `rollback`, run `sudo pft-integrity accept --reason "..."`.
- `maint/`: `apply` needs a pft-maint window. `pft-maint lock`s (24 h collectors) block it.

## Tests

- `tests/run-tests.sh` (no root, 42 cases): a stateful fake `iptables`/`iptables-restore`
  (`tests/fake_iptables.py`) plus stubs for docker, pft-maint, systemctl, journald and `server_info`, and a fake
  clock. The fixtures in `tests/fixtures/` are real `ss`, `resolv.conf`, `postfiatd.cfg`, `validators.txt` and
  `DOCKER-USER` output from the sentry, with public IPs replaced by documentation ranges. The suite covers plan
  parsing, every apply guard (firewall untouched), dry-run, apply + idempotent re-apply, check (counters, drop log,
  peers, IP drift), reapply (IP change, flushed chain, duplicate jump), rollback (twice, original `DOCKER-USER`
  byte-identical), and the dead-man (trip after 3 bad polls, no trip on 2, poll count, restore failure).
- `tests/netns-test.sh` (root, 17 cases): **real** iptables in three throwaway network namespaces ("container",
  "host" with `FORWARD -> DOCKER-USER` and the sentry's rate-limit rules, "internet" with listeners). The
  container connects out before apply. After apply, :80, :8080 and :53 to a non-resolver are dropped (5 s
  timeouts, DROP counter > 0). :53 to the resolver, 2559, 51235 and 443 still connect. An inbound connection to
  the container's 2559 gets its reply. Re-apply is byte-identical. Reapply restores a flushed `DOCKER-USER`.
  Rollback leaves the filter table identical to before.
- `drill-sentry.sh`: the live found -> fixed -> verified drill. It points every notifier on the host at a
  throwaway topic, proves the guard, probes before, applies in a pft-maint window with an inline dead-man, probes
  after, checks the drop log and the validator-list fetch, runs check, and rebaselines pft-integrity.
- `stability.sh` (read-only): evidence that the node stayed healthy under the policy. It reports the container's
  start time and restart count, every `NetworkOPs` heartbeat line in `debug.log` since `applied_at` (one a second)
  in 10-minute buckets with the mode each reports, and N `server_info` samples (state, peers, ledger range, DROP
  counter). PASS = no container start in the window, every heartbeat `full`, no empty bucket, every sample `full`
  with peers >= the apply-time baseline. A heartbeat line without a `mode: x.` field (for example
  `set mode to DISCONNECTED`) counts as not full; it is never skipped. Timestamps are read as UTC whatever the host
  time zone is (the sentry runs on UTC+1). `tests/stability-test.sh` (11 cases, one fault each) runs it against real
  sentry heartbeat lines (`tests/fixtures/heartbeat.log`) with stubbed docker/iptables and a fake clock.
- `drill-rollback.sh`: the live rollback drill, run on a host that already has the policy. Notifiers go to a
  throwaway topic. It checks PASS and probes blocked first. Then `rollback` without `--yes` must refuse with the
  table unchanged, and `rollback --yes` must leave `DOCKER-USER` byte-identical both to the live rules minus the
  jump and to the pre-apply listing in `logs/sentry-live-drill.log`. The whole filter table must equal the
  before-snapshot minus the pft-egress lines, with no `PFT-EGRESS` chain, the timer disabled, the probe connecting
  again and the validator list still 200. Then it rebaselines pft-integrity, re-applies in a pft-maint window with
  the inline dead-man (the policy stays on), checks PASS and probes blocked, and rebaselines again.

Logs: [`logs/`](logs/).
