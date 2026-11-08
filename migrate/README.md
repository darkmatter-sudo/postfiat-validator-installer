# pft-migrate: planned host migration with fencing

Status: **design (step 1)**. Nothing below is implemented yet; this section is the contract the code and tests will be
written against.

Moving a Post Fiat node (validator or sentry, `postfiatd` in Docker) to a new host means copying its identity
(`[node_seed]`, so `pubkey_node` stays the same and the peer's `[peer_private]`/`[ips_fixed]` pairing keeps working)
and its configuration. The dangerous moment is the cutover: two running copies of one node identity confuse peers, and
for a validator with a token they would be two signers. `pft-migrate.sh` makes "both copies running" a state the tool
refuses to enter.

## What it reuses

| From | Used for |
|---|---|
| `backup/pft-backup.sh` | file list of the node's configuration (cfg, validators.txt, compose files + `.env`, add-on units); the bundle uses the same list **plus** every file named by `COMPOSE_FILE` in `.env` (backup lesson: overlays were missed once) |
| `keyescrow/` | age recipients/identities and the "plaintext never on disk, decrypt in a pipe" rule; `cluster:node_seed`/`fp_key` item paths |
| `cluster/` | `pubkey_node` read-back and the pinned seed file `/var/lib/pft-cluster/node_seed` |
| `maint/` | `pft-maint lock` so the watchdog/monitors do not restart or page during the fenced window |
| `rebuild/` | the LXD sandbox (own bridge, resource caps, teardown proof) as the drill's fresh target host |

## Commands

```
pft-migrate.sh plan        --role validator|sentry [--json]          # read-only: what would move, sizes, checks
pft-migrate.sh export      --to RECIPIENT.pub --out DIR               # age bundle + MANIFEST.sha256 + sidecar sha256
pft-migrate.sh fence-source --bundle-id ID                            # stop node, restart=no, fence file, maint lock
pft-migrate.sh import      --bundle FILE --identity KEY               # verify outer+inner sha256, unpack, no start
pft-migrate.sh start-target --fence-proof FILE                        # refuses unless the source fence is proven
pft-migrate.sh verify      --expect-pubkey PUB                        # server_state full + pubkey_node match
pft-migrate.sh rollback    --bundle-id ID                             # stop/fence target, unfence + start source
```

## Fencing guarantees

1. `export` records the source's `pubkey_node` and a random bundle id in the (encrypted) manifest.
2. `fence-source` stops the container, sets its restart policy to `no`, writes `/var/lib/pft-migrate/FENCED`
   (bundle id, time, pubkey), takes a `pft-maint` lock, and prints a fence proof: container state `exited`, restart
   policy, and the source's peer port no longer answering. A source start (`docker compose up`, or this tool) while
   `FENCED` exists is refused by the tool and by a compose pre-start guard.
3. `start-target` checks the fence proof is for the same bundle id and pubkey, then **probes the source itself**; if
   the source node still answers, it refuses (exit 4).
4. `rollback` is the only path that removes `FENCED`: it stops and fences the target first, then restores the source.

## Limits (by design)

- The ledger DB is not moved; the target syncs from the network (downtime = time to `full`, measured).
- Fencing is cooperative for anything outside this tool: someone running plain `docker start` on the source bypasses
  the guard. The fence proof makes that visible, it cannot make it impossible.
- No validator token is moved by the drill host (it has none); the token path is covered by offline tests only.

## Drill (step 4, planned)

Real source = this validator host, target = a fresh LXD sandbox (rebuild/ infrastructure). Alerts during the drill
go to a throwaway ntfy topic; an Alertmanager silence covers only the planned source stop; afterwards: operator-topic
read-back = 0, `pft-integrity` re-baselined for every intended change, source back at `full`.
