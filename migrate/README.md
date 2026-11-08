# pft-migrate: planned host migration with fencing

Status: **implemented, offline-tested (steps 2-3)**; the live LXD drill (step 4) is not run yet. `pft-migrate.sh` +
`tests/run-tests.sh` (two fake hosts, stubbed docker/RPC/probe, real age keys).

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
# source                                                  # target
pft-migrate.sh plan [--role validator|sentry] [--json]    age-keygen -o target.key   # recipient: age-keygen -y
sudo pft-migrate.sh export --to age1... --out DIR         # copy DIR/pft-migrate-ID.age + .sha256 to the target
sudo pft-migrate.sh fence-source --bundle-id ID --proof-out source.proof   # copy source.proof to the target
                                                          sudo pft-migrate.sh import --bundle B.age --identity target.key
                                                          sudo pft-migrate.sh start-target --fence-proof source.proof --source SRC_ADDR
                                                          pft-migrate.sh verify --expect-pubkey n9... --since-proof source.proof
# rollback: on the target first                           sudo pft-migrate.sh fence --bundle-id ID --proof-out target.proof
sudo pft-migrate.sh rollback --bundle-id ID --fence-proof target.proof --target TGT_ADDR
pft-migrate.sh verify --expect-pubkey n9... --since-proof target.proof
```

Exit codes: 0 ok, 1 check failed / timeout, 2 integrity or crypto error (sidecar, age, layout, manifest, wrong
identity), 3 usage, 4 refused by a fencing rule. `verify` prints `downtime_s` = seconds from the proof's `fenced_at`
to `server_state full` with the expected `pubkey_node`.

Bundle contents (paths inside the encrypted tar; `import` rejects anything else, links and devices included):
`META`, `MANIFEST.sha256`, `cfgvol/postfiatd.cfg` + `validators.txt` (from the config volume, secrets kept: the
bundle is the identity), `compose/` (every COMPOSE_FILE member + `.env`), `cluster/node_seed` + `node_pub`
(pft-cluster), and the overlays' host files `host/etc/pft-seccomp/*.json`, `host/etc/apparmor.d/pft-*`. Plaintext is
staged only under `STAGE_BASE` (`/dev/shm`, RAM) and removed on exit. `import --skip-overlay NAME` drops one overlay
(and its host file) for a target that cannot load it, e.g. AppArmor inside a nested LXD sandbox; this is recorded in
`IMPORTED` as `skipped=`.

The compose guard is `docker-compose.migrate-fence.yml` (appended to COMPOSE_FILE): `restart: "no"` and an entrypoint
that does not exist, so a plain `docker compose up -d` on a fenced or freshly imported host creates a container that
cannot run. `import` installs it, `start-target` removes it, `fence` adds it, `rollback` restores the source's `.env`
byte-identical from the copy taken at the first fence.

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

## Offline tests

`bash migrate/tests/run-tests.sh` (no root, docker or network): arguments, plan (file list, missing overlay member
or host file), export (age header, 0600, sidecar, inner manifest, no plaintext seed in the bundle, RAM stage
removed), fence (state, proof fields, guard against `compose up`, idempotent re-fence, second bundle refused),
import negatives (wrong identity, flipped byte with and without a re-made sidecar, truncation, no sidecar, changed file,
extra file, out-of-layout path, symlink, `../` escape, bad META, running copy), import (modes, volume labels, never
starts), start-target refusals (proof running / other bundle / other pubkey / no guard, source still answering, host
fenced), verify (match, wrong identity, timeout, downtime), rollback (target running, older proof, wrong bundle, on
the target, byte-identical `.env`, restart policy restored, lock removed) and seed/age-identity never printed.

Mutation check: `bash migrate/tests/mutate.sh` removes one safety check at a time (16 mutants: source/target probe,
sidecar, layout, manifest, extra file, links, guard, proof checks, restart-policy restore, running-copy refusal,
fenced-host refusal, identity check, proof age, identity-file recipient) and needs the suite to fail for each.

| Log | What | Result |
|---|---|---|
| [logs/01-offline-checks.log](logs/01-offline-checks.log) | shellcheck, suite, mutants | shellcheck 0, suite 119 passed / 0 failed, mutants 15 killed / **1 survived** ("export accepts identity file": an age-keygen identity also fails the recipient match, so the secret-key guard was never tested alone) |
| [logs/02-offline-checks.log](logs/02-offline-checks.log) | same, after adding a recipient+secret-key file test | shellcheck 0, suite 120 passed / 0 failed, mutants 16 killed / 0 survived |

A read-only `plan` on the live validator listed 13 files (cfg, validators.txt, 6 compose files + `.env`, pinned
seed + pub, AppArmor profile, seccomp JSON), `RESULT: OK`, and left nothing in `/dev/shm`; its output is not
published (host layout).

## Drill (step 4, planned)

Real source = this validator host, target = a fresh LXD sandbox (rebuild/ infrastructure). Alerts during the drill
go to a throwaway ntfy topic; an Alertmanager silence covers only the planned source stop; afterwards: operator-topic
read-back = 0, `pft-integrity` re-baselined for every intended change, source back at `full`.
