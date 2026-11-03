# pft-cluster: pinned node identities and a validator + sentry cluster

`../sentry` puts the validator behind a sentry: the validator's only fixed peer is the sentry, and the sentry is
the public node. Two things were still missing:

1. **Node identity is not pinned.** Without `[node_seed]`, postfiatd keeps its node key (`pubkey_node`) in
   `wallet.db` inside the data volume (`NodeIdentity.cpp`, `getNodeIdentity`). Recreating the sentry with a fresh
   data volume, or a restore from a different backup, gives it a new identity, and anything that recognises the
   sentry by key stops matching.
2. **The two nodes are plain peers.** With `[cluster_nodes]`, each node lists the other's node public key. Cluster
   members are trusted for load reports (cluster fee), are not charged as ordinary peers for the traffic they relay,
   are flagged `cluster: true` in `peers`, and exchange periodic cluster reports, so each side can prove the other
   counts it as a member. The sentry relays everything for the validator, so this is the relationship postfiatd has
   for exactly this setup.

`pft-cluster.sh` adds both, on Dockerized postfiatd 1.0.9, with the same safety pattern as the other add-ons:
read-only audit, guarded apply inside a `pft-maint` window with a health gate and **automatic rollback**, explicit
rollback, metrics + one alert, pft-integrity baseline handling, and an offline test suite with a mutant harness.

Source facts this relies on (postfiatd at the running build's commit `32723c15e686a2088f2c83017a6ff909d93822cd`):

| what | source |
|---|---|
| section names `node_seed`, `cluster_nodes` | `src/xrpld/core/ConfigSections.h` (`SECTION_NODE_SEED`, `SECTION_CLUSTER_NODES`) |
| `[node_seed]`: first line, base58 seed; key = `generateSecretKey(secp256k1, seed)` -> `derivePublicKey` | `src/xrpld/app/main/NodeIdentity.cpp` |
| `validation_create` derives `validation_public_key` with the same two calls, so its key IS the node key a `[node_seed]` with its `validation_seed` gives | `src/xrpld/rpc/handlers/ValidationCreate.cpp` |
| `[cluster_nodes]`: `<n9 key> [comment]` per line; a malformed entry or invalid key makes `Cluster::load` fail (node does not start); duplicates are skipped | `src/xrpld/overlay/detail/Cluster.cpp`, `Application.cpp` |
| `peers` RPC: `cluster` object (every member except self; `age` only after that member sent a report), `peers[].cluster = true` for a connected member | `src/xrpld/rpc/handlers/Peers.cpp`, `src/xrpld/overlay/detail/PeerImp.cpp` |
| cluster reports from a non-member are rejected ("unknown cluster") | `PeerImp::onMessage(TMCluster)` |

So "the peer counts **us** as a member" is visible locally: `cluster[<peer key>].age` exists only if the peer sends
us cluster reports, and it only sends them to nodes in its own `[cluster_nodes]`. The audit uses that as the
second direction (`live:reports`); `live:peer` is the first (we list it and it is connected as a member).

## Live proof (run 1, 2026-11-03T13:11Z): 51/51 checks, both hosts clustered

Recorded with `drill/live-run.sh` at commit `4d375983bc361ed40698d38fdc0044230514832c` (the run commit adds the
`cluster.rules.yml` line to `alerts/prometheus.yml` and the five `fleet/manifest.tsv` lines). Both nodes ran under
the enforced `pft-postfiatd` AppArmor profile (`../apparmor`). Node keys appear only as `node:` fingerprints
(sha256 with a per-cluster key, first 12 hex); seeds are never printed. Script sha256 values are in the log header
(`pft-cluster.sh` `a31db6d4d9779e399e020dd1f371ff2c7f678ed05e3dc45e477d9becdcdf0975`).

| step (`logs/09-live.log`) | result |
|---|---|
| 0 preflight (also `logs/07`, rc 4: run-commit lines absent; `logs/08`, rc 0: ready) | both nodes full, integrity PASS on both, redaction control 18/18 |
| 1 notifiers on a throwaway topic, silence excluding `PFTAlertPipelineWatchdog`, `pft-maint` window | 3/3 |
| 2 install on both hosts + the validator's pull of the sentry file; `PFTClusterMissing` loaded | 4/4 |
| 3 `keygen` (`validation_create`) on each node, seed 0700/0600 root, `set-peer` both ways | 6/6 |
| 4 before: `cfg:node_seed` and `live:peer` FAIL on both hosts (not clustered) | 4/4 |
| 5 sentry apply with an injected gate miss: exit 1, automatic rollback, config sha256 `aef4f1ff544a` and `pubkey_node` back | 3/3 |
| 6 sentry apply, 7 validator apply `--require-peer` (gate: sentry connected with `cluster=true`, report 8 s old) | 4/4 |
| 8 after: `live:peer` + `live:reports` PASS from both sides (both directions) | 2/2 |
| 9 seed found 0 times in `docker inspect`, `ps`, last 20000 log lines, textfiles, on both hosts | 2/2 |
| 10 sentry container re-created (Id `8b9a8200d56e` -> `f3874051771a`): `pubkey_node` unchanged `node:001a67fe0285`, cluster re-formed | 5/5 |
| 11 sentry-only rollback (back to `node:1ddc9abb8b42`, validator sees it gone), re-apply `--require-peer` | 6/6 |
| 12 textfiles `findings 0` / `peer_clustered 1`, Prometheus `pft_cluster_findings 0` for both | 2/2 |
| 13 integrity accept on both, fleet sync + skew (`cluster` CURRENT on both), rulecheck OK | 4/4 |
| 14 restore: env files byte-identical, window ended, operator topics 0 messages, integrity PASS, both nodes full | 6/6 |

The sentry re-creation drops runtime `docker update` settings, so `logs/10-resources-reapply.log` puts the
sentry's cpu-shares / memory reservation back (the same values as before the run).

## Usage

```
pft-cluster audit [--json] [--prom FILE | --textfile]   read-only (root: reads the 0600 seed and config)
sudo pft-cluster keygen                                validation_create on this node -> /var/lib/pft-cluster/node_seed
pft-cluster pubkey                                     this node's pinned public key (public; for set-peer on the other host)
sudo pft-cluster set-peer KEY [TAG]                    the other node's pinned key -> PEER_PUBKEY in /etc/pft-cluster.env
pft-cluster plan                                       read-only: the block apply would write (seed redacted)
sudo pft-cluster apply --yes [--dry-run] [--require-peer]
sudo pft-cluster rollback --yes                        restore the newest config backup, restart, gate
sudo pft-cluster pull                                  validator: copy the sentry's textfile (install.sh --pull)
pft-cluster validate FILE HOST                         the check pull applies to a fetched textfile
```

Exit codes: 0 PASS / applied, 1 findings / rolled back after a gate miss, 2 error, 3 usage, 4 refused, 5 rollback failed.

| check id | PASS when |
|---|---|
| `seed:stored` | `/var/lib/pft-cluster` is 0700, `node_seed` is 0600 root, seed and stored public key are well-formed base58 |
| `cfg:node_seed` | exactly one `[node_seed]` section, inside the managed block, equal to the stored seed (compared with `cmp`, never printed) |
| `cfg:mode` | `postfiatd.cfg` is 0600 once it holds a seed (INFO while it holds none) |
| `cfg:cluster_nodes` | `PEER_PUBKEY` is listed and every entry is well-formed (WARN: an unmanaged `[cluster_nodes]`, merged by postfiatd) |
| `live:pubkey` | `server_info.pubkey_node` = the pinned key (FAIL also means "config written, restart pending") |
| `live:cluster` | `peers.cluster` lists `PEER_PUBKEY`: the running node loaded the config |
| `live:peer` | a connected peer has `public_key` = `PEER_PUBKEY` and `cluster: true` (matched by key, never by address: inbound peers behind docker-proxy all show the bridge gateway) |
| `live:reports` | that member sent a cluster report within `REPORT_MAX` (300 s): **it lists this node too** |
| `secret:exposure` | the seed is in none of: `docker inspect`, any process command line (`ps -eo args`), the last 5000 container log lines, the textfiles |

Node keys are printed as keyed fingerprints `node:<12 hex>` (`sha256(fp_key || key)`, `fp_key` a random 0600 file
shared by both hosts), so logs can show that two keys are equal without publishing either. `pubkey` prints the real
public key for the operator.

## Secrets

- The seed comes from `validation_create` on the node itself (admin RPC inside the container). Its answer goes
  straight into 0600 files in a 0700 directory; the private key and the RFC1751 words are discarded.
- The seed never appears on a command line: every comparison and search reads it from the file (`cmp`, `grep -Ff`,
  `awk` reading the file), and the config candidate is built by `cat`-ing the file.
- `postfiatd.cfg` becomes 0600 when the seed is written (it was 0644 in the image). Config backups are 0600 in
  `/var/lib/pft-cluster/backups` (0700); each records the original mode/owner (`.meta`) and the pre-apply
  `pubkey_node` (`.pubkey`), and rollback restores both.
- `secret:exposure` re-checks `docker inspect`, process args, container logs and textfiles on every audit.

## apply and rollback

`plan` / `apply --dry-run` show the block (other lines of `postfiatd.cfg` are kept byte-for-byte; trailing blank lines
before the block are normalised once, so re-applying never grows the file):

```
# BEGIN pft-cluster (managed; edit with pft-cluster, see cluster/README.md)
[node_seed]
<seed: redacted>

[cluster_nodes]
node:<fingerprint of PEER_PUBKEY> sentry
# END pft-cluster
```

0. **Refusals (exit 4, nothing changed):** not root, no `--yes`, no `pft-maint` window, no stored seed, no or
   malformed `PEER_PUBKEY`, `PEER_PUBKEY` = this node's own key, an unmanaged `[node_seed]` or `[cluster_nodes]`
   section, broken block markers.
1. **Idempotent:** if the candidate equals the live file (0600), the node already runs the pinned key and the member
   is loaded, apply prints `already applied` and does not restart.
2. **Change:** backup (0600 + `.meta` + `.pubkey`), candidate written 0600 in the config directory and renamed over
   `postfiatd.cfg`, `docker restart -t 60`.
3. **Health gate** (`HEALTH_BUDGET`, 900 s: a sentry resync after a restart can take several minutes): the container
   restarted (StartedAt changed), `server_state` full, `pubkey_node` = pinned key, `PEER_PUBKEY` in `peers.cluster`,
   `:2559` listening, `sshd -t` + a fresh `:22` handshake, every pft daemon that was running still active.
   `--require-peer` (used for the second host) also needs `live:peer` and `live:reports`.
4. **Automatic rollback** on a miss: byte-identical restore (sha256 compared) + original mode/owner, restart, rollback
   gate (same checks, and `pubkey_node` must be the **pre-apply** key again), exit 1; exit 5 if that fails.
5. **pft-integrity:** if installed, the new baseline is accepted only if every changed item is
   `cfgvol:postfiatd.cfg`; anything else is reported and left for a human.

`rollback --yes` does steps 4-5 from the newest backup (needs a window too).

Sequence on two hosts (`drill/live-run.sh`): `keygen` on both, exchange keys with `pubkey` / `set-peer`, apply on the
**sentry first** (its gate cannot require the validator yet: the validator still runs its old key), then on the
validator with `--require-peer`, then `--require-peer` audits on both sides.

## Install, metrics, alert

```
sudo ./install.sh                 # validator (HOST_LABEL=validator, PEER_LABEL=sentry)
sudo ./install.sh --host sentry   # sentry (PEER_LABEL=validator)
sudo ./install.sh --pull          # validator: pull the sentry's textfile (PULL_SSH in /etc/pft-cluster.env)
```

Config keys: [`pft-cluster.env.example`](pft-cluster.env.example) (`/etc/pft-cluster.env`, root 0600, never sourced).

`pft-cluster.timer` audits every 5 minutes into `pft_cluster_<host>.prom`: `pft_cluster_check{host,check,status}`,
`pft_cluster_peer_clustered{host}` (1 = connected member that reports to us), `pft_cluster_findings{host}`,
`pft_cluster_last_run_timestamp_seconds{host}`. The unit is sandboxed (`ProtectSystem=strict`, AF_UNIX only for
docker.sock, capabilities `CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`).

### Alert

`../alerts/cluster.rules.yml`: **PFTClusterMissing** (warning) when `max by (host) (pft_cluster_findings) > 0` for
15 minutes: the cluster is missing or degraded on that host (peer not a connected member, no reports from it, node
not on its pinned key, config/seed storage wrong, or the seed exposed). 15 minutes lets a planned restart re-form
the cluster without paging. A stopped audit is caught by pft-rulecheck (`textfile pft_cluster_*.prom 20m`) and
`PFTTextfileStale`. The sentry runs no Prometheus; its alert is evaluated on the validator from the pulled file.
promtool tests: `../alerts/cluster.tests.yml`.

## Tests

- `tests/run-tests.sh`: offline suite against a fake host (`tests/stubs.sh`) and a fake postfiatd
  (`tests/fake_node.py`, which answers `server_info` / `peers` / `validation_create` from the config it loaded at its
  last restart, following the source rules above). No root, docker or network. It uses a temp dir under
  `~/.cache` (override `TEST_TMPDIR`): `/tmp` is noexec on a host hardened by `../mounts`, and the stubs must run.
- `tests/mutate.py`: mutant harness; each mutant is one exact replacement that must match once; an unmutated control
  run must pass first; every suite run has a timeout (a hang counts as killed); documented equivalents are listed with
  the reason.
- Recorded run `logs/11-suite-mutants.log` (git archive of `4d37598`, the live run's commit; script sha256 in the
  header): shellcheck clean, suite 130 passed / 0 failed, mutant control 130/130, 52 killed + 1 documented equivalent
  (G13: `cp -p` success already implies equal bytes) of 53, 0 survived / not applied.
- `drill/identity-control.sh`: the source facts above, checked on **throwaway containers** (same image as the running
  node, `--network none`, a fresh anonymous data volume per run, `--memory 2g`; the live nodes and their volumes are
  never touched): the stock config twice gives two different `pubkey_node` values; the stock config plus a
  `[node_seed]` from `validation_create` gives the same key twice, equal to `validation_public_key`; a malformed
  `[cluster_nodes]` entry stops postfiatd (`Overlay:ERR Malformed entry` / `Application:FTL Invalid entry in cluster
  configuration`), which is why apply validates entries and the gate rolls back a node that does not come up.
- `drill/recreate.sh`: re-creates the sentry container with its full runtime profile (pft-confine's `recreate_args`
  plus caps, read-only root, tmpfs, pids/memory limits, security_opt read back from HostConfig), refuses if the image
  tag now names another image, compares a config summary before/after and restores the old container on any mismatch.
