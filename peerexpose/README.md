# peerexpose/ — what does your public peer port tell the internet?

`pft-peerexpose.sh` audits the HTTP handlers that postfiatd serves on its **public peer port (2559)** to anyone who
can reach it, and restricts them per host role with a guarded apply/rollback.

| Handler | What it can disclose | Controlled by |
|---|---|---|
| `/crawl` | node pubkey, build, uptime, state accounting; the overlay peer list (peer IPs, ports, pubkeys, versions); counts; UNL publisher lists | `[crawl]` |
| `/vl/<publisher key>` | the signed validator list the node trusts | `[vl] enable` |
| `/health` | `{"info":{}}` when healthy, state details when not | always served |

## Role policy

- **validator** (behind a sentry): everything in `/crawl` and `/vl` must be restricted. Its peer list reveals the
  sentry, and it is not meant to be a public crawl target.
- **sentry**: `crawl.overlay.*` and `crawl.counts` must be restricted (the overlay list contains the validator's
  address). Server info, UNL lists and `/vl` stay public so the sentry remains a useful public peer.
- `/health` details are reported but allowed for both roles.

## Audit (read-only)

```bash
pft-peerexpose audit --role validator                                  # local peer port
pft-peerexpose audit --role sentry --url https://<sentry-address>:2559  # cross-host: what the internet sees
pft-peerexpose audit --role validator --json
```

Every field is classified `disclosed`/`restricted` and judged `ok`/`VIOLATION` against the role policy. **Values are
never printed** (only counts), so the output is safe to publish. `/vl` is probed with the publisher keys from the local
admin RPC (`validators`, via `docker exec <container> curl`) or `--vl-key`. Exit codes: 0 no violation, 1 violation(s),
2 error (port unreachable / unparseable answer), 3 usage.

## Tests

```bash
bash tests/run-tests.sh   # offline: curl/sudo/docker are PATH stubs answering from tests/fixtures/
bash tests/mutate.sh      # classifier mutation check: every mutant must make the suite fail
```

Fixtures use documentation addresses (RFC 5737) and fake keys, include a 12-peer (two-digit) and a 1-peer case,
restricted/hardened nodes, unreachable and non-JSON answers, and config files with stock comments, operator-made
mixed-case `[Crawl]`/`[VL]` sections mid-file, and one invalid edit per validation rule. `mutate.sh` also mutates the
config renderer, the effective-settings parser and each validation rule.

```bash
sudo bash tests/keyprobe.sh   # what the blocks really do in the running image (throwaway container, --network none)
```

`keyprobe.sh` starts a throwaway container from the live node's image with **no network** and a copy of the live
config, once per variant, and prints only status codes and JSON key names. Results on `testnet-light-latest`
(2026-10-27):

| Variant | `/crawl` | `/crawl` sections | audit |
|---|---|---|---|
| stock (no `[crawl]`/`[vl]`) | 200 | `overlay`, `server`, `unl`, `version` | validator: 6 violations |
| validator block | **403** | none | validator: 0 violations |
| sentry block | 200 | `server`, `unl`, `version` (**no `overlay`**) | sentry: 0 violations |

`/vl/<key>` answered 404 in all three variants. With no network the node never fetches a validator list, so the probe
cannot tell an enabled `/vl` handler from a disabled one. `[vl] enable=0` is proven on the live node instead, where
`/vl/<publisher key>` serves a list before the change.

## Plan (read-only)

```bash
pft-peerexpose plan --role validator                                          # this host
pft-peerexpose plan --role sentry --ssh <sentry-ssh-alias> --container postfiatd-sentry
pft-peerexpose render --role sentry < postfiatd.cfg                           # print the rendered config
pft-peerexpose validate --role validator --old postfiatd.cfg --new edited.cfg
```

`plan` reads `postfiatd.cfg` from the container (a remote host through `ssh TARGET sudo -n`), removes any existing
`[crawl]`/`[vl]` sections, and appends one managed block for the role:

| Role | Managed block | Effective result |
|---|---|---|
| validator | `[crawl]` `0`, `[vl]` `enable=0` | `/crawl` 403, `/vl` off |
| sentry | `[crawl]` `overlay=0 server=1 counts=0 unl=1`, `[vl]` `enable=1` | `/crawl` without the peer list |

Rendering is idempotent and switching role re-renders cleanly. Validation rejects the result unless there is exactly
one `[crawl]` and one `[vl]` section, the effective settings (with postfiatd's defaults: crawl 1, overlay 1, server 1,
counts 0, unl 1, vl 1) match the role, `[port_peer]` is present, and **no line outside those two sections changes**.
`plan` prints effective settings before and after and the diff of the two sections only (no addresses or keys live
there). Exit 0 with `CHANGE NEEDED` or `NO CHANGE`, 2 on error. The change takes effect on the next container restart.

## Apply / rollback (writes)

```bash
pft-peerexpose apply --role validator --dry-run                     # everything up to the write: diff, lock + health check
pft-peerexpose apply --role validator                               # this host; required peers default to its [ips_fixed]
pft-peerexpose apply --role sentry --ssh <sentry-ssh-alias> --container postfiatd-sentry \
    --url https://<sentry-address>:2559 --require-peer <validator-address>
pft-peerexpose rollback --role sentry --ssh <sentry-ssh-alias> --container postfiatd-sentry --url https://<sentry-address>:2559
```

`apply`, in order:

1. read and render the config, `validate` it (same rules as above); `NO CHANGE` exits 0 without a restart;
2. **refuse (exit 4)** if a `pft-maint` data-collection lock is held, another apply/rollback holds the run lock, or
   the node fails the health gate *now* (so a node that is already unhealthy or missing its sentry is never touched);
3. `--dry-run` stops here (diff printed, nothing written);
4. timestamped backup (`0600` in a `0700` dir, `$STATE_DIR/backups/<target>/`, `LATEST` pointer per target);
5. open a `pft-maint` window (on the host running the tool, which also covers the sentry) and an Alertmanager silence
   for `2 x gate timeout + 10 min`; if either fails, nothing is changed;
6. install the config (same mode, atomic rename, sha256 check), restart the container **once**;
7. **gate** within `--gate-timeout` (900 s): `server_state` full or proposing, peers >= `--min-peers`, every required
   peer connected (validator default: the addresses in its `[ips_fixed]`, i.e. the sentry; matched against the
   `peers` admin RPC, never printed), and the role audit (local port, or `--url` for a remote target) shows
   0 violations;
8. gate failed: restore the backup, restart, gate again without the audit (exit 2 `ROLLED BACK`; exit 5 if that also
   fails). The window is closed in every case; the silence runs out on its own (container-restart alerts stay true for
   15 min after a start).

`rollback` restores `LATEST` (or `--from FILE`) for that target with the same lock check, window, silence and gate
(without the audit). It refuses if any line outside `[crawl]`/`[vl]` changed since the backup, keeps a `pre-rollback`
copy that does not move `LATEST` (so a second rollback is a `NO CHANGE`), and exits 0 `NO CHANGE` when the running
config already equals the backup. Exit codes: 0 applied / rolled back / no change, 2 error or automatic rollback,
3 usage, 4 refused (nothing changed), 5 rollback failed.

Env: `STATE_DIR` (`~/.local/state/pft-peerexpose`), `AM` (`http://127.0.0.1:9093`, `none` = no silence),
`SILENCE_MATCHER` (`alertname=~.+`), `MAINT_CMD` (`pft-maint`, `none` = no window), `POLL_SEC` (10).

The tests stub docker (config reads/writes, restart, admin RPC), `pft-maint` and Alertmanager. A restart makes the
config "take effect", so the gate sees the after-state: applied, idempotent re-apply, rollback byte-identical and
idempotent, drift refusal, automatic rollback when the block does not take effect, missing fixed peer, write failure
(exit 5), lock held, node syncing, too few peers, dry run, `AM=none`, remote sentry through ssh. `mutate.sh` adds
mutants for the lock check, required peers, the audit in the gate, the automatic rollback, the `LATEST` pointer, dry
run, the silence and the rollback drift check.

_The two-host live drill (after the data-collection lock ends 2026-10-28T06:20Z) and the found → fixed → verified
results are added in the next commit._
