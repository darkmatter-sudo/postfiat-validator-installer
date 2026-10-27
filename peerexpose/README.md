# peerexpose/ — what does your public peer port tell the internet?

`pft-peerexpose.sh` audits the HTTP handlers that postfiatd serves on its **public peer port (2559)** to anyone who
can reach it, and restricts them per host role (plan/render/validate now; guarded apply/rollback next).

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

_apply/rollback (backups, maintenance window + Alertmanager silence, health gate, automatic rollback), the two-host
drill and the found → fixed → verified results are added in the next commits._
