# peerexpose/ — what does your public peer port tell the internet?

`pft-peerexpose.sh` audits the HTTP handlers that postfiatd serves on its **public peer port (2559)** to anyone who
can reach it, and (next step, in progress) restricts them per host role with a guarded plan/apply/rollback.

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
restricted/hardened nodes, unreachable and non-JSON answers.

_Plan/apply/rollback, the two-host drill and the found → fixed → verified results are added in the next commits._
