# pft-keyescrow: cross-host escrow of add-on secrets (work in progress)

The add-ons in this repo create secrets that exist on one host only: the pinned node seed of `../cluster`, the
logship TLS keys and CA key, the journald FSS sealing key of `../audittrail`, the heartbeat HMAC keys, and the
ntfy targets. If a host's disk is lost, they are gone, and some of them (the node seed = the node's identity
`pubkey_node`, the logship CA key) cannot be recreated without reconfiguring the other host too.

pft-keyescrow encrypts each host's secrets to the **peer's** age public key and keeps N generations there, so
either host can be rebuilt from the other one. Plaintext is never written to disk and never crosses the network:
the source host packs and encrypts in one pipe, the peer stores ciphertext only, and the peer checks a generation by
decrypting it in memory with its own age identity (root-only, 0600).

Status: **steps 1-2 of the task are done offline (inventory, metrics, alert rules; keygen, seal, two-way escrow,
receive + in-memory verify, tamper detection)**. Restore, the mutant run, install and the live two-host proof come
next. This README covers only what exists now.

## Inventory (read-only)

```sh
sudo keyescrow/pft-keyescrow.sh inventory            # table + RESULT line
sudo keyescrow/pft-keyescrow.sh inventory --json     # one object per item
sudo keyescrow/pft-keyescrow.sh inventory --textfile # also writes pft_keyescrow.prom for node_exporter
```

Every declared item comes from a line of an add-on's source in this repo (the `cite` column). `tests/run-tests.sh`
checks that each cited line still names the path, so a renamed path in an add-on breaks the test, not the escrow.

| id | hosts | path | mode owner:group | need | cite |
|---|---|---|---|---|---|
| cluster:node_seed | both | /var/lib/pft-cluster/node_seed | 600 root:root | req | cluster/pft-cluster.sh:78 |
| cluster:fp_key | both | /var/lib/pft-cluster/fp_key | 600 root:root | req | cluster/pft-cluster.sh:80 |
| cluster:env | both | /etc/pft-cluster.env | 600 root:root | req | cluster/install.sh:17 |
| logship:env | both | /etc/pft-logship.env | 600 root:root | req | logship/pft-logship.sh:40 |
| logship:host_key | both | /etc/pft-logship/tls/host.key | 640 root:systemd-journal-remote | req | logship/pft-logship.sh:115 |
| logship:ca_key | validator | /etc/pft-logship/ca/ca.key | 600 root:root | req | logship/pft-logship.sh:237 |
| journald:fss | both | /var/log/journal/&lt;machine-id&gt;/fss | 600 root:systemd-journal | req | audittrail/pft-audittrail.sh:87 |
| alertpath:hmac | both | /etc/pft-alertpath/hmac.key | 600 root:root | req | alertpath/pft-alertpath.sh:168 |
| watchdog:hmac | both | /etc/pft-watchdog/hmac.key | 600 root:root | req | watchdog/pft-heartbeat.sh:14 |
| ntfy:monitor | validator | /etc/postfiat-monitor.env | 600 root:root | req | monitor/install-monitor.sh:15 |
| ntfy:maint | both | /etc/pft-maint/ntfy.env | 600 root:root | opt | maint/install.sh:36 |
| ntfy:alertpath | sentry | /etc/pft-alertpath/ntfy.env | 600 root:root | req | alertpath/pft-alertpath.sh:300 |
| ntfy:watchdog | sentry | /etc/pft-watchdog/ntfy.env | 600 root:root | req | watchdog/install.sh:12 |
| ntfy:alerts | validator | conf `ALERTS_NTFY_ENV` (the alert stack's `NTFY_ENV_FILE`) | 600 conf `ALERTS_NTFY_OWNER` | opt | alerts/run-stack.sh:13 |
| valkeys:keys | validator | conf `VALKEYS_DIR`/validator-keys.json | 600 | opt | valkeys/pft-valkeys.sh:33 |

Notes:
- `logship:host_key` is 0640 group `systemd-journal-remote` because journal-remote must read it. The inventory checks
  the mode each source declares, not a blanket 0600.
- `ntfy:maint` is optional: without it pft-maint falls back to the monitor env (maint/README.md:41).
- `valkeys:keys`: the validator master key belongs offline (valkeys/README.md). It is checked only when `VALKEYS_DIR`
  is set in `/etc/pft-keyescrow.env`.
- The validator does not propose yet (no `[validator_token]`), so there is no token to escrow. When one is added,
  it lives in postfiatd.cfg, and `../valkeys` already covers its permissions and sequence.

States: `ok`, `perm` (mode/owner/group differ, symlink or not a regular file), `missing` (required), `absent`
(optional), `unreadable` (run as root). Owners and groups are never printed, only `ok`/`BAD`.

Escrow state per present item: the fingerprint is the first 16 hex of `sha256(fp_key || file bytes)`. It is keyed
with a host-local random key, so a published fingerprint of a low-entropy secret (an ntfy topic) cannot be reversed
by hashing guesses. The inventory compares it with the fingerprint recorded at the last escrow and reports `same`,
`drift` (changed since) or `new` (never escrowed). Before keygen there is no `fp_key`, so fingerprints show `n/a`.

Exit codes: 0 everything ok and escrowed, 1 drift / not escrowed, 2 perm / missing / unreadable, 3 usage.

## Metrics and alerts

`--textfile` writes `pft_keyescrow_items{node,state}`, `pft_keyescrow_drift_items{node}`,
`pft_keyescrow_last_escrow_timestamp_seconds{node}` (0 = never), `pft_keyescrow_inventory_exit_code{node}` and
`pft_keyescrow_collect_timestamp_seconds{node}`. Writes are atomic (a temp file in the same directory, then mv).

### Alerts

`../alerts/keyescrow.rules.yml` (tests: `keyescrow.tests.yml`):
- `PFTKeyEscrowStale` `reason=age`: last escrow older than 36 h, or never.
- `PFTKeyEscrowStale` `reason=drift`: an item changed or appeared after the last escrow and stayed that way for 2 h.
- `PFTKeyEscrowInventoryFailed`: inventory exit 2 (missing / wrong permissions / unreadable) for 15 min.

The rules file is **not yet listed in `../alerts/prometheus.yml`**. It gets added in the same commit as the live
install, so Prometheus never loads a rule whose metric has no series yet.

## Escrow (offline-tested; not installed yet)

```sh
sudo pft-keyescrow keygen          # both hosts: STATE_DIR/fp_key + age identity (0600), prints the age recipient
sudo pft-keyescrow set-peer age1...  # both hosts: the OTHER host's recipient -> PEER_RECIPIENT in /etc/pft-keyescrow.env
sudo pft-keyescrow escrow          # the host with PEER_SSH (validator): both directions in one run
sudo pft-keyescrow verify [--all] [--textfile]   # re-check what this host holds for the peer
```

One `escrow` run on the validator:
1. `seal` here: the inventory must have no perm/missing/unreadable item (refused otherwise, nothing sealed). The ok
   items are packed by `keyescrow_tar.py pack` (tar stream: a `MANIFEST` with path, mode, uid, gid, size and sha256
   per item, then the bytes) straight into `age -r PEER_RECIPIENT`. The result is `outbox/gen-G.age` plus
   `gen-G.meta` (gen, ciphertext sha256 and size, recipient, and the keyed fingerprints only: no plaintext hash
   outside the encryption).
2. Push: `tar gen-G.meta gen-G.age | PEER_SSH sudo -n pft-keyescrow serve receive validator`. The peer writes both
   as 0600 temp files, checks the ciphertext sha256 and size against the meta, renames `.age` and then `.meta` (the
   meta is the commit marker), then decrypts in memory and checks every item's size and sha256 against the MANIFEST
   (no missing, extra or duplicate members). A generation that fails this first check is discarded, so it never
   displaces a good one. Only a `VERIFIED` answer makes this host record the generation's fingerprints in
   `escrowed.tsv` (drift baseline, last escrow time).
3. The peer seals (`serve seal`), this host pulls it (`serve export G`), receives and verifies it the same way, then
   `serve ack G` makes the peer record it.
4. Each side keeps the newest `KEEP` (default 7) verified generations.

`serve` runs only `receive LABEL | seal | export GEN | ack GEN`. Everything else is refused. `PEER_SSH` follows the
same pattern as the other pulls in this repo (`runuser -u <agent user> -- ssh ... <peer>`).

`verify` checks the held generations again: a one-byte change of a ciphertext fails the sha256 check. If an attacker
also rewrites the meta's hash, age's authentication fails on decrypt. Both cases give `VERIFY FAILED` and exit 2.
`--textfile` writes `pft_keyescrow_held_generations`, `pft_keyescrow_held_newest_timestamp_seconds`,
`pft_keyescrow_held_verify_ok` and `pft_keyescrow_verify_timestamp_seconds` (per `node`, `peer`).

## Tests

```sh
bash keyescrow/tests/run-tests.sh          # inventory: fake root, no root/network needed
bash keyescrow/tests/run-escrow-tests.sh   # keygen/seal/escrow/verify/tamper with the real age binary, two fake hosts
promtool test rules alerts/keyescrow.tests.yml
```
