# pft-keyescrow: cross-host escrow of add-on secrets (work in progress)

The add-ons in this repo create secrets that exist on one host only: the pinned node seed of `../cluster`, the
logship TLS keys and CA key, the journald FSS sealing key of `../audittrail`, the heartbeat HMAC keys, and the
ntfy targets. If a host's disk is lost, they are gone, and some of them (the node seed = the node's identity
`pubkey_node`, the logship CA key) cannot be recreated without reconfiguring the other host too.

pft-keyescrow encrypts each host's secrets to the **peer's** age public key and keeps N generations there, so
either host can be rebuilt from the other one. Plaintext is never written to disk and never crosses the network:
the source host packs and encrypts in one pipe, the peer stores ciphertext only, and the peer checks a generation by
decrypting it in memory with its own age identity (root-only, 0600).

Status: **steps 1-3 of the task are done and tested offline (inventory, metrics, alert rules; keygen, seal,
two-way escrow, receive + in-memory verify, tamper detection, pft-maint-gated restore with backups; mutation run)**.
Install and the live two-host proof (step 4) come next. This README covers only what exists now.

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

The rules file is listed in `../alerts/prometheus.yml` since the live install (log 13): it was added only after
both hosts exported metrics, so Prometheus never loaded a rule whose metric had no series.

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

## Restore (offline-tested; not installed yet)

```sh
sudo pft-maint start --ttl 30m --reason "restore sentry node_seed"     # on the TARGET host
sudo pft-keyescrow restore --host sentry --item cluster:node_seed --dry-run
sudo pft-keyescrow restore --host sentry --item cluster:node_seed --yes  # run on the host with PEER_SSH
```

The host that holds the target's escrow checks its copy (sha256 + in-memory decrypt) and re-encrypts it in one pipe
(`age -d | age -r`) to the target's **current** age recipient. So a rebuilt host only needs `keygen` first, and its
old identity is not needed. The target decrypts in memory and `keyescrow_tar.py apply` writes the items:
- Refused unless `pft-maint status --json` reports `window=active` on the target (fail closed: no pft-maint, a
  failing status, or `none`/`expired` all refuse). `--dry-run` prints the plan without a window and writes nothing.
- age does not authenticate the sender, so the target writes only (id, path) pairs from its **own** registry. A
  payload that names an allowed id with a different path is refused before anything is written.
- Everything is checked first (sha256, sizes, allow list, selection); nothing is written unless all of it passes.
- A file with different bytes is copied to `STATE_DIR/restore-backups/<UTC>/` (0700 dir, 0600 files) before it is
  replaced. Same bytes with a wrong mode/owner only get the mode/owner fixed. Each file is written to a temp file
  in its own directory, fsynced, chowned/chmodded to the MANIFEST's uid/gid/mode, then renamed into place.
- After applying, the inventory runs again and prints each item's state.

## Tests

```sh
bash keyescrow/tests/run-tests.sh          # inventory: fake root, no root/network needed
bash keyescrow/tests/run-escrow-tests.sh   # keygen/seal/escrow/verify/tamper/restore with real age, two fake hosts
promtool test rules alerts/keyescrow.tests.yml
python3 keyescrow/tests/mutate.py -j 3     # 44 mutants over every refusal and integrity check (both files)
```

`tests/mutate.py`: each mutant is one exact text replacement in `pft-keyescrow.sh` or `keyescrow_tar.py` (it must
match exactly once, else NOT APPLIED = harness failure). An unmutated control run must pass first. Each suite run has
a timeout and runs in its own session with stdin from /dev/null, and on timeout the whole process group is killed.
After the run no process from a mutant copy may be left. One mutant is documented as equivalent: P11
(`O_NOFOLLOW` in pack), because the inventory refuses symlinks before pack is called.

## Results so far (all from the logs in `logs/`)

| log | what | result |
|---|---|---|
| `logs/01-inventory.log` | live read-only inventory, both hosts | validator `ok 10 ... absent(optional) 3 ... new 10 -> exit 1` (l.24), sentry `ok 10 ... absent(optional) 1 ... new 10 -> exit 1` (l.49): every required secret present with its declared mode/owner, nothing escrowed yet |
| `logs/02-offline.log` | inventory suite, shellcheck, promtool | `67 passed, 0 failed` (l.79); `SUCCESS: 3 rules found` (l.83); promtool tests `SUCCESS` (l.87) |
| `logs/03-offline.log` | inventory + escrow suites (real age 1.0.0) | `67 passed, 0 failed` (l.86) and `48 passed, 0 failed` (l.138) |
| `logs/04-offline.log` | after restore | 67/67 (l.15) and escrow + restore 64/64 (l.83) |
| `logs/05a-dev-mutants-1.log` | first mutant pass (dev) | 3 survivors: S4 (l.17), E2 (l.19), E3 (l.20); `40 killed + 1 documented equivalent of 44` (l.47) |
| `logs/05b-dev-mutants-2.log` | the 3 former survivors after 3 new tests | `3 killed` (l.6) |
| `logs/05-mutants.log` | recorded mutant run on the commit in its header | control 67/67 + 76/76 (l.10); `ORPHANS: 0` (l.55); `43 killed + 1 documented equivalent of 44, 0 survived` (l.56) |

05a/05b are the raw harness output of dev passes (no header line); 05 is the recorded run. In 05, l.5 is
`sha256sum` skipping the ignored `tests/__pycache__` directory (harmless).
The last line of 05 (`0`) is an independent `ps` count of mutant-copy processes after the run.
