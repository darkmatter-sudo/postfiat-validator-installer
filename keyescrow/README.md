# pft-keyescrow: cross-host escrow of add-on secrets (work in progress)

The add-ons in this repo create secrets that exist on one host only: the pinned node seed of `../cluster`, the
logship TLS keys and CA key, the journald FSS sealing key of `../audittrail`, the heartbeat HMAC keys, and the
ntfy targets. If a host's disk is lost, they are gone, and some of them (the node seed = the node's identity
`pubkey_node`, the logship CA key) cannot be recreated without reconfiguring the other host too.

pft-keyescrow will encrypt each host's secrets to the **peer's** age public key and keep N generations there, so
either host can be rebuilt from the other one. Plaintext never leaves the host it belongs to, and the peer can check
a generation against its manifest but cannot read it.

Status: **step 1 of the task is done (read-only inventory, metrics, alert rules)**. Keygen, escrow, verify and restore
come next. This README covers only what exists now.

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

## Tests

```sh
bash keyescrow/tests/run-tests.sh      # offline: fake root, no root/network needed
promtool test rules alerts/keyescrow.tests.yml
```
