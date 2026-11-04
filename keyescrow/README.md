# pft-keyescrow: cross-host escrow of add-on secrets

The add-ons in this repo create secrets that exist on one host only: the pinned node seed of `../cluster`, the
logship TLS keys and CA key, the journald FSS sealing key of `../audittrail`, the heartbeat HMAC keys, and the
ntfy targets. If a host's disk is lost, they are gone, and some of them (the node seed = the node's identity
`pubkey_node`, the logship CA key) cannot be recreated without reconfiguring the other host too.

pft-keyescrow encrypts each host's secrets to the **peer's** age public key and keeps N generations there, so
either host can be rebuilt from the other one. Plaintext is never written to disk and never crosses the network:
the source host packs and encrypts in one pipe, the peer stores ciphertext only, and the peer checks a generation by
decrypting it in memory with its own age identity (root-only, 0600).

Status: all steps done. Steps 1-3 are tested offline (inventory, metrics, alert rules; keygen, seal, two-way escrow,
receive + in-memory verify, tamper detection, pft-maint-gated restore with backups; mutation runs). Step 4 so far:
**installed on both hosts, live two-way escrow + verify PASS (logs 10, 12), pull of the sentry metrics, zero-leak
check on both hosts, alert rules loaded (log 13), one-byte tamper drill on both holders with PFTKeyEscrowVerifyFailed
FIRING -> RESOLVED on a throwaway topic and 0 operator messages (log 20), and the live sentry node_seed loss +
restore + restart with pubkey_node unchanged (log 21), and the first unattended nightly timer run (log 24)**.

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

Expected-evolving items: journald evolves the FSS sealing key **in place** at every seal interval (forward-secure
sealing), so the live `journald:fss` fingerprint moved minutes after each escrow (log 15: the escrow unit's own
inventory lines from the journal, and the fss mtime moving while nothing else changes). Counted as drift, that would hold
`PFTKeyEscrowStale reason=drift` firing for ever. Items listed in conf `EVOLVING` (default `journald:fss`) report
escrow `evolving` instead: not drift and not alerted, while "never escrowed" still counts as `new`. The nightly
escrow keeps a copy at most a day old. Restoring an older FSS state is a restore of the sealing key as of that
night (journald seeks it forward to the current epoch); the verification key stays off-host as `../audittrail`
requires.

## Metrics and alerts

Pull (validator): `sudo pft-keyescrow pull` runs `serve textfile pft_keyescrow|pft_keyescrow_held` on the sentry
through `PEER_SSH` (no other file can be named) and installs the copies as `pft_keyescrow_sentry.prom` /
`pft_keyescrow_held_sentry.prom` only if every line is a `pft_keyescrow_*` HELP/TYPE line or an integer sample with
`node="sentry"`, the file is at most 64 KiB and has its timestamp sample (a rejected file keeps the previous copy).

`--textfile` writes `pft_keyescrow_items{node,state}`, `pft_keyescrow_drift_items{node}`,
`pft_keyescrow_last_escrow_timestamp_seconds{node}` (0 = never), `pft_keyescrow_inventory_exit_code{node}` and
`pft_keyescrow_collect_timestamp_seconds{node}`. Writes are atomic (a temp file in the same directory, then mv).

### Alerts

`../alerts/keyescrow.rules.yml` (tests: `keyescrow.tests.yml`):
- `PFTKeyEscrowStale` `reason=age`: last escrow older than 36 h, or never.
- `PFTKeyEscrowStale` `reason=drift`: an item changed or appeared after the last escrow and stayed that way for 2 h.
- `PFTKeyEscrowInventoryFailed`: inventory exit 2 (missing / wrong permissions / unreadable) for 15 min.
- `PFTKeyEscrowVerifyFailed`: the newest generation a host holds for its peer failed the ciphertext sha256 or the
  in-memory decrypt + MANIFEST check, or none is held, for 5 min (`pft_keyescrow_held_verify_ok == 0`).

The rules file is listed in `../alerts/prometheus.yml` since the live install (log 13): it was added only after
both hosts exported metrics, so Prometheus never loaded a rule whose metric had no series.

## Escrow

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

## Restore (offline-tested; live drill on the sentry node seed: log 21)

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

Live drill (`drill/restore-run.sh`, log 21): the sentry's pinned seed (`/var/lib/pft-cluster/node_seed`) is moved into
a 0700 drill dir, so `pft-cluster audit` on the sentry FAILs `seed:stored`; `restore --host sentry --item
cluster:node_seed` (dry run, then `--yes` inside the window) writes it back byte-identical (cmp against the moved copy)
with mode 600 root:root; then `pft-maint restart-node` (run on the sentry with `CONTAINER=postfiatd-sentry`) restarts
the node and `pubkey_node` is the same as before the drill. postfiatd reads `[node_seed]` only at start, so the live
identity never changed during the loss; the restart proves the restored state starts the same identity. Seed bytes and
node keys are never printed: the drill compares them inside the script and prints HMAC tags under a per-run random key
(equal tags = equal values). In restart-node's verdict line, `sentry down (not peered before)` is pft-maint's
validator-side "is my sentry peered" field, which is always 0 when it runs on the sentry itself.

## Install

```sh
sudo keyescrow/install.sh --host validator      # and on the sentry: --host sentry (keygen if no identity yet)
sudo pft-keyescrow set-peer <the other host's age recipient>       # on each host
#   validator /etc/pft-keyescrow.env: PEER_SSH="runuser -u OPERATOR -- ssh -o BatchMode=yes -o ConnectTimeout=10 SENTRY"
sudo keyescrow/install.sh --escrow-host         # validator: first escrow through the unit, then the timers
sudo keyescrow/install.sh --enable              # each host, after the first escrow: hourly inventory + verify
sudo pft-integrity accept --reason "pft-keyescrow installed"
```

Units (`systemd/`, sandboxed: ProtectSystem=strict, read-only home, only the state and textfile dirs writable,
capabilities limited to reading other users' secret files and, for the ssh units, runuser):
- `pft-keyescrow.timer` (both hosts, hourly): `inventory --textfile` + `verify --textfile`.
- `pft-keyescrow-escrow.timer` (validator, nightly 02:40 UTC): `escrow` (both directions), then inventory, verify
  and pull. A failed direction fails the unit and leaves the last-escrow time unchanged (PFTKeyEscrowStale after 36 h).
- `pft-keyescrow-pull.timer` (validator, every 15 min): `pull`.

Nightly proof (`drill/nightly-run.sh`, read-only, log 24): started before the timer, it records the newest generation
each side holds, waits until `pft-keyescrow-escrow.timer` triggers the service and the service has finished, then
checks the unit's Result and its own journal (sudo), a newer verified generation on both holders, the last escrow time,
inventory on both hosts, the held metrics, Prometheus alerts and a zero-leak scan on both hosts (including the run's own
raw log). With `WAIT_MAX=0` (no run) it must fail: log 23 is that negative control (9 FAIL).

The rules are evaluated on the validator only: the sentry runs no Prometheus, and its metrics arrive by `pull`.

## Tests

```sh
bash keyescrow/tests/run-tests.sh          # inventory: fake root, no root/network needed
bash keyescrow/tests/run-escrow-tests.sh   # keygen/seal/escrow/verify/tamper/restore with real age, two fake hosts
promtool test rules alerts/keyescrow.tests.yml
python3 keyescrow/tests/mutate.py -j 3     # 56 mutants over every refusal and integrity check (both files)
sudo python3 -I keyescrow/drill/leakcheck.py --tool /usr/local/bin/pft-keyescrow --conf /etc/pft-keyescrow.env \
  --host validator --scan /var/lib/pft-keyescrow --scan /var/lib/pft-exporter/textfile   # live zero-leak check
bash keyescrow/drill/tamper-run.sh > LOG 2>&1   # live one-byte tamper drill, both holders, alerts on a throwaway topic
bash keyescrow/drill/restore-run.sh > LOG 2>&1  # live sentry node_seed loss + restore + guarded restart, pubkey_node kept
LOG=LOG bash keyescrow/drill/nightly-run.sh > LOG 2>&1   # read-only proof of the next nightly timer run
```

`tests/mutate.py`: each mutant is one exact text replacement in `pft-keyescrow.sh` or `keyescrow_tar.py` (it must
match exactly once, else NOT APPLIED = harness failure). An unmutated control run must pass first. Each suite run has
a timeout and runs in its own session with stdin from /dev/null, and on timeout the whole process group is killed.
After the run no process from a mutant copy may be left. One mutant is documented as equivalent: P11
(`O_NOFOLLOW` in pack), because the inventory refuses symlinks before pack is called.

`drill/leakcheck.py` reads the installed registry, takes up to three 16-byte probes (start, middle, end) of every
present secret and searches them in every scanned file; it prints item ids and counts only. Its controls: each
probe must be found in the secret file itself, and log 08 shows a clean scan dir (exit 0) and the same dir with a
planted copy of the secret (`leaks 3  FAIL`, exit 1).

## Results (all from the logs in `logs/`)

| log | what | result |
|---|---|---|
| `logs/01-inventory.log` | live read-only inventory, both hosts | validator `ok 10 ... absent(optional) 3 ... new 10 -> exit 1` (l.24), sentry `ok 10 ... absent(optional) 1 ... new 10 -> exit 1` (l.49): every required secret present with its declared mode/owner, nothing escrowed yet |
| `logs/02-offline.log` | inventory suite, shellcheck, promtool | `67 passed, 0 failed` (l.79); `SUCCESS: 3 rules found` (l.83); promtool tests `SUCCESS` (l.87) |
| `logs/03-offline.log` | inventory + escrow suites (real age 1.0.0) | `67 passed, 0 failed` (l.86) and `48 passed, 0 failed` (l.138) |
| `logs/04-offline.log` | after restore | 67/67 (l.15) and escrow + restore 64/64 (l.83) |
| `logs/05a-dev-mutants-1.log` | first mutant pass (dev) | 3 survivors: S4 (l.17), E2 (l.19), E3 (l.20); `40 killed + 1 documented equivalent of 44` (l.47) |
| `logs/05b-dev-mutants-2.log` | the 3 former survivors after 3 new tests | `3 killed` (l.6) |
| `logs/05-mutants.log` | recorded mutant run on the commit in its header | control 67/67 + 76/76 (l.10); `ORPHANS: 0` (l.55); `43 killed + 1 documented equivalent of 44, 0 survived` (l.56) |

| `logs/05c-dev-mutants-3.log` | dev pass, new pull mutants U1-U8 | `8 killed` (l.11) |
| `logs/05d-dev-mutants-4-dupid.log` | dev pass, evolving mutants (first named V1-V4, which collided with existing ids; renamed F1-F4) | harness ran both V4s (l.5, l.9) |
| `logs/05e-dev-mutants-5.log` | dev pass, F1-F4 | `4 killed` (l.7) |
| `logs/06-mutants-stopped.log`, `09-...`, `11-...` | recorded runs stopped / superseded (annotated at the end of each): 06 and 09 because a code fix followed, 11 because its control run failed 1 escrow test that 7 later runs did not reproduce (the harness now names failing control tests) | not evidence |
| `logs/07-install-live.log` | live install on both hosts + first two-way escrow | escrow itself worked (verify on both holders l.161, l.179; inventory after exit 0), but `RESULT: FAIL - 3 failed check(s)` (l.302): install.sh printed none of the unit's output (l.134-136; a finished oneshot has no InvocationID), fixed in 533a222 |
| `logs/08-offline.log` | suites, lint, promtool, fix-reverted control, leakcheck controls | 67/67 (l.32), 90/90 (l.51); the die() test FAILS on the parent commit's tool (l.55-56); promtool `SUCCESS: 4 rules found` (l.60) + tests `SUCCESS` (l.64); leakcheck clean rc=0 (l.72), planted copy rc=1 (l.76) |
| `logs/10-reinstall-live.log` | re-install + second two-way escrow through the unit | `RESULT: PASS - 0 failed check(s)` (l.309); it also showed `sort: write error` (l.114, fixed with IgnoreSIGPIPE=no) and led to the EVOLVING fix |
| `logs/12-reinstall-live.log` | re-install (EVOLVING, units) + third two-way escrow | escrow PASS (l.115); 3 generations held and verified on each side (l.195, l.239); inventory both hosts `drift 0, new 0, evolving 0 -> exit 0` (l.243-244); held ok=1 each way (l.260, l.263); leak check 11 + 10 secrets, 0 leaks (l.295, l.311); `RESULT: PASS - 0 failed check(s)` (l.333) |
| `logs/13-rules-live.log` | rules loaded in the live Prometheus | all 4 rules `ok inactive` (l.6-9) with live series for both nodes |
| `logs/14-mutants.log` | recorded mutant run on the commit in its header (56 mutants: + U1-U8 pull, F1-F4 evolving) | control 74/74 + 90/90 (l.9); `ORPHANS: 0` (l.66); `55 killed + 1 documented equivalent of 56, 0 survived` (l.67) |
| `logs/15-fss-evolving.log` | why journald:fss is EVOLVING | the escrow unit recorded fss fp `31fc04dd...` at 21:22Z (l.7) and `9f9ceaf1...` at 21:33Z (l.12); the fss mtime moved again at 21:44:59Z (l.22), 7 s after the third escrow (l.17), and inventory now reports `escrow evolving` with `drift 0, ... evolving 1 -> exit 0` (l.30-31), drift_items 0 on both nodes (l.34-35) |
| `logs/16-fleet-sync.log` | `pft-fleet sync --addon fleet` (manifest lines for keyescrow) in a pft-maint window, [MAINT] to a throwaway topic | before `BEHIND=1` (l.10), `SYNCED validator fleet` (l.42), after `CURRENT=53 BEHIND=0` (l.104), `0 check(s) failed -> PASS` (l.125) |
| `logs/17-tamper-preflight.log` | `PREFLIGHT_ONLY=1 drill/tamper-run.sh` (nothing changed) | `0 check(s) failed` (last line) |
| `logs/18-...-harness-fail.log`, `logs/19-...-harness-fail.log` | first two recorded tamper drills, superseded (annotated at the end of each) | 18: 3 FAIL (l.97, 99, 167): the validator's unit journal was read without sudo, and the drill left drift_items exported (fixed in a9d3801); 19: 1 FAIL (l.177): grep `VERIFY` cannot match `VERIFIED` (fixed in 162e4f3). In both, the alert fired and resolved for both pairs and the operator topics got 0 messages |
| `logs/20-tamper-live.log` | one-byte tamper drill, both holders (`drill/tamper-run.sh`, sha256 in l.3 = the file at the pinned commit) | T1 validator-held copy: `flipped 1 byte at offset 10340 of 20680` (l.73), `ciphertext sha256 MISMATCH` (l.95); T2 sentry-held copy with the meta re-hashed: sha check passes, the in-memory decrypt fails `payload unreadable` (l.113); `restore --dry-run` refused from both tampered copies (l.128, l.139, check l.143); verify_ok 0 for both pairs (l.149); `PFTKeyEscrowVerifyFailed` firing for both (l.154-155) and `[FIRING]` on the throwaway topic for both (l.157-158); bytes put back byte-identical (l.166), VERIFIED again (l.178), `[RESOLVED]` for both (l.185-188), query_range first/last firing sample per pair (l.190-191); drift 0 after restore (l.206); operator topics 0 messages (l.218-220); integrity PASS, both nodes full, `verify --all` exit 0 (l.222-233); `0 check(s) failed -> PASS` (l.235) |
| `logs/21-restore-live.log` | sentry node_seed loss + restore from the validator's escrow + guarded restart (`drill/restore-run.sh`, sha256 in l.3 = the file at the pinned commit) | preflight: no lock on the sentry (l.13), verify --all + cluster audit PASS both hosts (l.49, l.54), seed 600 root:root + tags (l.55), dry run `unchanged` (l.76); seed moved away (l.97), cluster audit FAILs seed:stored (l.103); dry run `would be restored (was absent)` (l.107, l.124); `restored (was absent) (mode 600, backup none)` (l.128), RESULT PASS (l.156); `cmp` identical + sha256 tag equal to l.55 (l.157-161); mode/owner equal (l.162); cluster audit PASS again (l.168); `restart-node PASS: server_state full after 55s` (l.175); pubkey_node tag after == before (l.181-182); cluster audit PASS both hosts (l.195); inventory `[ok] cluster:node_seed` (l.202); verify --all exit 0 both (l.207); everything restored (l.228); throwaway topic only `[MAINT]` start/end (l.229), operator topics 0 messages (l.232-234); integrity PASS + both nodes full (l.236-240); `0 check(s) failed -> PASS` (l.242). l.17 is an ssh notice on stderr (no tty), harmless |
| `logs/22-nightly-dev-negative-superseded.log` | first dev negative run of `drill/nightly-run.sh` (`WAIT_MAX=0`), superseded (note at the end) | 8 FAIL; the Result check passed off the previous run and 3 command lines printed the home path: both fixed in 682144f |
| `logs/23-nightly-dev-negative.log` | negative control on the final script (`WAIT_MAX=0`, no timer run yet) | `RESULT: FAIL - 9 failed check(s)` (l.149): every check that needs tonight's run fails |
| `logs/24-nightly-live.log` | first unattended nightly run (`drill/nightly-run.sh`, sha256 in l.4 = the file at the pinned commit; installed tool sha256 = repo `pft-keyescrow.sh`, l.5) | timer triggered the service at 02:41:25Z (l.49-50), `Result=success ExecMainStatus=0` (l.58); journal: validator gen `VERIFIED` by the sentry, sentry gen `VERIFIED` here, `RESULT: PASS - both directions` (l.155-158), no age identity (l.159); newer verified generations on both holders `20261103T214449Z -> 20261104T024132Z` and `20261103T214447Z -> 20261104T024127Z` (l.175-176); last escrow time moved (l.180); inventory exit 0 both (l.185); held verify_ok 1 both (l.194); 0 PFTKeyEscrow* alerts (l.202); 0 leaks on both hosts incl. the raw log (l.224, l.240); `RESULT: PASS - 0 failed check(s)` (l.244) |

05a/05b are the raw harness output of dev passes (no header line); 05 is the recorded run. In 05, l.5 is
`sha256sum` skipping the ignored `tests/__pycache__` directory (harmless).
The last line of 05 (`0`) is an independent `ps` count of mutant-copy processes after the run.
