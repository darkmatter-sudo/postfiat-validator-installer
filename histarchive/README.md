# histarchive: keep the ledger history that `online_delete` prunes

The testnet-light image runs postfiatd with `[node_db] online_delete=512`, so a node keeps only the last
~512-1024 validated ledgers (about 30-60 minutes). `pft-histarchive` follows the node and keeps every validated
ledger in daily compressed segments that anyone can re-verify offline, with an encrypted replica on the sentry.

Nothing is trusted that is not recomputed: every ledger is checked before it is written and again by `verify`.

| check | what is recomputed |
|---|---|
| `hash` | SHA-512Half(`LWR\0` + 118-byte header) equals the ledger hash |
| `txroot` | the transaction SHAMap root rebuilt from every `[tx_blob, meta]` equals the header's `transaction_hash` |
| `header` | the header's own ledger index equals the line's index |
| `chain` | the header's `parent_hash` equals the previous ledger's hash, across segment boundaries too |
| `order` / `missing` | indexes strictly increase by one; a missing index must be inside a recorded `gaps.jsonl` range |
| segment | whole-file gzip decode (CRC + length), sha256 of the file and of the content against `MANIFEST.jsonl`, first/last/count/first_parent/last_hash |
| MANIFEST | every entry carries `entry` = sha256 of its own canonical JSON and `prev_entry` = the previous entry's hash (a hash chain over the sealed days) |
| `fill` | a MANIFEST fill entry covers exactly one recorded gap, at most once, with every ledger of it; its ledgers are spliced into the stream at the gap, so `chain` runs into both archived neighbours; every `gapfills.jsonl` line must match a fill entry |

The hash rules come from [`pft-ledger-stats/hashverify`](https://github.com/darkmatter-sudo/pft-ledger-stats/tree/main/hashverify):
`lib_hashverify.py` here is a byte-identical copy of `hashverify/lib_hashverify.py` at commit
`f99ae9743629dee83435e0f6c294319028a75c03` (sha256 `64ec1dacc49fcc955975a6c5f5ee85d657c9c7921dbe0ef15cd9b9411ef4e414`;
`TestLib.test_vendored_lib_is_the_pinned_hashverify_copy` fails if it drifts). It is excluded from `ruff format` so
it stays byte-identical.

## Files

| file | role |
|---|---|
| `histarchive.py` | follower (`follow`), offline `verify`, `seal`, `status`, `gaps`, `fill-gap` (see [Gap repair](#gap-repair)), `crosscheck` (seeded sample vs the public RPC, `--record` / `--offline` / `--negative`), `cipher-index`, `replica-check`, `replica-compare` (stdlib only) |
| `lib_hashverify.py` | ledger-hash / tx-ID / SHAMap rules (vendored, see above) |
| `pft-histarchive.sh` | host CLI: `follow`, `metrics`, `verify`, `status`, `keygen`, `replicate`, `verify-replica`, `restore-verify`, `crosscheck`, `gaps`, `fill-gap`, `periodic`, `serve` (peer side), `replica-check` |
| `install.sh` | idempotent install: `--role archive` (validator) / `--role replica` (sentry), `--adopt DIR`, `--uninstall` |
| `systemd/pft-histarchive.service` | the follower: unprivileged system user, localhost-only network, `MemoryMax=256M`, `CPUQuota=50%`, idle I/O |
| `systemd/pft-histarchive-periodic.{service,timer}` | every 5 min: metrics; full verify daily and after each new sealed day; replicate daily and after each new sealed day |
| `../alerts/histarchive.rules.yml` + `.tests.yml` | 4 alert rules and their promtool tests |
| `tests/test_fillgap.py` | gap repair: staged / RPC fills, every refusal with a no-partial-write snapshot, crash points, verify over fills, locking, `gaps` metrics, wrapper + replica |
| `tests/seqcheck.py` | independent sequence check of an archive dir (imports nothing from the tool) |
| `tests/test_histarchive.py`, `tests/test_wrapper.py` | fixture tests (fake JSON-RPC node with correctly hashed synthetic ledgers; a second state dir as the peer, real `age`) |
| `tests/mutate.py` | mutation harness (baseline must pass first) |
| `drill/kill-resume.sh` | kill -9 resume drill against a running follower unit |
| `drill/install-run.sh` | recorded two-host install through pft-fleet inside a pft-maint window (throwaway topic) |
| `drill/fill-run.sh` | recorded live gap repair: upgrade both hosts through pft-fleet, fill the real reboot gap from the committed capture, replicate + restore-verify, scratch peer-RPC fill (throwaway topic) |
| `drill/repro-real-gap.py` | offline re-derivation of the real fill from the committed capture (stub node, no network): gap recorded, filled, fill segment byte-identical to the live one, duplicate refused, seqcheck |
| `drill/fresh-clone.sh` | anonymous public clone at a commit: sha256 vs the live run, all suites, promtool, `repro-real-gap.py` |
| `logs/data/gap-8042619-8042680/` | the staged capture of the reboot gap (64 read-only `ledger` answers 8042618-8042681 taken from the sentry's node before it pruned them) + SHA256SUMS |
| `drill/alert-run.sh` | recorded two-host replica / tamper / alert drill on tmpfs copies (throwaway topic) |
| `diskcost.py`, `tests/test_diskcost.py` | measured disk cost and projection (stdlib), with hand-computed fixture tests |

## Archive layout (`/var/lib/pft-histarchive/archive`)

```
active/YYYY-MM-DD.jsonl       today's ledgers (UTC day of the ledger's close time); one fsynced line per ledger
segments/YYYY-MM-DD.jsonl.gz  sealed days (gzip of the exact active bytes)
MANIFEST.jsonl                one hash-chained entry per sealed day
gaps.jsonl                    ledger ranges that could not be archived, with the reason (append-only)
segments/fill-A-B.jsonl.gz    a verified fill of the recorded gap A..B (fill-gap)
gapfills.jsonl                append-only log of fills (mirrors the MANIFEST fill entries)
.lock                         flock: seal and fill-gap exclusive, verify shared
state.json, status.json       start ledger; follower progress
```

A ledger line is `{"i": index, "h": hash, "d": header hex, "t": [[tx_blob, meta], ...]}`: the node's own binary
`ledger` answer, so every check above can be redone from the archive alone.

**Crash safety.** One `write` + `fsync` per line, so a SIGKILL leaves at most one torn last line; resume cuts it and
continues at the last archived ledger + 1 (no duplicates, no skips). Sealing writes `X.gz.tmp`, fsyncs, renames,
fsyncs the directory, appends the MANIFEST entry and only then removes the active file; resume finishes or redoes a
half-done seal (each step has a test). **Gaps.** If the follower was down longer than the node keeps ledgers, the
pruned range is recorded in `gaps.jsonl` with its reason and the chain restarts after it; `verify` accepts a missing
range only when it is recorded, and the alert below fires for an hour after any new gap.

**What only the replica can prove.** Someone who rewrites the archive *and* recomputes every hash, every MANIFEST
entry and the chain after it produces a self-consistent archive. That is why the MANIFEST head is copied off-host:
`verify-replica` compares the sentry's `REPLICA.json` head entry and every ciphertext sha256 with the local ones, and
`restore-verify` checks that the restored head entry is in the local chain.

## Replica on the sentry

`pft-histarchive replicate` (validator, root) encrypts each sealed segment once with `age` to the validator's own
histarchive recipient (plus any `EXTRA_RECIPIENTS`, e.g. an offline operator key), encrypts the current
MANIFEST/gaps/state as one `meta-<hash>.tar.age`, writes `REPLICA.json` (sha256 of every ciphertext + the MANIFEST
head entry) and pushes only the files the sentry does not hold yet over the same admin link `../keyescrow` uses
(`PEER_SSH`, the peer runs `sudo -n pft-histarchive serve receive|index|check|export`, names are allow-listed). The
sentry holds ciphertext only and can check it without the key (`replica-check`); the validator then compares the
sentry's index with its own (`verify-replica`). `restore-verify` fetches everything back into a scratch dir, checks
every sha256, decrypts with the validator's identity, runs a full offline `verify` on the restored copy and compares
it day by day with the local MANIFEST.

Keep a copy of `/var/lib/pft-histarchive/age.key` (or add an offline `EXTRA_RECIPIENTS` key): without one of them the
replica cannot be decrypted if the validator is lost. The ledger data itself is public; encryption keeps the
sentry's copy unreadable and authenticated (age is AEAD: an altered file does not decrypt).

## Disk cost (measured)

Measured with `diskcost.py` on the live install (log `logs/10-diskcost.log`): one sealed day so far, the partial
2026-11-10 (the archive starts at the six-hour live run's first ledger, 21:22:56Z). The projection uses bytes per
ledger x the observed close-time rate, so it does not depend on the day being complete; re-run it after a few full
days (`sudo python3 diskcost.py --dir /var/lib/pft-histarchive/archive --outbox /var/lib/pft-histarchive/outbox`).

| sealed day | ledgers | close-time span | txs | raw | gzip | ratio |
|---|---|---|---|---|---|---|
| 2026-11-10 | 3112 (7937915-7941026) | 9419 s | 1122 | 3.41 MB | 792.78 KB | 4.3x |

| measure | value |
|---|---|
| gzip bytes per ledger | 254.7 B (raw 1094.9 B) |
| observed ledger rate | 0.3303 /s = 28537 ledgers/day |
| projected sealed archive | 7.27 MB/day, 218.09 MB/30 days, 2.65 GB/year |
| largest active (uncompressed) day | 31.24 MB |
| archive dir now | 1.38 MB in 5 files (active 583.58 KB) |
| validator outbox (encrypted copies) | 803.99 KB in 3 files |
| sentry replica (ciphertext) | 803.99 KB in 3 files |

The whole six-hour live run (log `logs/12-live-run-end.log`, data in `logs/data/live-run-1/`) gives the same figure:

| part | ledgers | txs | raw | gzip | gzip per ledger |
|---|---|---|---|---|---|
| sealed 2026-11-10 | 3112 | 1122 | 3407223 B | 792777 B | 254.7 B |
| active 2026-11-11 (to 03:40Z; `gzip -9n` copy, not a sealed segment) | 4367 | 1484 | 4874761 B | 1134407 B | 259.8 B |
| whole run | 7479 | 2606 | 8.28 MB | 1.93 MB | 257.7 B (7.35 MB/day at 28537 ledgers/day) |

Testnet traffic is light (1122 txs in 3112 ledgers); ledgers with many transactions are larger, so treat the
per-ledger figure as a floor and watch `pft_histarchive_ledgers` / disk usage. The sentry stores the same size again
(ciphertext of each sealed day, plus one metadata tar). The follower used 12.7 MB of memory
(`MemoryMax=256M`) and ~13 s of CPU in its first 16 minutes.

## Proof (logs in `logs/`)

| log | what | result |
|---|---|---|
| 01 | six-hour live run launch (transient unit, code pinned to `dde88f8`) | started 2026-11-10T21:22:56Z at ledger 7937915 |
| 02 | kill -9 resume drill on the live follower (two SIGKILLs; the second with a torn half-line injected before the restart, 55 bytes cut on resume) | 14/14 checks ok |
| 03 / 04 | mutation harness: dev pass, then the recorded run | dev 35/36 (M26 survived, fixed in `d6f9f90`); recorded 38/38 caught, baseline 60 tests pass |
| 05 | mid-window public-RPC crosscheck, seed 20261110, sample 40 (snapshot copy) | 40/40 MATCH live and offline; `--negative` 0/40 MATCH |
| 06 / 07 | two-host install preflight and recorded install (adopts a copy of the live archive) | 10/10; 45 checks ok, 0 failed, operator topics 0 |
| 08 / 09 | replica / tamper / alert drill on tmpfs copies (throwaway ntfy topic) | 41 checks ok, 0 failed: 3 alerts FIRING + RESOLVED, operator topics 0 |
| 10 | disk cost (`diskcost.py`) | table above |
| 12 | live run end: unit journal, follow log, full `verify`, independent sequence check | 7479 ledgers (7937915-7945393), 2606 txs, gaps 0, duplicates 0, missing 0, lag 0 at all 11 progress lines |
| 13 | final public-RPC crosscheck over the whole archive, seed 20261111, sample 60 (7938329-7945387) | 60/60 MATCH live and offline (`xc-public-final.jsonl`); `--negative` 60/60 MISMATCH |
| 14 | fresh public clone at the pinned commit: sha256, shellcheck, ruff, fixture tests, promtool, offline verify + crosscheck of `logs/data/live-run-1` | see log |

Anyone can re-check the live run without a node: unpack `logs/data/live-run-1` into an archive dir
(`segments/`, `MANIFEST.jsonl`, `state.json`, and `active-2026-11-11.jsonl.gz` gunzipped to `active/2026-11-11.jsonl`),
then run `histarchive.py verify --dir DIR` and
`histarchive.py crosscheck --dir DIR --offline logs/data/live-run-1/xc-public-final.jsonl --seed 20261111 --sample 60`.

**Deviations.** (1) The six-hour run used a transient unit in a scratch dir (code pinned to `dde88f8`), not the
installed `pft-histarchive.service`, because the install (07) came after the run had started; the install adopted a
verified copy of that archive and its own follower resumed without a gap. (2) `histarchive.py` changed after
`dde88f8` (verify metrics, crosscheck negative mode, `replica-compare`); the follower functions are unchanged
(function-level AST compare in log 14), and the end-of-run `verify` and both crosschecks ran the final code.
(3) Log 01 records a first launch with `Restart=always`, stopped after 32 s and relaunched with `Restart=on-failure`
(so the `--until` exit is final); the archive resumed at the next ledger.

### Gap repair proof (task_290beaeb, logs 16-22)

The real gap: a planned validator reboot for glibc USN-9065-1 (2026-11-14) kept the follower down longer than the
node keeps ledgers, so `gaps.jsonl` recorded 8042619-8042680 (62 ledgers, `pruned on the node before archiving`).
The 64 ledgers 8042618-8042681 had been captured read-only from the sentry's node before it pruned them
(`logs/data/gap-8042619-8042680/`, sha256 `3de3e996...` checked by the runner's preflight).

| log | what | result |
|---|---|---|
| 16 | `drill/fill-run.sh` preflight (read-only) | 10/10 ok |
| 17 | live run: stopped at the step-4 gate because the follower-restart check read a log file the unit does not write (the follower had resumed on 1.1.0 with no gap, per its journal); fixed in `06f24f7` | stopped, restore ran, integrity PASS |
| 18 | first mutation run, stopped after 6 mutants to move it to a detached unit (superseded by 21) | 6/6 caught so far |
| 19 | resumed run: stopped at the step-5 gate because the PromQL `a or b or c` check returned one of three same-label series (values were right); fixed in `9bce569` | stopped, restore ran |
| 20 | resumed run: preflight stop (the previous run's own silence was active); resume mode now keeps the drill's silences until the clean end (`cc0849a`) | stopped before any change |
| 21 | mutation harness at `70288e8` (code and tests identical to the live-run code), 69 mutants (31 new for gap repair); a first launch timed out the baseline at the old 300 s per-suite limit, `70288e8` raised it to 600 s | **69/69 caught**, baseline 110 tests PASS (386 s) |
| 22 | resumed live run, all steps | **PASS, 0 failed**: verify gaps 1 -> 0 (filled 1), seqcheck missing 62 -> 0, duplicate fill refused with MANIFEST/gapfills/segments unchanged, Prometheus `gap_fillable` 1 -> 0 and `PFTHistarchiveGapFillable` pending -> inactive, replicate sent `fill-8042619-8042680.jsonl.gz.age`, verify-replica + sentry replica-check + restore-verify PASS (`SAME fill-8042619-8042680`), scratch copy with a deliberate 30-ledger gap filled from the public testnet RPC (30/30, verify filled 2, seqcheck PASS), integrity/skew/rulecheck/aptrust/jobwatch ok, operator topics 0 messages since the start of run 17 |
| 23 | fresh anonymous public clone at the pinned commit (`drill/fresh-clone.sh`): sha256 of the 7 key files vs log 22's preflight, capture SHA256SUMS, shellcheck, ruff, all four suites, promtool, offline re-derivation of the real fill (`drill/repro-real-gap.py`) | see log |

After log 21 the only change to code or tests is the order of import lines in three test files: `ruff.toml` now pins
the first-party modules, because without it ruff's import check depended on the working directory (each of
`ruff check histarchive` and `cd histarchive && ruff check .` flagged a different file). Log 23 runs all suites on the
result; the 7 key files of the live run are unchanged (sha256 in log 23).

Runs 17-22 changed nothing beyond the intended steps: each stopped run's restore ended the pft-maint window and
removed the throwaway target; steps 1-4 are idempotent and ran again in 22. `tests/test_fillgap.py` holds every
adversarial case (tamper, truncation/torn line, swapped ledgers, foreign history, broken lower/upper anchor, staged
anchor copy differs, conflicting duplicate, missing anchors, duplicate fill, double commit under the lock, unvalidated
RPC answers, busy archive) with a byte-for-byte snapshot of the archive before and after each refusal.

## Install

```
# sentry first (the replica role has no units: the validator drives it)
sudo ./install.sh --role replica
# validator (copies PEER_SSH from /etc/pft-keyescrow.env, creates the age identity, starts the follower)
sudo ./install.sh --role archive [--adopt DIR]
sudo pft-integrity accept --reason "pft-histarchive installed"
sudo pft-schedaudit accept && sudo pft-schedaudit collect
sudo pft-jobwatch inventory
```

The repo side of an install is one commit: the six `histarchive` lines in `../fleet/manifest.tsv`, the
`histarchive.rules.yml` line in `../alerts/prometheus.yml` and the histarchive lines in
`../rulecheck/pft-rulecheck.conf.example` (appended to `/etc/pft-rulecheck.conf` on the validator). Commit them together
with the install, never earlier: a rule or manifest line without its collector reads as dead/missing and pages.
`drill/install-run.sh` does the whole two-host install and checks it.

The validator's jobwatch textfile had ~1.7 KB of budget left (one timer is ~1.1 KB), so histarchive uses one timer;
the follower is a long-running service.

## Rollback

```
sudo ./install.sh --uninstall          # stops the follower + timer, removes the textfiles; keeps data and conf
sudo rm /etc/systemd/system/pft-histarchive*.service /etc/systemd/system/pft-histarchive-periodic.timer \
        /usr/local/bin/pft-histarchive && sudo rm -r /usr/local/lib/pft-histarchive && sudo systemctl daemon-reload
# data (only if you mean it): /var/lib/pft-histarchive on both hosts; user: sudo userdel pft-histarchive
```

Then remove the `histarchive.rules.yml` line from `../alerts/prometheus.yml`, reload Prometheus, and accept the
change in pft-integrity / pft-schedaudit.

## Gap repair

A recorded gap is history the node pruned before the follower got to it (e.g. a reboot for a security patch longer
than the node's ~30-60 min of history). Another node often still holds it: a peer, the public testnet RPC, or a
capture taken in time. `fill-gap` puts it back **without trusting the source**:

```
sudo pft-histarchive gaps                                   # OPEN/FILLED, anchors, FILLABLE from FILL_RPC
sudo pft-histarchive fill-gap 8042619-8042680 --staged capture.jsonl --dry-run
sudo pft-histarchive fill-gap 8042619-8042680 --staged capture.jsonl   # or --rpc https://rpc.testnet.postfiat.org/
```

1. The range must be a recorded gap, exactly (`FROM-TO` as in `gaps.jsonl`), and not filled yet.
2. Both neighbours must be in the archive: ledger FROM-1 (anchor below) and TO+1 (anchor above).
3. The source's ledgers are read: `--rpc` asks `server_info` + `ledger` (binary, expanded, validated only, rate-limited,
   read-only methods only); `--staged` reads a JSONL file of `ledger` answers or archive records. Ledgers outside
   the gap are context only; a staged copy of an anchor must equal the archived one byte for byte.
4. Every ledger of the gap is checked: `header`, `hash`, `txroot` (as at ingest), and `chain` from the anchor below
   through every ledger to the anchor above (`TO+1`'s parent hash must be the filled `TO`'s hash). A missing,
   duplicated-with-different-content, torn or swapped ledger, a foreign history or a broken anchor is a FAIL line
   naming the ledger and check; **any FAIL refuses the fill and nothing is written** (exit 1).
5. Commit, under the archive's exclusive lock, after re-checking that no other run filled the gap meanwhile:
   `segments/fill-A-B.jsonl.gz` (tmp, fsync, rename, fsync dir), then one MANIFEST entry
   `{"kind": "fill", "gap": <the gaps.jsonl line>, "anchor_below", "anchor_above", "source": {type, rpc host or
   staged file name + sha256}, "tool", ...}` chained like every other entry, then a `gapfills.jsonl` line.
   `gaps.jsonl` is never rewritten. A crash before the MANIFEST append leaves an unlisted segment (verify FAILs it) that
   the next run removes and redoes; a crash before the `gapfills.jsonl` line is repaired by the next `fill-gap`.
6. The wrapper then runs a full `verify` (textfile: `pft_histarchive_gaps` drops, `pft_histarchive_gaps_filled` rises)
   and `gaps` (textfile `pft_histarchive_gaps.prom`).

The follower keeps running: it only appends to `active/`, and its seals take the same lock. The fill segment
replicates like a day segment (`fill-A-B.jsonl.gz.age`; the sentry's `receive` accepts that name) and
`restore-verify` checks it (`SAME fill-A-B`). A restored copy holds sealed segments only, so while the gap's day is
still active the fill's neighbours are not in it: `verify --sealed-only` then checks the fill as its own chain from
the `anchor_below` hash recorded in its MANIFEST entry (NOTE line); a full `verify` requires both neighbours and
compares them with the entry's `anchor_below` / `anchor_above`. Set `FILL_RPC=` in `/etc/pft-histarchive.env` to let the 5-minute
periodic run ask the source (one `server_info`, only while a gap is open) whether an open gap is fillable;
`PFTHistarchiveGapFillable` then says so while it still can be done.

`tests/seqcheck.py ARCHIVE_DIR` re-checks indexes, header hashes and parent links of the whole archive (fills
included) with its own code, and that the missing ledgers are exactly the open gaps.

## Alerts

| alert | fires when | for |
|---|---|---|
| `PFTHistarchiveStale` | no ledger archived for 15 min, or more than 300 ledgers behind validated (a frozen textfile ages too) | 10m |
| `PFTHistarchiveIntegrity` | last full verify failed, no verify for 26 h, or a new gap within the last hour | 0m |
| `PFTHistarchiveGapFillable` | an open gap has both anchors archived and `FILL_RPC` still holds it: run `fill-gap` (resolves once filled, or once the source pruned it) | 15m |
| `PFTHistarchiveReplica` | the sentry's replica differs from the local copy (missing/extra/altered file, stale index, its own check failed, unreachable) or was not compared for 26 h | 30m |
