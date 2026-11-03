# pft-backfill: find and repair ledger-history gaps inside the online_delete window

A pruning postfiatd node (`[node_db] online_delete=N`) should always hold the newest N validated ledgers. After a
restart, a stall or a short outage its `complete_ledgers` can fragment (`a-b,c-d`), so it cannot serve part of the
history it is configured to keep. `pft-backfill.sh` measures that, exports it as metrics, alerts on it, and
(opt-in, capped, dry run by default) asks the node to re-acquire the missing ledgers with its own admin
`ledger_request`, then checks every ledger that arrives against three independent hash sources. It never touches
the database files.

Status: steps 1-3 of the task are in this folder (status, plan, repair, pull, units, rules, offline tests). The
two-host install and the live sentry gap / repair / alert drill (step 4) are recorded under `logs/` when they run.

## Source facts (postfiatd 1.0.9, commit `32723c15e686a2088f2c83017a6ff909d93822cd`)

| what | source |
|---|---|
| `complete_ledgers` = disjoint `a-b` / `a` intervals joined by `,`, or `empty` | `RangeSet.h:100-111` |
| rotation when `validated >= lastRotated + online_delete`; deletes below the PREVIOUS rotation point, so a complete node always holds at least the newest N ledgers: window = `[validated-N+1, validated]` | `SHAMapStoreImp.cpp:331-344` |
| `online_delete >= ledger_history` (default 256): after a restart the node's own backfill may stop short of the window (an "edge" gap, normal for up to ~30 min) | `SHAMapStoreImp.cpp:151` |
| `ledger_request` by index: refuses `>= validated` ("Ledger index too large"), takes the ledger's hash from the validated chain (skip list, or the next flag ledger, which it acquires first and answers `lgrNotFound` "acquiring ledger containing requested index"), then starts an inbound acquisition of exactly that hash and answers the ledger or the acquisition status (`hash`, `have_header`, `have_state`, ...) | `RPCHelpers.cpp:1040-1131`, `LedgerRequest.cpp` |
| a completed GENERIC acquisition is stored (`LedgerMaster::storeLedger`) and `tryAdvance` runs | `InboundLedger.cpp:437-486` |

Probe of the real answer shapes on the validator: [logs/02-rpc-shapes.log](logs/02-rpc-shapes.log). Note that
`ledger_request` for a ledger the node already holds also answers with an acquisition status first (`have_state:
false`), so arrival is judged by the plain `ledger` RPC, never by the `ledger_request` answer alone.

## Commands

```
pft-backfill status [--json] [--textfile | --prom FILE]   read-only; exit 0 no gap, 1 gap / not full, 2 error
pft-backfill plan [--max-ledgers N]                       read-only: missing sequences, newest first
pft-backfill repair [--apply] [--max-ledgers N] [--interval S] [--wait S] [--max-runtime S] [--textfile]
pft-backfill validate FILE NODE                           check a status textfile (install + pull use it)
pft-backfill pull                                         validator, root: copy the sentry's textfiles
```

Gap kinds inside the window: **interior** = missing ledgers above the oldest held one (a real hole), **edge** =
missing ledgers below the oldest held one (history not yet acquired after a (re)start).

## Repair: caps and refusals

| cap | default | hard limit |
|---|---|---|
| ledgers per run (`--max-ledgers`) | 16 | 256 |
| pause between polls and between ledgers (`--interval`) | 2 s | 1-60 s |
| arrival wait per ledger (`--wait`) | 90 s | 600 s |
| runtime (`--max-runtime`) | 600 s | 1800 s |
| `ledger_request` re-sent while waiting | every 5th poll | - |

- **Dry run by default.** Without `--apply` it prints the plan and requests nothing.
- **Allowlisted RPC only.** The node is only ever sent `server_info`, `ledger` and `ledger_request`, always through
  `docker exec CONTAINER curl` to the container's own loopback admin port (the first binary of a `docker exec`, so
  the enforced `pft-postfiatd` AppArmor profile from `../apparmor` needs no extra rule). No shell runs in the
  container.
- **Refuses (exit 4)** when the node is not `full`/`proposing`/`validating`, when `pft-maint status --json` reports
  any window other than `none` (or pft-maint is missing / fails: fail closed), or when another repair holds
  `/run/lock/pft-backfill.lock`.
- Plan order: interior holes first, newest first, then the edge.

## Repair: what counts as verified

For each ledger that becomes servable (`ledger` RPC answers it with a 64-hex `ledger_hash` and `parent_hash`):

| check | passes when | if unavailable |
|---|---|---|
| validated chain | the hash `ledger_request` named for this sequence (or the ledger it returned) equals the arrived hash, and never changed between calls | `chain n/a` -> UNVERIFIED |
| previous link | held `seq-1`'s `ledger_hash` = arrived `parent_hash` | `n/a` |
| next link | held `seq+1`'s `parent_hash` = arrived `ledger_hash` | `n/a` |
| public RPC | `rpc.testnet.postfiat.org` `ledger` hash equals (3 tries, 2 s / 4 s backoff, each failed try printed) | `n/a` (public history is finite) |

VERIFIED = chain ok + at least one link ok + no MISMATCH anywhere. Any MISMATCH or `ledger_request` error -> run exit
2. Ledgers that time out or are cut by the runtime cap -> exit 1 (INCOMPLETE). Every run prints `complete_ledgers`
before and after and `counts: planned fetched verified failed timeout skipped (ledger_request calls)`.

## Metrics and alerts

`pft_backfill.prom` (status): `pft_backfill_up`, `_node_full`, `_online_delete`, `_validated_seq`, `_ranges`,
`_window_held_ledgers`, `_missing_ledgers{kind}`, `_gaps{kind}`, `_gap_size{kind,first,last}` (at most 8 series),
`_status_timestamp_seconds`. `pft_backfill_repair.prom` (repair `--textfile`): `pft_backfill_repair_ledgers{result=
planned|fetched|verified|failed|timeout|skipped}`, `_dry_run`, `_exit_code`, `_timestamp_seconds`. Every series
carries `node="validator|sentry"`; the validator pulls the sentry's files (`pull` validates every line).

<a id="alerts"></a>Rules in [`../alerts/backfill.rules.yml`](../alerts/backfill.rules.yml), promtool tests in
[`../alerts/backfill.tests.yml`](../alerts/backfill.tests.yml) (incl. a recovery case and a blinking-gap case):

- **PFTBackfillGap** - interior ledgers missing for 20 min while the node is full. Edge gaps are exported, not
  alerted.
- **PFTBackfillCheckFailed** - status cannot read the node (`up 0`) or the last repair ended with exit 2, for 10 min.

A stopped timer is caught by `pft-rulecheck` (install adds `textfile pft_backfill*.prom 20m` for the status files; the repair file is a last-run record and gets `3650d -`, first match wins; and `ignore-metric pft_backfill_repair_exit_code`, which has no series until the first opt-in repair) and PFTTextfileStale.

## Units

| unit | what | sandbox |
|---|---|---|
| `pft-backfill.timer` | `status --textfile` every 5 min, both hosts | AF_UNIX only, `CAP_DAC_READ_SEARCH` only, ProtectSystem=strict, writes only the textfile dir |
| `pft-backfill-repair.timer` | `repair --apply --textfile` hourly, default caps; **opt-in** (`install.sh --enable-repair`) | + AF_INET/6 for the public RPC check, + `/run/lock` |
| `pft-backfill-pull.timer` | validator: copy the sentry's two textfiles every 5 min | ssh as the operator account in `PULL_SSH` |

## Install

```
sudo ./install.sh                         # validator
sudo ./install.sh --host sentry           # sentry (CONTAINER defaults to postfiatd-sentry)
sudo ./install.sh --pull                  # validator, after PULL_SSH is in /etc/pft-backfill.env
sudo ./install.sh --enable-repair         # also enable the hourly capped repair
sudo pft-integrity accept --reason "pft-backfill installed"
```

The files are listed in `../fleet/manifest.tsv` once installed (pft-fleet keeps them in sync).

## Tests

```
bash backfill/tests/run-tests.sh          # status/plan against a stub docker (captured live fixtures)
bash backfill/tests/run-repair-tests.sh   # repair + pull + validate against stub_node.py (fake clock, no waiting)
python3 -m unittest discover -s backfill/tests -p 'test_*.py'   # parser
promtool test rules alerts/backfill.tests.yml
```

`stub_node.py` models an honest node (hash = sha256 of the sequence, so every parent link is checkable) and each
fault the repair must catch: wrong arrived hash, broken parent link on a held neighbour, `ledger_request` error,
hash changing between calls, `lgrNotFound`-only answers, public-RPC mismatch / down / not found, never arriving.

## Limits

- `ledger_request` makes the node fetch from its peers: a ledger no peer still has cannot be repaired (it times
  out and is reported, never invented).
- Edge ledgers close to the bottom of the window may rotate out while a long run waits; they then time out.
- Whether a fetched ledger also re-enters `complete_ledgers` is up to the node; the run prints before/after so the
  live result is visible, and the verification is done on what the node actually serves.
