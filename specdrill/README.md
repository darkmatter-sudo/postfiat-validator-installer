# specdrill: measured CPU, memory and block-I/O floors for a postfiatd node

Node sizing advice is usually a guess. `pft-specdrill` measures it: it starts DISPOSABLE throwaway nodes from the
live node's own postfiatd 1.0.9 image, one at a time, each under one resource limit (`--cpus`, `--memory`,
`--device-read/write-bps`), and records how long each takes to reach `full`, how far behind the network it runs over
a 20-minute window, its close-time jitter, peers, OOM/restart events and peak RSS. `specdrill.py report` turns the
cells into `cells.json`, `cells.csv` and `REPORT.md` with a minimum and a safe value per axis.
Status: runner, report helper and stubbed tests; live matrix results follow in [Results](#results).

## Usage

```
pft-specdrill plan [--axes cpu,mem,io]                     # the cells and every guard's current verdict; no changes
sudo pft-specdrill run-cell --out DIR --axis cpu --cpus 0.5 --mem 2048 [--io BPS]   # one cell -> DIR/<cell>/
sudo pft-specdrill matrix --out DIR --axes cpu,io --yes    # every cell of the axes, in sequence
pft-specdrill report CELLS_DIR OUT_DIR                     # cells.json, cells.csv, REPORT.md (offline, deterministic)
sudo pft-specdrill cleanup                                 # remove every pft-specdrill labelled container/volume/network
```

Exit codes: 0 ok, 1 cell ran but could not be recorded, 3 usage, 4 refused by a guard.

## The matrix

One factor at a time from a base cell of 2 vCPU, 2048 MiB, unlimited I/O:

| axis | values |
|---|---|
| cpu | 0.25, 0.5, 1, 2 vCPU |
| mem | 512, 768, 1024, 1536, 2048 MiB (`--memory-swap` = `--memory`: no swap) |
| io | 1, 4, 16 MB/s read and write on the Docker data disk |

A cell PASSES when the node reaches `full` within `FULL_DEADLINE_S` (600 s), is never OOM-killed or restarted, is
not aborted, and its ledger lag (reference validated index minus the cell's validated index, sampled every
`POLL_SEC` = 10 s) has a nearest-rank p95 <= 2 over the 20-minute window. A cell that is not full after
`FULL_TIMEOUT_S` (900 s) ends as `never_full`. Per axis, the **minimum** is the smallest value whose every larger
tested value also passed; **safe** is the next tested value above it.

## Safety: what keeps the live validator untouched

Every cell is refused (exit 4, nothing created) unless all of these hold, each checked right before the cell:

| guard | refusal |
|---|---|
| root, and the exclusive lock `/run/pft-specdrill.lock` | `lock: another pft-specdrill run holds ...` |
| an active `pft-maint` window with at least the cell's worst case (`FULL_TIMEOUT_S + WINDOW_S + 120 s`) left | `maint: ...` |
| live node `full` and its lag vs the public reference RPC <= `LIVE_LAG_MAX` (3) | `live: ...` |
| `pft-integrity verify` PASS and its service not running | `integrity: ...` |
| `MemAvailable - cell memory >= HEADROOM_MIB` (1536) | `headroom: ...` |
| free disk under `/var/lib/docker` >= `DISK_MIN_GB` (10) | `disk: ...` |
| the image is the live container's image id and present locally (`docker create --pull never`) | `image: ...` |
| no labelled resources left from an earlier run | `leftovers: ...` |

After `docker create` and before `docker start`, the container is checked: its config has no `[validator_token]`,
`[validation_seed]` or `[ips_fixed]` stanza, it publishes no ports, is unprivileged, sits on its own bridge network,
and its mounts are exactly its own labelled volumes (`containment: ...`, torn down, never started). The cell gets no
config bind mount: it runs the image's baked testnet config, peers outbound only, and never connects to the live node.

The postfiatd image declares `VOLUME /etc/postfiatd /var/lib/postfiatd/db /var/log/postfiatd`; docker adds an
anonymous volume at every declared path a container leaves unmounted, and `docker rm -f` without `-v` leaks it. So
each cell creates one labelled volume per declared path (read with `docker image inspect -f '{{json .Config.Volumes}}'`,
plus the db path; docker seeds an empty named volume from the image, so the baked config is still there), the
containment check requires the `{Type, Name, Destination}` set of `.Mounts` to equal that plan, and teardown uses
`docker rm -fv`. The stub's `docker create` mirrors this from a real capture (`tests/fixtures/inspect-real.json`:
`docker inspect` of two never-started throwaways, one with all three volumes, one with only the db volume).

`pft-integrity` would see a throwaway postfiatd-image container as a node change, so its hourly timer is paused for
the cell: a transient failsafe SERVICE `specdrill-rearm-integrity` (`sleep <cell budget + 300 s> && systemctl start
pft-integrity.timer`) is started first, then `pft-integrity.timer` is stopped. It is a service, not a timer, because
pft-schedaudit lists every loaded timer (a transient timer would raise PFTSchedEntryUnexpected) and pft-jobwatch every
`pft-*.timer`. The `EXIT`/`INT`/`TERM` trap removes every labelled container, volume and network, stops the failsafe
and then restarts the timer (in that order, so no integrity run sees the transient unit).

While a cell runs, each poll can abort it (torn down, `meta.json` `abort` = reason):
`live_lag` (live node not full, unreadable, or lag > `LIVE_LAG_MAX` for `LIVE_ABORT_POLLS` = 2 polls in a row),
`maint_window_ended`, `host_mem_low` (`MemAvailable < HEADROOM_MIB / 2`).

The `pft-maint` window itself is opened by the recorded drill runner `drill/live-run.sh`, not by `pft-specdrill`.

## The recorded live run (`drill/live-run.sh`)

```
AXES=cpu,io RUN=05 bash specdrill/drill/live-run.sh 2>&1 | tee LOG     # repo root, agent user, run detached
DRY=1 RUN=dry1 bash specdrill/drill/live-run.sh                          # one short cpu=2 cell through every step
```

It runs a byte-identical copy of the runner and helper (sha256 = HEAD, so repo edits cannot reach a running drill)
and, per axis, opens a `pft-maint` window whose `[MAINT]` messages go to a throwaway ntfy topic. Before the first
cell it silences exactly the four alerts the run causes, on the validator only: `PFTKernelCritical`
`pattern=~oom_cgroup|hung_task` (OOM cells, 1 MB/s I/O cells), `PFTKernelWarning pattern=oom_invoked`,
`PFTJobDisabled timer=pft-integrity.timer` (all `host="validator"`) and `PFTKeyEscrowStale reason=drift`
(`node="validator"`: `pft-keyescrow` sees the throwaway `/etc/pft-maint/ntfy.env` as a new secret, and its 2 h
`for:` is shorter than a matrix axis); never the pipeline watchdog. The restore re-runs `pft-keyescrow.service` right
after the real target is back and requires `escrow drift 0, new 0`. After the matrix it checks: the live
validator was `full` at every poll of every cell with lag <= 3, 0 labelled resources, `pft-integrity` PASS on both
hosts with nothing to accept, AppArmor/seccomp 0 denials, no new histarchive gap, and every alert that was active at
any time during the run (Prometheus `ALERTS`) is the watchdog, a digest-only valwatch alert or one of the four
silenced ones. It expires its silences only after a drain, then reads back the throwaway topic and every operator
topic (0 alert/`[MAINT]` messages; the hourly agent's own `[pft-agent]` messages are counted apart).

## Data per cell

`DIR/<cell>/meta.json` (limits, start/end, abort, OOM, restarts, peak RSS = max `VmHWM` of the node process read
from the host's `/proc`), `samples.jsonl` (one line per poll: cell state/validated index/close time/peers, reference
index, live state and lag), `cell.json` (the summary `specdrill.py summarize` derives from the two).

## Tests

```
TMPDIR=$HOME/.cache python3 -m pytest -q specdrill/tests
shellcheck specdrill/pft-specdrill.sh
```

`tests/test_specdrill.py` checks the metrics and the report against hand-computed fixtures. `tests/test_runner.py`
drives the real runner with every external binary (docker, curl, systemctl, systemd-run, pft-maint, pft-integrity)
replaced by `tests/stub.py` and a fake clock: each guard refuses with its own reason and makes no create/pause call,
each numeric limit has a just-passing and a just-failing case, each abort path and SIGTERM tear the cell down and
re-arm the integrity timer.

`tests/mutants.py` is the mutation harness: each of its mutants breaks one guard, containment check, abort, teardown
step, command check or metric/verdict/spec rule; each runs on its own copy of the folder with its own `TMPDIR`, and is
CAUGHT only when pytest reports failures with at least one `FAILED` test id (a hang is killed and counts as not
caught). Every anchor must occur exactly once; the unmutated baseline must pass first.

```
TMPDIR=$HOME/.cache python3 specdrill/tests/mutants.py -j 3
```

## Results

Pending the live matrix run.
