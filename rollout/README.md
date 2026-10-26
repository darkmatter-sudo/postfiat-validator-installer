# pft-rollout: two-host canary image rollout with auto-rollback

[`upgrade/postfiat-upgrade.sh`](../upgrade/postfiat-upgrade.sh) pulls the rolling image and restarts one host. It has
no health gate, no soak and no way back: if a new image starts but never syncs, the node stays down until someone
notices. `pft-rollout` rolls an image across a validator and its sentry one host at a time, sentry first (the
canary), and puts the previous image back on any host that does not pass the gate.

```
preflight (all hosts, changes nothing)
  foundation build_version known | no pft-maint data-collection lock | each running image still in the local store
  each host healthy now (same conditions as the gate)          any failure -> exit 4, nothing touched
for host in hosts.conf order (sentry, then validator):
  target = docker pull IMAGE_TAG   (or --no-pull --target REF: a local image, for drills)
  pft-maint start (window, pushed to the sentry) + Alertmanager silence
  deploy:  target == running image -> docker restart (no-op rollout, still gated)
           compose container       -> retag IMAGE_TAG, docker compose up -d   (keeps COMPOSE_FILE overrides)
           docker run container    -> retag, stop, rename to NAME-prerollout-<run>, docker run with the same config,
                                      compare the new container's config with the old one (drift = fail)
  gate  (<= GATE_TIMEOUT) -> soak (SOAK_SEC) -> PASS: pft-maint end, next host
                                             -> FAIL: restore recorded image, re-gate, pft-maint end, STOP
```

| File | What |
|---|---|
| `pft-rollout.sh` | `plan [--json]`, `run --yes [--target REF --no-pull]`, `status [--json]`, `rollback --yes [--host L]` |
| `hosts.conf.example` | host list in rollout order: `host LABEL local\|ssh SSH_TARGET\|- CONTAINER MIN_PEERS`, optional `post LABEL COMMAND...` |
| `tests/test-rollout.sh` | 20 offline cases with fake docker/ssh/sudo/curl/pft-maint and a fake clock; `--mutants` runs 15 mutation controls |
| `tests/stubs/` | the fakes (the docker fake keeps per-host JSON state and parses `docker run` flags back into inspect output) |

## Usage

```bash
sudo install -D -m 0644 rollout/hosts.conf.example /etc/pft-rollout/hosts.conf   # edit SSH target / peers
rollout/pft-rollout.sh plan                      # read-only: images, digests, rollback image present, health, locks
rollout/pft-rollout.sh run --yes                 # pull IMAGE_TAG on each host in turn, gate, soak, promote
rollout/pft-rollout.sh status --json             # running image per host + last run + lock state
rollout/pft-rollout.sh rollback --yes            # put back the recorded image on hosts the last run promoted
```

Run it as a user with passwordless `sudo` on the validator host and `ssh SSH_TARGET sudo -n` access to the sentry
(or as root with an ssh config for the sentry). Every command on a host goes through `sudo -n` / `ssh ... sudo -n`.

### Post commands

A `docker run` recreate gives the sentry a new container and usually a new bridge IP. Add-ons keyed to the container
need a nudge: [pft-egress](../egress/README.md) renders its default-deny rules for the container's IP and would
otherwise wait up to 5 minutes for its reapply timer. A `post` line in `hosts.conf` runs a command as root on that host
(`bash -c`, through the same `sudo -n` / ssh path) every time the container has been started on a new or restored image:
after deploy (before the health gate), after a no-op restart, and after a rollback restore.

```
post sentry pft-egress reapply --container postfiatd-sentry
```

Several `post` lines for one host run in order, joined with `&&`. A failing post command counts as a failed deploy
(restore + re-gate, stop) or, after a restore, as a failed rollback (exit 5). Its output is printed with a `post:`
prefix, and each run is a `post_hook` audit event with its exit code. `plan` shows the post command per host.

## Health gate and thresholds

A poll is `server_info` from inside the container (`docker exec NAME curl 127.0.0.1:5005`). It passes only if ALL hold:

| Condition | Default | Env |
|---|---|---|
| `server_state` is `full` or `proposing` | | |
| `build_version` equals the foundation RPC's | https://rpc.testnet.postfiat.org | `FOUNDATION_RPC` |
| `peers` >= the host's `MIN_PEERS` column | 5 (example conf) | `hosts.conf` |
| validated ledger `age` <= | 20 s | `MAX_LEDGER_AGE` |

| Phase | Default | Env |
|---|---|---|
| poll interval | 10 s | `POLL_SEC` |
| gate: first passing poll within | 1800 s | `GATE_TIMEOUT` |
| soak after the gate | 300 s | `SOAK_SEC` |
| soak fails after N consecutive failing polls | 3 | `SOAK_BAD_POLLS` |
| validated `seq` must advance over the soak by | 10 | `MIN_ADVANCE` |
| rollback re-gate within | 1800 s | `ROLLBACK_TIMEOUT` |

The gate timeout is long on purpose: a restarted node can take 15+ minutes to reach `full` again.

## Failure matrix

| What fails | What pft-rollout does | Other host | Exit |
|---|---|---|---|
| another run holds the lock | refuses | untouched | 4 |
| pft-maint data-collection lock held | refuses | untouched | 4 |
| foundation RPC build unknown | refuses | untouched | 4 |
| a running image is not in the local store (no way back) | refuses | untouched | 4 |
| a host is unhealthy before the run | refuses | untouched | 4 |
| pull fails / `--target` missing on a host | that host is not changed, stop | later hosts untouched | 1 |
| pft-maint start or the silence fails | that host is not changed, stop | later hosts untouched | 1 |
| recreate drifts from the old container's config | restore + re-gate, stop | later hosts untouched | 1 |
| post command fails after deploy | restore (post runs again) + re-gate, stop | later hosts untouched | 1 |
| gate timeout, wrong build, too few peers, stale ledger | restore + re-gate, stop | later hosts untouched | 1 |
| soak: 3 failing polls in a row or ledger not advancing | restore + re-gate, stop | later hosts untouched | 1 |
| second host (validator) fails | validator restored; sentry stays on the new image (it passed) | promoted | 1 |
| restore or re-gate fails | `ROLLBACK FAILED`, recorded image + digest printed for manual action | later hosts untouched | 5 |
| SIGINT/SIGTERM during a host | restore that host, stop | later hosts untouched | 6 |

"Restore" means: retag `IMAGE_TAG` to the recorded image ID; compose -> `docker compose up -d`; docker run -> remove
the new container, rename `NAME-prerollout-<run>` back, restart policy back to `unless-stopped`, start it (the exact
old container). Then the container's image ID is compared with the recorded one before the re-gate.

## Audit log and state

`$STATE_DIR` (default `~/.local/state/pft-rollout`): `audit.jsonl` gets one JSON line per event (`run_start`,
`preflight_ok`, `host_start`, `target`, `window_open`, `post_hook`, `deployed`, `gate_pass`/`gate_fail`, `soak_pass`/`soak_fail`,
`rollback_start`, `rollback_done`/`rollback_fail`, `window_close`, `host_done`, `run_end`), each with `ts`, `run` and
`host`. `last-run.json` holds the recorded image ID + repo digest, target, mode and result per host, which
`rollback` and `status` read. `rollout.lock` is an `flock` lock.

## Alerting during a rollout

Each host step opens a [pft-maint](../maint/README.md) window on the validator host (pushed to the sentry, so the
watchdog, health monitor and integrity monitor on both hosts suppress) and an Alertmanager silence (`SILENCE_MATCHER`,
default `alertname=~.+`, i.e. every alert on that Alertmanager) that lasts GATE_TIMEOUT + SOAK_SEC + ROLLBACK_TIMEOUT + 25 min. The window is ended when the host is
done. The silence is NOT expired early: `PFTContainerRestarted` stays true for 15 minutes after a container start, so
an early expiry would page. pft-maint itself sends one `[MAINT]` start and one end message per window by design.

## Tests

`tests/test-rollout.sh` (no root, no network, nothing on the hosts touched). Cases: gate pass on both hosts (config
preserved, canary first, one window + silence per host), gate timeout on the canary, second-host failure, rollback
re-gate failure, lock contention, missing previous image, no-op rollout, soak failure, data-collection lock, config
drift, wrong build, too few peers, stale ledger, drill path (`--target` image on the sentry only), manual rollback,
read-only `plan`/`status`, post command (runs after deploy and before the gate, runs again after a rollback restore,
a failing post command rolls back, a post line for an unknown host is a config error). `--mutants` applies 15 one-line mutations to a copy of the script (build check off, continue
after a failed host, no lock, no recorded-image check, rollback without re-gate, no soak, no drift check, peers check
off, ledger-age check off, data-collection lock check off, restore forcing restart=unless-stopped, post failure ignored, no post after deploy, no post after restore, post lines not
parsed); each must make at least one case FAIL.

Published runs (Ubuntu 22.04, no host touched): `logs/rollout/test-1.log` and `test-2.log` (16/16 each; test-2 is after the
CapDrop assertion was made null-safe), `mutants-1-timeout.log` (M1-M8 caught, then stopped by a 1200 s outer `timeout`, exit 124,
M9-M10 not reached), `mutants-2.log` (full run, M1-M11 all caught, 0 not caught). The `jq: error ... Cannot iterate over null`
line in mutants-2 comes from the CapDrop assertion running against M7's drifted container (CapDrop missing); the case still FAILed
as intended, and the assertion now reads `CapDrop // []`. `test-3.log` (20/20) and `mutants-3.log` (M1-M15 all caught, 0 not caught) are after the post-command
change (cases 17-20, mutants M12-M15).

### Live drill checker

`drill/check-drill.sh noop|badimage AUDIT_JSONL RUN_ID FACTS_JSON` gives the PASS/FAIL verdict for the live no-op run
and the bad-image drill. It reads only what a run leaves behind: the audit lines of that run ID, plus a facts file
that the drill wrapper writes (exit code, sentry and validator container image ID and `StartedAt` before and after,
number of messages on the throwaway alert topic). `noop` needs exit 0 and, on both hosts in canary order, a target
equal to the recorded image, gate and soak PASS, promotion, no rollback, a restart (`StartedAt` changed) and the same
image ID. `badimage` needs exit 1, a sentry deploy, gate FAIL and rollback re-gate PASS, the sentry back on its
recorded image, no validator audit event, the validator's image ID and `StartedAt` unchanged, and 0 alert-topic
messages (a missing count is a FAIL, not 0).

The checker is tested before any live run. `tests/test-check-drill.sh` runs pft-rollout.sh against the
test-rollout.sh stubs (a no-op run, a real upgrade, a bad-image drill, and a bad-image drill whose rollback also
fails), builds the facts from the stub containers, and checks each positive verdict. It then runs 16 negatives (plus 2 usage-error cases)
(e.g. validator restarted, alert message received, alert count missing, sentry left on the bad image,
`rollback_done` removed, wrong run ID, an upgrade passed off as a no-op), each of which must print one exact
`FAIL <check>` line. `tests/mutants-check-drill.sh` weakens one check at a time (C1-C8) and requires
test-check-drill.sh to fail on each mutant. Published run: `logs/rollout/checker-1.log` (shellcheck clean, 20/20,
C1-C8 all caught, test-rollout.sh still 20/20 after the sourcing guard was added).

## Limits

- Two-host design tested with one compose host and one `docker run` host. The `docker run` recreate keeps user, env,
  command, mounts, ports, log driver/options, network, restart policy, security_opt, caps, read-only root, tmpfs, pids
  and memory limits; anything else (ulimits, DNS, extra hosts, devices) is not re-applied, but the drift check compares
  ulimits, DNS, extra hosts and privileged too, so a container that uses them rolls back instead of losing them.
- The rolling `testnet-light-latest` tag is used (per Post Fiat's validator guide), not a pinned digest. The digest
  actually running before and after is recorded in the audit log and state file.
- The previous `docker run` container is kept stopped as `NAME-prerollout-<run>` for `rollback`; remove old ones by hand.
- Only one Alertmanager silence target (`AM`) is supported; `AM=none` / `MAINT_CMD=none` disable silence / window.
