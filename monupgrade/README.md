# monupgrade — reversible Prometheus + Alertmanager image upgrades

`pft-monupgrade.sh` upgrades the pinned images of the loopback monitoring stack started by
[`../alerts/run-stack.sh`](../alerts/run-stack.sh) (containers `pft-prometheus`, `pft-alertmanager`; plain
`docker run`, no compose file) without risking the alerting of a Post Fiat node: every target image is pinned to its
registry digest and checked against the live rules and configuration before anything is swapped.

Status: `plan`, `apply`, `rollback`, their offline tests and the live-run tooling (`drill/`). The recorded two-host
runs follow.

## plan (no container change)

```
pft-monupgrade plan [--out FILE] [--no-pull]
```

1. **Current state** per container: `Config.Image` (must be `repo:vX.Y.Z`), image id, and the repo digest from the
   image's `RepoDigests`.
2. **Target** per image: the highest `vX.Y.Z` tag on Docker Hub (no `-rc`, `-distroless`, `latest`) of the **same
   major** as the running tag, pushed at least `MIN_AGE_DAYS` (14) ago, pinned to that tag's manifest-list digest.
   `TARGET_PROM` / `TARGET_AM` override it (`vX.Y.Z` = digest looked up on the hub, `vX.Y.Z@sha256:...` = no hub
   call). A running tag that is already the target or newer is `UPTODATE` (never a downgrade).
3. **Pull by digest** (`docker pull repo:tag@sha256:...`), then the local `RepoDigests` must contain exactly
   `repo@sha256:...`. The image store gains one image per target; no container is touched. `--no-pull` requires the
   digest to be present already.
4. **Checks**, first with the CURRENT images (control), then with the TARGET images, each in a throwaway container
   (`--rm --network none --read-only --tmpfs /tmp --cap-drop ALL --user 65534`) with the same read-only mounts as the
   live Prometheus (`/etc/pft-alerts`, `/etc/pft-slo`):
   `promtool check config prometheus.yml`, `promtool check rules` over every `rule_files` entry (globs expanded),
   `promtool test rules` over every `tests.yml` / `*.tests.yml` of both folders, `amtool check-config
   alertmanager.yml`. A check that fails on both images prints `CONTROL-FAIL` and `FAIL` (a config problem, still a
   blocker); one that fails only on the target is an upgrade incompatibility.

Exit: `0` upgrade available and every target check passed, `3` nothing to upgrade, `4` a target check failed,
`1` error, `2` usage. Every failure prints `FAIL <image> reason=<name>`:

| reason | meaning |
|--------|---------|
| `container-missing` | `docker inspect` of the container failed |
| `current-unpinned` | running ref has no `vX.Y.Z` tag or no repo digest |
| `hub-unreachable` | Docker Hub tag list unreadable or not JSON (fails closed) |
| `no-target` | no eligible tag (age / major / suffix), or an override that is not `vX.Y.Z` + sha256 |
| `pull-failed` | pull by digest failed, or (`--no-pull`) the digest is not in the store |
| `digest-mismatch` | pulled image's `RepoDigests` do not contain the pinned digest |
| `promtool-check-config` / `promtool-check-rules` / `promtool-test-rules` / `amtool-check-config` | that check failed on the target image |

`--out FILE` writes the plan as JSON (current ref/digest, target tag/digest, control result, failure reasons); `apply`
will consume it.

Env: `DOCKER` (e.g. `"sudo docker"`), `ALERTS_DIR`, `SLO_DIR`, `PROM_CONTAINER`, `AM_CONTAINER`, `PROM_REPO`,
`AM_REPO`, `TARGET_PROM`, `TARGET_AM`, `MIN_AGE_DAYS`, `HUB_URL`; tests only: `HUB_TAGS_DIR`, `NOW`.

## apply / rollback

```
pft-monupgrade apply --plan FILE --yes     # re-create both containers on the plan's digest-pinned targets
pft-monupgrade rollback --yes              # back to the images that ran before the last apply
```

**Refused (exit 4, no container touched)** without `--yes`; not root; no active `pft-maint` window; alert routing
not isolated (`NTFY_TEST_URL` unset, the bridge's mounted `ntfy.env` not pointing at it, or the bridge started before
that file changed); Prometheus/Alertmanager not ready or their API unreadable; the watchdog
(`PFTAlertPipelineWatchdog`) not active or covered by a silence; a `*-premonupgrade` container left over. `apply`
also refuses a plan older than `PLAN_MAX_AGE` (24 h), a plan with failures, a running digest that differs from the
plan's `current_digest`, or a target that is not in the image store with its digest. Both containers already on the
targets -> `NOTHING TO DO`, exit 0 (a second apply is a no-op); `rollback` after a rollback likewise.

**Switch.** Backup to `STATE_DIR/backup/<run>/` (`docker inspect` of both containers, `prometheus.yml`,
`alertmanager.yml`, Alertmanager silences, an API snapshot, `SHA256SUMS`). Alertmanager first, then Prometheus: stop,
rename to `NAME-premonupgrade` (restart policy `no`, kept for the automatic rollback), `docker run` the new image
with the configuration rebuilt from the container's own `docker inspect` (name, restart policy, network,
security-opt, cap-drop/add, read-only, user, log driver, every bind and volume mount, arguments). Alertmanager's
data volume is mounted by name, so silences and the notification log survive the swap (`run-stack.sh up` would
start a fresh one).

**Gate** (one `CHECK` line each): both containers running the wanted ref; `/-/ready`; Prometheus and Alertmanager
versions = target tags; the rule set (group/name), scrape targets, targets up and receivers identical to the
snapshot before the switch (waits up to `SETTLE_TIMEOUT` for the first evaluation); no rule unhealthy that was healthy
before; every active silence still active; watchdog active and unsilenced; 9090/9093 listening on loopback only; a
synthetic `PFTMonupgradeTest` alert posted to Alertmanager is not silenced and reaches the `NTFY_TEST_URL` topic
within `DELIVERY_TIMEOUT` (then resolved); configuration signature of each re-created container (everything above
except the image) equal to the one recorded before the change. PASS -> the `-premonupgrade` containers are removed
(volumes kept), `STATE_DIR/state.json` records previous/current refs, exit 0. Any failure or error -> automatic
rollback (an INT/TERM during the switch is held until the gate ends and then also rolls back) (the kept previous containers are renamed back, their restart policy restored and started),
exit 1 (2 if the previous containers are not ready afterwards).

Prometheus keeps its TSDB volume across the swap in both directions; a rollback across a TSDB format change would
need the data volume restored from backup (the targets used here are all Prometheus 3.x).

## Tests

```
bash tests/run-tests.sh        # plan: stub docker (tests/stub_docker.sh) + Docker Hub fixtures (tests/fixtures)
bash tests/run-apply-tests.sh  # apply/rollback: stateful fake docker + Prometheus/Alertmanager/ntfy APIs (tests/fake_stack.py)
```

Each failure path asserts its exit code, its named reason and what must NOT have happened (no pull, no check
container). The selection fixtures cover the age gate, semver order (`v3.15.1` > `v3.9.10`), other majors,
`-rc`/`-distroless`/`latest`, and invalid hub JSON. The apply suite runs apply -> second apply (no-op) -> rollback ->
rollback (no-op) -> re-apply, 14 refusals (each with zero container-changing docker calls), and 10 injected gate
failures (docker run x2, readiness, lost rule, unhealthy rule, target down, no delivery, exposed port, lost silences,
configuration drift) that must all end on the original images with restart policies, Alertmanager data volume and silences intact. The fake derives every
API answer from the containers actually running (version = image tag; silences only if the original Alertmanager
volume is mounted), so the re-create logic itself is under test. One more case serves a `/api/v1/rules` body larger than one argv string
(the live one is ~134 KB; dry run 2 on the sentry canary refused with `Argument list too long` before the fix), so
the API bodies are read by jq from files.

## Live runs (`drill/`)

The sentry runs **no** Prometheus/Alertmanager: the sentry's alerts are evaluated by the validator's stack. So
"sentry first" means a **temporary canary stack** on the sentry, then the live stack on the validator.

- `drill/canary.sh up|down` (on the sentry, from a run copy of the pushed commit): `run-stack.sh up` with
  `EXPORTER_CHECK=0` (no exporter there, so its scrape targets are down before and after, compared as is), the
  validator's **current** images pinned to their digests, the bridge pointed at a throwaway topic. It refuses a host
  that already has any stack container or the Prometheus volume. `down` removes the containers, both volumes and
  every image pulled after `up` (image store = before), and fails if anything is left.
- `drill/live-run.sh` (repo root on the validator): preflight (clean pushed HEAD, shellcheck, both offline suites,
  integrity PASS both hosts, both nodes full, no window, no unsilenced alert but the watchdog/digest-only ones,
  imagescan before); pft-maint window on both hosts with its `[MAINT]` target on a throwaway topic and one
  Alertmanager silence for everything except the watchdog, `PFTMonupgradeTest` and digest-only alerts (the gate
  checks that the watchdog never matches it); per host `plan` -> `apply` -> `rollback` -> `apply` -> `apply`
  (`NOTHING TO DO`); the validator's live bridge is moved to the throwaway topic for its cycle (`run-stack.sh
  bridge`) and back after it; imagescan after (fixable counts per monitoring image only, never ids); integrity
  accept of the re-created monitoring containers; end window, drain, expire the silence, read back the throwaway
  topics and every operator topic.

```
HOSTS="sentry validator" RUN=NN bash monupgrade/drill/live-run.sh 2>&1 | tee LOG
DRY=1 HOSTS=sentry RUN=dryN ...     # not the basis; a dry validator cycle rolls back once more at the end
```
