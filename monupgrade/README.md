# monupgrade — reversible Prometheus + Alertmanager image upgrades

`pft-monupgrade.sh` upgrades the pinned images of the loopback monitoring stack started by
[`../alerts/run-stack.sh`](../alerts/run-stack.sh) (containers `pft-prometheus`, `pft-alertmanager`; plain
`docker run`, no compose file) without risking the alerting of a Post Fiat node: every target image is pinned to its
registry digest and checked against the live rules and configuration before anything is swapped.

Status: `plan` and its offline tests. `apply` / `rollback` and the recorded runs follow.

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

## Tests

```
bash tests/run-tests.sh      # offline: stub docker (tests/stub_docker.sh) + Docker Hub fixtures (tests/fixtures)
```

Each failure path asserts its exit code, its named reason and what must NOT have happened (no pull, no check
container). The selection fixtures cover the age gate, semver order (`v3.15.1` > `v3.9.10`), other majors,
`-rc`/`-distroless`/`latest`, and invalid hub JSON.
