# upstream-rollback: digest-pinned upgrade rollback for the validator guide

Test kit and evidence for a docs-only PR to
[postfiatorg/postfiatorg.github.io](https://github.com/postfiatorg/postfiatorg.github.io). The PR changes section 10
("Upgrade Procedure After Fresh Install") of the validator guide. Before, the upgrade was one-way: `docker compose pull`
moves the `-light-latest` tag, and nothing recorded which image the node ran before. The PR adds:

- a **pre-upgrade record**: before `docker compose pull`, the running image ID and its first RepoDigest are written
  to `pre-upgrade-<UTC>.txt` in the node directory, and the block prints `recorded <file>` only when a digest is in it;
- **Rolling Back an Upgrade**: pin the recorded digest in `docker-compose.override.yml` (the downloaded
  `docker-compose.yml` stays unchanged), verify with `docker compose config`, the container's image ID and the
  existing `server_info` check. The section also covers an existing override file (the block leaves it and the node
  unchanged), the database/config format caution for downgrades, and the `docker image prune` retention note;
- **Returning to the Rolling Tag**: record again, remove the override, pull, up.

The rolling-tag advice (`-light-latest`, no version pins) is unchanged. The changed section is byte-identical in
`content/validator-setup.md`, `static/agents/validator-setup.md` and `static/agents/validator-setup.txt`.

## Files

| file | what it does |
|---|---|
| `extract_rollback.py` | `extract_rollback.py OUTDIR GUIDE [GUIDE ...]`: cuts section 10 out of the first guide copy, fails unless every other copy has a byte-identical section 10, and writes the seven bash blocks as `01-dircheck.sh` .. `07-return.sh` plus `section.txt`. A marker line per block pins the block order. |
| `sentry-proof.sh` | live test on the **sentry** in a throwaway compose project (steps S0-S11 in its header). It runs on the validator as the agent user and reaches the sentry with `ssh relay`. |
| `logs/` | published, redacted logs (list below). |

## What the live test does

The throwaway project lives in `/var/tmp/pftrb-<random>` on the sentry. Its container is named `postfiatd`, the name
the guide's blocks use. That name is free on the sentry, whose real node is `postfiatd-sentry`. The container runs
`sleep infinity` with `network_mode: none`. It uses three local images that share the real image's layers:

- OLD: the sentry's real image under a local rolling tag `localhost/pftrb/postfiatd:testnet-light-latest`. It keeps
  the real `agtipft/postfiatd@sha256:...` RepoDigest.
- NEW and FIXED: `docker commit` copies with a label. They stand for the bad release and the fixed release.

The guide blocks run unchanged through `ssh relay bash -s`, with these two edits, both printed as a diff in the log:

1. Each **rolling-tag** `docker compose pull` (blocks 03 and 07) becomes `docker tag <NEW|FIXED> <local rolling tag>`.
   The local tag has no registry, so the release is simulated, and the test downloads nothing new.
2. The rollback's `REC=pre-upgrade-YYYYMMDDTHHMMSSZ.txt` placeholder line is set to the record under test, as the
   guide tells the operator to do.

The **pinned** `docker compose pull` (override present) runs unchanged against Docker Hub, and the test requires
that it changes nothing: the image and container inventory and the container ID stay the same.

Assertions: the record holds the OLD image ID and the real RepoDigest; the upgrade recreates the container on NEW;
three controls (C1: no `postfiatd` container, so there is no `recorded` line; C2: a rollback with that incomplete
record prints `no repo_digest` and changes nothing; C3: with an existing override, the block prints
`exists: not changed`, and the override bytes and the container stay the same); the rollback config shows the
digest, the container is recreated on OLD, the two printed image IDs are equal, and the override is exactly the three
published lines; the pinned pull is a no-op; the return removes the override, the config shows the `-light-latest`
tag, and the container runs on FIXED; shellcheck passes on every block; cleanup leaves the inventory as it was
before the test.

Around the test: an Alertmanager silence on `host="sentry"`, a `pft-maint` window whose `[MAINT]` messages go to a
throwaway ntfy topic, and the sentry's `pft-integrity.timer` paused. The failsafe that re-arms it is a sleeping transient service, not a timer, because `pft-schedaudit` reports a transient timer as an unexpected scheduled entry. At the end the runner collects `pft-schedaudit` and `pft-jobwatch` on the sentry and requires them clean. It expires the silence only when no new sentry alert is active, then watches 3 more minutes. Before
and after the test, the runner records the ID, StartedAt and `server_state` of both real containers (validator
`postfiatd`, sentry `postfiatd-sentry`) and runs `pft-integrity verify` on both hosts. At the end it reads back the
throwaway topic and every operator topic.

**shellcheck.** The blocks are checked with `-e SC2164`. SC2164 asks for `cd ... || exit` on
`cd "$POSTFIATD_DIR"`. In a terminal where the operator pastes the block, `|| exit` closes that terminal. The guide
already uses a bare `cd "$POSTFIATD_DIR"` six times at upstream `99a3412`. The runner also proves that without the
exclusion, the only findings are SC2164 on the three `cd` lines.

**Image store note.** On the containerd image store (the sentry runs Docker 29.1), every local image carries a RepoDigest,
including the committed NEW/FIXED copies. So control C1 makes the record incomplete by renaming the container away.
It does not use an image without a digest. The guide names both causes of a missing `recorded` line.

## Run it

From a checkout of this repo on the validator (agent user, `ssh relay` reaches the sentry), with the PR branch of the
guide repo checked out in `guide/`:

```bash
git clone -q -b upgrade-rollback https://github.com/darkmatter-sudo/postfiatorg.github.io.git guide
python3 -I upstream-rollback/extract_rollback.py out guide/content/validator-setup.md \
  guide/static/agents/validator-setup.md guide/static/agents/validator-setup.txt
bash upstream-rollback/sentry-proof.sh out 2>&1 | tee LOG
```

## Logs

(filled in with the recorded runs)
