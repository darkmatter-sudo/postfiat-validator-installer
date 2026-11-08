# pft-backupwatch: backup freshness, integrity and restore-readiness monitor

Status: **design + step 1 (check) in progress**. Nothing is installed on any host yet; no rule, fleet-manifest or
rulecheck line exists until the live install run (lesson: rule lines ship in the same commit as the install).

`../backup` writes one config archive a day (`pft-backup.timer`), and `../jobwatch` sees whether that timer ran and
exited 0. Neither says whether the newest archive is **fresh, intact, current and restorable**: a timer can exit 0
and still write an archive that misses a member, that no longer matches the live config, or that sits only on the
host it is meant to rebuild. `pft-backupwatch` closes that gap. It is read-only on the node: it never restores,
never writes into `/etc`, `/opt/postfiatd` or a container, and never runs `docker exec` (the node is
AppArmor/seccomp-confined; ad-hoc execs are denied and page). Archives are read as streams in memory by a Python 3
stdlib helper; nothing is extracted to disk.

## What it checks (`check`)

| Check | OK | WARN | FAIL |
|---|---|---|---|
| `fresh` | newest archive younger than `MAX_AGE_H` (default 26 h: daily timer + 15 min jitter + slack) | older than `MAX_AGE_H` | older than `FAIL_AGE_H` (50 h) or no archive at all |
| `size` | newest >= `MIN_BYTES` and within `SIZE_RATIO` (0.5..2.0) of the previous archive | outside the ratio | below `MIN_BYTES` (truncated/empty) |
| `sidecar` | `<archive>.sha256` exists and matches | - | missing or mismatch |
| `manifest` | archive opens (gpg archives: decrypted in memory with `PASSFILE`), every member listed in `MANIFEST.sha256` with the right sha256, no unlisted member | - | unreadable / wrong passphrase / bad member / missing member / extra member |
| `content` | the members a restore needs are present (`postfiatd.cfg`, `validators.txt`, `docker-compose.yml`, `.env`, every `COMPOSE_FILE` member that `.env` names) and the reference members hold data, not an error message | a reference member (`firewall/`) missing or holding a tool error | a required member missing |
| `drift` | each config file in the archive equals the live file (`postfiatd.cfg` compared after stripping the same secret sections as pft-backup; container config read from the volume's host path via `docker inspect`, not `docker exec`) | a file differs or is gone since the backup (config changed after the last backup: the next backup will pick it up) | - |
| `offhost` (`check --offhost`, or `OFFHOST=1`) | the sentry holds a replica of the newest archive, its sha256 equals the local ciphertext sha256 recorded at replication, and it decrypts with the sentry's age identity to the archive's sidecar sha256 | replica of an older archive only | no replica / ssh down / sha mismatch / does not decrypt |

Exit codes: 0 every check OK, 1 at least one WARN, 2 at least one FAIL, 3 usage/config error. `--json` prints one
object per check (`name`, `state`, `detail`) plus the archive name, age and size.

## Off-host replica (`replicate`)

Archives that live only on the validator do not survive losing the validator. `replicate` encrypts the newest
archive (plain or gpg) to the sentry's age recipient (the one `../keyescrow` already uses, `PEER_RECIPIENT`) in a
pipe and streams it over the admin SSH link (`PEER_SSH`) into `serve receive` on the sentry, which writes ciphertext
only, checks its sha256 against the sender's, decrypts it in memory with its own identity, compares the result with
the archive sidecar sha256, and keeps the newest `REPLICA_KEEP` (default 7) generations. Plaintext never touches the
sentry's disk and never crosses the network.

## Metrics and alerts (step 2)

`pft_backupwatch_*.prom` textfiles on both hosts (the sentry's file is pulled to the validator, which runs the only
Prometheus), five alerts in `../alerts/backupwatch.rules.yml` with promtool tests including recovery cases. Details
are filled in when they are built.

## Not covered

- The ledger database (`postfiatd-data` volume): pft-backup does not save it by design (a node re-syncs), so
  backupwatch does not check it either.
- Secrets that pft-backup strips by default (`[node_seed]`, ntfy env): `../keyescrow` escrows those.
