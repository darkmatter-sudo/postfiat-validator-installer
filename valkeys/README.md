# pft-valkeys: validator master-key and token lifecycle

A Post Fiat validator signs with an **ephemeral key** carried in a `[validator_token]`. The token is derived from an
offline **master key** and has a **manifest sequence**: each `create_token` raises it by one, peers keep only the
highest sequence they have seen for a master key, and a revocation is a manifest with sequence `4294967295`. The
official guide (steps 5-8) shows the one-time `validator-keys create_keys` / `create_token`, but nothing in this repo
covered rotation, revocation, or checking that the running token is the newest one. `../secrets` checks where key
files could leak; this add-on owns the lifecycle and the sequence.

- `keys create`, `token rotate`, `revoke`: wrap the `validator-keys` binary that ships in the postfiatd image. It runs
  in a throwaway container with `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, as your
  uid:gid, with only the key directory mounted. Outputs are 0600, nothing is overwritten, no secret reaches stdout.
- `check`: read-only. Reports the running manifest sequence, the ephemeral key and the key/config file permissions,
  remembers the highest sequence seen per master key (`--state`), and writes Prometheus textfile metrics. An old token
  put back (e.g. from a backup) is a `FAIL` and the `PFTValkeysSequenceRegression` alert.

Target: Ubuntu 22.04, Docker, `agtipft/postfiatd:testnet-light-latest` (postfiatd 1.0.9). Needs `jq`.

## Usage

```bash
# On an offline/admin machine with Docker (NOT the validator). DIR is created 0700.
valkeys/pft-valkeys.sh keys create  --dir ~/pft-keys            # prints the master public key only
valkeys/pft-valkeys.sh token rotate --dir ~/pft-keys            # writes ~/pft-keys/token-seq<N>.cfg (0600)
valkeys/pft-valkeys.sh revoke --dir ~/pft-keys --confirm-key nH...   # then type: REVOKE nH...

# On the validator / sentry (read-only):
sudo valkeys/pft-valkeys.sh check                               # container postfiatd, /etc/postfiatd/postfiatd.cfg
sudo valkeys/pft-valkeys.sh check --container postfiatd-sentry --host sentry
sudo valkeys/pft-valkeys.sh check --state /var/lib/pft-valkeys/state.json \
     --textfile-dir /var/lib/pft-exporter/textfile             # sequence history + metrics
```

`check` exit codes: `0` OK (INFO lines don't count), `1` WARN, `2` FAIL, `3` usage. Key commands: `0` done, `2`
refused or failed, `3` usage.

### Key commands and their refusals

| Command | Refuses (exit 2) when |
|---|---|
| all | `--dir` is a symlink, not a directory, not owned by you, or not mode 700; `validator-keys` fails (its temp output is deleted) |
| `keys create` | `DIR/validator-keys.json` already exists |
| `token rotate` | key file missing, not 0600 or not a validator-keys file; key revoked; `--out` exists or its directory is group/other-writable; the sequence did not go up by exactly one |
| `revoke` | `--confirm-key` is not the master public key in the key file; the phrase `REVOKE <public key>` is not typed (terminal) or passed as `--confirm-phrase` (no terminal); already revoked; `revocation.cfg` exists |

`validator-keys` prints the token to its stdout. pft-valkeys captures that output in a 0600 temp file inside the
0700 key directory, copies only the `[validator_token]` (or `[validator_key_revocation]`) block into the output file,
deletes the temp file and prints the public key, the old and new sequence and the file path. `validator-keys` itself
creates the key file with the container's umask (0644); it is in the 0700 directory and is chmod 600 right after.

### check: what it reads

Everything goes through `docker exec <container>`: `stat` of the config, `grep -c` of the section **headers**
`[validator_token]`, `[validation_seed]`, `[validator_key_revocation]` (never their values), a `find` for JSON files
containing `"secret_key"` under `/etc/postfiatd` and `/var/lib/postfiatd` (count only), and the admin RPC commands
`server_info`, `validator_info` and `manifest <master key>` through the postfiatd CLI. It writes only `--state` and
`--textfile-dir`.

| ID | OK / INFO | WARN | FAIL |
|---|---|---|---|
| `conf.perms` | config 0600-style (or no secret in it: INFO) | holds a token/seed and is group-readable | holds a token/seed and is world-readable |
| `conf.token` | | | two `[validator_token]` sections; token **and** revocation |
| `conf.seed` | | `[validation_seed]` (master secret online) | |
| `conf.revocation` | | revocation configured: the node does not validate | |
| `conf.read` | | | container not running / config not found |
| `keys.online` | no master key file in the container | a `secret_key` JSON in the container | |
| `keys.perms` (`--keydir`) | dir 700, every file 600 | | anything else, or a file owned by another uid |
| `rpc` | `server_state` | | `server_info` fails |
| `validator` | master key loaded (or not a validator: INFO, sequence checks skipped) | | token configured but no key loaded; `server_info` and `validator_info` disagree |
| `ephemeral` | ephemeral key present and not the master key | | missing or equal to the master key |
| `seq` | first record / same / advanced (state updated) | | lower than the highest seen (**regression**); `4294967295` (revoked); state file not a JSON object |
| `seq.network` | | | the node knows a newer manifest for its own master key than the running token |

Without `--state`, `seq` only reports the sequence (and `seq.network` still compares with what peers relayed).

## Rotation runbook

1. On the offline machine: `pft-valkeys.sh token rotate --dir DIR`. Note the new sequence it prints.
2. Copy `DIR/token-seq<N>.cfg` to the validator (scp to a 0700 dir). In `postfiatd.cfg` replace the whole
   `[validator_token]` section with the file's content. Keep the config 0600.
3. Restart postfiatd (`cd /opt/postfiatd && sudo docker compose restart`; silence alerts for the window first).
4. `sudo pft-valkeys.sh check --state /var/lib/pft-valkeys/state.json` must show `seq N advanced from N-1` and a new
   ephemeral key. Then shred the copied token file (`shred -u`).
5. Never restore an older token from a backup: peers ignore a lower sequence once they have seen a higher one, and
   `check` reports it as a regression. If the newest token is lost, rotate again (sequence N+1).

## Revocation runbook

Revoke only when the **master** key is compromised or retired; a leaked token alone is fixed by rotating.

1. On the offline machine: `pft-valkeys.sh revoke --dir DIR --confirm-key <master public key>` and type the phrase.
   It writes `DIR/revocation.cfg` (sequence 4294967295) and marks the key file revoked; `token rotate` refuses it
   from then on.
2. On the validator, replace `[validator_token]` with the `[validator_key_revocation]` section and restart. The node
   announces the revocation and stops validating with that key: `check` shows `WARN conf.revocation` and
   `validator: not configured`.
3. Create a new master key in a new directory (`keys create`), rotate a token, install it, and publish the new
   public key to whoever lists your validator. Keep the revoked directory (offline) as a record.

**Safety:** the master key directory is the validator's identity. Keep it offline, backed up encrypted, and never
on the validator or sentry (`keys.online` warns if one is found in the container). Never paste a token, revocation
or `secret_key` into tickets or logs; pft-valkeys never prints them.

## Monitoring

`check --textfile-dir DIR [--host LABEL]` writes `DIR/pft_valkeys_<LABEL>.prom` atomically (0644):

| Metric | Meaning |
|---|---|
| `pft_valkeys_up` | 1 if the node container could be read |
| `pft_valkeys_validator_configured` | 1 if `validator_info` reports a loaded key |
| `pft_valkeys_manifest_sequence{master}` | running token's sequence (`master` = first 12 chars of the public key) |
| `pft_valkeys_manifest_sequence_max{master}` | highest sequence in the state file |
| `pft_valkeys_sequence_regression` | 1 if the running token is older than one already seen |
| `pft_valkeys_findings{grade="warn\|fail"}` | number of WARN / FAIL lines |
| `pft_valkeys_last_run_timestamp_seconds` | end of the run |

Run it from cron or a timer (e.g. every 15 min) with `--state` on a validator that has a token. This repo's
validator has no token yet (the official guide's steps 5-8 are not done), so the add-on is **not** installed on the
live hosts and its rules are not loaded into `../alerts/prometheus.yml`.

### Alerts

`alerts/valkeys.rules.yml` (tests: `alerts/valkeys.tests.yml`):

- `PFTValkeysSequenceRegression` (critical, immediately): `pft_valkeys_sequence_regression == 1`.
- `PFTValkeysCheckFailing` (warning, 15m): any FAIL finding, or `pft_valkeys_up == 0`.
- `PFTValkeysCheckStale` (warning, 10m): no run for over 2 h.

## Tests

```bash
valkeys/tests/run-tests.sh                 # offline, no docker/keys/node: tests/stub-docker.sh fakes both
shellcheck valkeys/pft-valkeys.sh valkeys/tests/*.sh valkeys/drill/*.sh
cd valkeys/alerts && promtool check rules valkeys.rules.yml && promtool test rules valkeys.tests.yml
valkeys/drill/drill.sh LOGFILE             # isolated drill with real validator-keys + a throwaway node
```

The drill (`drill/drill.sh`) uses real `validator-keys` and a throwaway standalone postfiatd (`--network none`,
`-a --start`) in a `mktemp` directory: live read-only checks before, `keys create` + refusals, token seq 1 loaded and
checked, rotation to seq 2, the old seq-1 token put back (regression FAIL + metric), revocation with the double
confirmation (and its refusals), a scan of its own log for every secret string and generic secret patterns, then it
shreds the keys and repeats the live checks.

## Live proof

Recorded on pft-agent's validator host (Ubuntu 22.04.5) against commit `385e764` (sha256 of every file in each log
header). The live validator and sentry were only read; neither has a validator token yet.

| Log | What | Result |
|---|---|---|
| [`logs/01-tests.log`](logs/01-tests.log) | offline suite (parsing, sequence compare, permission grading, refusals, fixture audits, state/textfile) | 95 passed, 0 failed |
| [`logs/02-lint.log`](logs/02-lint.log) | shellcheck of the tool, tests and drill; `bash -n` | exit 0 |
| [`logs/03-promtool.log`](logs/03-promtool.log) | promtool 3.5.0 `check rules` (3 rules) + `test rules` | SUCCESS |
| [`logs/04-drill.log`](logs/04-drill.log) | isolated drill: seq 1 -> seq 2 -> old-token regression -> revocation, secret scan, shred | 30 pass, 0 fail |
| [`logs/05-secret-scan.log`](logs/05-secret-scan.log) | scan of logs 01-04 before commit: base64 runs >= 60 chars (sha256 digests excluded), key/token/seed/PEM markers, IPv4, home paths | 0 matches (`grep -c` exit 1 = none) |

Drill highlights (`logs/04-drill.log`): the live validator and sentry were `full` before and after, with the same
config sha256 and `pft-integrity verify` PASS on both; `check` on both live nodes exited 0 (not a validator,
config 644 with no secret). On the throwaway node, seq 1 was recorded, seq 2 showed `advanced from 1`, the seq-1
token put back gave `FAIL seq ... LOWER than the highest seen (2)` with `pft_valkeys_sequence_regression 1`, and the
revocation config gave `WARN conf.revocation` with the node no longer validating. The drill compared all 19 secret
strings of its throwaway key (master `secret_key` + every token/revocation line) with its own log: 0 matches. The
key directory and the drill container were then destroyed.
