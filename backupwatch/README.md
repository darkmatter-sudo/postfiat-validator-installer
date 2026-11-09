# pft-backupwatch: backup freshness, integrity and restore-readiness monitor

Status: **installed on both hosts (logs 07-12); live alert drill `drill/alert-run.sh` (logs 13-14, re-run at the fixed helper: logs 17-18, PASS 52/0).** The validator
runs `ROLE=archive` (check + replicate + pull), the sentry `ROLE=replica`; `../alerts/backupwatch.rules.yml` is loaded
by Prometheus and listed in `../fleet` and `../rulecheck`.

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

## Files and usage

| File | What it is |
|---|---|
| `pft-backupwatch.sh` | CLI: `check [--json] [--offhost]`, `replicate`, `serve receive\|status\|verify` (the only verbs `PEER_SSH` runs on the peer), `version` (usage in its header); conf `/etc/pft-backupwatch.env` (root-owned, sourced only if owned by root) |
| `backupwatch_lib.py` | stdlib helper: archive listing, in-memory tar/manifest/content/drift checks, gpg decrypt to a pipe, `render` (the table) |
| `tests/test_backupwatch.py` | offline suite: synthetic archives in pft-backup's exact layout (fresh, old + age boundaries, missing, byte flip, truncated, size ratio, no sidecar, unlisted extra file, listed-but-absent, edited member, missing COMPOSE_FILE member, firewall reference error, drifted / gone files, cfg drift vs secret-only change, gpg right / wrong / no passphrase, usage) + the wrapper with a stub docker that answers only the exact inspect it must send + replication against a fake peer (`PEER_SSH` = a script running this same CLI's `serve` with its own dirs and a real age identity): replicate OK, ciphertext only on the peer, 0700 store, local record, no scratch left; `--offhost` OK / newer archive not replicated (WARN) / keep-3 prune / tampered replica / tampered replica + re-hashed meta / no local record / peer down (FAIL); refusals: wrong recipient (peer cannot decrypt, nothing stored), archive != sidecar (no peer call), bad recipient, no PEER_SSH, forged ciphertext sha, oversize, name outside the pattern, unknown verb |
| `tests/mutate.py` | mutation harness: 50 mutants (25 helper, 17 CLI, 8 rule), each in its own copy with its own temp base; a mutant must make the suite (or `promtool test rules`) fail with a FAIL line |
| `systemd/` | `pft-backupwatch.service/.timer` (both hosts, `collect` every 15 min), `pft-backupwatch-pull.service/.timer` (validator: the sentry's textfile, 2 min after it collects), `pft-backupwatch-replicate.service/.timer` (validator: started by `pft-backup.service.d/pft-backupwatch.conf` (`OnSuccess=`) right after each successful backup, then `OnSuccess=` a collect; the daily 04:05 + up to 10 min timer is the fallback). Before this drop-in the newest archive sat 35-58 min without an off-host copy each night (03:17 + 15 min backup vs 04:05 + 10 min replicate), longer than `PFTBackupNoOffhostCopy`'s 30 min `for`, so the alert fired nightly (log 19) |
| `../alerts/backupwatch.rules.yml`, `../alerts/backupwatch.tests.yml` | the five alerts and their promtool tests (fire at each `for` boundary + recovery for every alert) |
| `drill/checks-run.sh` | recorded lint + suite + promtool + mutation harness + unit verify + read-only live check (helper JSON and wrapper table) and `collect --stdout` at a pushed commit |
| `install.sh` | `--role replica` (sentry: script, helper, conf `ROLE=replica`, state + replica dirs 0700, collect unit/timer; needs keyescrow's age identity) and `--role archive` (validator: + `OFFHOST=1`, `PEER_SSH` and `REPLICA_RECIPIENT` copied from `/etc/pft-keyescrow.env`, replicate + pull units/timers; runs one replicate, collect and pull through the sandboxed units, each must succeed with offhost OK, then enables the timers). Idempotent; `--uninstall` disables the timers and removes the textfiles. Install the replica role first |
| `drill/install-run.sh` | recorded two-host install at a pushed commit: preflight, rollout silence (not the pipeline watchdog), pft-maint window with `[MAINT]` on a throwaway topic, pft-fleet sync, both install.sh roles, rulecheck lines, rule load, schedaudit + integrity accept, offhost check, cross-host replica sha256, Prometheus, fleet skew, rulecheck, jobwatch, restore + keyescrow re-run + operator-topic read-back. `PREFLIGHT_ONLY=1`: step 0 only; `RESUME=<run>`: re-run at already-installed bytes |
| `drill/verify-run.sh` | read-only re-verification of the installed state on both hosts (no window, no silence, nothing started but `check --offhost` and `serve verify`) |
| `drill/alert-run.sh` | recorded two-host alert drill at a pushed commit: the INSTALLED CLI collects from copies on tmpfs (`/dev/shm/pft-bw-drill`, 0700, removed at the end) while `pft-backupwatch.timer` is stopped on both hosts. Validator: drift on copies of the archived host files (one copy gets an appended comment line, `PFT_BW_ROOT`), lowered thresholds (`MAX_AGE_H 1`, `FAIL_AGE_H 2`, `DRIFT_GRACE_H 0`), an empty drill `STATE_DIR` (no replication record -> offhost FAIL against the real peer), then one byte flipped in the archive COPY; sentry: one byte flipped in a copy of the newest replica. Then a real collect (all resolve), then a conf with an invalid `MAX_AGE_H` (`up 0`, PFTBackupwatchStale) and a real collect again. Throwaway ntfy topic (bridge re-created on a 0600 temp env), silence on everything but `PFTBackup*` and the pipeline watchdog, ALERTS `query_range`, operator-topic read-back. Real archives, replicas and config are only read |
| `drill/update-run.sh` | recorded two-host update of the installed helper through pft-fleet inside a pft-maint window (`[MAINT]` on a throwaway topic, rollout silence, keyescrow re-run, operator-topic read-back); used for the run 14 read fix |

```
sudo pft-backupwatch check            # table + RESULT line, exit 0/1/2
sudo pft-backupwatch check --json     # the helper's JSON
sudo pft-backupwatch replicate        # validator: newest archive -> encrypted replica on the sentry
sudo pft-backupwatch check --offhost  # + the offhost check (status + verify on the sentry over PEER_SSH)
sudo pft-backupwatch collect --stdout # the textfile it would write (ROLE=archive on the validator, ROLE=replica on the sentry)
sudo pft-backupwatch pull             # validator: the sentry's textfile via `serve metrics`, validated
```

## Off-host replica (`replicate`)

Archives that live only on the validator do not survive losing the validator. `replicate` encrypts the newest
archive (plain or gpg) to the sentry's age recipient (the one `../keyescrow` already uses, `PEER_RECIPIENT`) in a
pipe and streams it over the admin SSH link (`PEER_SSH`) into `serve receive` on the sentry, which writes ciphertext
only, checks its sha256 against the sender's, decrypts it in memory with its own identity, compares the result with
the archive sidecar sha256, and keeps the newest `REPLICA_KEEP` (default 7) generations. Plaintext never touches the
sentry's disk and never crosses the network. On the validator the ciphertext exists only in `SCRATCH`
(`/dev/shm`) for the transfer and is removed right after. The validator records name, ciphertext sha256 and
plaintext (sidecar) sha256 in `STATE_DIR/replica.tsv`; `check --offhost` compares the sentry's `serve status` and
`serve verify` answers with that record, so a replica swapped or re-hashed on the sentry still fails.

## Metrics

`collect` writes `TEXTFILE_DIR/pft_backupwatch_<HOST_LABEL>.prom` atomically (0644, temp file + rename). The
validator (`ROLE=archive`) runs `check` (with `--offhost` when `OFFHOST=1`); the sentry (`ROLE=replica`) reads its
own replica store (`serve status` + `serve verify` of the newest replica). The validator runs the only Prometheus, so
`pull` fetches the sentry's file with `serve metrics` over `PEER_SSH` and installs it only if every sample is a
`pft_backupwatch_*` line labelled `host="sentry"` and the file has an `up` and a collect timestamp sample.

| Metric | Host | Meaning |
|---|---|---|
| `pft_backupwatch_up` | both | 1 if the run produced a result; 0 = the check or the store read failed (the file still gets written) |
| `pft_backupwatch_collect_timestamp_seconds` | both | time of the last collect |
| `pft_backupwatch_check_state{check}` | validator | 0 OK / 1 WARN / 2 FAIL for `fresh`, `size`, `sidecar`, `manifest`, `content`, `drift`, `offhost` (only the checks that ran) |
| `pft_backupwatch_archive_age_seconds`, `pft_backupwatch_archive_bytes` | validator | newest archive (-1: none) |
| `pft_backupwatch_drift_files` | validator | archived config files that differ from (or are gone on) the live host |
| `pft_backupwatch_drift_since_timestamp_seconds` | validator | first collect that saw drift (kept in `STATE_DIR/drift.since`; 0 and removed once drift is OK) |
| `pft_backupwatch_drift_overdue` | validator | 1 if drift is older than `DRIFT_GRACE_H` (30 h): a daily backup ran since and still did not capture the change |
| `pft_backupwatch_replicas` | sentry | encrypted replicas held |
| `pft_backupwatch_replica_newest_age_seconds` | sentry | archive age of the newest replica (from its name; -1: none) |
| `pft_backupwatch_replica_verify_ok` | sentry | 1 if the newest replica re-hashes to its recorded ciphertext sha256 and decrypts to its plaintext sha256 |

Drift alone is not an alert: a config change is normal, and the next daily backup picks it up. Drift that outlives a
backup cycle means the backups no longer hold what a restore would need.

## Alerts

`../alerts/backupwatch.rules.yml`, tested by `../alerts/backupwatch.tests.yml`:

| Alert | Expression (short) | for | Severity |
|---|---|---|---|
| `PFTBackupStale` | `check_state{check="fresh"} >= 1` (newest archive older than 26 h, or none) | 30m | warning |
| `PFTBackupBroken` | `check_state{check=~"sidecar\|manifest\|content\|size"} == 2` (one alert per failing check) | 15m | critical |
| `PFTBackupConfigDrift` | `drift_overdue == 1` | 15m | warning |
| `PFTBackupNoOffhostCopy` | `check_state{check="offhost"} >= 1 or replica_verify_ok == 0` (either side) | 30m | warning |
| `PFTBackupwatchStale` | collect older than 45 min (3 timer periods) or `up == 0`, per host | 10m | warning |

## Results so far

| Log | What it shows |
|---|---|
| [`logs/01-checks-step1.log`](logs/01-checks-step1.log) | ruff clean, suite 62 passed / 0 failed, live read-only check of the validator's newest archive: fresh, size, sidecar, manifest (22 members), drift (17 files equal the live host) OK; **content WARN**: the timer-made archives hold `ufw-status.txt` = `ERROR: Couldn't determine iptables version` and no `docker-user.rules`. Cause: `pft-backup.service`'s unitguard drop-in (`RestrictAddressFamilies=AF_UNIX`, no `CAP_NET_ADMIN`) stops ufw/iptables, and pft-backup keeps going. A real gap backupwatch was built to find; fixed and verified in log 03 |
| [`logs/03-backupfix.log`](logs/03-backupfix.log) | **found -> fixed -> verified** (`drill/backupfix-run.sh`): before = content WARN (exit 1); probe of pft-backup's two firewall commands in a transient unit: installed profile fails both (`Couldn't determine iptables version`, `Failed to initialize nft: Address family not supported`), new profile (`../unitguard/profiles/pft-backup.service.conf`: + `CAP_NET_ADMIN CAP_NET_RAW`, + `AF_NETLINK`; `/run` stays read-only, not needed) runs both; `pft-unitguard apply` (one real backup + the profile's check, which now requires both firewall members) exit 0; `pft-integrity` FAIL on the changed drop-in, accepted, PASS; after = every check OK on the new archive (23 members, 3 reference members present). `RESULT: PASS - 0 failed` |
| [`logs/02-checks-wrapper.log`](logs/02-checks-wrapper.log) | with `pft-backupwatch.sh`: shellcheck exit 0, ruff clean, suite 77 passed / 0 failed; live check through the helper (JSON) and the wrapper (table) give the same result: 5 OK + content WARN, exit 1 both |
| [`logs/04-checks-replication.log`](logs/04-checks-replication.log) | with replication: shellcheck exit 0, ruff clean, suite 109 passed / 0 failed; live check (after the log 03 fix) exit 0, every check OK, through the helper and the wrapper |
| [`logs/05-checks-step3.log`](logs/05-checks-step3.log) | step 3 at `32cafcf`: shellcheck 0, ruff clean, suite 155/0, promtool check 5 rules + unit tests SUCCESS, units clean, live `check` exit 0 and `collect --stdout` OK; **RESULT: FAIL**: mutant M14 (empty PASSFILE accepted) SURVIVED, 46/47 caught. An earlier dev pass had shown M14 caught, but only because parallel copies shared one temp base and tripped each other's "no scratch left" checks; the committed harness gives each copy its own. Fixed in `c2d5561`: own test for an empty PASSFILE, plus two finds of the same run: the textfile lacked its final newline (`$(...)` strips it), and the recorded commands printed a local home path (redacted to `<home>` in this published copy, 3 lines; the script now lets `$PWD`/`$ST` expand only inside the eval) |
| [`logs/06-checks-step3.log`](logs/06-checks-step3.log) | at `c2d5561`: shellcheck 0, ruff clean, suite **158/0**, promtool SUCCESS (5 rules; every alert fires at its `for` boundary and recovers), mutants **50 caught / 0 survived / 0 not applied / 0 broken**, orphans 0, units clean, live `check` exit 0 (all OK) and `collect --stdout` exit 0 (6 check states 0, drift 0), `/dev/shm` clean. `RESULT: PASS` |
| [`logs/07-preflight.log`](logs/07-preflight.log) | install runner `PREFLIGHT_ONLY=1` at `a2e10cc`: 9 ok / 0 failed, nothing changed |
| [`logs/08-install.log`](logs/08-install.log) | first two-host install at `a2e10cc`: **stopped at step 5** (20 ok / 1 FAIL). Both hosts installed, first replicate + validator `check --offhost` OK, but the check of the pulled sentry file read `replicas 0`: the sentry had written its textfile at its own install, before the replica arrived, and its next collect was up to 15 min away (runner bug: sequencing). The gate stopped the run before the next host change; restore ended the window and put the pft-maint target back |
| [`logs/09-preflight.log`](logs/09-preflight.log) | `RESUME=08` preflight at `d54d08f` (fix: collect on the sentry, then pull, before the check): **FAIL** 8 ok / 1: the read-only FOUND check now sourced the installed conf (`OFFHOST=1`) with a scratch `STATE_DIR`, so offhost read "not recorded locally". Fixed in `220a906` (`PFT_BW_CONF=/nonexistent`: local checks only) |
| [`logs/10-preflight.log`](logs/10-preflight.log) | `RESUME=08` preflight at `220a906`: 9 ok / 0 failed |
| [`logs/11-install.log`](logs/11-install.log) | full install at `220a906` (`RESUME=08`): **45 ok / 1 FAIL**. Every functional check passed: sentry + validator install, pulled sentry file `replicas 1` / `replica_verify_ok 1`, idempotent second run, rulecheck lines, 5 rules loaded (health ok, none firing), schedaudit 0 new/removed on both, integrity PASS on both, `check --offhost` all OK, replica ciphertext sha256 on the sentry == the validator's record, plaintext sha256 == archive == sidecar, `serve verify` OK, Prometheus series, rulecheck OK on both, 4 timers, jobwatch 0 failed/missed/disabled, restore + keyescrow drift 0, `[MAINT]` start/end on the throwaway topic, **operator topics 0 messages**. The FAIL is a checker bug: it expected a sentry row for `fleet`, which is a validator-only add-on (the skew output in the log is exit 0, every add-on CURRENT, 0 BEHIND/MODIFIED/MISSING/UNEXPECTED/DIVERGED). Check fixed in `0673b55` |
| [`logs/12-verify.log`](logs/12-verify.log) | read-only re-verify at `0673b55` with the fixed skew check: **8 ok / 0 failed, PASS** (installed bytes == repo on both hosts, fleet skew, integrity PASS both, `check --offhost` OK, cross-host replica sha256 + `serve verify`, timers, Prometheus, rules inactive, Alertmanager only the pipeline watchdog) |
| [`logs/13-alert-preflight.log`](logs/13-alert-preflight.log) | alert drill `PREFLIGHT_ONLY=1` at `1c7a3a4`: real `check --offhost` all OK, sentry replica verifies, 5 rules healthy, no PFTBackup* alert, only this task's own rollout silences name PFTBackup*, both nodes full, integrity PASS both, redaction control 16/16; nothing changed |
| [`logs/14-alert-drill.log`](logs/14-alert-drill.log) | **two-host alert drill at `1c7a3a4`: every alert FIRING and RESOLVED, 1 check FAIL = a real finding.** 2a drift on host-file copies: PFTBackupConfigDrift FIRING 13:02Z (`for` 15m); 2b one byte flipped in the archive COPY: PFTBackupBroken x3 (sidecar, manifest, content) FIRING 13:17Z; PFTBackupStale and PFTBackupNoOffhostCopy (validator offhost FAIL + sentry `replica_verify_ok 0` from a corrupted replica copy) FIRING 13:17Z (`for` 30m); real collect -> all RESOLVED by 13:19Z; invalid drill conf -> `up 0` -> PFTBackupwatchStale FIRING 13:29Z, RESOLVED 13:30Z. 10 messages on the throwaway topic, **operator topics 0 messages**, ALERTS `query_range` pending -> firing for all 6 alert/host pairs, real `check --offhost` OK and replica verify 1 at the end, integrity PASS both, nodes full. **Finding (the FAIL):** after the byte flip the helper did not say "archive not readable". `tarfile` (`r:gz`) stopped silently at the first garbled header after member 1 and never reached the gzip CRC, so it saw a PARTIAL member set: manifest "MANIFEST.sha256 missing" and a false drift `postfiatd.cfg changed`. The alerts were right (Broken fired), the reason was not. Fixed in `f17ae01`: the whole gzip stream is decoded first (length + CRC), and only zero padding may follow the last tar member; new tests: byte flip asserts content + drift "archive not readable", a bad inner header inside a valid gzip, a bad CRC with intact data; mutants M26/M27. Fail-before: the new tests on the old helper fail 2 checks |
| [`logs/15-checks.log`](logs/15-checks.log) | at `f17ae01`: shellcheck 0, ruff clean, suite **162/0**, promtool SUCCESS, mutants **52 caught / 0 survived**, live check exit 0. `RESULT: PASS` |
| [`logs/16-update.log`](logs/16-update.log) | helper update at `17f096c` (`drill/update-run.sh`): pft-fleet dry run 2 writes (`backupwatch_lib.py` on both hosts), pft-maint window with `[MAINT]` on a throwaway topic, sync exit 0 (integrity accepted by pft-fleet), installed bytes == repo on both hosts, collect x2 + pull success, real `check --offhost` all OK, Prometheus up 1 both / worst state 0, integrity PASS both, fleet CURRENT both, keyescrow drift 0, **operator topics 0**. `PASS` 21/0 |
| [`logs/17-alert-preflight.log`](logs/17-alert-preflight.log) | alert drill `PREFLIGHT_ONLY=1` at `772028c` (installed helper = `f17ae01` fix): real check OK, 5 rules healthy, no PFTBackup* alert or silence, both nodes full, integrity PASS both, redaction control 16/16; nothing changed |
| [`logs/18-alert-drill.log`](logs/18-alert-drill.log) | **alert drill re-run at `772028c`: `0 check(s) failed -> PASS` (52 `CHECK ok`, 0 `CHECK FAIL`).** The byte-flipped archive copy now reads sidecar FAIL `sha256 mismatch`, manifest FAIL `archive truncated or corrupt (BadGzipFile)`, content + drift FAIL `archive not readable` (the run 14 finding, fixed). Throwaway topic, 10 messages: [FIRING] PFTBackupConfigDrift 14:28:25Z, PFTBackupStale 14:43:25Z, PFTBackupNoOffhostCopy x2 (validator + sentry) 14:43:25Z, PFTBackupBroken x3 (sidecar, manifest, content) 14:44:10Z; all [RESOLVED] 14:45:10-14:45:26Z after the real collect; PFTBackupwatchStale (`up 0`) [FIRING] 14:56:10Z, [RESOLVED] 14:57:10Z. ALERTS `query_range` pending -> firing for all 6 alert/host pairs; **operator topics 0 messages** (2 topics read back); real check OK, integrity PASS both, nodes full at the end. The drill silence was left to run out by the runner while another series was pending; it was expired by hand after Prometheus showed only the pipeline watchdog (not in the log) |

## Not covered

- The ledger database (`postfiatd-data` volume): pft-backup does not save it by design (a node re-syncs), so
  backupwatch does not check it either.
- Secrets that pft-backup strips by default (`[node_seed]`, ntfy env): `../keyescrow` escrows those.
- Drill limits (`drill/alert-run.sh`): the thresholds are lowered in the drill conf (`MAX_AGE_H 1`, `FAIL_AGE_H 2`,
  `DRIFT_GRACE_H 0`) so the real 4-5 h old archive reads stale and drift is overdue at once; the corruption and drift
  are made on tmpfs COPIES, and pft-backupwatch.timer is stopped on both hosts for the run, so the textfiles are the
  only real thing the drill writes. PFTBackupwatchStale was exercised live through its `up == 0` branch on the
  validator only; its age branch (collect older than 45 min) and the sentry side are covered by the promtool tests,
  not by the live drill.
