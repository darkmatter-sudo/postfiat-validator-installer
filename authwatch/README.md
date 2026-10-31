# authwatch: SSH/sudo authentication monitoring for a validator and its sentry

`pft-authwatch` reads the sshd and sudo entries of the systemd journal every minute and turns them into
Prometheus counters: accepted logins split by **key class** (the key's fingerprint is in a local allowlist or
not), failed attempts by reason, refused algorithm negotiations and sudo results. Three alerts go with it:
a login with a key that is not allowlisted, a burst of failed attempts, and a collector that stopped.

Before this, nothing on the two hosts looked at logins. `audit/` and `sshcrypto/` check how sshd is configured,
not who actually logs in. A leaked admin key, or a key someone quietly added to `authorized_keys`, would have
gone unnoticed.

**Privacy.** User names, addresses and fingerprints stay in the journal and the allowlist. The textfile and the
state file only hold counts and timestamps, and the only labels are `host`, `method`, `key_class`, `reason`,
`kind` and `result` (tested in `tests/run-tests.sh` section 6). A fingerprint is compared with the allowlist
and then dropped.

## Files

| File | Installed to | Role |
|---|---|---|
| `pft-authwatch.sh` | `/usr/local/bin/pft-authwatch` | `collect`, `pull`, `allow`, `scan`, `status`, `validate`, `version` |
| `authwatch_parse.py` | `/usr/local/lib/pft-authwatch/authwatch_parse.py` | journal JSON -> counters, state file, textfile (Python 3 stdlib) |
| `systemd/pft-authwatch.{service,timer}` | `/etc/systemd/system/` | collection every minute at :25, sandboxed (both hosts) |
| `systemd/pft-authwatch-pull.{service,timer}` | `/etc/systemd/system/` | validator: copies the sentry's textfile every minute at :50 |
| `install.sh` | - | idempotent install / `--pull` / `--uninstall` |
| `pft-authwatch.env.example` | `/etc/pft-authwatch.env` | `HOST_LABEL`, paths, `PULL_SSH` (root-owned, 0600) |
| `../alerts/authwatch.rules.yml`, `../alerts/authwatch.tests.yml` | `/etc/pft-alerts/` | 3 alert rules + promtool tests |
| `tests/run-tests.sh` | - | offline suite: stub journalctl/ssh/ssh-keygen, real (redacted) fixtures |
| `tests/make_fixtures.py`, `tests/fixtures/journal-{validator,sentry}.jsonl` | - | fixture capture + redaction from the real journals |
| `tests/mutate.py` | - | mutation controls for the script, the parser and the rules |
| `logs/` | - | redacted logs of every recorded run (table below) |

## How it counts

`collect` runs `journalctl -o json SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sudo --after-cursor <saved cursor>`
(under `JOURNAL_TIMEOUT`, with stderr kept out of the data), so every entry is read once. The parser adds the
entries to the counters in `/var/lib/pft-authwatch/state-<host>.json`, stores the new cursor and writes the
state and the textfile, each through a temp file and a rename. If a run dies half way, the next run reads again
from the cursor that was last written: nothing is counted twice and nothing is lost (test section 4). The first
run only stores the journal tail as its cursor, so history before the install is not replayed.

One event is counted per connection attempt. The companion lines of the same attempt are deliberately skipped:

| Journal line (sshd, LogLevel INFO) | Counter |
|---|---|
| `Accepted publickey for U from A port P ssh2: ED25519 SHA256:F` | `ssh_accepted_total{method="publickey",key_class="allowlisted"\|"unknown"}` |
| `Accepted password/keyboard-interactive/... for U ...` | `ssh_accepted_total{method="password"\|"other",key_class="none"}` |
| `Invalid user U from A port P` | `ssh_failed_total{reason="invalid_user"}` (its `Connection closed by invalid user` / `Disconnected from invalid user` lines are not counted) |
| `Connection closed by / Connection reset by / Disconnected from authenticating user U A port P [preauth]` | `ssh_failed_total{reason="preauth_abort"}` (a real account name, no key accepted) |
| `error: maximum authentication attempts exceeded for ...` | `ssh_failed_total{reason="max_auth"}` |
| `Failed password / publickey / ... for ...` | `ssh_failed_total{reason="failed_password"\|"failed_publickey"\|"failed_other"}` |
| `Unable to negotiate with A port P: no matching cipher/MAC/key exchange method/host key type found` | `ssh_negotiation_failed_total{kind=...}` (not a failed login) |
| sudo `U : [N incorrect password attempts ;] TTY=... ; PWD=... ; USER=... ; COMMAND=...` | `sudo_total{result="ok"\|"auth_failure"}` |
| sudo `U : user NOT in sudoers / command not allowed ; ...` | `sudo_total{result="denied"}` |

With `PasswordAuthentication no`, OpenSSH 8.9 logs a rejected key at INFO only as the `authenticating user ...
[preauth]` close line. That is why `preauth_abort` is a failure reason.

Metrics (`pft_authwatch_*{host="..."}`): `up`, `collect_timestamp_seconds`, `ssh_accepted_total`,
`ssh_failed_total`, `ssh_negotiation_failed_total`, `sudo_total`, `journal_entries_total`,
`journal_unmatched_total`, `last_unknown_login_timestamp_seconds`, `last_failed_timestamp_seconds`,
`allowlist_entries`, `info{version}`.

## Install

```sh
# validator
sudo authwatch/install.sh                 # HOST_LABEL=validator, imports authorized_keys fingerprints, timer on
# sentry
sudo authwatch/install.sh --host sentry
# validator, after adding PULL_SSH to /etc/pft-authwatch.env (same form as /etc/pft-statewatch.env)
sudo authwatch/install.sh --pull
# alert rules: ../alerts/prometheus.yml lists /etc/pft-alerts/authwatch.rules.yml; reload Prometheus
sudo pft-integrity accept --reason "pft-authwatch installed"
```

`install.sh` imports the fingerprint of every key in `/root/.ssh/authorized_keys` and
`/home/*/.ssh/authorized_keys`, the keys that are allowed today. Later keys are added on purpose:

```sh
sudo pft-authwatch allow add SHA256:<43 chars> "laptop 2026-11"
sudo pft-authwatch allow import /home/<user>/.ssh/authorized_keys
sudo pft-authwatch allow remove SHA256:<43 chars>
sudo pft-authwatch allow count
sudo pft-authwatch status                 # timer, allowlist size, counters (no identities)
sudo pft-authwatch scan --since -24h      # one-off totals + largest failed count per 10 min
```

The sentry runs no Prometheus or Alertmanager. Its file is collected on the sentry and pulled to the
validator's textfile dir, and every `host="sentry"` alert is evaluated on the validator.

## Alerts

| Alert | Expression | Why this threshold |
|---|---|---|
| `PFTAuthUnknownKeyLogin` (critical) | `sum by (host) (increase(pft_authwatch_ssh_accepted_total{key_class!="allowlisted"}[15m])) > 0` | any login with a key outside the allowlist, or without a key, pages at the next evaluation |
| `PFTAuthFailedBurst` (warning) | `sum by (host) (increase(pft_authwatch_ssh_failed_total[10m])) > 400` | above the highest 10-min count of the baseline below (337) |
| `PFTAuthwatchStale` (warning, for 2m) | `time() - pft_authwatch_collect_timestamp_seconds > 300` | the collector (or, for the sentry, the pull) stopped; logins would go unseen |

`../alerts/authwatch.tests.yml` holds the promtool tests. They cover firing, resolving, summing over series,
counter resets, the background-level non-firing case and per-host staleness.

## Baseline and thresholds

`pft-authwatch scan` over the whole retained journal of each host, empty allowlist (`logs/04-baseline-scan.log`):

| | validator | sentry |
|---|---|---|
| journal range (UTC) | 2026-10-29T17:40Z - 2026-10-31T04:38Z | 2026-10-29T09:59Z - 2026-10-31T04:39Z |
| sshd/sudo entries | 493085 | 148815 |
| failed attempts (invalid_user / preauth_abort / max_auth) | 4049 (1799 / 2213 / 37) | 3960 (2262 / 1698 / 0) |
| 10-min windows with failures | 210 | 253 |
| largest failed count in one 10-min window (p99) | 199 (99) | 337 (90) |
| refused negotiations | 754 | 632 |
| accepted logins | 21 | 23154 (mostly the validator's 1-minute pulls) |

Internet background is a few hundred failed attempts per hour on each host, and none of them succeed. The burst
threshold sits above the largest 10-minute count seen on either host, so normal scanning does not page.

## Tests

```sh
bash authwatch/tests/run-tests.sh          # offline, no root
promtool test rules alerts/authwatch.tests.yml   # or: DOCKER="sudo docker" alerts/run-stack.sh check
python3 -u authwatch/tests/mutate.py       # every mutant must be CAUGHT
shellcheck authwatch/*.sh authwatch/tests/*.sh
```

The fixtures are real sshd/sudo journal entries from both hosts, up to 3 per message shape. They are redacted
deterministically by `tests/make_fixtures.py`: RFC 5737 / 2001:db8 addresses, `userNN` names, synthetic
fingerprints and cursors, and `/usr/bin/true` for sudo commands. The tests compare the parser's counts with
independent `grep` counts over the same fixture messages.

## Logs

| Log | What |
|---|---|
| `01-fixture-capture.log` | first fixture capture (superseded by 02: sudo `(command continued)` lines were not redacted yet) |
| `02-fixture-capture.log` | fixture capture on both hosts, line counts and sha256 of the committed fixtures |
| `04-baseline-scan.log` | baseline scan of both journals (table above). Run 03 was the same scan, but it printed the journal range in the host's local time zone; it is not published |
