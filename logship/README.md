# pft-logship: cross-host journal forwarding

`pft-audittrail` makes a host's journal tamper-evident, but the evidence still lives on the host it describes:
whoever becomes root there can delete or truncate it. `pft-logship` sends each host's systemd journal to the
other host of the pair (validator <-> sentry) within seconds, so deleting the local copy no longer deletes the
evidence. It uses the distro's own `systemd-journal-upload` (sender) and `systemd-journal-remote` (receiver,
TCP 19532), with mutual TLS from a private two-host CA. Neither node is restarted at any step.

What is forwarded: the whole system journal, so auditd events, pft-audittrail/journald entries, the add-on units
and the **postfiatd container logs**. Both containers use Docker's `json-file` log driver, so their logs are not
in journald at all. Switching the driver means recreating the container, which this add-on never does. Instead
`pft-logship-dockerlog@NAME` follows `docker logs` and writes each line into the journal under
`SyslogIdentifier=NAME`. It resumes from a saved timestamp, with no duplicates and no gaps.

## Files

| File | What it is |
|------|------------|
| `pft-logship.sh` | `plan` / `apply` / `sign` / `check` / `lag` / `rollback` (`--dry-run` for apply/rollback) |
| `pft-logship-dockerlog.py` | the docker json-file -> journal bridge (state: last timestamp + lines seen at it) |
| `check.sh` | offline checks: shellcheck, ruff, both stub suites, mutation controls M1-M5, promtool |
| `tests/run-tests.sh`, `tests/test-dockerlog.sh` | stub-based unit tests (fake journalctl/systemctl/curl/openssl/docker) with captured real fixtures |
| `drill-marker.sh`, `drill-delete.sh`, `drill-badcert.sh`, `drill-outage.sh` | the four live drills |
| `lag-sample.sh` | 1h forwarding-lag sampler (median / p95 / max per host) |
| `../alerts/logship.rules.yml`, `../alerts/logship.tests.yml` | the `PFTLogshipBroken` alert rule and its promtool tests |

## Install (sentry first)

```bash
# /etc/pft-logship.env on each host (root, 0600): SELF_NAME/PEER_NAME labels, SELF_ADDR/PEER_ADDR, CA_HERE=1 on one
# host, DOCKER_CONTAINERS=postfiatd (validator) or postfiatd-sentry (sentry). Addresses stay out of the repo.
bash logship/pft-logship.sh plan                     # read-only: drop-ins, timers, UFW rule, steps
sudo bash logship/pft-logship.sh apply --dry-run     # every action, nothing changed
sudo bash logship/pft-logship.sh apply               # makes this host's key + CSR, exits 4 until a cert exists
sudo pft-logship sign host.csr > host.crt            # on the CA host, for both CSRs (only CSRs/certs travel)
sudo bash logship/pft-logship.sh apply               # writes config, UFW rule, units, timers; starts them
sudo pft-integrity accept --reason "pft-logship apply"
sudo pft-logship check                               # exit 0 = both directions OK
```

`apply` installs `systemd-journal-remote`. Each host creates its own key under `umask 077` (`/etc/pft-logship/tls`,
key 0640 root:systemd-journal-remote), so no key ever leaves its host or enters the repo. `journal-upload` runs as a
DynamicUser and gets the key as a systemd credential. `apply` also adds one UFW rule that allows TCP 19532 from the
peer address only, `pft-logship-vacuum.timer` (hourly `journalctl --vacuum-size=STORE_CAP` on the received files,
because journal-remote in systemd 249 has no `MaxUse=`), the bridge units, and `pft-logship-check.timer`.
`rollback` removes all of that. It keeps the received journals, and it keeps the keys unless you pass `--purge-keys`.

## Check, metrics and alert

`pft-logship check` exits 1 if any of these fails: a unit not active, a bridge not active or its newest entry older
than `MAX_LAG`, the cert not chaining to the pair CA or not matching the key, no mutual-TLS handshake with the
peer, a send lag above `MAX_LAG` (120 s), a cursor stalled (unchanged for `MAX_LAG` while the local journal is
ahead of it), or a newest entry received from the peer older than `MAX_LAG`. The send lag is the newest local
journal entry minus the time of the last uploaded entry, taken from the `t=` field of journal-upload's saved cursor.

`pft-logship-check.timer` runs `check --textfile` every minute. That writes, atomically, `pft_logship_up` (1 only if
every check passed) and `pft_logship_lag_seconds` into the pft exporter's textfile directory.

### Alert

`PFTLogshipBroken` (warning, `for: 5m`) fires when any of these holds:

- `pft_logship_up == 0`
- `pft_logship_lag_seconds > 120`
- the metrics file is older than 300 s (the check timer stopped)
- the metric is missing altogether

The rule is in `alerts/logship.rules.yml` and is listed in `alerts/prometheus.yml`. It has 7 promtool test cases:
a healthy presence control, failure, a 3-minute blip that stays quiet, lag, lag exactly at the limit, stale, and
missing. Mutant M5 drops the stale branch, and the suite must catch it. To fix the alert, run
`sudo pft-logship check` on the host and read which line failed. After `rollback`, remove the rule from
`rule_files`, otherwise the "missing" branch fires.

## Results (published logs in [`../logs/logship/`](../logs/logship/))

| Claim | Evidence |
|-------|----------|
| Unit tests 56/56, bridge tests 16/16, shellcheck + ruff clean, M1-M5 each caught by exactly its test, promtool check + test PASS | `check-8.log` (also shellchecks the drill scripts; check-6 failed on two test regexes of mine, published; check-7 PASS) |
| FAIL before apply on both hosts (no cursor) | `plan-sentry-1.log`, `plan-validator-1.log` |
| Apply sentry first, then validator; check PASS both directions | `apply1-*`, `sign.log`, `apply2-*`, `check-live-1.log`, `apply3-*-check-timer.log` |
| Rule loaded live, metrics fresh, no alert | `alert-rule-live-1.log` |
| Marker arrives on the peer in 4.4 s (sentry -> validator) and 4.8 s (validator -> sentry), including ssh polling | `drill-marker-2.log` |
| Local archived journal file with the marker removed: local query 0, peer copy 1, restored byte-identical (sha256), both directions | `drill-delete-sentry-1.log`, `drill-delete-validator-1.log` |
| No client cert and a rogue-CA cert with the same CN: HTTP 401, nothing stored; real cert: 202, stored | `drill-badcert-1-FAIL-get-probe.log`, `drill-badcert-2..4.log` |
| 1h lag, 60 samples per host: validator median 0 s, p95 1 s, max 2 s; sentry median 0 s, p95 1 s, max 1 s | `lag-1h.log` |

Found while building, then fixed and verified:

- OpenSSL 3.0.2 `req -verify` exits 0 on a bad self-signature, so `sign` matches on "verify OK" (M1).
- `genpkey` under umask 022 left the key world-readable until `chmod`. It now runs under umask 077 (M3). The
  sentry's key was made by the old build, in a window of milliseconds, and is now 0640.
- `docker logs --since` reads every rotated json file first (19 s for 543 MB). A fresh bridge starts with
  `--tail 0` instead (`bridge-smoke-1-FAIL-8s-window.log` -> `bridge-smoke-2.log`).
- The first bad-cert probe used `GET /`. journal-remote completes the TLS handshake without a client cert and
  answers 406 to anyone, because it checks the client cert per request on `POST /upload`. So the drill now
  uploads. The same limit applies to `check`'s TLS probe: it proves the peer's server cert and the handshake.
  Client authentication is proven by the bad-cert drill.

## Threat model and limits

- **Root before catch-up.** Anything written in the seconds between a log line and its upload (median lag 0 s,
  p95 1 s here) can be removed by an attacker who already has root, before it leaves the host. During a peer outage
  that window is the whole outage: entries stay queued locally until the peer is back. `PFTLogshipBroken` fires
  after 5 minutes of that.
- **Peer compromise.** The peer holds a full copy of this host's journal (config paths, auditd events, node logs),
  so root on either host can read both journals. The pair CA key lives on one host. Whoever holds it can issue a
  client cert and upload forged entries under the other host's name. Received files sit in
  `/var/log/journal/remote` with `Seal=false`, so tamper-evidence for them comes from the sender's own FSS seal
  (pft-audittrail), not from the copy.
- **Clock skew.** Lag and the "newest received entry" age compare timestamps from both hosts. Both hosts were
  NTP-synchronized during the proof (`facts-1.log`). A large clock step on either host shows up as false lag or as a negative lag, which is clamped to 0. Check NTP
  before trusting a lag alert.
- **Cap.** Each sender gets `STORE_CAP` (2G) on the receiver. The vacuum timer removes the oldest archived files
  above it. The active file is never removed, so usage can go above the cap by up to one file
  (received files here are at most 104 MiB, `facts-1.log`). Older
  evidence ages out by design, so keep anything you need elsewhere.
- **Not covered:** logs that never reach journald or docker (for example files an attacker writes directly), and
  the bridge's resume delay after a restart (about 19 s while docker scans its rotated logs, below `MAX_LAG`).
