# audittrail/ logs (2026-10-26, Ubuntu 22.04.5 LTS on both hosts)

Every run is kept, including the failed ones, in the order they ran. "build" = sha256 prefix of the
`pft-audittrail.sh` the run used (printed in each log header). The final build is `0ddb08ce4075`; it differs from
`451983cd8ebd` (used by most drills) only by the `report` fix for path-less events (unit-tests.log).

| File | What |
|---|---|
| `unit-tests.log` | **final:** shellcheck (0.8.0) clean over every audittrail script and the test suite, then `tests/run-tests.sh` against the final build `0ddb08ce4075`: **52/52**, exit 0 |
| `unit-tests-old-vs-fixed-4-report.log` | the suite against the previous build `451983cd8ebd`: 51 passed / 1 failed (the new path-less `report` test), then the fixed build 52/52 (before a cosmetic edit to one stub line: its timestamp now says UTC)
| `unit-tests-old-vs-fixed-1-audit-yes.log` | old build `3d1330` 36/44 vs fixed 44/44: the `Audit=yes` finding (below) |
| `unit-tests-old-vs-fixed-2-rollback.log` | old build `6939f45` 45/47 vs fixed 47/47: the `${R:?}` rollback abort |
| `unit-tests-old-vs-fixed-3-keychange.log` | old build `a7a5d40` 47/51 vs fixed `451983cd` 51/51 (x5): the FSS key-change fix |
| `sentry-integrity-accept-1-auditd.log` | pft-integrity after installing the auditd package on the sentry -> accept -> PASS |
| `sentry-live-apply-run1.log` | **FAILED run.** sentry before `check` FAIL exit 1 (expected) -> apply -> `check` FAIL exit 1: `enabled=0`. journald's restart (to start sealing) switched kernel auditing off, because `Audit=` defaults to `no` on systemd 249. Also a sealed file reported FAIL without a key. Both fixed |
| `sentry-live-apply.log` | sentry, fixed build: before `check` FAIL exit 1 -> apply -> `check` PASS exit 0 (36 rules) |
| `sentry-integrity-accept-2-apply.log` | pft-integrity after apply on the sentry -> accept -> PASS |
| `sentry-drill-tamper-run1.log` | **FAILED run** (old drill, one key): 3 archived files FAIL with the current key. Investigation in `sentry-sealed-files-vs-keys.log` |
| `sentry-sealed-files-vs-keys.log` | each sentry sealed file against each off-host key: every file verifies with exactly one key, except the file `...693d8...` (03:29:24-03:33:03Z) which fails with **every** key: sealed under two keys by a key change (journald appended to an active file sealed under the old key). This led to the key-change fix. That file stays unverifiable; its keys are kept |
| `sentry-drill-rollback-run1.log` | **FAILED run** 6/9: `rollback` aborted on `${R:?}` (empty root prefix) and the journald restart left auditing disabled. Fixed |
| `sentry-drill-rollback-run2.log` | rollback drill on the `${R:?}` fix, 9/9; this run's rollback + re-apply is what produced the two-key file above |
| `sentry-integrity-accept-3-reapply.log` | key handed off-host + pft-integrity accept after the re-apply |
| `sentry-drill-rollback-run3.log` | **FAILED check** 9/10 on the key-change fix: the fix worked, but the drill's new checker was wrong (journald always logs the Runtime Journal line before the flush). Checker tested against real lines, then: |
| `sentry-drill-rollback.log` | **rollback-and-re-apply drill, final: 10/10.** check PASS -> rollback (`--yes` required) -> rules/drop-in/key/state removed, auditing still enabled, journald back on `/var/log/journal` with an unsealed file, sealed active file archived -> `check` exit 1 -> re-apply -> `check` PASS |
| `sentry-drill-tamper-run2.log` | **FAILED run** 6/7 (key history): a copy of the ACTIVE `system.journal` tore while journald was writing. The drill now retries the copy and prints every retry |
| `sentry-drill-tamper-run3.log` | 7/7 (the retry path was not needed in this run) |
| `validator-live-apply.log` | validator: dry-run diff, before `check` FAIL exit 1 (7) -> apply -> `check` PASS (48 rules), no node restart |
| `validator-integrity.log` | validator pft-integrity PASS 54 after apply (the tool's files are not baseline items; nothing to accept) |
| `validator-drill-tamper-run1.log` | **FAILED run** 6/7, verifier = the sentry side: torn first copy of the active file (no retry in phase 1 yet), and the flip check passed vacuously ("Failed to open files"). Both fixed |
| `validator-drill-tamper.log` | **tamper drills 1+2 on the validator: 7/7.** Canary write -> `ausearch -k pft-canary` event with auid (`<user>`), counted by `report`; sealed files verified off-host with the key that never leaves the verifier; byte-flipped COPY -> `journalctl --verify` FAIL (corruption at the flipped offset); live files PASS |
| `sentry-drill-tamper.log` | **tamper drills 1+2 on the sentry: 7/7**, with the full key history (every archive PASS with its own key; first copy of the active file tore, copy 2 PASS) |
| `sentry-drill-immutable-run1.log` | **FAILED check** 8/9: `apply --immutable` (-e 2) PASS, `check` PASS (expects 2), `auditctl -D` refused (exit 255), but `auditctl -W` prints "immutable mode, no rule changes allowed" and **exits 0**, so the checker read a correct refusal as FAIL |
| `sentry-drill-immutable.log` | **tamper drill 3, final: 7/7** (`--already-immutable`): -D and -W refused, judged by kernel state (36 rules still loaded, the canary watch still loaded, enabled 2). The sentry was left immutable. `rollback` exiting 2 under `-e 2` is covered by the unit tests only; it was not run live, because it would also remove the journald drop-in and FSS key on the sentry |
| `sentry-check-report-run1.log` | sentry `check` PASS + `report`: the `pft-units` row shows an empty object `" (3)"` (install's `fchmod`, no path). In this log I echoed "check without --immutable must FAIL"; that expectation was wrong: `check` takes the expected `enabled` value from the installed immutable rules file, not from a flag, so PASS is correct |
| `validator-check-report.log` | validator, final build: `check` PASS, `report --since today` (auids hashed, pft-agent objects `<redacted>`, the new binary install shown as `(no path: changed-file-attributes-of)`) |
| `sentry-check-report.log` | the same on the sentry, final build |
| `validator-drill-drift.log` | **live ruleset drift**: `auditctl -W` drops the `/etc/localtime` watch -> `check` exit 1, names the missing rule -> `CONFIG_CHANGE op=remove_rule key=pft-time` audited -> `augenrules --load` -> `check` PASS. 7/7. (The drill counts `-k pft-` lines, 38; `check` counts all 48 rules incl. `-F key=` syscall rules) |

Not published: two read-only exploration logs and three investigation logs (raw journald/audit output that
contains addresses and the host name). Their findings are described above.

Redactions (nothing else changed): machine-id -> `<machine-id>`; local-time timestamps (journalctl `Validated
from`, `Head:`/`Tail:`, ausearch `msg=audit(...)`) -> `<local-time-redacted>`, remaining timezone name -> `<tz>`.
The drill scripts themselves print the login user as `<user>` and never print secret paths or key contents
(keys are identified by a sha256 prefix only).
