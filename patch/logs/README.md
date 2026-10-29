# pft-patch run logs

Raw output of every recorded run, in order, including runs that were stopped or superseded (each says so in a
`STOPPED` / `NOTE` line appended at the time). Each log starts with its UTC start time and the commit it ran.

Redaction applied before publishing (nothing else changed): ntfy topics -> `<redacted>`, public IPv4 ->
`<redacted-ip>`, the agent's username -> `<user>`, its home directory -> `~`, host names -> `validator` / `sentry`,
boot ids -> first 8 hex chars, local-time syslog stamps -> `<local-time>`.

| run | what | result |
|---|---|---|
| 01 | read-only discovery, both hosts | 0 security updates pending on either host; sentry had a newer kernel in jammy-updates |
| 02 | read-only probes of the real apt/needrestart output formats (validator) | formats captured for the tests |
| 03 | build 1 tests + shellcheck @ 357f3a4 | 58/58, shellcheck 0 |
| 04 | build 1 mutants @ 357f3a4 | 24/24 caught |
| 05 | build 2 tests @ f24c8fe | 167/167; superseded by 07 (shellcheck -x could not follow `source=` paths from the repo root) |
| 06 | build 2 mutants @ f24c8fe | STOPPED, superseded |
| 07 | build 2 tests @ b1b53fd | 167/167, shellcheck 0 |
| 08 | build 2 mutants @ b1b53fd | STOPPED: a read-only live preflight found root cannot ssh to the sentry (SSH_AS fix) |
| 09 | build 2 tests @ d3660e6 | 170/170 |
| 10 | build 2 mutants @ d3660e6 | STOPPED, superseded by build 3 |
| 11 | build 3 tests @ 362969d | 193/193 |
| 12 | build 3 mutants @ 362969d | STOPPED, superseded by build 4 (found by drill A) |
| 13 | install + `policy apply` on both hosts @ 362969d | applied; status WARN (pending non-security updates) |
| 14 | validator integrity re-baseline after the install | PASS 87/87 |
| 15 | **drill A**: `--all`, injected sentry post-gate failure | sentry kernel installed + real reboot; injected FAIL at the sentry post-gate; validator UNTOUCHED; found the egress-retry gap (build 4) |
| 16 | build 4 tests @ 4e2563a (`16-suite` = full suite output) | 206/206 |
| 17 | build 4 mutants @ 4e2563a | no result: the process died with the drill B validator reboot (note in the log) |
| 18 | reinstall build 4 on both hosts | integrity: unit mtime only, accepted |
| 19 | **drill B**: `--all` both hosts, injected sentry reboot | sentry gated PASS; validator pulled a kernel -> exit 10, real local reboot at 02:58Z |
| 28 | the boot-time resume log of drill B (pft-patch-resume.service) | RESULT: PASS - validator patched, rebooted and gated |
| 20 | alertpath maintenance hold: tests + mutants (working tree) | 44/44; STOPPED (agent shell limit), superseded by 21 |
| 21 | alertpath hold @ 7c47394: tests + mutants | 44/44; 34/35 caught, **1 not applied** (M24 still targeted the old text) |
| 22 | build 5 tests @ ceaaeee | 215/215, shellcheck 0 |
| 23 | deploy pft-alertpath 7c47394 to the sentry | integrity FAIL on the new binary, accepted with reason, PASS |
| 24 | alertpath mutants after the M24 retarget | STOPPED: launched before the fix was committed |
| 27 | deploy pft-patch build 5 to both hosts @ 2625075 | both hosts `status` OK; integrity: unit mtime only, accepted, PASS |

Drill B found two gaps, both fixed afterwards: dockerd left pft-prometheus Exited (255) after the validator reboot and
the post-gate did not notice (build 5 containers check), and the sentry's alertpath monitor sent one STALE page to the
operator's topic at 02:59:17Z while the validator rebooted (alertpath 7c47394 holds state changes inside a pft-maint
window + 300 s).
