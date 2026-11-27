# healthcheck: continuous health check for the validator guide

Section "9. Verify Node Health" of the official validator guide (`postfiatorg/postfiatorg.github.io`,
`content/validator-setup.md` and the two `static/agents/validator-setup.*` copies) only has one-off checks. The upstream
change adds a "Continuous health check" subsection after it, identical in all three copies:

- a read-only `/usr/local/bin/postfiat-healthcheck` (POSIX sh + `python3`) that asks the node for `server_info` over the
  loopback admin port (`docker exec postfiatd curl ... http://localhost:5005/`) and prints one
  `CHECK <name> OK|FAIL|UNKNOWN <detail>` line per check (`state`, `validated_ledger_age`, `peers`, `complete_ledgers`)
  and a `RESULT` line; exit `0` OK, `1` FAIL, `2` UNKNOWN; thresholds (`OK_STATES`, `MAX_LEDGER_AGE`, `MIN_PEERS`,
  `MIN_LEDGERS`, `RPC_TIMEOUT`) and `CONTAINER` can be overridden in `/etc/default/postfiat-healthcheck`;
- a oneshot `postfiat-healthcheck.service` and a `postfiat-healthcheck.timer` (`OnCalendar=*:0/5`, `Persistent=true`);
- commands to run it once and see failures, an optional `OnFailure=` alerting drop-in, and uninstall steps.

This folder holds the evidence tooling:

| File | What it does |
| --- | --- |
| `extract_healthcheck.py GUIDE OUTDIR` | cuts the subsection, its four blocks and the three files the install block writes out of one guide copy |
| `check-guide.sh GUIDE_REPO BASE HEAD OUTDIR` | diff touches exactly the 3 guide copies; every extracted part byte-identical in all 3 (cmp + sha256); shellcheck (`-s sh` for the script); `systemd-analyze verify` of service + timer in a private mount namespace (the extracted script bind-mounted over `/usr/local/bin`, nothing on the host changes) |
| `tests/test_healthcheck.py EXTRACT_DIR [--mutants]` | runs the extracted script unchanged with a `docker` shim first in `PATH` and a loopback mock RPC: 42 healthy, FAIL, UNKNOWN and override cases, each asserting the exit code and every CHECK/RESULT verdict, and that only `POST server_info` reached the mock; `--mutants` runs all cases against 22 mutants of the script |
| `sentry-proof.sh EXTRACT_DIR` | the live sequence on the sentry only (never the validator), see below |

Run (`sudo` needed for `check-guide.sh`; OUTDIR must be on an exec-capable filesystem):

```bash
git clone https://github.com/darkmatter-sudo/postfiatorg.github.io.git guide && git -C guide checkout <PR_SHA>
sudo bash healthcheck/check-guide.sh guide <PR_SHA>~1 <PR_SHA> out
python3 -I healthcheck/tests/test_healthcheck.py out/copy1 --mutants
```

## Sentry live sequence

`sentry-proof.sh` runs from the validator and reaches the sentry over ssh. All steps run inside an Alertmanager silence
scoped to `host="sentry"` (the induced FAIL makes the unit fail on purpose); `pft-integrity` and `pft-schedaudit`
accept the new files and timer right after the install, and again after the scratch copy is removed.

1. install with the guide's install block, unchanged; the only host input is `/etc/default/postfiat-healthcheck` with
   `CONTAINER=postfiatd-sentry`, the override the guide documents; installed files byte-identical to the guide;
   `systemd-analyze verify` of the installed units
2. the guide's run-once block: `exit 0`, `RESULT OK`
3. wait for three timer-started runs, each `RESULT OK` and `Result=success`; `systemctl --failed` empty
4. `MIN_PEERS=1000` in the defaults file -> the service run fails with only `peers` FAIL, `Result=exit-code`, listed by
   `systemctl --failed`; the node keeps running (still `full`, container start time unchanged)
5. remove the override -> next run `RESULT OK`, `systemctl --failed` empty again
6. uninstall on a scratch copy: the install block with `postfiat-healthcheck` renamed `scratch-healthcheck`, plus the
   guide's alert drop-in and a defaults file, then the guide's uninstall block with the same rename: every scratch file
   and unit gone, the real install untouched
7. end: node `full`, never restarted; integrity PASS; schedaudit 0 unexpected; jobwatch lists the timer

The health check stays installed on the sentry afterwards.

## Results (2026-11-27)

Upstream: issue [postfiatorg/postfiatorg.github.io#60](https://github.com/postfiatorg/postfiatorg.github.io/issues/60),
PR [#61](https://github.com/postfiatorg/postfiatorg.github.io/pull/61), head `7685c56a7dfa2c2ff52d80ac8f2f513645d3414d`
(2 commits on upstream main `8da236f68fb1dbc050fe6463c427f6e0bb5d5d1c`), 3 files, +486/-0. Logs 01-02 ran the tooling
at `0502968873646d6b1fe1826c7d5e2592d501b4e2`, log 03 at `9e11641094d85d77695ead2c09c54466e2477703` (only
`sentry-proof.sh` differs).

| Log | What | Result lines |
| --- | --- | --- |
| `logs/01-guide-static.log` | fresh anonymous clones; full diff; check-guide | 5-9 heads and the 2 PR commits; 535/539 diff = 3 files, +486; 551/569/587 subsection sha256 `d644ad5c...` in all copies; 595-602 8 parts identical; 605-608 shellcheck; 613 systemd-analyze; 615-616 0 failed, exit 0 |
| `logs/02-tests.log` | ruff + shellcheck; 42 mock-RPC cases; 22 mutants | 6 lint clean; 8 shim self-check; 235 `42 passed, 0 failed`; 237-258 every mutant KILLED; 259 `22/22 killed`; 260-261 PASS, exit 0 |
| `logs/03-sentry-live.log` | sentry live sequence (`RUNS=3`) | 35 nothing installed (incl. stamps); 50/63 install exit 0 + byte-identical; 74 systemd-analyze; 103 run now OK; 137-158 timer runs 10:20:01, 10:25:00, 10:30:01 RESULT OK; 162-181 3 runs, no failure, `--failed` empty; 194-220 peers-only FAIL, exit-code 1, listed by `--failed`, node still full and not restarted; 239-245 recovered; 309-319 scratch uninstall removed every file incl. the timer stamp, real install untouched; 333-361 end state; 367 PASS |

The health check stays installed on the sentry.

History: dry run 1 (unpublished) found that the guide's first run-once command (`sudo /usr/local/bin/postfiat-healthcheck`)
ignores `/etc/default/postfiat-healthcheck`; the guide runs it through the service instead. Recorded run 1 (guide
`4746f94`) passed but showed the uninstall left systemd's `Persistent=` stamp file, so the PR gained commit `7685c56`
and the harness checks stamps; one re-run counted the run-once invocation as a timer run (1 s journal cut-off, fixed in
`9e11641`). All logs above are from the final head.
