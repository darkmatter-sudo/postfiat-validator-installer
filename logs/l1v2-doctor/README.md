# postfiatl1v2 validator-doctor runbook commands: raw logs

Upstream issue: https://github.com/postfiatorg/postfiatl1v2/issues/279
PR: https://github.com/postfiatorg/postfiatl1v2/pull/281 (head cd67df7b37ced37922dfdef16c7a65ff5b1153ca, base main b7506921e64298f8156813bfbf1af7b900ffa9c7)

Ubuntu 22.04 (Python 3.10.12), shellcheck 0.8.0, ruff 0.17.1, docs checks in a throwaway `python:3.12-slim` container
with the repo's hash-pinned `requirements-docs.txt`. No cargo on this box. Every build-ordering test uses a stub `cargo`
on `PATH` that records it was started and sleeps 5 s, so no real build is needed. The stubs live under the gitignored
`target/`, because `/tmp` is mounted `noexec` here. The home directory is shown as `~` in every log; nothing else is changed.

| Log | What it shows |
|---|---|
| 01-main-repro.log | main b7506921: the runbook doctor lines with line numbers, `parse_unit_map` (226-233), the build (975-977) before the mapping parse (997-999), the shipped `postfiat-validator-N(-rpc).service` units. Then the runbook command run verbatim: exit 1 `unit mapping must be node_id=unit` after 5.1 s, with cargo started. With `--no-build` it still exits 1. `parse_unit_map` accepts `=unit` and `validator-0=`. The RPC template expands to `postfiat-rpc-N.service` |
| 02-branch.log | the PR branch: diff vs main, sha256 of the changed scripts and fixtures. **A** fail-on-main: main + only the new test and fixtures = 13 failures, exit 1. **B** branch = 0 failures. **C** each bad fixture as a path exits 1, the good one 0. **D** malformed mapping 85-147 ms over 5 runs, cargo never started. **E** ruff clean on the new script; the doctor's pre-existing ruff findings are identical on main and branch; no shell files changed; the stub text is shellcheck clean. **F** `public-doc-links`, `test-public-doc-links`, `mkdocs build --strict`, `docs-site-redaction-check` pass; tree clean |
| 03-fresh-clone.log | anonymous fresh clone of the fork at the PR head (checked against `gh pr view 281`), sha256 equal to 02, same A-F with fail-on-main against the then-current upstream main d334bbe9 (only a handoff doc added since the base): 13 failures on main, 0 at the head, controls 5x exit 1 + good 0, 84-94 ms with no cargo, lint and docs pass |
| 04-continuation-probe.log | verification follow-up, recorded after submission: anonymous fresh clones of the PR head cd67df7b and of this repo (for `probe-continuation.py`); the runbook fence `docs/runbooks/validator-doctor.md:23-28` and `fenced_commands()` (test lines 93-122) with line numbers; the probe prints the one joined command `fenced_commands()` returns for that fence and its argv (no problems), then the same with a no-join mutant: 4 separate lines, 0 doctor invocations found in the fence, 5 of 6 fixture expectations fail (all 5 negative controls see 0 invocations), so the fixtures catch a missing join. The full test at the head still ends `failures=0`. sha256 of the test equals 03 |
| probe-continuation.py | the probe used by 04 (read-only; imports the test script and swaps `fenced_commands` for the mutant only in-process) |
| record.sh | the recorder that produced 01-03 (one command per line, `exit=` after each). Before 03 its header line got a branch for a cwd that is not a git repo; nothing else changed |

`exit=1` appears only where the log runs main on purpose (01 repro, A in 02 and 03). The `FAIL` lines in 04 are the no-join mutant being caught, on purpose.
