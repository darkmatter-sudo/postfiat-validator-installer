# postfiatl1v2 logrotate overlap: raw logs

Upstream issue: https://github.com/postfiatorg/postfiatl1v2/issues/259
PR: https://github.com/postfiatorg/postfiatl1v2/pull/260 (head e941096678b92323ada2169de14c645e54deeb05, base main 615d3d37e5c3d911454dc6533a880855e02a6ecf)

Ubuntu 22.04.5, logrotate 3.19.0, shellcheck 0.8.0. Home directory shown as `~`.

| Log | What it shows |
|---|---|
| 01-repro-main.log | issue reproduction on main in a temp tree: 6 `duplicate log entry` lines, 3 rule files skipped, logrotate rc=1; install.sh lines 19-20 and its shellcheck output on main (SC2148 error) |
| 03-newtest-on-main.log | `scripts/test-validator-host-logrotate` from the PR run against a main worktree: RESULT: FAIL (duplicate entries after install.sh, rc=2 from `sed`) |
| 04-branch-tests.log | the PR checkout: sha256 of the files, new test RESULT: PASS, shellcheck of 3 files clean, `scripts/test-postfiat-logrotate` with and without a `postfiat` user. This checkout was made with umask 002, so as mapped root logrotate ignores the group-writable example (`Handling 0 logs`); 05 repeats it with umask 022. |
| 05-fresh-clone.log | fresh clone of the PR head (umask 022): new test PASS, shellcheck clean, `scripts/test-postfiat-logrotate` rc=0 (`Handling 1 logs`), and the same new test against a fresh clone of main: RESULT: FAIL |
| 06-restore-hashes.log | `06-restore-hashes.sh` (this folder) on a fresh clone of the PR head: sha256 of every `/etc/logrotate.d` file before install.sh, at each of its logrotate dry-run calls, and after it refuses, for generic+fleet (pre-check refusal), generic and logonly+fleet (`refusing: ... restored` path; fleet rules edited, then restored byte for byte); control with the restore loop removed: RESULT: FAIL |
