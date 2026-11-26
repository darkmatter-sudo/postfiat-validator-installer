# postfiatl1v2 rpc-events-report: raw logs

Upstream issue: https://github.com/postfiatorg/postfiatl1v2/issues/261
PR: https://github.com/postfiatorg/postfiatl1v2/pull/262 (head 4b9a8b6f9c7f87315f0a7d78a894be097a1caa2a, base main 615d3d37e5c3d911454dc6533a880855e02a6ecf)

Ubuntu 22.04 (glibc 2.35), Python 3.10.12, shellcheck 0.8.0, ruff 0.17.1, jq 1.6, logrotate 3.19.0.
The home directory is shown as `~` in every log (also inside quoted commands, where the real run had the full path).

Release binary for the real capture: `postfiat-node` from release `cobalt-operator-v2-20260824`,
sha256 `e036033d437d85c4f60fc8e6689a771fdda01dd2ce88456571e6c9092faf4caf` (GitHub asset digest and the
release's `cobalt-operator-assets-SHA256SUMS.txt`, both in the logs). It links against GLIBC_2.39, so it was
started through the glibc 2.39 loader, libc and libm copied from a local Ubuntu 24.04 image
(`RPC_EVENTS_NODE_LAUNCHER`); their sha256 are in the logs.

| Log | What it shows |
|---|---|
| 02-branch.log | the PR branch: file sha256, binary hash checks, shellcheck/ruff check/ruff format --check, `scripts/test-rpc-events-report` without the binary (107/0) and with it (123/0, real capture of 9 events, breach naming 127.0.0.1 + status), wrong-hash control refused, docs-site-redaction-check, public-doc-links, test-public-doc-links, mkdocs --strict, `bash -n` of the scripts/check list, `scripts/test-postfiat-logrotate` (informational: exits 1 here, its files are unchanged from main) |
| 03-fresh-clone.log | fresh clone of the fork, checkout of the PR head, same tests: 107/0 and 123/0, control refused |
| 04-mutants.log | `mutants.py` (this folder): unmutated baseline PASS, then 15 single-line mutants of the guards in `rpc-events-report`, each must apply once and make the suite fail: 15 caught |
| runner.sh | the script that produced 02-04 |
| 06-mutant-diff.log | `mutant-diff.sh` (this folder), for the verification request: fresh clone at the PR head, unmutated baseline 107/0, then the `inode ignored` and `rotated read from 0` mutants from `mutants.py` shown as `diff -u`, the FAIL lines of `scripts/test-rpc-events-report` against each mutated tool and its exit status (1), and the line-numbered assertions that report them |

Run 01 (unpublished) was superseded by 02: the runner's own `sed` took `smoke;` as a file name in the `bash -n` step; fixed in runner.sh, no repository change.
Run 05 (unpublished) was superseded by 06: same result, but its `diff -u` headers carried local file timestamps; 06 uses `--label`.
