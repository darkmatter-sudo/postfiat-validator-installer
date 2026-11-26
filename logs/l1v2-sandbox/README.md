# postfiatl1v2 validator-host sandbox drop-ins: raw logs

Upstream issue: https://github.com/postfiatorg/postfiatl1v2/issues/268
PR: https://github.com/postfiatorg/postfiatl1v2/pull/269 (head 7203a70f0449e760a9d5b8ea1bf75972d9a52356, base main 615d3d37e5c3d911454dc6533a880855e02a6ecf)

Ubuntu 22.04 (glibc 2.35), systemd 249 (249.11-0ubuntu3.23), kernel 5.15, shellcheck 0.8.0, Python 3.10.12.
The home directory is shown as `~` in every log (also inside quoted commands, where the real run had the full path); nothing else is changed.

Release binary: `postfiat-node` from release `cobalt-operator-v2-20260824`, sha256
`e036033d437d85c4f60fc8e6689a771fdda01dd2ce88456571e6c9092faf4caf` (matches the release's
`cobalt-operator-assets-SHA256SUMS.txt`, both in the logs). It links against GLIBC_2.39, so the transient units start it
through the glibc 2.39 loader and libraries copied from a local Ubuntu 24.04 image (`SANDBOX_NODE_LIBDIR`; loader sha256 in the logs).
All live tests use throwaway transient units (`postfiat-sbxtest-<pid>-*`, user `nobody`) over a throwaway data dir; no installed unit is touched.

| Log | What it shows |
|---|---|
| 01-branch.log | the PR branch: diff vs main, file sha256, release hash, shellcheck clean, static part (29/0), static + live part (85/0: per service before/after replies or readiness, install.sh without restart, `systemctl show` of every directive, Seccomp_filters 16 -> 34, `systemd-analyze security` 5.0 -> 1.8 for RPC and transport, uninstall back to 5.0, one probe per directive with/without), `--negative-controls` (3/3 rejected: AF_INET blocked, ProtectProc missing, wrong hash), no leftover units/drop-ins/data dirs, docs-site-redaction-check, public-doc-links, test-public-doc-links, mkdocs --strict |
| 02-fresh-clone.log | fresh clone of the fork at the PR head (checked against `gh pr view 269`), same tests: 29/0, 85/0, controls 3/3, nothing left behind |
| 03-mutants.log | `mutants.py` (this folder) on the fresh clone: unmutated baseline 29/0, then 10 single-snippet mutants of the guards in `install.sh` (restart, dry-run, rollback, LoadState, unit names, file mode, value mapping, uninstall, daemon-reload), each applied once and shown as a diff: 10 caught |
| record.sh | the recorder that produced 01-03 (one command per line, `exit=` after each) |
