# token-modes: owner-only validator token files in the validator guide

Test kit and evidence for a docs-only PR to
[postfiatorg/postfiatorg.github.io](https://github.com/postfiatorg/postfiatorg.github.io). The PR changes sections 6
and 7 of the validator guide ("Set the Validator Domain and Capture Public Proof", "Inject the Validator Token into
`postfiatd.cfg`"). On main, three files that hold the `[validator_token]` block are created with the shell's default
mode (`644` under the usual `umask 022`), so any local user can read the token:

- `set-domain-output.txt` (written by `tee`),
- `postfiatd.cfg.new` on the host (written by `awk >` and `>>`),
- `/etc/postfiatd/postfiatd.cfg` inside the container (`docker cp` keeps the host file's `644`).

A re-run of sections 6-7 (new domain, rotated token) also leaves the host `postfiatd.cfg` copy with the token at `644`.
The PR:

- runs the writing commands of sections 6 and 7 in a `( umask 077 ... )` subshell, so new files are owner-only;
- adds `chmod 600` for `set-domain-output.txt`, `postfiatd.cfg` and `postfiatd.cfg.new`, which also fixes files an
  earlier run left at `644` (`tee` and `docker cp` keep or copy the existing mode);
- adds a read-only verifier block: mode and owner of each token-bearing host file and of the config inside the
  container; it prints `token file modes OK` only when all are `600` and owned by the operator (host) or root
  (container);
- adds a block that removes the two host config copies once `server_info` shows the new `pubkey_validator`, and lists
  both copies in "Keep these files secure and private".

The node still reads its config: the guide's compose file runs the container as `user: "0:0"`. Sections 5-7 are
byte-identical in `content/validator-setup.md`, `static/agents/validator-setup.md` and
`static/agents/validator-setup.txt`.

## Files

| file | what it does |
|---|---|
| `extract_token.py` | `extract_token.py OUTDIR GUIDE [GUIDE ...]`: cuts sections 5-7 out of the first guide copy, fails unless every other copy has byte-identical sections 5-7, and writes each bash block to a named file (`05-keys.sh` .. `07d-remove.sh`, `blocks.txt` = guide order). A marker line per block fixes its role; the verifier and removal blocks are optional, so the same tool reads main and the PR branch. |
| `token-test.sh` | `EXPECT=pass\|fail bash token-modes/token-test.sh GUIDE`: live test on the **sentry** in a throwaway compose project (steps S0-S10 in its header). It runs on the validator as the agent user and reaches the sentry with `ssh relay`. Exit 0 only if every harness check is ok and the mode verdict equals `EXPECT`. |
| `fresh-clone.sh` | reproducibility transcript: fresh public clone at a pinned commit, sha256 of the key files, shellcheck, identical-section diff of the three guide copies, then `token-test.sh` on main (`EXPECT=fail`) and on the PR branch (`EXPECT=pass`). |
| `logs/` | published, redacted logs (list below). |

## What the live test does

The throwaway project lives in `/var/tmp/pfttok-<random>` on the sentry. Its compose file has the guide compose file's
three mounts (as project volumes), `user: "0:0"`, no published ports and `network_mode: none`, and it uses the image
`postfiatd-sentry` already runs (nothing is pulled). Its container is named `test-pfttok-<random>`: many host tools on
our hosts pick a container named exactly `postfiatd`, so that name stays free. The guide blocks run as one paste
session in one shell (`ssh relay bash -s`) that starts with `umask 022` (the Ubuntu default) and `POSTFIATD_DIR` set to
the project dir. The only edit is the container name (`docker exec postfiatd `, ` postfiatd:/` -> the test name),
printed as a diff in the log. Fresh throwaway keys are created by section 5; the `[validator_token]` lines of the
`set_domain` output are replaced by a marker before anything reaches the log, and file contents are only ever checked
with `grep -q` (never printed).

Assertions: one `MODE` line per file (host: the six files the sections write; container: `postfiatd.cfg`, and whether
`/root/.ripple` is gone) with mode, owner and whether it holds the token; the node starts with the injected config and
`server_info` returns `pubkey_validator` equal to the `set_domain` public key (proof the `600` config was read); the
config is readable for the container user `0:0` and, with `600`, not for uid 65534; the removal block deletes both
copies; on copies with the verifier, a re-run of sections 5-7 with a new identity, over the six host files set to `644` as an older guide left them, ends with every file at `600` again and the node on the new public key. The
verdict `MODES FAIL` lists every token-bearing file that is not `600`.

Around the test: an Alertmanager silence on `host="sentry"`, a `pft-maint` window whose `[MAINT]` messages go to a
throwaway ntfy topic, a preflight gate that the sentry's next hourly `pft-integrity` run is at least 15 minutes away,
and at the end: both live nodes have the same container ID and `StartedAt` and are `full`, `pft-integrity` PASS on both
hosts, schedaudit clean, the silence expired only once no new sentry alert is pending or firing, 3 minutes without one,
and every operator ntfy topic polled with 0 messages. Neither live `postfiatd` is stopped, restarted or changed.

## Logs

| log | what it is |
|---|---|
| `logs/01-main.log` | `token-test.sh` on upstream main `ac8b944` with `EXPECT=fail`: `MODES FAIL` for `set-domain-output.txt`, `postfiatd.cfg.new` and the container `postfiatd.cfg` (all `644`), harness clean, 0 operator messages |
| `logs/02-branch.log` | `token-test.sh` on the PR branch with `EXPECT=pass`: every token-bearing file `600` on the first run and on the rerun over `644` leftovers, node up with the new `pubkey_validator`, uid 65534 cannot read the config, both config copies removed, 0 operator messages |
