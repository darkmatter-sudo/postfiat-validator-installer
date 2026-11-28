# domain-rerun: re-run `set_domain` from the newest key file

Test kit and evidence for a docs-only PR to
[postfiatorg/postfiatorg.github.io](https://github.com/postfiatorg/postfiatorg.github.io). The PR changes two
Troubleshooting entries of the validator guide: "`domain` is empty in `validator_info`" and "The operator already
has validator keys". The text is the same in `content/validator-setup.md`, `static/agents/validator-setup.md` and
`static/agents/validator-setup.txt`.

Problem on main: both entries send the operator back to the original `validator-keys.json`. Every
`validator-keys set_domain` (or `create_token`) run increments `token_sequence` in the key file inside the container.
Section 6 saves that updated file as `validator-keys.domain.json`, but the original `validator-keys.json` keeps the
old sequence. A re-run from the original file therefore issues a manifest with a sequence the node has already
seen. The node keeps using its older manifest and the new domain never shows in `validator_info`.

The PR:

- names the key file to use: `validator-keys.domain.json` if `set_domain` ever ran, otherwise `validator-keys.json`;
- adds a re-run block that keeps a dated `chmod 600` backup of that file (`validator-keys.backup-<UTC time>.json`),
  re-runs `set_domain` from it and saves the updated file as the new `validator-keys.domain.json` (`chmod 600`,
  under `umask 077`);
- adds a read-only check that the new `token_sequence` is greater than the backup's and greater than the `seq` of the
  manifest the node runs now (`validator_info`). It prints `sequence increase OK` only then, and the entry says not
  to inject the token otherwise. If an older key file was used, it says to run the two blocks again: each run starts
  from the file the previous run saved;
- changes only the Troubleshooting section. Sections 6-7 are left as they are, so it does not overlap with the open
  PR #78 (token file modes in sections 6-7).

## Files

| file | what it does |
|---|---|
| `extract_domain.py` | `extract_domain.py OUTDIR GUIDE [GUIDE ...]`: cuts sections 5-7 and the Troubleshooting section out of the first guide copy. It fails unless every other copy has byte-identical sections 5-7 and Troubleshooting. It writes each bash block to a named file: `05-keys.sh` .. `07b-cleanup.sh`, plus `T1-rerun.sh` and `T2-seqcheck.sh` when the "`domain` is empty" entry has the re-run blocks (main has none). A marker line fixes each block's role. |
| `domain-test.sh` | `EXPECT=pass\|fail bash domain-rerun/domain-test.sh GUIDE`: live test on the **sentry** in a throwaway compose project (steps S0-S9 in its header). It runs on the validator as the agent user and reaches the sentry with `ssh relay`. Exit 0 only if every harness check is ok and the re-run verdict equals `EXPECT`. |
| `fresh-clone.sh` | reproducibility transcript: fresh public clone at a pinned commit, sha256 of the key files, shellcheck, the identical-section diff of the three guide copies (main and PR head), then `domain-test.sh` on main (`EXPECT=fail`) and on the PR head (`EXPECT=pass`). |
| `logs/` | published, redacted logs (list below). |

## What the live test does

The throwaway project lives in `/var/tmp/pftdom-<random>` on the sentry. Its compose file has the guide compose file's
three mounts (as project volumes), `user: "0:0"`, no published ports and `network_mode: none`. It uses the image
`postfiatd-sentry` already runs, so nothing is pulled. Its container is named `test-pftdom-<random>`: many host
tools on our hosts pick a container named exactly `postfiatd`, so that name stays free. The guide blocks run in one
sentry shell per step (`ssh relay bash -s`). The edits are the container name (`docker exec postfiatd `,
` postfiatd:/` -> the test name) and, for the re-run only, the domain in the `export VALIDATOR_DOMAIN` block
(`example.com` -> `example.org`). Both are printed as a diff in the log. Section 5 creates fresh throwaway keys. The
`[validator_token]` lines of the `set_domain` output are replaced by a marker before anything reaches the log. Key
files are only read for `token_sequence` and `public_key`.

1. First setup: sections 5-7 with domain A (`example.com`), then `STATE first-setup`.
2. Re-run with domain B (`example.org`), the way the guide copy says:
   - main: the entry only says "Re-run `validator-keys set_domain`", so the test runs the guide's only `set_domain`
     block (section 6, from `./validator-keys.json`), then token extraction, injection and restart (section 7);
   - PR: the entry's re-run block and sequence check, then the same extraction and injection, only if the check
     printed `sequence increase OK`.
   Then `STATE after-rerun-restart`.
3. A second `docker compose restart` on the same volumes, then `STATE after-second-restart`.
4. PR only, a control: the newest key file is moved aside, so the re-run block falls back to `validator-keys.json`.
   The check must refuse it and nothing is injected. Then the two blocks are repeated, as the entry says, until the
   check prints `sequence increase OK`.

Each `STATE` line has `validator_info` `domain`, `seq` and `master_key`, `server_info` `pubkey_validator` and the
`token_sequence` of every key file. `RERUN PASS` needs, after both restarts: domain B, `seq` greater than after the
first setup, and `master_key` and `pubkey_validator` equal to the `set_domain` public key.

Around the test: an Alertmanager silence on `host="sentry"` and a `pft-maint` window whose `[MAINT]` messages go to
a throwaway ntfy topic. A preflight gate checks that the sentry's next hourly `pft-integrity` run is at least 15
minutes away. At the end: both live nodes have the same container ID and `StartedAt` and are `full`,
`pft-integrity` passes on both hosts, schedaudit is clean, and the silence is expired only once no new sentry alert is
pending or firing, followed by 3 minutes without one. Every operator ntfy topic is polled and must have 0 messages.
Neither live `postfiatd` is stopped, restarted or changed.

## Logs

| log | what it is |
|---|---|
| `logs/01-main.log` | `domain-test.sh` on upstream main `ac8b944` with `EXPECT=fail`. First setup: domain `example.com`, seq 1, master key (line 260). Re-run from `validator-keys.json` with `example.org`: debug.log `Manifest: Stale; Seq: 1; OldSeq: 1` (339); after the restart `validator_info` has no domain and no seq, and `master_key`/`pubkey_validator` are an ephemeral `n9...` key (336). After a second restart: `example.org`, but seq 1 again (351). `RERUN FAIL` (357), harness clean, 0 operator messages (408), `RESULT: PASS` (411). |
| `logs/02-branch.log` | `domain-test.sh` on the PR head `8eed109` with `EXPECT=pass`. First setup seq 1 (290); re-run block + check: `token_sequence: backup 1, new 2; running manifest seq: 1`, `sequence increase OK` (355-356); `AcceptedUpdate Seq: 2; OldSeq: 1` (407); `example.org`, seq 2, master key after both restarts (404, 420). Control: an older key file is refused (491, 493) and nothing is injected (498); repeating the blocks uses `create_token` and reaches `sequence increase OK` at 3 (604-608). `RERUN PASS` (620), 0 operator messages (671), `RESULT: PASS` (674). |
