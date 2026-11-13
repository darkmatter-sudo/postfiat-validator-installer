# aptrust: APT and container-image supply-chain trust audit

`pft-aptrust.sh` answers one question for a Post Fiat validator or sentry host (Ubuntu 22.04, postfiatd 1.0.9 in
Docker): **who can put code on this host through the package and image channels?** It grades the APT sources, the
keys they trust, APT options that weaken signature or TLS checks, pinning, the provenance of every running container
image and its compose `image:` line, and code installed outside any package manager. It is read-only by default; a
separate `apply` makes only safe, reversible fixes (key migration to `signed-by`, ownership/mode repair) and rolls
itself back if `apt-get update` gets worse.

It does not duplicate the neighbouring add-ons: [`../vulnscan`](../vulnscan) looks for CVEs in what is installed,
[`../integrity`](../integrity) watches file hashes of what is installed, [`../rollout`](../rollout) deploys images.
aptrust looks one step earlier: at the channels new code arrives through.

| File | Purpose |
|---|---|
| `pft-aptrust.sh` | `audit [--json] [--textfile]`, `apply --dry-run\|--yes`, `rollback --yes`, `pull`, `validate`, `version` (bash + gpg/gpgv + jq) |
| `install.sh` | installs the script, the off-package allowlist (`../fleet/manifest.tsv` copy) and the twice-daily timer; `--pull` makes the validator's run also copy the sentry's textfile and installs the hourly pull timer |
| `systemd/pft-aptrust.{service,timer}` | sandboxed `pft-aptrust audit --textfile` at 04:41 and 16:41 UTC (+ up to 10 min); validator: plus `pull` in the same run |
| `systemd/pft-aptrust-pull.{service,timer}` | validator only: sandboxed `pft-aptrust pull` every hour at :23 UTC (+ up to 60 s) |
| `pft-aptrust.env.example` | `/etc/pft-aptrust.env`: `HOST_LABEL`, `OFFICIAL_IMAGES`, `LOCAL_IMAGES`, `OFFPKG_ALLOW`, `EXPIRY_WARN_DAYS`, `PULL_SSH` |
| `tests/run-tests.sh` | offline suite: fixture root shaped like the hosts, stub gpg/dpkg/apt/apt-config/docker/pft-maint, fake clock, plus real-gpg keyring cases |
| `tests/mutate.py` | mutation harness: every mutant disables one check or guard; the suite (or promtool) must fail on each |
| `../alerts/aptrust.rules.yml`, `../alerts/aptrust.tests.yml` | 2 alerts + promtool tests |

## Audit

One line per check: `PASS`, `INFO`, `WARN` or `FAIL`, then `RESULT:`. Exit 0 = no WARN/FAIL (INFO allowed),
1 = findings, 2 = error (no `/etc/apt` or no gpg), 3 = usage. `--json` prints the same rows as one JSON object.

| Check | FAIL | WARN | INFO / PASS |
|---|---|---|---|
| `src:FILE:N` (one-line and deb822 sources) | `trusted=yes`, `allow-insecure`/`allow-weak`/`allow-downgrade-to-insecure=yes`, `signed-by` naming a missing keyring, third-party over http without `signed-by` | third-party without `signed-by` (trusts every global key) or over http | INFO Ubuntu archive over http (InRelease is signature-checked); PASS https + `signed-by` |
| `perm:PATH` | APT config/keyring path not root-owned or group/world-writable | | |
| `legacy` | `/etc/apt/trusted.gpg` holds keys | | PASS absent/empty |
| `global:FILE` (`trusted.gpg.d`) | | non-stock global key | INFO stock file of a package, `dpkg -V` clean |
| `key:FILE` | weak key (RSA < 2048, DSA) or no usable key left | usable key expires within `EXPIRY_WARN_DAYS` | INFO expired keys kept next to a usable one |
| `aptconf:KEY` (`apt-config dump`) | `AllowInsecureRepositories`, `AllowDowngradeToInsecureRepositories`, `AllowWeakRepositories`, `AllowUnauthenticated` true; https `Verify-Peer`/`Verify-Host` false | `Check-Valid-Until`/`Check-Date` false | |
| `pin:FILE:N` | | `Pin-Priority >= 1000` (allows downgrades), third-party pin > 500 for every package | INFO stock package files |
| `image:NAME` (running containers) | | `latest`/untagged third-party image, or no RepoDigest (unknown local build) | **INFO official rolling tag** (`agtipft/postfiatd:*-light-latest`, per Post Fiat's validator guide) or known local build; PASS registry RepoDigest |
| `compose:FILE:N` | | `latest`/untagged | INFO official rolling tag or version tag without digest; PASS `tag@sha256`. `${VAR}`, `${VAR:-default}`, `${VAR-default}` are resolved from the project's `.env` (compose `working_dir` label; read as text, never sourced), so `TAG=latest` in `.env` is a WARN |
| `offpkg:PATH` (`/usr/local/{bin,sbin}`) | group/world-writable or not root-owned | not from a package and not in the allowlist | counted when the path is in the installed manifest copy or `OFFPKG_ALLOW` |
| `pip:` / `npm:` / `dpkg-local:` | | package installed outside APT (global pip/npm, `dpkg -i` with no archive) | |

The official image's rolling tag is reported as INFO, not FAIL, on purpose: Post Fiat's validator guide installs
`agtipft/postfiatd:testnet-light-latest`. The running container's RepoDigest is still printed, so a reviewer can see
exactly which image is live.

## Apply and rollback

`sudo pft-aptrust apply --dry-run` prints the plan. `sudo pft-aptrust apply --yes` changes only three kinds of thing:

- `perm`: `chown root:root` and remove group/world write bits on an APT config or keyring path;
- `sign`: add `signed-by=/etc/apt/keyrings/pft-aptrust-HOST.gpg` to a one-line source that has none, with the key
  that actually signs that source's cached `InRelease` (checked with `gpgv`), exported from the global keyring;
- `drop`: remove a non-stock global keyring once every usable key in it has moved to a `signed-by` keyring (expired and
  revoked keys sign nothing APT accepts, so they need no new home; GitHub CLI's vendor keyring carries one, [36](logs/36-drop-dead-key.log)).

Options, pins, packages and images are report-only. Apply refuses (exit 4, nothing written) without `--yes`, outside
an active `pft-maint` window with at least `MAINT_MIN` (600 s) left or while a data-collection lock is held, when an
earlier apply is still in place, or when `apt-get update` already fails before the change (pre gate). It saves every
path it touches (bytes, mode, owner) to `/var/lib/pft-aptrust/backup-ID/`, makes the change, then runs the post
gate: `apt-get update` must exit 0 with no signature/fetch error and list every index the pre gate listed. If not,
it restores the backup, checks each sha256 and exits 1 (5 if a restored file does not match). `rollback --yes`
restores the last apply the same way, inside a window.

## Metrics

`audit --textfile` writes `pft_aptrust_HOST.prom` into the pft exporter's textfile directory: `pft_aptrust_up`,
`pft_aptrust_last_run_timestamp_seconds`, and when the audit completed `pft_aptrust_checks{result=pass|info|warn|fail}`,
`pft_aptrust_sources`, `pft_aptrust_keys`. The sentry runs no Prometheus: the validator's run copies the sentry's file
(`pull`, validated: only `pft_aptrust_` samples whose first label is `host="sentry"`, `up` and `last_run` present,
at most 65536 bytes; a failed pull keeps the old copy, so a broken pull shows up as PFTAptrustStale).
The same-run pull alone was not enough: both hosts' timers add up to 10 min of random delay, so the sentry's audit
can finish after the validator's pull, which then copied a 12 h old file and the next copy came 12 h later (24 h,
PFTTextfileStale at 15 h, 2026-11-13). `pft-aptrust-pull.timer` (validator, hourly) bounds the copy's age to about
12.7 h (sentry audit at 16:41-16:56, copied by 17:24, replaced by the 05:24 pull at the latest).

## Alerts

| Alert | Fires when | Severity |
|---|---|---|
| `PFTAptrustUntrusted` | `pft_aptrust_checks{result="fail"} > 0` for 5 min | critical |
| `PFTAptrustStale` | `pft_aptrust_up == 0`, or no audit for 26 h, for 30 min | warning |

WARN results do not page; they show in the metric and in `sudo pft-aptrust audit`.

## Install

```
sudo ./install.sh                        # validator
sudo ./install.sh --host sentry          # sentry
sudo ./install.sh --pull                 # validator, after PULL_SSH is set in /etc/pft-aptrust.env
```

Then `sudo pft-integrity accept --reason "pft-aptrust installed"`, `sudo pft-schedaudit accept` + `collect`, and
`sudo pft-jobwatch inventory` (the audit timer's interval must read 43200, the validator's pull timer 3600). install.sh adds the `textfile` and `require` lines
to `/etc/pft-rulecheck.conf`. The files are listed in `../fleet/manifest.tsv`, including the allowlist copy
(`fleet/manifest.tsv` -> `/usr/local/lib/pft-aptrust/manifest.tsv`), so `pft-fleet sync --addon aptrust` keeps the allowlist
current. Re-sync aptrust whenever the manifest changes (until then `pft-fleet skew` shows aptrust BEHIND).
`drill/install-run.sh` is the recorded two-host install, done through pft-fleet inside a pft-maint window with a
throwaway topic.

## Tests

```
TEST_TMPDIR=~/.cache bash aptrust/tests/run-tests.sh
TEST_TMPDIR=~/.cache python3 -u aptrust/tests/mutate.py --jobs 4
docker run --rm --network none --entrypoint promtool -v "$PWD/alerts":/w:ro -w /w prom/prometheus:v3.5.0 test rules aptrust.tests.yml
```

## Results

| step | log | result |
|---|---|---|
| install preflight | [31](logs/31-install-preflight.log), [32](logs/32-install-preflight.log) | 31: the pull-ssh probe FAILed because it read `PULL_SSH` from a file that only has `PEER_SSH`, so it ran an empty command. Fixed in the runner (37db036: read pft-kmod's `PULL_SSH`, refuse an empty command); 32: preflight 10/10 |
| two-host install | [33](logs/33-install-run.log) | 44 ok / 1 FAIL. The FAIL is the final "no rollout alert pending" check. It ran seconds after pft-keyescrow was re-run, before Prometheus had scraped `drift_items 0`, so PFTKeyEscrowStale (reason=drift, pending since the throwaway ntfy.env swap, silenced) was still listed. [34](logs/34-install-aftercheck.log) shows its last pending sample at 08:06:30Z and drift_items 0 on both hosts. The rollout silence was then expired by hand, and the operator topics got 0 messages (read back after the expiry). The runner now polls that check for up to 150 s |
| FOUND -> FIXED -> VERIFIED | [33](logs/33-install-run.log) step 9 | FOUND (dev audits): offpkg WARN for `/usr/local/bin/pft-sshcrypto` on both hosts, because the sshcrypto add-on was missing from the fleet manifest (installed bytes = repo bytes on both hosts). FIXED: 7 sshcrypto lines added to `fleet/manifest.tsv`. VERIFIED: audit 0 warn / 0 fail on both hosts, offpkg 43 (validator) / 35 (sentry) add-on files match the allowlist, `pft-fleet skew` shows sshcrypto + aptrust CURRENT on both |
| compose `.env` resolution | [30](logs/30-mutants-dev-compose.log) | new mutants A50-A54 + A37: 6 caught, 0 survived |
| drop + dead keys | [35](logs/35-suite-dev.log), [36](logs/36-drop-dead-key.log), [37](logs/37-mutants-p18-p19.log) | FOUND while preparing the live drill: `apply` would sign the GitHub CLI source but keep the migrated global keyring, because GitHub's vendor keyring carries an expired key next to the current one and `drop` wanted every key moved (36: the HEAD script plans sign + manual, the fixed one sign + drop, on a seeded COPY of `/etc/apt`). FIXED: `drop` counts usable keys only (same expired/revoked test as `key:`). Tests 153/153 (3 new dead-key cases), mutants P18/P19 caught |
| live preflight | [38](logs/38-live-preflight.log) | dry run of steps 0/0b: all checks ok, nothing changed |
| two-host live drill | [39](logs/39-live-run.log) | **PASS, 61 checks ok / 0 failed.** Weaknesses seeded by the run on both hosts: a comment-only `apt.conf.d` file at root:root 0660 (perm FAIL; group root has no members, checked first) and, on the validator, the GitHub CLI source without `signed-by` with its key copied into `trusted.gpg.d` (WARN src + WARN global). Steps: refusals outside a window (exit 4, `/etc/apt` unchanged); throwaway topics for the bridge and pft-maint; pft-fleet sync of the fixed script with the pft-integrity rebaseline on both hosts (PASS 236/142 right after); `PFTAptrustUntrusted` firing for host=validator and host=sentry 341 s after the seeded textfiles, `[FIRING]` on the throwaway topic; `VERIFY_INJECT` auto-rollback exit 1, `/etc/apt` byte+mode identical to the seeded state; `apply --yes` (perm 0640, signed-by keyring with 1 key, global key dropped, post gate 5/5 and 4/4 indexes); audit 0 WARN / 0 FAIL on both; `[RESOLVED]` 67 s later; `rollback --yes` byte+mode identical to the seeded state; unseed: byte+mode identical to the pre-run snapshot; operator topics 0 messages, integrity PASS, nodes full, no window left |
| recorded full mutant run | [43](logs/43-mutants-full.log) | at de6189e (the mutated files `pft-aptrust.sh`, `alerts/aptrust.rules.yml` and the suite are byte-identical at the submitted commit: `git diff de6189e HEAD` on them is 0 lines). Controls (unmutated copies) PASS: suite 153/153, promtool SUCCESS. **91 caught, 0 survived, 0 not applied, 0 broken of 91.** The harness still exited 1, because its orphan check (`pgrep -fc '[a]tmut\.'`) counted 1 process. No mutant process or scratch dir was left afterwards ([44](logs/44-orphan-controls.log) step 0). The most likely match is the shell that launched the run, whose own command line named an older scratch dir (`atmut.<old>`), the same self-match trap as `pgrep -f`. The process list was not captured at 11:15:59Z, so this cause is not proven |
| orphan-check fix | [44](logs/44-orphan-controls.log) | `mutate.py` now counts only processes whose command line names THIS run's unique scratch dir and prints each one (4b8d334, aa392b0). Recorded controls: a decoy shell that only names `atmut.decoy-old-scratch` is counted by the old pattern (1) but not by the fixed check (2 mutants, orphan 0, exit 0); the positive control `ATMUT_ORPHAN_SELFTEST=1` leaves one child behind and is reported (orphan 1, exit 1); cleanup by PID, nothing left |
| fresh public clone (final) | [45](logs/45-fresh-clone.log) | anonymous clone at a89c719 (the submitted commit adds only this log and README text): tree clean, shellcheck exit 0 (incl. `tests/orphan-controls.sh`), suite 153/153, promtool test SUCCESS + check 2 rules, mutated files and suite unchanged since the recorded mutant run 43 (diff 0 lines; only `tests/mutate.py` + `tests/orphan-controls.sh` changed, logs/44) |
| fresh public clone (earlier) | [42](logs/42-fresh-clone.log) | anonymous clone at 4b7d592: tree clean, shellcheck exit 0, suite 153/153, promtool test SUCCESS + check 2 rules, mutated files unchanged since the recorded mutant run (diff 0 lines). (A first transcript, 41 at d6a6ce7, had the same results but echoed one command with the local home path; the script now redacts echoed commands too, and 41 stays private) |

### Found -> fixed -> verified (generic, both hosts)

| host | found (seeded or real) | fixed by | verified |
|---|---|---|---|
| validator, sentry | real: `pft-sshcrypto` files not in the fleet manifest -> offpkg WARN | 7 manifest lines (67edae8), pft-fleet sync | audit 0 WARN / 0 FAIL ([33](logs/33-install-run.log) step 9) |
| validator, sentry | seeded: group-writable APT config file -> perm FAIL, `PFTAptrustUntrusted` firing | `apply --yes` (`perm`, mode 0640) | audit 0/0, alert RESOLVED ([39](logs/39-live-run.log) step 4) |
| validator | seeded: third-party source with no `signed-by`, its key global -> WARN src + WARN global | `apply --yes` (`sign` + `drop`) | audit 0/0, `apt-get update` same indexes, no signature error ([39](logs/39-live-run.log) step 4) |
| tool | real: `drop` kept a keyring whose only other key was expired | `fprs` counts usable keys only (cc3ecf8) | [36](logs/36-drop-dead-key.log), tests + P18/P19, live drop in [39](logs/39-live-run.log) |

### Negative controls and clean fixture

[35](logs/35-suite-dev.log) lines 1-20: the clean fixture (shaped like the hosts) PASSes with exit 0, no WARN/FAIL line and
a `fail 0 / warn 0` textfile. Lines 21-92: 51 `neg` fixtures, one per named weakness (trusted=yes, allow-insecure/weak,
deb822 `Trusted: yes`, missing or global-only keyrings, http third-party, legacy `trusted.gpg`, modified stock key,
group/world-writable or non-root APT paths, RSA-1024/DSA/expired/revoked/expiring/empty keys, each insecure APT option,
pins >= 1000 or > 500 for all, untagged/`latest`/digest-less images, compose `latest` and missing files, unknown or
writable `/usr/local` files, global pip/npm, `dpkg -i` packages): each exits 1 with its finding, and the boundary
cases next to them (RSA-2048, 31-day expiry, single-package pin 600, ...) do not. Every check and guard is also a
mutant: 91 in `tests/mutate.py`, each must make the suite or promtool fail ([43](logs/43-mutants-full.log): 91 caught).

### Deviations

- The hosts had no supply-chain FAIL of their own (dev audits: 0 FAIL on both; the only real finding was the
  sshcrypto offpkg WARN above). So the apply/rollback and alert proof runs on weaknesses the drill SEEDS and removes
  itself; the seeded perm FAIL is a comment-only file in a root-only group, so nothing was actually exposed.
- The official image's rolling tag (`agtipft/postfiatd:testnet-light-latest`, Post Fiat's validator guide) is INFO,
  not FAIL, as the card asks; the live RepoDigest is printed next to it.
- The probe and dev-audit logs (host-specific listings of packages, paths and keys) are kept private, per this
  repo's rule for security add-ons; the published logs carry the generic results.
- The recorded full mutant run ([43](logs/43-mutants-full.log)) caught 91 of 91 mutants but exited 1 because of the
  harness's own orphan check (see Results). That check was fixed afterwards in `tests/mutate.py` only (the mutated
  files did not change) and the fix was proven with recorded controls ([44](logs/44-orphan-controls.log)). The
  91-mutant run was not repeated on the fixed harness: it takes about 70 min.
