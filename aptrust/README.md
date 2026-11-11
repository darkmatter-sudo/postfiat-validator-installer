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
| `install.sh` | installs the script, the off-package allowlist (`../fleet/manifest.tsv` copy) and the twice-daily timer; `--pull` makes the validator's run also copy the sentry's textfile |
| `systemd/pft-aptrust.{service,timer}` | sandboxed `pft-aptrust audit --textfile` at 04:41 and 16:41 UTC (+ up to 10 min); validator: plus `pull` in the same run |
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
| `compose:FILE:N` | | `latest`/untagged | INFO official rolling tag or version tag without digest; PASS `tag@sha256` |
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
- `drop`: remove a non-stock global keyring once every key in it has moved to a `signed-by` keyring.

Options, pins, packages and images are report-only. Apply refuses (exit 4, nothing written) without `--yes`, outside
an active `pft-maint` window with at least `MAINT_MIN` (600 s) left or while a data-collection lock is held, when an
earlier apply is still in place, or when `apt-get update` already fails before the change (pre gate). It saves every
path it touches (bytes, mode, owner) to `/var/lib/pft-aptrust/backup-ID/`, makes the change, then runs the post
gate: `apt-get update` must exit 0 with no signature/fetch error and list every index the pre gate listed. If not,
it restores the backup, checks each sha256 and exits 1 (5 if a restored file does not match). `rollback --yes`
restores the last apply the same way, inside a window.

## Metrics and alerts

`audit --textfile` writes `pft_aptrust_HOST.prom` into the pft exporter's textfile directory: `pft_aptrust_up`,
`pft_aptrust_last_run_timestamp_seconds`, and when the audit completed `pft_aptrust_checks{result=pass|info|warn|fail}`,
`pft_aptrust_sources`, `pft_aptrust_keys`. The sentry runs no Prometheus: the validator's run copies the sentry's file
(`pull`, validated: only `pft_aptrust_` samples whose first label is `host="sentry"`, `up` and `last_run` present,
at most 65536 bytes; a failed pull keeps the old copy, so a broken pull shows up as PFTAptrustStale).

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
`sudo pft-jobwatch inventory` (the timer's interval must read 43200).

## Tests

```
TEST_TMPDIR=~/.cache bash aptrust/tests/run-tests.sh
TEST_TMPDIR=~/.cache python3 -u aptrust/tests/mutate.py --jobs 4
docker run --rm --network none --entrypoint promtool -v "$PWD/alerts":/w:ro -w /w prom/prometheus:v3.5.0 test rules aptrust.tests.yml
```

## Results

(In progress: filled from the published logs after the two-host install, apply/rollback and alert drill.)
