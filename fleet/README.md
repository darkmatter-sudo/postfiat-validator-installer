# pft-fleet: add-on inventory, version skew and pinned sync

Every add-on in this repo is installed by copying files (scripts, units, Python helpers) to fixed paths on the
validator and the sentry. After a few weeks of fixes the two hosts drift: one host gets the new script and the other
keeps the old one, or a hand edit is never committed. `pft-integrity` notices that *something* changed, but not
whether the bytes are an older release, a newer one, or something nobody committed. `pft-fleet` answers that by
comparing the installed bytes with this repo's git history, and can put one add-on back on a pinned commit safely.

| File | What |
|---|---|
| `pft-fleet.sh` | `inventory`, `skew`, `sync` (bash: host access over ssh, backups, gates, rollback) |
| `fleet_lib.py` | stdlib helper: git history index, classification, table / JSON / textfile metrics, sync plan |
| `manifest.tsv` | which repo file is installed where, with which mode, on which host role (validator, sentry, both) |
| `systemd/pft-fleet.{service,timer}` | hourly `pft-fleet skew --metrics` on the validator (sandboxed, read-only except the textfile/state dirs) |
| `install.sh` | installs the above on the validator, runs one skew through the unit, enables the timer |
| `fleet.conf.example`, `hosts.conf.example` | `/etc/pft-fleet/fleet.conf` (REPO, REF, SSH_AS, dirs), `/etc/pft-fleet/hosts.conf` |
| `../alerts/fleet.rules.yml`, `../alerts/fleet.tests.yml` | stale-drift alert + promtool tests |
| `tests/run-tests.sh` | stubbed two-host tests (temp git repo, fake host trees, stub ssh/systemctl/docker/pft-maint/pft-integrity) |
| `tests/mutate.sh` | mutation controls for the classifier and the sync/rollback paths |
| `drill/live-run.sh` | the two-host live drill (throwaway ntfy topic, one pft-maint window) |

## Install

On the validator (the host that runs `../alerts`):

```bash
sudo install -d -m 755 /etc/pft-fleet
sudo install -m 644 fleet/fleet.conf.example /etc/pft-fleet/fleet.conf   # set REPO and SSH_AS
sudo install -m 644 fleet/hosts.conf.example /etc/pft-fleet/hosts.conf
sudo fleet/install.sh
sudo pft-integrity accept --reason "pft-fleet installed"
```

`REPO` is a git checkout of this repo on the validator; pft-fleet only reads it (`git show`, `git log`) and never
fetches, pulls or checks out. `REF` (default `main`) is the version every host should run. The ssh host is reached as
`SSH_AS` (root usually has no key for the sentry), and every command there runs through `sudo -n`.

## Use

```bash
sudo pft-fleet inventory [--json]            # every tracked file + unit on every host
sudo pft-fleet skew [--json] [--metrics]     # per-add-on state; exit 0 current, 1 drift, 2 modified/missing/unreadable
sudo pft-fleet sync --addon NAME --to COMMIT [--hosts sentry] [--apply] [--reason TEXT]
```

### States

Per file on a host (`expected` = the host's role is listed for that file in `manifest.tsv`):

| State | Meaning |
|---|---|
| CURRENT | installed bytes = the file at `REF` |
| BEHIND | installed bytes = the file at an older commit in `REF`'s history; the output names that commit and how many newer commits touched the file (`@067704c9fdde (-1)`) |
| MODIFIED | installed bytes match no committed version of the file (hand edit, partial copy, foreign build) |
| MISSING | expected on this host, not installed |
| UNEXPECTED | installed, but the manifest does not list this host's role for the file |
| DIVERGED | cross-host: the same install path has different bytes on two hosts (shown as host `*`) |

An add-on's state on a host is its worst file (MODIFIED > MISSING > BEHIND > UNEXPECTED > CURRENT). `skew` exits 2
for MODIFIED, MISSING or a host that could not be read; 1 for BEHIND, UNEXPECTED or DIVERGED; 0 when everything is
CURRENT; 3 for usage/config errors. `inventory` exits 0 (2 if a host could not be read).

### Sync

`sync` installs one add-on's files exactly as they are at `COMMIT` (`git show COMMIT:path`). The commit must be in
`REF`'s history: a branch nobody merged is refused (exit 3). Without `--apply` it prints the plan (current state,
current and target sha256, `write` or `keep` per file) and changes nothing. With `--apply`, host by host, **every
sentry-role host first**, stopping at the first host that fails:

| Phase | What |
|---|---|
| pre | a `pft-maint` window is active on that host (the validator's window reaches the sentry over the watchdog channel); the node is `full`/`proposing`; `pft-integrity verify` is PASS, or its only findings are files this sync rewrites (so the accept below cannot hide anything else). Any failure: exit 4, nothing written |
| write | each file that differs is copied with `cp -p` to `/var/lib/pft-fleet/backup/<stamp>-<addon>-<host>/`, then replaced atomically (temp file + `mv`, root:root, manifest mode); `systemctl daemon-reload` if a unit changed |
| gate | installed sha256 = the commit's bytes; `bash -n` for bash scripts, a Python `ast` parse for `.py`; unit `LoadState=loaded`; no unit of the add-on in `failed`; node still `full`/`proposing` |
| rollback | gate failed: restore every backup (`cp -p`, so bytes, mode, owner and mtime come back; a file that did not exist is removed), daemon-reload, require the original sha256 of every file. Exit 5 (6 if a hash still differs: the backup dir is printed). Later hosts are not touched |
| accept | gate passed: `pft-integrity accept --reason "pft-fleet sync ADDON@COMMIT on HOST: FILES (REASON)"` |

Exit: 0 synced (or nothing to do), 3 usage, 4 refused, 5 rolled back, 6 rollback mismatch. No node restart: add-on
files are host-side tools; the gate only checks that the node stays healthy.

Test hooks (documented, used by the tests and the drill): `PFT_FLEET_INJECT_GATE_FAIL=<label>` makes the post-write
gate fail on that host; `PFT_FLEET_ROOT_<label>` puts a host's files under a prefix; `PFT_FLEET_SSH`, `PFT_FLEET_NOROOT`.

## Metrics and alerts

`skew --metrics` writes `pft_fleet.prom` to the node_exporter textfile dir and keeps a drift clock in
`/var/lib/pft-fleet/drift.json`:

| Metric | Meaning |
|---|---|
| `pft_fleet_up` / `pft_fleet_host_up{host}` | every host / this host was read |
| `pft_fleet_last_run_timestamp_seconds`, `pft_fleet_exit_code` | last skew run and its exit code |
| `pft_fleet_addon_state{host,addon,state}` | 1 for the add-on's state on that host |
| `pft_fleet_addon_diverged{addon}` | 1 when an installed file differs between hosts |
| `pft_fleet_drift_since_timestamp_seconds{host,addon}` | first run that saw the add-on not CURRENT (host `*` for DIVERGED); gone when it is CURRENT again; kept while the host is unreadable |

### Alerts

`../alerts/fleet.rules.yml`:

| Alert | Fires when |
|---|---|
| `PFTFleetDriftStale` | an add-on has not been CURRENT on a host (or has been DIVERGED) for more than 24h (+10m). Drift for a few hours during a sentry-first rollout is normal; a day means nobody finished it |
| `PFTFleetCheckStale` | no skew run for 3h (the timer is hourly) |
| `PFTFleetHostUnreadable` | a host's inventory failed for 2h |

`fleet.tests.yml` checks each rule's firing and non-firing edges with `promtool test rules`.

## Tests

`tests/run-tests.sh` builds a temp git repo with two fake add-ons and a five-commit history (including a commit whose
script fails `bash -n`, and a branch that is not merged), two fake hosts (the sentry through a stub ssh), and stubs
for systemctl, docker, pft-maint, pft-integrity, sudo and mv. It covers every classification (CURRENT, BEHIND with
commit and distance, MODIFIED, MISSING, UNEXPECTED, worst-file-wins, DIVERGED between two BEHIND versions, no DIVERGED
for identical old copies), an unreadable host, the metrics and the drift clock, the dry run, every refusal, a
successful sync (mode, backup, accept reason, sentry first), and every rollback path: injected gate failure on either
host, a script that fails `bash -n`, a unit that does not load, a unit left `failed`, the node leaving `full`, bytes
on disk that differ from the commit, a file that did not exist before, and a restore that cannot complete (exit 6).

`tests/mutate.sh` applies each mutant to a copy, runs the suite, and requires it to fail. A mutant that drops
`or rep["diverged"]` from the exit code is equivalent (a DIVERGED file always leaves at least one host's copy
BEHIND, MODIFIED or UNEXPECTED, which already gives exit >= 1), so it is not in the table.

## Limits

- Generated files are not tracked: pft-unitguard drop-ins, the pft-egress and pft-logship units (their bytes are
  host-specific by design), env/config files. `pft-integrity` covers them.
- The manifest is maintained by hand: a new add-on needs its lines added. A file not in the manifest is invisible.
- `sync` only writes files. It does not run an add-on's `install.sh` steps (new packages, users, state dirs, first
  runs). For a release that needs those, run the add-on's installer.
- `sync` never deletes a file that the target commit no longer has; it refuses a commit where a manifest file does
  not exist.
- The maintenance window is required on each host before it is written; on the sentry it arrives over the
  watchdog channel within one `pft-watchdog` run.
- Template units (`name@.service`) are checked by file and by their loaded instances' states, not `LoadState`.

## Live proof (validator + sentry, 2026-10-30)

| Step | Result | Log |
|---|---|---|
| tests at 2d7f309 | shellcheck 0, `run-tests.sh` 91/91, mutants 20/20 caught (0 survived, 0 not applied), promtool check 3 rules + test SUCCESS, `../alerts/run-stack.sh check` SUCCESS | [`logs/01-tests.log`](logs/01-tests.log) |
| install on the validator | first skew through the sandboxed unit read both hosts (`Result=success`); timer enabled; `pft-integrity accept` for the two new units, PASS on both hosts; Prometheus loaded the 3 rules; `pft_fleet_up 1` scraped | [`logs/02-install.log`](logs/02-install.log) |
| live inventory + skew | 98 files and 55 unit states read, 31 add-on/host pairs CURRENT, **2 BEHIND on the validator** (`pft-alertpath` one commit behind the sentry's copy, `pft-backup.sh` one commit behind), alertpath **DIVERGED**, exit 1; dry-run plans for both | [`logs/03-live-inventory-skew.log`](logs/03-live-inventory-skew.log) |
| two-host drill (add-on `sysctl` on the sentry) | 30 checks ok, 0 failed: A baseline CURRENT; B dry run changes nothing, pinned sync to 2a68ebb -> sentry BEHIND + DIVERGED (exit 1); C injected gate failure -> exit 5, original sha256 restored, sentry pft-integrity PASS without an accept; D health-gated sync -> CURRENT; E hand edit -> MODIFIED (exit 2); F sync -> CURRENT (integrity finding on the rewritten file allowed, accepted with reason); G the two real BEHIND files synced on the validator, final skew 33 CURRENT, exit 0. Throwaway topic got exactly the two [MAINT] messages, operator topics 0, notifier env files restored sha256-identical, both nodes full, integrity PASS on both | [`logs/04-drill.log`](logs/04-drill.log) |
| metrics after the drill | unit exit 0, `pft_fleet_exit_code 0`, drift clock empty (0 drift series in Prometheus), 33 add-ons CURRENT, rules health ok, 0 PFTFleet alerts, no maintenance window left open | [`logs/05-metrics-after-drill.log`](logs/05-metrics-after-drill.log) |

Logs are the raw output of the commands they print (`$ ...` lines, exit code after each). Redacted on the way out:
the home directory as `~`, the operator account as `<user>`, ntfy topics as `<redacted>` (the drill's redact.py
also covers host addresses and node keys); a grep for host names, public addresses, topics, `/home/` and the account
name over the published logs finds nothing. The sentry is reached through the ssh alias `relay`.
