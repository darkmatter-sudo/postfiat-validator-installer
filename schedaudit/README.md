# schedaudit — scheduled-execution entry-point audit (pft-schedaudit)

Status: **in progress**: installed on both hosts, found → fixed → verified (log 03, 45/45 checks PASS), package-id
update (log 06, PASS); the non-executing tamper drill on a throwaway topic is not run yet (see [Results](#results)).

`../jobwatch` watches the OUTCOME of the `pft-*`/`postfiat*` timers. Nothing in this repo looked at the other ways
code gets run on a schedule on a validator or sentry: `/etc/crontab`, `/etc/cron.d`, user crontab spools, the
`run-parts` directories, `/etc/anacrontab`, `at` spools, and the ~70 systemd timers that come with Ubuntu itself.
`pft-integrity` tracks `/usr/local/bin`, `pft-*` units and their drop-ins, but no cron file at all, so a new
`/etc/cron.d` file or an edited `/etc/cron.hourly` script changed nothing it checks. `pft-schedaudit` inventories every
scheduled entry point (enabled, disabled, masked or commented out), checks each one, compares the set with the last
accepted one, exports the result as textfile metrics, and gives `pft-integrity` the list of files to track.

| File | What it is |
|---|---|
| `pft-schedaudit.sh` | CLI: `collect`, `audit`, `inventory`, `apply`, `accept`, `scope`, `pull`, `validate`, `version` (usage in its header) |
| `schedaudit_lib.py` | stdlib helper: cron/anacron/at/timer parsers, path-chain + dpkg + user + timer-target checks, allowlist, state, textfile renderer |
| `tests/test_schedaudit.py` | offline suite: a fixture host tree built in a temp dir + `tests/stub_systemctl.py` |
| `tests/mutate.py` | mutant harness: helper, wrapper, `pft-integrity` hook and rule mutants; the suite or promtool must fail each |
| `tests/fixtures/` | `systemctl show` output captured on the validator (TZ=UTC): pft-jobwatch, pft-heartbeat (monotonic), xfs_scrub_all (disabled), mdmonitor-oneshot (`ExecStart` `path=sh`), plus variants with only the named fields changed (unit not found, binary missing, unpackaged binary, `User=alice`, masked) |
| `install.sh` | install/uninstall the collector (`--host NAME --reason TEXT`) or the validator's pull of the sentry file (`--pull`) |
| `systemd/` | `pft-schedaudit.service/.timer` (both hosts, every 5 min at :20; sandboxed: no network, only `CAP_DAC_READ_SEARCH`) and `pft-schedaudit-pull.service/.timer` (validator, :01:50 every 5 min) |
| `pft-schedaudit.env.example` | `/etc/pft-schedaudit.env` (root-owned 0600): `HOST_LABEL`, `ALLOW_FILE`, `PULL_SSH` |
| `../alerts/schedaudit.rules.yml` | `PFTSchedEntryUnexpected`, `PFTSchedauditStale` (+ `schedaudit.tests.yml`, promtool) |
| `../integrity/pft-integrity.sh` | `collect_sched`: every path from `pft-schedaudit scope` becomes a `sched:PATH` item |
| `../rulecheck/*.conf.example` | textfile age + `require` lines for `pft_schedaudit_*.prom` |

## Usage

```
sudo pft-schedaudit audit                 # findings table; exit 1 if anything is unexpected
sudo pft-schedaudit audit --format json   # the same with every entry, its paths and findings
sudo pft-schedaudit inventory             # every entry, no checks (tsv or --format json)
sudo pft-schedaudit apply --dry-run       # what the permissions-only fix would chmod
sudo pft-schedaudit apply                 # chmod go-w on fixable chain_writable paths, then re-audit
sudo pft-schedaudit accept --reason "added nightly backup cron"   # the current entry set becomes the expected one
sudo pft-schedaudit scope                 # files/dirs pft-integrity tracks as sched:* items
```

## What is inventoried

| Source | Entries | States |
|---|---|---|
| `/etc/crontab`, `/etc/cron.d/*` | one per job line (system format, with user field); `PATH=` lines are read for command resolution | `active`, `commented` (a `#` line that parses as a job for an existing user; the stock `m h dom mon dow user-name command` help line does not), `inert-name` (cron skips `cron.d` names with a dot, e.g. `x.dpkg-old`) |
| `/var/spool/cron/crontabs/*` | one per job line, user = file name | `active`, `commented` |
| `/etc/cron.{hourly,daily,weekly,monthly}/*` | one per file (run by `run-parts`) | `active`, `inert-name` (names outside `[A-Za-z0-9_-]`, e.g. `.placeholder`), `not-executable`, `no-schedule` (no active crontab/anacrontab line runs that dir) |
| `/etc/anacrontab` | one per job line | `active`, `commented` |
| `/var/spool/cron/atjobs`, `/var/spool/at` | one per job file | `queued` (0700, atd will run it), `done` |
| systemd timers | every unit from `systemctl list-unit-files --type=timer` + `list-units --type=timer --all` (template `@.timer` files skipped) with its unit, `ExecStart` binaries, unit files and drop-ins | `active`, `inactive`, `disabled`, `masked` |
| user-unit timer files | `*.timer` in `/etc/systemd/user`, `/usr/lib/systemd/user`, `~/.config/systemd/user` | `user-unit` (listed and path-checked; a user manager's own schedule is not resolved) |

Each entry has a stable id `SOURCE/NAME@HASH`: for cron lines the hash is over the normalised line, for files over
their content, for timers over schedule + unit + `ExecStart` + `User` + unit file paths (never `next_elapse` or run
times, so ids do not move between runs). Editing a line therefore shows up as one `new` and one `removed` id.
Packaged files whose content matches dpkg's md5 are identified by package instead of content: a `run-parts` script
like `/etc/cron.daily/apport`, and a timer whose timer and service unit files are both packaged, md5-verified and have
no drop-ins. An unattended-upgrades update of such a file keeps its id (no alert); a non-package edit fails the md5,
gets a content id (`new` + `removed`) and a `pkg_modified` finding.

## Checks

| Check | Severity | Meaning | Fix |
|---|---|---|---|
| `chain_writable` | crit | the definition file, a script/binary the job runs, a path its command names, or any parent dir up to `/`, is group/other-writable (symlink targets walked too) | `apply` (chmod go-w) when root owns it |
| `chain_owner` | crit | one of those paths is not owned by root (a user crontab file is owned by its user by design and is skipped; its dir is checked) | by hand (`chown`); `apply` never changes owners |
| `writable_dir` | crit | the job runs something under a tree any user can write: a sticky world-writable dir in the chain, or `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/home`, ... | move the script |
| `pkg_modified` | warn | a packaged file (script, binary, unit, conffile) differs from dpkg's md5 (`/var/lib/dpkg/info/*.md5sums`, `Conffiles:` in `/var/lib/dpkg/status`; `/bin`↔`/usr/bin` aliases resolved) | reinstall, or allowlist an intended edit |
| `untracked` | warn | an unpackaged file that `pft-integrity` does not track | install the `pft-integrity` hook (below) |
| `nonsystem_user` | warn | the job runs as a login user (uid ≥ `UID_MIN` from `/etc/login.defs`), or comes from a user crontab | allowlist with the reason, or remove |
| `timer_target` | crit | a timer whose unit is not found / masked / broken, or whose `ExecStart` binary is missing (bare names like `path=sh` are resolved through systemd's default search path first) | fix or remove the timer |

Commands are not executed or parsed as shell. Paths are taken from the command text (absolute paths) plus its first
word resolved through the crontab's `PATH` (cron's default `/usr/bin:/bin`); `/proc`, `/sys`, `/dev` are skipped.

### Allowlist (`/etc/pft-schedaudit.allow`)

```
# CHECK           ENTRY_GLOB             PATH_GLOB                 REASON (required, 8+ chars)
nonsystem_user    cron.d/my-agent@*      /etc/cron.d/my-agent      operator's own unprivileged agent cron, runs as its user by design
```

A line without a reason, with a reason under 8 characters or with an unknown check is a config error (exit 3): every
exception has to say why. Allowed findings stay visible (`ALLOWED` rows, `allowed="1"` series); lines that match
nothing are reported as unused (`pft_schedaudit_allowlist_unused`).

### apply (permissions only)

`apply` plans `chmod go-w` for every not-allowlisted `chain_writable` path owned by root, prints `PLAN` (`--dry-run`)
or `FIXED old -> new` lines, appends them to `/var/lib/pft-schedaudit/apply.log`, and re-audits. It never edits,
moves or deletes a file, never changes an owner and never touches a sticky dir (`writable_dir`).

### pft-integrity integration

`pft-schedaudit scope` lists the definition file, unit files and every unpackaged script/binary each entry runs or
names (except files under user-writable trees, which `writable_dir` already flags), packaged `/etc` files (they can be
edited), and the scheduling dirs themselves. `../integrity/pft-integrity.sh` `collect_sched` adds each file as a
`sched:PATH` item (sha256, mode, owner, mtime) and each dir as a listing item (names, modes, owners), so a new
`/etc/cron.d` file changes the integrity manifest too. If `pft-schedaudit` is not installed there are no `sched:`
items; if `scope` fails there is one `sched:scope status error` item (a WARN, never silence). When the installed
`pft-integrity` contains `collect_sched()`, `audit`/`collect` pass `--integrity-hook` and those files count as tracked.

## Metrics (`pft_schedaudit_HOST.prom`, label `host` = validator | sentry, never a hostname)

| Metric | Meaning |
|---|---|
| `pft_schedaudit_up` | 1 if every scheduling source could be read (systemctl failure: 0, and the file holds nothing else) |
| `pft_schedaudit_collect_timestamp_seconds` | time of the last run |
| `pft_schedaudit_entries{source,state}` | entry counts |
| `pft_schedaudit_findings{check,severity,allowed}` | findings; every check has an `allowed="0"` and `"1"` series, so rules never see a missing series |
| `pft_schedaudit_unexpected{kind}` | `new` / `removed` (vs the accepted set), `finding` (not allowlisted), `unaccepted` (1 until the first accept) |
| `pft_schedaudit_allowlist_unused` | allowlist lines that matched nothing |
| `pft_schedaudit_accepted_timestamp_seconds` | time of the last accept |

The file is written atomically (temp file + rename, 0644); a file over `TEXT_BUDGET` (61440 bytes) is replaced by an
`up 0` file instead of one the exporter would silently drop. On the validator `pft-schedaudit pull` copies the
sentry's file over ssh and validates it (every sample `pft_schedaudit_*`, first label `host="sentry"`, `up` and
timestamp present, ≤ 64 KiB) before renaming it in. The sentry runs no Prometheus: its alerts are evaluated on the
validator from the pulled file.

## Alerts

| Alert | Fires when |
|---|---|
| `PFTSchedEntryUnexpected` | `pft_schedaudit_unexpected{kind=~"new|removed|finding|unaccepted"} > 0` while the audit itself works (`up == 1`), for 2 min; one alert per host and kind, value = count |
| `PFTSchedauditStale` | the last audit is older than 15 min, or `up == 0`, for 10 min |

If the change is yours: `sudo pft-schedaudit accept --reason "..."` and `sudo pft-integrity accept --reason "..."`.
If it is not, treat it as possible tampering: `sudo pft-schedaudit audit --format json` shows the file and line.

## Tests

```
TEST_TMPDIR=~/.cache python3 -u schedaudit/tests/test_schedaudit.py      # offline suite
TEST_TMPDIR=~/.cache python3 -u schedaudit/tests/mutate.py --jobs 2      # mutants (needs docker for promtool)
shellcheck schedaudit/*.sh integrity/pft-integrity.sh && ruff check schedaudit && ruff format --check schedaudit
cd alerts && promtool test rules schedaudit.tests.yml
```

/tmp is `noexec` on these hosts, so the suites build their fixture trees and stubs under `~/.cache`.

## Scope limits

- The audit reads files and `systemctl`; it does not parse shell. A job that builds a path at run time
  (`$(...)`, variables) is checked only for the literal paths in its text.
- A user systemd manager's own timers are listed as files (`user-unit`), not resolved through `systemctl --user`.
- `pkg_modified` uses dpkg's md5 database, which a root attacker can also edit; `pft-integrity` (manifest hash kept
  off-host with `--expect-sha`) is the tamper-evident layer.
- Accept blesses what is there. Review `audit` before the first accept.

## Results

| Log | What | Result |
|---|---|---|
| `logs/01-checks.log` | shellcheck, ruff, promtool check + test, offline suite, mutant harness at `d44e5d4` | PASS: suite 98/98, mutants 56/56 caught, 0 orphans |
| `logs/02-install-preflight.log` | `PREFLIGHT_ONLY=1 drill/install-run.sh` at `c081cd4` (changes nothing) | 12/12 checks ok |
| `logs/03-install.log` | two-host install at `c081cd4` through pft-fleet in a pft-maint window | PASS, 45/45 checks ok |
| `logs/04-checks.log` | the same checks at `1ad593b` (package ids) | PASS: suite 107/107, mutants 60/60 caught, 0 orphans |
| `logs/05-update-preflight.log` | `PREFLIGHT_ONLY=1 drill/update-run.sh` at `7e923ec` | 6/6 checks ok |
| `logs/06-update.log` | two-host update to `7e923ec` through pft-fleet in a pft-maint window: 28 re-identified ids per host (every NEW id has a REMOVED partner with the same SOURCE/NAME), accepted with a reason | PASS, 26/26 checks ok |

Found → fixed → verified (log 03):

| Host | Entries (step 0 → after install) | Found (step 0, HEAD helper, nothing installed) | Fix | Verified (step 9, installed tool) |
|---|---|---|---|---|
| validator | 89 → 91 (+ `pft-schedaudit.timer`, `pft-schedaudit-pull.timer`) | 11 `untracked` (job scripts in `/usr/local/sbin`, provider cron files in `/etc/cron.d` and `/etc/cron.hourly`), 1 `nonsystem_user` (the operator's own unprivileged agent cron) | `pft-integrity` `collect_sched` hook synced by pft-fleet: 31 `sched:*` items tracked; allowlist line with its reason for the agent cron | 0 unexpected findings, 1 ALLOWED, 0 new / removed, baseline yes |
| sentry | 65 → 66 (+ `pft-schedaudit.timer`) | 6 `untracked` | the same hook: 26 `sched:*` items | 0 findings, 0 new / removed, baseline yes |

No `chain_writable`, `chain_owner`, `writable_dir`, `pkg_modified` or `timer_target` finding on either host. Both
textfiles scrape with `up 1` and all 8 `pft_schedaudit_unexpected` series 0; `pft-fleet skew` CURRENT for schedaudit
and integrity on both hosts; pft-rulecheck `RESULT OK` on both; pft-integrity PASS on both; both nodes `full`; the
[MAINT] messages reached the throwaway topic and the operator topics received 0 messages during the run.

Since log 03: package-verified run-parts scripts and packaged timers are identified by package (see
[What is inventoried](#what-is-inventoried)), installed on both hosts by update run 06 (28 ids re-identified and
accepted per host, 0 unexpected afterwards, operator topics 0 messages).

Pending: the non-executing tamper drill (a never-firing cron.d entry, `PFTSchedEntryUnexpected` FIRING then
RESOLVED on a throwaway topic, `apply` on a deliberately 0666 drill file).
