# fwaudit: declared inbound policy vs effective exposure

**Status: in progress (task_32d07e3a).** In: the read-only audit (`audit [--json] [--textfile]`), per-role
policies, redacted captures of both hosts, remediation (`plan/apply/rollback` with the dead-man), the hourly timer,
textfile metrics, the validator's pull of the sentry textfile, the one alert (`PFTFwauditExposure`) with promtool
tests, `install.sh`, and their tests. Still to come: the live install with the fleet/integrity/schedaudit/jobwatch/
rulecheck integration, the mutation run, the drills and the results table.

## Why

`ufw status` does not say what is reachable. On a Docker host a published port is DNATed in `nat PREROUTING` and
travels the FORWARD path, so UFW's INPUT rules never see it (`DOCKER-USER` decides); docker-proxy serves a family
Docker did not DNAT on the INPUT path; `*` listeners are dual-stack while `[::]` ones are IPv6-only; and nftables
tables outside iptables-nft add hooks of their own. `pft-fwaudit` captures the rulesets and sockets once and walks
the real chains for each listener.

## Usage

```
sudo pft-fwaudit audit [--role validator|sentry] [--json] [--bundle FILE]   # 0 PASS, 1 WARN, 2 FAIL, 3 usage, 4 capture
sudo pft-fwaudit collect [--out FILE]                                        # capture bundle only
sudo pft-fwaudit plan [--role R] [--json] [--bundle FILE]     # 0 nothing to do, 1 actions, 2 manual items left
sudo pft-fwaudit apply --yes [--role R] [--dry-run] [--deadman MIN] [--foreground]
sudo pft-fwaudit rollback --yes
```

Policy (`policy/ROLE.policy`): `allow PROTO PORT FAMILY SOURCE [limit]  # purpose`, FAMILY `v4|v6|both`, SOURCE
`any`, a CIDR, or `@name` resolved from `/etc/pft-fwaudit.peers` (`name=CIDR[,CIDR]`, kept off the repo).

States per (family, proto, port): `open` (any source), `limited` (any source past a rate/conn limit), `sources`
(only listed CIDRs), `closed` (not shown).

| Finding | Verdict | Meaning |
|---|---|---|
| ufw-inactive, default-incoming-allow | FAIL | UFW off or default incoming not deny |
| undeclared-exposure | FAIL | reachable, not in the policy |
| source-too-broad | FAIL | declared for a peer/CIDR, reachable from more |
| missing-limit | FAIL | declared `limit`, reachable without one on the actual path |
| declared-unreachable | WARN | declared, but no listener on that family or filtered |
| stale-allow | WARN | UFW allows a port nothing listens on (a future listener is exposed at once) |
| loopback-dnat-unguarded | WARN | 127.0.0.1-published port without Docker's raw PREROUTING drop |
| nft-foreign-table | WARN | nftables table outside iptables-nft hooks input/forward/prerouting (not modelled) |
| ufw-rule-bypassed | INFO | port is published via DNAT: its UFW rule is not on the path |

## Remediation: plan / apply / rollback

`plan` only ever narrows UFW, one family at a time (`from 0.0.0.0/0` or `from ::/0`), and lists everything else as
MANUAL (it is never changed by the tool):

| Finding | Planned change |
|---|---|
| stale-allow; undeclared-exposure decided by a UFW user rule on the INPUT path | delete those UFW rules (that family only) |
| source-too-broad on the INPUT path | `ufw allow proto P from CIDR ... comment pft-fwaudit` per declared source, then delete every other allow for the port |
| missing-limit on the INPUT path | `ufw limit ... from 0.0.0.0/0` (or `::/0`), then delete the plain ALLOW from Anywhere |
| default-incoming-allow | `ufw default deny incoming` |
| ufw-inactive, Docker DNAT/DOCKER-USER paths, ACCEPTs outside UFW, nft tables, declared-unreachable, loopback DNAT | MANUAL |

`apply` (without `--dry-run`) refuses, changing nothing, unless: `--yes`; a `pft-maint` window is active with at least
`DEADMAN_MIN*60 + MAINT_MARGIN` seconds left and no data-collection lock; the node is `full` with `>= MIN_PEERS` peers
(host `RPC_URL`, or the same `docker exec CONTAINER curl` server_info call pft-selfheal makes); SSH `v4/tcp/22` is a
reachable declared exposure; no earlier apply is pending. It then snapshots `/etc/ufw/user.rules`, `user6.rules` and
`/etc/default/ufw` (sha256 recorded), runs adds before deletes (rule numbers re-read from `ufw status numbered` before
every delete), re-audits, and rolls back unless every planned finding is gone and every declared exposure is still
reachable. The dead-man (transient unit `fwaudit-deadman`, outside the `pft-*` namespace on purpose) polls every
`POLL_SEC` for `DEADMAN_MIN` minutes and rolls back after `BAD_POLLS` consecutive polls with the node not full, peers
below baseline minus `PEER_SLACK`, or a declared exposure (SSH included) gone. `rollback` copies the snapshot back,
runs `ufw reload` and checks the sha256 of every restored file. A UFW change moves the `pft-integrity` fw items: accept
the baseline with a reason after an intended apply.

## Install, timer and metrics

```
sudo ./install.sh --role validator     # or --role sentry on the sentry; needs /etc/pft-fwaudit.peers for @peers
sudo ./install.sh --pull               # validator: hourly copy of the sentry's textfile (PULL_SSH in the env file)
sudo ./install.sh --uninstall          # refuses while an apply is pending its dead-man
```

`pft-fwaudit.timer` runs `pft-fwaudit audit --textfile` hourly at :11 UTC (+ up to 60 s) through a sandboxed unit
(read-only file system except the textfile dir, no home, capabilities NET_ADMIN/NET_RAW for the rulesets and
SYS_PTRACE/DAC_READ_SEARCH for `ss -p` socket owners). It writes `pft_fwaudit_HOST.prom` atomically:

| Metric | Labels | Meaning |
|---|---|---|
| `pft_fwaudit_up` | host | 1 = captured and graded; 0 = capture or policy error (then only up + timestamp) |
| `pft_fwaudit_last_run_timestamp_seconds` | host | time of the run |
| `pft_fwaudit_verdict` | host | 0 PASS, 1 WARN, 2 FAIL |
| `pft_fwaudit_findings` | host, severity | findings by severity (fail/warn/info) |
| `pft_fwaudit_finding_class` | host, class, severity | every class, 0 when absent |
| `pft_fwaudit_exposed` | host, family, state | reachable (family, proto, port) entries, state open/limited/sources |

On the validator, `pft-fwaudit-pull.timer` (:16 UTC, 5 min after the sentry's run, independent of this host's own
run) copies the sentry's textfile over ssh, validates it (`pft-fwaudit validate FILE HOST`: only `pft_fwaudit_`
samples whose first label is the peer's host, up + timestamp present, at most 64 KiB) and renames it in; a failed
fetch or validation leaves the previous copy, which then ages. `pft-rulecheck` grades the age
(`textfile pft_fwaudit_*.prom 3h pft_fwaudit_last_run_timestamp_seconds` and a `require` line per host), so a
stopped timer or failing pull shows up as `PFTTextfileStale`.

### Two-host install (recorded)

[`drill/install-run.sh`](drill/install-run.sh) installs fwaudit at the current pushed HEAD on both hosts inside a
`pft-maint` window whose `[MAINT]` messages go to a throwaway ntfy topic: `pft-fleet sync` of the fleet manifest copy,
fwaudit and aptrust's allowlist copy; `/etc/pft-fwaudit.peers` (root 0600, values never printed); `install.sh --role`
on the sentry, then on the validator, `PULL_SSH` + `install.sh --pull`; Prometheus reload; `pft-schedaudit`
accept + collect, `pft-jobwatch inventory`, `pft-integrity accept` on both hosts. It then checks the installed audit
(PASS on both hosts), the Prometheus series, aptrust, AppArmor/seccomp, `pft-fleet skew`, `pft-rulecheck`, the
timers, and reads back every operator topic (must be 0 messages). `PREFLIGHT_ONLY=1` runs step 0 only.

| Run | Result | Log |
|---|---|---|
| 05 preflight | 11 checks ok, 0 failed, nothing changed | [`logs/05-install-preflight.log`](logs/05-install-preflight.log) |
| 06 install | FAIL 1 check: the sentry peers file came out 0644 (`umask` in the remote shell did not reach the file `sudo tee` created); `install.sh` then set it to 0600, but the runner had no stop gate after step 4 and went on to install on the sentry | [`logs/06-install-run-FAIL-sentry-peers-mode.log`](logs/06-install-run-FAIL-sentry-peers-mode.log) |
| 07 revert | run 06's partial install removed from both hosts (files, timer, rulecheck lines, jobwatch entry), integrity accepted, silence expired once only the watchdog was active | [`logs/07-revert-run06.log`](logs/07-revert-run06.log) |
| 08 install | **PASS, 51 checks ok, 0 failed**: audit PASS on both hosts, up 1 / verdict 0 / 0 fail / 0 warn in Prometheus, skew all CURRENT, rulecheck OK on both hosts, integrity PASS, operator topics 0 messages | [`logs/08-install-run.log`](logs/08-install-run.log) |
| 09 integrity v6 gap tests | **14 passed, 0 failed** (`integrity/tests/test-fw.sh`, stubbed ufw/iptables/ip6tables); the pre-fix collector is the failing control (misses a v6-only deletion and addition); mutation "drop the per-family table" killed (2 failed) | [`logs/09-integrity-v6-gap-tests.log`](logs/09-integrity-v6-gap-tests.log) |
| 10 integrity v6 sync | **PASS, 26 checks ok, 0 failed** ([`drill/integrity-sync-run.sh`](drill/integrity-sync-run.sh)): `pft-fleet sync --addon integrity` in a `pft-maint` window (throwaway topic), installed sha256 = HEAD on both hosts, verify PASS, new baselines carry `fw:ufw v6_rules` (validator 2, sentry 1), skew all CURRENT, operator topics 0 messages | [`logs/10-integrity-v6-sync-run.log`](logs/10-integrity-v6-sync-run.log) |

Fix for run 06 (in run 08's runner): the sentry file is created `install -m 600 /dev/null` before `tee` writes it, and
the runner stops after step 4 if any check failed. Logs 01-04 are the read-only live audit, the sentry IPv6 fix and
re-audit, and the live plan / apply dry-run (see [Found -> fixed -> verified](#found---fixed---verified)). Log 02 is
the raw output with public IPv4 addresses replaced by `<redacted-ip>`; nothing else in the logs is changed.

### Cross-host TCP check (own hosts only)

[`drill/tcp-crosscheck.sh`](drill/tcp-crosscheck.sh) runs on the validator and tests the audit against real
connections between the two hosts this repo operates (nothing else is contacted, nothing is changed). For each
direction it reads the target's installed `pft-fwaudit audit --json`, derives what the prober should reach (open /
limited entries, or a `sources` entry that lists the prober's address; everything else blocked), and makes one TCP
connect per family to every reachable tcp entry, every non-loopback tcp listener of the target and control port 9.
Controls: v4 tcp/22 must be expected and observed reachable (the probe sees an open port), tcp/9 must be expected and
observed blocked on both families (it sees a closed one), and `FWXC_FLIP=PORT` inverts one port's expectation, which
must end `RESULT: FAIL` (mismatches are reported, not just computed). Addresses are never printed.

| Run | Result | Log |
|---|---|---|
| 12 crosscheck | **PASS, 16 checks, 0 mismatches**, controls PASS; includes the source-restricted tcp/19532 (reachable from the listed peer on IPv4, blocked on IPv6) and the sentry's IPv4-only tcp/2559 (IPv6 blocked, the stale v6 allow fixed above) | [`logs/12-crosscheck.log`](logs/12-crosscheck.log) |
| 13 comparator control | `FWXC_FLIP=2559`: **RESULT: FAIL, 4 failures in 16 checks, exit 1** as required (both mismatch directions: expected blocked/observed connected and expected reach/observed timeout); open/closed controls still PASS | [`logs/13-crosscheck-flip-control.log`](logs/13-crosscheck-flip-control.log) |

## Alert

One rule, `PFTFwauditExposure` (`../alerts/fwaudit.rules.yml`, critical, `for: 5m`), with a `reason` label:

- `fail-findings`: at least one FAIL finding (undeclared exposure, source too broad, missing limit, UFW inactive or
  default allow). The summary carries the count.
- `audit-error`: `pft_fwaudit_up == 0` (the capture or the policy failed; the graded series are absent then).

WARN and INFO findings do not page. Runbook: `sudo pft-fwaudit audit` names class, port and family for each finding;
`sudo pft-fwaudit plan` lists the UFW changes `apply` can make in a pft-maint window; Docker/nftables items are
manual. Tests: `promtool test rules alerts/fwaudit.tests.yml` (fire at the `for` boundary and one minute before,
recovery at the hand-computed sample, a 4-minute FAIL that never fires, WARN-only and clean cases, both hosts).

## Found -> fixed -> verified

| Host | Found (capture 00:14Z) | Fix | Verified |
|---|---|---|---|
| sentry | stale-allow tcp/2559 IPv6: UFW allowed it, nginx listens on IPv4 only | removed the v6 rule (2026-11-14T00:45Z); `sentry/relay-setup.sh` now adds an IPv4-only rule | re-audit 00:46Z PASS, fixture `sentry-postfix.bundle`; installed audit PASS on both hosts in install run 08 |

Follow-up found by the same fix: `pft-integrity` did not notice the v6-only deletion above (its `fw:ufw` item hashed
`ufw show added`, which lists a dual-family rule once). Fixed in [`../integrity`](../integrity/README.md) (per-family
rule table + `v6_rules`), tested in log 09 with the old collector as the failing control, deployed to both hosts in
log 10.

Logs: [`logs/01-live-audit.log`](logs/01-live-audit.log) (found), [`logs/02-sentry-v6-fix.log`](logs/02-sentry-v6-fix.log) (fixed), [`logs/03-sentry-reaudit.log`](logs/03-sentry-reaudit.log) (verified), [`logs/08-install-run.log`](logs/08-install-run.log) (installed, PASS both hosts).

## Tests

`python3 -m pytest -q fwaudit/tests` runs over `tests/fixtures/*.bundle`, redacted real captures
(`tests/redact_capture.py`: global addresses to 203.0.113.0/24 / 2001:db8::/32, link-local interface ids to fe80::N).
Every finding class has an injected-fault test and a control that must not raise it.
`tests/test_plan.py` maps every class to its planned change or MANUAL; `tests/test_apply.py` runs the real script
against stubs (`tests/stubs`: ufw, capture, RPC, pft-maint, systemd) and, for every guard, asserts no mutating ufw
call was made and user.rules is unchanged; dead-man trips (node down, peer drop, lost SSH exposure, re-audit still
finding, failed ufw command) assert the restored sha256.
`tests/test_textfile.py` checks every metric against the evaluator's `--json` for the same real capture, the up-0
paths (incomplete bundle, missing policy, failed capture: only up + timestamp written), an unwritable textfile dir
(no file), and `validate`/`pull` (spoofed host, foreign metric, malformed, missing up/timestamp, oversize, failed
fetch: previous copy byte-identical; config refusals).

### Mutation testing

[`tests/mutate.py`](tests/mutate.py) applies 83 single-text mutants (evaluator E01-E32, plan/ufwnum P01-P14, shell
S01-S31, alert rule R01-R06), each exactly once to a private copy of the folder, and runs that copy's full pytest
suite (rule mutants: `promtool test rules`). CAUGHT needs a pytest failure summary plus at least one FAILED test (the
log names them) or a hang killed at the timeout; NOT APPLIED and BROKEN count as failures. Controls before any mutant:
the unmutated copy passes the suite and promtool (baseline), a copy whose evaluator never returns is reported HANG and
leaves no process (timeout), and after the run no process names the scratch dir (orphan).

| Run | Result | Log |
|---|---|---|
| 11 dev pass (100 tests) | 66 caught, **17 survived** (found): unmodelled match options, conditional ACCEPT, INPUT policy ACCEPT, DROP in a jumped chain, udp listeners, loopback listeners behind an ACCEPT, published port without docker-proxy, `inet filter` nft table, FAIL-then-WARN verdict, multicast `-d`, ufwnum DENY, plan exit 2, and five dead-man/rollback paths that only the post-apply re-audit had covered | [`logs/11-mutants-dev-17-survivors.log`](logs/11-mutants-dev-17-survivors.log) |
| fix | 16 new tests (116 total); the collect/rpc stubs gained fake-clock timelines so dead-man polls can change mid-watch (bad/good/bad/bad, SSH lost at +60 s, not-full with peers intact) | commit 892d7a8b7f622f6cc2633e1119bf5863af55d503 |
| 14 recorded (116 tests) | **83 caught, 0 survived, 0 not applied, 0 broken of 83**; controls: baseline 116 passed + promtool SUCCESS, timeout HANG after 60 s with 0 processes left, orphan check 0 | [`logs/14-mutants.log`](logs/14-mutants.log) |
