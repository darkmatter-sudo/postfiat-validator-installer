# dnsaudit: DNS dependency audit and monitor

`pft-dnsaudit.sh` is a read-only audit of the DNS path that a Post Fiat validator or sentry host (Ubuntu 22.04,
systemd-resolved stub, postfiatd 1.0.9 in Docker) depends on. It derives the names that matter from the live
configuration and checks four things. They resolve on the host path and on the node container's own path. More
than one upstream resolver answers. The upstreams validate DNSSEC, and both paths reject a DNSSEC-bogus control
name. No LLMNR/mDNS listener is open, and the host stub and the container's `resolv.conf` look as expected. A
15-minute timer writes textfile metrics. One digest-only alert rule reports findings.

Why it matters: a node with working peers can still be one DNS failure away from trouble. It may not be able to
refresh its validator list (`[validator_list_sites]`), reach its bootstrap peer by name, pull a security update
(apt mirrors), pull a new image (registry) or send an alert (ntfy). These failures are silent until the day they
are needed. The audit names each dependency and tests the exact path each consumer uses.

It never changes anything and never runs a command inside the node container. It reads the container's files on
the host through `/proc/<pid>/root`. Container-path queries run the **host's** `dig` inside the container's
network namespace (`nsenter -t PID -n`), so the container's AppArmor/seccomp profiles
([`../apparmor`](../apparmor), [`../seccomp`](../seccomp)) never see them.

| File | Purpose |
|---|---|
| `pft-dnsaudit.sh` | `audit`, `names`, `pull`, `validate`, `version` (bash; dig, getent, ss, resolvectl, nsenter, jq for `--json`) |
| `systemd/pft-dnsaudit.{service,timer}` | sandboxed `pft-dnsaudit audit --textfile` every 15 minutes (validator: plus `pull` in the same run) |
| `pft-dnsaudit.env.example` | `/etc/pft-dnsaudit.env`: `HOST_LABEL`, `EXTRA_NAMES`, `NTFY_FILES`, controls, `PULL_SSH` |
| `tests/run-tests.sh` | offline suite, run once per host fixture set (stub dig/getent/ss/resolvectl/docker/nsenter, fake `/proc` + `/etc`) |
| `tests/stub_dig.py` | the dig stub: answers are real dig captures from each host with the queried name swapped in |
| `tests/capture.sh` | how the fixtures were recorded (read-only, on each host; addresses replaced by documentation addresses) |
| `tests/fixtures/{validator,sentry}/` | the captures: `resolvectl dns/status`, `ss -lnu/-lnt`, both `resolv.conf`s, node config sections, apt sources, dig answers |
| `tests/mutate.py` | mutation harness: each mutant disables one check, guard or parser step; the suite must fail on every one |
| `tests/rules-mutants.sh` | alert-rule mutants; `dnsaudit.tests.yml` must fail on each (after a passing unmutated baseline) |
| `../alerts/dnsaudit.rules.yml`, `../alerts/dnsaudit.tests.yml` | 1 digest-only alert + promtool tests (pending, firing, recovery) |

## Critical names

`pft-dnsaudit names` prints them, one `SOURCE NAME` per line. Each name is listed once, under its first source.

| Source | Where it comes from |
|---|---|
| `vl` | hosts of `[validator_list_sites]` in the container's `/etc/postfiatd/validators.txt` and `postfiatd.cfg` |
| `peer` | hostnames (IP literals skipped) in the container's `[ips]` and `[ips_fixed]` |
| `ntfy` | host of `NTFY_SERVER` / `NTFY_URL` in `NTFY_FILES` (default `/etc/postfiat-monitor.env /etc/pft-watchdog/ntfy.env`) |
| `apt` | hosts of `deb` lines and `URIs:` in `/etc/apt/sources.list` and `sources.list.d/` |
| `registry` | registry of the running container's image (`docker.io` images: `registry-1.docker.io`, `auth.docker.io`) |
| `extra` | `EXTRA_NAMES` in the env file, and `--name` on the command line (control runs) |

## Audit

`pft-dnsaudit audit [--json] [--textfile] [--name NAME ...]` prints one line per check. It exits 0 if every check is
PASS/INFO, 1 for any WARN/FAIL, 2 on error and 3 on usage errors. Resolver addresses are never printed: resolvers
are numbered in the order systemd-resolved lists them.

| Check | PASS | WARN / FAIL / INFO |
|---|---|---|
| `source:S` | the source yields at least one name | FAIL no name (or the node container is not running); INFO `peer` lists IP literals only |
| `resolve:NAME` | the host path (`getent ahosts`, i.e. glibc and `/etc/resolv.conf`, what apt/docker/curl use) returns an address | FAIL no address |
| `cresolve:NAME` | `vl` and `peer` names through the container's own nameservers, from inside its network namespace, NOERROR | FAIL with the status (NXDOMAIN, SERVFAIL, TIMEOUT); the next nameserver is tried after a timeout |
| `redundancy` | at least 2 distinct upstream resolvers in systemd-resolved | WARN 1, FAIL 0 |
| `upstream:N` | resolver N answers the first critical name | FAIL with the status |
| `dnssec:upstream:N` | resolver N sets AD on `DNSSEC_GOOD` (ietf.org) and answers SERVFAIL for `DNSSEC_BAD` (dnssec-failed.org), both queried with DO | FAIL "does not validate" (no AD and bogus answered) or "inconsistent" (any other mix) |
| `dnssec:stub` | the host path refuses `DNSSEC_BAD` | FAIL the host path returned an address for it |
| `dnssec:container` | the container path refuses `DNSSEC_BAD` (SERVFAIL). The query uses the flags the container's glibc would send: AD only when its `resolv.conf` has `options trust-ad` | FAIL with the status |
| `dnssec:signed` | INFO: how many critical names are DNSSEC-signed (AD from the first validating upstream) | INFO "no validating upstream" |
| `llmnr` | no listener on 5355 (UDP or TCP) and resolved's **global** LLMNR is off (per-link `+LLMNR` is inert while the global setting is off) | FAIL listener; WARN global on, or unreadable |
| `mdns` | no UDP listener on 5353 and resolved's global mDNS is off | FAIL listener; WARN global on, or unreadable |
| `stub` | `/etc/resolv.conf` is resolved's `stub-resolv.conf` with `nameserver 127.0.0.53` only | WARN any other file or an extra nameserver; FAIL no nameserver |
| `embedded` | the container's `resolv.conf`: Docker's embedded DNS (`127.0.0.11`) with an `ExtServers` record (user-defined network), or at least 2 direct nameservers (default bridge) | WARN embedded DNS without `ExtServers`, or 1 nameserver; FAIL none, or the container is not running |

**Operator acceptance.** An unexpired line `CHECK UNTIL REASON` in `/etc/pft-dnsaudit.accept` (`UNTIL` = epoch
seconds or `YYYY-MM-DD`, UTC) turns that check's WARN/FAIL into INFO `accepted until ... (REASON); was FAIL: ...`.
It also counts in `pft_dnsaudit_accepted`. A line whose time has passed (an acceptance ending exactly now counts
as passed) is ignored, and the check says so. PASS checks are never touched.

**Negative controls.** `--name NAME` adds a control name (for example `pft-control.invalid`, which can never
resolve). It refuses `--textfile` (exit 3), so a control run can never change the metrics.

## Metrics and alert

`--textfile` writes `pft_dnsaudit_HOST.prom` atomically (temp file + rename) to `/var/lib/pft-exporter/textfile`.
On the validator, the unit's `ExecStartPost` also pulls the sentry's file (`pft-dnsaudit pull`). The pull accepts
only `pft_dnsaudit_` samples whose first label is `host="PEER"`, up to 32 KiB, with an `up` and a `last_run`
sample. A failed fetch or validation keeps the old copy, so a dead peer goes stale instead of looking healthy.

| Metric | Meaning |
|---|---|
| `pft_dnsaudit_up{host}` | 1 if the last audit completed (0 when dig/getent/resolvectl are missing; no findings series then) |
| `pft_dnsaudit_last_run_timestamp_seconds{host}` | when the last audit ran |
| `pft_dnsaudit_duration_seconds{host}` | wall time of the last audit |
| `pft_dnsaudit_check_status{host,check}` | per check: 0 PASS, 1 INFO (incl. accepted), 2 WARN, 3 FAIL |
| `pft_dnsaudit_checks{host,status}` | checks per status |
| `pft_dnsaudit_names{host,source}` | critical names per source |
| `pft_dnsaudit_upstream_resolvers{host}` | distinct upstream resolvers |
| `pft_dnsaudit_signed_names{host}` | critical names that are DNSSEC-signed |
| `pft_dnsaudit_accepted{host}` | checks turned into INFO by the acceptance file |

### Alerts

| Alert | Condition | Routing |
|---|---|---|
| `PFTDNSAuditFinding` | `max by (host) (pft_dnsaudit_check_status) >= 2 or max by (host) (pft_dnsaudit_up) == 0` for 30m (two audits) | `notify: digest`, severity info: Alertmanager keeps it out of the paging route (daily digest only) |

DNS findings are posture, not outages. When a critical name really stops resolving, the alerts that already page
(node state, peers, apt/vulnscan feed age, the alert pipeline watchdog) show it first. A stale or missing
textfile is [`../rulecheck`](../rulecheck)'s job:
`textfile pft_dnsaudit_*.prom 45m pft_dnsaudit_last_run_timestamp_seconds` (3 runs), plus `require` lines for
each host's file.

## Install (through ../fleet) and rollback

The files are deployed with [`../fleet`](../fleet) (`manifest.tsv` rows `dnsaudit`, both roles), inside a
`pft-maint` window, sentry first:

```bash
sudo pft-fleet sync --addon fleet    --to COMMIT --apply --reason "..."   # pft-fleet reads its installed manifest copy
sudo pft-fleet sync --addon aptrust  --to COMMIT --apply --reason "..."   # aptrust's off-package allowlist is a copy too
sudo pft-fleet sync --addon dnsaudit --to COMMIT --apply --reason "..."
# per host: env file, one run through the sandboxed unit (textfile first), then the timer
printf 'HOST_LABEL=sentry\n' | sudo install -m 600 /dev/stdin /etc/pft-dnsaudit.env    # validator: HOST_LABEL=validator
sudo systemctl start pft-dnsaudit.service && sudo systemctl enable --now pft-dnsaudit.timer
# validator only: PULL_SSH in /etc/pft-dnsaudit.env + the pull drop-in, then one more run
printf '[Service]\nEnvironment=PFT_DA_PULL=1\n' | sudo install -D -m 644 /dev/stdin /etc/systemd/system/pft-dnsaudit.service.d/pull.conf
# only now: the rule file in prometheus.yml + Prometheus reload, so the rule's series exist when it loads
sudo pft-schedaudit accept --reason "..." && sudo pft-schedaudit collect   # new timer; then pft-integrity accept for env/drop-in
```

Rollback, per host: `sudo systemctl disable --now pft-dnsaudit.timer`, then `sudo pft-jobwatch forget
pft-dnsaudit.timer`. Remove the drop-in, `/etc/pft-dnsaudit.env`, the textfile(s) and
`/var/lib/systemd/timers/stamp-pft-dnsaudit.timer`. Then `pft-fleet sync` to a commit without the `dnsaudit` rows
(or delete the three installed files), remove the `prometheus.yml` and rulecheck lines, reload Prometheus, and run
`pft-schedaudit accept` + `collect` and `pft-integrity accept`. Nothing else on the host depends on it.

## Tests

```bash
TEST_TMPDIR=$HOME/.cache bash dnsaudit/tests/run-tests.sh         # offline suite, both host fixture sets
TEST_TMPDIR=$HOME/.cache python3 -I dnsaudit/tests/mutate.py -j 4  # every mutant must be caught
TEST_TMPDIR=$HOME/.cache bash dnsaudit/tests/rules-mutants.sh      # alert-rule mutants (promtool in the local prom/prometheus:v3.5.0 image)
shellcheck dnsaudit/*.sh dnsaudit/tests/*.sh && (cd dnsaudit && ruff check . && ruff format --check .)
```

The baseline in each fixture set is the live capture of that host, with every path validating. Every check then
gets a control input that must make exactly that check WARN/FAIL with its specific reason. The suite also checks
that the script never runs `docker exec` (the docker stub accepts `inspect` only). Container-path queries must go
through `nsenter` to the container's nameservers. Resolver addresses never appear in the output or the textfile.
