# kmod: kernel-module attack-surface audit and hardening

`pft-kmod.sh` audits which kernel modules a Post Fiat validator or sentry host (Ubuntu 22.04, postfiatd 1.0.9 in
Docker) could load that it never uses, and denies them in one managed modprobe.d file. This follows CIS Ubuntu 22.04
1.1.1.x (unused filesystems, usb-storage) and 3.4.x (uncommon network protocols). The deny list is checked against
what the host actually loads and needs, so a rule cannot break Docker networking, overlayfs, netfilter/ufw, AppArmor,
auditd or chrony. It complements [`../sysctl`](../sysctl) (kernel and network sysctls) and
[`../audittrail`](../audittrail) (audit rules for module loads).

Why it matters: many kernel local privilege escalations were reachable from an unprivileged process only because
the kernel autoloads a protocol module on the first `socket()` call: DCCP (CVE-2017-6074), RDS (CVE-2010-3904),
TIPC (CVE-2021-43267), n_hdlc (CVE-2017-2636). Ubuntu's `blacklist-rare-network.conf` only blacklists some of them.
A blacklist line stops alias matching only. An explicit `modprobe` still loads the module, and so does a module
that depends on it. `install M /bin/false` blocks both.

| File | Purpose |
|---|---|
| `pft-kmod.sh` | `audit`, `list`, `apply`, `rollback`, `pull`, `validate` (bash + jq, no other dependency) |
| `install.sh` | installs the script and the hourly timer; `--pull` makes the validator's run also copy the sentry's textfile |
| `systemd/pft-kmod.{service,timer}` | hourly sandboxed `pft-kmod audit --textfile` (validator: plus `pull` in the same run) |
| `pft-kmod.env.example` | `/etc/pft-kmod.env`: `HOST_LABEL`, `KEEP`, `EXTRA_DENY`, `EXTRA_REQUIRED`, `PULL_SSH` |
| `tests/run-tests.sh` | offline suite (stub modprobe/docker/pft-maint, fake `/proc`), 109 assertions |
| `tests/stub_modprobe.py` | the stub: fake modprobe.d, module tree with dependencies, `modules.builtin` |
| `tests/mutants.py` | mutation harness: 24 mutants, each disables one guard or check; the suite must fail on every one |
| `tests/rules-mutants.sh` | 8 alert-rule mutants; `kmod.tests.yml` must fail on each (after a passing unmutated baseline) |
| `drill/live-run.sh`, `drill/host-run.sh` | recorded two-host rollout (sentry first, sentry reboot, rollback/re-apply) |
| `../alerts/kmod.rules.yml`, `../alerts/kmod.tests.yml` | 2 alerts + promtool tests (firing and recovery) |

## Deny list

`pft-kmod list` prints it. Every entry is written as `install M /bin/false` + `blacklist M` to
`/etc/modprobe.d/60-pft-kmod.conf`.

| Class | Modules |
|---|---|
| filesystems (CIS 1.1.1.1-1.1.1.7) | cramfs freevxfs jffs2 hfs hfsplus udf |
| storage (CIS 1.1.1.8) | usb-storage |
| network (CIS 3.4.1-3.4.4) | dccp sctp rds tipc |
| network (uncommon, also in Ubuntu's blacklist-only file) | atm can ieee802154 appletalk x25 ax25 netrom rose |
| tty | n_hdlc |

**Not on the list:** `squashfs` (snapd and LXD mount snaps with it, and it is built into Ubuntu kernels) and
`overlay` (Docker overlay2). Add host-specific exceptions with `KEEP="usb-storage"` and more modules with
`EXTRA_DENY`.

## Audit

`pft-kmod audit [--json] [--textfile]` is read-only. It prints one line per check and exits 0 for PASS, 1 for any
WARN/FAIL, 2 on error.

| Check | PASS | WARN / FAIL / INFO |
|---|---|---|
| `deny:M` | the effective config (`modprobe -c`) has `install M /bin/false` and M is not loaded | FAIL loaded (`/proc/modules`); FAIL loadable (in the module tree, no rule); WARN absent from this kernel's tree and no rule (a later `linux-modules-extra` install would make it loadable); INFO built in (modprobe.d cannot deny it) |
| `autoload` | `kernel.modprobe` is a modprobe binary, so kernel autoload requests go through the install rules | FAIL otherwise (autoload bypasses modprobe.d); INFO if `modules_disabled=1` |
| `required` | every REQUIRED module (Docker bridge/veth/NAT, overlay, netfilter/iptables/nft, kTLS, xfrm netlink) and every loaded module resolves (`modprobe --show-depends`) to insmod/builtin lines only | FAIL `required:M` if an install rule blocks M or one of its dependencies (any file, not only ours) |
| `managed` | `60-pft-kmod.conf` matches what apply would write | WARN missing or drifted |

AppArmor, audit and the clock discipline chrony uses are built into the Ubuntu kernel (no module to block). The
required set is still derived from the live `/proc/modules`, so whatever a host loads today (zfs for LXD, for example) is protected, and so are its dependencies.

## Apply and rollback

```
sudo pft-maint start --ttl 30m --reason "kmod apply"
sudo pft-kmod apply --dry-run        # guards + diff, writes nothing, needs no window
sudo pft-kmod apply --yes
sudo pft-kmod audit                  # deny 20: 20 enforced
sudo pft-kmod rollback --yes         # byte-identical restore (or removal) of the previous file
```

`apply` refuses (exit 4, nothing written) when:

- `--yes` is missing;
- there is no active pft-maint window, the window has less than `MAINT_MIN` (600 s) left, or a data-collection
  lock is held;
- the node is not full, has fewer than `MIN_PEERS` peers, or its container is not running
  (`docker exec <container> postfiatd server_info`);
- `kernel.modprobe` is not modprobe;
- a deny-list module is loaded, built in, REQUIRED, or a dependency of a required or loaded module. The required
  closure is the set plus every insmod line of its `--show-depends`;
- the last apply is still in place.

It then backs up an existing file (bytes, mode, mtime), writes the new one and verifies:

- every deny module resolves to `install /bin/false`;
- the required set is still unblocked;
- the node is still full with peers, and the container is running.

Any verify failure restores the previous file byte-identical and exits 1. `VERIFY_INJECT=required` forces that path
for drills. Nothing is loaded or unloaded: a module that is already loaded refuses the apply instead.

modprobe.d is read at every load request, so no reboot or initramfs rebuild is needed. None of the listed modules
is in the Ubuntu initramfs. The reboot drill below proves the rules persist.

`rollback` restores the backup (or removes the file if there was none), checks the sha256 against the one recorded at
apply (exit 5 on mismatch), archives the apply record and re-runs the required check.

## Metrics and alerts

The hourly `pft-kmod.timer` (:23 + up to 5 min) writes `pft_kmod_HOST.prom`, about 1.4 KB. The validator's run also
pulls the sentry's file over `PULL_SSH` (validated: only `pft_kmod_` samples with `host="sentry"` first, at most
16 KiB, `up` and `last_run` present). That way the pull needs no second timer: every timer adds about 1.1 KB to
pft-jobwatch's textfile, which is close to its budget.

| Metric | Meaning |
|---|---|
| `pft_kmod_up`, `pft_kmod_last_run_timestamp_seconds` | audit completed / when |
| `pft_kmod_deny_modules{state=enforced\|loaded\|loadable\|absent\|builtin}` | deny-list modules by state |
| `pft_kmod_required_blocked` | required/loaded modules whose resolution hits an install rule |
| `pft_kmod_autoload_ok`, `pft_kmod_managed` | kernel.modprobe is modprobe / managed file matches |

### Alerts

| Alert | Fires when |
|---|---|
| `PFTKmodFinding` | loaded + loadable deny modules + required blocked + autoload bypass > 0 for 15 min |
| `PFTKmodAuditStale` | `up == 0` for 10 min, or no audit for 3 h (timer stopped, or the sentry's pull failing) |

`promtool test rules kmod.tests.yml` covers firing, recovery after apply, a fully applied host that never fires, a
10-minute blip that never fires, required/autoload terms, audit failure and recovery, and staleness.

## Tests

```
TEST_TMPDIR=~/.cache bash kmod/tests/run-tests.sh            # 109 assertions, no root, nothing on the host changes
TEST_TMPDIR=~/.cache python3 -I kmod/tests/mutants.py -j 3   # every mutant must be CAUGHT
```

Every apply/rollback guard has its own test, and each test's input passes every other guard. Example: the "REQUIRED"
test denies `br_netfilter`, which is required but not loaded, so it hits the REQUIRED guard and not the loaded
guard.

## Results

| Step | Result | Log |
|---|---|---|
| lint + promtool + offline suite | shellcheck and ruff clean; `promtool test rules kmod.tests.yml` SUCCESS; suite 107/107 | [`logs/01-suite.log`](logs/01-suite.log) |
| mutation pass 1 | **22/24 caught, 2 survived** (real gaps): M14, because no test had a later modprobe.d file overriding our rule, so post-apply verify was never exercised; M22, because the "too big" fixture was also malformed, so the content check refused it before the size cap could | [`logs/02-mutants.log`](logs/02-mutants.log) |
| tests for both gaps | `99-override.conf` (`install dccp /sbin/modprobe --ignore-install dccp`) must fail verify and restore; an oversized file made only of valid samples, plus an under-cap control; suite 109/109 | [`logs/03-suite.log`](logs/03-suite.log) |
| mutation pass 2 | 24/24 caught (M14 by the override test, M22 by the 21551-byte valid file) | [`logs/04-mutants.log`](logs/04-mutants.log) |
| alert-rule mutants (`tests/rules-mutants.sh`) | unmutated tests SUCCESS first, then **8/8 killed** (thresholds, both `for`s, the loaded, required and autoload terms, the up term). The first attempt stopped at its baseline check: the promtool container (user nobody) could not read a 0700 temp dir, so every mutant would have "failed" | [`logs/05-rule-mutants.log`](logs/05-rule-mutants.log) |
| node check fix | a read-only dry run on the hosts showed `postfiatd server_info` in the container needs `--conf /etc/postfiatd/postfiatd.cfg` (without it the image reads /etc/opt/postfiat and fails), so the node gate would always refuse. Fixed in pft-kmod and both drill scripts; the stub docker now fails without `--conf` like the real image; suite 109/109 | [`logs/07-suite-conf-fix.log`](logs/07-suite-conf-fix.log) |
| mutation pass 3 (after the fix) | 24/24 caught | [`logs/08-mutants.log`](logs/08-mutants.log) |


### Live proof (sentry first, then validator)

`drill/live-run.sh sentry|validator` (on the validator, from a clean committed HEAD that is pushed after the rollout) drives `drill/host-run.sh` on each
host. Before any change it points every notifier at a throwaway ntfy topic, opens a pft-maint window and creates an
Alertmanager silence that excludes the pipeline watchdog. It restores all three on exit, and expires the silence only
when nothing is pending in Prometheus and 25 min have passed since the reboot (PFTContainerRestarted's window). Only
found → fixed → verified results are published.

| step | result | log |
| --- | --- | --- |
| sentry run 11 | **stopped at setup, nothing changed**: ssh joins its arguments into one remote shell line, so the `;` in the sed script split it and the sentry's notifier files were never redirected. The run restored every file (sha256 equal) and expired its silence. Fixed by quoting per host (`printf %q` for ssh only; the same fix for `--reason '...(...)'`) and by keeping the sentry copy outside `/tmp`, which tmpfiles empties at boot. Both helpers were dev-checked on scratch files on both hosts before the next run | [`logs/09-live-sentry-run11-setup-stopped.log`](logs/09-live-sentry-run11-setup-stopped.log) |
| sentry: install, apply | before: `deny 20: 0 enforced, 13 loadable, 7 absent` (exit 1); dccp `insmod` in dry run. After apply: `deny 20: 20 enforced, 0 loadable` (exit 0); `modprobe dccp` and `modprobe cramfs` refused (`install /bin/false`); SCTP `socket()` fails with `Protocol not supported`; crc7 (not on the list) loads and unloads; required closure (97 modules) unblocked; node `full 22` before and after, container networks/ports hash and egress 200 unchanged | [`logs/10-live-sentry.log`](logs/10-live-sentry.log) |
| sentry reboot | boot_id changed, back over ssh in 76 s, `full` 2 min 21 s after the reboot command; audit PASS 20 enforced, no deny module loaded, dccp still refused | same log, section 4 |
| sentry rollback + re-apply | rollback restores the pre-apply state (file absent) and the audit shows 13 loadable again; re-apply writes a file byte-identical to the first apply; PASS; dccp refused again | same log, section 5 |
| sentry integrity after the reboot | the run's last check FAILed: pft-integrity WARNed on one sshd config file, **mtime only** (sha256 unchanged). Cause, traced via auditd: the hosting provider's cloud-init boot command rewrites that file at every boot with identical content; effective sshd settings were confirmed unchanged. Explained by the planned reboot, so accepted into the baseline; verify PASS | [`logs/11-sentry-integrity-after-reboot.log`](logs/11-sentry-integrity-after-reboot.log) |
| validator: install, apply, rollback + re-apply, pull | same before/after (13 loadable → 20 enforced), refused dccp/cramfs/SCTP, crc7 control, required closure 111 unblocked, node `full 14` and network hash unchanged throughout; rollback byte-identical, re-apply identical; `install --pull` brings the sentry's `pft_kmod_up 1` into the validator textfile; **0 checks failed** | [`logs/12-live-validator.log`](logs/12-live-validator.log) |
| Prometheus | `promtool check config` with kmod.rules.yml listed: SUCCESS; `promtool test rules kmod.tests.yml`: SUCCESS; both rule expressions evaluated empty on live data before the reload; after SIGHUP both rules `ok`/inactive | [`logs/13-promtool-config.log`](logs/13-promtool-config.log), [`logs/14-prometheus-reload.log`](logs/14-prometheus-reload.log) |
| pft-fleet | manifest tracks pft-kmod; first sync refused without a pft-maint window (by design), then synced inside one (throwaway topic); skew `kmod CURRENT` on both hosts, `CURRENT=65 BEHIND=0 DIVERGED=0`; integrity PASS both | [`logs/15-fleet-skew-before-sync.log`](logs/15-fleet-skew-before-sync.log), [`logs/16-fleet-sync.log`](logs/16-fleet-sync.log) |
| operator topics | read back every real notifier topic on both hosts and the agent's own topic: 0 messages since 18:05Z (drill notifications went to throwaway topics only: `[MAINT]` start/end) | [`logs/17-operator-topic-readback.log`](logs/17-operator-topic-readback.log) |

| final lint + suite | shellcheck (every kmod script, drills included) and ruff clean; offline suite 109/109 on the rollout HEAD | [`logs/18-final-lint-suite.log`](logs/18-final-lint-suite.log) |
| fresh public clone | anonymous clone at the pushed commit: shellcheck clean, suite 109/109, promtool SUCCESS, installed `pft-kmod` equal to the repo copy on both hosts, logs 10-12 byte-identical to the raw runs. The first attempt ran in `/tmp`, which is noexec on this host, so every script exec was refused (22/109); re-run from a 0755 dir under the agent's home | [`logs/20-public-clone-verify.log`](logs/20-public-clone-verify.log), [`logs/19-public-clone-attempt1-tmp-noexec.log`](logs/19-public-clone-attempt1-tmp-noexec.log) |

Two jobs on the validator that pull from the sentry (keyescrow, upgradewatch) failed while the sentry rebooted; they
were re-run once it was back, and PFTJobFailed cleared under the run's silence.
