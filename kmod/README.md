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
| mutation pass 2 | see log | [`logs/04-mutants.log`](logs/04-mutants.log) |
| alert-rule mutants (`tests/rules-mutants.sh`) | unmutated tests SUCCESS first, then **8/8 killed** (thresholds, both `for`s, the loaded, required and autoload terms, the up term). The first attempt stopped at its baseline check: the promtool container (user nobody) could not read a 0700 temp dir, so every mutant would have "failed" | [`logs/05-rule-mutants.log`](logs/05-rule-mutants.log) |


### Live proof (sentry first, then validator)

`drill/live-run.sh sentry|validator` (on the validator, from a clean committed HEAD that is pushed after the rollout) drives `drill/host-run.sh` on each
host. Before any change it points every notifier at a throwaway ntfy topic, opens a pft-maint window and creates an
Alertmanager silence that excludes the pipeline watchdog. It restores all three on exit. Results are added here as
they are produced. Only found → fixed → verified results are published.
