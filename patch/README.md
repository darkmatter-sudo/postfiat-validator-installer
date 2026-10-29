# patch/ — controlled OS patching for a validator + sentry

`pft-patch.sh` moves Ubuntu updates and reboots on a Post Fiat node host out of the random daily
unattended-upgrades slot and into a planned, gated, sentry-first maintenance window.

Why: on a stock Ubuntu 22.04 node host, `unattended-upgrades` installs packages from
`${distro_codename}` and `${distro_codename}-security` every day at a random time, with an empty
`Package-Blacklist`. `docker.io`, `containerd` and `runc` come from the Ubuntu archive, so an unattended
upgrade of one of them restarts dockerd/containerd, i.e. restarts postfiatd at an unplanned moment,
outside any maintenance window and without a health gate. Reboots needed by kernel updates are never
taken at all unless someone notices `/var/run/reboot-required`.

> Status: build 1 (`status`, `policy`). The gated `run` mode and the live two-host proof follow in
> build 2; this README is extended then.

## Modes

| command | changes the host? | what it does |
|---|---|---|
| `pft-patch status [--json]` | no | pending updates by class, holds, reboot/kernel state, services on old libraries, unattended Docker-runtime exposure |
| `pft-patch policy show` | no | prints the apt drop-in `policy apply` would install |
| `sudo pft-patch policy apply --yes` | yes | installs `/etc/apt/apt.conf.d/52pft-patch`, checks the **effective** apt config, backs up first |
| `sudo pft-patch policy rollback --yes` | yes | restores the state before the newest apply, checks it byte for byte |

### status

`status` only reads: `apt-get -s -o Debug::NoLocking=1 dist-upgrade` (a simulation that takes no lock),
`apt-mark showhold`, `/var/run/reboot-required(.pkgs)`, `needrestart -b -r l` (list mode, restarts
nothing), `apt-config dump` and `dpkg-query`. The offline suite checks that the fake host's files are
unchanged after `status` and that `apt-get` is only ever called with `-s`.

| item | OK | WARN (exit 1) | CRIT (exit 2) |
|---|---|---|---|
| updates | none pending | non-security updates pending (kernels counted) | any update whose candidate comes from a `*-security` pocket |
| holds | no holds | held packages, none with an update | a held package has an update waiting |
| reboot | no flag | | `/var/run/reboot-required` present (packages listed) |
| kernel | needrestart KSTA 1 | KSTA 2/3: a newer kernel is installed but not running | |
| services | none | services still running old libraries | |
| exposure | every installed runtime package is blacklisted | an installed Docker runtime package (`docker.io docker-ce docker-ce-cli containerd containerd.io runc`) is not in the effective `Unattended-Upgrade::Package-Blacklist` | |
| autoreboot | `Automatic-Reboot` false (default) | `Automatic-Reboot` true | |

An update counts as security when its candidate's origin list contains a `-security` pocket
(`Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security`); third-party repos are "other".
needrestart only reports the kernel state as root; run without root, `status` says so (INFO) instead of
reporting a clean kernel. `--json` gives the same data as one object (`result`, `exit`, `updates`,
`holds`, `reboot_required`, `needrestart`, `unattended`, `items`).

### policy

The drop-in keeps unattended **security** updates on for everything else and only takes out the two
things that touch postfiatd:

```
Unattended-Upgrade::Package-Blacklist {
    "docker.io"; "docker-ce"; "docker-ce-cli"; "containerd"; "containerd.io"; "runc";
};
Unattended-Upgrade::Automatic-Reboot "false";
```

- apt merges lists across `apt.conf.d` files and the last file wins for a scalar. A later file (say
  `99local` with `Automatic-Reboot "true"`) would silently beat ours, so `apply` re-reads the
  **effective** config with `apt-config dump` after installing the file. If any runtime package is not
  blacklisted or Automatic-Reboot is not false, it puts the previous state back and exits 4.
- unattended-upgrades matches blacklist entries as Python regexes with `re.match` (anchored at the
  start, not the end). `status` uses the same rule, so `docker` covers `docker.io` but `io` does not.
- Before writing, `apply` stores in `/var/lib/pft-patch/backup/<UTC stamp>/` the drop-in's previous
  bytes (or an `absent` marker) and the sha256 of the full `apt-config dump`. `rollback` restores the
  newest backup and requires both the drop-in sha256 and the `apt-config dump` sha256 to equal the
  recorded ones (exit 5 otherwise, backup kept). A second `apply` with the same content is a no-op and
  makes no backup.

Exit codes: `status` 0/1/2 as above. `policy`: 0 done or already applied, 2 error, 3 usage,
4 refused (not root, no `--yes`, not effective), 5 rollback mismatch.

## Tests

```bash
bash patch/tests/run-tests.sh        # 58 stubbed tests: no root, no apt, no network
bash patch/tests/mutate.sh           # 24 mutants; the unmutated control must pass first
shellcheck -x patch/pft-patch.sh patch/tests/*.sh
```

The stub `apt-config` parses the fake host's `apt.conf.d` files in name order the way apt does for the
two forms used here (lists append, the last scalar wins), so the override and rollback tests run
against a real effective-config computation rather than a canned answer.
