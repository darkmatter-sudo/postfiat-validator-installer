# sshban: fail2ban for keys-only Post Fiat hosts

Internet scanners hit port 22 on every public host. On a keys-only validator or sentry (PasswordAuthentication no)
they cannot get in, but they fill the journal and, before this add-on, tripped `PFTAuthFailedBurst` (../authwatch)
several times a day (peak 444 failed attempts per 10 min on the sentry, 2026-11-09). `sshban` bans a source after 5
failed attempts in 10 min, for 1 h, doubling on every repeat up to a week.

| File | What it does |
|---|---|
| `pft-sshd.jail` | `[sshd]` jail: `backend = systemd` (journal, `_COMM=sshd`), `mode = aggressive` (invalid users, preauth aborts, failed negotiation), `maxretry 5`, `findtime 10m`, `bantime 1h`, `bantime.increment` x2 up to `1w`, `banaction = iptables-multiport` |
| `install.sh` | `sudo ./install.sh [--ignore CIDR]...` installs `fail2ban` from the Ubuntu archive, writes `/etc/fail2ban/jail.d/pft-sshd.local` (template + `ignoreip = 127.0.0.1/8 ::1 CIDR...`), `fail2ban-client -t`, restarts, prints the jail status (ban list redacted). `--check` prints the status only, `--uninstall` removes the jail file and stops fail2ban. Idempotent |

Design choices:

- **No sshd changes.** Key and password settings are never touched; a successful key login never counts as a failure,
  so the validator -> sentry admin link (several sessions a minute) cannot be banned. The peer host is also put in
  `ignoreip` (`--ignore`), and so are the operator's usual admin sources. Addresses are passed at install time and
  live only in the root-owned jail file, never in this repo.
- **Runtime-only bans.** `iptables-multiport` adds a `f2b-sshd` chain to `INPUT`; ufw's `user.rules` (hashed by
  `../integrity`, archived by `../backup`) and the `DOCKER-USER` chain stay unchanged, so bans never show up as drift.
- **Not `ufw limit 22/tcp`.** ufw's limit is per connection (6 in 30 s), which the admin link and the pull timers
  exceed; fail2ban only counts failed authentication.
- What still pages is in `../authwatch`: any login with an unknown key or without a key (`PFTAuthUnknownKeyLogin`;
  the unknown-source alert was removed 2026-11-09). Routine brute force is summarised at most once a
  day (`pft-authwatch digest`).

Install (each host, peer address first; keep an SSH session open and test a fresh key login before closing it):

```bash
sudo ./sshban/install.sh --ignore <peer-ip>
sudo ./sshban/install.sh --check
```

## Logs

| Log | What it shows |
|---|---|
| [`logs/01-install-two-hosts.log`](logs/01-install-two-hosts.log) | install on the sentry and the validator, sshd auth settings unchanged before/after, fresh key login to the sentry after the change, jail status, bans after the first hours |
