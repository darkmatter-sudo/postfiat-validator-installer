# pft-sshcrypto: SSH crypto-policy audit and safe hardening

`../audit` checks how sshd lets people in (root login, passwords, MaxAuthTries). This add-on checks **what crypto
sshd negotiates**: key exchange, ciphers, MACs, host key algorithms and host key sizes. It grades every offered item
OK / WARN / FAIL against a written policy, proves with loopback-only handshakes that the running daemon really
negotiates what its config says, and can apply a hardened policy without risking a lockout: validated drop-in,
`reload` (never restart), a new-session login check, and a timer that rolls the change back by itself unless the
new session is confirmed. Rollback is byte-identical (sha256 of every sshd config file and of `sshd -T`).

Tested on Ubuntu 22.04.5 with OpenSSH 8.9p1, on a validator host and a sentry host.

**One Prometheus for both hosts** (same design as `../vulnscan`, `../rulecheck`): each host audits itself every
hour; `pft-sshcrypto pull` on the validator copies the sentry's textfile over the existing admin ssh link
(validated, all-or-nothing) and the validator's Prometheus alerts on both (`host="validator"`, `host="sentry"`).
The sentry runs no Prometheus or Alertmanager of its own.

## Usage

```
pft-sshcrypto audit [--json] [--no-probe] [--textfile-dir DIR]   grade sshd -T + host keys, loopback probes
sudo pft-sshcrypto apply [--policy FILE] [--revert-after SECS]   install the policy drop-in (auto-revert armed)
sudo pft-sshcrypto rollback [--auto]                             restore the pre-apply files byte-identically
pft-sshcrypto status                                             state, snapshot, armed revert timer
sudo pft-sshcrypto pull                                          validator: copy the sentry's textfile
pft-sshcrypto validate FILE HOST                                 check a textfile before it is served
pft-sshcrypto policy-table                                       print the policy table below
```

| command | exit 0 | exit 1 | exit 2 | exit 3 |
|---|---|---|---|---|
| audit | every graded item OK, 0 probe mismatches | at least one WARN or FAIL item, or a probe mismatch | audit error: `sshd -T` failed, a host key unreadable, a probe could not run, no loopback listener | - |
| apply | applied and confirmed, timer stopped | - | refused before any reload (bad policy, `sshd -t` failed, policy shadowed by an earlier drop-in, timer could not be armed, a revert already armed); the file was restored | reloaded but NOT confirmed: the armed timer rolls back at the deadline |
| rollback | restored, sha256-identical, new session confirmed | - | nothing to roll back, or a check failed | - |

Text output: one line per offered algorithm (`kind grade name reason`), one per host key (type and bits only: no
paths, no fingerprints), one per probe, then a `RESULT:` line. `--json` prints one object with `result`, `exit`,
`counts`, `algorithms[]`, `hostkeys[]`, `probes[]`, `probe_mismatches` and `errors[]`.

## Policy

Graded lists: `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms` (fully), `PubkeyAcceptedAlgorithms` and
`CASignatureAlgorithms` (only SHA-1 and DSA are graded there: narrowing user-key algorithms can lock out existing
keys, so the policy never changes them). The first matching row wins (`pft-sshcrypto policy-table` prints this table
from the code, `sshcrypto_grade.py`):

| Kind | Algorithm (`*` = prefix/substring) | Grade | Why |
|---|---|---|---|
| kex | `sntrup761x25519-sha512@openssh.com` | OK | hybrid post-quantum + X25519 |
| kex | `curve25519-sha256` | OK | X25519 |
| kex | `curve25519-sha256@libssh.org` | OK | X25519 (pre-RFC name) |
| kex | `diffie-hellman-group16-sha512` | OK | 4096-bit fixed group |
| kex | `diffie-hellman-group18-sha512` | OK | 8192-bit fixed group |
| kex | `diffie-hellman-group-exchange-sha256` | OK | OK only if every /etc/ssh/moduli entry is >= 3072 bits |
| kex | `diffie-hellman-group14-sha256` | WARN | 2048-bit group |
| kex | `ecdh-sha2-nistp*` | WARN | NIST P-curves |
| kex | `*sha1*` | FAIL | SHA-1 exchange hash |
| cipher | `chacha20-poly1305@openssh.com` | OK | AEAD |
| cipher | `aes256-gcm@openssh.com` | OK | AEAD |
| cipher | `aes128-gcm@openssh.com` | OK | AEAD |
| cipher | `aes256-ctr` | OK | CTR (MAC must be EtM) |
| cipher | `aes192-ctr` | OK | CTR (MAC must be EtM) |
| cipher | `aes128-ctr` | OK | CTR (MAC must be EtM) |
| cipher | `*-cbc*` | FAIL | CBC mode |
| cipher | `arcfour*` | FAIL | RC4 |
| cipher | `blowfish*` | FAIL | 64-bit block |
| cipher | `cast128*` | FAIL | 64-bit block |
| mac | `hmac-sha2-512-etm@openssh.com` | OK | encrypt-then-MAC |
| mac | `hmac-sha2-256-etm@openssh.com` | OK | encrypt-then-MAC |
| mac | `umac-128-etm@openssh.com` | OK | encrypt-then-MAC |
| mac | `umac-64-etm@openssh.com` | WARN | 64-bit tag |
| mac | `hmac-sha2-512` | WARN | encrypt-and-MAC |
| mac | `hmac-sha2-256` | WARN | encrypt-and-MAC |
| mac | `umac-128@openssh.com` | WARN | encrypt-and-MAC |
| mac | `umac-64@openssh.com` | FAIL | 64-bit tag, encrypt-and-MAC |
| mac | `*sha1*` | FAIL | SHA-1 |
| mac | `*md5*` | FAIL | MD5 |
| mac | `*ripemd*` | FAIL | RIPEMD-160 |
| hostkey | `ssh-ed25519` | OK | Ed25519 |
| hostkey | `ssh-ed25519-cert-v01@openssh.com` | OK | Ed25519 certificate |
| hostkey | `sk-ssh-ed25519*` | OK | Ed25519 (FIDO) |
| hostkey | `rsa-sha2-512*` | OK | RSA/SHA-512 (key size graded separately) |
| hostkey | `rsa-sha2-256*` | OK | RSA/SHA-256 (key size graded separately) |
| hostkey | `ecdsa-sha2-nistp*` | WARN | NIST P-curves |
| hostkey | `sk-ecdsa-sha2-nistp*` | WARN | NIST P-curves (FIDO) |
| hostkey | `ssh-rsa*` | FAIL | RSA/SHA-1 signature |
| hostkey | `ssh-dss*` | FAIL | DSA |
| pubkey | `ssh-rsa*` | FAIL | RSA/SHA-1 signature |
| pubkey | `ssh-dss*` | FAIL | DSA |
| pubkey | `*` | OK | user-key algorithms: only SHA-1/DSA graded |
| casig | `ssh-rsa*` | FAIL | RSA/SHA-1 signature |
| casig | `ssh-dss*` | FAIL | DSA |
| casig | `*` | OK | CA signature algorithms: only SHA-1/DSA graded |
| any | anything else | WARN | not in policy |
| hostkey-file | RSA >= 3072 / 2048-3071 / < 2048 bits | OK / WARN / FAIL | key size |
| hostkey-file | ED25519 / ECDSA / DSA | OK / WARN / FAIL | key type (graded only if offered) |

Host key files are graded only if the server offers an algorithm that uses them (an ECDSA key that no offered
algorithm uses is `UNUSED`, not a finding).

**The hardened policy** (`hardened.conf`, written to `/etc/ssh/sshd_config.d/10-pft-sshcrypto.conf`; `10-` so it
precedes other drop-ins, because sshd takes the first value it reads) keeps only OK items:

```
# pft-sshcrypto hardened policy (OpenSSH 8.9, Ubuntu 22.04). Only algorithms graded OK by sshcrypto_grade.py.
# Dropped vs the 8.9 defaults: ecdh-sha2-nistp*, diffie-hellman-group14-sha256, diffie-hellman-group-exchange-sha256
# (stock /etc/ssh/moduli has 2048-bit groups), every SHA-1/64-bit/encrypt-and-MAC MAC, and ECDSA host key
# signatures. User key algorithms (PubkeyAcceptedAlgorithms) are NOT narrowed: that could lock out existing keys.
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
```

Compared with the OpenSSH 8.9 defaults it drops the NIST-curve key exchanges, `diffie-hellman-group14-sha256`,
`diffie-hellman-group-exchange-sha256` (the stock `/etc/ssh/moduli` contains 2048-bit groups), every SHA-1, 64-bit-tag
and encrypt-and-MAC MAC, and ECDSA host key signatures. Clients from the last ~8 years (OpenSSH >= 6.5, PuTTY >= 0.68)
support everything that remains. A client that has only the host's ECDSA key in its `known_hosts` is asked once to
accept the host's Ed25519 or RSA key; the host keys themselves are not changed.

## How the probes work

The grader's plan lists, per kind (kex, cipher, mac, hostkey), the first offered OK algorithm (positive control) and
a fixed list of weak algorithms (SHA-1 and NIST key exchanges, CBC ciphers, SHA-1/MD5/64-bit/encrypt-and-MAC MACs,
`ssh-rsa` and ECDSA host keys). Each one is offered **alone** by the local `ssh` client to `127.0.0.1` (or `::1`) on
sshd's first port, as the non-existent user `pft-sshcrypto-probe` with no key: `Permission denied (publickey)` means
the handshake negotiated it, `no matching ...` means sshd refused it. Nothing leaves the host. A MAC probe forces a
non-AEAD cipher (MACs are never negotiated with chacha20/GCM); a host key algorithm is expected only if sshd also has
a key for it. A probe whose outcome contradicts `sshd -T` is a **MISMATCH** (the running daemon is not serving the
config on disk: a missed reload, a second sshd, socket activation). Each probe leaves one `Invalid user
pft-sshcrypto-probe from 127.0.0.1` line in the auth log.

## How apply and rollback stay safe

1. Refuse if a revert is already armed. On the first apply only, snapshot the sha256 of `sshd_config` and every file
   in `sshd_config.d`, a copy of the drop-in (or "absent") and the sha256 of `sshd -T` into `/var/lib/pft-sshcrypto/pre`.
2. Write the drop-in. `sshd -t` must accept the whole config, and `sshd -T` must show every policy directive with
   exactly the policy value (an earlier drop-in could shadow it). If not, restore at once (sshd was not reloaded,
   so nothing took effect) and exit 2. A policy file may only set the four crypto directives.
3. Arm the revert: a transient `pft-sshcrypto-revert.timer` (`systemd-run --on-active=REVERT_AFTER`, default 120 s)
   that runs `pft-sshcrypto rollback --auto`. Armed **before** the reload.
4. `systemctl reload ssh`: the listener re-reads its config; existing sessions are untouched.
5. Confirm a **new** session: `ssh` with the default client algorithms, a dedicated key and strict host key checking
   against the host's own public keys must log in and print a token. Then an audit with probes must show 0
   mismatches. The confirm key is created by `install.sh` and is usable only from loopback and only to print the token:
   `restrict,from="127.0.0.1,::1",command="echo pft-sshcrypto-confirm-ok"` in root's `authorized_keys`.
6. Confirmed: stop the timer, record `applied`, exit 0. Not confirmed: exit 3 and **leave the timer armed**. Nobody
   needs to log in again for the revert to happen.

`rollback` restores the drop-in from the snapshot (or deletes it if it did not exist), runs `sshd -t`, reloads, and
then requires the file manifest **and** the `sshd -T` sha256 to equal the snapshot and a new session to log in.
A file someone else changed in `sshd_config.d` meanwhile makes it fail loudly (exit 2, diff printed) instead of
claiming success. A second `apply` keeps the first snapshot, so rollback always returns to the state before the tool
first touched the host.

## Metrics (`/var/lib/pft-exporter/textfile/pft_sshcrypto_<host>.prom`, written atomically on every audit)

| metric | meaning |
|---|---|
| `pft_sshcrypto_up{host}` | 1 audit completed, 0 audit error (then no findings/probe series) |
| `pft_sshcrypto_last_run_timestamp_seconds{host}` | time of the last audit |
| `pft_sshcrypto_findings{host,kind,grade}` | offered WARN / FAIL items per kind (kex, cipher, mac, hostkey, pubkey, casig, hostkey-file) |
| `pft_sshcrypto_probes{host}`, `pft_sshcrypto_probe_mismatches{host}` | loopback handshakes run / contradicting `sshd -T` |
| `pft_sshcrypto_hostkey_bits{host,type}` | size of each offered host key |
| `pft_sshcrypto_policy_applied{host}`, `pft_sshcrypto_revert_pending{host}` | apply committed / waiting for confirm or revert |

## Alerts

`../alerts/sshcrypto.rules.yml`, tested in `../alerts/sshcrypto.tests.yml` (promtool, 1-minute samples, every
annotation asserted with its computed value):

| alert | fires when |
|---|---|
| `PFTSSHCryptoFailGrade` (critical) | sum of FAIL findings > 0 for 5 min |
| `PFTSSHCryptoProbeMismatch` (critical) | probe mismatches > 0 for 5 min |
| `PFTSSHCryptoWarnGrade` (warning) | sum of WARN findings > 0 for 24 h |
| `PFTSSHCryptoAuditFailing` (warning) | `up == 0` for 15 min |
| `PFTSSHCryptoNotRunning` (warning) | last audit older than 3 h for 10 min |
| `PFTSSHCryptoRevertPending` (critical) | an unconfirmed apply neither confirmed nor reverted for 15 min (timer lost to a reboot, or rollback failed) |

## Install

```
sudo sshcrypto/install.sh                    # validator (sentry: --host sentry). Changes no sshd setting.
sudo sshcrypto/install.sh --pull             # validator: needs PULL_SSH in /etc/pft-sshcrypto.env
sudo pft-sshcrypto audit                     # read the findings
sudo pft-sshcrypto apply                     # harden (auto-revert armed until a new session is confirmed)
sudo docker kill -s HUP pft-prometheus       # load ../alerts/sshcrypto.rules.yml (listed in ../alerts/prometheus.yml)
sudo pft-integrity accept --reason "pft-sshcrypto"
```

`install.sh` copies the script, grader and `hardened.conf`, writes `HOST_LABEL` to `/etc/pft-sshcrypto.env`, creates
the confirm key (under `umask 077`), adds the restricted `authorized_keys` line, adds a
`textfile pft_sshcrypto_*.prom 3h` line to `/etc/pft-rulecheck.conf` if `../rulecheck` is installed, runs one audit
through the sandboxed unit and enables the hourly timer. `--uninstall` refuses while a policy is applied.

The audit unit runs as root (it reads the host keys) without capabilities, `ProtectSystem=strict`, writable only
`/var/lib/pft-exporter/textfile`, `AF_UNIX/AF_INET/AF_INET6` only.

## Tests

```
bash sshcrypto/tests/run-tests.sh        # stubbed: no root, no real sshd/ssh/systemd
python3 sshcrypto/tests/mutate.py        # mutation check of that suite
promtool test rules alerts/sshcrypto.tests.yml
```

`tests/stubs.py` stands in for `sshd` (`-T` = a fixture overridden by the drop-ins, first file wins; `-t`),
`ssh` (negotiates against what the "running daemon" serves, which only `systemctl reload` updates), `ssh-keygen`,
`systemctl` and `systemd-run` (records the armed timer and its command, which the tests then run). Fixtures: the
OpenSSH 8.9 defaults, a legacy config (CBC, SHA-1, DSA, RSA 1024) and two moduli files.

Results (`logs/01-tests.log`, `logs/02-mutants.log`, `logs/03-lint.log`): suite **88 passed, 0 failed**;
**34/34 mutants caught** (control run 88/88 first; every mutant applied exactly once; each one is listed with the FAIL
lines it produced); shellcheck 0 findings in 5 scripts; ruff clean; promtool `check rules` 6 rules, `test rules`
SUCCESS. `01-tests.log` also runs the suite against the two earlier versions that had the live-found confirm bugs
(below): `bf9889c` fails E1 (87/88), `0a6120c` fails E1 and F8 (86/88), so each fix has a test that fails without it
(mutants M33, M34).

## Results on the two hosts (found -> fixed -> verified)

Both hosts ran the stock Ubuntu 22.04 / OpenSSH 8.9 algorithm lists (the existing `40-pft-hardening.conf` from
`../audit` sets only authentication options).

| | validator | sentry |
|---|---|---|
| before (`12`, `13` step 1) | `RESULT: FAIL - 48 ok, 18 warn, 3 fail, 27 probes, 0 probe mismatches` (FAIL: `hmac-sha1`, `hmac-sha1-etm`, `umac-64`; WARN: NIST-curve and 2048-bit key exchanges, group exchange with 2048-bit moduli, encrypt-and-MAC MACs, ECDSA host key algorithms and key) | same |
| apply / after (step 2-3) | `APPLIED`; `RESULT: OK - 48 ok, 0 warn, 0 fail, 27 probes, 0 probe mismatches` | same |
| rollback (step 4) | sha256 manifest of `sshd_config` + 3 drop-ins and `sshd -T` sha256 equal to before (4b, 4c) | same |
| login-breaking drill (step 5) | apply exit 3 `CONFIRM FAILED ... no matching cipher found`; new session refused, existing session still runs commands; the timer rolled back by itself 66 s after the apply; manifest + `sshd -T` identical again; new session works; 20/20 checks | 20/20 checks; the whole run streamed through a validator->sentry ssh connection opened before the drill, and a fresh validator->sentry connection every 10 s failed only inside the 60 s window (`13`, end) |
| alert drill (`14`) | `PFTSSHCryptoFailGrade` fired for `host=validator` and `host=sentry`; `[FIRING]` and `[RESOLVED]` for both on a throwaway topic; the fix was the real `apply` on both hosts; resolved 59 s after it; operator topics 0 messages; 17/17 checks | (evaluated on the validator) |
| final (`15`) | `state: applied`, audit `OK` 48/0/0, 27 probes, 0 mismatches, ECDSA key `UNUSED`; pft-integrity PASS after accept; pft-rulecheck 76 rules LIVE, 15 textfiles FRESH | same audit result; pft-integrity PASS after accept |

**Bugs the live runs found (kept as evidence):**

| run | found | fix |
|---|---|---|
| `08` (5c FAIL, 19/20) | the confirm session ran ssh at `LogLevel=ERROR`; OpenSSH 8.9 logs "Unable to negotiate" at INFO, so the failure reason was empty. The stub ssh printed it at any level, so the suite missed it. | `0a6120c`: confirm at `LogLevel=INFO`; the stub honours LogLevel; mutant M33 |
| `10` (5c FAIL, 19/20) | at INFO, a command-less session first prints "Pseudo-terminal will not be allocated ...", which became the reason line | `2de089a`: confirm with `-T`; the stub prints the pty notice; mutant M34 |

In both failed runs every safety check still passed (not committed, timer armed, new session refused, existing session
alive, automatic revert, identical hashes); only the printed reason was wrong. Two recorded test/mutant runs were
stopped part-way when the code under them changed (`logs/superseded-*`, lesson: never edit code under a recorded run).

## Limits

- Only the algorithm lists and host keys are graded; authentication settings are `../audit`'s job.
- The probes use the local OpenSSH client; algorithms it no longer supports are `skipped`, not tested.
- The revert timer is transient: a reboot while an apply is pending loses it (the drop-in stays, unconfirmed).
  `PFTSSHCryptoRevertPending` fires after 15 min in that case.
- `rollback` restores sshd's own files only; host keys, `moduli` and `authorized_keys` are never changed by `apply`.

## Logs

| log | content |
|---|---|
| `01-tests.log` | stubbed suite 88/88 at `2de089a` + regression controls against `bf9889c` and `0a6120c` |
| `02-mutants.log` | 34/34 mutants caught |
| `03-lint.log` | shellcheck, ruff, promtool check/test rules, promtool check config |
| `04-install-validator.log`, `05-install-sentry.log`, `06-install-pull.log` | installs (first audit through the sandboxed unit) |
| `07-integrity-install.log`, `09-reinstall.log`, `11-reinstall.log` | pft-integrity WARN items from the installs, accepted |
| `08-host-run-validator-failed.log`, `10-host-run-validator-failed.log` | first two validator host runs (19/20 each, see above) |
| `12-host-run-validator.log`, `13-host-run-sentry.log` | before / apply / after / rollback / login-breaking auto-revert drill, 20/20 each |
| `14-alert-drill.log` | two-host throwaway-topic alert drill, 17/17 |
| `15-final-state.log` | final audits (JSON), status, integrity accept, rulecheck |
| `16-verification.log` | verification answer: installed sha256 on both hosts = pinned commit, current audit OK on both |
| `superseded-*` | recorded runs stopped when the code changed |

Redaction: home directory -> `~`, the agent account -> `<user>`, the sentry's address -> `<redacted-ip>`, host names
-> `<host>`; the alert drill filters topics/addresses with `../peerexpose/drill/redact.py`.
