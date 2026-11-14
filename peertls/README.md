# peertls: TLS posture audit of your own peer ports

Read-only, rate-limited audit of the TLS that a Post Fiat node's peer port (2559) actually speaks: protocols,
TLS 1.2 suite classes, TLS 1.3 suites, DHE group size, certificate key / signature / validity, compression, RFC 5746,
client-initiated renegotiation, `TLS_FALLBACK_SCSV`, extended master secret, ticket lifetime, and run-to-run drift
of all of it. Human and JSON reports, textfile metrics, one alert with promtool tests, a weekly timer.
Status: code, policies and tests; live install and two-host results follow in [Results](#results).

## Why

The peer protocol runs over TLS with a self-signed certificate postfiatd makes at start, and what the port accepts is
decided by the build and by `[port_peer]` in `postfiatd.cfg` (inbound connections use that port's `ssl_ciphers`, see
`src/xrpld/rpc/detail/ServerHandler.cpp` `makeContexts()`; without it the built-in default list of
`src/libxrpl/basics/make_SSLContext.cpp` applies). Which OpenSSL the binary links decides what that list means, so
the only reliable answer is to ask the port. `pft-peertls` does that with plain `openssl s_client` handshakes, keeps
every raw answer in a bundle, and grades the bundle offline.

## Usage

```
sudo pft-peertls audit [--target NAME] [--json] [--public] [--textfile] [--no-state]  # 0 PASS 1 WARN 2 FAIL 3 usage 4 capture
sudo pft-peertls audit --bundle FILE [--json]       # grade a saved capture (no network)
sudo pft-peertls collect [--target NAME] [--out FILE]
sudo pft-peertls plan [--target NAME]               # the probes and handshake count a run would make
pft-peertls render REPORT.json                      # human report from a JSON report, byte-identical to the live one
pft-peertls crosscheck A.json B.json                # host A's remote view of B == B's own local view (and back)
sudo pft-peertls pull                               # validator: copy the sentry's textfile
```

### What is probed, and how much

Only targets in the root-owned `/etc/pft-peertls.targets` (`NAME ADDR PORT local|remote [CONTAINER]`, kept off the
repo, see `pft-peertls.targets.example`). A `local` target must be a loopback address, a `remote` target must be one
of your own hosts on the peer port; names are refused, any other port is refused, and nothing else is ever probed.
Without `--target` only local targets run (the weekly timer). The probe matrix (`peertls_eval.py matrix`) is 21
handshakes per target; a run whose plan exceeds `MAX_HANDSHAKES` (40, cannot be raised) is refused before the first
connection. Probes are 0.2 s apart on loopback and at least 5 s (default 6 s) apart across hosts, which keeps a
cross-host run under UFW's `LIMIT` rule (6 new connections per 30 s per source).

| Probe | Offer (client side, `@SECLEVEL=0` where needed so the server's answer is graded) |
|---|---|
| `proto.tls1`, `proto.tls1_1`, `proto.tls1_2`, `proto.tls1_3` | one protocol version |
| `cipher.null`, `anull`, `export`, `rc4`, `3des`, `cbc_sha1`, `cbc_sha2`, `kx_rsa`, `kx_dhe`, `ecdhe_aead` | TLS 1.2 with one class of suites |
| `tls13.aes128gcm`, `aes256gcm`, `chacha20` | TLS 1.3 with one suite |
| `hs.reneg` | TLS 1.2, then a client-initiated renegotiation (`R`) |
| `hs.fallback` | TLS 1.2 with `-fallback_scsv` |
| `cert` | the leaf certificate (`openssl x509 -text -fingerprint -sha256`) |

A class the local OpenSSL cannot offer (OpenSSL 3 has no export/RC4 suites and refuses 3DES) is reported `INFO
untestable`, never PASS.

### Checks and policy

`policy/ROLE.policy` (validator and sentry: the same rules, same build): `protocol NAME forbid|require|allow`,
`cipher CLASS forbid|require|allow`, `min_rsa_bits`, `min_ec_bits`, `min_dh_bits`, `forbid_sig_hash`,
`min_cert_days_left`, `max_ticket_lifetime`, and `severity CHECK WARN` to lower a violation from FAIL.

| Check | FAIL / WARN when |
|---|---|
| `probe.reachable` | any probe could not connect, or no certificate came back |
| `proto.*` | a forbidden version is accepted or a required one refused (`tls1_3` missing is WARN) |
| `cipher.*` | a forbidden class accepted (CBC-SHA2 and static-RSA key exchange are WARN) or `ecdhe_aead` refused |
| `cipher.tls13_suites` | TLS 1.3 accepted but none of its suites |
| `kx.dh_bits` | the DHE group is smaller than `min_dh_bits` |
| `cert.key`, `cert.sig_hash`, `cert.validity` | key below minimum, MD5/SHA-1 signature, expired / not yet valid / fewer than `min_cert_days_left` days |
| `hs.compression`, `hs.client_reneg`, `hs.fallback_scsv` | TLS compression on, client renegotiation accepted, fallback accepted while TLS 1.3 is offered |
| `hs.secure_reneg`, `hs.ems`, `hs.ticket_lifetime` | (WARN) no RFC 5746 extension, no extended master secret, ticket hint above `max_ticket_lifetime` |
| `drift.posture`, `drift.cert` | (WARN) accepted protocols/classes/suites, renegotiation, DH group or certificate key changed since the last run; a certificate change is INFO when the container's start time changed too (postfiatd makes a new certificate at every start) |

State per target set is kept in `/var/lib/pft-peertls/state-NAMES.json`; the next run is the new baseline.

### Waivers and publishing

`/etc/pft-peertls.waivers` (root-owned, private): `CHECK TARGET|* until=YYYY-MM-DD reason`, for a finding that cannot
be fixed on the host. A waived check counts as `WAIVED` (no verdict impact); expired waivers stop applying and are
counted. `--public` drops waived findings and every probe behind them from the report and keeps the count, so a
published report never details an open weakness. Fix what can be fixed first; report the rest privately.

### Metrics

`--textfile` writes `pft_peertls_HOST.prom` (atomic): `pft_peertls_up`, `pft_peertls_last_run_timestamp_seconds`,
and when graded `pft_peertls_verdict` (0/1/2), `pft_peertls_checks{result}`, `pft_peertls_check{target,check}`
(0 pass, 1 warn, 2 fail, 3 waived, -1 info), `pft_peertls_drift{target}` (restart-explained certificate changes
excluded), `pft_peertls_handshakes`, `pft_peertls_cert_not_after_seconds{target}`. First label is always `host`;
no `job`/`instance` labels. `pull` accepts only `pft_peertls_` samples whose first label is the peer's host.

## Alert

`alerts/peertls.rules.yml`, one alert `PFTPeerTLSPosture` (for 5m) with `reason` = `fail-checks` (verdict FAIL),
`audit-error` (up 0) or `drift` (posture changed since the previous run, not explained by a restart). WARN does not
page. To acknowledge a drift: read `sudo pft-peertls audit`, and once the change is understood (for example a
postfiatd upgrade) run `sudo pft-peertls audit --textfile`; the current posture becomes the baseline. Staleness is
graded by pft-rulecheck (`textfile pft_peertls_*.prom 8d`). Tests: `promtool test rules alerts/peertls.tests.yml`.

## Install

Files: `pft-peertls.sh` -> `/usr/local/bin/pft-peertls`, `peertls_eval.py` and `policy/` ->
`/usr/local/lib/pft-peertls/`, `systemd/pft-peertls.{service,timer}` (both hosts),
`systemd/pft-peertls-pull.{service,timer}` (validator). Config: `/etc/pft-peertls.env`, `/etc/pft-peertls.targets`
(and, only if needed, `/etc/pft-peertls.waivers`), all root-owned 0600.

## Tests

```
cd peertls && TMPDIR=$HOME/.cache python3 -m pytest -q tests     # needs openssl; starts s_server on 127.0.0.1 only
shellcheck pft-peertls.sh && ruff check . && ruff format --check .
```

`tests/test_peertls.py` runs every check against a real weak `openssl s_server` on loopback (TLS 1.0/1.1 on,
TLS 1.2 off, TLS 1.3 off, static RSA, CBC-SHA2, CBC-SHA1, NULL, anonymous, no ECDHE AEAD, 1024-bit DH, 1024-bit key,
SHA-1 signature, expired / short-lived / not-yet-valid certificate via the evaluator clock, client renegotiation on,
closed port), each asserting the exact reason, with a clean server as control. Where OpenSSL 3 cannot build such a
server (compression, missing RFC 5746, no EMS, long ticket lifetime, ignored FALLBACK_SCSV) the test edits one line
of a real capture and checks that the unedited capture passes. Guards (target rules, handshake cap, pace floor) are
tested with a logging `openssl` stub that must never be called.

## Results

Pending: live install, two-host and cross-host runs, mutation run and fresh-clone transcript.
