# pft-bundle: sanitized diagnostics bundle

When you ask for help with a node (Discord, a GitHub issue), the first questions are always the same: which image,
is it `full`, how many peers, what does the config say, what is in `debug.log`, is the disk full. `pft-bundle.sh`
collects all of that with one command into a `tar.gz` you can share. Before anything is written it removes
secrets, replaces your IPs, hostnames and ntfy topics with tokens, and scans the result. If any secret or identity
is still there, it writes no bundle (fail closed).

It is read-only. RPC calls are read-only admin methods sent through `docker exec <container> curl` (the admin port
is bound only inside the container). Files are read with `cat`/`tail`. Nothing is restarted or reconfigured.
The only file it writes is the bundle, mode 0600, in `--out` (default `/var/tmp`).

## Usage

```bash
sudo bash bundle/pft-bundle.sh collect                                    # validator (container postfiatd)
sudo bash bundle/pft-bundle.sh collect --container postfiatd-sentry --label sentry-host
sudo bash bundle/pft-bundle.sh collect --log-lines 5000 --redact my-vps-name --literal-env ~/.pft-ntfy.env
sudo bash bundle/pft-bundle.sh collect --sign-key ~/.ssh/id_ed25519       # adds MANIFEST.sha256.sig
bash bundle/pft-bundle.sh verify pft-bundle-<label>-<UTC>.tar.gz           # on the host that made it
bash bundle/pft-bundle.sh verify B.tar.gz --no-host-literals --signers allowed_signers   # anywhere else
```

`--redact WORD` adds an extra hostname-class literal (e.g. a provider name in a cloud hostname).
`--literal-env FILE` adds `NTFY_TOPIC`/`NTFY_URL`/`NTFY_TOKEN` values from another env file.
`--keep-raw DIR` keeps the unsanitized collection (root-only, for debugging). Never share it.

Exit codes: `0` ok, `2` a secret or identity survived, manifest/hash/signature mismatch (collect writes no
bundle), `3` usage, `4` missing prerequisite (root, container, python3, jq).

## What is collected

| file | source |
|---|---|
| `meta/os.txt` | UTC time, OS, kernel, uptime, load, hostname (tokenized), tool hashes |
| `meta/collect.log` | one line per item: exit code and size |
| `meta/redactions.json` | how many replacements per class (counts only) |
| `docker/container.json` | selected `docker inspect` fields: image, state, restart count, caps, read-only, pids, mounts |
| `docker/image.txt` | image id, tags, repo digest, created; Docker server version |
| `rpc/*.json` | `server_info`, `server_state`, `peers`, `validator_list_sites`, `feature` |
| `config/postfiatd.cfg` | the node config, secret-stripped (below) |
| `logs/debug.log.tail` | last `--log-lines` (2000) lines of `debug.log` |
| `system/df.txt`, `df-inodes.txt`, `memory.txt` | `df -hT`, `df -i`, `free -m` |
| `system/ufw.txt` | `ufw status verbose` |
| `system/units.txt`, `addons.txt` | `pft-*`/`postfiat*` units and timers; installed `pft-*` binaries with sha256 prefix |
| `MANIFEST.sha256` | sha256 of every file above |

Timestamps are UTC (`TZ=UTC`), so the bundle does not carry the host timezone.

## What is redacted

| class | rule |
|---|---|
| secret config sections | `[validator_token]`, `[validation_seed]`, `[validator_keys]` dropped with their content (a one-line marker stays) |
| config comments | dropped (the stock config's comments are ~1500 lines and include a public example seed) |
| config credentials | values of `*password*`, `*secret*`, `*seed*`, `*token*`, `*user*` keys become `<redacted>` |
| ntfy | `https://ntfy.<...>/<topic>` becomes `<ntfy-url>`; topic/URL/token values from `/etc/*.env`, `/etc/*/*.env` and `--literal-env` become `<redacted-topic>` |
| hostnames | `hostname`, `hostname -f`, `hostname -s`, the container hostname (`server_info.hostid`), `--redact` words, matched as whole words regardless of case, become `<host-N>` |
| IPv4 | every address except loopback, `0.0.0.0` and RFC 1918 (Docker bridges, LAN) becomes `<ip-N>`; the host's own global addresses are tokenized even if private |
| IPv6 | every address except `::1` and `::` becomes `<ip-N>` (link-local too: it can embed the MAC) |

Tokens are stable within one bundle: a peer address gets the same `<ip-N>` in `peers.json`, `debug.log.tail` and
`postfiatd.cfg`, so you can still follow one peer across files. The mapping is never written anywhere.
IPv6 candidates are checked with Python's `ipaddress`, so `ConsensusPhase::accepted`, `Json::Value`, times
(`12:34:56`) and MAC addresses are left alone.

After redaction the bundle is scanned. Any of these makes `collect` fail (no bundle) and `verify` fail: XRPL
seeds (`s`/`sEd` + 28 base58, not part of a longer base58 word), validator-token blobs, `validation_secret_key`,
`master_seed`, a surviving `[validator_token]`/`[validation_seed]` header, PEM private keys, GitHub tokens, ntfy
access tokens (`tk_...`), and any identity literal that survived. Only `file:line class` is printed, never the
matched text. Seeds found outside the config are not rewritten on purpose: a seed in `debug.log` is a leak you
need to know about, so the tool stops instead of quietly hiding it.

`verify` checks that the tar has one top-level directory and no absolute or `..` members, that the member list
equals `MANIFEST.sha256` exactly, every hash, the signature (with `--signers`, an `ssh-keygen -Y` allowed-signers
file with namespace `pft-bundle`), and runs the same scan with this host's literals (unless `--no-host-literals`).

## Limits (best effort)

- Detection is pattern-based. A secret in a format not listed above (e.g. a custom API key in a unit file name)
  is not caught. Read the bundle before you share it. It is small and plain text.
- Over-redaction is possible: a C++ scope name made only of hex digits (`Cafe::Face`) is a valid IPv6 address
  and gets tokenized, and so does a four-part version number that looks like a public IPv4.
- Node public keys (`pubkey_node`, peer `public_key`) are kept. They are public on the network, but they do
  identify your node.
- The manifest proves the bundle was not changed after it was made. It is not an identity proof unless you sign
  it with `--sign-key` and the recipient checks your public key.
- `peers.json` keeps peer versions and latencies of other operators' nodes (addresses tokenized).

## Tests

```bash
bash bundle/tests/run-tests.sh      # 19 sanitizer unit tests, shellcheck, 46 collect/verify checks (sudo)
```

`tests/stub/docker` serves `tests/fixtures/` (synthetic config with a token block, documentation-range IPs, a
fake hostname and topic), so the collect path is tested end to end without a node. Negative cases: a planted fake
seed in `debug.log` (collect exits 2, no bundle written, value not printed), a tampered file, an unlisted file, a
re-hashed bundle with a seed or a topic added, a `..` member, wrong signer, unsigned bundle with `--signers`.

Live proof on both hosts: `sudo bash bundle/live-proof.sh <container> <label>` runs collect and verify, counts
how often each real identity appears in the raw collection and in the extracted bundle (counts only, with a
planted control line per value), and checks that `server_state`, container start time / restart count and
`pft-integrity` are the same before and after. Logs: [`../logs/bundle/`](../logs/bundle/).
