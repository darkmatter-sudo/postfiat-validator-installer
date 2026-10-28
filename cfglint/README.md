# cfglint/ — does postfiatd actually read what your config says?

postfiatd ignores unknown sections and keys **silently**. A typo, or a key copied from the image's own example config,
leaves a setting at its default with no log line. Example: the example `postfiatd.cfg` documents `[vl] enable = <flag>`,
but postfiatd reads `enabled`. `enable=0` changes nothing and `/vl` stays public (proven below on a throwaway node).

`pft-cfglint.sh` checks a `postfiatd.cfg` against a **registry of every section and key the running build reads**.
The registry is extracted from the postfiatd source at the exact commit the node runs, with file:line provenance.

Read-only: it runs `docker exec <container> cat /etc/postfiatd/postfiatd.cfg` and `postfiatd --version`, nothing else.
It prints section/key names and line numbers only and **never prints config values** (tokens, seeds).

## Usage

```bash
bash cfglint/pft-cfglint.sh                                          # this host's container "postfiatd"
bash cfglint/pft-cfglint.sh --ssh <sentry-ssh-alias> --container postfiatd-sentry
bash cfglint/pft-cfglint.sh --file /path/to/postfiatd.cfg --json     # any file, JSON output
```

Exit codes: **0** no findings · **1** findings (error or warning) · **2** usage error, unreadable config/registry, or no
build commit. In container mode, a registry built from a different commit than `postfiatd --version` reports
gives `registry-mismatch` (warning, exit 1): regenerate the registry for that build.

| code | severity | meaning |
|---|---|---|
| `unknown-section` | error | the build never reads this section (closest match suggested) |
| `unknown-key` | error | the section is read, the key is not (closest match suggested) |
| `unread-documented-key` | error | documented in `cfg/postfiatd-example.cfg` but never read, e.g. `[vl] enable` |
| `empty-value` | error | `key=` with no value; postfiatd's key regex needs a value, so the key stays unset |
| `no-section` | error | a line before the first `[section]` |
| `duplicate-key` | warn | repeated key; the last value wins (`Section::set` insert_or_assign) |
| `duplicate-section` | warn | repeated header; postfiatd merges the lines into the first |
| `not-key-value` | warn | plain value line in a section that only reads keys |
| `registry-mismatch` | warn | registry commit ≠ running build commit |

Port sections are the names listed under `[server]`. Each is checked against the keys `parse_Port()` reads.
Value-list sections (`[ips]`, `[validators]`, `[validator_token]`, …) are not key-checked: a `=` inside a token is data.

## Registry (`registry.json`)

```bash
git init src && cd src && git remote add origin https://github.com/postfiatorg/postfiatd.git
git fetch --depth 1 origin <commit from `postfiatd --version`> && git checkout FETCH_HEAD && cd ..
python3 -I cfglint/extract_registry.py src > cfglint/registry.json
```

The committed registry is for **32723c15e686a2088f2c83017a6ff909d93822cd** (postfiatd 1.0.9, both hosts here). It has
71 sections (15 read keys, 56 are value lists or single values) and 78 keys, plus 22 port-section keys. Every key carries
the `file:line` where it is read. The extractor scans non-test C++ under `src/xrpld` and `src/libxrpl` for section
lookups (`section("x")`, `SECTION_*` macros, `getSingleSection`, `config["x"]`) and key reads (`set`, `get`,
`get_if_exists`, `.get`, `.exists`, `.value_or`, `populate`, multi-line calls included).

A key read inside a function that receives a `Section` parameter is mapped by an explicit per-file table, which
names the caller (e.g. `Port.cpp` → port sections, nodestore backends → `[node_db]`). Anything else maps to the
nearest preceding section lookup within 60 lines. **A key read it cannot attribute makes the extractor exit 1**, so
nothing is dropped silently. Keys documented in the example config but never read are listed as `documented_unread`:
`[vl] enable` and `[transaction_queue] zero_basefee_transaction_feelevel`.

Limitations: this is a regex scan, not a C++ parser. Keys read through computed names, or through a helper the per-file
table does not know, are missed. The provenance test, the guard and the regenerate-identically test bound this but
don't remove it. Values are not type-checked. `[validators_file]` contents (a separate file) are not linted.

## Results (logs/)

| log | what | result |
|---|---|---|
| [`01-registry.log`](logs/01-registry.log) | build commit on both hosts, extraction at that commit, regenerate = committed, `[vl]` source lines | both 32723c15; `vl` keys = `enabled` (OverlayImpl.cpp:1625); `enable` documented at example cfg:1367, 0 reads |
| [`02-tests.log`](logs/02-tests.log) | shellcheck, ruff format, 33 fixture/registry tests, 26 mutants | shellcheck rc 0; 33 passed 0 failed; provenance 130/130 key sites; **26/26 mutants caught** |
| [`03-live-lint.log`](logs/03-live-lint.log) | validator + sentry, text and `--json` | both **exit 0**, 0 findings, build = registry commit; negative control (live cfg copy with `enable=0`) **exit 1** |
| [`04-vl-drill.log`](logs/04-vl-drill.log) | throwaway node per variant, peer port on 127.0.0.1 only | see below; 0 failures, container removed after each variant (0 left) |

`[vl]` drill (stock `cfg/postfiatd-testnet-light.cfg` at 32723c15, with network, publisher list loaded):

| `[vl]` | pft-cfglint | `GET /vl/<publisher key>` |
|---|---|---|
| (none) | exit 0 | **HTTP 200**, signed list served |
| `enable=0` | **exit 1** `unread-documented-key` (did you mean `enabled`?) | **HTTP 200**, still served |
| `enabled=0` | exit 0 | **HTTP 403**, not served |

Mutants: C1-C20 mutate `cfglint.py` and must make `tests/run-tests.sh` fail. E1-E6 mutate `extract_registry.py` and
must change the registry, make it exit non-zero, or fail `tests/extractor-guard.sh`, which feeds it a synthetic source
tree with an orphan key read. A control first checks that the unmutated extractor reproduces `registry.json` exactly.

```bash
SRC=<postfiatd checkout> bash cfglint/tests/run-tests.sh     # SRC optional: adds provenance + regenerate checks
SRC=<postfiatd checkout> bash cfglint/tests/mutate.sh        # SRC optional: adds extractor mutants E1-E6
bash cfglint/drill/vl-drill.sh <src>/cfg/postfiatd-testnet-light.cfg <src>/cfg/validators-testnet.txt
```
