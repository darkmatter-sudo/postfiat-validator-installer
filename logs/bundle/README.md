# bundle/ logs

All runs on Ubuntu 22.04 hosts, output tee'd unedited. Host labels: validator-host, sentry-host.

| log | what |
|---|---|
| `1-tests.log` | `bash bundle/tests/run-tests.sh`: 19 unit tests, shellcheck, collect/verify end to end with fake docker (48/48) |
| `2-live-validator.log` | validator run 1. Identity labels skip `ntfy-value-1` because an empty `NTFY_TOKEN=` was counted (value skipped, number used); fixed in live-proof.sh (sha c719293007afa0de) |
| `3-live-sentry.log` | sentry, final scripts (run from a temp copy on the host, nothing installed) |
| `4-live-validator-run2.log` | validator, final scripts |

`raw_hits` counts the value in the unsanitized collection, `bundle_hits` in the extracted bundle, `control_hits`
in a one-line control file that contains the value once (proves the grep would find it). The hosts' own public
addresses do not occur in what is collected (raw 0), and the hostname occurs once (`meta/os.txt`). Other
operators' peer addresses in `peers.json` are what gets tokenized (`distinct_ips` in the redactions line).
