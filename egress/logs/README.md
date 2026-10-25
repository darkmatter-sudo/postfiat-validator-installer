# egress/ logs

| File | What |
|---|---|
| `sentry-live-drill.log` | `drill-sentry.sh` on the sentry, 2026-10-25T04:22-04:33Z: guard refusal, plan, before-probe (`example.com:80` CONNECTED), apply inside a pft-maint window with the 10 min dead-man inline (PASS), after-probe BLOCKED (5 s) + 3 kernel drop lines, validator-list fetch HTTP 200 before and after, `check` PASS, pft-integrity verify -> accept -> PASS, notifiers restored (sha256 match), throwaway topic read back |
| `netns-test.log` | `tests/netns-test.sh`, real iptables in throwaway namespaces, 17/17 |
| `netns-test-run1.log` | first netns run (17/17), before two fixes: `iptables -C` on the nf_tables backend echoed the rule into `check` output, and `probe` timed with the fake clock (0s) instead of the real one (5s = DROP) |
| `unit-tests.log` | shellcheck + ruff + `tests/run-tests.sh` 42/42 |
| `unit-tests-run1-ruff-exe001.log` | the same run before the fix: ruff EXE001 (test helper not executable) |

Redactions: public IPv4 -> `<redacted-ip>`, kernel `MAC=` -> `<redacted-mac>`, ntfy topic -> `<redacted>`,
user name -> `<user>` (done by the drill's own output filter); afterwards the local-time timestamp of the three kernel
lines -> `<local-time-redacted>` and the checkout path -> `<repo>`. Nothing else was changed.
