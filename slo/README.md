# slo/ — availability SLO, error budget and burn-rate alerts

Prometheus recording rules for a validator availability SLI, multi-window multi-burn-rate alerts, and
`pft-slo-report`, a CLI that turns Prometheus history into a Markdown error-budget report.
Builds on [`../exporter`](../exporter) (metrics) and [`../alerts`](../alerts) (Prometheus, Alertmanager,
ntfy bridge). Planned work announced with [`../maint`](../maint) (`pft-maint start`) does not burn budget.

| File | What |
|---|---|
| `slo.rules.yml` | SLI recording rules, 5m/30m/1h/6h/30d error ratios, budget remaining, `PFTSLOFastBurn`, `PFTSLOSlowBurn` |
| `gen_tests.py` → `tests.yml` | promtool unit tests (steady-good, fast-burn, exporter-down, slow-burn, maintenance-window, state) |
| `pft_slo_report.py` | `pft-slo-report` CLI (Prometheus `/api/v1/query_range` only) |
| `tests/` | offline CLI tests against recorded API fixtures + exporter `pft_maint_active` tests |
| `check.sh` | every offline check + two mutation controls that must fail |
| `install.sh` | deploy: exporter with `pft_maint_active`, alert stack with these rules mounted |

## SLI definition

Evaluated every 15 s (the scrape interval) by `pft-slo-sli`:

```
good     = up == 1                                  # exporter scraped
           AND pft_up == 1                          # node answered server_info
           AND server_state >= full                 # full, validating or proposing
           AND pft_validated_ledger_age_seconds < 10
eligible = pft_maint_active == 0                    # no valid pft-maint window open
bad      = eligible AND NOT good
```

A component series that is missing counts as not good. When the scrape fails, the exporter's series go stale, and
when the RPC is down the exporter emits no `server_state`, so every component falls back to 0 through
`or on (job, instance) (0 * up)`. `pft_maint_active` comes from the exporter. It reads
`/var/lib/pft-maint/flag.json` with the same checks as `pft-maint active`: regular file, root-owned, not
group/other-writable, ≤ 4 KiB, `v == 1`, typed fields, TTL ≤ 4 h, start not in the future, now < expiry. A
malformed flag is **not** maintenance (`pft_maint_flag_malformed 1`).

Error ratio over a window W: `sum_over_time(bad[W]) / max(sum_over_time(eligible[W]), 1)`. It is 0 when the whole
window is maintenance.

**Objective:** `pft:slo_objective:ratio`, default `0.995` over 30 days (budget 0.5 % ≈ 3 h 36 min per 30 days).
To change it, edit that one `vector(...)` expression. Both alerts and `pft-slo-report` read it (the CLI falls
back to 0.995, or takes `--objective`).

## Burn-rate alerts

Burn rate 1 means the budget runs out in exactly 30 days. Thresholds follow the Google SRE workbook (ch. 5):

| Alert | Condition | for | Severity | Meaning |
|---|---|---|---|---|
| `PFTSLOFastBurn` | error ratio > 14.4 × budget over **1h AND 5m** | 2m | critical | 2 % of the 30-day budget gone in 1 h |
| `PFTSLOSlowBurn` | error ratio > 6 × budget over **6h AND 30m** | 15m | warning | 5 % of the budget gone in 6 h |

With 99.5 %, fast = 7.2 % errors (≈ 4.3 bad minutes in an hour) and slow = 3 %. The short window makes the alert
resolve soon after recovery. Both route through the existing Alertmanager → `pft-alert-bridge` → ntfy path
(`../alerts/alertmanager.yml`, default receiver).

### PFTSLOFastBurn
The node is down or degraded right now. Check `sudo postfiat-health` and `docker logs postfiatd`, then run
`pft-slo-report --window 6h` for the bad intervals and their likely causes. A planned restart should run inside
`pft-maint start`. If it did not, that is the cause.

### PFTSLOSlowBurn
Errors are intermittent (stale validated ledger, short flaps). Run `pft-slo-report --window 24h` and look at the
cause column: `validated ledger stale` usually points to peering or consensus trouble, so check `../peers`.

## pft-slo-report

```bash
python3 slo/pft_slo_report.py --window 30d --step 60s -o report.md
python3 slo/pft_slo_report.py --start 2026-10-23T19:00:00Z --end 2026-10-23T21:00:00Z --step 60s \
    --maint-history /var/lib/pft-maint/history.jsonl
```

It reads the raw exporter series (`up`, `pft_up`, `pft_server_state`, `pft_validated_ledger_age_seconds`,
`pft_maint_active`, `pft_uptime_seconds`) with range queries only, chunked under Prometheus's 11 000-point limit,
and applies the SLI above at every step. Because it uses the raw series, it covers all retained history
(15 days in `../alerts`), not just the time since these rules were deployed. Output, per instance: SLI %, objective
met, eligible/bad time, the window's error budget, consumed/remaining, maintenance excluded, unmeasured time,
a recording-rule cross-check, a table of bad intervals with a likely cause (exporter down → RPC down →
server_state → stale/no validated ledger; plus "node restarted" when `pft_uptime_seconds` reset), and the
maintenance windows. `--maint-history` also excludes windows from pft-maint's `history.jsonl`. It covers the time
before the exporter had `pft_maint_active`, and the report says which source it used.
`--record DIR` / `--replay DIR` save and replay raw API responses (offline tests). Exit 0 ok, 1 no data, 2 error.

## Tests

```bash
DOCKER="sudo docker" bash slo/check.sh
```

This runs: `tests.yml` is regenerated and must match; `promtool check rules` and `promtool test rules`;
`python3 -m unittest` (CLI against real recorded fixtures + synthetic series; exporter flag validation);
`ruff check` (config `slo/ruff.toml`, py310 = Ubuntu 22.04); `shellcheck`. Then two **mutation controls** that
must fail. M1 removes the maintenance exclusion from `pft:sli_bad:bool`, and promtool's maintenance-window test
has to fail. M2 makes the CLI ignore maintenance, and the unit tests have to fail with assertions, not errors.

## Deploy

```bash
NTFY_ENV_FILE=~/.config/pft-alerts/ntfy.env bash slo/install.sh
sudo pft-integrity accept --reason "slo: exporter pft_maint_active + alert stack with slo rules"
```

This restarts `pft-exporter` and recreates the three alert-stack containers. It never restarts `postfiatd`.
The Prometheus data volume is kept. Alertmanager silences are not kept (its storage is not a volume), so create
silences after this step, not before.

## Limits

- **Sampled SLI.** One sample per 15 s (the report's `--step`, default 15 s). A blip shorter than a step can be
  missed, and each bad step counts as a full step.
- **Prometheus down = unmeasured, not bad.** While Prometheus itself is not running, nothing is recorded. The
  report shows that time as "unmeasured" and the rules cannot see it. Cross-host liveness is
  [`../watchdog`](../watchdog)'s job.
- **Young history inflates ratios.** `sum_over_time` uses only the samples that exist, so in the first 6 h after
  deploy a short outage is a large share of the "6h" window, and the slow burn can fire early (see the
  fast-burn promtool case). The 30-day ratio means "since deploy" until 30 days of history exist. Prometheus
  here keeps 15 days, so the 30-day budget ratio covers at most 15 days.
- **The budget scales to the report window.** `pft-slo-report` compares bad time against
  (1 − objective) × eligible time *in the chosen window*. A 2 h window with a 1 min outage shows > 100 % consumed,
  although the 30-day budget is fine.
- **Single node view.** The SLI is what this node reports about itself (server_state, validated ledger age), not
  whether the network accepts its validations.
- **The maintenance flag is trusted.** Any root user can open a window and exclude time. Windows are capped at 4 h
  (pft-maint `MAX_TTL_SEC`), every window is in `history.jsonl`, and the report lists every excluded window.
