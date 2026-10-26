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
M3 makes the drill checker accept a `[FIRING]` message sent before the alert fired, and its tests have to fail.

## Live drill

```bash
sudo bash slo/drill.sh [--stop-min 7] [--out DIR]
```

Stops `postfiatd` twice on the validator host. **B** is a planned stop inside `pft-maint start`: the SLI must
record maintenance (`pft:sli_maint:bool` 1, `pft:sli_bad:bool` 0) and no `PFTSLO*` alert may go pending or send a
message. **A** is an unplanned stop with no window: `pft:sli_bad:bool` must go to 1, `PFTSLOFastBurn` must go
pending, then firing, and its `[FIRING]` message must arrive. After the node is back to `full`, the alert must
resolve. A 7 min stop is about 8 bad minutes with the restart. That is above the fast-burn threshold (4.3 min in 1 h,
`for: 2m`) and below the slow-burn one (10.8 min in 6 h), so `PFTSLOSlowBurn` should stay quiet. The checker
reports it either way.

The script does not page anyone. Before the first stop it points every notifier on both hosts at one random
throwaway ntfy topic: `postfiat-monitor`, `pft-integrity`, `pft-maint`, the sentry's `pft-watchdog`, and the
alert bridge (re-created by `run-stack.sh up` with a throwaway `NTFY_ENV_FILE`). It then silences every non-SLO
alert in Alertmanager for 90 min. The SLO alerts are deliberately not silenced, because their delivery is part of
the test. The bridge goes back to the real topic only after no `PFTSLO*` alert is active in Prometheus or
Alertmanager, and after `[RESOLVED] PFTSLOFastBurn` reached the throwaway topic (or 3 min passed). If an SLO
alert is still active then, it is silenced for 60 min. Every file is restored on any exit (trap) and compared by
sha256. The script refuses to start if a `pft-maint` data-collection lock or window is active, if the node is
not `full`, or if a `PFTSLO*` alert is already active.

`drill_check.py` decides pass/fail from `samples.jsonl` (one Prometheus poll every 15 s: `pft:sli_maint:bool`,
`pft:sli_bad:bool`, 5m/1h ratios, `/api/v1/alerts`) and `ntfy.jsonl` (the topic read back, titles only). It is
tested offline in `tests/test_drill_check.py`. The samplers are tested against real API responses, and the
checker against a synthetic timeline with one fault injected per test (maintenance not excluded, SLO alert or
message during B, firing without pending, stale or missing `[FIRING]`, never resolved, too many failed polls).

### Run 1 (2026-10-26, FAIL 12/13) and what it changed

Log: [`logs/slo/drill-1-fail.log`](../logs/slo/drill-1-fail.log), with `drill-1-samples.jsonl`, `drill-1-ntfy.jsonl`
and `drill-1-check.txt`. Drill A worked as designed: `pft:sli_bad:bool` was 1 in 27/28 down samples,
`PFTSLOFastBurn` went pending at 00:39:34Z, firing at 00:41:21Z (107 s later), `[FIRING]` reached the throwaway
topic at 00:41:32Z and `[RESOLVED]` at 00:48:31Z. Drill B recorded `pft:sli_bad:bool` 0 in all 42 samples, with no
`PFTSLO*` alert and no message. Three problems surfaced, and all three are fixed in `drill.sh`:

1. **The checker FAIL.** The first B sample (00:22:28Z, 3 s after `pft-maint start`, the node still `full`) had
   `pft:sli_maint:bool` 0, because the exporter needs one scrape to see a new window. B now starts with a `B-arm`
   phase that waits for `pft:sli_maint:bool` 1 (up to 120 s) before the node is stopped. The checker ignores
   `B-arm` and stays strict for `B`.
2. **The silence was lost on restore.** `run-stack.sh up` recreates Alertmanager, and every silence goes with it
   (the expiry at the end returned HTTP 404). `PFTContainerRestarted` was still firing in Prometheus at that
   moment, so the fresh Alertmanager would have routed it to the real topic. It was caught by hand within
   about 40 s: a silence was posted before Alertmanager received the alert, the alert showed as `suppressed`, and
   the bridge sent nothing. `restore` now creates the non-SLO silence again on the new Alertmanager, and also an
   SLO silence if a `PFTSLO*` alert is still active or a tail silence existed. Whether to expire it at the end is
   decided from Prometheus, because a fresh Alertmanager holds no alerts yet.
3. **No slow-burn headroom check.** Run 1 left about 8 bad minutes in the 6 h window (`ratio_rate6h` 0.0222). A
   second run inside 6 h would add about 9 more and cross the slow-burn line (0.03), and `PFTSLOSlowBurn` would
   then stay active past the drill. The preflight now refuses (exit 4) when `ratio_rate6h + (stop-min + 2)/360`
   reaches `6 * (1 - objective)`: see `logs/slo/drill-guard-3-slowburn.log`.

The new pieces were tested before any further live run: `logs/slo/drill-fix-tests-1.log` and `-2.log`, and the offline suite again after the change (`logs/slo/check-4.log`, PASS incl. M1-M3) (both
silence variants against the live Alertmanager, a dead Alertmanager giving an empty id, the Prometheus filter on
synthetic answers, the `until-maint` stop condition, and the checker on run 1's samples with the pre-arm sample
relabelled, which gives 13/13).

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
