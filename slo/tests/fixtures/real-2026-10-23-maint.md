# Post Fiat node availability SLO report

- Window: 2026-10-23T19:00:00Z -> 2026-10-23T21:00:00Z (2h00m), step 60s, job `postfiat`
- SLI: good = scrape up AND pft_up = 1 AND server_state >= full AND validated ledger age < 10s
- Objective: 99.500% (error budget 0.500% of eligible time)
- Maintenance source: pft_maint_active metric + 7 window(s) from history file
- Source: Prometheus /api/v1/query_range only (pft-slo-report)

## Instance `127.0.0.1:9877`

| Metric | Value |
|---|---|
| SLI (good / eligible) | 98.6486% |
| Objective met in window | NO |
| Eligible time | 1h14m |
| Bad time | 1m00s (1 steps) |
| Error budget for window | 22s |
| Budget consumed | 270.3% |
| Budget remaining | -170.3% |
| Maintenance excluded | 47m00s (2 windows) |
| Measured span | 2026-10-23T19:00:00Z -> 2026-10-23T21:00:00Z |
| Unmeasured (no Prometheus data) | 0s |
| Recording-rule cross-check (pft:sli_bad:bool) | rule not present |

### Bad intervals (1)

| Start (UTC) | End (UTC) | Duration | Likely cause |
|---|---|---|---|
| 2026-10-23T20:14:00Z | 2026-10-23T20:15:00Z | 1m00s | node RPC down (1m00s); node restarted (pft_uptime_seconds reset) |

### Maintenance windows excluded (2)

| Start (UTC) | End (UTC) | Duration |
|---|---|---|
| 2026-10-23T19:10:00Z | 2026-10-23T19:25:00Z | 15m00s |
| 2026-10-23T20:21:00Z | 2026-10-23T20:53:00Z | 32m00s |

Step accounting: each step stands for 60s; a bad interval ends at the last bad step + one step. A sampled SLI can miss sub-step blips.
