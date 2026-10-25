# Post Fiat node availability SLO report

- Window: 2026-10-10T01:21:00Z -> 2026-10-25T01:21:00Z (360h00m), step 60s, job `postfiat`
- SLI: good = scrape up AND pft_up = 1 AND server_state >= full AND validated ledger age < 10s
- Objective: 99.500% (error budget 0.500% of eligible time)
- Maintenance source: pft_maint_active metric + 7 window(s) from history file
- Source: Prometheus /api/v1/query_range only (pft-slo-report)

## Instance `127.0.0.1:9877`

| Metric | Value |
|---|---|
| SLI (good / eligible) | 99.9549% |
| Objective met in window | yes |
| Eligible time | 73h55m |
| Bad time | 2m00s (2 steps) |
| Error budget for window | 22m11s |
| Budget consumed | 9.0% |
| Budget remaining | 91.0% |
| Maintenance excluded | 1h14m (7 windows) |
| Measured span | 2026-10-21T22:13:00Z -> 2026-10-25T01:21:00Z |
| Unmeasured (no Prometheus data) | 284h52m |
| Recording-rule cross-check (pft:sli_bad:bool) | rule not present |

### Bad intervals (2)

| Start (UTC) | End (UTC) | Duration | Likely cause |
|---|---|---|---|
| 2026-10-22T10:10:00Z | 2026-10-22T10:11:00Z | 1m00s | node RPC down (1m00s); node restarted (pft_uptime_seconds reset) |
| 2026-10-23T20:14:00Z | 2026-10-23T20:15:00Z | 1m00s | node RPC down (1m00s); node restarted (pft_uptime_seconds reset) |

### Maintenance windows excluded (7)

| Start (UTC) | End (UTC) | Duration |
|---|---|---|
| 2026-10-23T18:13:00Z | 2026-10-23T18:14:00Z | 1m00s |
| 2026-10-23T18:15:00Z | 2026-10-23T18:35:00Z | 20m00s |
| 2026-10-23T19:10:00Z | 2026-10-23T19:25:00Z | 15m00s |
| 2026-10-23T20:21:00Z | 2026-10-23T20:53:00Z | 32m00s |
| 2026-10-24T00:12:00Z | 2026-10-24T00:14:00Z | 2m00s |
| 2026-10-24T01:10:00Z | 2026-10-24T01:13:00Z | 3m00s |
| 2026-10-24T23:12:00Z | 2026-10-24T23:13:00Z | 1m00s |

Step accounting: each step stands for 60s; a bad interval ends at the last bad step + one step. A sampled SLI can miss sub-step blips.
