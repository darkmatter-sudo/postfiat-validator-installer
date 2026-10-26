# Post Fiat node availability SLO report

- Window: 2026-10-25T07:40:45Z -> 2026-10-26T07:40:45Z (24h00m), step 15s, job `postfiat`
- SLI: good = scrape up AND pft_up = 1 AND server_state >= full AND validated ledger age < 10s
- Objective: 99.500% (error budget 0.500% of eligible time)
- Maintenance source: pft_maint_active metric
- Source: Prometheus /api/v1/query_range only (pft-slo-report)

## Instance `127.0.0.1:9877`

| Metric | Value |
|---|---|
| SLI (good / eligible) | 98.8993% |
| Objective met in window | NO |
| Eligible time | 23h28m |
| Bad time | 15m30s (62 steps) |
| Error budget for window | 7m02s |
| Budget consumed | 220.1% |
| Budget remaining | -120.1% |
| Maintenance excluded | 32m00s (3 windows) |
| Measured span | 2026-10-25T07:40:45Z -> 2026-10-26T07:40:45Z |
| Unmeasured (no Prometheus data) | 0s |
| Recording-rule cross-check (pft:sli_bad:bool) | 5761 steps agree, 0 disagree |

### Bad intervals (2)

| Start (UTC) | End (UTC) | Duration | Likely cause |
|---|---|---|---|
| 2026-10-26T00:35:30Z | 2026-10-26T00:43:15Z | 7m45s | node RPC down (7m15s), server_state connected (30s); node restarted (pft_uptime_seconds reset) |
| 2026-10-26T07:24:30Z | 2026-10-26T07:32:15Z | 7m45s | node RPC down (7m15s), server_state connected (30s); node restarted (pft_uptime_seconds reset) |

### Maintenance windows excluded (3)

| Start (UTC) | End (UTC) | Duration |
|---|---|---|
| 2026-10-26T00:22:45Z | 2026-10-26T00:33:30Z | 10m45s |
| 2026-10-26T01:09:30Z | 2026-10-26T01:19:45Z | 10m15s |
| 2026-10-26T07:11:15Z | 2026-10-26T07:22:15Z | 11m00s |

Step accounting: each step stands for 15s; a bad interval ends at the last bad step + one step. A sampled SLI can miss sub-step blips.
