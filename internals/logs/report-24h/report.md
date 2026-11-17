# pft-internals two-host report

Window 2026-11-16T06:05:00Z .. 2026-11-17T06:05:00Z (24.00 h), step 60 s, 1441 expected samples per series.
Built offline from the query capture (sha256 `df2231ae8526e8cfac246dddfc8f8bd1f751398f76457a0cfabe250324f39e55`) by `report_internals.py build`;
every query string is in the capture. Percentiles are nearest-rank over the finite samples.

| query | container | unit | samples | coverage % | min | p50 | p95 | max |
|---|---|---|---:|---:|---:|---:|---:|---:|
| up_min | postfiatd | 0/1 | 1441 | 100.00 | 1 | 1 | 1 | 1 |
| up_min | postfiatd-sentry | 0/1 | 1441 | 100.00 | 1 | 1 | 1 | 1 |
| nodestore_read_ms | postfiatd | ms | 1441 | 100.00 | 0.01329 | 0.0901 | 0.2638 | 0.4855 |
| nodestore_read_ms | postfiatd-sentry | ms | 1441 | 100.00 | 0.01169 | 0.05559 | 0.1599 | 0.3057 |
| nodestore_reads_per_s | postfiatd | 1/s | 1441 | 100.00 | 6.619 | 10.95 | 54.24 | 55.88 |
| nodestore_reads_per_s | postfiatd-sentry | 1/s | 1441 | 100.00 | 5.804 | 9.005 | 52.77 | 55.67 |
| nodestore_hit_ratio | postfiatd | ratio | 1441 | 100.00 | 0.1711 | 0.8084 | 0.8269 | 0.8383 |
| nodestore_hit_ratio | postfiatd-sentry | ratio | 1441 | 100.00 | 0.1266 | 0.8102 | 0.8318 | 0.8565 |
| cached_view_hit_ratio | postfiatd | ratio | 1441 | 100.00 | 0.8025 | 0.8081 | 0.8108 | 0.8156 |
| cached_view_hit_ratio | postfiatd-sentry | ratio | 1441 | 100.00 | 0.8008 | 0.8083 | 0.8111 | 0.8164 |
| nodestore_written_bytes_per_s | postfiatd | B/s | 1441 | 100.00 | 5715 | 6955 | 7894 | 8773 |
| nodestore_written_bytes_per_s | postfiatd-sentry | B/s | 1441 | 100.00 | 4588 | 6438 | 7342 | 7989 |
| sle_hit_ratio | postfiatd | ratio | 1441 | 100.00 | 0.8964 | 0.8966 | 0.8968 | 0.8968 |
| sle_hit_ratio | postfiatd-sentry | ratio | 1441 | 100.00 | 0.8947 | 0.8948 | 0.895 | 0.895 |
| treenode_cache_size | postfiatd | entries | 1441 | 100.00 | 190 | 425 | 2396 | 8478 |
| treenode_cache_size | postfiatd-sentry | entries | 1441 | 100.00 | 198 | 434 | 1883 | 8458 |
| db_total_bytes | postfiatd | B | 1441 | 100.00 | 2267136 | 2271232 | 2275328 | 2284544 |
| db_total_bytes | postfiatd-sentry | B | 1441 | 100.00 | 2306048 | 2310144 | 2319360 | 2340864 |
| objects_total | postfiatd | objects | 1441 | 100.00 | 155632 | 162704 | 173484 | 178019 |
| objects_total | postfiatd-sentry | objects | 1441 | 100.00 | 157157 | 162800 | 172710 | 178426 |
| job_waiting_sum | postfiatd | jobs | 1441 | 100.00 | 0 | 0 | 0 | 3 |
| job_waiting_sum | postfiatd-sentry | jobs | 1441 | 100.00 | 0 | 0 | 0 | 3 |
| job_peak_ms_max | postfiatd | ms | 1441 | 100.00 | 3 | 57 | 243 | 675 |
| job_peak_ms_max | postfiatd-sentry | ms | 1441 | 100.00 | 2 | 39 | 192 | 879 |
| jobs_per_s | postfiatd | 1/s | 1441 | 100.00 | 44.51 | 51.16 | 52.91 | 53.89 |
| jobs_per_s | postfiatd-sentry | 1/s | 1441 | 100.00 | 38.94 | 44.98 | 46.54 | 47.4 |
| job_queue_wait_ms | postfiatd | ms | 1441 | 100.00 | 756.4 | 2977 | 7347 | 11374 |
| job_queue_wait_ms | postfiatd-sentry | ms | 1441 | 100.00 | 248.7 | 1149 | 2876 | 4400 |
| rpc_calls_per_s | postfiatd | 1/s | 1441 | 100.00 | 1.701 | 1.779 | 1.809 | 1.819 |
| rpc_calls_per_s | postfiatd-sentry | 1/s | 1441 | 100.00 | 0.2154 | 0.2376 | 0.241 | 0.2462 |
| rpc_errors_per_s | postfiatd | 1/s | 1441 | 100.00 | 0 | 0 | 0 | 0 |
| rpc_errors_per_s | postfiatd-sentry | 1/s | 1441 | 100.00 | 0 | 0 | 0 | 0 |
| restarts_window | postfiatd | count | 1441 | 100.00 | 0 | 0 | 0 | 0 |
| restarts_window | postfiatd-sentry | count | 1441 | 100.00 | 0 | 0 | 0 | 0 |
| anomalies_window | postfiatd | count | 1441 | 100.00 | 0 | 0 | 0 | 0 |
| anomalies_window | postfiatd-sentry | count | 1441 | 100.00 | 0 | 0 | 0 | 0 |

## Queries

- `up_min` (0/1): collector up (1 = valid sample). `min_over_time(pft_internals_up[1m])`
- `nodestore_read_ms` (ms): mean NodeStore read time over 10m (rule PFTInternalsNodeStoreSlow). `1000 * rate(pft_internals_nodestore_read_duration_seconds_total[10m]) / rate(pft_internals_nodestore_reads_total[10m])`
- `nodestore_reads_per_s` (1/s): NodeStore reads per second. `rate(pft_internals_nodestore_reads_total[10m])`
- `nodestore_hit_ratio` (ratio): NodeStore reads answered from cache over 15m (informational). `rate(pft_internals_nodestore_read_hits_total[15m]) / rate(pft_internals_nodestore_reads_total[15m])`
- `cached_view_hit_ratio` (ratio): CachedView lookups that hit over 15m (rule PFTInternalsCacheCollapse). `sum without (result) (rate(pft_internals_cached_view_total{result="hit"}[15m])) / sum without (result) (rate(pft_internals_cached_view_total[15m]))`
- `nodestore_written_bytes_per_s` (B/s): NodeStore bytes written per second. `rate(pft_internals_nodestore_written_bytes_total[10m])`
- `sle_hit_ratio` (ratio): SLE cache hit ratio (node-reported). `pft_internals_cache_hit_ratio{cache="SLE"}`
- `treenode_cache_size` (entries): tree node cache entries. `pft_internals_cache_size{cache="treenode"}`
- `db_total_bytes` (B): SQLite databases, total. `pft_internals_db_bytes{db="total"}`
- `objects_total` (objects): live objects, all types. `sum by (container) (pft_internals_objects)`
- `job_waiting_sum` (jobs): jobs queued and not started (rule PFTInternalsJobBacklog). `sum by (container) (pft_internals_job_waiting)`
- `job_peak_ms_max` (ms): largest job-type peak time (rule PFTInternalsJobPeak). `max by (container) (pft_internals_load_job_peak_ms)`
- `jobs_per_s` (1/s): jobs finished per second, all types. `sum by (container) (rate(pft_internals_job_finished_total[10m]))`
- `job_queue_wait_ms` (ms): mean time a job waited in the queue (delta of the non-monotonic gauge, floored at 0). `1000 * sum by (container) (clamp_min(delta(pft_internals_job_queue_wait_seconds[10m]), 0)) / sum by (container) (rate(pft_internals_job_started_total[10m]))`
- `rpc_calls_per_s` (1/s): admin/public RPC calls per second. `sum by (container) (rate(pft_internals_rpc_started_total[10m]))`
- `rpc_errors_per_s` (1/s): RPC calls that errored per second. `sum by (container) (rate(pft_internals_rpc_errored_total[10m]))`
- `restarts_window` (count): node restarts seen per sample (non-zero = restart). `pft_internals_node_restarts_total - pft_internals_node_restarts_total offset 1m`
- `anomalies_window` (count): counter anomalies per sample (rule PFTInternalsCounterAnomaly). `pft_internals_counter_anomalies_total - pft_internals_counter_anomalies_total offset 1m`
