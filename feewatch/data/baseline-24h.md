# pft-feewatch baseline

History rows used: 2884 (unparseable lines skipped: 0). Escalation threshold: 4.

## postfiatd

- window 1793492460..1793578860 (1440 min), samples 1442, coverage 1.0000, gaps > 2 min: 0, admin answers 1.0000
- ledgers 7655934..7684474
- minutes with open ledger > expected: 0; escalation > 1: 0; >= threshold: 0; local > net: 0
- observed base fee {'10': 1442}, max_queue_size {'2000': 1442}, expected_ledger_size {'32': 1442}

| metric | n | min | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|---|
| queue size | 1442 | 0 | 0 | 0 | 0 | 0 | 0 |
| queue fill ratio | 1442 | 0 | 0 | 0 | 0 | 0 | 0 |
| open ledger size | 1442 | 0 | 0 | 3 | 4 | 5 | 0.478502 |
| escalation multiple | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor total | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor server | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor local | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor net | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor cluster | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor fee_escalation | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor fee_queue | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| drops base_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |
| drops median_fee | 1442 | 5000 | 5000 | 5000 | 5000 | 5000 | 5000 |
| drops minimum_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |
| drops open_ledger_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |

Minutes with a load_factor source above 1: none

## postfiatd-sentry

- window 1793492460..1793578860 (1440 min), samples 1442, coverage 1.0000, gaps > 2 min: 0, admin answers 1.0000
- ledgers 7655932..7684474
- minutes with open ledger > expected: 0; escalation > 1: 0; >= threshold: 0; local > net: 0
- observed base fee {'10': 1442}, max_queue_size {'2000': 1442}, expected_ledger_size {'32': 1442}

| metric | n | min | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|---|---|
| queue size | 1442 | 0 | 0 | 0 | 0 | 0 | 0 |
| queue fill ratio | 1442 | 0 | 0 | 0 | 0 | 0 | 0 |
| open ledger size | 1442 | 0 | 0 | 3 | 4 | 5 | 0.453537 |
| escalation multiple | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor total | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor server | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor local | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor net | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor cluster | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor fee_escalation | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| load_factor fee_queue | 1442 | 1 | 1 | 1 | 1 | 1 | 1 |
| drops base_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |
| drops median_fee | 1442 | 5000 | 5000 | 5000 | 5000 | 5000 | 5000 |
| drops minimum_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |
| drops open_ledger_fee | 1442 | 10 | 10 | 10 | 10 | 10 | 10 |

Minutes with a load_factor source above 1: none

