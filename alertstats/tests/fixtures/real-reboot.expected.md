# Alert behaviour report (validator)

Window 2026-11-12T16:00:00Z -> 2026-11-12T17:00:00Z (1h00m), step 15s. Sources: alertmanager ok, bridge absent, prometheus ok.
Flap rule: >= 3 unsilenced fired episodes of one series starting within 1h00m, in the last 24h00m.

## Headline

| metric | value |
|---|---|
| episodes | 26 |
| fired | 5 |
| pending_only | 21 |
| open | 1 |
| gap_split | 4 |
| flaps | 0 |
| flapping_alertnames | 0 |
| active_alertnames | 15 |
| hygiene_warn | 14 |
| hygiene_info | 100 |
| notifications | 0 |
| prometheus_gap_s | 225 |
| alerting rules / alertnames | 115 / 114 |

## Per alert

| alertname | sev | for | fired | pending-only | open | gap-split | flaps | flapping | TTR n | TTR p50 | TTR p95 | firing | silenced | max near-miss |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PFTAlertPipelineWatchdog | none | 0s | 1 | 0 | 1 | 0 | 0 | no | 0 | - | - | 56m15s | 0s | - |
| PFTClockOffsetHigh | warning | 10m00s | 0 | 2 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 6m00s |
| PFTClusterMissing | warning | 15m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 4m00s |
| PFTContainerRestarted | warning | 0s | 1 | 0 | 0 | 0 | 0 | no | 1 | 10m15s | 10m15s | 10m15s | 10m15s | - |
| PFTExporterDown | critical | 2m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 5m00s |
| PFTFeewatchStale | warning | 2m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 1m00s |
| PFTJobDisabled | warning | 5m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 5m00s |
| PFTJobFailed | warning | 3m00s | 2 | 6 | 0 | 0 | 0 | no | 2 | 3m00s | 5m00s | 8m00s | 8m00s | 2m00s |
| PFTLogshipBroken | warning | 5m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 1m00s |
| PFTPeerFixedLinkDown | critical | 3m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 2m00s |
| PFTPeerwatchStale | warning | 5m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 1m00s |
| PFTRulecheckNotRunning | warning | 1h05m | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 5m00s |
| PFTSchedEntryUnexpected | warning | 2m00s | 1 | 0 | 0 | 0 | 0 | no | 1 | 8m45s | 8m45s | 8m45s | 8m45s | - |
| PFTTimesyncStale | warning | 2m00s | 0 | 1 | 0 | 0 | 0 | no | 0 | - | - | 0s | 0s | 15s |
| PFTVulnRebootOwed | warning | 72h00m | 0 | 4 | 0 | 4 | 0 | no | 0 | - | - | 0s | 0s | 24m00s |

## Rule hygiene

| check | severity | alertname | detail |
|---|---|---|---|
| duplicate_name | info | PFTKeyEscrowStale | 2 rules |
| never_active | info | PFTAmendmentBlocked | 0 episodes |
| never_active | info | PFTAppArmorDrift | 0 episodes |
| never_active | info | PFTAptrustStale | 0 episodes |
| never_active | info | PFTAptrustUntrusted | 0 episodes |
| never_active | info | PFTAuthFailedBurst | 0 episodes |
| never_active | info | PFTAuthUnknownKeyLogin | 0 episodes |
| never_active | info | PFTAuthwatchStale | 0 episodes |
| never_active | info | PFTBackfillCheckFailed | 0 episodes |
| never_active | info | PFTBackfillGap | 0 episodes |
| never_active | info | PFTBackupBroken | 0 episodes |
| never_active | info | PFTBackupConfigDrift | 0 episodes |
| never_active | info | PFTBackupNoOffhostCopy | 0 episodes |
| never_active | info | PFTBackupStale | 0 episodes |
| never_active | info | PFTBackupwatchStale | 0 episodes |
| never_active | info | PFTCPUThrottled | 0 episodes |
| never_active | info | PFTClockNTSSourcesLow | 0 episodes |
| never_active | info | PFTClockNotSynchronised | 0 episodes |
| never_active | info | PFTCloseTimeDrift | 0 episodes |
| never_active | info | PFTCompleteLedgersGap | 0 episodes |
| never_active | info | PFTContainerOOMKill | 0 episodes |
| never_active | info | PFTContainerRestartLoop | 0 episodes |
| never_active | info | PFTDiskSpaceCritical | 0 episodes |
| never_active | info | PFTDiskSpaceLow | 0 episodes |
| never_active | info | PFTDiskWillFillIn24h | 0 episodes |
| never_active | info | PFTDivergenceCheckStale | 0 episodes |
| never_active | info | PFTFdNearLimit | 0 episodes |
| never_active | info | PFTFeeEscalated | 0 episodes |
| never_active | info | PFTFleetCheckStale | 0 episodes |
| never_active | info | PFTFleetDriftStale | 0 episodes |
| never_active | info | PFTFleetHostUnreadable | 0 episodes |
| never_active | info | PFTFwauditExposure | 0 episodes |
| never_active | info | PFTHighLoadFactor | 0 episodes |
| never_active | info | PFTHistarchiveIntegrity | 0 episodes |
| never_active | info | PFTHistarchiveReplica | 0 episodes |
| never_active | info | PFTHistarchiveStale | 0 episodes |
| never_active | info | PFTIOLatencyHigh | 0 episodes |
| never_active | info | PFTIOPressure | 0 episodes |
| never_active | info | PFTJobMissed | 0 episodes |
| never_active | info | PFTJobQueueOverflow | 0 episodes |
| never_active | info | PFTJobwatchStale | 0 episodes |
| never_active | info | PFTKernelCritical | 0 episodes |
| never_active | info | PFTKernelWarning | 0 episodes |
| never_active | info | PFTKernwatchStale | 0 episodes |
| never_active | info | PFTKeyEscrowInventoryFailed | 0 episodes |
| never_active | info | PFTKeyEscrowStale | 0 episodes |
| never_active | info | PFTKeyEscrowVerifyFailed | 0 episodes |
| never_active | info | PFTKmodAuditStale | 0 episodes |
| never_active | info | PFTKmodFinding | 0 episodes |
| never_active | info | PFTLedgerDiverged | 0 episodes |
| never_active | info | PFTLocalLoadHigh | 0 episodes |
| never_active | info | PFTLowPeers | 0 episodes |
| never_active | info | PFTMemoryGrowthToLimit | 0 episodes |
| never_active | info | PFTMemoryNearLimit | 0 episodes |
| never_active | info | PFTMemoryPressure | 0 episodes |
| never_active | info | PFTMountHardeningDrift | 0 episodes |
| never_active | info | PFTNoPeers | 0 episodes |
| never_active | info | PFTNodeBriefFullExit | 0 episodes |
| never_active | info | PFTNodeNotFull | 0 episodes |
| never_active | info | PFTNodeRPCDown | 0 episodes |
| never_active | info | PFTNodeStateFlapping | 0 episodes |
| never_active | info | PFTNodeVersionLag | 0 episodes |
| never_active | info | PFTPeerDisconnectRateHigh | 0 episodes |
| never_active | info | PFTPeerQualityDegraded | 0 episodes |
| never_active | info | PFTPidsNearLimit | 0 episodes |
| never_active | info | PFTPrivescAuditFailing | 0 episodes |
| never_active | info | PFTPrivescFail | 0 episodes |
| never_active | info | PFTPrivescStale | 0 episodes |
| never_active | info | PFTPrivescWarn | 0 episodes |
| never_active | info | PFTResourcesCollectorFailing | 0 episodes |
| never_active | info | PFTResourcesStale | 0 episodes |
| never_active | info | PFTRuleDead | 0 episodes |
| never_active | info | PFTSLOFastBurn | 0 episodes |
| never_active | info | PFTSLOSlowBurn | 0 episodes |
| never_active | info | PFTSSHCryptoAuditFailing | 0 episodes |
| never_active | info | PFTSSHCryptoFailGrade | 0 episodes |
| never_active | info | PFTSSHCryptoNotRunning | 0 episodes |
| never_active | info | PFTSSHCryptoProbeMismatch | 0 episodes |
| never_active | info | PFTSSHCryptoRevertPending | 0 episodes |
| never_active | info | PFTSSHCryptoWarnGrade | 0 episodes |
| never_active | info | PFTSchedauditStale | 0 episodes |
| never_active | info | PFTSeccompDenied | 0 episodes |
| never_active | info | PFTSeccompDrift | 0 episodes |
| never_active | info | PFTSelfhealBreakerOpen | 0 episodes |
| never_active | info | PFTSelfhealStale | 0 episodes |
| never_active | info | PFTStatewatchCollectorFailing | 0 episodes |
| never_active | info | PFTStatewatchStale | 0 episodes |
| never_active | info | PFTTextfileStale | 0 episodes |
| never_active | info | PFTTimesyncAuditCritical | 0 episodes |
| never_active | info | PFTTxQueueNearFull | 0 episodes |
| never_active | info | PFTUnsupportedAmendmentActivationSoon | 0 episodes |
| never_active | info | PFTUnsupportedAmendmentMajority | 0 episodes |
| never_active | info | PFTUpgradewatchStale | 0 episodes |
| never_active | info | PFTValidatedLedgerOld | 0 episodes |
| never_active | info | PFTValidatedLedgerStalled | 0 episodes |
| never_active | info | PFTValidatorNotProposing | 0 episodes |
| never_active | info | PFTVulnFeedStale | 0 episodes |
| never_active | info | PFTVulnHighCriticalPersistent | 0 episodes |
| never_active | info | PFTVulnScanFailing | 0 episodes |
| never_active | info | PFTVulnScanNotRunning | 0 episodes |
| no_for | warn | PFTAuthFailedBurst | authwatch.rules.yml:pft-authwatch |
| no_for | warn | PFTAuthUnknownKeyLogin | authwatch.rules.yml:pft-authwatch |
| no_for | warn | PFTContainerOOMKill | resources.rules.yml:pft-resources |
| no_for | warn | PFTContainerRestartLoop | postfiat.rules.yml:postfiat-resources |
| no_for | warn | PFTContainerRestarted | postfiat.rules.yml:postfiat-resources |
| no_for | warn | PFTHistarchiveIntegrity | histarchive.rules.yml:pft-histarchive |
| no_for | warn | PFTJobQueueOverflow | statewatch.rules.yml:pft-statewatch |
| no_for | warn | PFTKernelCritical | kernwatch.rules.yml:pft-kernwatch |
| no_for | warn | PFTKernelWarning | kernwatch.rules.yml:pft-kernwatch |
| no_for | warn | PFTKeyEscrowStale | keyescrow.rules.yml:pft-keyescrow |
| no_for | warn | PFTNodeBriefFullExit | statewatch.rules.yml:pft-statewatch |
| no_for | warn | PFTNodeStateFlapping | statewatch.rules.yml:pft-statewatch |
| no_for | warn | PFTPeerDisconnectRateHigh | statewatch.rules.yml:pft-statewatch |
| no_for | warn | PFTSeccompDenied | seccomp.rules.yml:pft-seccomp |

## Notifications (ntfy bridge deliveries)

No delivery log in the bundle.

## Prometheus data gaps

| from | to | seconds |
|---|---|---|
| 2026-11-12T16:24:30Z | 2026-11-12T16:28:15Z | 225 |
