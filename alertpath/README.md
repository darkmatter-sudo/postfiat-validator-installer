# alertpath/ — dead-man's switch for the alerting pipeline

[`../alerts`](../alerts/) pages you when the node breaks. Nothing pages you when **the pager itself** breaks:
Alertmanager stopped, a bad rules file that Prometheus refused to load, a webhook that keeps failing, or a
crashed ntfy bridge. All of these fail silently, and every alert just stops arriving.

This add-on sends a known-good alert through the real pipeline all the time and checks from a **second host**
(the sentry) that it keeps arriving. The second host also reads the pipeline's own self-metrics.

```
validator host (runs ../alerts)                            sentry host
  PFTAlertPipelineWatchdog  (expr: vector(1), always firing)
  -> Alertmanager route "alertpath" (repeat 1m, continue: false)
  -> alertpath_sink.py 127.0.0.1:9096  -> last.json
  pft-alertpath push   (timer, every 30s)                  pft-alertpath check --notify   (timer, every 60s)
    last.json + Prometheus/Alertmanager /metrics             verify HMAC, keep 10 min of snapshots,
    + bridge container/listener/ntfy errors                  decide OK / DEGRADED / STALE,
    -> HMAC-SHA256-signed snapshot                           ntfy on change (its own ntfy.env)
    -> ssh pftap@sentry  (forced command  ------------->   pft-alertpath receive -> spool
       `pft-alertpath receive`, restrict)
```

The watchdog alert never reaches the operator topic. Its route has `continue: false` and only one receiver (the
loopback sink). `amtool config routes test` proves it (log 02), and the drill counts 0 watchdog lines in the bridge.

**No new network listener.** The sink listens on 127.0.0.1 only. Snapshots go to the sentry over SSH with a
dedicated key, and that key can only run `pft-alertpath receive`. This is the same pattern as
[`../watchdog`](../watchdog/), but with its own key, user (`pftap`) and HMAC key.

## States

| State | Exit | Meaning |
|---|---|---|
| `OK` | 0 | a signed snapshot ≤ `SNAP_STALE_SEC` (150 s) old, the last watchdog delivery ≤ `WD_STALE_SEC` (180 s) before it, and no DEGRADED reason |
| `DEGRADED` | 1 | deliveries still arrive, but some part reports a failure (list below) |
| `STALE` | 2 | no valid snapshot for 150 s (validator host, push or ssh down), **or** no watchdog delivery for 180 s (Prometheus not evaluating, Alertmanager down, route or sink broken). STALE outranks DEGRADED |
| — | 3 | usage/config error |

DEGRADED reasons (each one has a fixture test and a mutant):
Prometheus unreachable · Prometheus last config reload failed · rule evaluation failures, notification errors or
dropped notifications increased in the last 3 min (`INC_WINDOW_SEC`; Prometheus-style counter increase with the sample before the window as baseline; resets handled) ·
Prometheus has no Alertmanager · the `alertpath` rule group is not loaded or was last evaluated more than 120 s ago ·
Alertmanager unreachable · Alertmanager last config reload failed · Alertmanager webhook notifications failed
increased · bridge container not running / not listening on :9095 · new `-> ERROR` lines from the bridge's ntfy
sends · a mis-routed delivery reached the sink · watchdog delivered as `resolved` · a spooled message was rejected
(bad HMAC, wrong type, replayed or future `ts`, oversize).

`check --json` prints one JSON object: `state`, `reasons[]`, `snapshot_age`, `delivery_age`, `snapshots`, `accepted`,
`since`. With `--notify` it sends one ntfy message per state change, and `RECOVERED` when the state returns to OK
(STALE = high, DEGRADED = default, RECOVERED = low). It sends nothing while the state is unchanged.

## Install

Requirements: `../alerts` stack running from this repo (it mounts `../alerts`, so the rule and route are already in
place after `git pull`), plus `curl jq ssh python3 ss` on the validator and `curl jq flock` on the sentry.

```bash
# 1. validator: reload the stack so it picks up alertpath.rules.yml and the "alertpath" route
cd alerts && DOCKER="sudo docker" ./run-stack.sh check
sudo docker kill -s HUP pft-alertmanager && sudo docker kill -s HUP pft-prometheus   # or ./run-stack.sh up
# 2. validator: sink + push timer, keys
cd ../alertpath && sudo ./install.sh validator --relay <sentry-ip>
#    compare the printed host-key fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the sentry
# 3. copy /etc/pft-alertpath/hmac.key and /etc/pft-alertpath/id_ed25519.pub to the sentry over your existing admin
#    SSH session (pipe them through stdin; don't paste the key into a command line). Then on the sentry:
sudo ./install.sh sentry --pubkey id_ed25519.pub --hmac-key hmac.key --ntfy-env ntfy.env
#    ntfy.env: NTFY_SERVER=https://ntfy.sh  NTFY_TOPIC=<topic>  [NTFY_TOKEN=<token>]   (shred the copies afterwards)
sudo pft-alertpath check --json        # on the sentry
# 4. if you run ../integrity: sudo pft-integrity accept --reason "alertpath install" on both hosts
```

Uninstall: `sudo ./install.sh uninstall validator [--purge]` and `sudo ./install.sh uninstall sentry [--purge]`.
After that, remove the `alertpath` route/receiver from `../alerts/alertmanager.yml` and the rule file line from
`prometheus.yml`, then reload. If you leave the route in place with no sink, Alertmanager just logs failed webhook
attempts for that one receiver.

## Tests

```bash
cd alerts && DOCKER="sudo docker" ./run-stack.sh check   # promtool check/test (incl. alertpath.tests.yml) + amtool
bash alertpath/tests/test-alertpath.sh    # 38 fixture tests: every state/reason, HMAC/replay/clock/oversize, notify sequence
bash alertpath/tests/test-sink.sh         # 11 tests of the sink on a spare loopback port
bash alertpath/tests/mutate.sh            # 32 mutants of pft-alertpath.sh; each must make the suite FAIL
shellcheck alertpath/*.sh alertpath/tests/*.sh alertpath/drill/*.sh alerts/run-stack.sh
```

The fixture tests sign snapshots with `openssl dgst -hmac` (independent of the script's bash HMAC). They feed them
through the real `receive` forced command and check the state, exit code and reason text. `push --print` is also
tested against `file://` fixture scrapes and a stub docker.

## Live drill

`drill/drill.sh` runs on the validator while the sentry's `ntfy.env` points at a **throwaway** topic:
baseline OK → `docker stop pft-alertmanager` (DEGRADED, then STALE) → start (OK) → PromQL syntax error in
`alertpath.rules.yml` + SIGHUP (reload fails → DEGRADED) → restore (OK). It reports per-fault detection latency,
lists the throwaway topic's messages, counts messages on the operator topics during the drill (must be 0), and
checks that the bridge never saw the watchdog. A trap always restarts Alertmanager and restores the rules file.

## Results

RESULTS_PLACEHOLDER

## Limitations

- Detection latency is bounded by the timers: up to 30 s (push) + 60 s (check) on top of the thresholds. A
  complete Alertmanager outage is DEGRADED within ~1.5 min and STALE within ~3–5 min.
- The sink proves that Alertmanager **delivered a webhook**, not that ntfy.sh delivered to your phone. ntfy-side
  failures only show up as bridge `-> ERROR` lines (DEGRADED). An ntfy.sh outage also hits the sentry's own
  notification, so use a different ntfy server or a token-protected topic on the sentry if you need independence
  from ntfy.sh.
- The snapshot is assembled on the validator. A root attacker there can forge an OK snapshot (it holds the HMAC
  key). The HMAC protects the channel, not a compromised validator. [`../integrity`](../integrity/) watches the
  installed files.
- A sentry outage silences this check too. The sentry's own health is covered by [`../watchdog`](../watchdog/) and
  the sentry metrics pulled into `../alerts` (see [`../resources`](../resources/)).
- A counter increase (e.g. Prometheus notification errors while Alertmanager was down) keeps the state DEGRADED for
  `INC_WINDOW_SEC` (180 s) after the last increase, so recovery to OK takes up to ~4.5 min after the fault is fixed.
  The first live drill found that the original rule (increase over the whole 10-min history) held a recovered
  pipeline in DEGRADED for 10 min; see Results.
