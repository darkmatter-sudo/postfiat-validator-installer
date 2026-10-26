#!/usr/bin/env bash
# Alertmanager silence helpers for slo/drill.sh, in their own file so tests/test_drill_restore.py can source them
# with a stubbed curl (no network, no root). Callers set AM and PROM (base URLs) before using them.
# shellcheck shell=bash

ts() { date -u +%FT%TZ; }

silence_slo() { # silence_slo false|true MINUTES COMMENT -> silence id (empty on failure)
  # false = every alert EXCEPT PFTSLO* (the drill's main silence), true = only PFTSLO* (drill tail)
  curl -fsS -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$(jq -nc --arg s "$(ts)" \
    --arg e "$(date -u -d "+$2 min" +%FT%TZ)" --arg c "$3" --argjson eq "$1" '{matchers:[{name:"alertname",
    value:"PFTSLO.*",isRegex:true,isEqual:$eq}], startsAt:$s, endsAt:$e, createdBy:"slo drill.sh", comment:$c}')" \
    | jq -r '.silenceID // empty'
}
silence_nonslo() { silence_slo false "$@"; }

finish_silence() { # finish_silence SIL: step 5, after restore() has re-posted SIL on the recreated Alertmanager
  # run-stack.sh recreated Prometheus too: an empty alert list right after it means "not evaluated yet", not "clear"
  # (run 2: expiring here let PFTContainerRestarted, a 15 min window after the node start, reach the real topic).
  # So the non-SLO silence is never expired early: it runs out at its own end time, > last node start + 15 min + 10 min.
  local active
  active="$(curl -fsS "$PROM/api/v1/alerts" | jq -r '[.data.alerts[].labels.alertname | select(startswith("PFTSLO") | not)] | unique | join(",")')" || active="unknown (Prometheus API failed)"
  echo "non-SLO alerts pending/firing in Prometheus (informational, fresh instance): ${active:-none}"
  if [ -z "$1" ]; then echo "no Alertmanager silence to keep"
  else echo "Alertmanager silence ${1:0:8} kept until its end time (60m; never expired early)"; fi
}
