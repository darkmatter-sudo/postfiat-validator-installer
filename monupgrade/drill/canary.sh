#!/usr/bin/env bash
# shellcheck disable=SC2015  # `test && log || fail` chains: log always returns 0
# canary.sh: a temporary copy of the monitoring stack (../../alerts/run-stack.sh) on a host that runs none, so
# pft-monupgrade's apply -> rollback -> re-apply can be proven there before the live stack is touched. The sentry
# runs no Prometheus/Alertmanager (its alerts are evaluated on the validator), so this is the "sentry first" step.
#
# Usage (on that host, from a run copy of the repo; sudo -n docker):
#   NTFY_ENV_FILE=FILE PROM_IMAGE=REF AM_IMAGE=REF STATE=DIR canary.sh up
#   STATE=DIR canary.sh down
#   canary.sh status
#  up    refuses if any stack container or the pft-prometheus-data volume already exists (never adopts a real
#        stack), records the local image IDs in STATE/images.before, then `run-stack.sh up` with EXPORTER_CHECK=0
#        (no exporter here: the scrape targets stay down before and after, which the parity gate compares as is).
#        NTFY_ENV_FILE must be a throwaway topic (the caller's job); every canary alert goes there.
#  down  removes the stack containers (also *-premonupgrade leftovers), their volumes (the named Prometheus volume
#        and Alertmanager's anonymous one) and every image that was not present before `up`; then checks that
#        none of them is left (exit 1 otherwise).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/../../alerts/run-stack.sh"
read -r -a DOCKER <<< "${DOCKER:-sudo -n docker}"
NAMES=(pft-prometheus pft-alertmanager pft-alert-bridge pft-prometheus-premonupgrade pft-alertmanager-premonupgrade)
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

present() { local c; for c in "${NAMES[@]}"; do "${DOCKER[@]}" inspect "$c" >/dev/null 2>&1 && echo "$c"; done; }

up() {
  : "${NTFY_ENV_FILE:?NTFY_ENV_FILE (throwaway topic) required}" "${PROM_IMAGE:?}" "${AM_IMAGE:?}" "${STATE:?}"
  [ -z "$(present)" ] || die "stack container(s) already present: $(present | tr '\n' ' ') - not a canary host"
  "${DOCKER[@]}" volume inspect pft-prometheus-data >/dev/null 2>&1 && die "volume pft-prometheus-data already exists"
  mkdir -p "$STATE" && "${DOCKER[@]}" image ls -q --no-trunc | sort -u >"$STATE/images.before" || die "cannot write $STATE"
  log "canary up: prometheus $PROM_IMAGE, alertmanager $AM_IMAGE ($(wc -l <"$STATE/images.before") images before)"
  DOCKER="${DOCKER[*]}" EXPORTER_CHECK=0 NTFY_ENV_FILE="$NTFY_ENV_FILE" PROM_IMAGE="$PROM_IMAGE" AM_IMAGE="$AM_IMAGE" \
    bash "$STACK" up
}

down() {
  : "${STATE:?}"
  local c vols=() v i rc=0
  for c in $(present); do
    mapfile -t -O "${#vols[@]}" vols < <("${DOCKER[@]}" inspect "$c" | jq -r '.[0].Mounts[] | select(.Type == "volume") | .Name')
    "${DOCKER[@]}" rm -f "$c" >/dev/null && log "removed container $c"
  done
  for v in $(printf '%s\n' "${vols[@]}" pft-prometheus-data | sort -u); do
    "${DOCKER[@]}" volume rm "$v" >/dev/null 2>&1 && log "removed volume ${v:0:24}"
  done
  if [ -r "$STATE/images.before" ]; then
    for i in $("${DOCKER[@]}" image ls -q --no-trunc | sort -u | comm -13 "$STATE/images.before" -); do
      "${DOCKER[@]}" image rm -f "$i" >/dev/null && log "removed image ${i:7:12}"
    done
    [ -z "$("${DOCKER[@]}" image ls -q --no-trunc | sort -u | comm -13 "$STATE/images.before" -)" ] \
      && log "image store = before up" || { log "FAIL images left that were not there before up"; rc=1; }
  else
    log "FAIL no $STATE/images.before: images not cleaned"; rc=1
  fi
  [ -z "$(present)" ] && log "no stack container left" || { log "FAIL containers left: $(present | tr '\n' ' ')"; rc=1; }
  for v in "${vols[@]}" pft-prometheus-data; do
    "${DOCKER[@]}" volume inspect "$v" >/dev/null 2>&1 && { log "FAIL volume left: ${v:0:24}"; rc=1; }
  done
  [ "$rc" = 0 ] && log "RESULT: canary removed" || log "RESULT: FAIL canary not fully removed"
  return "$rc"
}

status() { "${DOCKER[@]}" ps -a --filter name=pft- --format '  {{.Names}} {{.Status}} {{.Image}}'; }

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) sed -n '3,17p' "$0"; exit 2 ;;
esac
