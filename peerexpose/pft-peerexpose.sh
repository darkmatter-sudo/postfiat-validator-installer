#!/usr/bin/env bash
# pft-peerexpose - audit what a postfiatd node discloses on its PUBLIC peer port (2559).
#
# The peer port serves three HTTP handlers to anyone who can reach it:
#   /crawl        server info (node pubkey, build, uptime), the overlay peer list (peer IPs, ports, pubkeys,
#                 versions), optional counts, and the UNL publisher lists. Controlled by the [crawl] section.
#   /vl/<pubkey>  the signed validator list of a publisher the node trusts. Controlled by [vl] enable.
#   /health       a small health object ({"info":{}} when healthy, details when not). Always served.
# Each field is classified disclosed/restricted and compared with the role policy:
#   validator  everything in /crawl and /vl must be restricted (a validator behind a sentry is not a public
#              crawl target, and its peer list reveals the sentry)
#   sentry     crawl.overlay.* and crawl.counts must be restricted (the overlay list contains the validator's
#              address); server info, unl and /vl stay public so the sentry remains a useful public peer
# Values are NEVER printed: only status, policy verdict and counts, so output is safe to publish.
#
# Usage: pft-peerexpose audit --role validator|sentry [--url https://HOST:2559] [--container NAME]
#                             [--vl-key KEY]... [--json] [--timeout SEC]
#   --url        default https://127.0.0.1:2559 (local). Use the other host's public address for a cross-host
#                audit (what the internet sees). TLS is not verified (peer certs are self-signed).
#   --vl-key     publisher key(s) to probe on /vl/. Default: the keys from the local node's admin RPC
#                (`validators`, through `docker exec <container> curl`); none found = /vl probed with a dummy key.
# Exit: 0 no policy violation, 1 at least one VIOLATION, 2 error (port unreachable, unparseable answer),
#       3 usage error.
set -euo pipefail

ROLE=""
URL=https://127.0.0.1:2559
CONTAINER=postfiatd
JSON=false
TIMEOUT=10
VL_KEYS=()
RPC_URL=http://127.0.0.1:5005

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# fetch NAME PATH -> writes $TMP/NAME.body, prints the HTTP code ("000" if unreachable)
fetch() {
  local code
  code="$(curl -sk -m "$TIMEOUT" -o "$TMP/$1.body" -w '%{http_code}' "$URL$2" 2>/dev/null)" || true
  [ -n "$code" ] || code=000
  [ -f "$TMP/$1.body" ] || : > "$TMP/$1.body"
  printf '%s\n' "$code"
}

# local admin RPC: publisher keys the node trusts (one per line, may be empty)
local_vl_keys() {
  sudo -n docker exec "$CONTAINER" curl -s -m "$TIMEOUT" -d '{"method":"validators"}' "$RPC_URL" 2>/dev/null \
    | jq -r '.result.publisher_lists[]?.pubkey_publisher // empty' 2>/dev/null || true
}

RESULTS="$TMP/results.tsv"   # field <TAB> status <TAB> count <TAB> policy <TAB> note
ERRORS=0

# policy ROLE FIELD -> "restrict" or "allow"
policy() {
  case "$1:$2" in
    validator:health.*) echo allow ;;
    validator:*) echo restrict ;;
    sentry:crawl.overlay.*|sentry:crawl.counts) echo restrict ;;
    sentry:*) echo allow ;;
  esac
}

# record FIELD STATUS COUNT NOTE
record() {
  local verdict
  if [ "$2" = disclosed ] && [ "$(policy "$ROLE" "$1")" = restrict ]; then verdict=VIOLATION; else verdict=ok; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$verdict" "$4" >> "$RESULTS"
}

# present FILE JQ_EXPR -> count of matches (0 = restricted)
count() { jq -r "[$2] | length" "$1" 2>/dev/null || echo 0; }

audit() {
  : > "$RESULTS"
  local code n f
  # /crawl
  code="$(fetch crawl /crawl)"
  if [ "$code" = 000 ]; then
    echo "ERROR: $URL unreachable" >&2; ERRORS=$((ERRORS + 1)); return
  fi
  f="$TMP/crawl.body"
  if [ "$code" = 200 ]; then
    if ! jq -e 'type == "object"' "$f" >/dev/null 2>&1; then
      echo "ERROR: /crawl answered 200 with a non-JSON body" >&2; ERRORS=$((ERRORS + 1)); return
    fi
    record crawl.endpoint disclosed 1 "http 200"
  else
    record crawl.endpoint restricted 0 "http $code"
    echo '{}' > "$f"
  fi
  for spec in \
    'crawl.server.pubkey_node|.server.pubkey_node // empty' \
    'crawl.server.build_version|.server.build_version // empty' \
    'crawl.server.uptime|.server.uptime // empty' \
    'crawl.server.state_accounting|.server.state_accounting // empty' \
    'crawl.overlay.peer_ip|.overlay.active[]?.ip // empty' \
    'crawl.overlay.peer_port|.overlay.active[]?.port // empty' \
    'crawl.overlay.peer_pubkey|.overlay.active[]?.public_key // empty' \
    'crawl.overlay.peer_version|.overlay.active[]?.version // empty' \
    'crawl.counts|.counts // empty' \
    'crawl.unl.publisher_lists|.unl.publisher_lists[]? // empty'; do
    n="$(count "$f" "${spec#*|}")"
    if [ "$n" -gt 0 ]; then record "${spec%%|*}" disclosed "$n" ""; else record "${spec%%|*}" restricted 0 ""; fi
  done
  # /vl/<key>
  local keys=("${VL_KEYS[@]}") k served=0 probed=0
  if [ "${#keys[@]}" -eq 0 ]; then mapfile -t keys < <(local_vl_keys); fi
  [ "${#keys[@]}" -gt 0 ] || keys=(ED0000000000000000000000000000000000000000000000000000000000000000)
  for k in "${keys[@]}"; do
    probed=$((probed + 1))
    code="$(fetch vl "/vl/$k")"
    if [ "$code" = 200 ] && jq -e 'has("blob")' "$TMP/vl.body" >/dev/null 2>&1; then served=$((served + 1)); fi
  done
  if [ "$served" -gt 0 ]; then
    record vl.list disclosed "$served" "served for $served/$probed publisher key(s)"
  else
    record vl.list restricted 0 "not served for $probed publisher key(s)"
  fi
  # /health
  code="$(fetch health /health)"
  n="$(count "$TMP/health.body" '.info // {} | keys[]')"
  if [ "$code" = 000 ]; then
    record health.details restricted 0 "unreachable"
  elif [ "$n" -gt 0 ]; then
    record health.details disclosed "$n" "http $code, node not fully healthy"
  else
    record health.details restricted 0 "http $code, empty info"
  fi
}

report() {
  local violations
  violations="$(awk -F'\t' '$4 == "VIOLATION"' "$RESULTS" | wc -l)"
  if $JSON; then
    jq -R -s --arg role "$ROLE" --argjson errors "$ERRORS" --argjson violations "$violations" '
      { role: $role, errors: $errors, violations: $violations,
        fields: [ split("\n")[] | select(length > 0) | split("\t")
                  | { field: .[0], status: .[1], count: (.[2] | tonumber), policy: .[3], note: .[4] } ] }' "$RESULTS"
  else
    echo "pft-peerexpose audit - $(date -u +%FT%TZ) - role $ROLE"
    awk -F'\t' '{ printf "  %-30s %-10s n=%-4s %-9s %s\n", $1, $2, $3, $4, $5 }' "$RESULTS"
    echo "RESULT: $violations violation(s), $ERRORS error(s)"
  fi
  if [ "$ERRORS" -gt 0 ]; then return 2; fi
  if [ "$violations" -gt 0 ]; then return 1; fi
  return 0
}

[ $# -gt 0 ] || usage
CMD="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift ;;
    --url) URL="${2:-}"; shift ;;
    --container) CONTAINER="${2:-}"; shift ;;
    --vl-key) VL_KEYS+=("${2:-}"); shift ;;
    --json) JSON=true ;;
    --timeout) TIMEOUT="${2:-}"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done
case "$ROLE" in validator|sentry) ;; *) echo "--role validator|sentry is required" >&2; exit 3 ;; esac
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "--timeout must be an integer" >&2; exit 3; }

case "$CMD" in
  audit)
    audit
    rc=0; report || rc=$?
    exit "$rc" ;;
  *) echo "unknown command: $CMD" >&2; usage ;;
esac
