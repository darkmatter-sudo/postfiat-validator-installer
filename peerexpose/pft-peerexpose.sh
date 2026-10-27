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
#
#        pft-peerexpose plan --role validator|sentry [--ssh TARGET] [--container NAME]
#   Read-only. Reads postfiatd.cfg from the container (on TARGET through `ssh TARGET sudo -n` if given), renders the
#   role's managed [crawl]/[vl] block, validates that nothing else changes, and prints the effective settings
#   before -> after plus the diff. Exit 0 (prints CHANGE NEEDED or NO CHANGE), 2 error, 3 usage.
#        pft-peerexpose render --role validator|sentry < postfiatd.cfg      (stdout: the rendered config)
#        pft-peerexpose validate --role validator|sentry --old FILE --new FILE
#   Checks a (hand-)edited config against the role: exit 0 OK, 1 rejected (reason printed), 3 usage.
set -euo pipefail

ROLE=""
URL=https://127.0.0.1:2559
CONTAINER=postfiatd
JSON=false
TIMEOUT=10
VL_KEYS=()
RPC_URL=http://127.0.0.1:5005
SSH_TARGET=""
OLD_FILE=""
NEW_FILE=""
CFG=/etc/postfiatd/postfiatd.cfg

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }

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

# ---------- config: render / validate / plan ----------
MARK="# pft-peerexpose managed block (role policy, see peerexpose/README.md)"

# hx CMD... : run CMD as root on the target host (local sudo -n, or ssh SSH_TARGET sudo -n)
hx() {
  if [ -n "$SSH_TARGET" ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_TARGET" "sudo -n $(printf '%q ' "$@")"
  else
    sudo -n "$@"
  fi
}
read_cfg() { hx docker exec "$CONTAINER" cat "$CFG"; }

role_block() { # ROLE -> the managed block
  echo "$MARK"
  case "$1" in
    validator) printf '[crawl]\n0\n\n[vl]\nenable=0\n' ;;
    sentry) printf '[crawl]\noverlay=0\nserver=1\ncounts=0\nunl=1\n\n[vl]\nenable=1\n' ;;
  esac
}

# stdin cfg -> cfg without any [crawl]/[vl] section, without the marker and without trailing blank lines
strip_managed() {
  awk -v mark="$MARK" '
    $0 == mark { next }
    /^[[:space:]]*\[/ { skip = (tolower($0) ~ /^[[:space:]]*\[(crawl|vl)\][[:space:]]*$/) }
    skip { next }
    /^[[:space:]]*$/ { blank++; next }
    { while (blank > 0) { print ""; blank-- } print }'
}

render() { # ROLE, stdin cfg -> stdout new cfg (idempotent)
  strip_managed
  echo
  role_block "$1"
}

# effective [crawl]/[vl] settings of a cfg on stdin, with postfiatd's defaults (crawl 1, overlay 1, server 1,
# counts 0, unl 1, vl 1). Prints e.g. "crawl=1 overlay=1 server=1 counts=0 unl=1 vl=1".
effective() {
  awk '
    BEGIN { v["crawl"] = 1; v["overlay"] = 1; v["server"] = 1; v["counts"] = 0; v["unl"] = 1; v["vl"] = 1 }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[[:space:]]*\[/ { sec = tolower($0); gsub(/[[:space:]\[\]]/, "", sec); next }
    sec == "crawl" || sec == "vl" {
      line = $0; gsub(/[[:space:]]/, "", line)
      if (line !~ /=/) { if (sec == "crawl") v["crawl"] = (line == "1" || tolower(line) == "true") ? 1 : 0; next }
      k = tolower(substr(line, 1, index(line, "=") - 1)); val = substr(line, index(line, "=") + 1)
      val = (val == "1" || tolower(val) == "true") ? 1 : 0
      if (sec == "crawl" && (k == "overlay" || k == "server" || k == "counts" || k == "unl")) v[k] = val
      if (sec == "vl" && k == "enable") v["vl"] = val
    }
    END { printf "crawl=%d overlay=%d server=%d counts=%d unl=%d vl=%d\n",
                  v["crawl"], v["overlay"], v["server"], v["counts"], v["unl"], v["vl"] }'
}

want_effective() { # ROLE
  case "$1" in
    validator) echo "crawl=0 overlay=1 server=1 counts=0 unl=1 vl=0" ;;
    sentry) echo "crawl=1 overlay=0 server=1 counts=0 unl=1 vl=1" ;;
  esac
}

# validate ROLE OLD NEW -> 0 ok, else prints the reason and returns 1
validate_cfg() {
  local n
  n="$(grep -ciE '^[[:space:]]*\[crawl\][[:space:]]*$' "$3" || true)"
  [ "$n" -eq 1 ] || { echo "validate: expected exactly one [crawl] section, found $n"; return 1; }
  n="$(grep -ciE '^[[:space:]]*\[vl\][[:space:]]*$' "$3" || true)"
  [ "$n" -eq 1 ] || { echo "validate: expected exactly one [vl] section, found $n"; return 1; }
  [ "$(effective < "$3")" = "$(want_effective "$1")" ] \
    || { echo "validate: effective settings $(effective < "$3") != wanted $(want_effective "$1")"; return 1; }
  cmp -s <(strip_managed < "$2") <(strip_managed < "$3") \
    || { echo "validate: lines outside [crawl]/[vl] would change"; return 1; }
  grep -qiE '^[[:space:]]*\[port_peer\][[:space:]]*$' "$3" || { echo "validate: [port_peer] missing"; return 1; }
  echo "validate: OK (one [crawl], one [vl], effective = $1 policy, nothing else changed)"
}

managed_view() { # cfg file -> only the [crawl]/[vl] sections (for diffs; no addresses or keys live there)
  awk '/^[[:space:]]*\[/ { on = (tolower($0) ~ /^[[:space:]]*\[(crawl|vl)\][[:space:]]*$/) } on' "$1"
}

plan() {
  local old="$TMP/old.cfg" new="$TMP/new.cfg"
  read_cfg > "$old" 2>/dev/null || { echo "ERROR: cannot read $CFG from $CONTAINER${SSH_TARGET:+ on $SSH_TARGET}" >&2; exit 2; }
  [ -s "$old" ] || { echo "ERROR: $CFG in $CONTAINER is empty" >&2; exit 2; }
  render "$ROLE" < "$old" > "$new"
  echo "pft-peerexpose plan - $(date -u +%FT%TZ) - role $ROLE, container $CONTAINER${SSH_TARGET:+ (remote)}"
  echo "  effective now:   $(effective < "$old")"
  echo "  effective after: $(effective < "$new")"
  if [ "$(effective < "$old")" = "$(want_effective "$ROLE")" ] && [ "$(managed_view "$old")" = "$(managed_view "$new")" ]; then
    echo "RESULT: NO CHANGE (managed block already in place)"; return 0
  fi
  validate_cfg "$ROLE" "$old" "$new" | sed 's/^/  /'
  [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "RESULT: ERROR (rendered config failed validation)"; exit 2; }
  echo "  diff ([crawl]/[vl] sections only):"
  diff <(managed_view "$old") <(managed_view "$new") | sed 's/^/    /' || true
  echo "RESULT: CHANGE NEEDED (container restart required to take effect)"
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
    --ssh) SSH_TARGET="${2:-}"; shift ;;
    --old) OLD_FILE="${2:-}"; shift ;;
    --new) NEW_FILE="${2:-}"; shift ;;
    --timeout) TIMEOUT="${2:-}"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done
case "$ROLE" in validator|sentry) ;; *) echo "--role validator|sentry is required" >&2; exit 3 ;; esac
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "--timeout must be an integer" >&2; exit 3; }

case "$CMD" in
  render) render "$ROLE" ;;
  validate)
    if [ ! -r "$OLD_FILE" ] || [ ! -r "$NEW_FILE" ]; then echo "validate needs readable --old FILE and --new FILE" >&2; exit 3; fi
    validate_cfg "$ROLE" "$OLD_FILE" "$NEW_FILE" || exit 1 ;;
  plan) plan ;;
  audit)
    audit
    rc=0; report || rc=$?
    exit "$rc" ;;
  *) echo "unknown command: $CMD" >&2; usage ;;
esac
