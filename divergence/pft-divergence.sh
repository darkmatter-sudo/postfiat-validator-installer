#!/usr/bin/env bash
# pft-divergence - read-only consensus-divergence check across two or more postfiatd RPC sources.
#
# A node can be up, "full" and fresh while it follows a different ledger chain than the network. This check
# asks every source for its newest validated ledger, takes the lowest of them (the latest index every source
# should hold, "tip") plus one deeper index (tip - DEPTH, "deep"), and compares ledger_hash, account_hash and
# transaction_hash at both indexes.
#
# Sources (SOURCES, space separated NAME=KIND:TARGET):
#   docker:CONTAINER        docker exec CONTAINER curl http://127.0.0.1:5005 (admin RPC inside the container)
#   ssh:HOST:CONTAINER      ssh -o BatchMode=yes HOST sudo -n docker exec CONTAINER curl ... (SSH_RUNAS=USER runs
#                           ssh as that user, for a root timer using the operator's ssh config)
#   http:URL                curl URL (e.g. the public RPC)
#
# Per source and overall state:
#   AGREE     hashes at tip and deep match every other source that answered
#   DIVERGED  a hash differs from the majority, and still differs after CONFIRM re-queries spaced by the
#             backoff (with no majority, e.g. two sources, every disagreeing source is DIVERGED)
#   UNKNOWN   the source did not answer after all retries, the index is outside its complete_ledgers, the
#             ledger is not validated, or there was nothing to compare against
# Every failed RPC is retried with BACKOFF (default "2 5 10" s) and every retry is printed on stderr, so a
# transient public-RPC error never counts as DIVERGED. Overall: DIVERGED > UNKNOWN > AGREE.
#
# Usage: sudo pft-divergence [--json] [--sources "..."] [--depth N] [--backoff "S S .."] [--confirm N]
#                            [--textfile FILE|--no-textfile] [--state FILE|--no-state] [--timeout S]
#                            [--ssh-runas USER] [--check-config]
#   config: $PFT_DIVERGENCE_CONF (default /etc/pft-divergence/divergence.env, root-owned, not group/world
#           writable) may set SOURCES DEPTH BACKOFF CONFIRM TEXTFILE STATE TIMEOUT SSH_RUNAS; flags win.
#   --textfile  Prometheus textfile, written atomically (default /var/lib/pft-exporter/textfile/pft_divergence.prom)
#   --check-config  validate options and sources, print them, exit 0 (nothing is queried)
#   --state     keeps last_agree_ledger between runs (default /var/lib/pft-divergence/state.json)
# Output: one human line on stdout (or one JSON object with --json); retries and re-queries on stderr.
# Exit: 0 AGREE, 1 UNKNOWN, 2 DIVERGED, 3 usage error.
set -euo pipefail

SOURCES="validator=docker:postfiatd public=http:https://rpc.testnet.postfiat.org/"
DEPTH=200
BACKOFF="2 5 10"
CONFIRM=2
TEXTFILE=/var/lib/pft-exporter/textfile/pft_divergence.prom
STATE=/var/lib/pft-divergence/state.json
TIMEOUT=10
SSH_RUNAS=""
CONF="${PFT_DIVERGENCE_CONF:-/etc/pft-divergence/divergence.env}"

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
die() { echo "pft-divergence: $*" >&2; exit 3; }

if [ -f "$CONF" ]; then
  perm="$(stat -c '%u %a' "$CONF")"
  [ "${perm%% *}" = 0 ] || [ "${perm%% *}" = "$(id -u)" ] || die "$CONF must be owned by root"
  [ $(( 8#${perm##* } & 8#022 )) -eq 0 ] || die "$CONF must not be group/world writable"
  # shellcheck source=/dev/null
  . "$CONF"
fi

JSON=false; CHECK_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=true ;;
    --sources) SOURCES="$2"; shift ;;
    --depth) DEPTH="$2"; shift ;;
    --backoff) BACKOFF="$2"; shift ;;
    --confirm) CONFIRM="$2"; shift ;;
    --textfile) TEXTFILE="$2"; shift ;;
    --no-textfile) TEXTFILE="" ;;
    --state) STATE="$2"; shift ;;
    --no-state) STATE="" ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --ssh-runas) SSH_RUNAS="$2"; shift ;;
    --check-config) CHECK_ONLY=true ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
  shift
done
# shellcheck disable=SC2086  # BACKOFF is a word list
for n in "$DEPTH" "$CONFIRM" "$TIMEOUT" $BACKOFF; do
  [[ "$n" =~ ^[0-9]+$ ]] || die "depth/confirm/timeout/backoff must be non-negative integers"
done
command -v jq >/dev/null || die "jq required"
[ -z "$SSH_RUNAS" ] || [[ "$SSH_RUNAS" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "bad SSH_RUNAS"

NAMES=(); KINDS=(); TGTS=()
for s in $SOURCES; do
  name="${s%%=*}"; spec="${s#*=}"; kind="${spec%%:*}"; tgt="${spec#*:}"
  [[ "$name" =~ ^[a-z0-9_-]+$ ]] || die "bad source name in '$s'"
  case "$kind" in
    docker) [[ "$tgt" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad container in '$s'" ;;
    ssh) [[ "$tgt" =~ ^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$ ]] || die "ssh source must be ssh:HOST:CONTAINER ('$s')" ;;
    http) [[ "$tgt" =~ ^https?://[^[:space:]\'\"]+$ ]] || die "bad URL in '$s'" ;;
    *) die "unknown source kind '$kind' in '$s'" ;;
  esac
  NAMES+=("$name"); KINDS+=("$kind"); TGTS+=("$tgt")
done
[ "${#NAMES[@]}" -ge 2 ] || die "need at least two sources"
[ "$(printf '%s\n' "${NAMES[@]}" | sort -u | wc -l)" -eq "${#NAMES[@]}" ] || die "duplicate source name"
read -r -a WAITS <<< "$BACKOFF"
if $CHECK_ONLY; then
  for ((i = 0; i < ${#NAMES[@]}; i++)); do echo "source ${NAMES[$i]}: ${KINDS[$i]} ${TGTS[$i]}"; done
  echo "depth $DEPTH, backoff '$BACKOFF', confirm $CONFIRM, timeout ${TIMEOUT}s, textfile ${TEXTFILE:-none}, state ${STATE:-none}"
  exit 0
fi
RETRY_LOG="$(mktemp)"   # rpc() runs in $(...) subshells, so retries are counted in a file, not a variable
trap 'rm -f "$RETRY_LOG"' EXIT

call() { # i body -> raw answer on stdout (empty on transport failure)
  local kind="${KINDS[$1]}" tgt="${TGTS[$1]}" body="$2" runas=()
  case "$kind" in
    docker) docker exec "$tgt" curl -s --max-time "$TIMEOUT" -H 'Content-Type: application/json' \
              -d "$body" http://127.0.0.1:5005/ 2>/dev/null || true ;;
    ssh) [ -z "$SSH_RUNAS" ] || runas=(runuser -u "$SSH_RUNAS" --)
         "${runas[@]}" ssh -o BatchMode=yes -o ConnectTimeout=5 "${tgt%%:*}" \
           "sudo -n docker exec ${tgt#*:} curl -s --max-time $TIMEOUT -H 'Content-Type: application/json' -d '$body' http://127.0.0.1:5005/" \
           2>/dev/null </dev/null || true ;;
    http) curl -s --max-time "$TIMEOUT" -H 'Content-Type: application/json' -d "$body" "$tgt" 2>/dev/null || true ;;
  esac
}

# rpc i what body jq-filter -> filter output on stdout, 0 on success. The filter must print "ERR <reason>"
# for a bad answer. Retries with backoff; every retry goes to stderr.
rpc() {
  local i="$1" what="$2" body="$3" filter="$4" a out n=0 reason
  while :; do
    a="$(call "$i" "$body")"
    if [ -z "$a" ]; then reason="no answer"
    elif ! out="$(jq -r "$filter" <<<"$a" 2>/dev/null)"; then reason="unparsable answer"
    elif [[ "$out" == ERR* ]]; then reason="${out#ERR }"
    else printf '%s' "$out"; return 0; fi
    if [ "$n" -ge "${#WAITS[@]}" ]; then
      printf 'giving up %s %s after %d attempts: %s\n' "${NAMES[$i]}" "$what" "$((n + 1))" "$reason" >&2
      printf '%s' "$reason"; return 1
    fi
    printf 'retry %s %s %d/%d in %ss: %s\n' "${NAMES[$i]}" "$what" "$((n + 1))" "${#WAITS[@]}" "${WAITS[$n]}" "$reason" >&2
    echo >> "$RETRY_LOG"
    sleep "${WAITS[$n]}"
    n=$((n + 1))
  done
}

ERRF='if .result.status != "success" then "ERR " + (.result.error // .error // "status " + (.result.status // "missing"))'
INFO_F="$ERRF"' elif (.result.info.validated_ledger.seq // null) == null then "ERR no validated ledger"
  else "\(.result.info.validated_ledger.seq) \(.result.info.complete_ledgers // "empty")" end'
ledger_f() {
  printf '%s' "$ERRF"' elif .result.validated != true then "ERR ledger '"$1"' not validated"
  elif (.result.ledger_index|tostring) != "'"$1"'" then "ERR answered ledger \(.result.ledger_index) for '"$1"'"
  elif ([.result.ledger.ledger_hash, .result.ledger.account_hash, .result.ledger.transaction_hash]
        | all(type == "string" and test("^[0-9A-F]{64}$"))) | not then "ERR missing/malformed hash"
  else "\(.result.ledger.ledger_hash) \(.result.ledger.account_hash) \(.result.ledger.transaction_hash)" end'
}

in_complete() { # idx complete_ledgers -> 0 if held
  local r lo hi rs
  IFS=, read -r -a rs <<< "$2"
  for r in "${rs[@]}"; do
    [[ "$r" =~ ^([0-9]+)(-([0-9]+))?$ ]] || continue
    lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[3]:-$lo}"
    [ "$1" -ge "$lo" ] && [ "$1" -le "$hi" ] && return 0
  done
  return 1
}

declare -A ST REASON SEQ CL HASH
FIELDS=(ledger_hash account_hash transaction_hash)
setst() { # i state reason  (keeps the worst: DIVERGED > UNKNOWN > AGREE)
  local cur="${ST[$1]:-AGREE}"
  case "$2:$cur" in
    DIVERGED:*|UNKNOWN:AGREE) ST[$1]="$2"; REASON[$1]="$3" ;;
  esac
}

N="${#NAMES[@]}"
answered=()
for ((i = 0; i < N; i++)); do
  if out="$(rpc "$i" server_info '{"method":"server_info","params":[{}]}' "$INFO_F")"; then
    SEQ[$i]="${out%% *}"; CL[$i]="${out#* }"; answered+=("$i")
  else
    setst "$i" UNKNOWN "server_info: $out"
  fi
done

TIP=0; DEEP=0
if [ "${#answered[@]}" -ge 2 ]; then
  TIP="$(for i in "${answered[@]}"; do echo "${SEQ[$i]}"; done | sort -n | head -1)"
  DEEP=$((TIP - DEPTH))
  [ "$DEEP" -ge 1 ] || DEEP=1
fi

compare() { # idx label: fill HASH[i,label] for usable sources, then judge
  local idx="$1" lab="$2" i out have=() keys nk c maj cnt
  for i in "${answered[@]}"; do
    if ! in_complete "$idx" "${CL[$i]}"; then
      setst "$i" UNKNOWN "$lab $idx outside complete_ledgers ${CL[$i]}"; continue
    fi
    if out="$(rpc "$i" "ledger $idx" '{"method":"ledger","params":[{"ledger_index":'"$idx"'}]}' "$(ledger_f "$idx")")"; then
      HASH[$i,$lab]="$out"; have+=("$i")
    else
      setst "$i" UNKNOWN "$lab ledger $idx: $out"
    fi
  done
  if [ "${#have[@]}" -lt 2 ]; then
    for i in "${have[@]}"; do setst "$i" UNKNOWN "$lab $idx: nothing to compare against"; done
    return
  fi
  for ((c = 0; ; c++)); do
    keys="$(for i in "${have[@]}"; do echo "${HASH[$i,$lab]}"; done | sort | uniq -c | sort -rn)"
    nk="$(wc -l <<<"$keys")"
    [ "$nk" -gt 1 ] || { [ "$c" -eq 0 ] || echo "mismatch at $lab $idx resolved on re-query $c" >&2; return; }
    [ "$c" -lt "$CONFIRM" ] || break
    local w="${WAITS[$(( c < ${#WAITS[@]} ? c : ${#WAITS[@]} - 1 ))]:-0}"
    echo "mismatch at $lab $idx ($nk distinct hash sets), re-query $((c + 1))/$CONFIRM in ${w}s" >&2
    sleep "$w"
    for i in "${have[@]}"; do
      if out="$(rpc "$i" "ledger $idx" '{"method":"ledger","params":[{"ledger_index":'"$idx"'}]}' "$(ledger_f "$idx")")"; then
        HASH[$i,$lab]="$out"
      fi
    done
  done
  cnt="$(head -1 <<<"$keys" | awk '{print $1}')"; maj=""
  [ $((cnt * 2)) -gt "${#have[@]}" ] && maj="$(head -1 <<<"$keys" | awk '{print $2, $3, $4}')"
  for i in "${have[@]}"; do
    if [ -n "$maj" ] && [ "${HASH[$i,$lab]}" = "$maj" ]; then continue; fi
    local f="" mine ref k k0=""
    read -r -a mine <<< "${HASH[$i,$lab]}"
    read -r -a ref <<< "${maj:-$(for j in "${have[@]}"; do [ "${HASH[$j,$lab]}" = "${HASH[$i,$lab]}" ] || { echo "${HASH[$j,$lab]}"; break; }; done)}"
    for k in 0 1 2; do
      [ "${mine[$k]}" = "${ref[$k]}" ] && continue
      f="$f${f:+,}${FIELDS[$k]}"; k0="${k0:-$k}"
    done
    setst "$i" DIVERGED "$lab $idx $f ${mine[$k0]:0:16} != ${maj:+majority }${ref[$k0]:0:16}"
  done
}

if [ "${#answered[@]}" -ge 2 ]; then
  compare "$TIP" tip
  compare "$DEEP" deep
else
  for i in "${answered[@]}"; do setst "$i" UNKNOWN "fewer than 2 sources answered server_info"; done
fi

RETRIES="$(wc -l < "$RETRY_LOG")"
OVERALL=AGREE
for ((i = 0; i < N; i++)); do
  case "${ST[$i]:-AGREE}" in DIVERGED) OVERALL=DIVERGED ;; UNKNOWN) [ "$OVERALL" = DIVERGED ] || OVERALL=UNKNOWN ;; esac
done

NOW="$(date -u +%s)"
LAST_AGREE=0
if [ -n "$STATE" ] && [ -f "$STATE" ]; then LAST_AGREE="$(jq -r '.last_agree_ledger // 0' "$STATE" 2>/dev/null || echo 0)"; fi
[[ "$LAST_AGREE" =~ ^[0-9]+$ ]] || LAST_AGREE=0
[ "$OVERALL" != AGREE ] || LAST_AGREE="$TIP"
if [ -n "$STATE" ]; then
  mkdir -p "$(dirname "$STATE")"
  printf '{"last_agree_ledger":%s,"last_state":"%s","ts":%s}\n' "$LAST_AGREE" "$OVERALL" "$NOW" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
fi

num() { case "$1" in AGREE) echo 0 ;; DIVERGED) echo 1 ;; *) echo 2 ;; esac; }
if [ -n "$TEXTFILE" ]; then
  d="$(dirname "$TEXTFILE")"; mkdir -p "$d"
  tmp="$(mktemp "$d/.pft_divergence.XXXXXX")"
  {
    echo "# HELP pft_divergence_state Per-source result of the last divergence check: 0 AGREE, 1 DIVERGED, 2 UNKNOWN"
    echo "# TYPE pft_divergence_state gauge"
    for ((i = 0; i < N; i++)); do printf 'pft_divergence_state{source="%s"} %s\n' "${NAMES[$i]}" "$(num "${ST[$i]:-AGREE}")"; done
    echo "# HELP pft_divergence_overall_state Worst state over all sources: 0 AGREE, 1 DIVERGED, 2 UNKNOWN"
    echo "# TYPE pft_divergence_overall_state gauge"
    echo "pft_divergence_overall_state $(num "$OVERALL")"
    echo "# HELP pft_divergence_last_agree_ledger Newest tip index at which all sources agreed"
    echo "# TYPE pft_divergence_last_agree_ledger gauge"
    echo "pft_divergence_last_agree_ledger $LAST_AGREE"
    echo "# HELP pft_divergence_checked_ledger Ledger indexes compared in the last check"
    echo "# TYPE pft_divergence_checked_ledger gauge"
    printf 'pft_divergence_checked_ledger{depth="tip"} %s\npft_divergence_checked_ledger{depth="deep"} %s\n' "$TIP" "$DEEP"
    echo "# HELP pft_divergence_retries RPC retries needed in the last check"
    echo "# TYPE pft_divergence_retries gauge"
    echo "pft_divergence_retries $RETRIES"
    echo "# HELP pft_divergence_check_timestamp Unix time of the last completed check"
    echo "# TYPE pft_divergence_check_timestamp gauge"
    echo "pft_divergence_check_timestamp $NOW"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE"
fi

if $JSON; then
  for ((i = 0; i < N; i++)); do
    jq -nc --arg n "${NAMES[$i]}" --arg s "${ST[$i]:-AGREE}" --arg r "${REASON[$i]:-}" --arg seq "${SEQ[$i]:-}" \
       --arg t "${HASH[$i,tip]:-}" --arg d "${HASH[$i,deep]:-}" \
       '{name:$n, state:$s, reason:$r, validated_seq:($seq|tonumber? // null),
         tip_ledger_hash:($t|split(" ")[0] // null), deep_ledger_hash:($d|split(" ")[0] // null)}'
  done | jq -sc --arg st "$OVERALL" --argjson tip "$TIP" --argjson deep "$DEEP" --argjson la "$LAST_AGREE" \
          --argjson r "$RETRIES" --argjson ts "$NOW" \
          '{ts:$ts, state:$st, tip:$tip, deep:$deep, last_agree_ledger:$la, retries:$r, sources:.}'
else
  line="$(date -u -d "@$NOW" +%FT%TZ) $OVERALL tip=$TIP deep=$DEEP retries=$RETRIES"
  for ((i = 0; i < N; i++)); do
    line="$line ${NAMES[$i]}=${ST[$i]:-AGREE}"
    [ -z "${REASON[$i]:-}" ] || line="$line(${REASON[$i]})"
  done
  [ "$OVERALL" != AGREE ] || line="$line hash=${HASH[${answered[0]},tip]:0:16}"
  echo "$line"
fi
case "$OVERALL" in AGREE) exit 0 ;; UNKNOWN) exit 1 ;; *) exit 2 ;; esac
