#!/usr/bin/env bash
# pft-peertls: read-only TLS posture audit of this operator's own Post Fiat peer ports (2559).
# The peer protocol runs over TLS with a certificate postfiatd generates at start; which protocols, suites and
# handshake features it accepts comes from the build, not from postfiatd.cfg. This probes the port with openssl
# s_client (one handshake per probe, paced, capped at MAX_HANDSHAKES per run), writes every raw answer into a bundle
# and peertls_eval.py grades it against POLICY_DIR/ROLE.policy: protocols, TLS 1.2 suite classes, TLS 1.3 suites,
# DHE group size, certificate key/signature/validity, compression, RFC 5746, client renegotiation, FALLBACK_SCSV,
# extended master secret, ticket lifetime, and drift of all of it (and of the certificate) since the last run.
#
# Usage: sudo pft-peertls collect [--target NAME] [--out FILE]           write a capture bundle (default: stdout)
#        sudo pft-peertls audit [--target NAME] [--json] [--public] [--bundle FILE] [--textfile] [--no-state]
#                                                     exit 0 PASS, 1 WARN, 2 FAIL, 3 usage/policy, 4 capture
#        sudo pft-peertls pull                        validator: copy the peer's textfile (PULL_SSH in the env file)
#        pft-peertls validate FILE HOST               the check pull applies to a fetched textfile
#        pft-peertls render REPORT.json               human report from a JSON report (offline, no network)
#        pft-peertls crosscheck A.json B.json         a remote view of a host == that host's own local view
#        pft-peertls plan [--target NAME]             the probes a run would make and its handshake count
#        pft-peertls version
#
# Targets come only from TARGETS (root-owned, kept off the public repo): `NAME ADDR PORT local|remote [CONTAINER]`.
# A local target must be a loopback address; a remote target must use PEER_PORT; nothing else is ever probed (no
# scanning, no third-party hosts). Without --target every local target is audited. A run whose probe plan exceeds
# MAX_HANDSHAKES (40) is refused before the first connection. Probes are PACE_LOCAL (0.2 s) apart on loopback and
# PACE_REMOTE (6 s) apart across hosts, under UFW's LIMIT rule (6 new connections per 30 s per source).
# --public drops findings waived in WAIVERS (open weaknesses that cannot be fixed here: they are reported privately,
# never published) and the probes behind them; counts stay. --textfile writes TEXTFILE_DIR/pft_peertls_HOST.prom
# (atomic): pft_peertls_up, pft_peertls_last_run_timestamp_seconds and, when graded, pft_peertls_verdict (0/1/2),
# pft_peertls_checks{result}, pft_peertls_check{target,check} (0 pass, 1 warn, 2 fail, 3 waived, -1 info),
# pft_peertls_drift{target}, pft_peertls_handshakes and pft_peertls_cert_not_after_seconds{target}.
# Conf: PFT_PTLS_CONF (/etc/pft-peertls.env, root-owned): ROLE (validator), POLICY_DIR (/usr/local/lib/pft-peertls/policy),
#       TARGETS (/etc/pft-peertls.targets), WAIVERS (/etc/pft-peertls.waivers), PEER_PORT (2559), MAX_HANDSHAKES (40),
#       PACE_LOCAL (0.2), PACE_REMOTE (6), PROBE_TIMEOUT (10), STATE_DIR (/var/lib/pft-peertls), HOST_LABEL (= ROLE),
#       TEXTFILE_DIR (/var/lib/pft-exporter/textfile); pull: PEER_LABEL (sentry), PULL_SSH, PULL_TIMEOUT (30),
#       REMOTE_DIR (/var/lib/pft-exporter/textfile), MAX_BYTES (65536)
# Test hooks: PFT_PTLS_TEST=1 (no root check; lets TARGETS name loopback fixture ports), PFT_PTLS_EVAL (path of
#       peertls_eval.py), PFT_PTLS_OPENSSL (openssl command), PFT_PTLS_DOCKER (docker command), PFT_PTLS_NOW (epoch)

set -uo pipefail
umask 077
VERSION=1

CONF="${PFT_PTLS_CONF:-/etc/pft-peertls.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
ROLE="${ROLE:-validator}"
POLICY_DIR="${POLICY_DIR:-/usr/local/lib/pft-peertls/policy}"
TARGETS="${TARGETS:-/etc/pft-peertls.targets}"
WAIVERS="${WAIVERS:-/etc/pft-peertls.waivers}"
PEER_PORT="${PEER_PORT:-2559}"
MAX_HANDSHAKES="${MAX_HANDSHAKES:-40}"
PACE_LOCAL="${PACE_LOCAL:-0.2}"
PACE_REMOTE="${PACE_REMOTE:-6}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-10}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-peertls}"
HOST_LABEL="${HOST_LABEL:-}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
PEER_LABEL="${PEER_LABEL:-sentry}"
PULL_SSH="${PULL_SSH:-}"
PULL_TIMEOUT="${PULL_TIMEOUT:-30}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
MAX_BYTES="${MAX_BYTES:-65536}"
TEST="${PFT_PTLS_TEST:-}"
EVAL="${PFT_PTLS_EVAL:-/usr/local/lib/pft-peertls/peertls_eval.py}"
read -r -a OPENSSL <<<"${PFT_PTLS_OPENSSL:-openssl}"
read -r -a DOCKER <<<"${PFT_PTLS_DOCKER:-docker}"

die() { printf 'pft-peertls: %s\n' "$1" >&2; exit "${2:-3}"; }
now() { if [ -n "${PFT_PTLS_NOW:-}" ]; then echo "$PFT_PTLS_NOW"; else date -u +%s; fi; }
need_root() { [ -n "$TEST" ] || [ "$(id -u)" = 0 ] || die "must run as root (reads the root-owned targets and waivers)" 3; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
is_loopback() { [[ "$1" =~ ^127\.[0-9]+\.[0-9]+\.[0-9]+$ || "$1" == "::1" ]]; }
evalpy() { python3 -I "$EVAL" "$@"; }

TMP=""
tmpdir() { [ -n "$TMP" ] || { TMP="$(mktemp -d)" || die "mktemp failed" 4; trap 'rm -rf "$TMP"' EXIT; }; }

# ---------- targets ----------
T_NAME=() T_ADDR=() T_PORT=() T_SCOPE=() T_CONT=()
load_targets() { # WANT ("" = every local target) -> fills T_*; dies on any line it would not probe
  local want="$1" n=0 name addr port scope cont extra
  [ -f "$TARGETS" ] || die "no targets file $TARGETS" 3
  [ -n "$TEST" ] || [ "$(stat -c %u "$TARGETS")" = 0 ] || die "$TARGETS is not root-owned" 3
  while read -r name addr port scope cont extra; do
    n=$((n + 1))
    case "$name" in ''|'#'*) continue ;; esac
    [ -z "${extra:-}" ] || die "$TARGETS line $n: too many fields" 3
    valid_label "$name" || die "$TARGETS line $n: bad name $name" 3
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "$TARGETS line $n: bad port $port" 3
    [[ "$addr" =~ ^[0-9a-fA-F.:]+$ ]] || die "$TARGETS line $n: address must be a literal IP ($addr)" 3
    case "$scope" in
      local) is_loopback "$addr" || die "$TARGETS line $n: local target $name must be loopback" 3 ;;
      remote) is_loopback "$addr" && die "$TARGETS line $n: remote target $name is loopback" 3 ;;
      *) die "$TARGETS line $n: scope must be local or remote" 3 ;;
    esac
    if [ "$port" != "$PEER_PORT" ] && ! { [ -n "$TEST" ] && is_loopback "$addr"; }; then
      die "$TARGETS line $n: $name port $port is not the peer port $PEER_PORT" 3
    fi
    if [ -n "$want" ]; then [ "$name" = "$want" ] || continue; else [ "$scope" = local ] || continue; fi
    T_NAME+=("$name") T_ADDR+=("$addr") T_PORT+=("$port") T_SCOPE+=("$scope") T_CONT+=("${cont:--}")
  done < "$TARGETS"
  [ "${#T_NAME[@]}" -gt 0 ] || die "no target ${want:-of scope local} in $TARGETS" 3
}

handshakes_per_target() { # reneg is two handshakes on one connection; the cert fetch is one more
  evalpy matrix | awk '{ n += ($2 == "reneg") ? 2 : 1 } END { print n }'
}

plan() {
  local per total
  per="$(handshakes_per_target)" || die "cannot read the probe matrix from $EVAL" 3
  total=$((per * ${#T_NAME[@]}))
  printf 'targets: %s\nprobes per target: %s handshakes\ntotal: %s (max %s)\n' "${T_NAME[*]}" "$per" "$total" "$MAX_HANDSHAKES"
  [ "$total" -le "$MAX_HANDSHAKES" ]
}

# ---------- probing ----------
HS=0
hostport() { if [[ "$1" == *:* ]]; then printf '[%s]:%s' "$1" "$2"; else printf '%s:%s' "$1" "$2"; fi; }
probe() { # ADDR PORT FLAG OFFER KIND: one s_client run, raw output to stdout as a bundle section body + rc
  local addr="$1" port="$2" flag="$3" offer="$4" kind="$5" rc pc
  pc=("${OPENSSL[@]}" s_client -connect "$(hostport "$addr" "$port")" -noservername)
  [ "$flag" = - ] || pc+=("$flag")
  case "$kind" in
    tls13) pc+=(-ciphersuites "$offer") ;;
    fallback) pc+=(-fallback_scsv) ;;
    *) [ "$offer" = - ] || pc+=(-cipher "$offer") ;;
  esac
  printf '### $ %s\n' "${pc[*]}"
  if [ "$kind" = reneg ]; then
    { sleep 1; printf 'R\n'; sleep 2; } | timeout "$PROBE_TIMEOUT" "${pc[@]}" 2>&1
    rc=${PIPESTATUS[1]}
    HS=$((HS + 2))
  else
    timeout "$PROBE_TIMEOUT" "${pc[@]}" </dev/null 2>&1
    rc=$?
    HS=$((HS + 1))
  fi
  printf '### rc=%s\n' "$rc"
}

started_at() { # CONTAINER -> epoch of its current start, or "-"
  local s
  [ "$1" != - ] || { echo -; return; }
  s="$("${DOCKER[@]}" inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null)" || { echo -; return; }
  date -u -d "$s" +%s 2>/dev/null || echo -
}

collect() {
  local i pid kind flag offer pace pem
  plan >/dev/null || die "probe plan exceeds MAX_HANDSHAKES ($MAX_HANDSHAKES); audit fewer targets per run" 3
  for i in "${!T_NAME[@]}"; do
    if [ "${T_SCOPE[$i]}" = local ]; then pace="$PACE_LOCAL"; else pace="$PACE_REMOTE"; fi
    printf '### target %s scope=%s started=%s\n' "${T_NAME[$i]}" "${T_SCOPE[$i]}" "$(started_at "${T_CONT[$i]}")"
    while read -r pid kind flag offer; do
      if [ "$kind" = cert ]; then
        printf '### cert\n'
        pem="$(timeout "$PROBE_TIMEOUT" "${OPENSSL[@]}" s_client -connect "$(hostport "${T_ADDR[$i]}" "${T_PORT[$i]}")" -noservername \
          </dev/null 2>/dev/null)"
        HS=$((HS + 1))
        printf '%s\n' "$pem" | "${OPENSSL[@]}" x509 -noout -text -fingerprint -sha256 2>&1
      else
        printf '### probe %s offer=%s\n' "$pid" "$offer"
        probe "${T_ADDR[$i]}" "${T_PORT[$i]}" "$flag" "$offer" "$kind"
      fi
      sleep "$pace"
    done < <(evalpy matrix)
  done
  printf '### end handshakes=%s\n' "$HS"
}

# ---------- grading, textfile ----------
state_file() { printf '%s/state-%s.json' "$STATE_DIR" "$(IFS=+; echo "${T_NAME[*]}")"; }

grade() { # BUNDLE [eval flags...] -> runs the evaluator against this role's policy, waivers and state
  local b="$1"; shift
  evalpy audit "$b" --policy "$POLICY_DIR/$ROLE.policy" --waivers "$WAIVERS" --host "$HOST_LABEL" --now "$(now)" "$@"
}

metrics() { # UP TS [REPORT_JSON]
  local L="host=\"$HOST_LABEL\""
  printf '# HELP pft_peertls_up 1 = the last run captured every probe and graded it against the policy.\n'
  printf '# TYPE pft_peertls_up gauge\npft_peertls_up{%s} %s\n' "$L" "$1"
  printf '# HELP pft_peertls_last_run_timestamp_seconds Unix time of the last run.\n'
  printf '# TYPE pft_peertls_last_run_timestamp_seconds gauge\npft_peertls_last_run_timestamp_seconds{%s} %s\n' "$L" "$2"
  [ "$1" = 1 ] || return 0
  jq -r --arg L "$L" '
    "# HELP pft_peertls_verdict Verdict of the last run: 0 PASS, 1 WARN, 2 FAIL.",
    "# TYPE pft_peertls_verdict gauge",
    "pft_peertls_verdict{\($L)} \({"PASS": 0, "WARN": 1, "FAIL": 2}[.verdict])",
    "# HELP pft_peertls_handshakes TLS handshakes the last run made.",
    "# TYPE pft_peertls_handshakes gauge",
    "pft_peertls_handshakes{\($L)} \(.handshakes)",
    "# HELP pft_peertls_checks Checks of the last run by result.",
    "# TYPE pft_peertls_checks gauge",
    (.counts | to_entries[] | "pft_peertls_checks{\($L),result=\"\(.key | ascii_downcase)\"} \(.value)"),
    "# HELP pft_peertls_check Result per check: 0 pass, 1 warn, 2 fail, 3 waived, -1 info.",
    "# TYPE pft_peertls_check gauge",
    (.checks[] | "pft_peertls_check{\($L),target=\"\(.target)\",check=\"\(.id)\"} \({"PASS": 0, "WARN": 1, "FAIL": 2, "WAIVED": 3, "INFO": -1}[.result])"),
    "# HELP pft_peertls_drift Posture or certificate items that changed since the previous run (restart-explained certificate changes excluded).",
    "# TYPE pft_peertls_drift gauge",
    (.drift as $d | .targets[] | .name as $n | "pft_peertls_drift{\($L),target=\"\($n)\"} \([$d[] | select(.target == $n and (.restart | not))] | length)"),
    "# HELP pft_peertls_cert_not_after_seconds Expiry of the certificate the target presented.",
    "# TYPE pft_peertls_cert_not_after_seconds gauge",
    (.targets[] | select(.cert | type == "object") | "pft_peertls_cert_not_after_seconds{\($L),target=\"\(.name)\"} \(.cert.not_after)")
  ' <<<"$3"
}

write_textfile() { # CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_peertls_$HOST_LABEL.XXXXXX" 2>/dev/null)" || { echo "pft-peertls: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { printf '%s\n' "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_peertls_$HOST_LABEL.prom"; }; then
    rm -f "$t"; echo "pft-peertls: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

do_audit() { # BUNDLE|"" -> prints the report, maybe writes textfile and state; returns the verdict rc
  local b="$1" t0 rj rc st=() body
  t0="$(now)"
  if [ -z "$b" ]; then
    b="$TMP/bundle"
    if ! collect > "$b"; then [ "$TF" = 0 ] || write_textfile "$(metrics 0 "$t0")"; die "capture failed" 4; fi
  fi
  if [ "$NOSTATE" = 0 ]; then
    mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR" 4
    st=(--state "$(state_file)" --write-state "$TMP/state.new")
  fi
  rj="$(grade "$b" "${st[@]}" --json)"; rc=$?
  if [ "$rc" -gt 2 ] || ! jq -e '.verdict and .checks' >/dev/null 2>&1 <<<"$rj"; then
    [ "$TF" = 0 ] || write_textfile "$(metrics 0 "$t0")"
    [ "$rc" -gt 2 ] || rc=4
    echo "pft-peertls: grading error (rc=$rc)" >&2
    return "$rc"
  fi
  if [ "$NOSTATE" = 0 ]; then mv -f "$TMP/state.new" "$(state_file)" || die "cannot write state" 4; fi
  if [ "$TF" = 1 ]; then
    body="$(metrics 1 "$t0" "$rj")" || { write_textfile "$(metrics 0 "$t0")"; return 4; }
    write_textfile "$body" || return 4
  fi
  if [ "$PUBLIC" = 1 ]; then printf '%s\n' "$rj" > "$TMP/full.json"; rj="$(python3 -I -c '
import json, sys
sys.path.insert(0, sys.argv[1])
import peertls_eval
print(json.dumps(peertls_eval.public_view(json.load(open(sys.argv[2]))), indent=1, sort_keys=True))' "$(dirname "$EVAL")" "$TMP/full.json")" || return 4
  fi
  if [ "$JSON" = 1 ]; then printf '%s\n' "$rj"; else printf '%s\n' "$rj" > "$TMP/out.json"; evalpy render "$TMP/out.json"; fi
  return "$rc"
}

validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"; [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_peertls_[a-z_]+ / || /^$/ { next }
    {
      if (match($0, /^pft_peertls_[a-z_]+\{/) == 0) { printf "line %d: not a pft_peertls_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_peertls_up\{/) up = 1
      if ($0 ~ /^pft_peertls_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_peertls_up sample"; exit 1 }
      if (!ts) { print "no pft_peertls_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ "$PEER_LABEL" != "$HOST_LABEL" ] || die "refusing to pull over this host's own textfile ($PEER_LABEL)"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-peertls-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_peertls_$PEER_LABEL.prom" >"$tmp" 2>/dev/null </dev/null; then
    rm -f "$tmp"; die "fetch of pft_peertls_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_peertls_$PEER_LABEL.prom"; }; then rm -f "$tmp"; die "rename failed" 1; fi
}

# ---------- main ----------
cmd="${1:-}"; shift || true
case "$cmd" in
  validate)
    [ $# -eq 2 ] || die "usage: pft-peertls validate FILE HOST"
    valid_label "$2" || die "bad host label $2"
    why="$(validate "$1" "$2")" || { echo "INVALID: $why"; exit 1; }
    echo "OK"; exit 0 ;;
  render) [ $# -eq 1 ] || die "usage: pft-peertls render REPORT.json"; evalpy render "$1"; exit $? ;;
  crosscheck) [ $# -eq 2 ] || die "usage: pft-peertls crosscheck A.json B.json"; evalpy crosscheck "$1" "$2"; exit $? ;;
  version) echo "pft-peertls $VERSION"; exit 0 ;;
esac
JSON=0 PUBLIC=0 TF=0 NOSTATE=0 bundle="" out="" want=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) want="${2:?}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --public) PUBLIC=1; shift ;;
    --textfile) TF=1; shift ;;
    --no-state) NOSTATE=1; shift ;;
    --bundle) bundle="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --role) ROLE="${2:?}"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$ROLE" =~ ^[a-z][a-z0-9-]*$ ]] || die "bad role $ROLE"
HOST_LABEL="${HOST_LABEL:-$ROLE}"
valid_label "$HOST_LABEL" || die "bad HOST_LABEL $HOST_LABEL"
[[ "$MAX_HANDSHAKES" =~ ^[0-9]+$ && "$MAX_HANDSHAKES" -le 40 ]] || die "MAX_HANDSHAKES must be an integer <= 40"
[[ "$PACE_LOCAL" =~ ^[0-9]+(\.[0-9]+)?$ && "$PACE_REMOTE" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "bad PACE_LOCAL/PACE_REMOTE"
awk -v p="$PACE_REMOTE" 'BEGIN { exit !(p + 0 >= 5) }' || die "PACE_REMOTE must be >= 5 s (UFW LIMIT: 6 per 30 s)"
[[ "$PROBE_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PROBE_TIMEOUT"

case "$cmd" in
  plan) need_root; load_targets "$want"; plan; exit $? ;;
  collect)
    need_root; load_targets "$want"
    if [ -n "$out" ]; then collect > "$out" || die "cannot write $out" 4; else collect; fi ;;
  audit)
    tmpdir
    if [ -n "$bundle" ]; then
      [ -f "$bundle" ] || die "no bundle $bundle" 3
      NOSTATE=1
      T_NAME=(bundle)
    else
      need_root; load_targets "$want"
    fi
    do_audit "$bundle"; exit $? ;;
  pull) need_root; pull ;;
  *) sed -n '10,18p' "$0" >&2; exit 3 ;;
esac
