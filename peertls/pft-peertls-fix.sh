#!/usr/bin/env bash
# pft-peertls-fix: remediation for the pft-peertls findings cipher.kx_rsa / cipher.cbc_sha2 on a Dockerized postfiatd.
# The inbound peer TLS context comes from the [port_peer] port section: ServerHandler::makeContexts() builds it with
# that port's `ssl_ciphers` (Port.cpp parses the key). Without the key postfiatd uses its built-in TLS 1.2 list, and
# with the OpenSSL 1.1.1 the image links that list still admits static-RSA and CBC-SHA2 suites. This tool writes one
# managed `ssl_ciphers` line into [port_peer] (TLS 1.2 only; TLS 1.3 suites are not affected), restarts the node once
# and gates on health AND on the port's live TLS answer. pft-peertls.sh itself stays read-only.
#
# Usage: pft-peertls-fix plan                       read-only: current [port_peer], the diff apply would make, refusals
#        sudo pft-peertls-fix apply --yes [--dry-run]   (inside a pft-maint window) back up postfiatd.cfg (0600),
#                                                   install the managed line, docker restart, gate; a failed restart
#                                                   or gate restores the backup byte-identical, restarts and re-gates
#        sudo pft-peertls-fix rollback --yes        restore the newest backup, restart, gate (inside a pft-maint window)
# Exit: 0 ok / already applied, 1 gate failed and rolled back, 2 error, 3 usage, 4 refused (nothing changed),
#       5 rollback failed (node needs a human)
#
# Gate (every POLL_SEC until HEALTH_BUDGET s): container restarted (StartedAt changed), server_state full,
# pubkey_node unchanged, peers >= MIN_PEERS, PEER_PORT listening, and on 127.0.0.1:PEER_PORT (3 handshakes):
# ECDHE-RSA-AES256-GCM-SHA384 accepted, AES256-GCM-SHA384 (static RSA) and DHE-RSA-AES256-SHA256 (CBC) refused after
# apply / as found before apply after a rollback. Then pft-integrity accepts the new baseline only if the
# postfiatd config file is the sole changed item.
# Conf: PFT_PTLS_CONF (/etc/pft-peertls.env): CIPHERS (ECDHE+AESGCM:ECDHE+CHACHA20), CONTAINER (auto: postfiatd,
#       postfiatd-sentry), BACKUP_DIR (/var/lib/pft-peertls/backup), PEER_PORT (2559), MIN_PEERS (1),
#       HEALTH_BUDGET (600), POLL_SEC (5)
# Test hooks: PFT_PTLSF_ROOT (path prefix for the config file, no root check), PFT_PTLSF_DOCKER, PFT_PTLSF_OPENSSL,
#       PFT_PTLSF_RPC (called with CONTAINER METHOD), PFT_PTLSF_MAINT, PFT_PTLSF_INTEGRITY, PFT_PTLSF_SS

set -uo pipefail
umask 077

CONF="${PFT_PTLS_CONF:-/etc/pft-peertls.env}"
conf_get() { # root-owned conf only (any owner under the test root)
  [ -f "$CONF" ] && { [ "$(stat -c %u "$CONF")" = 0 ] || [ -n "${PFT_PTLSF_ROOT:-}" ]; } \
    && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
CIPHERS="$(conf_get CIPHERS)"; CIPHERS="${CIPHERS:-ECDHE+AESGCM:ECDHE+CHACHA20}"
CONTAINER="$(conf_get CONTAINER)"
BACKUP_DIR="$(conf_get BACKUP_DIR)"; BACKUP_DIR="${BACKUP_DIR:-/var/lib/pft-peertls/backup}"
PEER_PORT="$(conf_get PEER_PORT)"; PEER_PORT="${PEER_PORT:-2559}"
MIN_PEERS="$(conf_get MIN_PEERS)"; MIN_PEERS="${MIN_PEERS:-1}"
HEALTH_BUDGET="$(conf_get HEALTH_BUDGET)"; HEALTH_BUDGET="${HEALTH_BUDGET:-600}"
POLL_SEC="$(conf_get POLL_SEC)"; POLL_SEC="${POLL_SEC:-5}"
R="${PFT_PTLSF_ROOT:-}"
DOCKER="${PFT_PTLSF_DOCKER:-docker}"
OPENSSL="${PFT_PTLSF_OPENSSL:-openssl}"
MAINT="${PFT_PTLSF_MAINT:-pft-maint}"
INTEGRITY="${PFT_PTLSF_INTEGRITY:-pft-integrity}"
SS="${PFT_PTLSF_SS:-ss}"
CFG_DEST=/etc/postfiatd
MARK="# pft-peertls-fix: managed line (inbound peer TLS 1.2 suites; see peertls/README.md)"
GOOD_SUITE=ECDHE-RSA-AES256-GCM-SHA384
WEAK_SUITES="AES256-GCM-SHA384 DHE-RSA-AES256-SHA256"

indent() { sed 's/^/  /'; }
die() { echo "pft-peertls-fix: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
mode_of() { stat -c %a "$1" 2>/dev/null; }
for v in MIN_PEERS HEALTH_BUDGET POLL_SEC PEER_PORT; do [[ "${!v}" =~ ^[0-9]+$ ]] || die "bad $v in $CONF" 3; done
# an OpenSSL cipher string, nothing that could break out of the config line
[[ "$CIPHERS" =~ ^[A-Za-z0-9+:!@=_.-]{1,200}$ ]] || die "bad CIPHERS in $CONF" 3

detect_container() {
  [ -n "$CONTAINER" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }; done
  echo postfiatd
}
cfg_file() { # CONTAINER -> host path of postfiatd.cfg (the volume mounted at CFG_DEST)
  local s
  s="$("$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "'"$CFG_DEST"'"}}{{.Source}}{{end}}{{end}}' "$1" 2>/dev/null)"
  [ -n "$s" ] && echo "$R$s/postfiatd.cfg"
}
rpc() { # CONTAINER METHOD -> JSON (same exec shape as pft-cluster; the sentry has no host RPC mapping)
  if [ -n "${PFT_PTLSF_RPC:-}" ]; then "$PFT_PTLSF_RPC" "$1" "$2"; return; fi
  # shellcheck disable=SC2016  # ${RPC_PORT:-5005} expands inside the container's shell
  "$DOCKER" exec "$1" sh -c 'curl -s -m 5 -d "{\"method\":\"'"$2"'\"}" http://127.0.0.1:${RPC_PORT:-5005}/' 2>/dev/null
}
field() { rpc "$1" server_info | jq -r ".result.info.$2 // \"unknown\"" 2>/dev/null || echo unknown; }
started_at() { "$DOCKER" inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null; }

# [port_peer] lines (header excluded) up to the next section header
peer_section() { awk '/^[ \t]*\[/{ s = ($0 ~ /^[ \t]*\[port_peer\][ \t\r]*$/); next } s' "$1"; }
peer_headers() { grep -cE '^[ \t]*\[port_peer\][ \t\r]*$' "$1"; }
key_lines() { peer_section "$1" | grep -cE '^[ \t]*ssl_ciphers[ \t]*='; }
managed_ok() { # FILE -> 0 if [port_peer] holds exactly MARK + our line and no other ssl_ciphers
  [ "$(key_lines "$1")" = 1 ] && peer_section "$1" | grep -A1 -xF "$MARK" | tail -1 | grep -qxF "ssl_ciphers = $CIPHERS"
}
candidate() { # FILE -> stdout: the managed pair right after the [port_peer] header, earlier managed pair dropped
  awk -v mark="$MARK" -v line="ssl_ciphers = $CIPHERS" '
    /^[ \t]*\[/ { s = ($0 ~ /^[ \t]*\[port_peer\][ \t\r]*$/); print; if (s) { print mark; print line }; next }
    s && $0 == mark { skip = 1; next }
    s && skip && $0 ~ /^[ \t]*ssl_ciphers[ \t]*=/ { skip = 0; next }
    { skip = 0; print }' "$1"
}
refusals() { # FILE -> reasons apply must refuse, one per line
  local n k
  n="$(peer_headers "$1")"; k="$(key_lines "$1")"
  [ "$n" = 1 ] || echo "postfiatd.cfg has $n [port_peer] sections (want exactly 1)"
  awk '/^[ \t]*\[server\]/{s=1; next} /^[ \t]*\[/{s=0} s' "$1" | grep -qxE '[ \t]*port_peer[ \t\r]*' \
    || echo "[server] does not list port_peer"
  if [ "$k" != 0 ] && ! peer_section "$1" | grep -qxF "$MARK"; then
    echo "[port_peer] already has an unmanaged ssl_ciphers line (review it by hand)"
  elif [ "$k" -gt 1 ]; then echo "[port_peer] has $k ssl_ciphers lines"; fi
  "$OPENSSL" ciphers -tls1_2 "$CIPHERS" >/dev/null 2>&1 || echo "CIPHERS '$CIPHERS' selects no TLS 1.2 suite in $OPENSSL"
  return 0
}
handshake() { # SUITE -> negotiated suite or NONE (one TLS 1.2 handshake on loopback)
  local out c
  out="$(timeout 10 "$OPENSSL" s_client -connect "127.0.0.1:$PEER_PORT" -tls1_2 -cipher "$1@SECLEVEL=0" </dev/null 2>&1)"
  c="$(awk '/^New, /{print $NF; exit}' <<<"$out")"
  if [ -z "$c" ] || [ "$c" = "(NONE)" ]; then echo NONE; else echo "$c"; fi
}
tls_view() { # -> "GOOD=<suite> AES256-GCM-SHA384=<..> DHE-RSA-AES256-SHA256=<..>"
  local s out
  out="GOOD=$(handshake "$GOOD_SUITE")"
  for s in $WEAK_SUITES; do sleep 0.3; out+=" $s=$(handshake "$s")"; done
  echo "$out"
}
want_view() { # applied|<recorded pre-apply view> -> the view the gate requires
  if [ "$1" = applied ]; then echo "GOOD=$GOOD_SUITE AES256-GCM-SHA384=NONE DHE-RSA-AES256-SHA256=NONE"; else echo "$1"; fi
}
listening() { "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ":$PEER_PORT\$"; }
health_gate() { # BEFORE_STARTED_AT CONTAINER PUBKEY WANT_VIEW LABEL
  local before="$1" c="$2" pk="$3" want="$4" label="$5" start now sa st p peers view tls_wait=0
  start="$(date +%s)"; view="not checked"
  while :; do
    now="$(date +%s)"; sa="$(started_at "$c")"; st="$(field "$c" server_state)"; p="$(field "$c" pubkey_node)"
    peers="$(field "$c" peers)"; [[ "$peers" =~ ^[0-9]+$ ]] || peers=0
    if [ -n "$sa" ] && [ "$sa" != "$before" ] && [ "$st" = full ] && [ "$p" = "$pk" ] && [ "$peers" -ge "$MIN_PEERS" ] \
       && listening; then
      view="$(tls_view)"
      if [ "$view" = "$want" ]; then
        echo "$(ts) $label: PASS after $((now - start)) s ($c restarted, server_state full, pubkey_node unchanged, peers $peers, :$PEER_PORT listening, TLS $view)"
        return 0
      fi
      tls_wait=1
    fi
    if (( now - start >= HEALTH_BUDGET )); then
      echo "$(ts) $label: FAIL after $((now - start)) s (restarted=$([ "$sa" != "$before" ] && echo yes || echo NO); server_state=$st; pubkey_node $([ "$p" = "$pk" ] && echo same || echo CHANGED); peers=$peers; listening=$(listening && echo yes || echo NO); TLS $view; want $want)"
      return 1
    fi
    # a TLS mismatch waits 30 s before the next 3 handshakes (UFW LIMIT: 6 new connections / 30 s)
    if [ "${tls_wait:-0}" = 1 ]; then tls_wait=0; sleep 30; else sleep "$POLL_SEC"; fi
  done
}
restart_node() {
  "$DOCKER" restart -t 60 "$1" >/dev/null 2>&1 && { echo "$(ts) restart: $1 restarted"; return 0; }
  echo "$(ts) restart: docker restart $1 FAILED"; return 1
}
maint_window() {
  "$MAINT" active >/dev/null 2>&1 && { echo "$(ts) $1: pft-maint window active"; return 0; }
  echo "$(ts) $1: REFUSED - no active pft-maint window (sudo pft-maint start --ttl 30m --reason ...); nothing changed"
  return 1
}
integrity_accept() { # REASON: only if the postfiatd config file is the sole changed item
  command -v "$INTEGRITY" >/dev/null 2>&1 || { echo "$(ts) integrity: not installed, skipped"; return 0; }
  local out items other
  out="$("$INTEGRITY" verify 2>&1)"
  items="$(grep -E '^  \[(WARN|FAIL)\] ' <<<"$out" | awk '{print $2}' | sort -u)"
  [ -n "$items" ] || { echo "$(ts) integrity: baseline already current"; return 0; }
  other="$(grep -vxE 'cfgvol:postfiatd\.cfg' <<<"$items")"
  [ -z "$other" ] || { echo "$(ts) integrity: NOT accepted - changed items besides the config: $(paste -sd' ' <<<"$other")"; return 1; }
  if "$INTEGRITY" accept --reason "$1" >/dev/null 2>&1; then echo "$(ts) integrity: accepted (cfgvol:postfiatd.cfg only): $1"
  else echo "$(ts) integrity: accept FAILED"; return 1; fi
}
restore_cfg() { # BACKUP CFG
  local m u g
  if ! cp -p "$1" "$2" || [ "$(sha "$1")" != "$(sha "$2")" ]; then echo "$(ts) rollback: restore FAILED (sha256 mismatch)"; return 1; fi
  if read -r m u g < "$1.meta" 2>/dev/null && [[ "$m" =~ ^[0-7]{3,4}$ ]]; then chown "$u:$g" "$2" 2>/dev/null; chmod "$m" "$2"; fi
  echo "$(ts) rollback: postfiatd.cfg restored byte-identical (sha256 $(sha "$2" | cut -c1-12), mode $(mode_of "$2"))"
}
locate() { # sets C CFG or dies
  C="$(detect_container)"; CFG="$(cfg_file "$C")"
  if [ -z "$CFG" ] || [ ! -f "$CFG" ]; then die "cannot find postfiatd.cfg of $C" 2; fi
}
show_diff() { # CFG CAND (no secrets: only [port_peer] changes, other lines are context-free)
  diff -U0 --label postfiatd.cfg --label postfiatd.cfg.candidate "$1" "$2" | grep -vE '^@@'
}

do_plan() {
  local cand rf
  locate
  echo "pft-peertls-fix plan - $(ts) (container $C, CIPHERS $CIPHERS)"
  echo "[port_peer] now:"; peer_section "$CFG" | grep -vE '^[ \t]*(#|$)' | sed 's/^/  /'
  if managed_ok "$CFG"; then echo "already applied (managed line present)"; fi
  rf="$(refusals "$CFG")"
  [ -n "$rf" ] && { echo "REFUSE:"; indent <<<"$rf"; return 4; }
  cand="$(mktemp -p "${TMPDIR:-/tmp}" .ptlsf.XXXXXX)" || die "mktemp failed"
  candidate "$CFG" > "$cand"; echo "diff:"; show_diff "$CFG" "$cand" | sed 's/^/  /'; rm -f "$cand"
  echo "then: docker restart $C, gate (budget $HEALTH_BUDGET s, TLS want $(want_view applied))"
  return 0
}
do_apply() {
  local dry="$1" cand rf b before pk pre
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  locate
  rf="$(refusals "$CFG")"
  [ -n "$rf" ] && { echo "$(ts) apply: REFUSED:"; indent <<<"$rf"; return 4; }
  if managed_ok "$CFG" && [ "$(tls_view)" = "$(want_view applied)" ]; then
    echo "$(ts) apply: already applied (managed line present, live TLS as wanted) - nothing to do"; return 0
  fi
  if [ "$dry" = 1 ]; then cand="$(mktemp -p "${TMPDIR:-/tmp}" .ptlsf.XXXXXX)" || die "mktemp failed" 2
  else
    maint_window apply || return 4
    { mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"; } || die "cannot create $BACKUP_DIR" 2
    cand="$(mktemp "$BACKUP_DIR/.cand.XXXXXX")" || die "mktemp failed" 2
  fi
  candidate "$CFG" > "$cand"
  if ! managed_ok "$cand" || [ "$(peer_headers "$cand")" != 1 ]; then
    rm -f "$cand"; echo "$(ts) apply: REFUSED - candidate check failed"; return 4
  fi
  if [ "$dry" = 1 ]; then
    show_diff "$CFG" "$cand"; rm -f "$cand"
    echo "$(ts) apply: dry run - container $C, pre-apply TLS $(tls_view); would: backup, install, restart, gate (TLS want $(want_view applied)); nothing changed"
    return 0
  fi
  pk="$(field "$C" pubkey_node)"; pre="$(tls_view)"; before="$(started_at "$C")"
  [ "$pk" != unknown ] || { rm -f "$cand"; echo "$(ts) apply: REFUSED - node RPC not answering"; return 4; }
  b="$BACKUP_DIR/postfiatd.cfg.$(date -u +%Y%m%dT%H%M%SZ)"
  { cp -p "$CFG" "$b" && chmod 600 "$b"; } || { rm -f "$cand"; die "backup failed" 2; }
  stat -c '%a %u %g' "$CFG" > "$b.meta"; printf '%s\n' "$pre" > "$b.tls"
  echo "$(ts) apply: backup $(basename "$b") (sha256 $(sha "$b" | cut -c1-12)); pre-apply TLS $pre"
  chown --reference="$CFG" "$cand" 2>/dev/null; chmod --reference="$CFG" "$cand"
  { mv -f "$cand" "$(dirname "$CFG")/.postfiatd.cfg.pft-peertls" && mv -f "$(dirname "$CFG")/.postfiatd.cfg.pft-peertls" "$CFG"; } \
    || die "install config failed" 2
  echo "$(ts) apply: config installed (sha256 $(sha "$b" | cut -c1-12) -> $(sha "$CFG" | cut -c1-12), mode $(mode_of "$CFG"))"
  if ! restart_node "$C" || ! health_gate "$before" "$C" "$pk" "$(want_view applied)" health; then
    echo "$(ts) apply: restart or gate failed -> automatic rollback"
    before="$(started_at "$C")"
    restore_cfg "$b" "$CFG" && restart_node "$C" && health_gate "$before" "$C" "$pk" "$pre" "rollback: health" || return 5
    integrity_accept "pft-peertls-fix: automatic rollback to $(basename "$b")" || true
    return 1
  fi
  integrity_accept "pft-peertls-fix apply: [port_peer] ssl_ciphers (backup $(basename "$b"))" || true
  echo "$(ts) apply: done"
}
do_rollback() {
  local b before pk pre
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
  b="$(find "$BACKUP_DIR" -maxdepth 1 -regextype posix-extended -regex '.*/postfiatd\.cfg\.[0-9]{8}T[0-9]{6}Z' 2>/dev/null | sort | tail -1)"
  [ -n "$b" ] || die "no config backup in $BACKUP_DIR" 2
  maint_window rollback || return 4
  locate
  pk="$(field "$C" pubkey_node)"; pre="$(cat "$b.tls" 2>/dev/null)"; before="$(started_at "$C")"
  [ -n "$pre" ] || die "no recorded pre-apply TLS view ($(basename "$b").tls)" 2
  restore_cfg "$b" "$CFG" || return 5
  restart_node "$C" || return 5
  health_gate "$before" "$C" "$pk" "$pre" "rollback: health" || return 5
  integrity_accept "pft-peertls-fix rollback: postfiatd.cfg restored from $(basename "$b")" || true
  echo "$(ts) rollback: done ($(basename "$b"))"
}

cmd="${1:-}"; shift || true
YES=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in --yes) YES=1 ;; --dry-run) DRY=1 ;; *) die "unknown option $1" 3 ;; esac
  shift
done
case "$cmd" in
  plan) do_plan; exit $? ;;
  apply) [ "$YES" = 1 ] || [ "$DRY" = 1 ] || die "apply rewrites postfiatd.cfg and restarts the node; pass --yes (or --dry-run)" 4
         do_apply "$DRY"; exit $? ;;
  rollback) [ "$YES" = 1 ] || die "rollback rewrites postfiatd.cfg and restarts the node; pass --yes" 4
            do_rollback; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
