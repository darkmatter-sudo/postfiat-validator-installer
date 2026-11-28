#!/usr/bin/env bash
# pft-dnsaudit: read-only DNS dependency audit and monitor for a Post Fiat validator or sentry host (Ubuntu 22.04,
# systemd-resolved stub, postfiatd 1.0.9 in Docker). Derives the names this host depends on from live configuration,
# then checks that they resolve on the host and container paths, that more than one upstream resolver answers, that
# the upstreams validate DNSSEC and the host/container paths reject a DNSSEC-bogus control name, that no LLMNR/mDNS
# listener is open, and that the host stub and the container's resolver configuration are what we expect.
# Never changes anything and never runs a command inside the node container: container files are read through the
# host's /proc/<pid>/root, and container-path queries run the HOST's dig in the container's network namespace
# (nsenter -n), so the container's AppArmor/seccomp profiles never see them.
#
# Usage: pft-dnsaudit audit [--json] [--textfile] [--name NAME ...]
#                                            --textfile also writes TEXTFILE_DIR/pft_dnsaudit_HOST.prom;
#                                            --name adds a control name (e.g. pft-control.invalid) and refuses
#                                            --textfile, so negative controls never touch the metrics
#        pft-dnsaudit names                  the derived critical names, one "SOURCE NAME" per line
#        sudo pft-dnsaudit pull              validator: copy the peer's textfile (PULL_SSH in the env file)
#        pft-dnsaudit validate FILE HOST     the check pull applies to a fetched textfile
#        pft-dnsaudit version
#
#  audit   one line per check, PASS / WARN / FAIL / INFO; exit 0 = only PASS/INFO, 1 = any WARN/FAIL, 2 = error.
#    source:vl|peer|ntfy|apt|registry   names derived from live config (FAIL: a source yields no name)
#            vl       hosts of [validator_list_sites] in the container's validators.txt / postfiatd.cfg
#            peer     hostnames (not IP literals) in the container's [ips] and [ips_fixed]
#            ntfy     host of NTFY_SERVER / NTFY_URL in NTFY_FILES
#            apt      hosts of deb lines / URIs: in /etc/apt/sources.list(.d)
#            registry registry of the running container's image (docker.io -> registry-1.docker.io, auth.docker.io)
#    resolve:NAME       the host path (getent ahosts, i.e. glibc -> /etc/resolv.conf) returns an address
#    cresolve:NAME      vl/peer names through the container's own nameservers, from inside its network namespace
#    redundancy         >= 2 distinct upstream resolvers configured in systemd-resolved (1 WARN, 0 FAIL)
#    upstream:N         upstream resolver N (numbered, never printed) answers the first critical name
#    dnssec:upstream:N  resolver N sets AD on DNSSEC_GOOD and returns SERVFAIL for DNSSEC_BAD (both with DO)
#    dnssec:stub        the host path refuses DNSSEC_BAD (getent fails)
#    dnssec:container   the container path refuses DNSSEC_BAD (query flags as the container's glibc sends them:
#                       AD only with `options trust-ad`)
#    dnssec:signed      INFO: how many critical names are DNSSEC-signed (AD from a validating upstream)
#    llmnr / mdns       no listener on 5355 (udp/tcp) / 5353 (udp), and resolved's global setting is off
#    stub               /etc/resolv.conf is resolved's stub file with nameserver 127.0.0.53 only
#    embedded           the container's resolv.conf: Docker's embedded DNS (127.0.0.11) or >= 2 nameservers
#  An unexpired line "CHECK UNTIL REASON" in ACCEPT_FILE (UNTIL = epoch or YYYY-MM-DD) turns that check's WARN/FAIL
#  into INFO "accepted until ..." (an operator risk decision); an expired one is ignored and says so.
#  pull    runs "$PULL_SSH cat -- REMOTE_DIR/pft_dnsaudit_PEER.prom", validates it (only pft_dnsaudit_ samples whose
#          first label is host="PEER", <= MAX_BYTES, an up and a last_run sample) and renames it into TEXTFILE_DIR.
#          Exit 1 fetch failed, 2 validation failed (the old copy stays, so a dead peer goes stale).
#
# Exit codes: 0 ok, 1 findings, 2 error, 3 usage.
# Config: /etc/pft-dnsaudit.env (KEY=VALUE, read, never sourced; PFT_DA_CONF overrides the path): HOST_LABEL
#   (validator), PEER_LABEL (sentry), PULL_SSH, PULL_TIMEOUT (30), EXTRA_NAMES (more critical names),
#   NTFY_FILES ("/etc/postfiat-monitor.env /etc/pft-watchdog/ntfy.env"), DNSSEC_GOOD (ietf.org),
#   DNSSEC_BAD (dnssec-failed.org), DIG_TIMEOUT (3)
# Env: TEXTFILE_DIR (/var/lib/pft-exporter/textfile)  REMOTE_DIR (same)  ACCEPT_FILE (/etc/pft-dnsaudit.accept)
#      CONTAINER (auto: postfiatd or postfiatd-sentry)  NODE_CFG_DIR (/etc/postfiatd, in the container)
#   Test hooks: PFT_DA_ROOT (prefix for /proc, /etc)  PFT_DA_DIG  PFT_DA_GETENT  PFT_DA_SS  PFT_DA_RESOLVECTL
#      PFT_DA_DOCKER  PFT_DA_NSENTER  PFT_DA_NOW (epoch)
set -uo pipefail
umask 022
VERSION=1.0.0

R="${PFT_DA_ROOT:-}"
DIG="${PFT_DA_DIG:-dig}"
GETENT="${PFT_DA_GETENT:-getent}"
SS="${PFT_DA_SS:-ss}"
RESOLVECTL="${PFT_DA_RESOLVECTL:-resolvectl}"
DOCKER="${PFT_DA_DOCKER:-docker}"
NSENTER="${PFT_DA_NSENTER:-nsenter}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
ACCEPT_FILE="${ACCEPT_FILE:-/etc/pft-dnsaudit.accept}"
NODE_CFG_DIR="${NODE_CFG_DIR:-/etc/postfiatd}"
MAX_BYTES=32768
HOST_LABEL=validator; PEER_LABEL=sentry; PULL_SSH=""; PULL_TIMEOUT=30; EXTRA_NAMES=""
NTFY_FILES="/etc/postfiat-monitor.env /etc/pft-watchdog/ntfy.env"; DNSSEC_GOOD=ietf.org; DNSSEC_BAD=dnssec-failed.org
DIG_TIMEOUT=3
CONF="${PFT_DA_CONF:-/etc/pft-dnsaudit.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|PULL_SSH|PULL_TIMEOUT|EXTRA_NAMES|NTFY_FILES|DNSSEC_GOOD|DNSSEC_BAD|DIG_TIMEOUT)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi

die() { printf 'pft-dnsaudit: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_DA_NOW:-$(date -u +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}\.?$ ]] && [ "${#1}" -le 253 ]; }
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$1" == *:* ]]; }

# ---------- critical names ----------
container() {
  if [ -n "${CONTAINER:-}" ]; then echo "$CONTAINER"; return; fi
  local c
  for c in postfiatd postfiatd-sentry; do
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && { echo "$c"; return; }
  done
  echo postfiatd
}
CPID=""; CROOT=""; CIMAGE=""
container_load() {
  local c; c="$(container)"
  CPID="$("$DOCKER" inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)"
  CIMAGE="$("$DOCKER" inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)"
  if [[ "$CPID" =~ ^[1-9][0-9]*$ ]] && [ -d "$R/proc/$CPID/root" ]; then CROOT="$R/proc/$CPID/root"; else CPID=""; CROOT=""; fi
}
# section FILE NAME -> non-comment lines of [NAME] in a postfiatd-style ini file
section() { awk -v s="[$2]" '/^[[:space:]]*#/ { next } /^\[/ { p = ($1 == s); next } p && NF { print $1 }' "$1" 2>/dev/null; }
url_host() { sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#^[^@/]*@##; s#[/?].*$##; s#:[0-9]+$##' <<<"$1"; }
names_vl() {
  local f
  [ -n "$CROOT" ] || return 0
  for f in "$CROOT$NODE_CFG_DIR/validators.txt" "$CROOT$NODE_CFG_DIR/postfiatd.cfg"; do
    section "$f" validator_list_sites | while read -r u; do url_host "$u"; done
  done
}
names_peer() {
  [ -n "$CROOT" ] || return 0
  { section "$CROOT$NODE_CFG_DIR/postfiatd.cfg" ips; section "$CROOT$NODE_CFG_DIR/postfiatd.cfg" ips_fixed; } |
    while read -r h; do is_ip "$h" || echo "$h"; done
}
names_ntfy() {
  local f
  for f in $NTFY_FILES; do
    sed -n -E 's/^(NTFY_SERVER|NTFY_URL)=["]?([^"]*)["]?$/\2/p' "$R$f" 2>/dev/null | while read -r u; do url_host "$u"; done
  done
}
names_apt() {
  { awk '$1 == "deb" || $1 == "deb-src" { for (i = 2; i <= NF; i++) if ($i ~ /:\/\//) { print $i; break } }' \
      "$R/etc/apt/sources.list" "$R"/etc/apt/sources.list.d/*.list 2>/dev/null
    awk '$1 == "URIs:" { for (i = 2; i <= NF; i++) print $i }' "$R"/etc/apt/sources.list.d/*.sources 2>/dev/null
  } | while read -r u; do url_host "$u"; done
}
names_registry() {
  local first="${CIMAGE%%/*}"
  [ -n "$CIMAGE" ] || return 0
  if [[ "$CIMAGE" == */* ]] && { [[ "$first" == *.* ]] || [[ "$first" == *:* ]] || [ "$first" = localhost ]; }; then
    echo "${first%%:*}"
  else
    printf '%s\n' registry-1.docker.io auth.docker.io
  fi
}
SOURCES="vl peer ntfy apt registry"
NAMES=()   # "source name", unique by name (first source wins)
names_load() {
  local s n seen=" "
  container_load
  for s in $SOURCES extra; do
    while read -r n; do
      [ -n "$n" ] || continue
      n="${n%.}"; n="${n,,}"
      valid_name "$n" || continue
      case "$seen" in *" $n "*) continue ;; esac
      seen="$seen$n "; NAMES+=("$s $n")
    done < <(if [ "$s" = extra ]; then tr ' ' '\n' <<<"$EXTRA_NAMES"; else "names_$s" | sort -u; fi)
  done
}
names_of() { local e; for e in "${NAMES[@]}"; do [ "${e%% *}" = "$1" ] && echo "${e#* }"; done; }

# ---------- queries ----------
# dig_q [nsenter-pid|-] SERVER NAME FLAGS... -> "STATUS FLAGS" (STATUS = NOERROR/NXDOMAIN/SERVFAIL/... or TIMEOUT)
dig_q() {
  local pid="$1" srv="$2" name="$3" out; shift 3
  if [ "$pid" = - ]; then out="$("$DIG" +time="$DIG_TIMEOUT" +tries=1 "$@" "@$srv" "$name" A 2>/dev/null)"
  else out="$("$NSENTER" -t "$pid" -n -- "$DIG" +time="$DIG_TIMEOUT" +tries=1 "$@" "@$srv" "$name" A 2>/dev/null)"; fi
  local st fl
  st="$(sed -n -E 's/.*status: ([A-Z]+),.*/\1/p' <<<"$out" | head -1)"
  fl="$(sed -n -E 's/^;; flags: ([a-z ]*);.*/\1/p' <<<"$out" | head -1)"
  printf '%s %s\n' "${st:-TIMEOUT}" "${fl// /,}"
}
has_flag() { [[ ",$2," == *",$1,"* ]]; }
upstreams() { # distinct upstream resolver addresses known to systemd-resolved (global + every link), in order
  "$RESOLVECTL" dns 2>/dev/null | sed -E 's/^[^:]*:[[:space:]]*//' | tr ' ' '\n' |
    sed -E 's/#.*$//; s/%.*$//' | grep -E '^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]*:[0-9a-fA-F:]+)$' | awk '!s[$0]++'
}
host_resolves() { timeout 15 "$GETENT" ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u | grep -c .; }
C_NS=(); C_TRUSTAD=0; C_EXT=0
container_resolv() {
  local f="$CROOT/etc/resolv.conf"
  C_NS=(); C_TRUSTAD=0; C_EXT=0
  [ -n "$CROOT" ] && [ -r "$f" ] || return 1
  mapfile -t C_NS < <(awk '$1 == "nameserver" { print $2 }' "$f")
  grep -Eq '^options([[:space:]].*)?[[:space:]]trust-ad([[:space:]]|$)' "$f" && C_TRUSTAD=1
  grep -Eq '^# ExtServers: \[.+\]' "$f" && C_EXT=1
  return 0
}
container_q() { # NAME FLAGS... -> first non-TIMEOUT answer over the container's nameservers
  local ns a="TIMEOUT -"
  for ns in "${C_NS[@]}"; do a="$(dig_q "$CPID" "$ns" "$@")"; [ "${a%% *}" = TIMEOUT ] || break; done
  echo "$a"
}

# ---------- audit ----------
ROWS=()
row() { ROWS+=("$(printf '%s\t%s\t%s' "$1" "$2" "$3")"); }
ACC_N=0
accepted() { # CHECK -> rc 0 + "until REASON" on stdout if an unexpired ACCEPT_FILE line covers CHECK
  local c u r e
  [ -r "$R$ACCEPT_FILE" ] || return 1
  while read -r c u r; do
    [ "$c" = "$1" ] || continue
    if [[ "$u" =~ ^[0-9]+$ ]]; then e="$u"; else e="$(date -u -d "$u" +%s 2>/dev/null)" || continue; fi
    if [ "$(now)" -lt "$e" ]; then printf '%s %s' "$(date -u -d "@$e" +%FT%TZ)" "$r"; return 0; fi
    printf 'EXPIRED %s' "$(date -u -d "@$e" +%FT%TZ)"; return 2
  done < <(grep -E '^[a-z]' "$R$ACCEPT_FILE")
  return 1
}
grade() { # STATUS CHECK NOTE: WARN/FAIL go through ACCEPT_FILE
  local a rc
  if [ "$1" = WARN ] || [ "$1" = FAIL ]; then
    a="$(accepted "$2")"; rc=$?
    if [ "$rc" = 0 ]; then ACC_N=$((ACC_N + 1)); row INFO "$2" "accepted until ${a%% *} (${a#* }); was $1: $3"; return; fi
    [ "$rc" = 2 ] && { row "$1" "$2" "$3 (acceptance ${a#EXPIRED } expired)"; return; }
  fi
  row "$1" "$2" "$3"
}
N_UP=0; N_SIGNED=0; N_CRIT=0

run_audit() {
  local s n k e cnt i a st fl first=""
  # sources
  for s in $SOURCES; do
    k="$(names_of "$s" | tr '\n' ' ')"; k="${k% }"
    if [ -n "$k" ]; then row PASS "source:$s" "$(wc -w <<<"$k") name(s): $k"
    elif [ "$s" = vl ] || [ "$s" = peer ] || [ "$s" = registry ]; then
      if [ -z "$CROOT" ]; then grade FAIL "source:$s" "node container not running or its rootfs is unreadable"
      elif [ "$s" = peer ]; then row INFO "source:$s" "[ips]/[ips_fixed] list IP literals only: no DNS dependency"
      else grade FAIL "source:$s" "no name derived from the container's configuration"; fi
    else grade FAIL "source:$s" "no name derived (files: $([ "$s" = ntfy ] && echo "$NTFY_FILES" || echo /etc/apt/sources.list*))"; fi
  done
  N_CRIT="${#NAMES[@]}"
  # host path
  for e in "${NAMES[@]}"; do
    n="${e#* }"; [ -n "$first" ] || first="$n"
    cnt="$(host_resolves "$n")"
    if [ "${cnt:-0}" -gt 0 ]; then row PASS "resolve:$n" "host path: $cnt address(es) (${e%% *})"
    else grade FAIL "resolve:$n" "host path: no address (${e%% *})"; fi
  done
  # container path (what postfiatd itself resolves)
  CF=(); container_resolv && { [ "$C_TRUSTAD" = 1 ] || CF=(+noadflag); }   # the container glibc sets AD only with trust-ad
  if [ "${#C_NS[@]}" -gt 0 ]; then
    for n in $(names_of vl) $(names_of peer); do
      a="$(container_q "$n" "${CF[@]}")"; st="${a%% *}"
      if [ "$st" = NOERROR ]; then row PASS "cresolve:$n" "container path: NOERROR"
      else grade FAIL "cresolve:$n" "container path: $st"; fi
    done
  fi
  # upstream resolvers
  mapfile -t UP < <(upstreams)
  N_UP="${#UP[@]}"
  if [ "$N_UP" -ge 2 ]; then row PASS redundancy "$N_UP distinct upstream resolvers"
  elif [ "$N_UP" = 1 ]; then grade WARN redundancy "1 upstream resolver: no redundancy"
  else grade FAIL redundancy "no upstream resolver configured in systemd-resolved"; fi
  i=0
  for a in "${UP[@]}"; do
    i=$((i + 1))
    read -r st fl <<<"$(dig_q - "$a" "${first:-$DNSSEC_GOOD}")"
    if [ "$st" = NOERROR ]; then row PASS "upstream:$i" "answers ${first:-$DNSSEC_GOOD}"
    else grade FAIL "upstream:$i" "${first:-$DNSSEC_GOOD}: $st"; fi
    read -r st fl <<<"$(dig_q - "$a" "$DNSSEC_GOOD" +dnssec)"
    local good="$st/$fl" bad
    bad="$(dig_q - "$a" "$DNSSEC_BAD" +dnssec)"; bad="${bad%% *}"
    if [ "$st" = NOERROR ] && has_flag ad "$fl" && [ "$bad" = SERVFAIL ]; then
      row PASS "dnssec:upstream:$i" "validates: AD on $DNSSEC_GOOD, SERVFAIL for $DNSSEC_BAD"
    elif [ "$st" = NOERROR ] && ! has_flag ad "$fl" && [ "$bad" != SERVFAIL ]; then
      grade FAIL "dnssec:upstream:$i" "does not validate: no AD on $DNSSEC_GOOD, $bad for $DNSSEC_BAD"
    else grade FAIL "dnssec:upstream:$i" "inconsistent: $DNSSEC_GOOD $good, $DNSSEC_BAD $bad"; fi
  done
  # signed critical names (AD from the first validating upstream)
  local vi=0 v=""; for i in "${!UP[@]}"; do
    [[ "$(printf '%s\n' "${ROWS[@]}")" == *$'PASS\tdnssec:upstream:'$((i + 1))$'\t'* ]] && { v="${UP[$i]}"; vi=$((i + 1)); break; }
  done
  if [ -n "$v" ]; then
    k=""; for e in "${NAMES[@]}"; do
      n="${e#* }"; read -r st fl <<<"$(dig_q - "$v" "$n" +dnssec)"
      has_flag ad "$fl" && { N_SIGNED=$((N_SIGNED + 1)); k="$k $n"; }
    done
    row INFO dnssec:signed "$N_SIGNED of $N_CRIT critical names are DNSSEC-signed (AD via resolver $vi)${k:+:$k}"
  else row INFO dnssec:signed "no validating upstream: signing status unknown"; fi
  # bogus control on the host and container paths
  if [ "$(host_resolves "$DNSSEC_BAD")" -gt 0 ] 2>/dev/null; then
    grade FAIL dnssec:stub "host path returned an address for the DNSSEC-bogus control $DNSSEC_BAD"
  else row PASS dnssec:stub "host path refuses the DNSSEC-bogus control $DNSSEC_BAD"; fi
  if [ "${#C_NS[@]}" -gt 0 ]; then
    a="$(container_q "$DNSSEC_BAD" "${CF[@]}")"; st="${a%% *}"
    if [ "$st" = SERVFAIL ]; then row PASS dnssec:container "container path refuses $DNSSEC_BAD (SERVFAIL)"
    else grade FAIL dnssec:container "container path: $st for the DNSSEC-bogus control $DNSSEC_BAD"; fi
  fi
  # LLMNR / mDNS
  local lis glob
  lis="$("$SS" -H -lnu 2>/dev/null | awk '{print "udp " $4}'; "$SS" -H -lnt 2>/dev/null | awk '{print "tcp " $4}')"
  glob="$("$RESOLVECTL" status 2>/dev/null | awk '/^Global/ { g = 1; next } /^Link / { g = 0 } g && /Protocols:/ { print; exit }')"
  if grep -Eq ':5355$' <<<"$lis"; then grade FAIL llmnr "listener open on port 5355 (LLMNR)"
  elif [[ "$glob" == *"+LLMNR"* ]]; then grade WARN llmnr "resolved global LLMNR is on (no listener seen)"
  elif [[ "$glob" == *"-LLMNR"* ]]; then row PASS llmnr "no 5355 listener; resolved global LLMNR off"
  else grade WARN llmnr "no 5355 listener; resolved global LLMNR setting unreadable"; fi
  if grep -Eq '^udp .*:5353$' <<<"$lis"; then grade FAIL mdns "listener open on udp 5353 (mDNS)"
  elif [[ "$glob" == *"+mDNS"* ]]; then grade WARN mdns "resolved global mDNS is on (no listener seen)"
  elif [[ "$glob" == *"-mDNS"* ]]; then row PASS mdns "no 5353 listener; resolved global mDNS off"
  else grade WARN mdns "no 5353 listener; resolved global mDNS setting unreadable"; fi
  # host stub
  local tgt ns
  tgt="$(readlink "$R/etc/resolv.conf" 2>/dev/null)"
  ns="$(awk '$1 == "nameserver" { print $2 }' "$R/etc/resolv.conf" 2>/dev/null | tr '\n' ' ')"
  if [[ "$tgt" == */run/systemd/resolve/stub-resolv.conf ]] && [ "$ns" = "127.0.0.53 " ]; then
    row PASS stub "/etc/resolv.conf -> resolved stub, nameserver 127.0.0.53 only"
  elif [ -z "$ns" ]; then grade FAIL stub "/etc/resolv.conf has no nameserver"
  else grade WARN stub "/etc/resolv.conf is not resolved's stub file (${tgt:-regular file}, $(wc -w <<<"$ns") nameserver(s))"; fi
  # container resolver configuration
  if [ -z "$CROOT" ]; then grade FAIL embedded "node container not running: its resolv.conf is unreadable"
  elif [ "${#C_NS[@]}" = 0 ]; then grade FAIL embedded "container resolv.conf has no nameserver"
  elif [ "${C_NS[*]}" = 127.0.0.11 ]; then
    if [ "$C_EXT" = 1 ]; then row PASS embedded "Docker embedded DNS (127.0.0.11) with recorded upstreams (ExtServers)"
    else grade WARN embedded "Docker embedded DNS without an ExtServers record: upstreams unknown"; fi
  elif [ "${#C_NS[@]}" -ge 2 ]; then row PASS embedded "${#C_NS[@]} direct nameservers (default bridge network)"
  else grade WARN embedded "1 direct nameserver: no redundancy on the container path"; fi
}

worst() { local r w=0; for r in "${ROWS[@]}"; do case "${r%%$'\t'*}" in WARN|FAIL) w=1 ;; esac; done; echo "$w"; }
code_of() { case "$1" in PASS) echo 0 ;; INFO) echo 1 ;; WARN) echo 2 ;; *) echo 3 ;; esac; }

metrics() { # UP RUN_TS DURATION
  local L="host=\"$HOST_LABEL\"" r st k n s c
  cat <<EOF
# HELP pft_dnsaudit_up 1 if the last audit completed.
# TYPE pft_dnsaudit_up gauge
pft_dnsaudit_up{$L} $1
# HELP pft_dnsaudit_last_run_timestamp_seconds When the last audit ran.
# TYPE pft_dnsaudit_last_run_timestamp_seconds gauge
pft_dnsaudit_last_run_timestamp_seconds{$L} $2
EOF
  [ "$1" = 1 ] || return 0
  printf '# HELP pft_dnsaudit_duration_seconds Wall time of the last audit.\n# TYPE pft_dnsaudit_duration_seconds gauge\n'
  printf 'pft_dnsaudit_duration_seconds{%s} %s\n' "$L" "$3"
  printf '# HELP pft_dnsaudit_check_status Per check: 0 PASS, 1 INFO (incl. accepted), 2 WARN, 3 FAIL.\n# TYPE pft_dnsaudit_check_status gauge\n'
  for r in "${ROWS[@]}"; do IFS=$'\t' read -r st k n <<<"$r"; printf 'pft_dnsaudit_check_status{%s,check="%s"} %s\n' "$L" "$k" "$(code_of "$st")"; done
  printf '# HELP pft_dnsaudit_checks Checks by status.\n# TYPE pft_dnsaudit_checks gauge\n'
  for s in PASS INFO WARN FAIL; do
    c=0; for r in "${ROWS[@]}"; do [ "${r%%$'\t'*}" = "$s" ] && c=$((c + 1)); done
    printf 'pft_dnsaudit_checks{%s,status="%s"} %s\n' "$L" "${s,,}" "$c"
  done
  printf '# HELP pft_dnsaudit_names Critical names derived per source.\n# TYPE pft_dnsaudit_names gauge\n'
  for s in $SOURCES; do printf 'pft_dnsaudit_names{%s,source="%s"} %s\n' "$L" "$s" "$(names_of "$s" | grep -c .)"; done
  printf '# HELP pft_dnsaudit_upstream_resolvers Distinct upstream resolvers in systemd-resolved.\n# TYPE pft_dnsaudit_upstream_resolvers gauge\n'
  printf 'pft_dnsaudit_upstream_resolvers{%s} %s\n' "$L" "$N_UP"
  printf '# HELP pft_dnsaudit_signed_names Critical names that are DNSSEC-signed.\n# TYPE pft_dnsaudit_signed_names gauge\n'
  printf 'pft_dnsaudit_signed_names{%s} %s\n' "$L" "$N_SIGNED"
  printf '# HELP pft_dnsaudit_accepted Checks turned into INFO by an unexpired ACCEPT_FILE line.\n# TYPE pft_dnsaudit_accepted gauge\n'
  printf 'pft_dnsaudit_accepted{%s} %s\n' "$L" "$ACC_N"
}

write_textfile() { # CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_dnsaudit_$HOST_LABEL.XXXXXX" 2>/dev/null)" || { echo "pft-dnsaudit: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { printf '%s\n' "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_dnsaudit_$HOST_LABEL.prom"; }; then
    rm -f "$t"; echo "pft-dnsaudit: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

audit() {
  local json=0 tf=0 t0 rc r st k n extra=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;; --textfile) tf=1 ;;
      --name) if [ $# -lt 2 ] || ! valid_name "$2"; then die "--name needs a DNS name" 3; fi; extra="$extra $2"; shift ;;
      *) die "unknown argument: $1" 3 ;;
    esac; shift
  done
  [ -n "$extra" ] && [ "$tf" = 1 ] && die "--name (control names) never writes the textfile: drop --textfile" 3
  EXTRA_NAMES="$EXTRA_NAMES$extra"
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL" 3
  [[ "$DIG_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || die "bad DIG_TIMEOUT" 3
  if ! valid_name "$DNSSEC_GOOD" || ! valid_name "$DNSSEC_BAD"; then die "bad DNSSEC_GOOD/DNSSEC_BAD" 3; fi
  t0="$(now)"
  if ! command -v "$DIG" >/dev/null || ! command -v "$GETENT" >/dev/null || ! command -v "$RESOLVECTL" >/dev/null; then
    [ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"
    die "dig, getent or resolvectl unavailable" 2
  fi
  names_load
  run_audit
  rc="$(worst)"
  [ "$tf" = 1 ] && { write_textfile "$(metrics 1 "$t0" "$(( $(now) - t0 ))")" || rc=2; }
  if [ "$json" = 1 ]; then
    printf '%s\n' "${ROWS[@]}" | jq -R -s -c --arg host "$HOST_LABEL" --arg ts "$(ts)" --argjson exit "$rc" '
      [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], check: .[1], note: .[2]}] as $r |
      {host: $host, time: $ts, result: (if $exit == 0 then "PASS" else "FINDINGS" end), exit: $exit, checks: $r}'
  else
    printf 'pft-dnsaudit audit %s - %s  host=%s  container=%s\n' "$VERSION" "$(ts)" "$HOST_LABEL" "$(container)"
    for r in "${ROWS[@]}"; do IFS=$'\t' read -r st k n <<<"$r"; printf '%-5s %-34s %s\n' "$st" "$k" "$n"; done
    printf 'RESULT: %s - %d checks: %d pass, %d info, %d warn, %d fail; %d critical names, %d upstream resolvers, %d accepted -> exit %d\n' \
      "$([ "$rc" = 0 ] && echo PASS || echo FINDINGS)" "${#ROWS[@]}" \
      "$(printf '%s\n' "${ROWS[@]}" | grep -c $'^PASS\t')" "$(printf '%s\n' "${ROWS[@]}" | grep -c $'^INFO\t')" \
      "$(printf '%s\n' "${ROWS[@]}" | grep -c $'^WARN\t')" "$(printf '%s\n' "${ROWS[@]}" | grep -c $'^FAIL\t')" \
      "$N_CRIT" "$N_UP" "$ACC_N" "$rc"
  fi
  return "$rc"
}

# ---------- pull ----------
validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"; [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_dnsaudit_[a-z_]+ / || /^$/ { next }
    {
      if (match($0, /^pft_dnsaudit_[a-z_]+\{/) == 0) { printf "line %d: not a pft_dnsaudit_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_dnsaudit_up\{/) up = 1
      if ($0 ~ /^pft_dnsaudit_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_dnsaudit_up sample"; exit 1 }
      if (!ts) { print "no pft_dnsaudit_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL" 3
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)" 3
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT" 3
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-dnsaudit-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_dnsaudit_$PEER_LABEL.prom" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_dnsaudit_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_dnsaudit_$PEER_LABEL.prom"; }; then rm -f "$tmp"; die "rename failed" 1; fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  audit) audit "$@" ;;
  names) [ $# -eq 0 ] || die "names takes no arguments" 3; names_load; printf '%s\n' "${NAMES[@]}" ;;
  pull) [ $# -eq 0 ] || die "pull takes no arguments" 3; pull ;;
  validate) [ $# -eq 2 ] || die "usage: pft-dnsaudit validate FILE HOST" 3; valid_label "$2" || die "bad host label" 3
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-dnsaudit $VERSION" ;;
  *) die "usage: pft-dnsaudit audit|names|pull|validate|version (see the header of this script)" 3 ;;
esac
