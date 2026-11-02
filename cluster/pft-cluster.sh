#!/usr/bin/env bash
# pft-cluster: pin each postfiatd node's identity with a [node_seed] and make the validator and its sentry members of
# one cluster ([cluster_nodes]), on Dockerized postfiatd 1.0.9 hosts (Ubuntu 22.04). Run the same script on both
# hosts; drill/live-run.sh does the two-host sequence (sentry first).
#
# Why: without [node_seed], a node's identity (pubkey_node) lives in wallet.db in the data volume and changes when
# that volume is lost or re-created. Cluster members trust each other's load reports, skip each other's
# resource charges (no fee/disconnect for a busy sentry relaying to its validator) and show up as `cluster: true`
# in `peers`, which makes the sentry<->validator link easy to monitor by key rather than by address.
#
# Usage: pft-cluster audit [--json] [--prom FILE | --textfile]
#        sudo pft-cluster keygen              validation_create on this node -> STATE_DIR/node_seed (0600), node_pub
#        pft-cluster pubkey                   print this node's pinned public key (n9..., public)
#        sudo pft-cluster set-peer KEY [TAG]  store the other node's public key (PEER_PUBKEY) in /etc/pft-cluster.env
#        pft-cluster plan                     read-only: the config block apply would write (seed redacted)
#        sudo pft-cluster apply --yes [--dry-run] [--require-peer]
#        sudo pft-cluster rollback --yes      restore the newest config backup, restart, gate
#        sudo pft-cluster pull                (validator: copy the peer's textfile, see install.sh --pull)
#        pft-cluster validate FILE HOST       (the check pull applies to a fetched textfile)
#
#  audit   read-only. Checks: seed:stored (STATE_DIR 0700, node_seed 0600 root, both keys well-formed),
#          cfg:node_seed (exactly one [node_seed] section, inside the managed block, equal to the stored seed),
#          cfg:mode (postfiatd.cfg 0600 once it holds a seed), cfg:cluster_nodes (PEER_PUBKEY listed, every
#          entry well-formed as Cluster::load parses it), live:pubkey (server_info pubkey_node = pinned key),
#          live:cluster (peers.cluster lists PEER_PUBKEY: the running node loaded the config),
#          live:peer (a connected peer with public_key = PEER_PUBKEY and cluster=true), live:reports (that member
#          sent a cluster report within REPORT_MAX s: the PEER also counts us as a member, i.e. both directions),
#          secret:exposure (the seed is not in docker inspect, any process command line, the last LOG_TAIL
#          container log lines or the textfile). Keys print as keyed fingerprints node:<12 hex> (FP_KEY file).
#  apply   0. refuses (exit 4) unless root, --yes, a pft-maint window is active, a seed is stored and PEER_PUBKEY
#             is a valid node public key.
#          1. candidate config = current postfiatd.cfg minus the old managed block, plus
#             # BEGIN pft-cluster / [node_seed] <seed> / [cluster_nodes] <PEER_PUBKEY> <TAG> / # END pft-cluster;
#             refuses (exit 4) if an unmanaged [node_seed] or [cluster_nodes] section exists. Idempotent: if the
#             candidate equals the live file and the node already runs the pinned key with the member loaded, exit 0.
#          2. backs the config up (STATE_DIR/backups, 0600), installs the candidate 0600, `docker restart`.
#          3. health gate (HEALTH_BUDGET s): container restarted, server_state full, pubkey_node = pinned key,
#             PEER_PUBKEY in peers.cluster, :PEER_PORT listening, sshd -t + :22 handshake, every pft daemon that was
#             active still active; --require-peer also needs live:peer and live:reports. A miss -> automatic
#             rollback (byte-identical restore, restart, rollback gate incl. the pre-apply pubkey_node back) exit 1;
#             exit 5 if that fails.
#          4. pft-integrity: if installed, accepts the new baseline ONLY when every changed item is the config file
#             (cfgvol:postfiatd.cfg); anything else is left for a human.
#  rollback  same restore + restart + rollback gate + integrity step, from the newest backup (exit 0 / 5).
#
# Exit codes: 0 PASS / applied, 1 findings / rolled back, 2 error, 3 usage, 4 refused, 5 rollback failed.
# Config: /etc/pft-cluster.env (KEY=VALUE, root 0600, read, never sourced): HOST_LABEL (validator), PEER_LABEL
#      (sentry), PEER_PUBKEY (the other node's pinned key), PEER_TAG (PEER_LABEL), PULL_SSH (validator only).
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  CFG_DEST (/etc/postfiatd)  PEER_PORT (2559)
#      HEALTH_BUDGET (900)  POLL_SEC (5)  REPORT_MAX (300)  LOG_TAIL (5000)  STATE_DIR (/var/lib/pft-cluster)
#      SEED_UID (0: the uid that must own node_seed)
#      Test hooks: PFT_CLUSTER_ROOT (path prefix for every file)  PFT_CLUSTER_DOCKER / _RPC / _SYSTEMCTL / _SS /
#      _SSHD / _KEYSCAN / _PS / _MAINT / _INTEGRITY (commands)  PFT_CLUSTER_INJECT (health: the apply gate misses)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
umask 022

R="${PFT_CLUSTER_ROOT:-}"
DOCKER="${PFT_CLUSTER_DOCKER:-docker}"
SYSTEMCTL="${PFT_CLUSTER_SYSTEMCTL:-systemctl}"
SS="${PFT_CLUSTER_SS:-ss}"
SSHD="${PFT_CLUSTER_SSHD:-sshd}"
KEYSCAN="${PFT_CLUSTER_KEYSCAN:-ssh-keyscan}"
PS="${PFT_CLUSTER_PS:-ps}"
MAINT="${PFT_CLUSTER_MAINT:-pft-maint}"
INTEGRITY="${PFT_CLUSTER_INTEGRITY:-pft-integrity}"
INJECT="${PFT_CLUSTER_INJECT:-}"
CFG_DEST="${CFG_DEST:-/etc/postfiatd}"
PEER_PORT="${PEER_PORT:-2559}"
HEALTH_BUDGET="${HEALTH_BUDGET:-900}"
POLL_SEC="${POLL_SEC:-5}"
REPORT_MAX="${REPORT_MAX:-300}"
LOG_TAIL="${LOG_TAIL:-5000}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-cluster}"
SEED_UID="${SEED_UID:-0}"
SEEDF="$STATE_DIR/node_seed"
PUBF="$STATE_DIR/node_pub"
FPF="$STATE_DIR/fp_key"
BACKUP_DIR="$STATE_DIR/backups"
CONF="${PFT_CLUSTER_CONF:-$R/etc/pft-cluster.env}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
PEER_LABEL="$(conf_get PEER_LABEL)"; PEER_LABEL="${PEER_LABEL:-sentry}"
PEER_PUBKEY="$(conf_get PEER_PUBKEY)"
PEER_TAG="$(conf_get PEER_TAG)"; PEER_TAG="${PEER_TAG:-$PEER_LABEL}"
PULL_SSH="$(conf_get PULL_SSH)"; PULL_TIMEOUT="${PULL_TIMEOUT:-30}"
BEGIN_MARK="# BEGIN pft-cluster (managed; edit with pft-cluster, see cluster/README.md)"
END_MARK="# END pft-cluster"
B58='[1-9A-HJ-NP-Za-km-z]'

valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
valid_pub() { [[ "$1" =~ ^n${B58}{50,51}$ ]]; }    # TokenType::NodePublic, 33-byte key: 52 chars (n9...)
valid_seed_file() { grep -qxE "s${B58}{24,34}" "$1" 2>/dev/null && [ "$(wc -l < "$1")" = 1 ]; }
valid_tag() { [[ "$1" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]; }
die() { echo "pft-cluster: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
RESULTS=""
FINDINGS=0
res() { # STATUS ID MESSAGE
  RESULTS+="$1"$'\t'"$2"$'\t'"$3"$'\n'
  case "$1" in FAIL|WARN) FINDINGS=$((FINDINGS + 1)) ;; esac
  return 0
}
fp() { # KEY -> node:<12 hex> keyed with FP_KEY, so published logs can compare keys without naming the nodes
  [ -n "$1" ] || { echo "node:none"; return; }
  if [ -r "$FPF" ]; then echo "node:$({ cat "$FPF"; printf '%s' "$1"; } | sha256sum | cut -c1-12)"; else echo "node:<no fp_key>"; fi
}

detect_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}
cfg_file() { # CONTAINER -> host path of postfiatd.cfg (the volume/bind mounted at CFG_DEST)
  local s
  s="$("$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "'"$CFG_DEST"'"}}{{.Source}}{{end}}{{end}}' "$1" 2>/dev/null)"
  [ -n "$s" ] && echo "$R$s/postfiatd.cfg"
}
rpc() { # CONTAINER METHOD -> JSON answer of the node's admin RPC (inside the container: the host mapping is not admin)
  if [ -n "${PFT_CLUSTER_RPC:-}" ]; then "$PFT_CLUSTER_RPC" "$1" "$2"; return; fi
  "$DOCKER" exec "$1" sh -c 'curl -s -m 5 -d "{\"method\":\"'"$2"'\"}" http://127.0.0.1:${RPC_PORT:-5005}/' 2>/dev/null
}
server_field() { rpc "$1" server_info | jq -r ".result.info.$2 // \"unknown\"" 2>/dev/null || echo unknown; }
started_at() { "$DOCKER" inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null; }
mode_of() { stat -c %a "$1" 2>/dev/null; }
jqe() { # jq -e ARGS on stdin; empty input is FALSE (jq 1.6 -e exits 0 on empty input, e.g. a node that is down)
  local in; in="$(cat)"
  [ -n "${in//[[:space:]]/}" ] || return 1
  jq -e "$@" >/dev/null 2>&1 <<<"$in"
}
owner_of() { stat -c %u "$1" 2>/dev/null; }

# ---- config parsing (postfiatd IniFile rules: trimmed lines, '#' starts a comment line, [name] opens a section) ----
section_count() { # FILE NAME
  awk -v n="$2" '{ sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "") } $0 == "[" n "]" { c++ } END { print c + 0 }' "$1"
}
section_unmanaged() { # FILE NAME -> count of headers outside the managed block
  awk -v n="$2" -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0 == b { inb = 1; next } $0 == e { inb = 0; next }
    { sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "") } $0 == "[" n "]" && !inb { c++ } END { print c + 0 }' "$1"
}
section_values() { # FILE NAME -> value lines of every [NAME] section (comments and blank lines dropped)
  awk -v n="$2" '{ sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "") }
    /^\[/ { s = ($0 == "[" n "]"); next } s && $0 != "" && substr($0, 1, 1) != "#" { print }' "$1"
}
block_count() { awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0 == b { nb++ } $0 == e { ne++ } END { print nb + 0, ne + 0 }' "$1"; }

# ---- audit ------------------------------------------------------------------------------------------------------
audit_checks() {
  local c cfg pub live peers seedline ok n bad e
  c="$(detect_container)"; cfg="$(cfg_file "$c")"
  [ -n "$cfg" ] && [ -f "$cfg" ] || die "cannot find postfiatd.cfg of $c (no $CFG_DEST mount)"
  pub="$(cat "$PUBF" 2>/dev/null)"
  # seed:stored
  if [ ! -f "$SEEDF" ]; then res FAIL seed:stored "no pinned seed (run: sudo pft-cluster keygen)"
  elif [ "$(mode_of "$STATE_DIR")" != 700 ] || [ "$(mode_of "$SEEDF")" != 600 ] || [ "$(owner_of "$SEEDF")" != "$SEED_UID" ]; then
    res FAIL seed:stored "seed storage not private (dir $(mode_of "$STATE_DIR"), file $(mode_of "$SEEDF") uid $(owner_of "$SEEDF"); want 700/600/$SEED_UID)"
  elif ! valid_seed_file "$SEEDF" || ! valid_pub "$pub"; then res FAIL seed:stored "stored seed or public key malformed"
  else res PASS seed:stored "seed 0600 in a 0700 dir; pinned key $(fp "$pub")"; fi
  # cfg:node_seed
  n="$(section_count "$cfg" node_seed)"
  if [ "$n" = 0 ]; then res FAIL cfg:node_seed "no [node_seed] (identity comes from wallet.db and changes with the data volume)"
  elif [ "$n" != 1 ]; then res FAIL cfg:node_seed "$n [node_seed] sections (postfiatd uses the first line of the merged section)"
  elif [ "$(section_unmanaged "$cfg" node_seed)" != 0 ]; then res FAIL cfg:node_seed "[node_seed] outside the pft-cluster block"
  else
    seedline="$(mktemp)"; section_values "$cfg" node_seed | head -1 > "$seedline"
    if [ -f "$SEEDF" ] && cmp -s "$seedline" "$SEEDF"; then res PASS cfg:node_seed "managed [node_seed] = stored seed"
    else res FAIL cfg:node_seed "[node_seed] differs from the stored seed"; fi
    rm -f "$seedline"
  fi
  # cfg:mode
  if [ "$(section_count "$cfg" node_seed)" = 0 ]; then res INFO cfg:mode "postfiatd.cfg $(mode_of "$cfg") (holds no seed)"
  elif [ "$(mode_of "$cfg")" = 600 ]; then res PASS cfg:mode "postfiatd.cfg 0600"
  else res FAIL cfg:mode "postfiatd.cfg holds the seed with mode $(mode_of "$cfg") (want 600)"; fi
  # cfg:cluster_nodes
  if ! valid_pub "$PEER_PUBKEY"; then res FAIL cfg:cluster_nodes "PEER_PUBKEY not set or malformed in $(basename "$CONF")"
  elif [ "$(section_count "$cfg" cluster_nodes)" = 0 ]; then res FAIL cfg:cluster_nodes "no [cluster_nodes] section"
  else
    bad="$(section_values "$cfg" cluster_nodes | awk '$1 !~ /^n[1-9A-HJ-NP-Za-km-z]+$/ || length($1) < 51 || length($1) > 52 { c++ } END { print c + 0 }')"
    if [ "$bad" != 0 ]; then res FAIL cfg:cluster_nodes "$bad malformed [cluster_nodes] entr(y/ies): postfiatd refuses to start"
    elif ! section_values "$cfg" cluster_nodes | awk -v k="$PEER_PUBKEY" '$1 == k { f = 1 } END { exit !f }'; then
      res FAIL cfg:cluster_nodes "PEER_PUBKEY $(fp "$PEER_PUBKEY") not listed"
    elif [ "$(section_unmanaged "$cfg" cluster_nodes)" != 0 ]; then res WARN cfg:cluster_nodes "[cluster_nodes] outside the pft-cluster block (merged by postfiatd)"
    else res PASS cfg:cluster_nodes "$PEER_LABEL $(fp "$PEER_PUBKEY") listed"; fi
  fi
  # live checks
  live="$(server_field "$c" pubkey_node)"
  if [ "$live" = unknown ]; then res FAIL live:pubkey "no server_info answer from $c"
  elif [ -n "$pub" ] && [ "$live" = "$pub" ]; then res PASS live:pubkey "pubkey_node $(fp "$live") = pinned key"
  else res FAIL live:pubkey "pubkey_node $(fp "$live") is not the pinned key $(fp "$pub") (not applied, or restart pending)"; fi
  peers="$(rpc "$c" peers)"
  if ! jqe '.result.cluster | type == "object"' <<<"$peers"; then
    res FAIL live:cluster "no peers answer from $c"; res FAIL live:peer "no peers answer"; res FAIL live:reports "no peers answer"
  else
    if jqe --arg k "$PEER_PUBKEY" '.result.cluster | has($k)' <<<"$peers"; then res PASS live:cluster "$PEER_LABEL $(fp "$PEER_PUBKEY") is a loaded cluster member"
    else res FAIL live:cluster "$PEER_LABEL $(fp "$PEER_PUBKEY") not in peers.cluster (config not loaded)"; fi
    ok="$(jq -r --arg k "$PEER_PUBKEY" '[.result.peers[]? | select(.public_key == $k)] | if length == 0 then "absent" elif any(.cluster == true) then "cluster" else "plain" end' <<<"$peers")"
    case "$ok" in
      cluster) res PASS live:peer "$PEER_LABEL connected, cluster=true" ;;
      plain) res FAIL live:peer "$PEER_LABEL connected but not as a cluster member" ;;
      *) res FAIL live:peer "$PEER_LABEL $(fp "$PEER_PUBKEY") not connected" ;;
    esac
    e="$(jq -r --arg k "$PEER_PUBKEY" '.result.cluster[$k].age // "none"' <<<"$peers")"
    if [[ "$e" =~ ^[0-9]+$ ]] && [ "$e" -le "$REPORT_MAX" ]; then res PASS live:reports "cluster report from $PEER_LABEL ${e} s ago (it counts this node as a member)"
    elif [[ "$e" =~ ^[0-9]+$ ]]; then res FAIL live:reports "last cluster report from $PEER_LABEL ${e} s ago (> $REPORT_MAX)"
    else res FAIL live:reports "no cluster report from $PEER_LABEL (it does not list this node in its [cluster_nodes])"; fi
  fi
  # secret:exposure (patterns always come from the file: the seed never goes on a command line)
  if [ -f "$SEEDF" ] && valid_seed_file "$SEEDF"; then
    bad=""
    "$DOCKER" inspect "$c" 2>/dev/null | grep -qFf "$SEEDF" && bad+=" docker-inspect"
    "$PS" -eo args 2>/dev/null | grep -qFf "$SEEDF" && bad+=" process-args"
    "$DOCKER" logs --tail "$LOG_TAIL" "$c" 2>&1 | grep -qFf "$SEEDF" && bad+=" container-log"
    grep -qsFf "$SEEDF" "$TEXTFILE_DIR"/*.prom && bad+=" textfile"
    if [ -n "$bad" ]; then res FAIL secret:exposure "seed found in:$bad"
    else res PASS secret:exposure "seed absent from docker inspect, process args, last $LOG_TAIL log lines, textfiles"; fi
  else res INFO secret:exposure "no stored seed to look for"; fi
}

print_results() {
  if [ "${JSON:-0}" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg ts "$(ts)" --arg host "$HOST_LABEL" --argjson n "$FINDINGS" '
      {ts:$ts, host:$host, findings:$n, result:(if $n==0 then "PASS" else "FAIL" end),
       checks:[split("\n")[] | select(length>0) | split("\t") | {status:.[0], id:.[1], detail:.[2]}]}'
  else
    echo "pft-cluster audit - $(ts) (host $HOST_LABEL)"
    printf '%s' "$RESULTS" | awk -F'\t' '{printf "  [%-4s] %-18s %s\n", $1, $2, $3}'
    echo "RESULT: $([ "$FINDINGS" = 0 ] && echo PASS || echo "FAIL - $FINDINGS finding(s)")"
  fi
}
clustered() { # 1 if the peer is connected as a member AND reports to us (both directions)
  printf '%s' "$RESULTS" | awk -F'\t' '($2 == "live:peer" || $2 == "live:reports") && $1 == "PASS" { n++ } END { print (n == 2) ? 1 : 0 }'
}
write_prom() { # FILE: node_exporter textfile, written atomically
  local f="$1" tmp h="$HOST_LABEL"
  tmp="$(mktemp "${f}.XXXXXX")" || return 2
  {
    echo "# HELP pft_cluster_check 1 if the cluster check passes (PASS/INFO), 0 if FAIL or WARN."
    echo "# TYPE pft_cluster_check gauge"
    printf '%s' "$RESULTS" | awk -F'\t' -v h="$h" '$1 != "INFO" { printf "pft_cluster_check{host=\"%s\",check=\"%s\",status=\"%s\"} %d\n", h, $2, $1, ($1 == "PASS") }'
    echo "# HELP pft_cluster_peer_clustered 1 if the peer node is connected as a cluster member and reports to this node."
    echo "# TYPE pft_cluster_peer_clustered gauge"
    echo "pft_cluster_peer_clustered{host=\"$h\"} $(clustered)"
    echo "# HELP pft_cluster_findings Number of FAIL + WARN cluster checks."
    echo "# TYPE pft_cluster_findings gauge"
    echo "pft_cluster_findings{host=\"$h\"} $FINDINGS"
    echo "# HELP pft_cluster_last_run_timestamp_seconds Unix time of the last completed audit."
    echo "# TYPE pft_cluster_last_run_timestamp_seconds gauge"
    echo "pft_cluster_last_run_timestamp_seconds{host=\"$h\"} $(date +%s)"
  } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f"
}
validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout (a pulled file must look like ours)
  local f="$1" h="$2" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le 65536 ] || { echo "larger than 65536 bytes"; return 1; }
  n="$(grep -cvE '^(# (HELP|TYPE) pft_cluster_.*|pft_cluster_[a-z_]+\{host="'"$h"'"(,[a-z]+="[A-Za-z0-9_.:-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^pft_cluster_last_run_timestamp_seconds\{host="'"$h"'"\} [0-9]+$' "$f" || { echo "no last_run sample"; return 1; }
  return 0
}
do_pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$TEXTFILE_DIR/.pft_cluster_$PEER_LABEL.prom.pull"
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "/var/lib/pft-exporter/textfile/pft_cluster_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi
  chmod 0644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_cluster_$PEER_LABEL.prom"
}

# ---- keys ---------------------------------------------------------------------------------------------------------
do_keygen() {
  local c tmp
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "keygen needs root" 4
  [ -f "$SEEDF" ] && { echo "$(ts) keygen: a seed is already stored ($(fp "$(cat "$PUBF" 2>/dev/null)")); nothing changed"; return 0; }
  c="$(detect_container)"
  (umask 077; mkdir -p "$STATE_DIR" "$BACKUP_DIR") || die "cannot create $STATE_DIR" 2
  chmod 700 "$STATE_DIR" "$BACKUP_DIR"
  [ -f "$FPF" ] || (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$FPF") || die "cannot write fp_key" 2
  tmp="$(umask 077; mktemp -d "$STATE_DIR/.keygen.XXXXXX")" || die "mktemp failed" 2
  # the answer goes straight from the node's RPC into 0600 files; nothing with the seed is printed or passed as an argument
  rpc "$c" validation_create > "$tmp/answer" 2>/dev/null
  jq -er '.result.validation_seed' "$tmp/answer" > "$tmp/seed" 2>/dev/null \
    && jq -er '.result.validation_public_key' "$tmp/answer" > "$tmp/pub" 2>/dev/null \
    && valid_seed_file "$tmp/seed" && valid_pub "$(cat "$tmp/pub")" \
    || { rm -rf "$tmp"; die "validation_create gave no usable seed/key on $c" 2; }
  mv -f "$tmp/seed" "$SEEDF" && mv -f "$tmp/pub" "$PUBF" && chmod 600 "$SEEDF" && chmod 644 "$PUBF"
  rm -rf "$tmp"
  echo "$(ts) keygen: seed stored (0600), pinned key $(fp "$(cat "$PUBF")")"
}
do_set_peer() { # KEY [TAG]
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "set-peer needs root" 4
  valid_pub "${1:-}" || die "not a node public key" 3
  local tag="${2:-$PEER_TAG}"; valid_tag "$tag" || die "bad tag" 3
  [ -f "$CONF" ] || { (umask 077; : > "$CONF"); }
  local k v
  for k in PEER_PUBKEY PEER_TAG; do
    v="$1"; [ "$k" = PEER_TAG ] && v="$tag"
    if grep -q "^$k=" "$CONF"; then sed -i "s|^$k=.*|$k=$v|" "$CONF"; else echo "$k=$v" >> "$CONF"; fi
  done
  chmod 600 "$CONF"
  echo "$(ts) set-peer: PEER_PUBKEY=$(fp "$1") tag $tag"
}

# ---- plan / apply / rollback --------------------------------------------------------------------------------------
mask() { # stdin -> stdout with seed lines redacted and every node key shown as its own fingerprint
  local l k
  while IFS= read -r l; do
    if [[ "$l" =~ ^([\ +-]?)s${B58}{24,34}$ ]]; then l="${BASH_REMATCH[1]}<seed: redacted>"; fi
    while [[ "$l" =~ (^|[^A-Za-z0-9])(n${B58}{50,51})([^A-Za-z0-9]|$) ]]; do k="${BASH_REMATCH[2]}"; l="${l//"$k"/$(fp "$k")}"; done
    printf '%s\n' "$l"
  done
}
block() { # SEEDFILE-or-"-" -> the managed block ("-" = seed redacted, for display)
  echo "$BEGIN_MARK"
  echo "[node_seed]"
  if [ "$1" = - ]; then echo "<seed: redacted, stored in $(basename "$STATE_DIR")/node_seed>"; else cat "$1"; fi
  echo
  echo "[cluster_nodes]"
  echo "$PEER_PUBKEY $PEER_TAG"
  echo "$END_MARK"
}
strip_block() { # FILE -> FILE without the managed block and without trailing blank lines
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0 == b { inb = 1; next } inb && $0 == e { inb = 0; next } inb { next }
    { lines[++n] = $0 } END { while (n > 0 && lines[n] ~ /^[ \t\r]*$/) n--; for (i = 1; i <= n; i++) print lines[i] }' "$1"
}
candidate() { # CFG SEEDFILE-or-"-" -> stdout
  strip_block "$1"; echo; block "$2"
}
refusals() { # CFG -> reasons apply must refuse, one per line
  local bc
  bc="$(block_count "$1")"
  [ "$bc" = "0 0" ] || [ "$bc" = "1 1" ] || echo "managed block markers broken (BEGIN/END counts $bc)"
  [ "$(section_unmanaged "$1" node_seed)" = 0 ] || echo "an unmanaged [node_seed] exists (remove it by hand first)"
  [ "$(section_unmanaged "$1" cluster_nodes)" = 0 ] || echo "an unmanaged [cluster_nodes] exists (move it into PEER_PUBKEY first)"
  return 0
}
do_plan() {
  local c cfg rf
  c="$(detect_container)"; cfg="$(cfg_file "$c")"
  [ -n "$cfg" ] && [ -f "$cfg" ] || die "cannot find postfiatd.cfg of $c"
  echo "pft-cluster plan - $(ts) (host $HOST_LABEL, container $c)"
  valid_pub "$PEER_PUBKEY" || { echo "REFUSE: PEER_PUBKEY not set (sudo pft-cluster set-peer KEY)"; return 4; }
  echo "managed block appended to postfiatd.cfg (other lines unchanged, file mode -> 0600):"
  block - | mask | sed 's/^/  /'
  echo "then: docker restart $c, health gate (budget ${HEALTH_BUDGET} s)"
  rf="$(refusals "$cfg")"
  [ -n "$rf" ] && { echo "REFUSE:"; sed 's/^/  /' <<<"$rf"; return 4; }
  return 0
}
maint_window() { # WHAT -> 0 if a pft-maint window is active; planned restarts run inside one
  "$MAINT" active >/dev/null 2>&1 && { echo "$(ts) $1: pft-maint window active"; return 0; }
  echo "$(ts) $1: REFUSED - no active pft-maint window (sudo pft-maint start --ttl 45m --reason ...); nothing changed"
  return 1
}
daemon_units() { # long-running pft units that are active now; the gate requires them to stay active
  "$SYSTEMCTL" list-units --type=service --state=running --no-legend 'pft-*' 2>/dev/null | awk '{print $1}' | grep -E '^pft-' | sort -u
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
restart_node() { # CONTAINER
  "$DOCKER" restart -t 60 "$1" >/dev/null 2>&1 && echo "$(ts) restart: $1 restarted" && return 0
  echo "$(ts) restart: docker restart $1 FAILED"; return 1
}
health_gate() { # BEFORE_STARTED_AT CONTAINER DAEMONS MODE(apply|rollback) EXPECT_PUBKEY REQUIRE_PEER
  local before="$1" c="$2" daemons="$3" mode="$4" want="$5" need="$6" start now st sa pk peers u dbad sshok mem pc age label
  start="$(date +%s)"; label="health"; [ "$mode" = rollback ] && label="rollback: health"
  while :; do
    now="$(date +%s)"; sa="$(started_at "$c")"
    st="$(server_field "$c" server_state)"; pk="$(server_field "$c" pubkey_node)"
    peers="$(rpc "$c" peers)"
    mem=0; pc=0; age=none
    if [ "$mode" = apply ]; then
      jqe --arg k "$PEER_PUBKEY" '.result.cluster | has($k)' <<<"$peers" && mem=1
      jqe --arg k "$PEER_PUBKEY" 'any(.result.peers[]?; .public_key == $k and .cluster == true)' <<<"$peers" && pc=1
      age="$(jq -r --arg k "$PEER_PUBKEY" '.result.cluster[$k].age // "none"' 2>/dev/null <<<"$peers")"
    fi
    dbad=""; sshok=0
    for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || dbad+=" $u"; done
    "$SSHD" -t >/dev/null 2>&1 && "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ':22$' \
      && "$KEYSCAN" -T 5 -t ed25519 127.0.0.1 2>/dev/null | grep -q ssh-ed25519 && sshok=1
    if [ "$sa" != "$before" ] && [ -n "$sa" ] && [ "$st" = full ] && [ "$pk" = "$want" ] && [ -z "$dbad" ] && [ "$sshok" = 1 ] \
       && "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ":$PEER_PORT\$" \
       && { [ "$mode" = rollback ] || { [ "$mem" = 1 ] && [ "$INJECT" != health ]; }; } \
       && { [ "$need" != 1 ] || { [ "$pc" = 1 ] && [[ "$age" =~ ^[0-9]+$ ]] && [ "$age" -le "$REPORT_MAX" ]; }; }; then
      echo "$(ts) $label: PASS after $((now - start)) s ($c restarted, server_state full, pubkey_node $(fp "$pk")$([ "$mode" = apply ] && echo ", $PEER_LABEL $(fp "$PEER_PUBKEY") a loaded member")$([ "$need" = 1 ] && echo ", connected cluster=true, report ${age} s ago"), :$PEER_PORT listening, sshd -t ok + :22 handshake, $(wc -w <<<"$daemons") pft daemons active)"
      return 0
    fi
    if (( now - start >= HEALTH_BUDGET )); then
      echo "$(ts) $label: FAIL after $((now - start)) s (restarted=$([ "$sa" != "$before" ] && echo yes || echo NO); server_state=$st; pubkey_node $(fp "$pk") want $(fp "$want"); member=$mem; peer_cluster=$pc; report_age=$age; ssh=$sshok; inactive daemons:${dbad:- none}${INJECT:+; injected=$INJECT})"
      return 1
    fi
    sleep "$POLL_SEC"
  done
}
integrity_accept() { # REASON: accept a new baseline only if every changed item is the postfiatd config file
  command -v "$INTEGRITY" >/dev/null 2>&1 || { echo "$(ts) integrity: pft-integrity not installed, skipped"; return 0; }
  local out items other
  out="$("$INTEGRITY" verify 2>&1)"
  items="$(grep -E '^  \[(WARN|FAIL)\] ' <<<"$out" | awk '{print $2}' | sort -u)"
  [ -n "$items" ] || { echo "$(ts) integrity: baseline already current"; return 0; }
  other="$(grep -vxE 'cfgvol:postfiatd\.cfg' <<<"$items")"
  if [ -n "$other" ]; then
    echo "$(ts) integrity: NOT accepted - changed items besides the config: $(paste -sd' ' <<<"$other")"
    return 1
  fi
  "$INTEGRITY" accept --reason "$1" >/dev/null 2>&1 && echo "$(ts) integrity: accepted (cfgvol:postfiatd.cfg only): $1" \
    || { echo "$(ts) integrity: accept FAILED"; return 1; }
}
restore_cfg() { # BACKUP CFG: bytes from the 0600 backup, mode/owner from BACKUP.meta (the original file's)
  local m u g
  cp -p "$1" "$2" || return 1
  [ "$(sha "$1")" = "$(sha "$2")" ] || { echo "$(ts) rollback: config sha256 mismatch after restore"; return 1; }
  if read -r m u g < "$1.meta" 2>/dev/null && [[ "$m" =~ ^[0-7]{3,4}$ ]]; then
    chown "$u:$g" "$2" 2>/dev/null; chmod "$m" "$2" || return 1
    [ "$(mode_of "$2")" = "$m" ] || { echo "$(ts) rollback: mode $(mode_of "$2") after restore, want $m"; return 1; }
  else echo "$(ts) rollback: no $(basename "$1").meta, mode left at $(mode_of "$2")"; fi
  echo "$(ts) rollback: postfiatd.cfg restored byte-identical (sha256 $(sha "$2" | cut -c1-12), mode $(mode_of "$2"))"
}
do_apply() {
  local dry="$1" need="$2" c cfg cand b rf before daemons prepub
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  c="$(detect_container)"; cfg="$(cfg_file "$c")"
  [ -n "$cfg" ] && [ -f "$cfg" ] || die "cannot find postfiatd.cfg of $c" 2
  valid_pub "$PEER_PUBKEY" || { echo "$(ts) apply: REFUSED - PEER_PUBKEY not set or malformed (sudo pft-cluster set-peer KEY)"; return 4; }
  [ -f "$SEEDF" ] && valid_seed_file "$SEEDF" && valid_pub "$(cat "$PUBF" 2>/dev/null)" \
    || { echo "$(ts) apply: REFUSED - no valid stored seed (sudo pft-cluster keygen)"; return 4; }
  [ "$(cat "$PUBF")" != "$PEER_PUBKEY" ] || { echo "$(ts) apply: REFUSED - PEER_PUBKEY is this node's own key"; return 4; }
  rf="$(refusals "$cfg")"
  [ -n "$rf" ] && { echo "$(ts) apply: REFUSED:"; sed 's/^/  /' <<<"$rf"; return 4; }
  if [ "$dry" = 1 ]; then
    cand="$(umask 077; mktemp "$STATE_DIR/.cand.XXXXXX")" || die "mktemp failed" 2
    candidate "$cfg" "$SEEDF" > "$cand"
    diff -u --label postfiatd.cfg --label postfiatd.cfg.candidate "$cfg" "$cand" | mask
    rm -f "$cand"
    echo "$(ts) apply: dry run, nothing changed"; return 0
  fi
  maint_window apply || return 4
  cand="$(umask 077; mktemp "$STATE_DIR/.cand.XXXXXX")" || die "mktemp failed" 2
  candidate "$cfg" "$SEEDF" > "$cand"
  [ "$(section_count "$cand" node_seed)" = 1 ] && [ "$(section_count "$cand" cluster_nodes)" = 1 ] \
    || { rm -f "$cand"; echo "$(ts) apply: REFUSED - candidate does not have exactly one [node_seed] and [cluster_nodes]"; return 4; }
  prepub="$(server_field "$c" pubkey_node)"
  if cmp -s "$cfg" "$cand" && [ "$(mode_of "$cfg")" = 600 ] && [ "$prepub" = "$(cat "$PUBF")" ] \
     && jqe --arg k "$PEER_PUBKEY" '.result.cluster | has($k)' <<<"$(rpc "$c" peers)"; then
    rm -f "$cand"; echo "$(ts) apply: already applied (config block current, pinned key live, member loaded) - nothing to do"; return 0
  fi
  before="$(started_at "$c")"; daemons="$(daemon_units)"
  b="$BACKUP_DIR/postfiatd.cfg.$(date -u +%Y%m%dT%H%M%SZ)"
  (umask 077; cp -p "$cfg" "$b") && chmod 600 "$b" || { rm -f "$cand"; die "backup failed" 2; }
  echo "$(ts) apply: backup $(basename "$b") (sha256 $(sha "$b" | cut -c1-12), pre-apply pubkey_node $(fp "$prepub"))"
  printf '%s\n' "$prepub" > "$b.pubkey"; stat -c '%a %u %g' "$cfg" > "$b.meta"
  # same directory, then rename: the file is never visible half-written or with a wider mode
  chown --reference="$cfg" "$cand" 2>/dev/null; chmod 600 "$cand"
  mv -f "$cand" "$(dirname "$cfg")/.postfiatd.cfg.pft-cluster" && mv -f "$(dirname "$cfg")/.postfiatd.cfg.pft-cluster" "$cfg" \
    || die "install config failed" 2
  echo "$(ts) apply: config installed (sha256 $(sha "$b" | cut -c1-12) -> $(sha "$cfg" | cut -c1-12), mode 600)"
  if ! restart_node "$c" || ! health_gate "$before" "$c" "$daemons" apply "$(cat "$PUBF")" "$need"; then
    echo "$(ts) apply: restart or health gate failed -> automatic rollback"
    before="$(started_at "$c")"
    restore_cfg "$b" "$cfg" && restart_node "$c" && health_gate "$before" "$c" "$daemons" rollback "$prepub" 0 || return 5
    integrity_accept "pft-cluster: automatic rollback to $(basename "$b")" || true
    return 1
  fi
  integrity_accept "pft-cluster apply: [node_seed] + [cluster_nodes] block in postfiatd.cfg (backup $(basename "$b"))" || true
  echo "$(ts) apply: done"
}
do_rollback() {
  local c cfg b before daemons want
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
  b="$(find "$BACKUP_DIR" -maxdepth 1 -regextype posix-extended -regex '.*/postfiatd\.cfg\.[0-9]{8}T[0-9]{6}Z' 2>/dev/null | sort | tail -1)"
  [ -n "$b" ] || die "no config backup in $BACKUP_DIR" 2
  maint_window rollback || return 4
  c="$(detect_container)"; cfg="$(cfg_file "$c")"
  [ -n "$cfg" ] && [ -f "$cfg" ] || die "cannot find postfiatd.cfg of $c" 2
  want="$(cat "$b.pubkey" 2>/dev/null)"
  before="$(started_at "$c")"; daemons="$(daemon_units)"
  restore_cfg "$b" "$cfg" || return 5
  restart_node "$c" || return 5
  if [ -n "$want" ] && valid_pub "$want"; then health_gate "$before" "$c" "$daemons" rollback "$want" 0 || return 5
  else echo "$(ts) rollback: no recorded pre-apply key; gate without the key check"
       health_gate "$before" "$c" "$daemons" rollback "$(server_field "$c" pubkey_node)" 0 || return 5; fi
  integrity_accept "pft-cluster rollback: postfiatd.cfg restored from $(basename "$b")" || true
  echo "$(ts) rollback: done ($(basename "$b"))"
}

cmd="${1:-}"; shift || true
valid_label "$HOST_LABEL" || die "bad HOST_LABEL in $CONF" 2
valid_tag "$PEER_TAG" || die "bad PEER_TAG in $CONF" 2
case "$cmd" in
  validate) [ $# -eq 2 ] && valid_label "$2" || die "usage: pft-cluster validate FILE HOST" 3
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  pubkey) [ -f "$PUBF" ] && valid_pub "$(cat "$PUBF")" || die "no pinned key (sudo pft-cluster keygen)" 2
          cat "$PUBF"; exit 0 ;;
  set-peer) do_set_peer "$@"; exit $? ;;
esac
YES=0; DRY=0; JSON=0; PROM=""; NEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;; --dry-run) DRY=1 ;; --json) JSON=1 ;; --require-peer) NEED=1 ;;
    --prom) PROM="${2:-}"; [ -n "$PROM" ] || die "--prom needs a file" 3; shift ;;
    --textfile) PROM="$TEXTFILE_DIR/pft_cluster_$HOST_LABEL.prom" ;;
    *) die "unknown option $1" 3 ;;
  esac
  shift
done
case "$cmd" in
  audit)
    audit_checks; print_results
    [ -n "$PROM" ] && { write_prom "$PROM" || die "cannot write $PROM" 2; }
    [ "$FINDINGS" = 0 ] && exit 0 || exit 1 ;;
  keygen) do_keygen; exit $? ;;
  plan) do_plan; exit $? ;;
  pull) [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "pull needs root" 4
        do_pull; exit $? ;;
  apply) [ "$YES" = 1 ] || [ "$DRY" = 1 ] || die "apply rewrites postfiatd.cfg and restarts the node; pass --yes (or --dry-run)" 4
         do_apply "$DRY" "$NEED"; exit $? ;;
  rollback) [ "$YES" = 1 ] || die "rollback rewrites postfiatd.cfg and restarts the node; pass --yes" 4
            do_rollback; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
