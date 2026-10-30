#!/usr/bin/env bash
# pft-fleet: add-on inventory, version-skew detection and pinned sync for a Post Fiat validator + sentry pair.
#
# Every add-on in this repo is installed by copying files (scripts, units, helpers) to fixed paths. After a few
# weeks of fixes the hosts drift: one host gets the new script, the other keeps the old one, a hand edit is never
# committed. pft-fleet compares the installed bytes on every host with the repo's git history.
#
# Usage: pft-fleet inventory [--json] [--hosts L1,L2]          read-only: every tracked file + unit, both hosts
#        pft-fleet skew [--json] [--metrics] [--hosts L1,L2]    read-only: per-add-on state + cross-host DIVERGED
#        pft-fleet sync --addon NAME --to COMMIT [--hosts L1,L2] [--apply] [--reason TEXT]
#
#  inventory  sha256 of every manifest file on every host, the newest commit with those bytes, the classification,
#             and enabled/active of every unit file (template units: every loaded instance).
#  skew       one line per host and add-on: CURRENT | BEHIND | MODIFIED | MISSING | UNEXPECTED (worst file wins),
#             plus `* ADDON DIVERGED` when an installed file differs between hosts. Exit 0 all CURRENT,
#             1 BEHIND/UNEXPECTED/DIVERGED, 2 MODIFIED/MISSING or a host could not be read, 3 usage/config error.
#             --metrics writes TEXTFILE_DIR/pft_fleet.prom (and the drift clock in STATE_DIR/drift.json).
#  sync       installs one add-on's files exactly as they are at COMMIT (must be an ancestor of REF). Dry run by
#             default: prints the plan and exits 0. With --apply (root), host by host, sentry role first:
#               pre    pft-maint window active on the host; node full/proposing; pft-integrity verify clean except
#                      items this sync rewrites
#               write  backup (cp -p) to BACKUP_DIR/<stamp>/, atomic replace (tmp + mv), daemon-reload for units
#               gate   installed sha256 == COMMIT bytes; bash -n / python ast parse; unit LoadState loaded and not
#                      failed; node still full/proposing
#               fail   rollback: restore the backups (cp -p: bytes, mode, owner, mtime), daemon-reload, require the
#                      original sha256 of every file, stop before the next host. Exit 5 (6 if a hash differs)
#               pass   pft-integrity accept --reason "pft-fleet sync ADDON@SHORT on HOST: FILES [REASON]"
#             Exit 0 synced (or nothing to do), 3 usage, 4 refused (pre-check), 5 rolled back, 6 rollback mismatch.
#
# Config: /etc/pft-fleet/fleet.conf (KEY=VALUE, parsed as data, never sourced): REPO (git checkout of this repo),
#   REF (main), HOSTS_CONF (/etc/pft-fleet/hosts.conf), TEXTFILE_DIR (/var/lib/pft-exporter/textfile),
#   STATE_DIR (/var/lib/pft-fleet), SSH_AS (user that holds the ssh key for ssh hosts; default $SUDO_USER).
# hosts.conf: host LABEL local|ssh SSH_TARGET|- CONTAINER validator|sentry
# Test hooks: PFT_FLEET_CONF  PFT_FLEET_LIB  PFT_FLEET_MANIFEST  PFT_FLEET_SSH  PFT_FLEET_NOROOT=1 (no root checks,
#   no chown)  PFT_FLEET_ROOT_<LABEL> (path prefix for that host)  PFT_FLEET_INJECT_GATE_FAIL=<LABEL> (the post-write
#   gate on that host fails: rollback drill)  PFT_FLEET_NOW (fixed clock for metrics)
set -uo pipefail
umask 022

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CONF="${PFT_FLEET_CONF:-/etc/pft-fleet/fleet.conf}"
conf_get() { [ -r "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1 | sed 's/^"\(.*\)"$/\1/'; }
REPO="$(conf_get REPO)"; REF="$(conf_get REF)"; REF="${REF:-main}"
HOSTS_CONF="$(conf_get HOSTS_CONF)"; HOSTS_CONF="${HOSTS_CONF:-/etc/pft-fleet/hosts.conf}"
TEXTFILE_DIR="$(conf_get TEXTFILE_DIR)"; TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
STATE_DIR="$(conf_get STATE_DIR)"; STATE_DIR="${STATE_DIR:-/var/lib/pft-fleet}"
SSH_AS="$(conf_get SSH_AS)"; SSH_AS="${SSH_AS:-${SUDO_USER:-}}"
LIB="${PFT_FLEET_LIB:-}"
[ -n "$LIB" ] || for c in "$HERE/fleet_lib.py" /usr/local/lib/pft-fleet/fleet_lib.py; do [ -f "$c" ] && { LIB="$c"; break; }; done
MANIFEST="${PFT_FLEET_MANIFEST:-}"
[ -n "$MANIFEST" ] || for c in "$HERE/manifest.tsv" /usr/local/lib/pft-fleet/manifest.tsv; do [ -f "$c" ] && { MANIFEST="$c"; break; }; done
SSH="${PFT_FLEET_SSH:-ssh}"
NOROOT="${PFT_FLEET_NOROOT:-0}"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit "${2:-3}"; }
usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 3; }

declare -A H_MODE H_SSH H_CONT H_ROLE H_ROOT
HOSTS=()
load_hosts() { # [L1,L2]
  local kw l m s c r rest want="${1:-}"
  [ -r "$HOSTS_CONF" ] || die "no hosts config $HOSTS_CONF (see hosts.conf.example)"
  while read -r kw l m s c r rest; do
    [ "$kw" = host ] || continue
    case "$m" in local|ssh) ;; *) die "$HOSTS_CONF: host $l: mode must be local or ssh" ;; esac
    case "$r" in validator|sentry) ;; *) die "$HOSTS_CONF: host $l: role must be validator or sentry" ;; esac
    [[ "$l" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || die "$HOSTS_CONF: bad label $l"
    if [ -n "$want" ] && [[ ",$want," != *",$l,"* ]]; then continue; fi
    HOSTS+=("$l"); H_MODE[$l]="$m"; H_SSH[$l]="$s"; H_CONT[$l]="$c"; H_ROLE[$l]="$r"
    local v="PFT_FLEET_ROOT_${l//-/_}"; H_ROOT[$l]="${!v:-}"
  done < <(grep -v '^[[:space:]]*#' "$HOSTS_CONF")
  [ "${#HOSTS[@]}" -ge 1 ] || die "no hosts selected from $HOSTS_CONF"
}
is_root() { [ "$(id -u)" = 0 ] || [ "$NOROOT" = 1 ]; }
hx() { # LABEL CMD... : CMD as root on that host
  local h="$1"; shift
  if [ "${H_MODE[$h]}" = ssh ]; then
    local rc
    rc="sudo -n $(printf '%q ' "$@")"
    if [ "$(id -u)" = 0 ] && [ -n "$SSH_AS" ] && [ "$SSH_AS" != root ]; then
      runuser -u "$SSH_AS" -- "$SSH" -o BatchMode=yes -o ConnectTimeout=10 "${H_SSH[$h]}" "$rc"
    else
      "$SSH" -o BatchMode=yes -o ConnectTimeout=10 "${H_SSH[$h]}" "$rc"
    fi
  elif [ "$(id -u)" = 0 ] || [ "$NOROOT" = 1 ]; then "$@"
  else sudo -n "$@"; fi
}

# Runs on the host: R PATH... -> "F<TAB>PATH<TAB>SHA|-" per path, then "U<TAB>UNIT<TAB>ENABLED<TAB>ACTIVE" per unit file
# shellcheck disable=SC2016
COLLECT='R="$1"; shift
for p in "$@"; do
  if [ -f "$R$p" ]; then s="$(sha256sum < "$R$p")"; printf "F\t%s\t%s\n" "$p" "${s%% *}"; else printf "F\t%s\t-\n" "$p"; fi
done
for p in "$@"; do
  case "$p" in /etc/systemd/system/*.service|/etc/systemd/system/*.timer) ;; *) continue ;; esac
  [ -f "$R$p" ] || continue
  u="${p##*/}"
  if [[ "$u" == *@.* ]]; then
    for i in $(systemctl list-units --all --plain --no-legend "${u%%@*}@*.${u##*.}" 2>/dev/null | awk "{print \$1}"); do
      printf "U\t%s\t%s\t%s\n" "$i" "$(systemctl is-enabled "$i" 2>/dev/null)" "$(systemctl is-active "$i" 2>/dev/null)"
    done
  else
    printf "U\t%s\t%s\t%s\n" "$u" "$(systemctl is-enabled "$u" 2>/dev/null)" "$(systemctl is-active "$u" 2>/dev/null)"
  fi
done'

manifest_paths() { awk '!/^[[:space:]]*#/ && NF==5 {print $3}' "$MANIFEST" | sort -u; }

collect_host() { # LABEL -> inventory TSV lines on stdout
  local h="$1" out rc paths=()
  mapfile -t paths < <(manifest_paths)
  out="$(hx "$h" bash -c "$COLLECT" collect "${H_ROOT[$h]}" "${paths[@]}" 2>/dev/null)"; rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q $'^F\t' <<<"$out"; then
    printf 'host\t%s\t%s\terror:collect rc=%s\n' "$h" "${H_ROLE[$h]}" "$rc"; return 0
  fi
  printf 'host\t%s\t%s\tok\n' "$h" "${H_ROLE[$h]}"
  awk -F'\t' -v h="$h" -v r="${H_ROLE[$h]}" '
    $1=="F" && NF==3 {printf "file\t%s\t%s\t%s\t%s\n", h, r, $2, $3}
    $1=="U" && NF==4 {e=$3; a=$4; if (e=="") e="-"; if (a=="") a="-"; printf "unit\t%s\t%s\t%s\t%s\t%s\n", h, r, $2, e, a}' <<<"$out"
}

INV=""
collect_all() {
  INV="$(mktemp)"
  local h
  for h in "${HOSTS[@]}"; do collect_host "$h" >> "$INV"; done
}
cleanup() { [ -n "$INV" ] && rm -f "$INV"; }
trap cleanup EXIT

need_repo() {
  [ -n "$REPO" ] || die "REPO not set in $CONF"
  git -c safe.directory='*' -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || die "REPO $REPO is not a git checkout"
  if [ -z "$LIB" ] || [ ! -f "$LIB" ]; then die "fleet_lib.py not found"; fi
  if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then die "manifest.tsv not found"; fi
}

cmd_report() { # inventory|skew ARGS...
  local mode="$1"; shift
  local json=() metrics=0 hosts=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=(--json) ;;
      --metrics) metrics=1 ;;
      --hosts) hosts="${2:?--hosts needs a list}"; shift ;;
      *) die "unknown argument $1" ;;
    esac; shift
  done
  need_repo; load_hosts "$hosts"; collect_all
  local extra=() rc
  if [ "$metrics" = 1 ]; then
    [ "$mode" = skew ] || die "--metrics is for skew"
    mkdir -p "$STATE_DIR" "$TEXTFILE_DIR" || die "cannot create $STATE_DIR / $TEXTFILE_DIR"
    extra=(--metrics "$TEXTFILE_DIR/pft_fleet.prom" --drift-state "$STATE_DIR/drift.json" --now "${PFT_FLEET_NOW:-}")
  fi
  python3 -I "$LIB" report --repo "$REPO" --ref "$REF" --manifest "$MANIFEST" --inv "$INV" --mode "$mode" \
    "${json[@]}" "${extra[@]}"; rc=$?
  return "$rc"
}

# ---------- sync ----------
POLL_LINE=""
node_ok() { # LABEL -> 0 when the node reports full or proposing
  local st
  st="$(hx "$1" docker exec "${H_CONT[$1]}" curl -s --max-time 8 -X POST -H 'Content-Type: application/json' \
    http://127.0.0.1:5005/ -d '{"method":"server_info","params":[{}]}' 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null)"
  POLL_LINE="server_state=${st:-down}"
  case "$st" in full|proposing) return 0 ;; *) return 1 ;; esac
}
integ_item() { # INSTALL_PATH -> pft-integrity item name (empty if that path is not covered by pft-integrity)
  case "$1" in
    /usr/local/bin/*) echo "bin:${1##*/}" ;;
    /etc/systemd/system/*) echo "unit:${1##*/}" ;;
  esac
}
# integrity_clean LABEL ALLOWED_ITEMS(newline list) -> 0 when verify is PASS or every finding is an allowed item
integrity_clean() {
  local h="$1" allowed="$2" j bad
  j="$(hx "$h" pft-integrity verify --json 2>/dev/null)"
  if [ -z "$j" ] || ! jq -e . >/dev/null 2>&1 <<<"$j"; then echo "pft-integrity verify gave no JSON"; return 1; fi
  if printf '%s\n' "$allowed" | grep -q .; then
    bad="$(jq -r '.findings[].item' <<<"$j" | grep -vxF -f <(printf '%s\n' "$allowed" | grep .); true)"
  else
    bad="$(jq -r '.findings[].item' <<<"$j")"
  fi
  if [ -n "$bad" ]; then echo "pft-integrity $(jq -r .status <<<"$j"): unrelated findings: $(paste -sd, - <<<"$bad")"; return 1; fi
  echo "pft-integrity $(jq -r .status <<<"$j") ($(jq -r '.findings | length' <<<"$j") findings, all on files this sync rewrites)"
}
host_sha() { # LABEL PATH -> sha256 or -
  hx "$1" bash -c "$COLLECT" collect "${H_ROOT[$1]}" "$2" 2>/dev/null | awk -F'\t' '$1=="F"{print $3; exit}'
}
put_file() { # LABEL DEST MODE < content : atomic replace as root:root
  local own=1; [ "$NOROOT" = 1 ] && own=0
  # shellcheck disable=SC2016
  hx "$1" bash -c 'set -e; d="$1"; install -d -m 755 "$(dirname "$d")"; t="$d.pft-fleet.new"; cat > "$t"; chmod "$2" "$t"
    [ "$3" = 1 ] && chown 0:0 "$t"; mv -f "$t" "$d"' put "${H_ROOT[$1]}$2" "$3" "$own"
}
backup_file() { # LABEL PATH DIR -> copy with cp -p (existing files only)
  # shellcheck disable=SC2016
  hx "$1" bash -c 'set -e; install -d -m 700 "$2"; cp -p "$1" "$2/$(printf "%s" "$3" | tr / _)"' bak "${H_ROOT[$1]}$2" "${H_ROOT[$1]}$3" "$2"
}
restore_file() { # LABEL PATH DIR
  # shellcheck disable=SC2016
  hx "$1" bash -c 'set -e; s="$2/$(printf "%s" "$3" | tr / _)"; t="$1.pft-fleet.rb"; cp -p "$s" "$t"; mv -f "$t" "$1"' rb \
    "${H_ROOT[$1]}$2" "${H_ROOT[$1]}$3" "$2"
}
remove_file() { hx "$1" rm -f -- "${H_ROOT[$1]}$2"; }

# gate LABEL : checks every written file and the node; GATE lines; 0 pass
gate() {
  local h="$1" fail=0 i p s u ls
  for i in "${!W_PATH[@]}"; do
    p="${W_PATH[$i]}"
    s="$(host_sha "$h" "$p")"
    if [ "$s" = "${W_TGT[$i]}" ]; then echo "GATE $h sha256 $p = target ${s:0:12} PASS"
    else echo "GATE $h sha256 $p = ${s:0:12} want ${W_TGT[$i]:0:12} FAIL"; fail=1; fi
    case "$p" in
      *.service|*.timer)
        u="${p##*/}"
        if [[ "$u" == *@.* ]]; then echo "GATE $h unit $u template (instances checked below) PASS"; continue; fi
        ls="$(hx "$h" systemctl show -p LoadState --value "$u" 2>/dev/null)"
        if [ "$ls" = loaded ]; then echo "GATE $h unit $u LoadState=loaded PASS"
        else echo "GATE $h unit $u LoadState=${ls:-?} FAIL"; fail=1; fi ;;
      *.py) if hx "$h" python3 -I -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "${H_ROOT[$h]}$p" >/dev/null 2>&1
            then echo "GATE $h syntax $p python PASS"; else echo "GATE $h syntax $p python FAIL"; fail=1; fi ;;
      *) if hx "$h" head -c 64 "${H_ROOT[$h]}$p" 2>/dev/null | head -1 | grep -q bash; then
           if hx "$h" bash -n "${H_ROOT[$h]}$p" >/dev/null 2>&1; then echo "GATE $h syntax $p bash -n PASS"
           else echo "GATE $h syntax $p bash -n FAIL"; fail=1; fi
         fi ;;
    esac
  done
  local failed
  failed="$(hx "$h" bash -c "$COLLECT" collect "${H_ROOT[$h]}" "${ADDON_PATHS[@]}" 2>/dev/null | awk -F'\t' '$1=="U" && $4=="failed"{print $2}' | paste -sd, -)"
  if [ -z "$failed" ]; then echo "GATE $h addon units failed=none PASS"; else echo "GATE $h addon units failed=$failed FAIL"; fail=1; fi
  if node_ok "$h"; then echo "GATE $h node $POLL_LINE PASS"; else echo "GATE $h node $POLL_LINE FAIL"; fail=1; fi
  if [ "${PFT_FLEET_INJECT_GATE_FAIL:-}" = "$h" ]; then echo "GATE $h injected failure (PFT_FLEET_INJECT_GATE_FAIL) FAIL"; fail=1; fi
  return "$fail"
}

cmd_sync() {
  local addon="" to="" hosts="" apply=0 reason=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --addon) addon="${2:?}"; shift ;;
      --to) to="${2:?}"; shift ;;
      --hosts) hosts="${2:?}"; shift ;;
      --apply) apply=1 ;;
      --reason) reason="${2:?}"; shift ;;
      *) die "unknown argument $1" ;;
    esac; shift
  done
  if [ -z "$addon" ] || [ -z "$to" ]; then die "sync needs --addon NAME --to COMMIT"; fi
  need_repo
  local commit refc
  commit="$(git -c safe.directory='*' -C "$REPO" rev-parse --verify -q "$to^{commit}")" || die "unknown commit $to"
  refc="$(git -c safe.directory='*' -C "$REPO" rev-parse --verify -q "$REF^{commit}")" || die "unknown REF $REF"
  git -c safe.directory='*' -C "$REPO" merge-base --is-ancestor "$commit" "$refc" || die "$commit is not in $REF's history (refusing unreviewed commits)"
  load_hosts "$hosts"; collect_all
  local plan rc
  plan="$(python3 -I "$LIB" plan --repo "$REPO" --ref "$REF" --manifest "$MANIFEST" --inv "$INV" --to "$commit" --addon "$addon")"; rc=$?
  [ "$rc" -eq 0 ] || exit "$rc"
  mapfile -t ADDON_PATHS < <(python3 -I "$LIB" files --manifest "$MANIFEST" --addon "$addon" | cut -f3)
  log "sync $addon to $commit ($(git -c safe.directory='*' -C "$REPO" log -1 --format=%cI "$commit")) REF $REF=$refc"
  printf 'PLAN %s\n' "HOST ROLE PATH MODE CURRENT_STATE CURRENT_SHA TARGET_SHA ACTION"
  awk -F'\t' '{printf "PLAN %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $8, substr($6,1,12), substr($7,1,12), $9}' <<<"$plan"
  # sentry role first, then validator
  local order=() h
  for h in "${HOSTS[@]}"; do [ "${H_ROLE[$h]}" = sentry ] && order+=("$h"); done
  for h in "${HOSTS[@]}"; do [ "${H_ROLE[$h]}" = sentry ] || order+=("$h"); done
  log "order: ${order[*]}"
  if [ "$apply" != 1 ]; then log "dry run (no --apply): nothing changed"; return 0; fi
  is_root || die "sync --apply must run as root" 4
  local short="${commit:0:12}" stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  for h in "${order[@]}"; do
    W_PATH=(); W_MODE=(); W_REPO=(); W_CUR=(); W_TGT=()
    local l r p m rp cur tgt st act
    while IFS=$'\t' read -r l r p m rp cur tgt st act; do
      if [ "$l" != "$h" ] || [ "$act" != write ]; then continue; fi
      W_PATH+=("$p"); W_MODE+=("$m"); W_REPO+=("$rp"); W_CUR+=("$cur"); W_TGT+=("$tgt")
    done <<<"$plan"
    if [ "${#W_PATH[@]}" -eq 0 ]; then log "$h: every $addon file already at $short - nothing to do"; continue; fi
    log "$h: ${#W_PATH[@]} file(s) to write"
    # pre-checks
    if ! hx "$h" pft-maint active >/dev/null 2>&1; then log "REFUSED $h: no active pft-maint window (sudo pft-maint start --ttl 30m --reason ...)"; exit 4; fi
    echo "PRE $h pft-maint window active PASS"
    if ! node_ok "$h"; then log "REFUSED $h: node $POLL_LINE"; exit 4; fi
    echo "PRE $h node $POLL_LINE PASS"
    local allowed="" i msg
    for i in "${!W_PATH[@]}"; do allowed+="$(integ_item "${W_PATH[$i]}")"$'\n'; done
    if ! msg="$(integrity_clean "$h" "$allowed")"; then log "REFUSED $h: $msg"; exit 4; fi
    echo "PRE $h $msg PASS"
    # backup + write
    local bdir="$STATE_DIR/backup/$stamp-$addon-$h" units=0
    for i in "${!W_PATH[@]}"; do
      p="${W_PATH[$i]}"
      if [ "${W_CUR[$i]}" != - ]; then backup_file "$h" "$p" "$bdir" || { log "ERROR $h: backup of $p failed - nothing written on $h"; exit 4; }
        echo "BACKUP $h $p sha256 ${W_CUR[$i]:0:12} -> $bdir"
      else echo "BACKUP $h $p absent before sync (rollback removes it)"; fi
    done
    for i in "${!W_PATH[@]}"; do
      p="${W_PATH[$i]}"
      if git -c safe.directory='*' -C "$REPO" show "$commit:${W_REPO[$i]}" | put_file "$h" "$p" "${W_MODE[$i]}"; then
        echo "WRITE $h $p ${W_CUR[$i]:0:12} -> ${W_TGT[$i]:0:12} mode ${W_MODE[$i]}"
      else echo "WRITE $h $p FAILED"; fi
      case "$p" in *.service|*.timer) units=1 ;; esac
    done
    [ "$units" = 1 ] && { hx "$h" systemctl daemon-reload && echo "RELOAD $h systemctl daemon-reload"; }
    if gate "$h"; then
      local files
      files="$(printf '%s\n' "${W_PATH[@]}" | sed 's#.*/##' | paste -sd, -)"
      if hx "$h" pft-integrity accept --reason "pft-fleet sync $addon@$short on $h: $files${reason:+ ($reason)}" >/dev/null 2>&1; then
        echo "ACCEPT $h pft-integrity baseline updated: pft-fleet sync $addon@$short ($files)"
      else echo "ACCEPT $h pft-integrity accept FAILED (files are synced; accept by hand)"; fi
      log "SYNCED $h $addon -> $short"
    else
      log "GATE FAILED on $h - rolling back"
      local bad=0
      for i in "${!W_PATH[@]}"; do
        p="${W_PATH[$i]}"
        if [ "${W_CUR[$i]}" != - ]; then restore_file "$h" "$p" "$bdir"; else remove_file "$h" "$p"; fi
      done
      [ "$units" = 1 ] && hx "$h" systemctl daemon-reload
      for i in "${!W_PATH[@]}"; do
        p="${W_PATH[$i]}"; s="$(host_sha "$h" "$p")"
        if [ "$s" = "${W_CUR[$i]}" ]; then echo "ROLLBACK $h $p sha256 ${s:0:12} = original PASS"
        else echo "ROLLBACK $h $p sha256 ${s:0:12} want ${W_CUR[$i]:0:12} FAIL"; bad=1; fi
      done
      if [ "$bad" = 1 ]; then log "ROLLBACK MISMATCH on $h - fix by hand from $bdir"; exit 6; fi
      log "ROLLED BACK $h: every file has its original sha256; later hosts untouched"
      exit 5
    fi
  done
  log "sync complete"
  return 0
}

[ $# -ge 1 ] || usage
cmd="$1"; shift
case "$cmd" in
  inventory|skew) cmd_report "$cmd" "$@"; exit $? ;;
  sync) cmd_sync "$@"; exit $? ;;
  -h|--help|help) usage ;;
  *) die "unknown command $cmd" ;;
esac
