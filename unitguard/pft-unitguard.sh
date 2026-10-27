#!/usr/bin/env bash
# pft-unitguard: systemd sandboxing for the host-side add-on units of a Post Fiat validator / sentry host
# (Ubuntu 22.04, systemd 249). Each unit gets one drop-in, 50-unitguard.conf, built from a per-unit profile in
# profiles/. Apply runs the unit and its functional check right after the drop-in lands and removes the drop-in
# again (rollback) if either fails.
#
# Usage: pft-unitguard audit    [--units "U1 U2"] [--tsv] [--detail]
#        pft-unitguard plan     UNIT
#        sudo pft-unitguard apply    UNIT|--all [--skip "U1 U2"]
#        sudo pft-unitguard rollback UNIT|--all
#
#  audit     read-only. For every profiled unit present on this host: systemd-analyze security exposure and
#            rating, User=/DynamicUser=, number of failed (✗) checks, whether the unitguard drop-in is installed,
#            the profile class (standard | docker | iptables) and the class target. Also checks that the drop-in
#            dirs/files and each unit's ExecStart binary are root-owned and not group/world-writable.
#            --detail adds the names of the failed checks (the missing directives) under each unit.
#            Exit 0 when every installed drop-in meets its class target, 1 otherwise.
#  plan      prints the drop-in apply would write, its path, the class, documented exceptions and the
#            functional check. Changes nothing.
#  apply     writes the drop-in (dir 0755, file 0644, root), daemon-reload, then runs the unit: oneshot units are
#            started (restarted when RemainAfterExit=yes) and must end with Result=success; long-running units are restarted and must stay active for
#            SETTLE_SEC with NRestarts unchanged. Then the profile's check command must exit 0. Any failure ->
#            the drop-in that was there before this apply is put back (also an earlier unitguard one, so a bad
#            profile change never strips a working profile), else it is removed; daemon-reload, unit re-run, exit 1.
#            Units in HOLD_UNITS (or --skip) are left alone (e.g. collectors in a data window).
#  rollback  removes the unitguard drop-in (restoring a saved earlier copy if there was one), daemon-reload.
#
# Profile format (profiles/<unit>.conf, template units as name@.service.conf): lines starting with "#@" are
# metadata, everything else is copied verbatim into the drop-in:
#   #@ class: standard|docker|iptables     #@ check: shell command (exit 0 = functional PASS)
#   #@ exception: text (repeatable)        #@ target: max exposure (default: standard 5.0, docker/iptables
#   "<before" = lower than the exposure recorded before the first apply)
#
# Exit codes: 0 ok, 1 check failed / rolled back / target missed, 3 usage, 4 refused, 5 rollback failed.
# Env: PROFILE_DIR (dir of this script/profiles)  DROPIN_ROOT (/etc/systemd/system)  STATE_DIR (/var/lib/pft-unitguard)
#      SETTLE_SEC (10)  HOLD_UNITS ("")
#      Test hooks: PFT_UNITGUARD_TEST=1 (no root check)  PFT_UNITGUARD_SYSTEMCTL  PFT_UNITGUARD_ANALYZE  PFT_UNITGUARD_SLEEP
#                  PFT_UNITGUARD_OWNER_UID (expected owner in the permission check, default 0)

# "A && B || C" is intended where C only logs. jq/awk programs are single-quoted on purpose.
# shellcheck disable=SC2015,SC2016
set -uo pipefail
umask 022

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PROFILE_DIR="${PROFILE_DIR:-$HERE/profiles}"
DROPIN_ROOT="${DROPIN_ROOT:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-unitguard}"
SETTLE_SEC="${SETTLE_SEC:-10}"
HOLD_UNITS="${HOLD_UNITS:-}"
DROPIN_NAME="50-unitguard.conf"
SYSTEMCTL="${PFT_UNITGUARD_SYSTEMCTL:-systemctl}"
ANALYZE="${PFT_UNITGUARD_ANALYZE:-systemd-analyze}"
SLEEP="${PFT_UNITGUARD_SLEEP:-sleep}"
OWNER_UID="${PFT_UNITGUARD_OWNER_UID:-0}"

usage() { sed -n '6,35p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-unitguard: $1" >&2; exit "${2:-3}"; }
log() { echo "[$(date -u +%FT%TZ)] $*"; }
need_root() { [ -n "${PFT_UNITGUARD_TEST:-}" ] || [ "$(id -u)" = 0 ] || die "$1 needs root" 4; }

# --- profiles -------------------------------------------------------------------------------------------------
profile_file() { # UNIT -> profile path (instance foo@bar.service -> foo@.service.conf)
  local u="$1" t
  case "$u" in *.service) ;; *) u="$u.service" ;; esac
  t="$(sed -E 's/@[^.]+\.service$/@.service/' <<<"$u")"
  [ -f "$PROFILE_DIR/$t.conf" ] && echo "$PROFILE_DIR/$t.conf"
}
meta() { sed -n "s/^#@ $2: //p" "$1"; }                     # PROFILE KEY -> values (one per line)
directives() { grep -v '^#@' "$1"; }
class_of() { local c; c="$(meta "$1" class | head -1)"; echo "${c:-standard}"; }
target_of() { # PROFILE -> max exposure, or "<before" (must end below the score recorded before the first apply)
  local t; t="$(meta "$1" target | head -1)"
  [ -n "$t" ] && { echo "$t"; return; }
  [ "$(class_of "$1")" = standard ] && echo 5.0 || echo "<before"
}
before_file() { echo "$STATE_DIR/$(backup_key "$1").before"; }
meets() { # SCORE TARGET UNIT -> 0 when SCORE meets TARGET
  local b
  if [ "$2" = "<before" ]; then b="$(cat "$(before_file "$3")" 2>/dev/null)"; [ -n "$b" ] && lt "$1" "$b"
  else lt_eq "$1" "$2"; fi
}
dropin_unit() { sed -E 's/@[^.]+\.service$/@.service/' <<<"$1"; } # drop-ins for instances go on the template
dropin_path() { echo "$DROPIN_ROOT/$(dropin_unit "$1").d/$DROPIN_NAME"; }

all_profiled() { # profiled units present on this host; templates -> every existing instance
  local p base inst
  for p in "$PROFILE_DIR"/*.conf; do
    [ -f "$p" ] || continue
    base="$(basename "$p" .conf)"
    case "$base" in
      *@.service)
        inst="$("$SYSTEMCTL" list-units --all --plain --no-legend "${base%.service}*.service" 2>/dev/null \
                | awk '{print $1}' | grep -v '^●' || true)"
        [ -n "$inst" ] && echo "$inst" ;;
      *) "$SYSTEMCTL" cat "$base" >/dev/null 2>&1 && echo "$base" ;;
    esac
  done
}
held() { local u; for u in $HOLD_UNITS; do [ "$u" = "$1" ] || [ "$u.service" = "$1" ] && return 0; done; return 1; }

# --- systemd facts ----------------------------------------------------------------------------------------------
exposure() { # UNIT -> "SCORE RATING FAILED_CHECKS" from systemd-analyze security
  "$ANALYZE" security --no-pager "$1" 2>/dev/null | awk '
    /^✗/ {f++}
    /Overall exposure level/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+$/) {s=$i; r=$(i+1)} }
    END { if (s == "") print "? ? ?"; else printf "%s %s %d\n", s, r, f }'
}
missing() { # UNIT -> space-separated names of the failed (✗) systemd-analyze checks
  "$ANALYZE" security --no-pager "$1" 2>/dev/null | awk '/^✗/ {printf "%s%s", (n++ ? " " : ""), $2} END {print ""}'
}
prop() { "$SYSTEMCTL" show -p "$2" --value "$1" 2>/dev/null; }
unit_user() {
  local d u; d="$(prop "$1" DynamicUser)"; u="$(prop "$1" User)"
  [ "$d" = yes ] && echo "dynamic" || echo "${u:-root}"
}
exec_bin() { prop "$1" ExecStart | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1; }
perm_ok() { # PATH -> 0 when PATH (symlinks resolved) and its parent dir are root-owned and not group/world-
  [ -e "$1" ] || return 0 # writable (missing path = ok)
  local f s
  for f in "$(readlink -f "$1")" "$(dirname "$(readlink -f "$1")")"; do
    s="$(stat -c '%u %A' "$f")"
    [ "${s%% *}" = "$OWNER_UID" ] && [ "$(cut -c6 <<<"${s#* }")" != w ] && [ "$(cut -c9 <<<"${s#* }")" != w ] || return 1
  done
}
lt_eq() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a+0 <= b+0) }'; }
lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a+0 < b+0) }'; }

# --- audit ------------------------------------------------------------------------------------------------------
cmd_audit() {
  local units="" tsv="" detail="" u p sc rt fl usr dp cls tgt bin perms verdict bad=0
  while [ $# -gt 0 ]; do
    case "$1" in --units) units="$2"; shift 2 ;; --tsv) tsv=1; shift ;; --detail) detail=1; shift ;; *) die "audit: unknown arg $1" ;; esac
  done
  [ -n "$units" ] || units="$(all_profiled)"
  [ -n "$units" ] || die "audit: no profiled units on this host" 1
  [ -n "$tsv" ] || printf '%-40s %-6s %-8s %-6s %-9s %-8s %-6s %-5s %s\n' \
    UNIT EXPOS RATING FAILED USER CLASS TARGET DROPIN VERDICT
  for u in $units; do
    case "$u" in *.service) ;; *) u="$u.service" ;; esac
    p="$(profile_file "$u")"
    read -r sc rt fl <<<"$(exposure "$u")"
    usr="$(unit_user "$u")"
    dp="$(dropin_path "$u")"; [ -f "$dp" ] && dp=yes || dp=no
    if [ -n "$p" ]; then cls="$(class_of "$p")"; tgt="$(target_of "$p")"; else cls="-"; tgt="-"; fi
    bin="$(exec_bin "$u")"; perms=ok
    for x in "$bin" "$DROPIN_ROOT/$(dropin_unit "$u").d" "$(dropin_path "$u")"; do perm_ok "$x" || perms="BAD:$x"; done
    if [ "$sc" = "?" ]; then verdict="UNKNOWN"; bad=1
    elif [ "$perms" != ok ]; then verdict="PERMS $perms"; bad=1
    elif [ "$dp" = no ]; then verdict="not-applied"
    elif [ "$tgt" != - ] && meets "$sc" "$tgt" "$u"; then verdict="OK"
    else verdict="ABOVE-TARGET"; bad=1; fi
    if [ -n "$tsv" ]; then printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$u" "$sc" "$rt" "$fl" "$usr" "$cls" "$tgt" "$dp" "$verdict"
    else printf '%-40s %-6s %-8s %-6s %-9s %-8s %-6s %-5s %s\n' "$u" "$sc" "$rt" "$fl" "$usr" "$cls" "$tgt" "$dp" "$verdict"; fi
    [ -z "$detail" ] || missing "$u" | fold -s -w 116 | sed 's/^/    missing: /'
  done
  return "$bad"
}

# --- plan -------------------------------------------------------------------------------------------------------
cmd_plan() {
  local u="${1:-}" p
  [ -n "$u" ] || die "plan: UNIT required"
  case "$u" in *.service) ;; *) u="$u.service" ;; esac
  p="$(profile_file "$u")" || true
  [ -n "$p" ] || die "plan: no profile for $u" 3
  echo "unit:      $u"
  echo "profile:   $p"
  echo "drop-in:   $(dropin_path "$u")"
  echo "class:     $(class_of "$p")   target: <= $(target_of "$p")"
  echo "check:     $(meta "$p" check | head -1)"
  meta "$p" exception | sed 's/^/exception: /'
  echo "--- drop-in content"
  render "$p"
}
render() { printf '# written by pft-unitguard from %s - remove with: pft-unitguard rollback <unit>\n' "$(basename "$1")"; directives "$1"; }

# --- apply / rollback ------------------------------------------------------------------------------------------
run_unit() { # UNIT -> 0 when the unit ran / runs fine under the current config
  local u="$1" type before after res active
  type="$(prop "$u" Type)"
  if [ "$type" = oneshot ]; then
    # RemainAfterExit=yes keeps a finished oneshot "active", and `start` on an active unit runs nothing (a false PASS)
    local verb=start; [ "$(prop "$u" RemainAfterExit)" = yes ] && verb=restart
    "$SYSTEMCTL" "$verb" "$u" >/dev/null 2>&1
    res="$(prop "$u" Result)"
    log "  run $u (oneshot, $verb): Result=$res ExecMainStatus=$(prop "$u" ExecMainStatus)"
    [ "$res" = success ]
  else
    "$SYSTEMCTL" restart "$u" >/dev/null 2>&1
    before="$(prop "$u" NRestarts)"
    "$SLEEP" "$SETTLE_SEC"
    after="$(prop "$u" NRestarts)"; active="$("$SYSTEMCTL" is-active "$u" 2>/dev/null)"
    log "  run $u (long-running): active=$active NRestarts $before -> $after after ${SETTLE_SEC}s"
    [ "$active" = active ] && [ "$before" = "$after" ]
  fi
}
run_check() { # PROFILE -> exit of the functional check (no check = pass)
  local c; c="$(meta "$1" check | head -1)"
  [ -n "$c" ] || { log "  check: (none in profile)"; return 0; }
  log "  check: $c"
  bash -c "$c" 2>&1 | sed 's/^/    | /'
  local rc="${PIPESTATUS[0]}"
  log "  check exit $rc"
  return "$rc"
}
backup_key() { local k="$1"; echo "${k////%}"; }

remove_dropin() { # UNIT -> restore earlier copy or delete; 0 ok
  local u="$1" dp bk
  dp="$(dropin_path "$u")"; bk="$STATE_DIR/$(backup_key "$dp").orig"
  if [ -f "$bk" ]; then cp -p "$bk" "$dp" && rm -f "$bk" || return 1; log "  restored earlier $dp"
  elif [ -f "$dp" ]; then rm -f "$dp" || return 1; log "  removed $dp"
    rmdir "$(dirname "$dp")" 2>/dev/null || true
  else log "  no drop-in at $dp"; fi
  "$SYSTEMCTL" daemon-reload
}
undo_apply() { # UNIT PREV -> put back the drop-in that was there before this apply (an earlier unitguard one too), else remove_dropin
  local u="$1" prev="$2" dp; dp="$(dropin_path "$u")"
  [ -f "$prev" ] || { remove_dropin "$u"; return; }
  cp -p "$prev" "$dp" && rm -f "$prev" || return 1
  log "  restored previous $dp"
  "$SYSTEMCTL" daemon-reload
}

apply_one() {
  local u="$1" p dp dir bk prev
  p="$(profile_file "$u")"
  [ -n "$p" ] || { log "SKIP $u: no profile"; return 3; }
  held "$u" && { log "HOLD $u: in HOLD_UNITS, left unchanged"; return 0; }
  dp="$(dropin_path "$u")"; dir="$(dirname "$dp")"; bk="$STATE_DIR/$(backup_key "$dp").orig"
  log "APPLY $u class=$(class_of "$p") target<=$(target_of "$p") -> $dp"
  install -d -m 0700 -o root -g root "$STATE_DIR" 2>/dev/null || install -d -m 0700 "$STATE_DIR"
  [ -f "$(before_file "$u")" ] || [ -f "$dp" ] || exposure "$u" | awk '{print $1}' > "$(before_file "$u")"
  log "  exposure before: $(cat "$(before_file "$u")" 2>/dev/null)"
  [ -f "$dp" ] && [ ! -f "$bk" ] && ! grep -q '^# written by pft-unitguard' "$dp" && cp -p "$dp" "$bk"
  prev="$STATE_DIR/$(backup_key "$dp").prev"; rm -f "$prev"
  [ -f "$dp" ] && cp -p "$dp" "$prev"
  install -d -m 0755 "$dir"
  [ -n "${PFT_UNITGUARD_TEST:-}" ] || chown root:root "$dir"
  render "$p" > "$dp.tmp" && chmod 0644 "$dp.tmp" && mv -f "$dp.tmp" "$dp" || { log "FAIL $u: cannot write $dp"; return 1; }
  "$SYSTEMCTL" daemon-reload
  if run_unit "$u" && run_check "$p"; then
    local now; now="$(exposure "$u")"
    if meets "${now%% *}" "$(target_of "$p")" "$u"; then rm -f "$prev"; log "PASS $u exposure now: $now"; return 0; fi
    log "FAIL $u runs, but exposure $now misses target $(target_of "$p")"
  fi
  log "FAIL $u under the profile -> automatic rollback"
  if ! undo_apply "$u" "$prev"; then log "ROLLBACK-FAILED $u"; return 5; fi
  if run_unit "$u"; then log "ROLLED-BACK $u (runs again on the $([ -f "$(dropin_path "$u")" ] && echo "previous drop-in" || echo "unit without a drop-in")) exposure: $(exposure "$u")"
  else log "ROLLED-BACK $u but it still fails without the profile"; return 5; fi
  return 1
}

cmd_apply() {
  local target="${1:-}" skip="" u rc=0 r
  [ -n "$target" ] || die "apply: UNIT or --all required"
  shift
  while [ $# -gt 0 ]; do case "$1" in --skip) skip="$2"; shift 2 ;; *) die "apply: unknown arg $1" ;; esac; done
  need_root apply
  HOLD_UNITS="$HOLD_UNITS $skip"
  if [ "$target" = --all ]; then
    for u in $(all_profiled); do apply_one "$u"; r=$?; [ "$r" -gt "$rc" ] && rc="$r"; done
  else
    case "$target" in *.service) ;; *) target="$target.service" ;; esac
    apply_one "$target"; rc=$?
  fi
  return "$rc"
}

cmd_rollback() {
  local target="${1:-}" u rc=0
  [ -n "$target" ] || die "rollback: UNIT or --all required"
  need_root rollback
  if [ "$target" = --all ]; then
    for u in $(all_profiled); do log "ROLLBACK $u"; remove_dropin "$u" || rc=5; done
  else
    case "$target" in *.service) ;; *) target="$target.service" ;; esac
    log "ROLLBACK $target"; remove_dropin "$target" || rc=5
  fi
  return "$rc"
}

case "${1:-}" in
  audit) shift; cmd_audit "$@" ;;
  plan) shift; cmd_plan "$@" ;;
  apply) shift; cmd_apply "$@" ;;
  rollback) shift; cmd_rollback "$@" ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 3 ;;
esac
