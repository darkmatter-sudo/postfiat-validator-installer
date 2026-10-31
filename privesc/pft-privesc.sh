#!/usr/bin/env bash
# pft-privesc: audit local privilege-escalation paths on a Post Fiat validator/sentry host (Ubuntu 22.04) and,
# opt-in, fix the safe ones reversibly.
#
# Usage: sudo pft-privesc audit [--json] [--show-names] [--textfile-dir DIR]   read-only; one line per check + RESULT
#        sudo pft-privesc apply [--dry-run] [--only ID,ID]                    fix what apply may fix (below)
#        sudo pft-privesc undo                                               restore every applied change
#        pft-privesc status | ids | version
#        sudo pft-privesc pull                                               validator: copy the peer's textfile
#        pft-privesc validate FILE HOST                                      exit 0 if FILE is an acceptable textfile
#
#  audit  collects facts (find -xdev for SUID/SGID files, dpkg -S / --verify / statoverride, getcap, systemctl show
#         of every loaded unit, getent passwd/group, bind mounts of running containers, visudo -c) into a temp dir,
#         then privesc_classify.py grades five areas: suid (SUID/SGID + file capabilities against dpkg), sudoers,
#         exec (root units + cron: every file they run and every parent dir), path (root PATH entries + files) and
#         rooteq (docker/lxd/disk membership, runtime sockets, container mounts). Directories that no non-root user
#         can traverse (root-owned, no o+x, group root or no g+x; e.g. /var/lib/containerd) are not searched:
#         nothing under them is reachable without root. Account names are hashed (acct-<8 hex>) unless
#         --show-names, so the output can be shared. IDs: `pft-privesc ids` or README.md.
#         Exit 0 clean; 1 WARN or FAIL findings; 2 collection error. Writes TEXTFILE_DIR/pft_privesc_HOST.prom
#         atomically on every run (also failed ones: up 0).
#  apply  only these change types, each on exactly the file a finding names: chmod (drop group/other write; o-rwx
#         on a runtime socket), chown root (dpkg-owned SUID file, sudoers file), and SUID/SGID removal for paths in
#         the unneeded list (dpkg-statoverride --update, so upgrades keep it) or in REMOVE_SUID (no dpkg owner:
#         plain chmod), and setcap -r for paths in the built-in unneeded-capabilities list. Never: file contents, group membership, sudo rules, PROTECTED binaries (sudo, su, passwd,
#         unix_chkpwd). Before: refuse unless visudo -c passes and AGENT_USER can `sudo -n true`. Each change is
#         recorded first in STATE/backup/manifest.tsv (old mode, uid, gid, statoverride, sha256). After every
#         sudoers change and at the end: visudo -c + the agent sudo check; if either fails, everything this run
#         changed is undone at once (exit 3). Then a re-audit. Exit 0 applied (or nothing to do), 2 refused.
#  undo   walks the manifest backwards: removes the statoverrides it added (re-adds any it replaced), restores
#         uid:gid then mode, and requires stat == recorded and sha256 unchanged for every entry, visudo -c OK and the
#         agent sudo check OK. The manifest then moves to STATE/last-undo. Exit 0 OK, 2 nothing to undo / failed.
#
# Config: /etc/pft-privesc.env (KEY=VALUE, root-owned; PFT_PE_CONF overrides): HOST_LABEL (validator), PEER_LABEL
#   (sentry), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), REMOTE_DIR (same), AGENT_USER (account whose sudo
#   apply/undo must keep; required for apply), UNNEEDED_SUID / REMOVE_SUID / CAP_ALLOW (colon lists, empty =
#   built-in), PULL_SSH, PULL_TIMEOUT (30).
# Test hooks: PFT_PE_ROOT (fake / prefix), PFT_PE_ROOT_UID (uid treated as root), PFT_PE_LIB (dir with
#   privesc_classify.py), PFT_PE_NOW, commands PFT_PE_DPKG PFT_PE_STATOVERRIDE PFT_PE_GETCAP PFT_PE_SETCAP PFT_PE_SYSTEMCTL
#   PFT_PE_GETENT PFT_PE_DOCKER PFT_PE_VISUDO PFT_PE_RUNUSER.
set -uo pipefail
umask 022
VERSION=1.0.0

HOST_LABEL=validator; PEER_LABEL=sentry; TEXTFILE_DIR=/var/lib/pft-exporter/textfile
REMOTE_DIR=/var/lib/pft-exporter/textfile; AGENT_USER=""; UNNEEDED_SUID=""; REMOVE_SUID=""; CAP_ALLOW=""
PULL_SSH=""; PULL_TIMEOUT=30
MAX_BYTES=16384
CONF="${PFT_PE_CONF:-/etc/pft-privesc.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|TEXTFILE_DIR|REMOTE_DIR|AGENT_USER|UNNEEDED_SUID|REMOVE_SUID|CAP_ALLOW|PULL_SSH|PULL_TIMEOUT)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
      *) printf 'pft-privesc: unknown key %s in %s\n' "$k" "$CONF" >&2; exit 2 ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi
ROOT="${PFT_PE_ROOT:-}"
LIBDIR="${PFT_PE_LIB:-/usr/local/lib/pft-privesc}"
CLASSIFY="$LIBDIR/privesc_classify.py"
DPKG="${PFT_PE_DPKG:-dpkg}"
STATOVERRIDE="${PFT_PE_STATOVERRIDE:-dpkg-statoverride}"
GETCAP="${PFT_PE_GETCAP:-getcap}"
SETCAP="${PFT_PE_SETCAP:-setcap}"
SYSTEMCTL="${PFT_PE_SYSTEMCTL:-systemctl}"
GETENT="${PFT_PE_GETENT:-getent}"
DOCKER="${PFT_PE_DOCKER:-docker}"
VISUDO="${PFT_PE_VISUDO:-visudo}"
RUNUSER="${PFT_PE_RUNUSER:-runuser}"
STATE="$ROOT/var/lib/pft-privesc"
BACKUP="$STATE/backup"
PROTECTED=" /usr/bin/sudo /usr/bin/su /usr/sbin/unix_chkpwd /usr/bin/passwd "

die() { printf 'pft-privesc: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_PE_NOW:-}" ]; then echo "$PFT_PE_NOW"; else date -u +%s; fi; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
log() { printf '%s %s\n' "$(ts)" "$*"; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
valid_label "$HOST_LABEL" || die "bad HOST_LABEL"
P() { printf '%s%s' "$ROOT" "$1"; }   # host path -> path under the test root
sha() { if [ -f "$1" ]; then sha256sum < "$1" | cut -c1-64; else echo -; fi; }

# dpkg owner of PATH (usrmerge: dpkg may know it as /bin/x, /sbin/x or /lib/x) -> "PKG<TAB>PKGPATH" or "-<TAB>-"
dpkg_owner() {
  local p="$1" alt="" out
  case "$p" in /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt="/${p#/usr/}" ;; esac
  for c in "$p" $alt; do
    if out="$("$DPKG" -S "$c" 2>/dev/null)" && [ -n "$out" ]; then
      out="$(printf '%s\n' "$out" | grep -F ": $c" | head -1)"
      [ -n "$out" ] && { printf '%s\t%s\n' "${out%%: *}" "$c" | sed 's/, /,/g'; return 0; }
    fi
  done
  printf -- '-\t-\n'
}

# find_reach ARGS... : find -xdev over / without descending into dirs no non-root user can traverse
find_reach() {
  find "$(P /)" -xdev \( -path "$(P /proc)" -o -path "$(P /sys)" -o \
    \( -type d -user root ! -perm -0001 \( -group root -o ! -perm -0010 \) \) \) -prune -o "$@" 2>/dev/null
}

collect() { # collect DIR : facts for privesc_classify.py (see its docstring); errors -> DIR/errors.tsv
  local d="$1" p m u g pkg out rest cn
  : > "$d/errors.tsv"
  find_reach -type f -perm /6000 -printf '%p\t%m\t%U\t%G\n' > "$d/suid.raw"
  : > "$d/suid.tsv"
  while IFS=$'\t' read -r p m u g; do
    p="${p#"$ROOT"}"
    printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$m" "$u" "$g" "$(dpkg_owner "$p")" >> "$d/suid.tsv"
  done < "$d/suid.raw"
  : > "$d/md5.tsv"
  for pkg in $(cut -f5 "$d/suid.tsv" | tr ',' '\n' | grep -v '^-$' | sort -u); do
    "$DPKG" --verify "$pkg" 2>/dev/null | awk '$1 ~ /^..5/ {print $NF}' >> "$d/md5.tsv"
  done
  if ! "$STATOVERRIDE" --list > "$d/override.raw" 2>/dev/null; then
    printf 'dpkg-statoverride --list failed\n' >> "$d/errors.tsv"
  fi
  awk 'NF==4 {print $1"\t"$2"\t"$3"\t"$4}' "$d/override.raw" > "$d/override.tsv"
  : > "$d/caps.tsv"
  find_reach -type f -perm /111 -print0 | xargs -0 -r "$GETCAP" 2>/dev/null > "$d/caps.raw"
  while read -r p rest; do
    [ -n "$p" ] || continue
    p="${p#"$ROOT"}"
    printf '%s\t%s\t%s\n' "$p" "${rest// /}" "$(dpkg_owner "$p" | cut -f1)" >> "$d/caps.tsv"
  done < "$d/caps.raw"
  if ! "$SYSTEMCTL" show --all -p Id,User,FragmentPath,DropInPaths,ExecCondition,ExecStartPre,ExecStart,\
ExecStartPost,ExecReload,ExecStop,ExecStopPost '*' > "$d/units.show" 2>/dev/null; then
    printf 'systemctl show failed\n' >> "$d/errors.tsv"
  fi
  "$GETENT" passwd | awk -F: '{print $1"\t"$3"\t"$4"\t"($7==""?"-":$7)}' > "$d/passwd.tsv" || printf 'getent passwd failed\n' >> "$d/errors.tsv"
  "$GETENT" group | awk -F: '{print $1"\t"$3"\t"($4==""?"-":$4)}' > "$d/group.tsv" || printf 'getent group failed\n' >> "$d/errors.tsv"
  : > "$d/mounts.tsv"
  if command -v "$DOCKER" >/dev/null 2>&1; then
    if out="$("$DOCKER" ps -q 2>/dev/null)"; then
      for cn in $out; do
        "$DOCKER" inspect --format '{{.Name}}{{range .Mounts}}{{if eq .Type "bind"}} {{.Source}}{{end}}{{end}}' "$cn" \
          2>/dev/null | awk '{n=substr($1,2); for (i=2;i<=NF;i++) print n"\t"$i}' >> "$d/mounts.tsv"
      done
    else
      printf 'docker ps failed\n' >> "$d/errors.tsv"
    fi
  fi
  out="$("$VISUDO" -c 2>&1)"; printf 'rc=%s\n%s\n' "$?" "$out" > "$d/visudo.txt"
}

classify() { # classify FACTS_DIR extra-args...
  local d="$1"; shift
  local args=(grade --facts "$d" --host "$HOST_LABEL" --now "$(now)")
  [ -n "$ROOT" ] && args+=(--root "$ROOT")
  [ -n "${PFT_PE_ROOT_UID:-}" ] && args+=(--root-uid "$PFT_PE_ROOT_UID")
  [ -n "$UNNEEDED_SUID" ] && args+=(--unneeded-suid "$UNNEEDED_SUID")
  [ -n "$REMOVE_SUID" ] && args+=(--remove-suid "$REMOVE_SUID")
  [ -n "$CAP_ALLOW" ] && args+=(--cap-allow "$CAP_ALLOW")
  python3 "$CLASSIFY" "${args[@]}" "$@"
}

# audit [--json] [--show-names] [--textfile-dir DIR] [--actions FILE] -> classifier exit code
audit() {
  local json=false names=false tdir="$TEXTFILE_DIR" actions="" t rc
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=true ;; --show-names) names=true ;;
      --textfile-dir) tdir="${2:?}"; shift ;;
      --actions) actions="${2:?}"; shift ;;
      *) die "unknown audit option $1" ;;
    esac
    shift
  done
  t="$(mktemp -d)"
  collect "$t"
  local extra=(--metrics "$t/metrics")
  $json && extra+=(--json)
  $names && extra+=(--show-names)
  [ -n "$actions" ] && extra+=(--actions "$actions")
  $json || echo "pft-privesc audit - $(ts) host=$HOST_LABEL"
  classify "$t" "${extra[@]}"; rc=$?
  if [ -s "$t/metrics" ] && [ -d "$tdir" ]; then
    {
      cat "$t/metrics"
      echo "# HELP pft_privesc_backup_entries Changes recorded by pft-privesc apply and not yet undone."
      echo "# TYPE pft_privesc_backup_entries gauge"
      echo "pft_privesc_backup_entries{host=\"$HOST_LABEL\"} $([ -f "$BACKUP/manifest.tsv" ] && wc -l < "$BACKUP/manifest.tsv" || echo 0)"
    } > "$tdir/.pft_privesc_$HOST_LABEL.prom.tmp" && mv -f "$tdir/.pft_privesc_$HOST_LABEL.prom.tmp" "$tdir/pft_privesc_$HOST_LABEL.prom"
  fi
  rm -rf "$t"
  return "$rc"
}

agent_sudo_ok() { # rc 0 if AGENT_USER can run `sudo -n true` (a non-interactive full-root check)
  [ -n "$AGENT_USER" ] || return 1
  "$RUNUSER" -u "$AGENT_USER" -- sudo -n true < /dev/null > /dev/null 2>&1
}
visudo_ok() { "$VISUDO" -c > /dev/null 2>&1; }

# current "MODE UID GID" of a path (no symlink follow for the stat itself: callers pass the element a finding named)
st() { stat -c '%a %u %g' "$(P "$1")"; }
caps_of() { "$GETCAP" "$(P "$1")" 2>/dev/null | awk '{$1=""; gsub(/ /,""); print}'; }
override_of() { # dpkg-statoverride entry for PATH -> "USER GROUP MODE" or "-"
  local o; o="$("$STATOVERRIDE" --list "$1" 2>/dev/null | awk 'NF==4 {print $1" "$2" "$3}')"
  printf '%s\n' "${o:--}"
}

# restore_entry LINE : put one manifest entry back, rc 1 + message on mismatch
restore_entry() {
  local id type path mode uid gid ov pkgpath sum now_st
  IFS=$'\t' read -r _ _ id type path mode uid gid ov pkgpath sum _ <<< "$1"
  if [ "$type" = suid-remove ] && [ "$pkgpath" != - ]; then
    "$STATOVERRIDE" --remove "$pkgpath" > /dev/null 2>&1
    if [ "$ov" != - ]; then
      # shellcheck disable=SC2086 # ov is "USER GROUP MODE" from the manifest
      "$STATOVERRIDE" --add $ov "$pkgpath" > /dev/null 2>&1 || { echo "re-adding the old statoverride of $path failed"; return 1; }
    fi
  fi
  if [ "$type" = cap-remove ]; then
    "$SETCAP" "${ov#caps=}" "$(P "$path")" || { echo "setcap on $path failed"; return 1; }
    [ "$(caps_of "$path")" = "${ov#caps=}" ] || { echo "$path capabilities are '$(caps_of "$path")', recorded '${ov#caps=}'"; return 1; }
  elif ! { chown "$uid:$gid" "$(P "$path")" && chmod "$mode" "$(P "$path")"; }; then
    echo "chown/chmod $path failed"; return 1
  fi
  now_st="$(st "$path")"
  [ "$now_st" = "$mode $uid $gid" ] || { echo "$path is '$now_st', recorded '$mode $uid $gid'"; return 1; }
  [ "$(sha "$(P "$path")")" = "$sum" ] || { echo "$path content changed since apply (sha256)"; return 1; }
  return 0
}

# undo_lines FILE : restore entries of FILE in reverse order; rc = number of failures
undo_lines() {
  local f="$1" line why n=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if why="$(restore_entry "$line")"; then
      log "restored  $(printf '%s' "$line" | cut -f4,5,6 | tr '\t' ' ')"
    else
      log "UNDO ERROR $why"; n=$((n + 1))
    fi
  done < <(tac "$f")
  return "$n"
}

apply() {
  local dry=false only="" t id type arg path pkgpath real seq cur ov sum line why n=0 skipped=0 sudoers_touched=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=true ;;
      --only) only=",${2:?},"; shift ;;
      *) die "unknown apply option $1" ;;
    esac
    shift
  done
  visudo_ok || die "visudo -c fails before apply: fix sudoers first (nothing changed)"
  agent_sudo_ok || die "AGENT_USER ('$AGENT_USER') cannot sudo -n true before apply: refusing (set AGENT_USER in $CONF)"
  t="$(mktemp -d)"
  audit --actions "$t/actions" --textfile-dir "$t" > "$t/before.txt"
  [ "$?" -eq 2 ] && { cat "$t/before.txt"; rm -rf "$t"; die "audit error before apply: nothing changed"; }
  grep -E '^(FAIL|WARN) ' "$t/before.txt" | sed 's/^/  before: /'
  : > "$t/plan"
  while IFS=$'\t' read -r id type arg path pkgpath; do
    [ -n "$id" ] || continue
    if [ -n "$only" ] && [[ "$only" != *",$id,"* ]]; then continue; fi
    # by resolved path too: with usrmerge /bin/sudo is /usr/bin/sudo
    real="$(realpath -m "$(P "$path")")"; real="${real#"$ROOT"}"
    if [[ "$PROTECTED" == *" $path "* || "$PROTECTED" == *" $real "* ]]; then
      log "skip (protected) $id $path"; skipped=$((skipped + 1)); continue
    fi
    case "$type" in chmod|chown|suid-remove|sudoers-fix|cap-remove) ;; *) log "skip (unknown type) $type $path"; continue ;; esac
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$type" "$arg" "$path" "${pkgpath:--}" >> "$t/plan"
  done < "$t/actions"
  if [ ! -s "$t/plan" ]; then log "nothing to apply ($skipped protected skipped)"; rm -rf "$t"; return 0; fi
  log "plan: $(wc -l < "$t/plan") change(s)"
  while IFS=$'\t' read -r id type arg path pkgpath; do log "  $id $type $arg $path"; done < "$t/plan"
  if $dry; then log "dry run: nothing changed"; rm -rf "$t"; return 0; fi
  mkdir -p "$BACKUP"; chmod 700 "$STATE" "$BACKUP"
  touch "$BACKUP/manifest.tsv"; chmod 600 "$BACKUP/manifest.tsv"
  seq="$(wc -l < "$BACKUP/manifest.tsv")"
  : > "$t/run.tsv"
  while IFS=$'\t' read -r id type arg path pkgpath; do
    seq=$((seq + 1))
    cur="$(st "$path")" || { log "ERROR cannot stat $path"; n=$((n + 1)); break; }
    ov=-; [ "$type" = suid-remove ] && [ "$pkgpath" != - ] && ov="$(override_of "$pkgpath")"
    [ "$type" = cap-remove ] && ov="caps=$arg"
    sum="$(sha "$(P "$path")")"
    read -r m u g <<< "$cur"
    line="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$seq" "$(ts)" "$id" "$type" "$path" "$m" "$u" "$g" \
      "$ov" "$pkgpath" "$sum" "$arg")"
    printf '%s\n' "$line" >> "$BACKUP/manifest.tsv"; printf '%s\n' "$line" >> "$t/run.tsv"   # record first
    case "$type" in
      chmod) chmod "$arg" "$(P "$path")" ;;
      chown) chown "$arg" "$(P "$path")" && chmod "$m" "$(P "$path")" ;;   # chown clears SUID: put the mode back
      sudoers-fix) chown 0:0 "$(P "$path")" && chmod 0440 "$(P "$path")"; sudoers_touched=true ;;
      suid-remove)
        if [ "$pkgpath" != - ]; then
          [ "$ov" != - ] && "$STATOVERRIDE" --remove "$pkgpath" > /dev/null 2>&1
          "$STATOVERRIDE" --update --add "$(stat -c %U "$(P "$path")")" "$(stat -c %G "$(P "$path")")" "$arg" "$pkgpath" > /dev/null
        else
          chmod "$arg" "$(P "$path")"
        fi ;;
      cap-remove) "$SETCAP" -r "$(P "$path")" ;;
    esac || { log "ERROR $type $path failed"; n=$((n + 1)); break; }
    log "applied   $id $type $arg $path (was $m $u $g)"
    if $sudoers_touched && ! { visudo_ok && agent_sudo_ok; }; then
      log "ERROR visudo -c or the agent sudo check failed after a sudoers change"; n=$((n + 1)); break
    fi
  done < "$t/plan"
  if [ "$n" -eq 0 ] && ! { visudo_ok && agent_sudo_ok; }; then log "ERROR final visudo -c / agent sudo check failed"; n=1; fi
  if [ "$n" -ne 0 ]; then
    log "rolling back the $(wc -l < "$t/run.tsv") change(s) of this run"
    undo_lines "$t/run.tsv"
    grep -vxF -f "$t/run.tsv" "$BACKUP/manifest.tsv" > "$BACKUP/manifest.tsv.new"; mv -f "$BACKUP/manifest.tsv.new" "$BACKUP/manifest.tsv"
    rm -rf "$t"; exit 3
  fi
  log "visudo -c OK, agent sudo -n true OK"
  rm -rf "$t"
  log "re-audit:"
  audit > "$STATE/apply-audit.txt"
  grep -E '^(FAIL|WARN) |^RESULT' "$STATE/apply-audit.txt" | sed 's/^/  after: /'
  log "APPLIED: $(wc -l < "$BACKUP/manifest.tsv") change(s) recorded in the backup manifest (undo: sudo pft-privesc undo)"
  return 0
}

undo() {
  local f="$BACKUP/manifest.tsv" n
  [ -s "$f" ] || die "nothing to undo (no backup manifest)"
  log "undo: $(wc -l < "$f") recorded change(s), newest first"
  undo_lines "$f"; n=$?
  visudo_ok || { log "UNDO ERROR visudo -c fails after undo"; n=$((n + 1)); }
  agent_sudo_ok || { log "UNDO ERROR agent sudo -n true fails after undo"; n=$((n + 1)); }
  [ "$n" -eq 0 ] || die "UNDO FAILED: $n problem(s); the manifest is kept in $f"
  rm -rf "$STATE/last-undo"; mkdir -p "$STATE/last-undo"; mv "$f" "$STATE/last-undo/manifest.tsv"
  audit > /dev/null
  log "UNDO OK: every entry stat-identical to the record, contents unchanged, visudo -c OK, agent sudo OK"
  return 0
}

status() {
  if [ -s "$BACKUP/manifest.tsv" ]; then
    echo "applied changes: $(wc -l < "$BACKUP/manifest.tsv")"; cut -f3,4,5,12 "$BACKUP/manifest.tsv" | sed 's/^/  /'
  else
    echo "applied changes: 0"
  fi
  [ -f "$STATE/last-undo/manifest.tsv" ] && echo "last undo: $(wc -l < "$STATE/last-undo/manifest.tsv") change(s) restored"
  return 0
}

validate() { # validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le "$MAX_BYTES" ] || { echo "larger than $MAX_BYTES bytes"; return 1; }
  n="$(grep -cvE '^(#.*|pft_privesc_[a-z_]+\{host="'"$h"'"(,[a-z_]+="[a-z0-9_-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^pft_privesc_up\{host="'"$h"'"\} [01]$' "$f" || { echo "no up sample"; return 1; }
  return 0
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$TEXTFILE_DIR/.pft_privesc_$PEER_LABEL.prom.pull"
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_privesc_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi
  mv -f "$tmp" "$TEXTFILE_DIR/pft_privesc_$PEER_LABEL.prom"
}

need_root() { [ "$(id -u)" -eq 0 ] || [ -n "$ROOT" ] || die "$1 needs root"; }
cmd="${1:-}"; shift || true
case "$cmd" in
  audit) need_root audit; audit "$@" ;;
  apply) need_root apply; apply "$@" ;;
  undo) need_root undo; undo ;;
  status) status ;;
  pull) need_root pull; pull ;;
  validate) [ $# -eq 2 ] || die "usage: pft-privesc validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  ids) python3 "$CLASSIFY" ids ;;
  version) echo "pft-privesc $VERSION" ;;
  *) die "usage: pft-privesc audit|apply|undo|status|pull|validate|ids|version (see the header)" ;;
esac
