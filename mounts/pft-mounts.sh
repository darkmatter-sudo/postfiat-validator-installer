#!/usr/bin/env bash
# pft-mounts: audit and harden HOST filesystem mount options on a Post Fiat validator or sentry host (Ubuntu 22.04,
# postfiatd in Docker). confine/ hardens the container and sysctl/ the kernel; this covers the host mounts that
# CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0 section 1.1.2 grades (/tmp, /dev/shm, /var/tmp), plus /proc
# hidepid and nodev/nosuid on postfiatd's ledger data directory as the container sees it.
#
# Usage: pft-mounts audit [--json] [--prom FILE]
#        pft-mounts plan                      (read-only: the fstab block and live remounts apply would do)
#        sudo pft-mounts apply --yes [--dry-run]
#        sudo pft-mounts rollback --yes       (restore the newest fstab backup, undo the live mounts)
#
#  audit   read-only. One line per check: PASS / FAIL (live option missing) / WARN (live OK but not persistent:
#          lost at the next boot; or a duplicate fstab target) / INFO. Persistence is read from /etc/fstab, or for
#          /tmp from an enabled /etc/systemd/system/tmp.mount (that unit file overrides an fstab line).
#  apply   1. writes a marked block (# BEGIN pft-mounts ... # END pft-mounts) to a candidate fstab, keeping every
#             other line byte-for-byte, and refuses (exit 4) unless `findmnt --verify --tab-file` accepts it.
#          2. backs the old fstab up, installs the candidate, `systemctl daemon-reload`.
#          3. live, no reboot, no container restart:
#               /tmp, /var/tmp   self-bind (mount --bind X X) unless already a mount, then
#                                mount -o remount,bind,nodev,nosuid,noexec X  (contents stay, disk-backed)
#               /dev/shm         mount -o remount,nodev,nosuid,noexec /dev/shm
#               /proc            mount -o remount,hidepid=invisible,gid=PROC_GROUP /proc  (group created if absent)
#               data dir         host: self-bind of the volume's _data dir with nodev,nosuid (future container
#                                starts inherit it); container: the same remount inside postfiatd's mount
#                                namespace (nsenter -m), so the running node gets it now.
#          4. health gate: postfiatd StartedAt unchanged, server_state full, :PEER_PORT listening, sshd config
#             valid + :22 listening + a new SSH handshake, every GATE_UNITS oneshot re-run with Result=success and
#             every long-running pft unit still active. A miss -> automatic rollback (exit 1; 5 if that fails).
#  rollback  restores the newest backup byte-identical (sha256 compared), reverts every live option apply set
#          (records in BACKUP_DIR/live.state which mounts it created and which it only remounted).
#
# Exit codes: 0 PASS / applied, 1 findings / rolled back, 2 error, 3 usage, 4 refused (not root, no --yes,
#             candidate fstab invalid), 5 rollback failed.
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  DATA_DEST (/var/lib/postfiatd/db)  PEER_PORT (2559)
#      PROC_GROUP (pft-procview)  HEALTH_BUDGET (300)  POLL_SEC (5)  BACKUP_DIR (/var/lib/pft-mounts)
#      GATE_UNITS (space-separated oneshot services re-run by the gate; default: the pft-*.service units with an
#      active timer whose name matches GATE_PATTERN)  GATE_PATTERN (heartbeat|statewatch|resources|rulecheck|authwatch)
#      Test hooks: PFT_MOUNTS_ROOT (path prefix for every file)  PFT_MOUNTS_DOCKER / _MOUNT / _NSENTER / _FINDMNT /
#      _SYSTEMCTL / _SS / _SSHD / _KEYSCAN / _GROUPADD / _GETENT / _RPC (commands)  PFT_MOUNTS_INJECT (health)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_MOUNTS_ROOT:-}"
DOCKER="${PFT_MOUNTS_DOCKER:-docker}"
MOUNT="${PFT_MOUNTS_MOUNT:-mount}"
UMOUNT="${PFT_MOUNTS_UMOUNT:-umount}"
NSENTER="${PFT_MOUNTS_NSENTER:-nsenter}"
FINDMNT="${PFT_MOUNTS_FINDMNT:-findmnt}"
SYSTEMCTL="${PFT_MOUNTS_SYSTEMCTL:-systemctl}"
SS="${PFT_MOUNTS_SS:-ss}"
SSHD="${PFT_MOUNTS_SSHD:-sshd}"
KEYSCAN="${PFT_MOUNTS_KEYSCAN:-ssh-keyscan}"
GROUPADD="${PFT_MOUNTS_GROUPADD:-groupadd}"
GETENT="${PFT_MOUNTS_GETENT:-getent}"
INJECT="${PFT_MOUNTS_INJECT:-}"
DATA_DEST="${DATA_DEST:-/var/lib/postfiatd/db}"
PEER_PORT="${PEER_PORT:-2559}"
PROC_GROUP="${PROC_GROUP:-pft-procview}"
HEALTH_BUDGET="${HEALTH_BUDGET:-300}"
POLL_SEC="${POLL_SEC:-5}"
GATE_PATTERN="${GATE_PATTERN:-heartbeat|statewatch|resources|rulecheck|authwatch}"
FSTAB="$R/etc/fstab"
BACKUP_DIR="${BACKUP_DIR:-$R/var/lib/pft-mounts}"
MOUNTINFO="$R/proc/self/mountinfo"
TMPUNIT="$R/etc/systemd/system/tmp.mount"
TMPWANT="$R/etc/systemd/system/local-fs.target.wants/tmp.mount"
BEGIN_MARK="# BEGIN pft-mounts (managed; edit with pft-mounts, see mounts/README.md)"
END_MARK="# END pft-mounts"

# target  CIS-prefix  options  (the /tmp-like targets; each gets a separate-mount check and one check per option)
TARGETS="/tmp 1.1.2.1 nodev,nosuid,noexec
/dev/shm 1.1.2.2 nodev,nosuid,noexec
/var/tmp 1.1.2.5 nodev,nosuid,noexec"
DATA_OPTS="nodev,nosuid"

die() { echo "pft-mounts: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
RESULTS=""
FINDINGS=0
res() { # STATUS CIS ID MESSAGE
  RESULTS+="$1"$'\t'"$2"$'\t'"$3"$'\t'"$4"$'\n'
  case "$1" in FAIL|WARN) FINDINGS=$((FINDINGS + 1)) ;; esac
  return 0
}

detect_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}

# mountinfo FILE -> "target<TAB>mount-opts<TAB>fstype<TAB>source<TAB>super-opts", octal escapes decoded.
# Later lines are mounted on top of earlier ones, so callers take the LAST line for a target.
mi_parse() {
  awk '{
    sep = 0; for (i = 7; i <= NF; i++) if ($i == "-") { sep = i; break }
    if (!sep) next
    t = $5; gsub(/\\040/, " ", t); gsub(/\\011/, "\t", t); gsub(/\\134/, "\\", t)
    printf "%s\t%s\t%s\t%s\t%s\n", t, $6, $(sep + 1), $(sep + 2), $(sep + 3)
  }' "$1"
}
mi_top() { awk -F'\t' -v t="$2" '$1 == t { l = $0 } END { if (l != "") print l }' <<<"$1"; } # MI TARGET
mi_covering() { # MI PATH -> the top line of the deepest mount that contains PATH
  awk -F'\t' -v p="$2" '{
    t = $1; if (t == "/" || p == t || index(p, t "/") == 1) { if (length(t) >= best) { best = length(t); l = $0 } }
  } END { if (l != "") print l }' <<<"$1"
}
has_opt() { # "a,b,c" OPT
  local o
  IFS=, read -ra o <<<"$1"
  local x; for x in "${o[@]}"; do [ "$x" = "$2" ] && return 0; done
  return 1
}
hidepid_on() { # super-opts -> 0 if hidepid is invisible/2 or noaccess/1 (ptraceable is not hiding)
  grep -qE '(^|,)hidepid=(invisible|2|noaccess|1)(,|$)' <<<"$1"
}

# fstab FILE -> "spec<TAB>target<TAB>type<TAB>opts<TAB>line-number" for each entry (comments/blank lines skipped,
# \040 decoded). Duplicate targets are all printed; mount -a stacks them so the last one wins.
fs_parse() {
  [ -f "$1" ] || return 0
  awk '/^[ \t]*(#|$)/ { next } NF >= 2 {
    t = $2; gsub(/\\040/, " ", t); s = $1; gsub(/\\040/, " ", s)
    printf "%s\t%s\t%s\t%s\t%d\n", s, t, (NF >= 3 ? $3 : "auto"), (NF >= 4 ? $4 : "defaults"), NR
  }' "$1"
}
fs_last() { awk -F'\t' -v t="$2" '$2 == t { l = $0 } END { if (l != "") print l }' <<<"$1"; }
fs_count() { awk -F'\t' -v t="$2" '$2 == t { n++ } END { print n + 0 }' <<<"$1"; }

# persistent options for TARGET -> "source-label<TAB>opts", or nothing
persist_opts() {
  local t="$1" fs="$2" e o
  if [ "$t" = /tmp ] && [ -f "$TMPUNIT" ] && [ -e "$TMPWANT" ]; then
    o="$(awk -F= '/^[ \t]*Options[ \t]*=/ { sub(/^[^=]*=[ \t]*/, ""); print }' "$TMPUNIT" | tail -1)"
    printf 'tmp.mount\t%s\n' "${o:-defaults}"; return
  fi
  e="$(fs_last "$fs" "$t")"
  [ -n "$e" ] && printf 'fstab:%s\t%s\n' "$(cut -f5 <<<"$e")" "$(cut -f4 <<<"$e")"
  return 0
}

data_source() { # CONTAINER -> host path of the volume/bind mounted at DATA_DEST
  "$DOCKER" inspect -f "{{range .Mounts}}{{if eq .Destination \"$DATA_DEST\"}}{{.Source}}{{end}}{{end}}" "$1" 2>/dev/null
}
container_pid() { "$DOCKER" inspect -f '{{.State.Pid}}' "$1" 2>/dev/null; }
label_path() { # never print a host-specific path: docker volumes as <docker-volume:NAME>
  sed -E 's#^/var/lib/docker/volumes/([^/]+)/_data$#<docker-volume:\1>#' <<<"$1"
}

audit_checks() {
  local mi fs t cis opts top p o n line pid cmi src cov live c
  mi="$(mi_parse "$MOUNTINFO")" || die "cannot read $MOUNTINFO"
  [ -n "$mi" ] || die "no mounts parsed from $MOUNTINFO"
  fs="$(fs_parse "$FSTAB")"
  while read -r t n; do
    [ "$n" -gt 1 ] && res WARN n/a "fstab-dup:$t" "$n fstab entries for $t (mount -a stacks them; the last one wins)"
  done < <(cut -f2 <<<"$fs" | sort | uniq -c | awk '$1 > 1 { print $2, $1 }')
  while read -r t cis opts; do
    top="$(mi_top "$mi" "$t")"
    p="$(persist_opts "$t" "$fs")"
    if [ -z "$top" ]; then
      res FAIL "$cis.1" "$t:separate" "not a separate mount (on $(cut -f1 <<<"$(mi_covering "$mi" "$t")"))"
      live=""
    else
      live="$(cut -f2 <<<"$top")"
      if [ -n "$p" ]; then res PASS "$cis.1" "$t:separate" "$(cut -f3 <<<"$top") mount, persistent via $(cut -f1 <<<"$p")"
      elif [ "$t" = /dev/shm ]; then res PASS "$cis.1" "$t:separate" "tmpfs mounted by systemd at boot"
      else res WARN "$cis.1" "$t:separate" "mounted now but no fstab/tmp.mount entry: gone after the next boot"; fi
    fi
    c=2
    IFS=, read -ra o <<<"$opts"
    for n in "${o[@]}"; do
      if [ -z "$top" ]; then res FAIL "$cis.$c" "$t:$n" "no separate mount, so no $n"
      elif ! has_opt "$live" "$n"; then res FAIL "$cis.$c" "$t:$n" "not set live${p:+ (persistent entry $(has_opt "$(cut -f2 <<<"$p")" "$n" && echo has it: remount pending || echo lacks it too))}"
      elif [ "$t" = /dev/shm ] && [ -z "$p" ] && [ "$n" != noexec ]; then res PASS "$cis.$c" "$t:$n" "set live (systemd default)"
      elif [ -z "$p" ] || ! has_opt "$(cut -f2 <<<"$p")" "$n"; then res WARN "$cis.$c" "$t:$n" "set live but not persistent (lost at the next boot)"
      else res PASS "$cis.$c" "$t:$n" "set live and in $(cut -f1 <<<"$p")"; fi
      c=$((c + 1))
    done
  done <<<"$TARGETS"

  # /proc hidepid (not in the CIS benchmark; hides other users' processes and command lines from local accounts)
  top="$(mi_top "$mi" /proc)"
  line="$(fs_last "$fs" /proc)"
  if [ -z "$top" ]; then res FAIL n/a proc:hidepid "/proc not mounted?"
  elif ! hidepid_on "$(cut -f5 <<<"$top")"; then res FAIL n/a proc:hidepid "off (any local account can list every process and its command line)"
  elif [ -z "$line" ] || ! hidepid_on "$(cut -f4 <<<"$line")"; then res WARN n/a proc:hidepid "on live but not in fstab (lost at the next boot)"
  else res PASS n/a proc:hidepid "$(grep -oE 'hidepid=[a-z0-9]+(,gid=[0-9]+)?' <<<"$(cut -f5 <<<"$top"),$(cut -f5 <<<"$top")" | head -1 | sed 's/,gid=[0-9]*/ (exempt gid set)/') live and in fstab"; fi

  # postfiatd data directory: graded as the CONTAINER sees it (that is the mount postfiatd uses); persistence is
  # the host-side entry for the volume directory, which every later container start inherits.
  c="$(detect_container)"
  pid="$(container_pid "$c")"
  src="$(data_source "$c")"
  if [ -z "$pid" ] || [ "$pid" = 0 ] || [ -z "$src" ]; then
    res INFO n/a data:mount "container $c not running or has no mount at $DATA_DEST (skipped)"
  else
    [ -r "$R/proc/$pid/mountinfo" ] || die "cannot read $c's mount table (/proc/$pid/mountinfo): run as root"
    cmi="$(mi_parse "$R/proc/$pid/mountinfo")"
    top="$(mi_top "$cmi" "$DATA_DEST")"
    cov="$(mi_covering "$mi" "$src")"
    res INFO n/a data:mount "$c:$DATA_DEST <- $(label_path "$src") on host mount $(cut -f1 <<<"$cov")$([ "$(cut -f1 <<<"$cov")" = / ] && echo ' (root fs: fixed with a self-bind, / itself is not changed)')"
    line="$(fs_last "$fs" "$src")"
    [ -z "$line" ] && [ "$(cut -f1 <<<"$cov")" != / ] && line="$(fs_last "$fs" "$(cut -f1 <<<"$cov")")"
    for n in ${DATA_OPTS//,/ }; do
      if [ -z "$top" ]; then res FAIL n/a "data:$n" "no $DATA_DEST mount in the container's mount table"
      elif ! has_opt "$(cut -f2 <<<"$top")" "$n"; then res FAIL n/a "data:$n" "not set on $DATA_DEST inside $c"
      elif [ -z "$line" ] || ! has_opt "$(cut -f4 <<<"$line")" "$n"; then res WARN n/a "data:$n" "set inside $c but no host fstab entry: the next container start loses it"
      else res PASS n/a "data:$n" "set inside $c and in fstab:$(cut -f5 <<<"$line")"; fi
    done
  fi
}

print_results() {
  if [ "${JSON:-0}" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg ts "$(ts)" --argjson n "$FINDINGS" '
      {ts:$ts, findings:$n, result:(if $n==0 then "PASS" else "FAIL" end),
       checks:[split("\n")[] | select(length>0) | split("\t") | {status:.[0], cis:.[1], id:.[2], detail:.[3]}]}'
  else
    echo "pft-mounts audit - $(ts)"
    printf '%s' "$RESULTS" | awk -F'\t' '{printf "  [%-4s] %-9s %-22s %s\n", $1, $2, $3, $4}'
    echo "RESULT: $([ "$FINDINGS" = 0 ] && echo PASS || echo "FAIL - $FINDINGS finding(s)")"
  fi
}

write_prom() { # FILE: node_exporter textfile, written atomically
  local f="$1" tmp
  tmp="$(mktemp "${f}.XXXXXX")" || return 2
  {
    echo "# HELP pft_mounts_check 1 if the mount check passes (PASS/INFO), 0 if FAIL or WARN."
    echo "# TYPE pft_mounts_check gauge"
    printf '%s' "$RESULTS" | awk -F'\t' '$1 != "INFO" { gsub(/"/, "", $3); printf "pft_mounts_check{check=\"%s\",cis=\"%s\",status=\"%s\"} %d\n", $3, $2, $1, ($1 == "PASS") }'
    echo "# HELP pft_mounts_findings Number of FAIL + WARN mount checks."
    echo "# TYPE pft_mounts_findings gauge"
    echo "pft_mounts_findings $FINDINGS"
    echo "# HELP pft_mounts_last_run_timestamp_seconds Unix time of the last completed audit."
    echo "# TYPE pft_mounts_last_run_timestamp_seconds gauge"
    echo "pft_mounts_last_run_timestamp_seconds $(date +%s)"
  } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f"
}

# ---- plan / apply ------------------------------------------------------------------------------------------

proc_gid() { "$GETENT" group "$PROC_GROUP" 2>/dev/null | cut -d: -f3; }

block() { # SRC GID -> the managed fstab block (SRC: data volume host path, may be empty)
  local src="$1" gid="$2"
  echo "$BEGIN_MARK"
  echo "/tmp /tmp none bind,nodev,nosuid,noexec 0 0"
  echo "/var/tmp /var/tmp none bind,nodev,nosuid,noexec 0 0"
  echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
  echo "proc /proc proc defaults,hidepid=invisible${gid:+,gid=$gid} 0 0"
  [ -n "$src" ] && echo "${src// /\\040} ${src// /\\040} none bind,$DATA_OPTS 0 0"
  echo "$END_MARK"
}
candidate() { # SRC GID -> fstab with the old managed block (if any) replaced; all other lines unchanged
  [ -f "$FSTAB" ] && awk -v b="$BEGIN_MARK" -v e="$END_MARK" '$0 == b { skip = 1; next } skip && $0 == e { skip = 0; next } !skip' "$FSTAB"
  block "$1" "$2"
}
managed_conflicts() { # targets the block manages that also have an UNMANAGED fstab line (apply refuses)
  local src="$1" t
  [ -f "$FSTAB" ] || return 0
  for t in /tmp /var/tmp /dev/shm /proc ${src:+"$src"}; do
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" -v t="$t" '$0 == b { skip = 1; next } skip && $0 == e { skip = 0; next }
      !skip && !/^[ \t]*(#|$)/ { x = $2; gsub(/\\040/, " ", x); if (x == t) print "line " NR ": " $0 }' "$FSTAB"
  done
}

do_plan() {
  local c src gid
  c="$(detect_container)"; src="$(data_source "$c")"; gid="$(proc_gid)"
  echo "pft-mounts plan - $(ts) (container $c)"
  echo "fstab block (other lines unchanged):"
  block "$src" "${gid:-<gid of $PROC_GROUP, created by apply>}" | sed -E 's#/var/lib/docker/volumes/([^/ ]+)/_data#<docker-volume:\1>#g; s/^/  /'
  echo "live:"
  echo "  /tmp, /var/tmp: self-bind if not a mount, then remount,bind,nodev,nosuid,noexec"
  echo "  /dev/shm: remount,nodev,nosuid,noexec   /proc: remount,hidepid=invisible,gid=<$PROC_GROUP>"
  [ -n "$src" ] && echo "  $(label_path "$src"): self-bind + remount,bind,$DATA_OPTS on the host and inside $c ($DATA_DEST)"
  local cf; cf="$(managed_conflicts "$src")"
  [ -n "$cf" ] && { echo "REFUSE: unmanaged fstab entries for managed targets (move them into the block by hand first):"; printf '  %s\n' "${cf//$'\n'/$'\n'  }"; return 4; }
  return 0
}

server_state() {
  if [ -n "${PFT_MOUNTS_RPC:-}" ]; then "$PFT_MOUNTS_RPC"; return; fi
  "$DOCKER" exec "$1" sh -c 'curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:${RPC_PORT:-5005}/' 2>/dev/null \
    | jq -r '.result.info.server_state // "unknown"' 2>/dev/null || echo unknown
}
started_at() { "$DOCKER" inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null; }
gate_units() {
  if [ -n "${GATE_UNITS+x}" ]; then tr ' ' '\n' <<<"$GATE_UNITS" | grep .; return 0; fi
  "$SYSTEMCTL" list-timers --all --no-legend 'pft-*' 2>/dev/null | grep -oE 'pft-[^ ]+\.service' | grep -E "$GATE_PATTERN" | sort -u
}
daemon_units() { # long-running pft units that are active now; the gate requires them to stay active
  "$SYSTEMCTL" list-units --type=service --state=running --no-legend 'pft-*' 2>/dev/null | awk '{print $1}' | grep -E '^pft-' | sort -u
}

health_gate() { # STARTED_AT CONTAINER DAEMONS [rollback] -> 0 healthy within budget
  # rollback mode: the same checks except StartedAt (a restart that already happened is not undone by a
  # rollback) and the injected miss
  local before="$1" c="$2" daemons="$3" mode="${4:-apply}" start now st sa u bad label
  start="$(date +%s)"; label="health"; [ "$mode" = rollback ] && label="rollback: health"
  # oneshots once: each must complete with Result=success under the new mounts
  bad=""
  for u in $(gate_units); do
    if "$SYSTEMCTL" start "$u" 2>/dev/null && [ "$("$SYSTEMCTL" show -p Result --value "$u" 2>/dev/null)" = success ]; then
      echo "$(ts) $label: unit $u ran, Result=success"
    else bad+=" $u"; echo "$(ts) $label: unit $u FAILED (Result=$("$SYSTEMCTL" show -p Result --value "$u" 2>/dev/null))"; fi
  done
  while :; do
    now="$(date +%s)"
    st="$(server_state "$c")"; sa="$(started_at "$c")"
    local dbad="" sshok=0
    for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || dbad+=" $u"; done
    "$SSHD" -t >/dev/null 2>&1 && "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ':22$' \
      && "$KEYSCAN" -T 5 -t ed25519 127.0.0.1 2>/dev/null | grep -q ssh-ed25519 && sshok=1
    if { [ "$INJECT" != health ] || [ "$mode" = rollback ]; } && [ -z "$bad" ] && [ -z "$dbad" ] && [ "$sshok" = 1 ] \
       && { [ "$sa" = "$before" ] || [ "$mode" = rollback ]; } && [ "$st" = full ] && "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ":$PEER_PORT\$"; then
      echo "$(ts) $label: PASS after $((now - start)) s ($c StartedAt unchanged, server_state full, :$PEER_PORT listening, sshd -t ok + :22 handshake, $(wc -w <<<"$daemons") pft daemons active)"
      return 0
    fi
    if [ -n "$bad" ] || (( now - start >= HEALTH_BUDGET )); then
      echo "$(ts) $label: FAIL after $((now - start)) s (server_state=$st; StartedAt $([ "$sa" = "$before" ] && echo unchanged || echo CHANGED); ssh=$sshok; failed units:${bad:- none}; inactive daemons:${dbad:- none}${INJECT:+; injected=$INJECT})"
      return 1
    fi
    sleep "$POLL_SEC"
  done
}

is_mount() { mi_top "$(mi_parse "$MOUNTINFO")" "$1" | grep -q .; }
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

live_apply() { # SRC PID GID: records every step in live.state for rollback
  local src="$1" pid="$2" gid="$3" t co po st="$BACKUP_DIR/live.state"
  : > "$st"
  for t in /tmp /var/tmp; do
    if is_mount "$t"; then echo "remount $t $(mi_top "$(mi_parse "$MOUNTINFO")" "$t" | cut -f2)" >> "$st"
    else "$MOUNT" --bind "$t" "$t" || return 1; echo "created $t" >> "$st"; fi
    "$MOUNT" --options-mode ignore -o remount,bind,nodev,nosuid,noexec "$t" || return 1
    echo "$(ts) live: $t bind,nodev,nosuid,noexec"
  done
  echo "remount /dev/shm $(mi_top "$(mi_parse "$MOUNTINFO")" /dev/shm | cut -f2)" >> "$st"
  "$MOUNT" --options-mode ignore -o "remount,$(cut -f2 <<<"$(mi_top "$(mi_parse "$MOUNTINFO")" /dev/shm)"),nodev,nosuid,noexec" /dev/shm || return 1; echo "$(ts) live: /dev/shm nodev,nosuid,noexec"
  # a remount without the per-mount flags would CLEAR /proc's nosuid,nodev,noexec: always pass them back
  po="$(mi_top "$(mi_parse "$MOUNTINFO")" /proc | cut -f2)"
  echo "proc /proc $po" >> "$st"
  "$MOUNT" --options-mode ignore -o "remount,$po,hidepid=invisible${gid:+,gid=$gid}" /proc || return 1; echo "$(ts) live: /proc hidepid=invisible (gid $PROC_GROUP)"
  if [ -n "$src" ] && [ -n "$pid" ] && [ "$pid" != 0 ]; then
    if is_mount "$src"; then echo "remount $src $(mi_top "$(mi_parse "$MOUNTINFO")" "$src" | cut -f2)" >> "$st"
    else "$MOUNT" --bind "$src" "$src" || return 1; echo "created $src" >> "$st"; fi
    "$MOUNT" --options-mode ignore -o "remount,bind,$DATA_OPTS" "$src" || return 1
    co="$(mi_top "$(mi_parse "$R/proc/$pid/mountinfo")" "$DATA_DEST" | cut -f2)"
    [ -n "$co" ] || { echo "$(ts) live: no $DATA_DEST in the container's mount table"; return 1; }
    "$NSENTER" -t "$pid" -m -- mount --options-mode ignore -o "remount,bind,$co,$DATA_OPTS" "$DATA_DEST" || return 1
    echo "container $pid $DATA_DEST $co" >> "$st" # recorded only once it succeeded: a failed remount changed nothing
    echo "$(ts) live: data dir $DATA_OPTS (host self-bind + inside the container)"
  fi
  return 0
}

inverse() { # ORIGINAL-OPTS -> the original options plus dev/suid/exec for each of ours it did not have
  local out="$1" x
  for x in dev suid exec; do has_opt "$1" "no$x" || out+=",$x"; done
  echo "$out"
}
live_revert() { # undo live.state in reverse order
  local st="$BACKUP_DIR/live.state" kind a b rc=0
  [ -f "$st" ] || { echo "$(ts) rollback: no live.state, live mounts untouched"; return 0; }
  while read -r kind a b; do
    case "$kind" in
      created) "$UMOUNT" "$a" && echo "$(ts) rollback: unmounted self-bind $(label_path "$a")" || rc=1 ;;
      remount) "$MOUNT" --options-mode ignore -o "remount,$( [ "$a" = /dev/shm ] || echo bind,)$(inverse "$b")" "$a" \
                 && echo "$(ts) rollback: $(label_path "$a") options back to $b" || rc=1 ;;
      proc)    "$MOUNT" --options-mode ignore -o "remount,$b,hidepid=off,gid=0" /proc && echo "$(ts) rollback: /proc hidepid=off (flags $b kept)" || rc=1 ;;
      container) "$NSENTER" -t "$a" -m -- mount --options-mode ignore -o "remount,bind,$(inverse "${b#* }")" "${b%% *}" \
                   && echo "$(ts) rollback: ${b%% *} back to ${b#* } inside the container" || rc=1 ;;
    esac
  done < <(tac "$st")
  [ "$rc" = 0 ] && mv -f "$st" "$st.reverted"
  return "$rc"
}

restore_fstab() { # BACKUP
  local b="$1"
  cp -p "$b" "$FSTAB" || return 1
  [ "$(sha "$b")" = "$(sha "$FSTAB")" ] || { echo "$(ts) rollback: fstab sha256 mismatch after restore"; return 1; }
  echo "$(ts) rollback: fstab restored byte-identical (sha256 $(sha "$FSTAB" | cut -c1-12))"
  "$SYSTEMCTL" daemon-reload
}

do_apply() {
  local dry="$1" c src pid gid b cand before daemons
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  c="$(detect_container)"; src="$(data_source "$c")"; pid="$(container_pid "$c")"
  [ -n "$src" ] || echo "$(ts) apply: $c has no $DATA_DEST mount; data dir step skipped"
  do_plan > /dev/null || { do_plan; return 4; }
  gid="$(proc_gid)"
  if [ -z "$gid" ]; then
    [ "$dry" = 1 ] && gid="<new>" || { "$GROUPADD" --system "$PROC_GROUP" || die "groupadd $PROC_GROUP failed" 2; gid="$(proc_gid)"; echo "$(ts) apply: created system group $PROC_GROUP (gid $gid, no members)"; }
  fi
  mkdir -p "$BACKUP_DIR" && chmod 0700 "$BACKUP_DIR"
  cand="$BACKUP_DIR/fstab.candidate"
  candidate "$src" "$gid" > "$cand"
  if ! "$FINDMNT" --verify --tab-file "$cand" >"$BACKUP_DIR/verify.out" 2>&1; then
    echo "$(ts) apply: REFUSED - findmnt --verify rejects the candidate fstab (installed fstab untouched)"; sed 's/^/  /' "$BACKUP_DIR/verify.out"; return 4
  fi
  echo "$(ts) apply: candidate fstab verified ($(grep -c . "$BACKUP_DIR/verify.out") findmnt lines, 0 errors)"
  if [ "$dry" = 1 ]; then diff -u "$FSTAB" "$cand" | sed -E 's#/var/lib/docker/volumes/([^/ ]+)/_data#<docker-volume:\1>#g'; echo "$(ts) apply: dry run, nothing changed"; return 0; fi
  if cmp -s "$FSTAB" "$cand" && audit_quiet; then echo "$(ts) apply: already applied (fstab block current, audit PASS) - nothing to do"; return 0; fi
  before="$(started_at "$c")"; daemons="$(daemon_units)"
  b="$BACKUP_DIR/fstab.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$FSTAB" "$b" || die "backup failed" 2
  install -m 0644 "$cand" "$FSTAB" || die "install fstab failed" 2
  "$SYSTEMCTL" daemon-reload
  echo "$(ts) apply: fstab installed (backup $(basename "$b"), sha256 $(sha "$b" | cut -c1-12) -> $(sha "$FSTAB" | cut -c1-12))"
  if ! live_apply "$src" "$pid" "$gid" || ! health_gate "$before" "$c" "$daemons"; then
    echo "$(ts) apply: live step or health gate failed -> automatic rollback"
    live_revert && restore_fstab "$b" && health_gate "$before" "$c" "$daemons" rollback || return 5
    return 1
  fi
  echo "$(ts) apply: done"
}
audit_quiet() { RESULTS=""; FINDINGS=0; audit_checks; [ "$FINDINGS" = 0 ]; }

do_rollback() {
  local b c before daemons
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
  b="$(find "$BACKUP_DIR" -maxdepth 1 -name 'fstab.2*' 2>/dev/null | sort | tail -1)"
  [ -n "$b" ] || die "no fstab backup in $BACKUP_DIR" 2
  c="$(detect_container)"; before="$(started_at "$c")"; daemons="$(daemon_units)"
  live_revert || return 5
  restore_fstab "$b" || return 5
  health_gate "$before" "$c" "$daemons" rollback || return 5
  echo "$(ts) rollback: done ($(basename "$b"))"
}

cmd="${1:-}"; shift || true
YES=0; DRY=0; JSON=0; PROM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;; --dry-run) DRY=1 ;; --json) JSON=1 ;;
    --prom) PROM="${2:-}"; [ -n "$PROM" ] || die "--prom needs a file" 3; shift ;;
    *) die "unknown option $1" 3 ;;
  esac
  shift
done
case "$cmd" in
  audit)
    audit_checks; print_results
    [ -n "$PROM" ] && { write_prom "$PROM" || die "cannot write $PROM" 2; }
    [ "$FINDINGS" = 0 ] && exit 0 || exit 1 ;;
  plan) do_plan; exit $? ;;
  apply) [ "$YES" = 1 ] || [ "$DRY" = 1 ] || die "apply changes /etc/fstab and live mounts; pass --yes (or --dry-run)" 4
         do_apply "$DRY"; exit $? ;;
  rollback) [ "$YES" = 1 ] || die "rollback changes /etc/fstab and live mounts; pass --yes" 4
            do_rollback; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
