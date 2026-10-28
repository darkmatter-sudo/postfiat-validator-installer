#!/usr/bin/env bash
# pft-timesync: authenticated, measured and safely managed host clocks for a Post Fiat validator or sentry
# (Ubuntu 22.04, postfiatd in a container). Validators sign close times and drop out of consensus when their clock
# drifts, so "NTPSynchronized=yes" is not enough: this tool audits the time daemon, migrates the host from
# systemd-timesyncd (SNTP, one unauthenticated source) to chrony with NTS-authenticated sources, and rolls back
# byte-identical when the migration does not reach a good sync within a budget. postfiatd is never restarted.
#
# Usage: sudo pft-timesync audit [--json]   (chronyc needs root for the unix command socket: cmdport 0)
#        pft-timesync plan                 (read-only: the chrony.conf and unit drop-in apply would write)
#        sudo pft-timesync apply --yes
#        sudo pft-timesync rollback --yes  (restore the newest backup: files, packages, active daemon)
#        sudo pft-timesync metrics         (write TEXTFILE_DIR/pft_timesync.prom; run by pft-timesync.timer)
#        pft-timesync boot-gate            (chrony.service ExecStartPre: allow makestep only right after boot)
#
#  audit    read-only. One line per check: PASS / WARN / CRIT / INFO. Checks: active daemon and conflicting
#           daemons, source count, NTS-authenticated sources, selected source, offset, root dispersion, stratum,
#           leap status, makestep policy, slew bound, RTC mode. Exit 0 all PASS, 1 any WARN, 2 any CRIT.
#  apply    1. preflight (nothing changed yet): downloads chrony, caches the installed systemd-timesyncd .deb for
#              the rollback, backs up every managed file (present/absent + sha256), records postfiatd's StartedAt.
#           2. stops timesyncd, installs chrony with a policy-rc.d that blocks the package's own start (so the
#              packaged default config, which allows clock steps, never runs), writes chrony.conf with NTS_SERVERS
#              (>= MIN_NTS), minsources, maxslewrate (bounded slewing) and NO makestep; makestep 1.0 3 is only
#              written by boot-gate when the host booted less than BOOT_WINDOW s ago. Starts chrony.
#              The candidate chrony.conf must pass `chronyd -p` before it replaces the file.
#           3. sync gate: within SYNC_BUDGET s chrony must have a selected source, >= MIN_NTS NTS-authenticated
#              reachable sources, leap status not "Not synchronised", |offset| <= OFFSET_WARN and root dispersion
#              <= DISP_WARN (a fresh chronyd reports skew 1000000 ppm and a dispersion of many seconds until it has a
#              frequency estimate, about 3 updates = 2-3 min, which the audit grades CRIT); postfiatd's
#              StartedAt must be unchanged and server_state full. Any miss -> automatic rollback (exit 1, or 5).
#  rollback stops chrony, purges it if it was not installed before, reinstalls the cached timesyncd .deb, restores
#           every managed file byte-identical (absent files removed), restarts the daemon that was active before,
#           then checks sha256/absence of every file, the package set and the active daemon (exit 0, or 5).
#
# Exit codes: audit 0/1/2 as above; apply 0 applied, 1 rolled back, 2 error, 3 usage, 4 refused (not root, no
#             --yes, preflight failed: nothing changed), 5 rollback failed.
# Env: NTS_SERVERS (5 public NTS servers)  MIN_NTS (4)  MIN_SOURCES (3, chrony minsources)  MAXSLEWRATE (500 ppm)
#      OFFSET_WARN (0.05 s)  OFFSET_CRIT (0.25 s)  DISP_WARN (0.1 s)  DISP_CRIT (1.0 s)  STRATUM_WARN (6)
#      SYNC_BUDGET (600 s)  POLL_SEC (5)  BOOT_WINDOW (300 s)  CONTAINER (auto: postfiatd or postfiatd-sentry)
#      BACKUP_DIR (/var/lib/pft-timesync)  TEXTFILE_DIR (/var/lib/pft-exporter/textfile)
#      Test hooks: PFT_TIMESYNC_ROOT (path prefix for every file)  PFT_TIMESYNC_SYSTEMCTL / _CHRONYC / _CHRONYD / _TIMEDATECTL /
#      _APTGET / _DPKGQ / _DPKG / _DOCKER / _RPC (commands)  PFT_TIMESYNC_INJECT (unreachable: TEST-NET-1 sources)

# jq/awk programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_TIMESYNC_ROOT:-}"
SYSTEMCTL="${PFT_TIMESYNC_SYSTEMCTL:-systemctl}"
CHRONYC="${PFT_TIMESYNC_CHRONYC:-chronyc}"
CHRONYD="${PFT_TIMESYNC_CHRONYD:-chronyd}"
TIMEDATECTL="${PFT_TIMESYNC_TIMEDATECTL:-timedatectl}"
APTGET="${PFT_TIMESYNC_APTGET:-apt-get}"
DPKGQ="${PFT_TIMESYNC_DPKGQ:-dpkg-query}"
DPKG="${PFT_TIMESYNC_DPKG:-dpkg}"
DOCKER="${PFT_TIMESYNC_DOCKER:-docker}"
INJECT="${PFT_TIMESYNC_INJECT:-}"
NTS_SERVERS="${NTS_SERVERS:-time.cloudflare.com nts.netnod.se ptbtime1.ptb.de ntppool1.time.nl nts.teambelgium.net}"
MIN_NTS="${MIN_NTS:-4}"
MIN_SOURCES="${MIN_SOURCES:-3}"
MAXSLEWRATE="${MAXSLEWRATE:-500}"
OFFSET_WARN="${OFFSET_WARN:-0.05}"
OFFSET_CRIT="${OFFSET_CRIT:-0.25}"
DISP_WARN="${DISP_WARN:-0.1}"
DISP_CRIT="${DISP_CRIT:-1.0}"
STRATUM_WARN="${STRATUM_WARN:-6}"
SYNC_BUDGET="${SYNC_BUDGET:-600}"
POLL_SEC="${POLL_SEC:-5}"
BOOT_WINDOW="${BOOT_WINDOW:-300}"
BACKUP_DIR="${BACKUP_DIR:-$R/var/lib/pft-timesync}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
CHRONY_CONF="$R/etc/chrony/chrony.conf"
TSD_CONF="$R/etc/systemd/timesyncd.conf"
DROPIN="$R/etc/systemd/system/chrony.service.d/50-pft-timesync.conf"
BOOT_CONF="$R/etc/chrony/conf.d/pft-boot-makestep.conf"
POLICY_RC="$R/usr/sbin/policy-rc.d"
TOOL_PATH="/usr/local/sbin/pft-timesync"
MANAGED=("$TSD_CONF" "$CHRONY_CONF" "$DROPIN" "$BOOT_CONF")
DAEMONS=(chrony systemd-timesyncd ntp ntpsec openntpd)

ts() { date -u +%FT%TZ; }
die() { echo "pft-timesync: $1" >&2; exit "${2:-2}"; }
num_le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !((a+0) <= (b+0))}'; }
abs() { awk -v a="$1" 'BEGIN{printf "%.9f", (a < 0 ? -a : a)}'; }

# ---------------------------------------------------------------- facts
active_daemons() { local d; for d in "${DAEMONS[@]}"; do "$SYSTEMCTL" is-active --quiet "$d" 2>/dev/null && echo "$d"; done; }

# chrony tracking CSV (chrony 4.2): 1 refid 2 name 3 stratum 4 reftime 5 system-time (POSITIVE = clock SLOW)
# 6 last 7 rms 8 freq 9 resid 10 skew 11 root-delay 12 root-dispersion 13 interval 14 leap
chrony_facts() { # -> KEY=VALUE lines; rc 1 if chronyd does not answer
  local tr src auth
  tr="$("$CHRONYC" -c -N tracking 2>/dev/null)" || return 1
  [ -n "$tr" ] || return 1
  src="$("$CHRONYC" -c -N sources 2>/dev/null)" || return 1
  auth="$("$CHRONYC" -c -N authdata 2>/dev/null)" || auth=""
  awk -F, '{printf "stratum=%s\noffset=%.9f\ndisp=%s\nleap=%s\n", $3, -$5, $12, $14}' <<<"$tr"
  # sources CSV: 1 mode(^ server, = peer, # refclock) 2 state 3 name 4 stratum 5 poll 6 reach(octal) ...
  awk -F, '$1=="^"{n++; if ($6 != "0") r++; if ($2=="*") s=$3} END{printf "sources=%d\nreachable=%d\nselected=%s\n", n, r, s}' <<<"$src"
  # NTS-authenticated = authdata Mode NTS with an established key (KLen > 0) AND the same source reachable
  awk -F, 'NR==FNR{if ($1=="^" && $6 != "0") reach[$3]=1; next} $2=="NTS" && $5+0 > 0 && ($1 in reach){n++}
           END{printf "nts=%d\n", n}' <(printf '%s\n' "$src") <(printf '%s\n' "$auth")
}

# systemd-timesyncd: no offset is exported; stratum/dispersion/leap come from the last NTP message
timesyncd_facts() {
  local m sync
  m="$("$TIMEDATECTL" show-timesync -p NTPMessage --value 2>/dev/null)"
  sync="$("$TIMEDATECTL" show -p NTPSynchronized --value 2>/dev/null)"
  printf 'synced=%s\nsources=%s\n' "$sync" "$("$TIMEDATECTL" show-timesync -p ServerName --value 2>/dev/null | grep -c .)"
  sed -nE 's/.*Stratum=([0-9]+).*/stratum=\1/p' <<<"$m"
  sed -nE 's/.*RootDispersion=([0-9.]+)(us|ms|s),.*/\1 \2/p' <<<"$m" \
    | awk '{f = ($2=="us") ? 1e-6 : ($2=="ms") ? 1e-3 : 1; printf "disp=%.9f\n", $1 * f}'
  sed -nE 's/.*Leap=([0-9]),.*/\1/p' <<<"$m" | awk '{split("Normal,Insert second,Delete second,Not synchronised", l, ","); print "leap=" l[$1+1]}'
}

get() { sed -n "s/^$1=//p" <<<"$2" | head -1; }

# ---------------------------------------------------------------- audit
CHECKS=(); WORST=0
res() { # STATE CHECK DETAIL
  CHECKS+=("$1|$2|$3")
  case "$1" in WARN) [ "$WORST" -lt 1 ] && WORST=1 ;; CRIT) WORST=2 ;; esac
}

grade() { # VALUE WARN CRIT CHECK DETAIL  (|value| graded)
  local a; a="$(abs "$1")"
  if num_le "$a" "$2"; then res PASS "$4" "$5"; elif num_le "$a" "$3"; then res WARN "$4" "$5 (> $2)"; else res CRIT "$4" "$5 (> $3)"; fi
}

run_audit() { # fills CHECKS/WORST and FACTS
  local act n f
  CHECKS=(); WORST=0; FACTS=""; DAEMON=none
  act="$(active_daemons)"; n="$(grep -c . <<<"$act")"
  if [ "$n" = 0 ]; then res CRIT daemon "no time daemon active (${DAEMONS[*]})"; return; fi
  if [ "$n" -gt 1 ]; then res CRIT conflicting-daemons "$(paste -sd' ' <<<"$act") active together"; else res PASS conflicting-daemons "only $act"; fi
  if grep -qx chrony <<<"$act"; then
    DAEMON=chrony; res PASS daemon "chrony"
    if ! f="$(chrony_facts)"; then res CRIT chronyd "chronyc gets no answer from chronyd"; return; fi
    FACTS="$f"
    [ "$(get sources "$f")" -ge "$MIN_SOURCES" ] && res PASS sources "$(get sources "$f") configured, $(get reachable "$f") reachable" \
      || res WARN sources "$(get sources "$f") configured (< $MIN_SOURCES), $(get reachable "$f") reachable"
    if [ "$(get nts "$f")" -ge "$MIN_NTS" ]; then res PASS nts "$(get nts "$f") NTS-authenticated reachable sources"
    else res WARN nts "$(get nts "$f") NTS-authenticated reachable sources (< $MIN_NTS)"; fi
    [ -n "$(get selected "$f")" ] && res PASS selected "a source is selected" || res CRIT selected "no source selected"
    grade "$(get offset "$f")" "$OFFSET_WARN" "$OFFSET_CRIT" offset "system clock $(get offset "$f") s from NTP time"
    if grep -qE '^[[:space:]]*makestep' "$CHRONY_CONF" 2>/dev/null; then res WARN makestep "chrony.conf allows clock steps after start (makestep), not only at boot"
    elif [ -f "$DROPIN" ] && grep -q 'boot-gate' "$DROPIN"; then res PASS makestep "steps only within ${BOOT_WINDOW} s of boot (boot-gate)"
    else res PASS makestep "never steps (no makestep)"; fi
    local slew; slew="$(awk '$1=="maxslewrate"{print $2}' "$CHRONY_CONF" 2>/dev/null | tail -1)"
    if [ -n "$slew" ] && num_le "$slew" 1000; then res PASS slew-bound "maxslewrate $slew ppm"
    else res WARN slew-bound "maxslewrate ${slew:-unset (chrony default 83333)} ppm (> 1000)"; fi
  elif grep -qx systemd-timesyncd <<<"$act"; then
    DAEMON=systemd-timesyncd; res WARN daemon "systemd-timesyncd (SNTP client, no authentication)"
    f="$(timesyncd_facts)"; FACTS="$f"$'\nnts=0\noffset=\nselected='
    [ "$(get sources "$f")" -ge "$MIN_SOURCES" ] && res PASS sources "$(get sources "$f") in use" || res WARN sources "$(get sources "$f") in use (< $MIN_SOURCES)"
    res WARN nts "0 NTS-authenticated sources (timesyncd cannot do NTS)"
    [ "$(get synced "$f")" = yes ] && res PASS selected "NTPSynchronized=yes" || res CRIT selected "NTPSynchronized=$(get synced "$f")"
    res INFO offset "not exported by systemd-timesyncd (see offset_probe.py)"
  else
    DAEMON="$(head -1 <<<"$act")"; res WARN daemon "$DAEMON (not audited in detail)"; return
  fi
  local s d l
  s="$(get stratum "$f")"; d="$(get disp "$f")"; l="$(get leap "$f")"
  if [ -z "$d" ]; then res WARN root-dispersion "unknown"; else grade "$d" "$DISP_WARN" "$DISP_CRIT" root-dispersion "$d s"; fi
  if [ -z "$s" ] || [ "$s" = 0 ] || [ "$s" -ge 16 ]; then res CRIT stratum "${s:-unknown} (unsynchronised)"
  elif [ "$s" -gt "$STRATUM_WARN" ]; then res WARN stratum "$s (> $STRATUM_WARN)"; else res PASS stratum "$s"; fi
  case "$l" in
    Normal) res PASS leap "Normal" ;;
    "Insert second"|"Delete second") res WARN leap "$l pending" ;;
    *) res CRIT leap "${l:-unknown}" ;;
  esac
  if [ "$("$TIMEDATECTL" show -p LocalRTC --value 2>/dev/null)" = no ]; then res PASS rtc "RTC in UTC (LocalRTC=no)"
  else res WARN rtc "RTC in local time (LocalRTC=yes): DST changes and dual-boot shift the boot clock"; fi
}

result_word() { case "$WORST" in 0) echo OK ;; 1) echo WARN ;; *) echo CRIT ;; esac; }

cmd_audit() {
  local json=0; [ "${1:-}" = --json ] && json=1
  run_audit
  if [ "$json" = 1 ]; then
    printf '%s\n' "${CHECKS[@]}" | jq -R -s --arg r "$(result_word)" --arg d "$DAEMON" --argjson e "$WORST" --arg t "$(ts)" '
      {time: $t, result: $r, exit: $e, daemon: $d,
       checks: [split("\n")[] | select(length > 0) | split("|") | {state: .[0], check: .[1], detail: .[2]}]}'
  else
    echo "pft-timesync audit - $(ts)"
    local c; for c in "${CHECKS[@]}"; do IFS='|' read -r s n d <<<"$c"; printf '[%-4s] %-20s %s\n' "$s" "$n" "$d"; done
    echo "RESULT: $(result_word) (daemon $DAEMON) -> exit $WORST"
  fi
  return "$WORST"
}

# ---------------------------------------------------------------- metrics
cmd_metrics() {
  local out tmp w c s n
  run_audit
  out="$TEXTFILE_DIR/pft_timesync.prom"; mkdir -p "$TEXTFILE_DIR"; tmp="$(mktemp "$TEXTFILE_DIR/.pft_timesync.XXXXXX")" || return 2
  {
    echo "# HELP pft_timesync_state Audit result: 0 OK, 1 WARN, 2 CRIT"; echo "# TYPE pft_timesync_state gauge"
    echo "pft_timesync_state $WORST"
    echo "# HELP pft_timesync_daemon Active time daemon (1 for the active one)"; echo "# TYPE pft_timesync_daemon gauge"
    echo "pft_timesync_daemon{daemon=\"$DAEMON\"} 1"
    echo "# HELP pft_timesync_check Per-check state: 0 PASS/INFO, 1 WARN, 2 CRIT"; echo "# TYPE pft_timesync_check gauge"
    for c in "${CHECKS[@]}"; do IFS='|' read -r s n _ <<<"$c"; case "$s" in WARN) w=1 ;; CRIT) w=2 ;; *) w=0 ;; esac
      echo "pft_timesync_check{check=\"$n\"} $w"; done
    for n in offset:offset_seconds:"System clock minus NTP time (chrony only)" disp:root_dispersion_seconds:"Root dispersion" \
             stratum:stratum:"Stratum of this host" nts:nts_sources:"NTS-authenticated reachable sources" \
             sources:sources:"Configured sources" reachable:reachable_sources:"Reachable sources"; do
      IFS=: read -r k m h <<<"$n"; v="$(get "$k" "$FACTS")"
      [ -n "$v" ] && printf '# HELP pft_timesync_%s %s\n# TYPE pft_timesync_%s gauge\npft_timesync_%s %s\n' "$m" "$h" "$m" "$m" "$v"
    done
    echo "# HELP pft_timesync_synced 1 if a source is selected / NTPSynchronized=yes"; echo "# TYPE pft_timesync_synced gauge"
    if [ -n "$(get selected "$FACTS")" ] || [ "$(get synced "$FACTS")" = yes ]; then echo "pft_timesync_synced 1"; else echo "pft_timesync_synced 0"; fi
    echo "# HELP pft_timesync_collect_timestamp_seconds Unix time of this collection"; echo "# TYPE pft_timesync_collect_timestamp_seconds gauge"
    echo "pft_timesync_collect_timestamp_seconds $(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp" && mv -f "$tmp" "$out"
}

# ---------------------------------------------------------------- plan / config
servers() { if [ "$INJECT" = unreachable ]; then echo 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5; else echo "$NTS_SERVERS"; fi; }

chrony_conf_text() {
  local s
  echo "# Managed by pft-timesync (postfiat-validator-installer/timesync). Changes are overwritten by 'apply'."
  echo "# NTS-authenticated sources only; no pool, no DHCP-provided (unauthenticated) servers."
  for s in $(servers); do echo "server $s iburst nts"; done
  cat <<EOF
# a clock update needs agreement of at least this many selectable sources
minsources $MIN_SOURCES
# running clock: slew only, at most $MAXSLEWRATE ppm ($(awk -v r="$MAXSLEWRATE" 'BEGIN{print r/1000}') ms per s). No makestep here: steps are only
# allowed right after boot, by /etc/chrony/conf.d/pft-boot-makestep.conf (written by 'pft-timesync boot-gate').
maxslewrate $MAXSLEWRATE
maxupdateskew 100.0
confdir /etc/chrony/conf.d
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
# no UDP command port; chronyc talks over the root-only unix socket
cmdport 0
rtcsync
leapsectz right/UTC
EOF
}

dropin_text() {
  cat <<EOF
# Managed by pft-timesync: allow makestep only within BOOT_WINDOW seconds of boot ("+" = runs outside the sandbox,
# it writes or removes /etc/chrony/conf.d/pft-boot-makestep.conf before chronyd reads its config).
[Service]
ExecStartPre=+$TOOL_PATH boot-gate
EOF
}

cmd_plan() {
  echo "# ${CHRONY_CONF#"$R"}"; chrony_conf_text
  echo "# ${DROPIN#"$R"}"; dropin_text
  echo "# boot-gate: within $BOOT_WINDOW s of boot ${BOOT_CONF#"$R"} = 'makestep 1.0 3', otherwise removed"
  echo "# packages: install chrony (removes systemd-timesyncd: both provide time-daemon); the installed timesyncd .deb is cached for rollback"
}

cmd_boot_gate() {
  local up; up="$(awk '{printf "%d", $1}' "$R/proc/uptime" 2>/dev/null)" || up=999999
  mkdir -p "$(dirname "$BOOT_CONF")"
  if [ "${up:-999999}" -lt "$BOOT_WINDOW" ]; then
    printf '# written by pft-timesync boot-gate at boot (uptime %s s): step the clock in the first 3 updates if > 1 s off\nmakestep 1.0 3\n' "$up" > "$BOOT_CONF"
    echo "boot-gate: uptime ${up}s < ${BOOT_WINDOW}s -> makestep 1.0 3 allowed for this start"
  else
    rm -f "$BOOT_CONF"; echo "boot-gate: uptime ${up}s >= ${BOOT_WINDOW}s -> no makestep (slew only)"
  fi
}

# ---------------------------------------------------------------- backup / rollback
pkg_ver() { "$DPKGQ" -W -f '${db:Status-Status} ${Version}\n' "$1" 2>/dev/null | awk '$1=="installed"{print $2}'; }
sha() { sha256sum "$1" | awk '{print $1}'; }

make_backup() { # -> backup dir on stdout
  local b f i=0
  b="$BACKUP_DIR/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$b" || return 1; chmod 0700 "$b"
  : > "$b/files.tsv"
  for f in "${MANAGED[@]}"; do
    i=$((i + 1))
    if [ -f "$f" ]; then cp -p "$f" "$b/f$i" && printf '%s\tpresent\t%s\tf%s\n' "$f" "$(sha "$f")" "$i" >> "$b/files.tsv" || return 1
    else printf '%s\tabsent\t-\t-\n' "$f" >> "$b/files.tsv"; fi
  done
  { echo "chrony=$(pkg_ver chrony)"; echo "systemd-timesyncd=$(pkg_ver systemd-timesyncd)"
    echo "active=$(active_daemons | paste -sd, -)"; } > "$b/state"
  echo "$b"
}

restore_check() { # BACKUP -> prints one line per file, rc 1 on any mismatch
  local b="$1" f st h k bad=0 now
  while IFS=$'\t' read -r f st h k; do
    if [ "$st" = absent ]; then
      if [ -e "$f" ]; then echo "  restore $f: should be absent, is present -> MISMATCH"; bad=1; else echo "  restore $f: absent as before"; fi
    else
      now="$( [ -f "$f" ] && sha "$f")"
      if [ "$now" = "$h" ]; then echo "  restore $f: sha256 $h byte-identical"; else echo "  restore $f: sha256 ${now:-missing} != $h -> MISMATCH"; bad=1; fi
    fi
  done < "$b/files.tsv"
  return "$bad"
}

do_rollback() { # BACKUP
  local b="$1" f st h k want_c want_t want_a now_c now_t now_a bad=0
  want_c="$(sed -n 's/^chrony=//p' "$b/state")"; want_t="$(sed -n 's/^systemd-timesyncd=//p' "$b/state")"
  want_a="$(sed -n 's/^active=//p' "$b/state")"
  echo "$(ts) rollback: from $b (before: chrony=${want_c:-none} timesyncd=${want_t:-none} active=${want_a:-none})"
  "$SYSTEMCTL" stop chrony 2>/dev/null
  if [ -z "$want_c" ] && [ -n "$(pkg_ver chrony)" ]; then
    DEBIAN_FRONTEND=noninteractive "$APTGET" purge -y -q chrony >/dev/null 2>&1 || echo "$(ts) rollback: apt-get purge chrony FAILED"
  fi
  if [ -n "$want_t" ] && [ "$(pkg_ver systemd-timesyncd)" != "$want_t" ]; then
    DEBIAN_FRONTEND=noninteractive "$DPKG" -i --force-confold "$b"/systemd-timesyncd_*.deb >/dev/null 2>&1 \
      || echo "$(ts) rollback: dpkg -i cached systemd-timesyncd FAILED"
  fi
  while IFS=$'\t' read -r f st h k; do
    if [ "$st" = absent ]; then rm -f "$f"; rmdir "$(dirname "$f")" 2>/dev/null; else mkdir -p "$(dirname "$f")"; cp -p "$b/$k" "$f"; fi
  done < "$b/files.tsv"
  "$SYSTEMCTL" daemon-reload 2>/dev/null
  for f in ${want_a//,/ }; do "$SYSTEMCTL" enable "$f" >/dev/null 2>&1; "$SYSTEMCTL" restart "$f" 2>/dev/null; done
  sleep "${RESTART_WAIT:-2}"
  restore_check "$b" || bad=1
  now_c="$(pkg_ver chrony)"; now_t="$(pkg_ver systemd-timesyncd)"; now_a="$(active_daemons | paste -sd, -)"
  echo "  packages: chrony=${now_c:-none} (before ${want_c:-none}), systemd-timesyncd=${now_t:-none} (before ${want_t:-none})"
  echo "  active daemon: ${now_a:-none} (before ${want_a:-none})"
  [ "$now_c" = "$want_c" ] && [ "$now_t" = "$want_t" ] && [ "$now_a" = "$want_a" ] || bad=1
  if [ "$bad" = 0 ]; then echo "$(ts) rollback: PASS (files byte-identical, packages and daemon as before)"; return 0; fi
  echo "$(ts) rollback: FAIL"; return 1
}

# ---------------------------------------------------------------- apply
container() {
  if [ -n "${CONTAINER:-}" ]; then echo "$CONTAINER"; return; fi
  local c; for c in postfiatd postfiatd-sentry; do "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }; done
}
started_at() { "$DOCKER" inspect -f '{{.State.StartedAt}}' "$1" 2>/dev/null; }
server_state() {
  if [ -n "${PFT_TIMESYNC_RPC:-}" ]; then "$PFT_TIMESYNC_RPC"; return; fi
  "$DOCKER" exec "$1" sh -c 'curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:${RPC_PORT:-5005}/' 2>/dev/null \
    | jq -r '.result.info.server_state // "unknown"' 2>/dev/null || echo unknown
}

sync_gate() { # CONTAINER STARTED_AT -> rc 0 if synced in budget and postfiatd untouched
  local c="$1" st0="$2" start now f off st sa
  start="$(date +%s)"
  while :; do
    now="$(date +%s)"
    f="$(chrony_facts 2>/dev/null)" || f=""
    off="$(get offset "$f")"; sa="$(started_at "$c")"; st="$(server_state "$c")"
    if [ -n "$f" ] && [ -n "$(get selected "$f")" ] && [ "$(get nts "$f")" -ge "$MIN_NTS" ] \
       && [ "$(get leap "$f")" != "Not synchronised" ] && num_le "$(abs "${off:-9}")" "$OFFSET_WARN" \
       && num_le "$(get disp "$f")" "${DISP_WARN}" \
       && [ "$sa" = "$st0" ] && [ "$st" = full ]; then
      echo "$(ts) sync gate: PASS after $((now - start)) s (selected $(get selected "$f"), $(get nts "$f") NTS sources, offset $off s, root dispersion $(get disp "$f") s, leap $(get leap "$f"); $c StartedAt unchanged, server_state full)"
      return 0
    fi
    if [ $((now - start)) -ge "$SYNC_BUDGET" ]; then
      echo "$(ts) sync gate: FAIL after $((now - start)) s (selected=$(get selected "$f") nts=$(get nts "$f") offset=${off:-?} disp=$(get disp "$f") leap=$(get leap "$f"); StartedAt $([ "$sa" = "$st0" ] && echo unchanged || echo CHANGED), server_state=$st${INJECT:+; injected=$INJECT})"
      return 1
    fi
    sleep "$POLL_SEC"
  done
}

cmd_apply() {
  local yes=0 a b c st0 n f
  for a in "$@"; do case "$a" in --yes) yes=1 ;; *) die "apply: unknown option $a" 3 ;; esac; done
  [ "$yes" = 1 ] || die "apply changes the host's time daemon; re-run with --yes (see 'plan')" 4
  [ -n "$R" ] || [ "$(id -u)" = 0 ] || die "apply must run as root" 4
  n="$(servers | wc -w)"; [ "$n" -ge "$MIN_NTS" ] || die "only $n NTS_SERVERS (< MIN_NTS $MIN_NTS)" 4
  [ -x "$R$TOOL_PATH" ] || die "$TOOL_PATH is not installed (chrony's boot-gate drop-in runs it): run install.sh first" 4
  [ -e "$POLICY_RC" ] && die "$POLICY_RC exists (another tool controls service starts); refusing" 4
  c="$(container)"; [ -n "$c" ] || die "no postfiatd container found (set CONTAINER)" 4
  st0="$(started_at "$c")"; [ -n "$st0" ] || die "cannot read $c StartedAt" 4

  echo "$(ts) apply: before"; cmd_audit | sed 's/^/  /'
  if [ "$(pkg_ver chrony)" != "" ] && "$SYSTEMCTL" is-active --quiet chrony && [ "$(chrony_conf_text)" = "$(cat "$CHRONY_CONF" 2>/dev/null)" ] \
     && [ "$(dropin_text)" = "$(cat "$DROPIN" 2>/dev/null)" ]; then
    echo "$(ts) apply: already applied (chrony active, chrony.conf and drop-in identical), nothing changed"; return 0
  fi
  # 1. preflight: nothing changes until every rollback ingredient is in place
  b="$(make_backup)" || die "backup failed" 4
  echo "$(ts) apply: backup $b"; sed 's/^/  /' "$b/files.tsv" "$b/state"
  if [ -n "$(pkg_ver systemd-timesyncd)" ]; then
    (cd "$b" && "$APTGET" download -q "systemd-timesyncd=$(pkg_ver systemd-timesyncd)" >/dev/null 2>&1)
    ls "$b"/systemd-timesyncd_*.deb >/dev/null 2>&1 || die "cannot cache systemd-timesyncd $(pkg_ver systemd-timesyncd) .deb for rollback; nothing changed" 4
    echo "$(ts) apply: cached $(basename "$b"/systemd-timesyncd_*.deb) for rollback"
  fi
  if [ -z "$(pkg_ver chrony)" ]; then
    DEBIAN_FRONTEND=noninteractive "$APTGET" install -y -q --download-only chrony >/dev/null 2>&1 || die "cannot download chrony; nothing changed" 4
  fi
  # 2. change
  echo "$(ts) apply: $c StartedAt $st0; stopping timesyncd, installing chrony (package start blocked by policy-rc.d)"
  "$SYSTEMCTL" stop systemd-timesyncd 2>/dev/null
  printf '#!/bin/sh\n# pft-timesync apply: block package-triggered service starts during the chrony install\nexit 101\n' > "$POLICY_RC"; chmod 0755 "$POLICY_RC"
  if [ -z "$(pkg_ver chrony)" ]; then
    DEBIAN_FRONTEND=noninteractive "$APTGET" install -y -q -o Dpkg::Options::=--force-confold chrony >/dev/null 2>&1; a=$?
  else a=0; fi
  rm -f "$POLICY_RC"
  if [ "$a" != 0 ]; then echo "$(ts) apply: apt-get install chrony failed (rc $a) -> automatic rollback"; do_rollback "$b" || return 5; return 1; fi
  mkdir -p "$(dirname "$CHRONY_CONF")" "$(dirname "$DROPIN")"
  chrony_conf_text > "$CHRONY_CONF.pft-new"
  if ! "$CHRONYD" -p -f "$CHRONY_CONF.pft-new" >/dev/null 2>&1; then
    rm -f "$CHRONY_CONF.pft-new"; echo "$(ts) apply: chronyd -p rejects the candidate chrony.conf -> automatic rollback"; do_rollback "$b" || return 5; return 1
  fi
  mv -f "$CHRONY_CONF.pft-new" "$CHRONY_CONF"; dropin_text > "$DROPIN"
  "$SYSTEMCTL" daemon-reload
  "$SYSTEMCTL" disable systemd-timesyncd >/dev/null 2>&1
  "$SYSTEMCTL" enable chrony >/dev/null 2>&1; "$SYSTEMCTL" restart chrony
  echo "$(ts) apply: chrony started ($(servers | wc -w) NTS servers${INJECT:+, injected=$INJECT}); sync gate budget ${SYNC_BUDGET} s"
  # 3. gate
  if sync_gate "$c" "$st0"; then
    echo "$(ts) apply: after"; cmd_audit | sed 's/^/  /'
    echo "$(ts) apply: PASS"; return 0
  fi
  echo "$(ts) apply: sync gate missed -> automatic rollback"; do_rollback "$b" || return 5
  echo "  $c StartedAt $(started_at "$c") ($([ "$(started_at "$c")" = "$st0" ] && echo unchanged || echo CHANGED)), server_state $(server_state "$c")"
  return 1
}

cmd_rollback() {
  local b
  [ "${1:-}" = --yes ] || die "rollback changes the host's time daemon; re-run with --yes" 4
  [ -n "$R" ] || [ "$(id -u)" = 0 ] || die "rollback must run as root" 4
  b="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)"
  [ -n "$b" ] && [ -f "$b/files.tsv" ] || die "no backup in $BACKUP_DIR" 2
  do_rollback "$b" || return 5
}

case "${1:-}" in
  audit) shift; cmd_audit "$@" ;;
  plan) cmd_plan ;;
  apply) shift; cmd_apply "$@" ;;
  rollback) shift; cmd_rollback "$@" ;;
  metrics) cmd_metrics ;;
  boot-gate) cmd_boot_gate ;;
  *) sed -n '8,13p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
