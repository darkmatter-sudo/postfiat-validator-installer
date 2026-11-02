#!/usr/bin/env bash
# pft-apparmor: replace Docker's generic docker-default AppArmor profile on the postfiatd container with a tailored,
# least-privilege profile (pft-postfiatd) on a Post Fiat validator or sentry host (Ubuntu 22.04, AppArmor 3.0,
# postfiatd 1.0.9 in Docker). It keeps the confine/ runtime profile (cap_drop ALL + SETGID SETUID, read-only root,
# noexec tmpfs, no-new-privileges) and the mounts/ host options; AppArmor is one more layer under them.
#
# Usage: pft-apparmor audit [--json] [--prom FILE | --textfile] [--since SEC]
#        sudo pft-apparmor learn --out FILE [--minutes N]   (throwaway container under a complain profile)
#        pft-apparmor events [--since-epoch T] [--profile P]  (normalized learn events from the audit log, TSV)
#        pft-apparmor generate --events FILE [--caps "SETGID SETUID"] [--name P]   (profile on stdout)
#        pft-apparmor check FILE                            (apparmor_parser -Q -K: parse + compile, load nothing)
#        sudo pft-apparmor apply --profile-file FILE [--complain] --yes   (inside a pft-maint window)
#        sudo pft-apparmor rollback --yes                   (undo the last apply; inside a pft-maint window)
#        sudo pft-apparmor pull                             (validator: copy the peer's textfile, see install.sh --pull)
#        pft-apparmor validate FILE HOST                    (the check pull applies to a fetched textfile)
#        sudo pft-apparmor ack-denials --reason TEXT [--until EPOCH] --yes   (after investigating DENIED records)
#
#  audit     read-only. One line per check: PASS / FAIL / WARN / INFO.
#              kernel     /sys/module/apparmor/parameters/enabled = Y
#              parser     apparmor_parser present
#              loaded     PROFILE is loaded in the kernel (and its mode)
#              container  the container runs under PROFILE (FAIL: docker-default or unconfined)
#              mode       PROFILE is in enforce mode (WARN: complain = logs only, blocks nothing)
#              boot       /etc/apparmor.d/PROFILE exists, defines PROFILE and parses; apparmor.service enabled
#                         (it loads /etc/apparmor.d before docker.service starts the container at boot)
#              recreate   the container's re-create path keeps the profile: compose = a listed compose file sets
#                         security_opt apparmor=PROFILE; docker run = the container's own HostConfig (restart keeps it)
#              confine:*  cap_drop ALL, read-only root, no-new-privileges still set (confine/ must not be undone)
#              denials    apparmor="DENIED" events for PROFILE in /var/log/audit/audit.log* during the last --since
#                         seconds (default 86400). WARN with the top three operation+path pairs. Records up to
#                         an acknowledged time (ack-denials) are not counted; a malformed ack file is a FAIL.
#  learn     loads a COMPLAIN copy of a seed profile (abstractions/base + network, nothing else) as PROFILE-learn,
#            starts a throwaway container with the live container's confine arguments (same image, caps, tmpfs,
#            read-only, pids/memory) but fresh anonymous volumes, no published ports, under PROFILE-learn; waits for
#            server_state full, exercises it (RPC, cron's identity switch, every cron.daily job, the hourly cron
#            line, the crontab logrotate line, a forced rotation, e2scrub's cron lines, a container restart), keeps
#            it running --minutes (default 65, so real cron ticks at :00 and :17 run), then writes the normalized
#            events to --out, removes the container and unloads PROFILE-learn. The live container is not touched.
#            The seed allows inet/inet6/unix/netlink sockets: in complain mode every unlisted sendmsg/recvmsg is
#            logged, which flooded and rotated /var/log/audit within two minutes on a syncing node.
#  generate  builds the profile from a learn events file. Paths under TREES collapse to TREE/**, /proc/<pid>
#            becomes @{PROC}/@{pid}; masks: r, w (from w/a/c/d), k, l, m; executed files get ix (inherit: the
#            daemon cannot get its own sub-profile while no-new-privileges is set, see README). Capabilities =
#            learned + --caps; plus EXTRA_EXEC (error-path-only binaries). Then the docker-default deny block (verbatim) and an explicit `audit deny` block
#            (shadow files, writes to /usr /etc /boot, exec from writable trees, mount/ptrace/raw sockets...).
#            Refuses (exit 4) if any learned allow overlaps an explicit deny.
#  apply     refuses (exit 4, nothing changed) without --yes, without an active pft-maint window holding
#            2*HEALTH_BUDGET+MAINT_MARGIN s and no data-collection lock, when the node is not full, when the
#            container is not confined (read-only root + no-new-privileges), when FILE does not define PROFILE or
#            does not compile, or when the last apply is still in place. Then: backs up an existing
#            /etc/apparmor.d/PROFILE, installs FILE there (enforce; --complain adds the complain flag for a
#            bounded learn window) and loads it (-r -W), and re-creates the container with apparmor=PROFILE:
#            compose = docker-compose.apparmor.yml + COMPOSE_FILE in .env (backed up), `docker compose up -d`;
#            docker run = stop, rename to NAME-preaa-<id> (kept, restart=no), `docker run` with the old
#            container's own arguments (name, restart, user, logging, network, ports, volumes, env, caps,
#            read-only, tmpfs, pids, memory, security_opt). Gate (HEALTH_BUDGET s, every POLL_SEC s): re-created,
#            runs under PROFILE in the wanted kernel mode, server_state full, peers >= MIN_PEERS, the confine
#            signature (every field above except the AppArmor profile) unchanged, every running pft-* service
#            still active; then RPC + cron identity switch + the hourly cron run + ps, and 0 DENIED records for
#            PROFILE since the start. Any failure, a failed step or SIGINT/SIGTERM -> automatic rollback.
#            Finally pft-integrity accept, only if every changed item is the container or its compose files.
#  ack-denials  records in STATE_DIR/denials-ack.json that the DENIED records for PROFILE up to --until (default
#            now, never in the future) were investigated (--reason, required, printed by every later audit). Used
#            after a drill's deliberate negative controls, so they do not hold the denials check at WARN for 24 h.
#  pull      runs PULL_SSH cat <peer's pft_apparmor_PEER_LABEL.prom> into TEXTFILE_DIR; the file must pass validate
#            (only pft_apparmor_* samples for that host label, a last_run sample, <= 64 KiB), else the last good
#            copy is kept (exit 2). The sentry runs no Prometheus: its alerts are evaluated from this copy.
#  rollback  restores the previous container (compose: .env byte-identical, override removed; run: the kept
#            NAME-preaa-<id>), the previous profile file (or removes + unloads PROFILE), and runs the same gate
#            for the previous profile. Exit 5 if the rollback gate does not pass.
#
# Exit codes: 0 PASS / ok, 1 findings (audit) / gate failed and rolled back (apply), 2 error, 3 usage, 4 refused,
#             5 rollback did not pass its gate, 6 interrupted (rolled back).
# Config: /etc/pft-apparmor.env (KEY=VALUE, read, never sourced): HOST_LABEL (validator), PROFILE (pft-postfiatd),
#         PEER_LABEL (sentry), PULL_SSH (validator only: command prefix that reaches the peer, e.g.
#         "runuser -u OP -- ssh -o BatchMode=yes X")  PULL_TIMEOUT (30 s, env)
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  TEXTFILE_DIR  LEARN_DIR (/var/lib/pft-apparmor)
#      TREES (directories collapsed to DIR/{,**})  EXTRA_EXEC (/usr/bin/logger)
#      SYNC_BUDGET (1200 s for the throwaway to reach full)
#      STATE_DIR (LEARN_DIR: apply-CONTAINER.json, backup/)  HEALTH_BUDGET (900)  POLL_SEC (10)
#      MAINT_MARGIN (300)  MIN_PEERS (1)  PFT_AA_INJECT=health (apply's gate fails: live automatic-rollback drill)
#      Test hooks: PFT_AA_ROOT (path prefix for every file)  PFT_AA_DOCKER / _PARSER / _SYSTEMCTL / _MAINT /
#      _INTEGRITY (commands)
#      PFT_AA_NOW (unix time)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_AA_ROOT:-}"
DOCKER="${PFT_AA_DOCKER:-docker}"
PARSER="${PFT_AA_PARSER:-apparmor_parser}"
SYSTEMCTL="${PFT_AA_SYSTEMCTL:-systemctl}"
CONF="$R/etc/pft-apparmor.env"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
LEARN_DIR="${LEARN_DIR:-$R/var/lib/pft-apparmor}"
SYNC_BUDGET="${SYNC_BUDGET:-1200}"
MAINT="${PFT_AA_MAINT:-pft-maint}"
INTEGRITY="${PFT_AA_INTEGRITY:-pft-integrity}"
STATE_DIR="${STATE_DIR:-$LEARN_DIR}"
HEALTH_BUDGET="${HEALTH_BUDGET:-900}"
POLL_SEC="${POLL_SEC:-10}"
MAINT_MARGIN="${MAINT_MARGIN:-300}"
MIN_PEERS="${MIN_PEERS:-1}"
INJECT="${PFT_AA_INJECT:-}" # "health": apply's gate fails (live automatic-rollback drill)
NOJ='{}'
# Executables a learn run cannot see because only error paths call them: /etc/cron.daily/logrotate runs
# `logger` only when logrotate fails (enforce probe 04 denied it).
EXTRA_EXEC="${EXTRA_EXEC-/usr/bin/logger}" # set and empty = none
TREES="${TREES:-/var/lib/postfiatd/db/ /var/log/postfiatd/ /etc/postfiatd/ /var/backups/ /var/lib/logrotate/ /var/lib/apt/ /var/opt/postfiat/ /run/ /tmp/ /var/lib/dpkg/alternatives/ /etc/logrotate.d/ /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ /var/spool/cron/}"

die() { echo "pft-apparmor: $1" >&2; exit "${2:-2}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
now() { echo "${PFT_AA_NOW:-$(date +%s)}"; }
conf_get() { # KEY DEFAULT: value from the env file (never sourced), else DEFAULT
  local v=""
  [ -r "$CONF" ] && v="$(sed -n "s/^$1=//p" "$CONF" | tail -1 | tr -d '"'"'")"
  echo "${v:-$2}"
}
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]]; }
HOST_LABEL="$(conf_get HOST_LABEL validator)"
PROFILE="$(conf_get PROFILE pft-postfiatd)"
valid_label "$PROFILE" || die "bad PROFILE in $CONF" 2
ACK_FILE="$STATE_DIR/denials-ack.json"
PEER_LABEL="$(conf_get PEER_LABEL sentry)"
PULL_SSH="$(conf_get PULL_SSH "")"; PULL_TIMEOUT="${PULL_TIMEOUT:-30}"

pick_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}

# ---------------------------------------------------------------------------------------------------- audit
RESULTS=""; FINDINGS=0; DENIED=0; ACKED_UNTIL=0
add() { # STATUS CHECK DETAIL
  RESULTS+="$1"$'\t'"$2"$'\t'"$3"$'\n'
  case "$1" in FAIL|WARN) FINDINGS=$((FINDINGS + 1)) ;; esac
}

loaded_mode() { # PROFILE -> enforce|complain|"" (from the kernel's profile list)
  local f="$R/sys/kernel/security/apparmor/profiles"
  [ -r "$f" ] || { echo "unreadable"; return; }
  awk -v p="$1" '$1 == p { gsub(/[()]/, "", $2); print $2; exit }' "$f"
}

denials() { # SINCE_EPOCH PROFILE -> "COUNT<TAB>top3 summary"
  local f files=()
  for f in "$R"/var/log/audit/audit.log*; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || { printf '0\tno readable audit log\n'; return 1; }
  cat -- "${files[@]}" | awk -v t="$1" -v p="$2" '
    index($0, "apparmor=\"DENIED\"") && (index($0, "profile=\"" p "\"") || index($0, "profile=\"" p "//")) {
      if (!match($0, /audit\([0-9]+/)) next
      e = substr($0, RSTART + 6, RLENGTH - 6) + 0
      if (e < t + 0) next
      n++; op = ""; nm = ""
      if (match($0, /operation="[^"]*"/)) op = substr($0, RSTART + 11, RLENGTH - 12)
      if (match($0, / name="[^"]*"/)) nm = substr($0, RSTART + 7, RLENGTH - 8)
      k[op " " nm]++
    }
    END {
      s = ""; for (i = 0; i < 3; i++) { b = ""; bn = 0; for (x in k) if (k[x] > bn) { bn = k[x]; b = x }
        if (bn == 0) break; s = s (s == "" ? "" : "; ") b " x" bn; delete k[b] }
      printf "%d\t%s\n", n + 0, s
    }'
}

audit_checks() {
  local c="$1" since="$2" en m ins prof cfgs f found=0 d
  en="$(cat "$R/sys/module/apparmor/parameters/enabled" 2>/dev/null)"
  [ "$en" = Y ] && add PASS kernel "AppArmor enabled in the kernel" || add FAIL kernel "AppArmor not enabled (enabled='${en:-missing}')"
  command -v "$PARSER" >/dev/null 2>&1 && add PASS parser "$PARSER present" || add FAIL parser "$PARSER not found (package apparmor)"
  m="$(loaded_mode "$PROFILE")"
  case "$m" in
    enforce|complain) add PASS loaded "$PROFILE loaded ($m)" ;;
    unreadable) add FAIL loaded "kernel profile list unreadable (run as root)" ;;
    *) add FAIL loaded "$PROFILE not loaded" ;;
  esac
  if ins="$("$DOCKER" inspect "$c" 2>/dev/null)" && [ "$(jq 'length' <<<"$ins")" = 1 ]; then
    prof="$(jq -r '.[0].AppArmorProfile // ""' <<<"$ins")"
    case "$prof" in
      "$PROFILE") add PASS container "$c runs under $PROFILE" ;;
      docker-default) add FAIL container "$c runs under docker-default (generic profile)" ;;
      ""|unconfined) add FAIL container "$c runs unconfined" ;;
      *) add FAIL container "$c runs under '$prof', not $PROFILE" ;;
    esac
    if [ "$prof" = "$PROFILE" ]; then
      case "$m" in
        enforce) add PASS mode "$PROFILE enforce" ;;
        complain) add WARN mode "$PROFILE in complain mode: logs, blocks nothing" ;;
        *) add FAIL mode "$PROFILE mode unknown ('$m')" ;;
      esac
    else
      add INFO mode "not graded: container not under $PROFILE"
    fi
    cfgs="$(jq -r '.[0].Config.Labels["com.docker.compose.project.config_files"] // ""' <<<"$ins")"
    if [ -n "$cfgs" ]; then
      IFS=, read -r -a fl <<<"$cfgs"
      for f in "${fl[@]}"; do
        grep -qE "apparmor[=:] *\"?$PROFILE\"?" "$R$f" 2>/dev/null && found=1
      done
      [ "$found" = 1 ] && add PASS recreate "compose file sets apparmor=$PROFILE" \
        || add FAIL recreate "no listed compose file sets apparmor=$PROFILE: the next 'docker compose up' drops it"
    else
      [ "$prof" = "$PROFILE" ] && add PASS recreate "docker run container: HostConfig keeps $PROFILE across restarts" \
        || add FAIL recreate "docker run container not created with apparmor=$PROFILE"
    fi
    jq -e '.[0].HostConfig.CapDrop // [] | map(ascii_upcase) | index("ALL") != null' <<<"$ins" >/dev/null \
      && add PASS confine:cap_drop "cap_drop ALL" || add FAIL confine:cap_drop "cap_drop ALL missing"
    jq -e '.[0].HostConfig.ReadonlyRootfs == true' <<<"$ins" >/dev/null \
      && add PASS confine:read_only "read-only root fs" || add FAIL confine:read_only "root fs writable"
    jq -e '.[0].HostConfig.SecurityOpt // [] | map(select(test("^no-new-privileges(:true|=true)?$"))) | length > 0' <<<"$ins" >/dev/null \
      && add PASS confine:nnp "no-new-privileges" || add FAIL confine:nnp "no-new-privileges missing"
  else
    add FAIL container "container $c not found"
  fi
  f="$R/etc/apparmor.d/$PROFILE"
  if [ ! -f "$f" ]; then add FAIL boot "$f missing: the profile is gone after a reboot"
  elif ! grep -qE "^profile ${PROFILE}[ {]" "$f"; then add FAIL boot "$f does not define profile $PROFILE"
  elif ! "$PARSER" -Q -K "$f" >/dev/null 2>&1; then add FAIL boot "$f does not parse"
  elif ! "$SYSTEMCTL" is-enabled apparmor.service >/dev/null 2>&1; then add FAIL boot "apparmor.service not enabled"
  else add PASS boot "$f parses; apparmor.service enabled"
  fi
  local eff="$since" note="" au
  if [ -e "$ACK_FILE" ]; then
    if ! au="$(jq -er --arg p "$PROFILE" 'select(type == "object" and .profile == $p and (.until | type) == "number" and (.reason | type) == "string") | .until' "$ACK_FILE" 2>/dev/null)" \
      || ! [[ "$au" =~ ^[0-9]+$ ]]; then
      add FAIL denials-ack "$ACK_FILE unreadable, malformed or for another profile: no DENIED record is treated as acknowledged"
    else
      ACKED_UNTIL="$au"
      if [ "$au" -ge "$since" ]; then
        eff=$((au + 1))
        note="; up to $(date -u -d "@$au" +%FT%TZ) acknowledged: $(jq -r '.reason' "$ACK_FILE" | tr -cd '[:print:]' | cut -c1-120)"
      fi
    fi
  fi
  if ! d="$(denials "$eff" "$PROFILE")"; then DENIED=0; add FAIL denials "${d#*$'\t'} (run as root)"
  else
    DENIED="${d%%$'\t'*}"
    if [ "$DENIED" = 0 ]; then add PASS denials "0 DENIED events in the last $(( $(now) - since ))s$note"
    else add WARN denials "$DENIED DENIED event(s) in the last $(( $(now) - since ))s: ${d#*$'\t'}$note"
    fi
  fi
}

print_results() {
  local c="$1"
  if [ "$JSON" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg h "$HOST_LABEL" --arg c "$c" --arg p "$PROFILE" --arg t "$(ts)" \
      --argjson n "$FINDINGS" --argjson d "$DENIED" --argjson a "$ACKED_UNTIL" '
      {host: $h, container: $c, profile: $p, time: $t, findings: $n, denied_events: $d, denied_acknowledged_until: $a,
       checks: (split("\n") | map(select(length > 0) | split("\t") | {status: .[0], check: .[1], detail: .[2]}))}'
  else
    echo "pft-apparmor audit - $(ts) | host $HOST_LABEL | container $c | profile $PROFILE"
    printf '%s' "$RESULTS" | awk -F'\t' '{printf "  [%-4s] %-18s %s\n", $1, $2, $3}'
    echo "RESULT: $([ "$FINDINGS" = 0 ] && echo PASS || echo "FAIL - $FINDINGS finding(s)")"
  fi
}

write_prom() { # FILE: node_exporter textfile, written atomically
  local f="$1" tmp h="$HOST_LABEL"
  tmp="$(mktemp "${f}.XXXXXX")" || return 2
  {
    echo "# HELP pft_apparmor_check 1 if the AppArmor check passes, 0 if FAIL or WARN."
    echo "# TYPE pft_apparmor_check gauge"
    printf '%s' "$RESULTS" | awk -F'\t' -v h="$h" '$1 != "INFO" { printf "pft_apparmor_check{host=\"%s\",check=\"%s\",status=\"%s\"} %d\n", h, $2, $1, ($1 == "PASS") }'
    echo "# HELP pft_apparmor_findings Number of FAIL + WARN AppArmor checks."
    echo "# TYPE pft_apparmor_findings gauge"
    echo "pft_apparmor_findings{host=\"$h\"} $FINDINGS"
    echo "# HELP pft_apparmor_denied_events DENIED events for the profile in the audit window."
    echo "# TYPE pft_apparmor_denied_events gauge"
    echo "pft_apparmor_denied_events{host=\"$h\"} $DENIED"
    echo "# HELP pft_apparmor_last_run_timestamp_seconds Unix time of the last completed audit."
    echo "# TYPE pft_apparmor_last_run_timestamp_seconds gauge"
    echo "pft_apparmor_last_run_timestamp_seconds{host=\"$h\"} $(now)"
  } > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$f"
}

validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout (a pulled file must look like ours)
  local f="$1" h="$2" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le 65536 ] || { echo "larger than 65536 bytes"; return 1; }
  n="$(grep -cvE '^(# (HELP|TYPE) pft_apparmor_.*|pft_apparmor_[a-z_]+\{host="'"$h"'"(,[a-z]+="[A-Za-z0-9_./:-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^pft_apparmor_last_run_timestamp_seconds\{host="'"$h"'"\} [0-9]+$' "$f" || { echo "no last_run sample"; return 1; }
  return 0
}

do_pull() { # validator: the peer's textfile through PULL_SSH; a file that fails validate never replaces the last good one
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$TEXTFILE_DIR/.pft_apparmor_$PEER_LABEL.prom.pull"
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "/var/lib/pft-exporter/textfile/pft_apparmor_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "pulled file rejected: $why" 2; fi
  chmod 0644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_apparmor_$PEER_LABEL.prom"
}

do_ack() { # UNTIL REASON: acknowledge the DENIED records up to UNTIL
  local u="$1" why="$2" prev=0 a b n tmp
  [[ "$u" =~ ^[0-9]+$ ]] && [ "$u" -le "$(now)" ] || die "--until must be a unix time, not in the future" 3
  [ -n "$why" ] && [ "${#why}" -le 200 ] && [[ "$why" != *[![:print:]]* ]] || die "--reason: 1-200 printable characters" 3
  if [ -e "$ACK_FILE" ]; then
    prev="$(jq -er --arg p "$PROFILE" 'select(.profile == $p) | .until | select(type == "number")' "$ACK_FILE" 2>/dev/null)" || prev=0
  fi
  [ "$u" -gt "$prev" ] || die "already acknowledged up to $prev" 4
  a="$(denials "$((prev + 1))" "$PROFILE")" || die "audit log unreadable (run as root)" 2
  b="$(denials "$((u + 1))" "$PROFILE")" || die "audit log unreadable (run as root)" 2
  n=$(( ${a%%$'\t'*} - ${b%%$'\t'*} ))
  mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR" 2
  tmp="$(mktemp "$ACK_FILE.XXXXXX")" || die "cannot write $ACK_FILE" 2
  jq -n --arg p "$PROFILE" --argjson u "$u" --argjson n "$n" --arg r "$why" --arg t "$(ts)" \
    '{profile: $p, until: $u, records: $n, reason: $r, at: $t}' > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$ACK_FILE" \
    || { rm -f "$tmp"; die "cannot write $ACK_FILE" 2; }
  echo "$(ts) ack-denials: $n DENIED record(s) for $PROFILE after $prev up to $u ($(date -u -d "@$u" +%FT%TZ)) acknowledged: $why"
}

# ---------------------------------------------------------------------------------------------------- events
# One TSV line per distinct (kind, key, mask): file<TAB>/path<TAB>mask | exec<TAB>/path<TAB>x | cap<TAB>name<TAB>- | extra<TAB>/path<TAB>x (hand-added) |
# net<TAB>family sock_type<TAB>- . Socket addresses are dropped (they identify peers), so the file is publishable.
normalize_events() { # SINCE_EPOCH PROFILE_PREFIX < audit lines
  awk -v t="$1" -v p="$2" '
    function field(k,   r) { if (match($0, " " k "=\"[^\"]*\"")) { r = substr($0, RSTART + length(k) + 3, RLENGTH - length(k) - 4); return r } return "" }
    index($0, "apparmor=\"ALLOWED\"") || index($0, "apparmor=\"DENIED\"") {
      if (!index($0, "profile=\"" p)) next
      if (!match($0, /audit\([0-9]+/)) next
      if (substr($0, RSTART + 6, RLENGTH - 6) + 0 < t + 0) next
      op = field("operation"); nm = field("name"); mk = field("requested_mask")
      if (op == "capable") { print "cap\t" field("capname") "\t-"; next }
      if (op == "exec") { print "exec\t" nm "\tx"; next }
      if (nm == "" || substr(nm, 1, 1) != "/") { f = field("family"); if (f != "") print "net\t" f " " field("sock_type") "\t-"; next }
      if (mk != "") print "file\t" nm "\t" mk
    }' | LC_ALL=C sort -u
}

collect_events() { # SINCE_EPOCH PROFILE_PREFIX -> normalized events from every readable audit log
  local f files=()
  for f in "$R"/var/log/audit/audit.log*; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || die "no readable /var/log/audit/audit.log* (run as root)" 2
  cat -- "${files[@]}" | normalize_events "$1" "$2"
}

# ---------------------------------------------------------------------------------------------------- generate
DENY_BLOCK='  # --- docker-default (moby profiles/apparmor/template.go), kept verbatim ---
  deny @{PROC}/* w,
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9/]*}/** w,
  deny @{PROC}/sys/[^k]** w,
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,
  deny mount,
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,'

# Explicit, logged denials (pft-apparmor additions). Kept in one list so generate can refuse overlaps.
# /etc/shadow is NOT denied: cron's pam_unix (account) reads it before every job (learn run 2026-11-02, 07:17:02Z
# hourly tick); it is the image's own file, not the host's.
AUDIT_DENY=(
  "/etc/gshadow rwklx" "/etc/shadow- rwklx" "/etc/gshadow- rwklx" "/etc/shadow wl"
  "/usr/** wl" "/etc/** wl" "/boot/** rwklx" "/root/** rwklx" "/home/** rwklx" "/var/lib/docker/** rwklx"
  "/tmp/** x" "/run/** x" "/var/** x" "/dev/shm/** x" "/var/lib/postfiatd/** x" "/var/log/** x" "/etc/postfiatd/** x"
)
AUDIT_DENY_OTHER='  audit deny umount,
  audit deny pivot_root,
  audit deny ptrace (trace,tracedby),
  audit deny network inet raw,
  audit deny network inet6 raw,
  audit deny network packet,
  audit deny capability sys_admin,
  audit deny capability sys_module,
  audit deny capability sys_ptrace,
  audit deny capability net_admin,
  audit deny capability net_raw,
  audit deny capability dac_override,
  audit deny capability dac_read_search,'

norm_path() { # PATH -> rule path (TREE/** for paths under TREES, @{PROC}/@{pid} for /proc/<n>)
  local p="$1" t
  p="$(sed -E 's#^/proc/[0-9]+/task/[0-9]+/#@{PROC}/@{pid}/task/@{tid}/#; s#^/proc/[0-9]+/#@{PROC}/@{pid}/#; s#^/proc/#@{PROC}/#' <<<"$p")"
  for t in $TREES; do # TREE{,**}: TREE/** alone does not match the directory TREE/ itself (enforce probe 04)
    case "$p" in "$t"*) echo "$t{,**}"; return ;; "${t%/}") echo "$t{,**}"; return ;; esac
  done
  echo "$p"
}

mask_norm() { # audit mask -> rule mask in canonical order (r w k l m); a/c/d -> w
  local m="$1" o=""
  [[ "$m" == *r* ]] && o+=r
  [[ "$m" =~ [wacd] ]] && o+=w
  [[ "$m" == *k* ]] && o+=k
  [[ "$m" == *l* ]] && o+=l
  [[ "$m" == *m* ]] && o+=m
  echo "$o"
}

glob_re() { # AppArmor glob (only ** and * used in AUDIT_DENY) -> ERE
  sed -E 's/[.+?()|^$]/\\&/g; s/\*\*/\x01/g; s/\*/[^\/]*/g; s/\x01/.*/g' <<<"$1"
}

overlaps() { # RULEPATH RULEMASK -> prints the deny entry an allow would hit, rc 0 if any
  local p="$1" m="$2" d dp dm c hit=1 probe
  probe="${p//\{,\*\*\}/x/y}"; probe="${probe//\*\*/x/y}"; probe="${probe//@\{PROC\}/\/proc}"; probe="${probe//@\{pid\}/1}"; probe="${probe//@\{tid\}/1}"
  for d in "${AUDIT_DENY[@]}"; do
    dp="${d% *}"; dm="${d##* }"
    [[ "$probe" =~ ^$(glob_re "$dp")$ ]] || continue
    for ((c = 0; c < ${#m}; c++)); do
      [[ "$dm" == *"${m:c:1}"* ]] && { echo "$d"; hit=0; break; }
    done
  done
  return $hit
}

do_generate() { # EVENTS CAPS NAME
  local ev="$1" caps="$2" name="$3" kind key mask rp k bad=0 x
  [ -r "$ev" ] || die "cannot read $ev" 2
  declare -A FM=() EX=() CAP=()
  while IFS=$'\t' read -r kind key mask; do
    case "$kind" in
      file) rp="$(norm_path "$key")"; FM[$rp]="${FM[$rp]:-}$mask" ;;
      exec) EX[$(norm_path "$key")]=1 ;;
      cap) [ -n "$key" ] && CAP[$key]=1 ;;
      extra) EX[$key]=1 ;;
      net|"") ;;
      *) die "unknown event kind '$kind' in $ev" 2 ;;
    esac
  done < "$ev"
  for k in $caps; do k="${k,,}"; CAP[${k#cap_}]=1; done
  for k in $EXTRA_EXEC; do EX[$k]=1; done
  for k in "${!FM[@]}"; do FM[$k]="$(mask_norm "${FM[$k]}")"; [ -n "${FM[$k]}" ] || unset 'FM[$k]'; done
  for k in "${!FM[@]}"; do
    x="$(overlaps "$k" "${FM[$k]}")" && { echo "pft-apparmor: learned allow '$k ${FM[$k]}' overlaps audit deny '$x'" >&2; bad=1; }
  done
  for k in "${!EX[@]}"; do
    x="$(overlaps "$k" x)" && { echo "pft-apparmor: learned exec '$k' overlaps audit deny '$x'" >&2; bad=1; }
  done
  [ "$bad" = 0 ] || exit 4
  echo "# AppArmor profile $name for the postfiatd container. Generated by pft-apparmor generate from $(basename "$ev")"
  echo "# (sha256 $(sha256sum < "$ev" | cut -c1-64)). Load: apparmor_parser -r -W /etc/apparmor.d/$name"
  echo "abi <abi/3.0>,"
  echo "#include <tunables/global>"
  echo
  echo "profile $name flags=(attach_disconnected,mediate_deleted) {"
  echo "  #include <abstractions/base>"
  echo
  echo "  # sockets: peer protocol (2559), RPC/WS/gRPC listeners, resolver, cron/pam"
  echo "  network inet stream,"
  echo "  network inet6 stream,"
  echo "  network inet dgram,"
  echo "  network inet6 dgram,"
  echo "  network netlink raw,"
  echo "  network unix,"
  echo
  echo "  signal (receive) peer=unconfined,"
  echo "  signal (send,receive) peer=$name,"
  echo "  ptrace (read,readby) peer=$name,  # ps reads the other processes' /proc entries"
  echo
  echo "  # capabilities: learned + the container's cap_add (confine/)"
  printf '%s\n' "${!CAP[@]}" | LC_ALL=C sort | sed 's/^/  capability /; s/$/,/'
  echo
  echo "  # executables (ix: stay in this profile)"
  for k in "${!EX[@]}"; do
    if [[ "${FM[$k]:-}" == *r* ]]; then echo "  $k rix,"; else echo "  $k ix,"; fi
  done | LC_ALL=C sort
  echo
  echo "  # files"
  for k in "${!FM[@]}"; do
    [ -n "${EX[$k]:-}" ] && [ "${FM[$k]}" = r ] && continue
    echo "  $k ${FM[$k]},"
  done | LC_ALL=C sort
  echo
  echo "$DENY_BLOCK"
  echo
  echo "  # --- pft-apparmor explicit denials (logged) ---"
  for k in "${AUDIT_DENY[@]}"; do echo "  audit deny ${k% *} ${k##* },"; done
  echo "$AUDIT_DENY_OTHER"
  echo "}"
}

# ---------------------------------------------------------------------------------------------------- learn
seed_profile() { # NAME
  cat <<SEED
#include <tunables/global>
profile $1 flags=(attach_disconnected,mediate_deleted,complain) {
  #include <abstractions/base>
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,
  network unix,
  signal (receive) peer=unconfined,
  signal (send,receive) peer=$1,
}
SEED
}

learn_args() { # INSPECT_JSON LEARN_PROFILE -> docker run args, one per line (image + cmd last)
  jq -r --arg lp "$2" '.[0] as $i |
    "--security-opt=apparmor=\($lp)",
    ($i.HostConfig.SecurityOpt // [] | map(select(startswith("apparmor") | not))[] | "--security-opt=\(.)"),
    ($i.HostConfig.CapDrop // [] | .[] | "--cap-drop=\(.)"),
    ($i.HostConfig.CapAdd // [] | .[] | "--cap-add=\(.)"),
    (if $i.HostConfig.ReadonlyRootfs then "--read-only" else empty end),
    ($i.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\(.key):\(.value)"),
    ($i.Mounts // [] | .[] | "--volume=\(.Destination)"),
    (if ($i.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\($i.HostConfig.PidsLimit)" else empty end),
    (if ($i.HostConfig.Memory // 0) > 0 then "--memory=\($i.HostConfig.Memory)" else empty end),
    ($i.Config.User // "" | select(length > 0) | "--user=\(.)"),
    $i.Config.Image,
    ($i.Config.Cmd // [] | .[])' <<<"$1"
}

rpc_state() { # CONTAINER -> server_state or ""
  "$DOCKER" exec "$1" curl -s -m 10 -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null \
    | jq -r '.result.info.server_state // empty' 2>/dev/null
}

lx() { local rc; echo "\$ $*"; "$@"; rc=$?; echo "(exit $rc)"; return "$rc"; }

exercise() { # CONTAINER
  local c="$1" lr
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"peers"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" setpriv --reuid=0 --regid=0 --init-groups true
  lx "$DOCKER" exec "$c" sh -c 'cd / && run-parts --report /etc/cron.hourly'
  lx "$DOCKER" exec "$c" sh -c 'for j in /etc/cron.daily/*; do [ "${j##*/}" = apt-compat ] && continue; echo "cron.daily/${j##*/}"; "$j"; done'
  lr="$("$DOCKER" exec "$c" sh -c "grep -h logrotate /etc/cron.d/* 2>/dev/null | grep -v '^#' | head -1 | sed 's/^\([^ ]* *\)\{6\}//'")"
  [ -n "$lr" ] && lx "$DOCKER" exec "$c" sh -c "$lr"
  lx "$DOCKER" exec "$c" sh -c 'logrotate -f -s /var/log/postfiatd/.logrotate.status /etc/logrotate.d/postfiatd'
  lx "$DOCKER" exec "$c" sh -c 'test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r'
  lx "$DOCKER" exec "$c" sh -c 'test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron'
  lx "$DOCKER" exec "$c" ps -eo pid,comm
}

do_learn() { # OUT MINUTES
  local out="$1" min="$2" c ins lp tc t0 sp i st end
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "learn needs root" 4
  c="$(pick_container)"; ins="$("$DOCKER" inspect "$c" 2>/dev/null)" || die "container $c not found" 2
  lp="$PROFILE-learn"; tc="$c-aalearn-$(date -u +%Y%m%d%H%M%S)"
  mkdir -p "$LEARN_DIR" && chmod 0700 "$LEARN_DIR" || die "cannot create $LEARN_DIR" 2
  sp="$LEARN_DIR/$lp"; seed_profile "$lp" > "$sp"
  t0="$(now)"
  echo "$(ts) learn: seed $lp (complain), throwaway $tc from $c's confine arguments; T0=$t0"
  sed 's/^/  | /' "$sp"
  lx "$PARSER" -r -W "$sp" || die "cannot load $sp" 2
  cleanup() { "$DOCKER" rm -f "$tc" >/dev/null 2>&1; "$PARSER" -R "$sp" >/dev/null 2>&1; }
  trap 'cleanup; exit 6' INT TERM
  mapfile -t A < <(learn_args "$ins" "$lp")
  echo "\$ $DOCKER run -d --name $tc ${A[*]}"
  "$DOCKER" run -d --name "$tc" "${A[@]}" >/dev/null || { cleanup; die "throwaway did not start" 2; }
  echo "$(ts) profile: $("$DOCKER" inspect -f '{{.AppArmorProfile}}' "$tc")"
  st=""; for ((i = 0; i < SYNC_BUDGET / 10; i++)); do
    st="$(rpc_state "$tc")"; [ "$st" = full ] && break; sleep 10
  done
  echo "$(ts) throwaway server_state: ${st:-none} (after ~$((i * 10))s)"
  [ "$st" = full ] || { cleanup; die "throwaway never reached full" 2; }
  exercise "$tc"
  lx "$DOCKER" restart -t 30 "$tc" >/dev/null
  for ((i = 0; i < SYNC_BUDGET / 10; i++)); do st="$(rpc_state "$tc")"; [ "$st" = full ] && break; sleep 10; done
  echo "$(ts) after restart server_state: ${st:-none}"
  end=$((t0 + min * 60))
  while [ "$(now)" -lt "$end" ]; do sleep 30; done
  exercise "$tc"
  echo "$(ts) collecting events since T0 for profile prefix $lp"
  collect_events "$t0" "$lp" > "$out.tmp" && mv -f "$out.tmp" "$out" || { cleanup; die "event collection failed" 2; }
  awk -F'\t' '{n[$1]++} END {for (k in n) printf "  %s %d\n", k, n[k]}' "$out" | LC_ALL=C sort
  cleanup; trap - INT TERM
  echo "$(ts) learn: done, $(wc -l < "$out") distinct events -> $out; throwaway removed, $lp unloaded"
}

# ---------------------------------------------------------------------------------------------------- apply
inspect0() { "$DOCKER" inspect "$1" 2>/dev/null | jq -c '.[0] // empty' 2>/dev/null; }

# Everything a re-create must keep, i.e. all of confine/'s runtime profile and the container's identity, but NOT the
# AppArmor profile. Canonical JSON: apply's gate requires it unchanged, so a lost flag rolls back.
confine_sig() { # INSPECT0
  jq -cS '{image: .Config.Image, cmd: (.Config.Cmd // []), entrypoint: (.Config.Entrypoint // []),
    user: (.Config.User // ""), env: (.Config.Env // [] | sort),
    cap_add: (.HostConfig.CapAdd // [] | map(ascii_upcase | sub("^CAP_"; "")) | sort),
    cap_drop: (.HostConfig.CapDrop // [] | map(ascii_upcase) | sort),
    read_only: (.HostConfig.ReadonlyRootfs // false), tmpfs: (.HostConfig.Tmpfs // {}),
    pids: (.HostConfig.PidsLimit // 0), memory: (.HostConfig.Memory // 0), memory_swap: (.HostConfig.MemorySwap // 0),
    security_opt: (.HostConfig.SecurityOpt // [] | map(select(startswith("apparmor") | not)
                   | sub("^no-new-privileges([:=]true)?$"; "no-new-privileges")) | sort),
    mounts: (.Mounts // [] | map({type: .Type, name: (if .Type == "volume" then .Name else null end),
             source: (if .Type == "bind" then .Source else null end), dest: .Destination, rw: .RW}) | sort_by(.dest)),
    ports: (.HostConfig.PortBindings // {}), network: (.HostConfig.NetworkMode // ""), log: (.HostConfig.LogConfig // {})}' <<<"$1"
}
sig_diff() { # SIG_A SIG_B -> names of the keys that differ (values are not printed: env may hold secrets)
  jq -rn --argjson a "$1" --argjson b "$2" '[($a + $b) | keys[] | select($a[.] != $b[.])] | join(",")'
}

# docker run arguments that re-create a `docker run` container exactly (confine/'s recreate set: name, restart, user,
# logging, network, ports, volumes, env beyond the image's; plus its runtime profile: caps, read-only, tmpfs, pids,
# memory, security_opt) with apparmor=PROFILE instead of the current AppArmor profile. Image + cmd last.
run_args() { # INSPECT0 IMAGE_ENV_JSON PROFILE
  jq -r --argjson ienv "$2" --arg p "$3" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if (.Config.User // "") != "" then "--user=\(.Config.User)" else empty end),
    "--log-driver=\(.HostConfig.LogConfig.Type)",
    ((.HostConfig.LogConfig.Config // {}) | to_entries[] | "--log-opt=\(.key)=\(.value)"),
    (if (.HostConfig.NetworkMode // "default") != "default" then "--network=\(.HostConfig.NetworkMode)" else empty end),
    ((.HostConfig.PortBindings // {}) | to_entries[] | .key as $k | .value[]
      | "--publish=\(if (.HostIp // "") != "" then .HostIp + ":" else "" end)\(.HostPort):\($k | sub("/tcp$"; ""))"),
    (.Mounts // [] | .[] | if .Type == "volume" then "--volume=\(.Name):\(.Destination)\(if .RW then "" else ":ro" end)"
                           elif .Type == "bind" then "--volume=\(.Source):\(.Destination)\(if .RW then "" else ":ro" end)"
                           else empty end),
    (.Config.Env // [] | map(select(. as $e | $ienv | index($e) | not)) | .[] | "--env=\(.)"),
    (.HostConfig.CapDrop // [] | .[] | "--cap-drop=\(.)"),
    (.HostConfig.CapAdd // [] | .[] | "--cap-add=\(.)"),
    (if .HostConfig.ReadonlyRootfs then "--read-only" else empty end),
    (.HostConfig.Tmpfs // {} | to_entries[] | "--tmpfs=\(.key):\(.value)"),
    (if (.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\(.HostConfig.PidsLimit)" else empty end),
    (if (.HostConfig.Memory // 0) > 0 then "--memory=\(.HostConfig.Memory)" else empty end),
    (if (.HostConfig.MemorySwap // 0) != 0 then "--memory-swap=\(.HostConfig.MemorySwap)" else empty end),
    (.HostConfig.SecurityOpt // [] | map(select(startswith("apparmor") | not))[] | "--security-opt=\(.)"),
    "--security-opt=apparmor=\($p)",
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}
show_args() { # args on stdin, one per line -> one line, env values and IPv4 addresses masked (publishable)
  sed -E 's/^(--env=[^=]*)=.*/\1=<value>/; s/([0-9]{1,3}\.){3}[0-9]{1,3}/<redacted-ip>/g' | paste -sd' '
}

maint_gate() { # -> "ok <remaining>" or "refuse <reason>"; apply + a possible rollback must fit the window
  local j w rem nl need=$((2 * HEALTH_BUDGET + MAINT_MARGIN))
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "refuse pft-maint status failed (is pft-maint installed?)"; return; }
  w="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"
  rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"; [[ "$rem" =~ ^[0-9]+$ ]] || rem=0
  nl="$(jq -r '.locks | length' <<<"$j" 2>/dev/null)"; [[ "$nl" =~ ^[0-9]+$ ]] || nl=1
  if [ "$w" != active ]; then echo "refuse no active pft-maint window (window=${w:-none}); run: sudo pft-maint start --ttl 45m --reason ..."
  elif [ "$rem" -lt "$need" ]; then echo "refuse window has ${rem}s left, needs 2*HEALTH_BUDGET+MAINT_MARGIN=${need}s"
  elif [ "$nl" -gt 0 ]; then echo "refuse $nl pft-maint data-collection lock(s) held: $(jq -r '.locks | join("; ")' <<<"$j")"
  else echo "ok $rem"; fi
}
daemon_units() { # long-running pft units that are active now; the gate requires them to stay active
  "$SYSTEMCTL" list-units --type=service --state=running --no-legend 'pft-*' 2>/dev/null | awk '{print $1}' | grep -E '^pft-' | sort -u
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
count_events() { # SINCE_EPOCH PROFILE KIND(DENIED|ALLOWED) -> number of audit records
  local f files=()
  for f in "$R"/var/log/audit/audit.log*; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || { echo 0; return 1; }
  cat -- "${files[@]}" | awk -v t="$1" -v q="$2" -v k="$3" '
    index($0, "apparmor=\"" k "\"") && (index($0, "profile=\"" q "\"") || index($0, "profile=\"" q "//")) {
      if (match($0, /audit\([0-9]+/) && substr($0, RSTART + 6, RLENGTH - 6) + 0 >= t + 0) n++ }
    END { print n + 0 }'
}

# Health gate after a re-create. apply: the container is new (StartedAt changed), runs under PROFILE, the profile
# is loaded in the wanted mode, server_state full, peers >= MIN_PEERS, confine signature unchanged, every pft
# daemon still active; then the live exercise (RPC, cron identity switch, the hourly cron run, ps) and 0 DENIED
# records for PROFILE since T0. rollback: the same with the pre-apply profile and no exercise/denial part.
health_gate() { # MODE(apply|rollback) CONTAINER BEFORE_STARTED_AT WANT_PROFILE WANT_MODE SIG DAEMONS T0
  local mode="$1" c="$2" before="$3" wp="$4" wm="$5" sig="$6" daemons="$7" t0="$8" i n ins sa prof km st peers why u dn al
  n=$(( HEALTH_BUDGET / POLL_SEC )); [ "$n" -ge 1 ] || n=1
  for ((i = 1; i <= n; i++)); do
    ins="$(inspect0 "$c")"; why=""
    sa="$(jq -r '.State.StartedAt // ""' <<<"${ins:-$NOJ}" 2>/dev/null)"
    prof="$(jq -r '.AppArmorProfile // ""' <<<"${ins:-$NOJ}" 2>/dev/null)"
    km="$(loaded_mode "$wp")"
    st="$(rpc_state "$c")"
    peers="$("$DOCKER" exec "$c" curl -s -m 10 -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null \
      | jq -r '.result.info.peers // 0' 2>/dev/null)"; [[ "$peers" =~ ^[0-9]+$ ]] || peers=0
    [ -n "$ins" ] || why+=" container missing;"
    [ -n "$sa" ] && [ "$sa" != "$before" ] || why+=" not re-created (StartedAt unchanged);"
    [ "$prof" = "$wp" ] || why+=" profile '${prof:-none}' want $wp;"
    [ "$km" = "$wm" ] || why+=" kernel mode '${km:-not loaded}' want $wm;"
    [ "$st" = full ] || why+=" server_state ${st:-none};"
    [ "$peers" -ge "$MIN_PEERS" ] || why+=" peers $peers < $MIN_PEERS;"
    [ -n "$ins" ] && [ "$(confine_sig "$ins")" = "$sig" ] || why+=" confine changed: $(sig_diff "$sig" "$(confine_sig "${ins:-$NOJ}")");"
    for u in $daemons; do [ "$("$SYSTEMCTL" is-active "$u" 2>/dev/null)" = active ] || why+=" $u inactive;"; done
    [ "$mode" = apply ] && [ "$INJECT" = health ] && why+=" injected failure (PFT_AA_INJECT=health);"
    [ -z "$why" ] && break
    [ "$i" -lt "$n" ] && sleep "$POLL_SEC"
  done
  if [ -n "$why" ]; then echo "$(ts) $mode: health FAIL after $i poll(s):$why"; return 1; fi
  echo "$(ts) $mode: health PASS after $i poll(s) ($c re-created, profile $prof ($wm), server_state full, peers $peers, confine signature unchanged, $(wc -w <<<"$daemons") pft daemons active)"
  [ "$mode" = apply ] || return 0
  exercise_live "$c" | sed 's/^/  | /'
  dn="$(count_events "$t0" "$wp" DENIED)"; al="$(count_events "$t0" "$wp" ALLOWED)"
  if [ "$wm" = enforce ] && [ "$dn" != 0 ]; then
    echo "$(ts) apply: gate FAIL - $dn DENIED record(s) for $wp since T0: $(denials "$t0" "$wp" | cut -f2)"; return 1
  fi
  echo "$(ts) apply: gate PASS - exercise done, DENIED since T0: $dn, ALLOWED (complain) since T0: $al"
}
exercise_live() { # CONTAINER: what the live node does on its own (no forced rotation, no restart: the live node is not a throwaway)
  local c="$1"
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"server_info"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" curl -s -m 10 -o /dev/null -w '%{http_code}\n' -X POST -d '{"method":"peers"}' http://127.0.0.1:5005
  lx "$DOCKER" exec "$c" setpriv --reuid=0 --regid=0 --init-groups true
  lx "$DOCKER" exec "$c" sh -c 'cd / && run-parts --report /etc/cron.hourly'
  lx "$DOCKER" exec "$c" ps -eo pid,comm
}

integrity_accept() { # CONTAINER REASON: accept a new baseline only if every changed item is ours
  command -v "$INTEGRITY" >/dev/null 2>&1 || { echo "$(ts) integrity: pft-integrity not installed, skipped"; return 0; }
  local out items other
  out="$("$INTEGRITY" verify 2>&1)"
  items="$(grep -E '^  \[(WARN|FAIL)\] ' <<<"$out" | awk '{print $2}' | sort -u)"
  [ -n "$items" ] || { echo "$(ts) integrity: baseline already current"; return 0; }
  other="$(grep -vxE "container:$1|compose:\.env|compose:docker-compose\.apparmor\.yml" <<<"$items")"
  if [ -n "$other" ]; then
    echo "$(ts) integrity: NOT accepted - changed items besides the container/compose: $(paste -sd' ' <<<"$other")"
    return 1
  fi
  "$INTEGRITY" accept --reason "$2" >/dev/null 2>&1 && echo "$(ts) integrity: accepted ($(paste -sd' ' <<<"$items")): $2" \
    || { echo "$(ts) integrity: accept FAILED"; return 1; }
}

profile_text() { # FILE MODE -> profile text for that mode (complain adds the flag; enforce removes it)
  if [ "$2" = complain ]; then
    sed -E "s/^(profile $PROFILE flags=\()/\1complain,/; s/^(profile $PROFILE flags=\(complain,)complain,/\1/" "$1"
  else
    sed -E "s/^(profile $PROFILE flags=\()complain,/\1/" "$1"
  fi
}

do_apply() { # PROFILE_FILE MODE
  local src="$1" pm="$2" c ins sig before daemons gate id st wd svc cfgs files eb ov pf pb pre_prof iimg ienv old rp t0
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "apply needs root" 4
  [ "$YES" = 1 ] || { echo "$(ts) apply: REFUSED - apply re-creates the container; re-run with --yes"; return 4; }
  [ -r "$src" ] || die "cannot read --profile-file $src" 2
  grep -qE "^profile $PROFILE flags=\([a-z_,]*\) \{$" "$src" || { echo "$(ts) apply: REFUSED - $src does not define profile $PROFILE (generate --name $PROFILE)"; return 4; }
  c="$(pick_container)"; ins="$(inspect0 "$c")"; [ -n "$ins" ] || die "container $c not found" 2
  pre_prof="$(jq -r '.AppArmorProfile // ""' <<<"$ins")"
  gate="$(maint_gate)"
  case "$gate" in ok*) ;; *) echo "$(ts) apply: REFUSED - ${gate#refuse }; nothing changed"; return 4 ;; esac
  st="$(rpc_state "$c")"; [ "$st" = full ] || { echo "$(ts) apply: REFUSED - node is ${st:-down}, not full; nothing changed"; return 4; }
  jq -e '.HostConfig.SecurityOpt // [] | map(select(test("^no-new-privileges"))) | length > 0' <<<"$ins" >/dev/null \
    && jq -e '.HostConfig.ReadonlyRootfs == true' <<<"$ins" >/dev/null \
    || { echo "$(ts) apply: REFUSED - $c is not confined (confine/ first: read-only root + no-new-privileges)"; return 4; }
  [ -f "$STATE_FILE" ] && [ "$(jq -r '.rolled_back // false' "$STATE_FILE" 2>/dev/null)" != true ] && [ "$pre_prof" = "$PROFILE" ] \
    && { echo "$(ts) apply: REFUSED - $c already runs under $PROFILE (state $STATE_FILE); rollback first to re-apply"; return 4; }
  id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"; t0="$(now)"
  sig="$(confine_sig "$ins")"; before="$(jq -r '.State.StartedAt // ""' <<<"$ins")"; daemons="$(daemon_units)"
  mkdir -p "$STATE_DIR/backup" && chmod 0700 "$STATE_DIR" || die "cannot create $STATE_DIR" 2
  echo "$(ts) apply $id on $c (host $HOST_LABEL): mode $pm, maintenance gate: $gate; before: profile ${pre_prof:-none}, server_state $st"
  echo "$(ts) apply: confine signature sha256 $(sha256sum <<<"$sig" | cut -c1-12) ($(jq -r 'keys | length' <<<"$sig") keys); $(wc -w <<<"$daemons") pft daemons active"
  # 1. profile into /etc/apparmor.d (boot) and the kernel; compiled first, so a bad file changes nothing
  pf="$R/etc/apparmor.d/$PROFILE"; pb=""
  profile_text "$src" "$pm" > "$STATE_DIR/candidate" || die "cannot write candidate" 2
  lx "$PARSER" -Q -K "$STATE_DIR/candidate" || { echo "$(ts) apply: REFUSED - candidate profile does not compile; nothing changed"; return 4; }
  if [ -f "$pf" ]; then pb="$STATE_DIR/backup/$PROFILE.$id"; cp -p "$pf" "$pb" || die "backup of $pf failed" 2; fi
  jq -n --arg id "$id" --arg c "$c" --arg pf "$pf" --arg pb "$pb" --arg pp "$pre_prof" --arg pm "$pm" --arg sig "$sig" \
    '{id:$id, container:$c, profile_file:$pf, profile_backup:$pb, pre_profile:$pp, mode:$pm, sig:$sig, phase:"profile"}' > "$STATE_FILE"
  install -m 0644 "$STATE_DIR/candidate" "$pf" || { do_rollback auto; return 5; }
  echo "$(ts) apply: installed $pf (sha256 $(sha "$pf" | cut -c1-12), $pm)${pb:+; previous file kept as backup/$(basename "$pb")}"
  lx "$PARSER" -r -W "$pf" || { echo "$(ts) apply: profile load failed -> automatic rollback"; do_rollback auto; return 1; }
  echo "$(ts) apply: kernel: $PROFILE ($(loaded_mode "$PROFILE"))"
  # 2. re-create the container with apparmor=PROFILE
  trap 'echo "$(ts) apply: interrupted -> automatic rollback"; do_rollback auto; exit 6' INT TERM
  cfgs="$(jq -r '.Config.Labels["com.docker.compose.project.config_files"] // ""' <<<"$ins")"
  if [ -n "$cfgs" ]; then
    wd="$(jq -r '.Config.Labels["com.docker.compose.project.working_dir"] // ""' <<<"$ins")"
    svc="$(jq -r '.Config.Labels["com.docker.compose.service"] // ""' <<<"$ins")"
    [ -d "$R$wd" ] && [ -n "$svc" ] || { do_rollback auto; die "compose working dir/service unknown" 2; }
    files="$(tr ',' '\n' <<<"$cfgs" | sed 's#.*/##' | grep -vx 'docker-compose.apparmor.yml' | paste -sd:)"
    eb="$STATE_DIR/backup/env.$id"; ov="$R$wd/docker-compose.apparmor.yml"
    touch "$R$wd/.env"; cp -p "$R$wd/.env" "$eb" || { do_rollback auto; die "cannot back up .env" 2; }
    jq --arg wd "$wd" --arg eb "$eb" --arg ov "$ov" '. + {kind:"compose", working_dir:$wd, env_backup:$eb, override:$ov, phase:"container"}' \
      "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
    printf '# written by pft-apparmor apply; remove with: sudo pft-apparmor rollback --yes\nservices:\n  %s:\n    security_opt:\n      - "apparmor=%s"\n' \
      "$svc" "$PROFILE" > "$ov"
    { grep -v '^COMPOSE_FILE=' "$eb"; echo "COMPOSE_FILE=$files:docker-compose.apparmor.yml"; } > "$R$wd/.env"
    chmod --reference="$eb" "$R$wd/.env" 2>/dev/null
    echo "$(ts) apply: wrote $wd/docker-compose.apparmor.yml; .env backed up, COMPOSE_FILE=$files:docker-compose.apparmor.yml"
    ( cd "$R$wd" && "$DOCKER" compose config -q ) || { echo "$(ts) apply: compose config invalid -> automatic rollback"; do_rollback auto; return 1; }
    ( cd "$R$wd" && "$DOCKER" compose up -d 2>&1 ) | sed 's/^/  | /'
    [ "${PIPESTATUS[0]}" = 0 ] || { echo "$(ts) apply: compose up failed -> automatic rollback"; do_rollback auto; return 1; }
  else
    iimg="$(jq -r .Config.Image <<<"$ins")"
    ienv="$("$DOCKER" image inspect "$iimg" 2>/dev/null | jq -c '.[0].Config.Env // []' 2>/dev/null)"; [ -n "$ienv" ] || ienv='[]'
    old="$c-preaa-$id"; rp="$(jq -r '.HostConfig.RestartPolicy.Name' <<<"$ins")"
    mapfile -t A < <(run_args "$ins" "$ienv" "$PROFILE")
    jq --arg o "$old" --arg rp "$rp" '. + {kind:"run", old_container:$o, restart:$rp, phase:"container"}' \
      "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
    echo "$(ts) apply: recreate: docker run -d $(printf '%s\n' "${A[@]}" | show_args)"
    "$DOCKER" stop -t 60 "$c" >/dev/null && "$DOCKER" rename "$c" "$old" && "$DOCKER" update --restart=no "$old" >/dev/null \
      || { echo "$(ts) apply: could not stop/rename $c -> automatic rollback"; do_rollback auto; return 1; }
    echo "$(ts) apply: previous container kept as $old (stopped, restart=no)"
    "$DOCKER" run -d "${A[@]}" >/dev/null || { echo "$(ts) apply: docker run failed -> automatic rollback"; do_rollback auto; return 1; }
  fi
  # 3. gate
  if ! health_gate apply "$c" "$before" "$PROFILE" "$pm" "$sig" "$daemons" "$t0"; then
    echo "$(ts) apply: gate failed -> automatic rollback"; do_rollback auto; local rc=$?; trap - INT TERM
    [ "$rc" = 0 ] && return 1; return "$rc"
  fi
  trap - INT TERM
  jq --arg t "$(ts)" '. + {phase:"applied", applied_at:$t, rolled_back:false}' "$STATE_FILE" > "$STATE_FILE.tmp" && mv -f "$STATE_FILE.tmp" "$STATE_FILE"
  integrity_accept "$c" "pft-apparmor apply $id: $c re-created under $PROFILE ($pm)" || true
  echo "$(ts) apply RESULT: PASS - $c runs under $PROFILE ($pm), node full (state $STATE_FILE)"
}

do_rollback() { # auto|manual: undo the last apply from the state file
  local how="$1" s c kind before ins sig daemons pp pf pb old
  [ -f "$STATE_FILE" ] || { echo "$(ts) rollback: no apply state ($STATE_FILE)"; return 2; }
  s="$(cat "$STATE_FILE")"; c="$(jq -r .container <<<"$s")"; kind="$(jq -r '.kind // ""' <<<"$s")"
  [ "$(jq -r '.rolled_back // false' <<<"$s")" = true ] && { echo "$(ts) rollback: apply $(jq -r .id <<<"$s") already rolled back"; return 0; }
  pp="$(jq -r '.pre_profile' <<<"$s")"; [ -n "$pp" ] || pp=unconfined
  pf="$(jq -r .profile_file <<<"$s")"; pb="$(jq -r '.profile_backup // ""' <<<"$s")"; sig="$(jq -r .sig <<<"$s")"
  echo "$(ts) rollback ($how) of apply $(jq -r .id <<<"$s") on $c: back to $pp"
  ins="$(inspect0 "$c")"; before="$(jq -r '.State.StartedAt // ""' <<<"${ins:-$NOJ}")"; daemons="$(daemon_units)"
  case "$kind" in
    compose)
      local wd; wd="$(jq -r .working_dir <<<"$s")"
      cp -p -- "$(jq -r .env_backup <<<"$s")" "$R$wd/.env" && rm -f -- "$(jq -r .override <<<"$s")" \
        || { echo "$(ts) ROLLBACK FAILED: cannot restore .env / remove override"; return 5; }
      echo "$(ts) rollback: .env restored, docker-compose.apparmor.yml removed"
      ( cd "$R$wd" && "$DOCKER" compose up -d 2>&1 ) | sed 's/^/  | /'
      [ "${PIPESTATUS[0]}" = 0 ] || { echo "$(ts) ROLLBACK FAILED: compose up"; return 5; } ;;
    run)
      old="$(jq -r .old_container <<<"$s")"
      if inspect0 "$old" >/dev/null && [ -n "$(inspect0 "$old")" ]; then
        "$DOCKER" rm -f "$c" >/dev/null 2>&1
        "$DOCKER" rename "$old" "$c" && "$DOCKER" update --restart="$(jq -r .restart <<<"$s")" "$c" >/dev/null \
          && "$DOCKER" start "$c" >/dev/null || { echo "$(ts) ROLLBACK FAILED: could not restore $old as $c"; return 5; }
        echo "$(ts) rollback: previous container $old restored as $c (restart=$(jq -r .restart <<<"$s"))"
      else
        echo "$(ts) ROLLBACK FAILED: previous container $old is gone"; return 5
      fi ;;
    *) echo "$(ts) rollback: container was not touched yet" ;;
  esac
  if [ -n "$pb" ] && [ -f "$pb" ]; then
    cp -p "$pb" "$pf" && lx "$PARSER" -r -W "$pf" >/dev/null || { echo "$(ts) ROLLBACK FAILED: profile restore"; return 5; }
    echo "$(ts) rollback: previous $pf restored (sha256 $(sha "$pf" | cut -c1-12)) and loaded"
  else
    if [ -f "$pf" ]; then "$PARSER" -R "$pf" >/dev/null 2>&1; rm -f "$pf"; fi
    echo "$(ts) rollback: $pf removed and $PROFILE unloaded (kernel: $(loaded_mode "$PROFILE"))"
  fi
  if [ -n "$kind" ]; then
    health_gate rollback "$c" "$before" "$pp" "$(loaded_mode "$pp")" "$sig" "$daemons" 0 || return 5
  fi
  jq --arg t "$(ts)" --arg h "$how" '. + {rolled_back:true, rolled_back_at:$t, rollback:$h}' <<<"$s" > "$STATE_FILE"
  integrity_accept "$c" "pft-apparmor rollback ($how) of apply $(jq -r .id <<<"$s"): $c back to $pp" || true
  echo "$(ts) rollback RESULT: PASS - $c back under $pp"
}

# ---------------------------------------------------------------------------------------------------- main
cmd="${1:-}"; shift || true
ARG=""; ARG2=""; JSON=0; PROM=""; SINCE=86400; OUT=""; MIN=65; EV=""; CAPS=""; NAME="$PROFILE"; SE=0; PP="$PROFILE"; YES=0; PF=""; PMODE=enforce; UNTIL=""; REASON=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --prom) PROM="${2:-}"; [ -n "$PROM" ] || die "--prom needs a file" 3; shift ;;
    --textfile) PROM="$TEXTFILE_DIR/pft_apparmor_$HOST_LABEL.prom" ;;
    --since) SINCE="${2:-}"; [[ "$SINCE" =~ ^[0-9]+$ ]] || die "--since needs seconds" 3; shift ;;
    --since-epoch) SE="${2:-}"; [[ "$SE" =~ ^[0-9]+$ ]] || die "--since-epoch needs a unix time" 3; shift ;;
    --profile) PP="${2:-}"; [ -n "$PP" ] || die "--profile needs a name" 3; shift ;;
    --out) OUT="${2:-}"; [ -n "$OUT" ] || die "--out needs a file" 3; shift ;;
    --minutes) MIN="${2:-}"; [[ "$MIN" =~ ^[0-9]+$ ]] || die "--minutes needs a number" 3; shift ;;
    --events) EV="${2:-}"; [ -n "$EV" ] || die "--events needs a file" 3; shift ;;
    --caps) CAPS="${2:-}"; shift ;;
    --name) NAME="${2:-}"; valid_label "$NAME" || die "bad --name" 3; shift ;;
    --profile-file) PF="${2:-}"; [ -n "$PF" ] || die "--profile-file needs a file" 3; shift ;;
    --complain) PMODE=complain ;;
    --until) UNTIL="${2:-}"; [[ "$UNTIL" =~ ^[0-9]+$ ]] || die "--until needs a unix time" 3; shift ;;
    --reason) REASON="${2:-}"; shift ;;
    --yes) YES=1 ;;
    -*) die "unknown option $1" 3 ;;
    *) if [ -z "$ARG" ]; then ARG="$1"; elif [ -z "$ARG2" ]; then ARG2="$1"; else die "too many arguments" 3; fi ;;
  esac
  shift
done
case "$cmd" in
  audit)
    C="$(pick_container)"
    audit_checks "$C" "$(( $(now) - SINCE ))"; print_results "$C"
    [ -n "$PROM" ] && { write_prom "$PROM" || die "cannot write $PROM" 2; }
    [ "$FINDINGS" = 0 ] && exit 0 || exit 1 ;;
  events) collect_events "$SE" "$PP"; exit 0 ;;
  generate) [ -n "$EV" ] || die "usage: pft-apparmor generate --events FILE" 3
            do_generate "$EV" "$CAPS" "$NAME"; exit 0 ;;
  check) [ -n "${ARG:-}" ] || die "usage: pft-apparmor check FILE" 3
         "$PARSER" -Q -K "$ARG"; exit $? ;;
  apply) [ -n "$PF" ] || die "usage: pft-apparmor apply --profile-file FILE [--complain] --yes" 3
         STATE_FILE="$STATE_DIR/apply-$(pick_container).json"; do_apply "$PF" "$PMODE"; exit $? ;;
  rollback) [ "$YES" = 1 ] || { echo "pft-apparmor: rollback re-creates the container; re-run with --yes" >&2; exit 4; }
            [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "rollback needs root" 4
            STATE_FILE="$STATE_DIR/apply-$(pick_container).json"
            gate="$(maint_gate)"; case "$gate" in ok*) ;; *) echo "$(ts) rollback: REFUSED - ${gate#refuse }; nothing changed"; exit 4 ;; esac
            do_rollback manual; exit $? ;;
  validate) [ -n "$ARG" ] && [ -n "$ARG2" ] && valid_label "$ARG2" || die "usage: pft-apparmor validate FILE HOST" 3
            why="$(validate "$ARG" "$ARG2")" && exit 0; echo "$why"; exit 2 ;;
  ack-denials) [ "$YES" = 1 ] || { echo "pft-apparmor: ack-denials hides DENIED records from the audit; re-run with --yes" >&2; exit 4; }
               [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "ack-denials needs root" 4
               do_ack "${UNTIL:-$(now)}" "$REASON"; exit 0 ;;
  pull) [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "pull needs root" 4
        do_pull; exit 0 ;;
  learn) [ -n "$OUT" ] || die "usage: pft-apparmor learn --out FILE [--minutes N]" 3
         do_learn "$OUT" "$MIN"; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
