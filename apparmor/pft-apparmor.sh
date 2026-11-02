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
#                         seconds (default 86400). WARN with the top three operation+path pairs.
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
#
# Exit codes: 0 PASS / ok, 1 findings, 2 error, 3 usage, 4 refused.
# Config: /etc/pft-apparmor.env (KEY=VALUE, read, never sourced): HOST_LABEL (validator), PROFILE (pft-postfiatd)
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  TEXTFILE_DIR  LEARN_DIR (/var/lib/pft-apparmor)
#      TREES (directories collapsed to DIR/{,**})  EXTRA_EXEC (/usr/bin/logger)
#      SYNC_BUDGET (1200 s for the throwaway to reach full)
#      Test hooks: PFT_AA_ROOT (path prefix for every file)  PFT_AA_DOCKER / _PARSER / _SYSTEMCTL (commands)
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

pick_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}

# ---------------------------------------------------------------------------------------------------- audit
RESULTS=""; FINDINGS=0; DENIED=0
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
  if ! d="$(denials "$since" "$PROFILE")"; then DENIED=0; add FAIL denials "${d#*$'\t'} (run as root)"
  else
    DENIED="${d%%$'\t'*}"
    if [ "$DENIED" = 0 ]; then add PASS denials "0 DENIED events in the last $(( $(now) - since ))s"
    else add WARN denials "$DENIED DENIED event(s) in the last $(( $(now) - since ))s: ${d#*$'\t'}"
    fi
  fi
}

print_results() {
  local c="$1"
  if [ "$JSON" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg h "$HOST_LABEL" --arg c "$c" --arg p "$PROFILE" --arg t "$(ts)" \
      --argjson n "$FINDINGS" --argjson d "$DENIED" '
      {host: $h, container: $c, profile: $p, time: $t, findings: $n, denied_events: $d,
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

lx() { echo "\$ $*"; "$@"; echo "(exit $?)"; }

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

# ---------------------------------------------------------------------------------------------------- main
cmd="${1:-}"; shift || true
JSON=0; PROM=""; SINCE=86400; OUT=""; MIN=65; EV=""; CAPS=""; NAME="$PROFILE"; SE=0; PP="$PROFILE"
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
    -*) die "unknown option $1" 3 ;;
    *) ARG="$1" ;;
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
  learn) [ -n "$OUT" ] || die "usage: pft-apparmor learn --out FILE [--minutes N]" 3
         do_learn "$OUT" "$MIN"; exit $? ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
