#!/usr/bin/env bash
# pft-dockerd: audit and harden the Docker DAEMON on a Post Fiat validator or sentry host (Ubuntu 22.04,
# Docker 29, postfiatd in a container). The container-level audit/ and confine/ add-ons cover the containers;
# this covers dockerd itself: daemon.json, sockets and their permissions, the docker group, TCP exposure,
# insecure registries, swarm/experimental, and the auditd watches for the Docker files. Every check maps to a
# CIS Docker Benchmark v1.6.0 recommendation.
#
# Usage: pft-dockerd audit [--json]
#        pft-dockerd plan                      (read-only: the merged daemon.json and audit rules apply would write)
#        sudo pft-dockerd apply --yes [--dry-run]
#        sudo pft-dockerd rollback --yes       (restore the newest backup of daemon.json, restart dockerd)
#
#  audit   read-only. One line per check: PASS / FAIL / DECISION (documented, deliberately not applied) / INFO.
#  apply   1. merges SAFE_KEYS into daemon.json (existing keys are kept; a key that already has another value is
#             reported and NOT overwritten), backs the old file up byte-for-byte, and runs `dockerd --validate`
#             on the candidate. A candidate that does not validate is never installed (exit 4, file untouched).
#          2. if live-restore is off, it is switched on FIRST with a reload (SIGHUP; live-restore is a reloadable
#             option) and confirmed in `docker info` before anything restarts dockerd.
#          3. installs the full file and restarts dockerd (the other keys are not reloadable). With live-restore
#             on, running containers keep running: the health gate requires every container's StartedAt to be
#             unchanged, DOCKER-USER to be unchanged, the peer port to listen again, and postfiatd's server_state
#             to be full within HEALTH_BUDGET seconds. Any miss -> automatic rollback: the backup is restored
#             byte-identical (sha256 compared), dockerd restarted, and the result checked again (exit 1).
#          4. writes the missing auditd watches to AUDIT_RULES and loads them with augenrules, unless auditd is in
#             immutable mode (-e 2): then the rules are staged and take effect at the next boot (reported).
#
# Exit codes: 0 PASS / applied, 1 findings / rolled back, 2 error, 3 usage, 4 refused (validation, not root,
#             no --yes), 5 rollback failed.
# Env: CONTAINER (auto: postfiatd or postfiatd-sentry)  PEER_PORT (2559)  HEALTH_BUDGET (300)  POLL_SEC (5)
#      AUDIT_RULES (/etc/audit/rules.d/pft-dockerd.rules)  BACKUP_DIR (/var/lib/pft-dockerd)
#      Test hooks: PFT_DOCKERD_ROOT (path prefix for every file)  PFT_DOCKERD_DOCKER / _DOCKERD / _SYSTEMCTL /
#      _AUDITCTL / _AUGENRULES / _SS / _IPT / _STAT / _GETENT / _PGREP / _RPC (commands)  RELOAD_WAIT (2)  PFT_DOCKERD_INJECT (bad-key | health)

# jq programs are single-quoted on purpose. "A && B || C" is intended where C only reports or returns.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

R="${PFT_DOCKERD_ROOT:-}"
DOCKER="${PFT_DOCKERD_DOCKER:-docker}"
DOCKERD="${PFT_DOCKERD_DOCKERD:-dockerd}"
SYSTEMCTL="${PFT_DOCKERD_SYSTEMCTL:-systemctl}"
AUDITCTL="${PFT_DOCKERD_AUDITCTL:-auditctl}"
AUGENRULES="${PFT_DOCKERD_AUGENRULES:-augenrules}"
SS="${PFT_DOCKERD_SS:-ss}"
IPT="${PFT_DOCKERD_IPT:-iptables}"
STAT="${PFT_DOCKERD_STAT:-stat}"
INJECT="${PFT_DOCKERD_INJECT:-}"
GETENT="${PFT_DOCKERD_GETENT:-getent}"
PGREP="${PFT_DOCKERD_PGREP:-pgrep}"
RELOAD_WAIT="${RELOAD_WAIT:-2}"
PEER_PORT="${PEER_PORT:-2559}"
HEALTH_BUDGET="${HEALTH_BUDGET:-300}"
POLL_SEC="${POLL_SEC:-5}"
DJSON="$R/etc/docker/daemon.json"
AUDIT_RULES="${AUDIT_RULES:-$R/etc/audit/rules.d/pft-dockerd.rules}"
BACKUP_DIR="${BACKUP_DIR:-$R/var/lib/pft-dockerd}"

# Keys apply merges. Each is either reloadable (live-restore) or affects only NEW containers, so none of them
# changes a running container. Running postfiatd/monitoring containers already set no-new-privileges and the
# postfiatd containers already rotate their logs; the daemon defaults make that the floor for future ones.
SAFE_KEYS='{"live-restore":true,"no-new-privileges":true,"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"5"}}'

# path -> CIS id for the auditd watches (1.1.x). /var/lib/docker (1.1.5) is a DECISION, see README.
WATCHES="/usr/bin/dockerd 1.1.3
/run/containerd 1.1.4
/etc/docker 1.1.6
/lib/systemd/system/docker.service 1.1.7
/run/containerd/containerd.sock 1.1.8
/lib/systemd/system/docker.socket 1.1.9
/etc/default/docker 1.1.10
/etc/docker/daemon.json 1.1.11
/etc/containerd/config.toml 1.1.12
/usr/bin/containerd 1.1.14
/usr/bin/containerd-shim-runc-v2 1.1.17
/usr/bin/runc 1.1.18"

die() { echo "pft-dockerd: $*" >&2; exit "${2:-2}"; }
ts() { date -u +%FT%TZ; }
RESULTS=""
FAILS=0
res() { # STATUS CIS ID MESSAGE
  RESULTS+="$1"$'\t'"$2"$'\t'"$3"$'\t'"$4"$'\n'
  [ "$1" = FAIL ] && FAILS=$((FAILS + 1))
  return 0
}

djson() { if [ -f "$DJSON" ]; then cat "$DJSON"; else echo '{}'; fi; }
info() { "$DOCKER" info --format '{{json .}}' 2>/dev/null; }
detect_container() {
  [ -n "${CONTAINER:-}" ] && { echo "$CONTAINER"; return; }
  local c
  for c in postfiatd postfiatd-sentry; do
    "$DOCKER" inspect "$c" >/dev/null 2>&1 && { echo "$c"; return; }
  done
  echo postfiatd
}

# perm check: PATH CIS OWNER MAXMODE (octal; the file's mode must not have bits outside MAXMODE)
perm() {
  local p="$1" cis="$2" want_owner="$3" max="$4" got mode owner
  got="$("$STAT" -L -c '%a %U:%G' "$R$p" 2>/dev/null)" || { res INFO "$cis" "perm:$p" "absent"; return; }
  mode="${got%% *}"; owner="${got#* }"
  if [ "$owner" != "$want_owner" ]; then res FAIL "$cis" "perm:$p" "owner $owner, want $want_owner"
  elif (( (8#$mode & ~8#$max) != 0 )); then res FAIL "$cis" "perm:$p" "mode $mode, want $max or stricter"
  else res PASS "$cis" "perm:$p" "$owner $mode"; fi
}

audit_checks() {
  local d i hosts insecure want rules enabled p cis members tcp
  d="$(djson)"
  printf '%s' "$d" | jq -e 'type=="object"' >/dev/null 2>&1 || { res FAIL 3.17 daemon-json "not a JSON object"; d='{}'; }
  i="$(info)" || die "docker info failed (is dockerd running? run as root or a docker-group user)"
  # 2.14 live-restore, 2.18 no-new-privileges, log rotation defaults
  [ "$(jq -r '.LiveRestoreEnabled' <<<"$i")" = true ] && res PASS 2.14 live-restore "enabled" \
    || res FAIL 2.14 live-restore "disabled (dockerd restart or crash stops every container)"
  [ "$(jq -r '."no-new-privileges" // false' <<<"$d")" = true ] && res PASS 2.18 no-new-privileges "daemon default on" \
    || res FAIL 2.18 no-new-privileges "not a daemon default (new containers may gain privileges via setuid)"
  if [ "$(jq -r '."log-driver" // "json-file"' <<<"$d")" = json-file ] && [ "$(jq -r '."log-opts"."max-size" // ""' <<<"$d")" = "" ]; then
    res FAIL n/a log-rotation "json-file without a default max-size (new containers can fill the disk)"
  else res PASS n/a log-rotation "$(jq -c '{d:(."log-driver"//"json-file"),o:(."log-opts"//{})}' <<<"$d")"; fi
  # 2.7 / 3.x TCP exposure: no -H tcp:// in daemon.json or on the command line, no dockerd TCP listener
  hosts="$(jq -r '(.hosts // [])[]' <<<"$d"; "$PGREP" -a -x dockerd 2>/dev/null | grep -oE -- '(-H|--host)[= ]*tcp://[^ ]+' || true)"
  tcp="$("$SS" -Hltnp 2>/dev/null | grep -E 'users:\(\("dockerd"' | awk '{print $4}' | sort -u | tr '\n' ' ')"
  if grep -q 'tcp://' <<<"$hosts" || [ -n "$tcp" ]; then res FAIL 2.7 tcp-socket "dockerd reachable over TCP"
  else res PASS 2.7 tcp-socket "unix socket only"; fi
  # 2.5 insecure registries beyond the built-in loopback defaults
  insecure="$(jq -r '[.RegistryConfig.InsecureRegistryCIDRs[]? | select(. != "127.0.0.0/8" and . != "::1/128")] + [.RegistryConfig.IndexConfigs[]? | select(.Secure==false) | .Name] | unique | length' <<<"$i")"
  [ "$insecure" = 0 ] && res PASS 2.5 insecure-registries "loopback defaults only" \
    || res FAIL 2.5 insecure-registries "$insecure non-loopback insecure registr(y/ies)"
  # 2.4 iptables management, 2.17 experimental, 2.16 seccomp, swarm (7.x)
  [ "$(jq -r 'if has("iptables") then .iptables else true end' <<<"$d")" = true ] && res PASS 2.4 iptables "dockerd manages iptables" \
    || res FAIL 2.4 iptables "iptables=false"
  [ "$(jq -r '.ExperimentalBuild' <<<"$i")" = false ] && res PASS 2.17 experimental "off" || res FAIL 2.17 experimental "on"
  jq -e '.SecurityOptions | any(startswith("name=seccomp"))' <<<"$i" >/dev/null && res PASS 2.16 seccomp "default profile" \
    || res FAIL 2.16 seccomp "no seccomp"
  jq -e '.SecurityOptions | any(. == "name=apparmor")' <<<"$i" >/dev/null && res PASS n/a apparmor "enabled" \
    || res FAIL n/a apparmor "apparmor not in use"
  [ "$(jq -r '.Swarm.LocalNodeState' <<<"$i")" = inactive ] && res PASS 7.1 swarm "inactive" \
    || res FAIL 7.1 swarm "swarm mode active (opens 2377/7946/4789)"
  # Documented decisions: not applied on a node host, reasons in README.
  want="$(jq -r 'if has("icc") then .icc else true end' <<<"$d")"; res DECISION 2.2 icc "icc=$want (not changed: see README)"
  want="$(jq -r 'if has("userland-proxy") then ."userland-proxy" else true end' <<<"$d")"; res DECISION 2.15 userland-proxy "userland-proxy=$want (not changed)"
  want="$(jq -r '."userns-remap" // "off"' <<<"$d")"; res DECISION 2.9 userns-remap "userns-remap=$want (not changed)"
  res DECISION 2.12 authorization-plugin "none (unix socket only, root/docker-group access is admin access)"
  res DECISION 1.1.5 audit:/var/lib/docker "not watched (postfiatd writes its ledger DB there continuously)"
  # 1.1.2 docker group: count only, never names
  members="$("$GETENT" group docker 2>/dev/null | awk -F: '{print $4}')"
  if [ -z "$members" ]; then res PASS 1.1.2 docker-group "no members"
  else res INFO 1.1.2 docker-group "$(tr ',' '\n' <<<"$members" | grep -c .) member(s); each is root-equivalent, review"; fi
  # 3.x permissions
  perm /lib/systemd/system/docker.service 3.1-3.2 root:root 644
  perm /lib/systemd/system/docker.socket 3.3-3.4 root:root 644
  perm /etc/docker 3.5-3.6 root:root 755
  perm /run/docker.sock 3.15-3.16 root:docker 660
  perm /etc/docker/daemon.json 3.17-3.18 root:root 644
  perm /etc/default/docker 3.19-3.20 root:root 644
  perm /run/containerd/containerd.sock 3.23-3.24 root:root 660
  # 1.1.x auditd watches (loaded in the kernel now)
  rules="$("$AUDITCTL" -l 2>/dev/null)"; enabled="$("$AUDITCTL" -s 2>/dev/null | awk '$1=="enabled"{print $2}')"
  while read -r p cis; do
    [ -e "$R$p" ] || { res INFO "$cis" "audit:$p" "path absent"; continue; }
    if grep -qE -- "^-w ${p//./\\.}( |$)" <<<"$rules" || covered_by_dir "$p" "$rules"; then res PASS "$cis" "audit:$p" "watched"
    elif [ "$enabled" = 2 ] && staged "$p"; then res FAIL "$cis" "audit:$p" "staged in $AUDIT_RULES, loads at next boot (auditd immutable)"
    else res FAIL "$cis" "audit:$p" "no auditd watch"; fi
  done <<<"$WATCHES"
}
covered_by_dir() { # a -w on a parent directory covers files under it (e.g. /etc/docker covers daemon.json)
  local p="$1" rules="$2" dir; dir="$(dirname "$p")"
  [ "$dir" != / ] && [ "$dir" != /usr/bin ] && [ "$dir" != /lib/systemd/system ] && [ "$dir" != /run ] \
    && grep -qE -- "^-w ${dir//./\\.}( |$)" <<<"$rules"
}
staged() { [ -f "$AUDIT_RULES" ] && grep -qE -- "^-w ${1//./\\.} " "$AUDIT_RULES"; }

print_results() {
  if [ "${JSON:-0}" = 1 ]; then
    printf '%s' "$RESULTS" | jq -R -s --arg ts "$(ts)" --argjson fails "$FAILS" '
      {ts:$ts, fails:$fails, result:(if $fails==0 then "PASS" else "FAIL" end),
       checks:[split("\n")[] | select(length>0) | split("\t") | {status:.[0], cis:.[1], id:.[2], detail:.[3]}]}'
  else
    echo "pft-dockerd audit - $(ts)"
    printf '%s' "$RESULTS" | awk -F'\t' '{printf "  [%-8s] %-10s %-42s %s\n", $1, $2, $3, $4}'
    echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo "FAIL - $FAILS finding(s)")"
  fi
}

candidate() { # merged daemon.json on stdout; conflicting existing values are kept (reported on stderr)
  local d; d="$(djson)"
  jq -n --argjson cur "$d" --argjson safe "$SAFE_KEYS" '
    $safe | to_entries | reduce .[] as $e ($cur;
      if has($e.key) and (.[$e.key] != $e.value) then . else .[$e.key] = $e.value end)' || return 1
  jq -rn --argjson cur "$d" --argjson safe "$SAFE_KEYS" \
    '$safe | to_entries[] | . as $e | select(($cur | has($e.key)) and ($cur[$e.key] != $e.value)) | "kept existing \($e.key)=\($cur[$e.key]|tojson) (safe value \($e.value|tojson) not forced)"' >&2
}
rules_text() { # missing watches only
  local rules p cis; rules="$("$AUDITCTL" -l 2>/dev/null)"
  echo "# pft-dockerd: auditd watches for the Docker daemon files (CIS Docker Benchmark v1.6.0 1.1.x)"
  while read -r p cis; do
    [ -e "$R$p" ] || continue
    grep -qE -- "^-w ${p//./\\.}( |$)" <<<"$rules" && continue
    covered_by_dir "$p" "$rules" && continue
    echo "-w $p -p wa -k pft-dockerd"   # CIS $cis
  done <<<"$WATCHES"
}

snapshot() { # container StartedAt list + DOCKER-USER rules + peer listener; one line each
  local c
  for c in $("$DOCKER" ps -q 2>/dev/null); do "$DOCKER" inspect -f '{{.Name}} {{.State.StartedAt}}' "$c"; done | sort
  "$IPT" -S DOCKER-USER 2>/dev/null | sed 's/^/ipt /'
}
server_state() {
  if [ -n "${PFT_DOCKERD_RPC:-}" ]; then "$PFT_DOCKERD_RPC"; return; fi
  "$DOCKER" exec "$1" sh -c 'curl -s -m 5 -d "{\"method\":\"server_info\"}" http://127.0.0.1:${RPC_PORT:-5005}/' 2>/dev/null \
    | jq -r '.result.info.server_state // "unknown"' 2>/dev/null || echo unknown
}
health_gate() { # BEFORE_SNAPSHOT CONTAINER -> 0 healthy within budget
  local before="$1" c="$2" start now st snap
  start="$(date +%s)"
  while :; do
    now="$(date +%s)"
    snap="$(snapshot)"; st="$(server_state "$c")"
    if [ "$INJECT" != health ] && [ "$snap" = "$before" ] && [ "$st" = full ] \
       && "$SS" -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ":$PEER_PORT\$"; then
      echo "$(ts) health: PASS after $((now - start)) s (StartedAt + DOCKER-USER unchanged, :$PEER_PORT listening, server_state full)"
      return 0
    fi
    if (( now - start >= HEALTH_BUDGET )); then
      echo "$(ts) health: FAIL after $((now - start)) s (server_state=$st; snapshot $([ "$snap" = "$before" ] && echo same || echo CHANGED)${INJECT:+; injected=$INJECT})"
      diff <(echo "$before") <(echo "$snap") | sed 's/^/  /' | head -20
      return 1
    fi
    sleep "$POLL_SEC"
  done
}
wait_docker() { local _n; for _n in $(seq 1 60); do "$DOCKER" info >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
sha() { if [ -f "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else echo absent; fi; }

do_rollback() { # BACKUP (or "absent") ; restores and restarts dockerd
  local b="$1"
  # restoring a file without live-restore means this restart stops and restarts the running containers
  { [ "$b" = absent ] || [ "$(jq -r '."live-restore" // false' "$b" 2>/dev/null)" != true ]; } \
    && echo "$(ts) rollback: WARNING the restored daemon.json has no live-restore; this dockerd restart restarts running containers"
  if [ "$b" = absent ]; then rm -f "$DJSON"; else cp -p "$b" "$DJSON"; fi
  "$SYSTEMCTL" restart docker && wait_docker || { echo "$(ts) rollback: dockerd did not come back"; return 5; }
  echo "$(ts) rollback: daemon.json sha256 $(sha "$DJSON") (backup $([ "$b" = absent ] && echo absent || sha "$b"))"
  if [ "$b" = absent ]; then [ ! -e "$DJSON" ]; else cmp -s "$b" "$DJSON"; fi \
    && echo "$(ts) rollback: daemon.json byte-identical to the pre-apply state" || { echo "$(ts) rollback: MISMATCH"; return 5; }
}

cmd_apply() {
  local yes=0 dry=0 cand c before b old live tmp out rc
  while [ $# -gt 0 ]; do case "$1" in --yes) yes=1 ;; --dry-run) dry=1 ;; *) die "unknown arg $1" 3 ;; esac; shift; done
  [ "$dry" = 1 ] || [ "$yes" = 1 ] || die "apply needs --yes (or --dry-run)" 4
  [ "$dry" = 1 ] || [ -n "$R" ] || [ "$(id -u)" = 0 ] || die "apply must run as root" 4
  cand="$(candidate)" || die "cannot merge $DJSON (not valid JSON?)" 4
  [ "$INJECT" = bad-key ] && cand="$(jq '. + {"pft-injected-bad-key": true}' <<<"$cand")"
  # health drill: a valid, harmless engine label makes the candidate differ even on an applied host, so the
  # drill really restarts dockerd and the injected gate miss exercises the rollback against a live-restore backup
  [ "$INJECT" = health ] && cand="$(jq '. + {"labels": ["pft.dockerd-drill=1"]}' <<<"$cand")"
  tmp="$(mktemp)"; printf '%s\n' "$cand" > "$tmp"
  echo "$(ts) apply: candidate daemon.json:"; sed 's/^/  /' "$tmp"
  out="$("$DOCKERD" --validate --config-file "$tmp" 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed 's/^/  dockerd --validate: /'
  if [ "$rc" != 0 ]; then
    rm -f "$tmp"; echo "$(ts) apply: REFUSED - candidate failed dockerd --validate; $DJSON untouched (sha256 $(sha "$DJSON"))"; return 4
  fi
  echo "$(ts) apply: audit rules to stage:"; rules_text | sed 's/^/  /'
  if [ "$dry" = 1 ]; then rm -f "$tmp"; echo "$(ts) apply: dry run, nothing changed"; return 0; fi

  c="$(detect_container)"
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  if [ -f "$DJSON" ]; then b="$BACKUP_DIR/daemon.json.$(date -u +%Y%m%dT%H%M%SZ)"; cp -p "$DJSON" "$b"; else b=absent; fi
  echo "$b" > "$BACKUP_DIR/last-backup"
  old="$(sha "$DJSON")"; echo "$(ts) apply: backup $b (sha256 $old)"
  if cmp -s "$tmp" "$DJSON" 2>/dev/null; then echo "$(ts) apply: daemon.json already as planned (no change)"; rm -f "$tmp"
  else
    before="$(snapshot)"
    live="$(info | jq -r '.LiveRestoreEnabled')"
    if [ "$live" != true ]; then # step 2: live-restore first, by reload
      jq '. + {"live-restore": true}' <<<"$(djson)" > "$DJSON.pft-tmp" && mv "$DJSON.pft-tmp" "$DJSON"
      "$SYSTEMCTL" reload docker; sleep "$RELOAD_WAIT"
      [ "$(info | jq -r '.LiveRestoreEnabled')" = true ] || { echo "$(ts) apply: live-restore did not take effect on reload -> rollback"; do_rollback "$b"; return 1; }
      echo "$(ts) apply: live-restore enabled by reload (no restart); snapshot unchanged: $([ "$(snapshot)" = "$before" ] && echo yes || echo NO)"
    fi
    install -m 644 -o root -g root "$tmp" "$DJSON" 2>/dev/null || install -m 644 "$tmp" "$DJSON"; rm -f "$tmp"
    echo "$(ts) apply: installed daemon.json (sha256 $(sha "$DJSON")); restarting dockerd (live-restore on)"
    "$SYSTEMCTL" restart docker && wait_docker || { echo "$(ts) apply: dockerd did not come back -> rollback"; do_rollback "$b"; return 1; }
    if ! health_gate "$before" "$c"; then echo "$(ts) apply: health gate missed -> automatic rollback"; do_rollback "$b" || return 5; return 1; fi
  fi
  # step 4: auditd watches
  if [ "$(rules_text | grep -c '^-w')" -gt 0 ]; then
    rules_text > "$AUDIT_RULES"; chmod 640 "$AUDIT_RULES"
    if [ "$("$AUDITCTL" -s | awk '$1=="enabled"{print $2}')" = 2 ]; then
      echo "$(ts) apply: auditd immutable (-e 2): $(grep -c '^-w' "$AUDIT_RULES") watch(es) staged in $AUDIT_RULES, active after the next reboot"
    else "$AUGENRULES" --load >/dev/null && echo "$(ts) apply: auditd watches loaded ($(grep -c '^-w' "$AUDIT_RULES"))"; fi
  else echo "$(ts) apply: auditd watches already complete"; fi
  echo "$(ts) apply: done"
}

cmd_rollback() {
  [ "${1:-}" = --yes ] || die "rollback needs --yes" 4
  local b; b="$(cat "$BACKUP_DIR/last-backup" 2>/dev/null)" || die "no backup recorded in $BACKUP_DIR" 4
  do_rollback "$b"
}

case "${1:-}" in
  audit) shift; JSON=0; [ "${1:-}" = --json ] && JSON=1; audit_checks; print_results; [ "$FAILS" = 0 ] ;;
  plan) echo "# daemon.json after apply:"; candidate; echo "# auditd rules apply would write to $AUDIT_RULES:"; rules_text ;;
  apply) shift; cmd_apply "$@" ;;
  rollback) shift; cmd_rollback "$@" ;;
  *) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 3 ;;
esac
