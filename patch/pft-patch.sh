#!/usr/bin/env bash
# pft-patch: controlled OS patching for a Post Fiat validator and its sentry (Ubuntu 22.04, postfiatd in Docker).
# Stock Ubuntu installs security updates unattended at a random time each day. On a node host that can restart
# dockerd/containerd (docker.io, containerd and runc ship in the Ubuntu archive), i.e. restart postfiatd at an
# unplanned moment. This tool keeps unattended SECURITY updates for everything else, takes the Docker runtime
# packages and reboots out of the unattended path, and gives a read-only view of what is pending.
#
# Usage: pft-patch status [--json]               read-only
#        sudo pft-patch policy apply --yes          install the unattended-upgrades policy drop-in
#        sudo pft-patch policy rollback --yes       restore the state before the newest apply, byte-identical
#        pft-patch policy show                      the drop-in apply would write (read-only)
#        sudo pft-patch run --yes [--hosts sentry,validator] [--all] [--runtime]   patch hosts, sentry first
#        sudo pft-patch upgrade --yes [--all] [--runtime]   one host step (run calls it on each host)
#        pft-patch host-info                        boot id, dpkg.log sha256, reboot flag (read-only)
#        sudo pft-patch resume                      finish a run after the local host rebooted (boot unit)
#
#  status  one line per item: OK / WARN / CRIT / INFO.
#          updates   `apt-get -s dist-upgrade` (simulation, no lock, nothing changes). An update is SECURITY if
#                    its candidate comes from a *-security pocket; the rest are "other". Kernels are counted too.
#          holds     `apt-mark showhold`, and which held packages have an update waiting.
#          reboot    /var/run/reboot-required (+ .pkgs) and needrestart's kernel state (KSTA 1 current, 2 ABI
#                    upgrade pending, 3 version upgrade pending).
#          services  needrestart -b: services still running old libraries (a restart, not a reboot, fixes them).
#          exposure  every installed Docker runtime package (RUNTIME_PKGS) must be in the effective
#                    Unattended-Upgrade::Package-Blacklist while unattended upgrades are on, and
#                    Unattended-Upgrade::Automatic-Reboot must be false.
#          Exit: 2 CRIT = security updates pending, reboot required, or a held package with a pending update;
#                1 WARN = other updates, services or kernel waiting for a restart/reboot, runtime exposure,
#                    Automatic-Reboot true, holds present; 0 = nothing pending and the policy is safe.
#  policy  apply   1. records the effective `apt-config dump` (sha256) and the drop-in's previous state
#                     (absent, or a byte copy) under BACKUP_DIR/<UTC stamp>/.
#                  2. writes POLICY_FILE (blacklist RUNTIME_PKGS, Automatic-Reboot "false"), then re-reads the
#                     EFFECTIVE config with apt-config: every runtime package blacklisted and Automatic-Reboot
#                     false, else the previous state is restored and apply exits 4 (a later apt.conf.d file can
#                     override ours; that must not pass silently). Unattended security updates stay on.
#          rollback restores the newest backup (removes the drop-in if it was absent, else copies the bytes
#                     back), then requires the drop-in sha256 and the effective `apt-config dump` sha256 to equal
#                     the recorded ones (exit 5 if not).
#
# Exit codes (policy): 0 applied / rolled back / already applied, 2 error, 3 usage, 4 refused (not root, no --yes,
#   policy not effective), 5 rollback mismatch.
# Env: RUNTIME_PKGS ("docker.io docker-ce docker-ce-cli containerd containerd.io runc")
#      POLICY_FILE (/etc/apt/apt.conf.d/52pft-patch)  BACKUP_DIR (/var/lib/pft-patch/backup)
#      Test hooks: PFT_PATCH_ROOT (path prefix for every file)  PFT_PATCH_APT_GET / _APT_CONFIG / _APT_MARK /
#      _DPKG_QUERY / _NEEDRESTART (commands)  PFT_PATCH_NOROOT=1 (skip the root check)

# jq programs are single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail
umask 022

R="${PFT_PATCH_ROOT:-}"
APT_GET="${PFT_PATCH_APT_GET:-apt-get}"
APT_CONFIG="${PFT_PATCH_APT_CONFIG:-apt-config}"
APT_MARK="${PFT_PATCH_APT_MARK:-apt-mark}"
DPKG_QUERY="${PFT_PATCH_DPKG_QUERY:-dpkg-query}"
NEEDRESTART="${PFT_PATCH_NEEDRESTART:-needrestart}"
RUNTIME_PKGS="${RUNTIME_PKGS:-docker.io docker-ce docker-ce-cli containerd containerd.io runc}"
POLICY_FILE="${POLICY_FILE:-$R/etc/apt/apt.conf.d/52pft-patch}"
BACKUP_DIR="${BACKUP_DIR:-$R/var/lib/pft-patch/backup}"
REBOOT_FILE="$R/var/run/reboot-required"
BOOT_ID_FILE="${BOOT_ID_FILE:-$R/proc/sys/kernel/random/boot_id}"
DPKG_LOG="$R/var/log/dpkg.log"
SYSTEMCTL="${PFT_PATCH_SYSTEMCTL:-systemctl}"
NO_RESTART_RE="${NO_RESTART_RE:-^(docker|containerd|dbus|systemd-logind|user@.*|getty@.*|serial-getty@.*)\.service$}"
CONF="${CONF:-$R/etc/pft-patch/hosts.conf}"
SSH="${PFT_PATCH_SSH:-ssh}"
PATCH_CMD="${PATCH_CMD:-pft-patch}"
MAINT_CMD="${MAINT_CMD:-pft-maint}"
AM="${AM:-http://127.0.0.1:9093}"
GATE_TIMEOUT="${GATE_TIMEOUT:-1800}"
POLL_SEC="${POLL_SEC:-10}"
MAX_LEDGER_AGE="${MAX_LEDGER_AGE:-20}"
REBOOT_TIMEOUT="${REBOOT_TIMEOUT:-600}"
WINDOW_TTL="${WINDOW_TTL:-5400}"
SILENCE_TAIL="${SILENCE_TAIL:-900}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-patch/run}"
RESUME_FILE="$STATE_DIR/resume.json"
INJECT="${PFT_PATCH_INJECT:-}"

die() { echo "pft-patch: $*" >&2; exit 2; }
usage() { sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 3; }
need_root() { [ "${PFT_PATCH_NOROOT:-0}" = 1 ] || [ "$(id -u)" = 0 ] || { echo "pft-patch: needs root" >&2; exit 4; }; }
sha() { sha256sum "$1" | cut -c1-64; }
aptdump_sha() { "$APT_CONFIG" dump 2>/dev/null | sha256sum | cut -c1-64; }

# ---------- readers (each prints data on stdout; rc 1 = could not read) ----------

# "pkg<TAB>class<TAB>old<TAB>new" for every Inst line of the simulation; class = security | other; old "-" = new package.
sim_updates() {
  local out
  out="$("$APT_GET" -s -o Debug::NoLocking=1 dist-upgrade 2>&1)" || { echo "apt-get -s failed: $(tail -1 <<<"$out")"; return 1; }
  awk '/^Inst /{
    pkg=$2; old="-"; if ($3 ~ /^\[/) { old=$3; gsub(/[][]/, "", old) }
    m=$0; sub(/^[^(]*\(/, "", m); split(m, f, " "); new=f[1]
    cls = (m ~ /-security[ ,)\/]/) ? "security" : "other"
    printf "%s\t%s\t%s\t%s\n", pkg, cls, old, new }' <<<"$out"
}

holds() { "$APT_MARK" showhold 2>/dev/null; }

# effective values of a list option, one per line
conf_list() { "$APT_CONFIG" dump 2>/dev/null | sed -n "s/^$1:: \"\(.*\)\";$/\1/p"; }
conf_val() { "$APT_CONFIG" dump 2>/dev/null | sed -n "s/^$1 \"\(.*\)\";$/\1/p" | tail -1; }

installed_runtime() {
  local p
  for p in $RUNTIME_PKGS; do
    [ "$("$DPKG_QUERY" -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | cut -c1-2)" = "ii" ] && echo "$p"
  done
}

# unattended-upgrades matches each blacklist entry as a Python regex with re.match (anchored at the start)
blacklisted() { # PKG  (reads the blacklist on stdin, one entry per line)
  python3 -c 'import re,sys; sys.exit(0 if any(e and re.match(e, sys.argv[1]) for e in sys.stdin.read().split("\n")) else 1)' "$1"
}

# ---------- status ----------

status() {
  local json=0 rc=0 lines=() items='[]' u sec oth ker hl hu rb rbp ksta svc nrok=1 exp=() bl ar uu p nr
  [ "${1:-}" = "--json" ] && json=1
  add() { # LEVEL NAME MESSAGE
    lines+=("$(printf '[%-4s] %-10s %s' "$1" "$2" "$3")")
    items="$(jq -c --arg l "$1" --arg n "$2" --arg m "$3" '. + [{level:$l,item:$n,message:$m}]' <<<"$items")"
    case "$1" in CRIT) rc=2 ;; WARN) [ "$rc" -lt 1 ] && rc=1 ;; esac
  }
  if u="$(sim_updates)"; then
    sec="$(awk -F'\t' '$2=="security"' <<<"$u" | grep -c . || true)"
    oth="$(awk -F'\t' '$2=="other"' <<<"$u" | grep -c . || true)"
    ker="$(awk -F'\t' '$1 ~ /^linux-(image|modules|headers)?/' <<<"$u" | grep -c . || true)"
    if [ "$sec" -gt 0 ]; then
      add CRIT updates "$sec security update(s) pending: $(awk -F'\t' '$2=="security"{print $1}' <<<"$u" | head -8 | paste -sd' ' -)"
    else add OK updates "0 security updates pending"; fi
    if [ "$oth" -gt 0 ]; then add WARN updates "$oth other update(s) pending ($ker kernel package(s)); install with run --all"
    else add OK updates "0 other updates pending"; fi
  else
    add CRIT updates "cannot simulate: $u"; sec=-1; oth=-1; ker=-1
  fi
  hl="$(holds)"
  if [ -n "$hl" ]; then
    hu="$(while IFS= read -r p; do awk -F'\t' -v p="$p" '$1==p{print p}' <<<"${u:-}"; done <<<"$hl" | paste -sd' ' -)"
    if [ -n "$hu" ]; then add CRIT holds "held with an update pending: $hu"
    else add WARN holds "$(grep -c . <<<"$hl") held package(s), none with a pending update: $(paste -sd' ' - <<<"$hl")"; fi
  else add OK holds "no held packages"; fi
  rb=0; rbp=""
  if [ -e "$REBOOT_FILE" ]; then
    rb=1; [ -f "$REBOOT_FILE.pkgs" ] && rbp="$(paste -sd' ' - < "$REBOOT_FILE.pkgs")"
    add CRIT reboot "reboot required${rbp:+ by: $rbp}"
  else add OK reboot "no reboot-required flag"; fi
  ksta=""; svc=""
  if nr="$("$NEEDRESTART" -b -r l 2>/dev/null)" && grep -q '^NEEDRESTART-KSTA:' <<<"$nr"; then
    ksta="$(sed -n 's/^NEEDRESTART-KSTA: *//p' <<<"$nr" | head -1)"
    svc="$(sed -n 's/^NEEDRESTART-SVC: *//p' <<<"$nr" | paste -sd' ' -)"
    case "$ksta" in
      1) add OK kernel "running kernel is the newest installed" ;;
      2|3) add WARN kernel "a newer kernel is installed (needrestart KSTA $ksta): reboot to load it" ;;
      *) add INFO kernel "needrestart kernel state unknown (${ksta:-none})" ;;
    esac
    if [ -n "$svc" ]; then add WARN services "restart needed (old libraries): $svc"
    else add OK services "no service runs old libraries"; fi
  else
    nrok=0; add INFO services "needrestart not available or incomplete (it needs root): kernel/services not checked"
  fi
  uu="$(conf_val 'APT::Periodic::Unattended-Upgrade')"
  ar="$(conf_val 'Unattended-Upgrade::Automatic-Reboot')"
  bl="$(conf_list 'Unattended-Upgrade::Package-Blacklist')"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    blacklisted "$p" <<<"$bl" || exp+=("$p")
  done <<<"$(installed_runtime)"
  if [ "${uu:-0}" = 0 ]; then
    add INFO exposure "unattended upgrades are off (APT::Periodic::Unattended-Upgrade=${uu:-unset}): no unattended runtime changes"
  elif [ "${#exp[@]}" -gt 0 ]; then
    add WARN exposure "unattended-upgrades may upgrade (and restart) the Docker runtime: ${exp[*]} not blacklisted"
  else add OK exposure "installed Docker runtime packages are blacklisted for unattended-upgrades"; fi
  case "${ar:-false}" in
    true|1|yes) add WARN autoreboot "Unattended-Upgrade::Automatic-Reboot=$ar: the host may reboot at any time" ;;
    *) add OK autoreboot "Automatic-Reboot=${ar:-false (default)}" ;;
  esac
  if [ "$json" = 1 ]; then
    jq -n --argjson items "$items" --argjson rc "$rc" --argjson sec "$sec" --argjson oth "$oth" --argjson ker "$ker" \
      --arg holds "$hl" --argjson rb "$rb" --arg rbp "$rbp" --arg ksta "$ksta" --arg svc "$svc" --argjson nrok "$nrok" \
      --arg exp "${exp[*]:-}" --arg ar "${ar:-false}" --arg uu "${uu:-0}" '{
        result: (["OK","WARN","CRIT"][$rc]), exit: $rc,
        updates: {security: $sec, other: $oth, kernel: $ker},
        holds: ($holds | split("\n") | map(select(length > 0))),
        reboot_required: ($rb == 1), reboot_pkgs: ($rbp | split(" ") | map(select(length > 0))),
        needrestart: {available: ($nrok == 1), ksta: $ksta, services: ($svc | split(" ") | map(select(length > 0)))},
        unattended: {enabled: ($uu != "0"), automatic_reboot: $ar, runtime_exposed: ($exp | split(" ") | map(select(length > 0)))},
        items: $items}'
  else
    printf '%s\n' "${lines[@]}"
    echo "RESULT: $(echo OK WARN CRIT | cut -d' ' -f$((rc + 1)))"
  fi
  return "$rc"
}

# ---------- policy ----------

policy_text() {
  local p
  echo '// Managed by pft-patch (postfiat-validator-installer/patch). Rollback: sudo pft-patch policy rollback --yes'
  echo '// Unattended security updates stay on; the Docker runtime and reboots go through pft-patch run instead.'
  echo 'Unattended-Upgrade::Package-Blacklist {'
  for p in $RUNTIME_PKGS; do printf '    "%s";\n' "$p"; done
  echo '};'
  echo 'Unattended-Upgrade::Automatic-Reboot "false";'
}

policy_effective() { # prints the problems; rc 0 = effective
  local bl ar p bad=0
  bl="$(conf_list 'Unattended-Upgrade::Package-Blacklist')"
  for p in $RUNTIME_PKGS; do blacklisted "$p" <<<"$bl" || { echo "not blacklisted: $p"; bad=1; }; done
  ar="$(conf_val 'Unattended-Upgrade::Automatic-Reboot')"
  case "${ar:-false}" in false|0|no) ;; *) echo "Automatic-Reboot is '$ar'"; bad=1 ;; esac
  return "$bad"
}

restore_from() { # BACKUP_SUBDIR
  if [ -f "$1/absent" ]; then rm -f "$POLICY_FILE"; else cp -p "$1/previous" "$POLICY_FILE"; fi
}

policy_apply() {
  local yes="$1" b cand probs
  [ "$yes" = 1 ] || { echo "pft-patch: policy apply changes apt configuration; add --yes" >&2; exit 4; }
  need_root
  cand="$(mktemp)"; policy_text > "$cand"
  if [ -f "$POLICY_FILE" ] && cmp -s "$cand" "$POLICY_FILE" && policy_effective >/dev/null; then
    rm -f "$cand"; echo "policy already applied ($POLICY_FILE sha256 $(sha "$POLICY_FILE"))"; return 0
  fi
  b="$BACKUP_DIR/$(date -u +%Y%m%dT%H%M%SZ)"
  [ -e "$b" ] && b="$b-$$"
  mkdir -p "$b" || die "cannot create $b"
  if [ -f "$POLICY_FILE" ]; then cp -p "$POLICY_FILE" "$b/previous"; sha "$POLICY_FILE" > "$b/previous.sha256"
  else : > "$b/absent"; fi
  aptdump_sha > "$b/aptconfig.sha256"
  echo "backup: $b (drop-in $([ -f "$b/absent" ] && echo absent || echo "sha256 $(cat "$b/previous.sha256")"), apt-config dump sha256 $(cat "$b/aptconfig.sha256"))"
  mkdir -p "$(dirname "$POLICY_FILE")"
  install -m 0644 "$cand" "$POLICY_FILE"; rm -f "$cand"
  if ! probs="$(policy_effective)"; then
    echo "REFUSED: the drop-in is not effective (another apt.conf.d file overrides it):"; printf '  %s\n' "$probs"
    restore_from "$b"; rm -rf "$b"
    echo "previous state restored; nothing changed"; exit 4
  fi
  echo "applied: $POLICY_FILE sha256 $(sha "$POLICY_FILE")"
  echo "effective: blacklist $(conf_list 'Unattended-Upgrade::Package-Blacklist' | paste -sd' ' -); Automatic-Reboot $(conf_val 'Unattended-Upgrade::Automatic-Reboot'); Unattended-Upgrade $(conf_val 'APT::Periodic::Unattended-Upgrade')"
}

policy_rollback() {
  local yes="$1" b d ok=1 want now
  [ "$yes" = 1 ] || { echo "pft-patch: policy rollback changes apt configuration; add --yes" >&2; exit 4; }
  need_root
  b=""
  for d in "$BACKUP_DIR"/2*; do   # glob order is sorted; the newest stamp wins, rolled-back ones are skipped
    [ -d "$d" ] && [ "${d%.rolled-back}" = "$d" ] && b="$d"
  done
  [ -n "$b" ] || { echo "pft-patch: no backup in $BACKUP_DIR" >&2; exit 2; }
  restore_from "$b"
  if [ -f "$b/absent" ]; then
    if [ -e "$POLICY_FILE" ]; then echo "drop-in still present: FAIL"; ok=0; else echo "drop-in removed (was absent before apply)"; fi
  else
    want="$(cat "$b/previous.sha256")"; now="$(sha "$POLICY_FILE")"
    echo "drop-in sha256 $now (recorded $want)"; [ "$now" = "$want" ] || ok=0
  fi
  want="$(cat "$b/aptconfig.sha256")"; now="$(aptdump_sha)"
  echo "apt-config dump sha256 $now (recorded $want)"; [ "$now" = "$want" ] || ok=0
  if [ "$ok" = 1 ]; then mv "$b" "$b.rolled-back"; echo "rollback: byte-identical"
  else echo "rollback: MISMATCH (backup kept in $b)"; exit 5; fi
}

# ---------- host steps (run ON the host being patched, as root; `run` calls them over hx) ----------

# one line: boot=<boot_id> dpkg=<sha256 of dpkg.log | none> reboot=<0|1>
host_info() {
  local b d
  b="$(cat "$BOOT_ID_FILE" 2>/dev/null)" || b=unknown
  if [ -f "$DPKG_LOG" ]; then d="$(sha "$DPKG_LOG")"; else d=none; fi
  echo "boot=$b dpkg=$d reboot=$([ -e "$REBOOT_FILE" ] && echo 1 || echo 0)"
}

is_runtime() { tr ' ' '\n' <<<"$RUNTIME_PKGS" | grep -qxF -- "$1"; }

# upgrade --yes [--all] [--runtime]: install the selected updates, then decide reboot / service restarts / nothing.
# Prints PLAN/SKIP/DEP lines, the apt output (prefixed), RESTARTED/DEFERRED lines and exactly one DECISION line.
# Exit 0 done (DECISION printed), 2 apt or a service restart failed (fail closed: `run` stops).
upgrade() {
  local all=0 rt=0 yes=0 a u hl p cls old new list=() out nr ksta s restarted=() rc
  for a; do case "$a" in --yes) yes=1 ;; --all) all=1 ;; --runtime) rt=1 ;; *) usage ;; esac; done
  [ "$yes" = 1 ] || { echo "pft-patch: upgrade installs packages; add --yes" >&2; exit 4; }
  need_root
  out="$(DEBIAN_FRONTEND=noninteractive "$APT_GET" -q update 2>&1)" || { echo "UPGRADE FAIL apt-get update: $(tail -1 <<<"$out")"; return 2; }
  u="$(sim_updates)" || { echo "UPGRADE FAIL $u"; return 2; }
  hl="$(holds)"
  while IFS=$'\t' read -r p cls old new; do
    [ -z "$p" ] && continue
    [ "$old" != - ] || { echo "DEP $p $new (new package, installed only as a dependency)"; continue; }
    [ "$all" = 1 ] || [ "$cls" = security ] || { echo "SKIP $p $cls (security-only run; use --all)"; continue; }
    if grep -qxF -- "$p" <<<"$hl"; then echo "SKIP $p held"; continue; fi
    if [ "$rt" = 0 ] && is_runtime "$p"; then echo "SKIP $p Docker runtime (restarts postfiatd; needs --runtime)"; continue; fi
    list+=("$p"); echo "PLAN $p $cls $old -> $new"
  done <<<"$u"
  if [ "${#list[@]}" -gt 0 ]; then
    # NEEDRESTART_SUSPEND: needrestart's apt hook does nothing; the decision below is made explicitly.
    out="$(DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 "$APT_GET" -y -q -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold install --only-upgrade "${list[@]}" 2>&1)"; rc=$?
    grep -v '^ *$' <<<"$out" | sed 's/^/  apt: /'
    [ "$rc" = 0 ] || { echo "UPGRADE FAIL apt-get install exit $rc"; return 2; }
    echo "INSTALLED ${#list[@]} package(s)"
  else
    echo "INSTALLED 0 package(s) (nothing selected)"
  fi
  if [ -e "$REBOOT_FILE" ]; then
    echo "DECISION reboot (reboot-required$([ -f "$REBOOT_FILE.pkgs" ] && echo " by: $(sort -u "$REBOOT_FILE.pkgs" | paste -sd' ' -)"))"
    return 0
  fi
  nr="$("$NEEDRESTART" -b -r l 2>/dev/null)"
  grep -q '^NEEDRESTART-KSTA:' <<<"$nr" || { echo "UPGRADE FAIL needrestart gave no kernel state"; return 2; }
  ksta="$(sed -n 's/^NEEDRESTART-KSTA: *//p' <<<"$nr" | head -1)"
  case "$ksta" in 2|3) echo "DECISION reboot (newer kernel installed, needrestart KSTA $ksta)"; return 0 ;; esac
  while read -r s; do
    [ -z "$s" ] && continue
    if [[ "$s" =~ $NO_RESTART_RE ]]; then echo "DEFERRED $s (not restarted by pft-patch; picked up at the next planned reboot)"; continue; fi
    "$SYSTEMCTL" restart "$s" || { echo "UPGRADE FAIL systemctl restart $s"; return 2; }
    restarted+=("$s"); echo "RESTARTED $s"
  done < <(sed -n 's/^NEEDRESTART-SVC: *//p' <<<"$nr")
  if [ "${#restarted[@]}" -gt 0 ]; then echo "DECISION restart ${restarted[*]}"; else echo "DECISION none"; fi
}

# ---------- run: sentry-first orchestration (on the validator, as root) ----------

now() { if [ -n "${PFT_PATCH_NOW_FILE:-}" ]; then cat "$PFT_PATCH_NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${PFT_PATCH_NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) > "$PFT_PATCH_NOW_FILE"; else sleep "$1"; fi; }
iso() { date -u -d "@$1" +%FT%TZ; }
log() { printf '[%s] %s\n' "$(iso "$(now)")" "$*"; }

declare -A H_MODE H_SSH H_CONT H_PEERS H_POST B_INFO B_START
HOSTS=()
load_conf() {
  local kw l m s c p rest
  [ -r "$CONF" ] || { log "no hosts config $CONF (see hosts.conf.example)"; exit 3; }
  while read -r kw l rest; do
    case "$kw" in
      host)
        read -r m s c p _ <<<"$rest"
        case "$m" in local|ssh) ;; *) log "$CONF: host $l: mode must be local or ssh"; exit 3 ;; esac
        [[ "$p" =~ ^[0-9]+$ ]] || { log "$CONF: host $l: min_peers must be a number"; exit 3; }
        HOSTS+=("$l"); H_MODE[$l]="$m"; H_SSH[$l]="$s"; H_CONT[$l]="$c"; H_PEERS[$l]="$p" ;;
      post) H_POST[$l]="${H_POST[$l]:+${H_POST[$l]} && }$rest" ;;
    esac
  done < <(grep -v '^[[:space:]]*#' "$CONF")
  [ "${#HOSTS[@]}" -ge 1 ] || { log "$CONF lists no hosts"; exit 3; }
}
hx() { # LABEL CMD... : CMD as root on that host; any ssh failure is a failure of CMD
  local h="$1"; shift
  if [ "${H_MODE[$h]}" = ssh ]; then
    "$SSH" -o BatchMode=yes -o ConnectTimeout=10 "${H_SSH[$h]}" "sudo -n $(printf '%q ' "$@")"
  elif [ "$(id -u)" = 0 ] || [ "${PFT_PATCH_NOROOT:-0}" = 1 ]; then "$@"
  else sudo -n "$@"; fi
}
has() { hx "$1" bash -c "command -v $2 >/dev/null"; }
started_at() { hx "$1" docker inspect -f '{{.State.StartedAt}}' "${H_CONT[$1]}" 2>/dev/null || echo unknown; }
POLL_LINE=""
poll_node() { # LABEL -> 0 when full|proposing, peers >= min, validated ledger age <= MAX_LEDGER_AGE
  local i st p age why=()
  i="$(hx "$1" docker exec "${H_CONT[$1]}" curl -s --max-time 8 -X POST -H 'Content-Type: application/json' \
    http://127.0.0.1:5005/ -d '{"method":"server_info","params":[{}]}' 2>/dev/null | jq -c '.result.info // empty' 2>/dev/null)"
  read -r st p age < <(jq -r '[.server_state // "down", .peers // 0, .validated_ledger.age // 999999] | map(tostring) | join(" ")' <<<"${i:-{\}}")
  case "$st" in full|proposing) ;; *) why+=("state=$st") ;; esac
  [ "$p" -ge "${H_PEERS[$1]}" ] || why+=("peers=$p<${H_PEERS[$1]}")
  [ "$age" -le "$MAX_LEDGER_AGE" ] || why+=("age=${age}s>${MAX_LEDGER_AGE}s")
  POLL_LINE="state=$st peers=$p age=${age}s"
  [ "${#why[@]}" -eq 0 ] && return 0
  POLL_LINE="$POLL_LINE FAIL(${why[*]})"; return 1
}

# gate LABEL pre|post -> 0 when every check passes. One GATE line per check. post waits up to GATE_TIMEOUT for the node.
gate() {
  local h="$1" ph="$2" t0 fail=0 out rc
  t0="$(now)"
  while ! poll_node "$h"; do
    { [ "$ph" = post ] && [ $(( $(now) - t0 )) -lt "$GATE_TIMEOUT" ]; } || break
    nap "$POLL_SEC"
  done
  if [[ "$POLL_LINE" == *FAIL* ]]; then log "GATE $ph $h node: FAIL $POLL_LINE (+$(( $(now) - t0 ))s)"; fail=1
  else log "GATE $ph $h node: PASS $POLL_LINE (+$(( $(now) - t0 ))s)"; fi
  out="$(hx "$h" pft-integrity verify 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then log "GATE $ph $h integrity: PASS ($(grep -o '[0-9]* unchanged' <<<"$out" | head -1))"
  else log "GATE $ph $h integrity: FAIL exit $rc"; grep -E '^\s*\[?(WARN|FAIL)' <<<"$out" | head -10 | sed 's/^/    /'; fail=1; fi
  if has "$h" pft-audittrail; then
    if hx "$h" pft-audittrail check >/dev/null 2>&1; then log "GATE $ph $h audittrail: PASS (check exit 0)"
    else log "GATE $ph $h audittrail: FAIL (pft-audittrail check)"; fail=1; fi
  fi
  if has "$h" pft-egress; then
    if hx "$h" pft-egress check --container "${H_CONT[$h]}" >/dev/null 2>&1; then log "GATE $ph $h egress: PASS (check exit 0)"
    else log "GATE $ph $h egress: FAIL (pft-egress check --container ${H_CONT[$h]})"; fail=1; fi
  fi
  if [ "$ph" = post ]; then
    out="$(hx "$h" "$PATCH_CMD" host-info 2>/dev/null)"
    if [[ "$out" == *reboot=0* ]]; then log "GATE post $h reboot-flag: PASS (no reboot-required left)"
    else log "GATE post $h reboot-flag: FAIL (${out:-host-info unreadable})"; fail=1; fi
    if [ "$INJECT" = "$h-postgate" ]; then
      log "GATE post $h INJECTED-FAILURE: drill (PFT_PATCH_INJECT=$INJECT), not a host fault; the checks above are the real result"
      fail=1
    fi
  fi
  return "$fail"
}

SIL=""; SIL_BODY=""
window_open() { # LABEL
  local e
  if [ "$MAINT_CMD" != none ]; then
    hx "$MAINT_HOST" "$MAINT_CMD" start --ttl "$WINDOW_TTL" --reason "pft-patch $RUN_ID $1" 2>&1 | sed 's/^/    maint: /'
    [ "${PIPESTATUS[0]}" = 0 ] || { log "WINDOW $1: pft-maint start failed"; return 1; }
  fi
  SIL=""
  if [ "$AM" != none ]; then
    e="$(iso $(( $(now) + WINDOW_TTL )))"
    SIL_BODY="$(jq -nc --arg s "$(iso "$(now)")" --arg e "$e" --arg c "pft-patch $RUN_ID $1 planned patching" \
      '{matchers:[{name:"alertname",value:".+",isRegex:true,isEqual:true}],startsAt:$s,endsAt:$e,createdBy:"pft-patch",comment:$c}')"
    SIL="$(curl -s --max-time 10 -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" -d "$SIL_BODY" \
      | jq -r '.silenceID // empty' 2>/dev/null)"
    [ -n "$SIL" ] || { log "WINDOW $1: Alertmanager silence failed"; window_close "$1" fail; return 1; }
    log "WINDOW $1: pft-maint window + Alertmanager silence ${SIL:0:8} until $e"
  fi
}
window_close() { # LABEL ok|restarted|fail : end the window; the silence is expired, or kept SILENCE_TAIL after a restart
  local e
  [ "$MAINT_CMD" = none ] || hx "$MAINT_HOST" "$MAINT_CMD" end --reason "pft-patch $RUN_ID $1 $2" 2>&1 | sed 's/^/    maint: /'
  [ -n "$SIL" ] || return 0
  if [ "$2" = restarted ]; then
    e="$(iso $(( $(now) + SILENCE_TAIL )))"
    if curl -sf --max-time 10 -o /dev/null -X POST -H 'Content-Type: application/json' "$AM/api/v2/silences" \
      -d "$(jq -c --arg id "$SIL" --arg e "$e" '. + {id:$id, endsAt:$e}' <<<"$SIL_BODY")"; then
      log "WINDOW $1: closed; silence ${SIL:0:8} kept until $e (restart-related alerts stay true for a while)"
    else log "WINDOW $1: closed; silence ${SIL:0:8} update failed (it ends at its original time)"; fi
  elif curl -sf --max-time 10 -o /dev/null -X DELETE "$AM/api/v2/silence/$SIL"; then
    log "WINDOW $1: closed; silence ${SIL:0:8} expired"
  else log "WINDOW $1: closed; silence ${SIL:0:8} expire failed"; fi
  SIL=""
}

reboot_remote() { # LABEL -> 0 when the host came back with a new boot id
  local h="$1" b0 b t0
  b0="$(hx "$h" "$PATCH_CMD" host-info 2>/dev/null | sed -n 's/^boot=\([^ ]*\).*/\1/p')"
  [ -n "$b0" ] || { log "REBOOT $h: cannot read boot id"; return 1; }
  hx "$h" systemd-run --on-active=5 --unit "pft-patch-reboot-$RUN_ID" systemctl reboot >/dev/null 2>&1 \
    || { log "REBOOT $h: could not schedule the reboot"; return 1; }
  log "REBOOT $h: scheduled (boot id ${b0:0:8})"
  t0="$(now)"
  while :; do
    nap "$POLL_SEC"
    b="$(hx "$h" "$PATCH_CMD" host-info 2>/dev/null | sed -n 's/^boot=\([^ ]*\).*/\1/p')"
    [ -n "$b" ] && [ "$b" != "$b0" ] && { log "REBOOT $h: back after $(( $(now) - t0 ))s (boot id ${b:0:8})"; return 0; }
    [ $(( $(now) - t0 )) -ge "$REBOOT_TIMEOUT" ] && { log "REBOOT $h: not back within ${REBOOT_TIMEOUT}s"; return 1; }
  done
}
post_hook() { # LABEL
  [ -n "${H_POST[$1]:-}" ] || return 0
  hx "$1" bash -c "${H_POST[$1]}" 2>&1 | sed 's/^/    post: /'
  if [ "${PIPESTATUS[0]}" = 0 ]; then log "POST $1: hook ok"; return 0; fi
  log "POST $1: hook FAILED"; return 1
}
status_line() { # LABEL WHEN
  log "STATUS $2 $1: $(hx "$1" "$PATCH_CMD" status --json 2>/dev/null | jq -c '{result, updates, holds, reboot_required,
    kernel: .needrestart.ksta, services: .needrestart.services, exposed: .unattended.runtime_exposed,
    automatic_reboot: .unattended.automatic_reboot}' 2>/dev/null || echo unreadable)"
}

# untouched LABEL -> 0 when the host's boot id, dpkg.log and container start time equal the run-start record
untouched() {
  local now_i now_s
  now_i="$(hx "$1" "$PATCH_CMD" host-info 2>/dev/null)"; now_s="$(started_at "$1")"
  if [ "$now_i" = "${B_INFO[$1]}" ] && [ "$now_s" = "${B_START[$1]}" ]; then
    log "UNTOUCHED $1: boot id, dpkg.log sha256 and container StartedAt equal the run-start record ($now_i StartedAt=$now_s)"
    return 0
  fi
  log "CHANGED $1: was '${B_INFO[$1]} StartedAt=${B_START[$1]}', now '$now_i StartedAt=$now_s'"; return 1
}
stop_run() { # FAILED_LABEL REASON -> exits 1 (later hosts untouched) or 5 (a later host changed)
  local h seen=0 bad=0
  log "STOP: $1 failed ($2); hosts after it are not touched"
  for h in "${SEL[@]}"; do
    [ "$seen" = 1 ] && { untouched "$h" || bad=1; }
    [ "$h" = "$1" ] && seen=1
  done
  if [ "$bad" = 1 ]; then log "RESULT: FAIL - a host after $1 changed during the run"; exit 5; fi
  log "RESULT: FAIL at $1 ($2)"; exit 1
}

patch_host() { # LABEL -> returns on success, exits via stop_run on any failure (or 10 on a local reboot)
  local h="$1" out dec rs=0 s0
  log "=== $h (${H_MODE[$h]}, container ${H_CONT[$h]}) ==="
  status_line "$h" before
  gate "$h" pre || stop_run "$h" "pre-gate"
  window_open "$h" || stop_run "$h" "maintenance window"
  s0="$(started_at "$h")"
  out="$(hx "$h" "$PATCH_CMD" upgrade --yes "${UP_ARGS[@]}" 2>&1)"
  printf '%s\n' "$out" | sed 's/^/    /'
  dec="$(sed -n 's/^DECISION //p' <<<"$out" | tail -1)"
  [ -n "$dec" ] || { window_close "$h" fail; stop_run "$h" "upgrade failed"; }
  log "DECISION $h: $dec"
  case "$dec" in
    reboot*)
      rs=1
      if [ "${H_MODE[$h]}" = local ]; then
        jq -n --arg run "$RUN_ID" --arg h "$h" --arg sil "$SIL" --arg body "$SIL_BODY" \
          '{run:$run, host:$h, silence:$sil, silence_body:$body}' > "$RESUME_FILE"
        hx "$h" systemd-run --on-active=15 --unit "pft-patch-reboot-$RUN_ID" systemctl reboot >/dev/null 2>&1 \
          || { rm -f "$RESUME_FILE"; window_close "$h" fail; stop_run "$h" "could not schedule the reboot"; }
        log "REBOOT $h: this host reboots in 15 s; pft-patch-resume.service runs the post-gate at boot ($RESUME_FILE)"
        exit 10
      fi
      reboot_remote "$h" || { window_close "$h" fail; stop_run "$h" "reboot"; }
      post_hook "$h" || { window_close "$h" fail; stop_run "$h" "post hook"; } ;;
    restart*) rs=1 ;;
  esac
  [ "$(started_at "$h")" = "$s0" ] || rs=1
  if ! gate "$h" post; then window_close "$h" fail; status_line "$h" after; stop_run "$h" "post-gate"; fi
  status_line "$h" after
  if [ "$rs" = 1 ]; then window_close "$h" restarted; else window_close "$h" ok; fi
  log "DONE $h"
}

SEL=()
cmd_run() {
  local yes=0 hosts="" a h l found
  UP_ARGS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) yes=1 ;; --all) UP_ARGS+=(--all) ;; --runtime) UP_ARGS+=(--runtime) ;;
      --hosts) [ $# -ge 2 ] || usage; hosts="$2"; shift ;;
      *) usage ;;
    esac; shift
  done
  [ "$yes" = 1 ] || { echo "pft-patch: run installs packages and may reboot hosts; add --yes" >&2; exit 4; }
  need_root
  load_conf
  if [ -n "$hosts" ]; then
    for a in ${hosts//,/ }; do [ -n "${H_MODE[$a]:-}" ] || { log "--hosts: unknown host '$a' (not in $CONF)"; exit 3; }; done
  fi
  for h in "${HOSTS[@]}"; do   # config order, never the --hosts order: the sentry (first line) always goes first
    found=0; for a in ${hosts//,/ }; do [ "$a" = "$h" ] && found=1; done
    { [ -z "$hosts" ] || [ "$found" = 1 ]; } && SEL+=("$h")
  done
  for h in "${SEL[@]}"; do l="$h"; done
  for h in "${SEL[@]}"; do
    [ "${H_MODE[$h]}" = local ] && [ "$h" != "$l" ] && { log "REFUSED: the local host $h must be the last host (it may reboot)"; exit 4; }
  done
  MAINT_HOST="${MAINT_HOST:-}"
  if [ -z "$MAINT_HOST" ]; then for h in "${HOSTS[@]}"; do [ "${H_MODE[$h]}" = local ] && MAINT_HOST="$h"; done; fi
  [ -n "$MAINT_HOST" ] || [ "$MAINT_CMD" = none ] || { log "no local host for pft-maint (set MAINT_HOST)"; exit 3; }
  mkdir -p "$STATE_DIR"
  exec 9>"$STATE_DIR/run.lock"
  flock -n 9 || { log "REFUSED: another pft-patch run holds $STATE_DIR/run.lock"; exit 4; }
  [ -e "$RESUME_FILE" ] && { log "REFUSED: $RESUME_FILE exists (a rebooted run has not finished)"; exit 4; }
  RUN_ID="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"
  log "pft-patch run $RUN_ID: hosts ${SEL[*]} (in this order), mode $([[ " ${UP_ARGS[*]} " == *" --all "* ]] && echo all || echo security-only)$([[ " ${UP_ARGS[*]} " == *" --runtime "* ]] && echo " + Docker runtime")${INJECT:+, INJECT=$INJECT}"
  if [ "$MAINT_CMD" != none ]; then
    a="$(hx "$MAINT_HOST" "$MAINT_CMD" lock list 2>&1)"
    [ "$a" = "no data-collection locks" ] || { log "PREFLIGHT: pft-maint data-collection lock held: $a"; exit 4; }
  fi
  for h in "${SEL[@]}"; do
    has "$h" "$PATCH_CMD" || { log "PREFLIGHT $h: unreachable or $PATCH_CMD not installed"; exit 4; }
    B_INFO[$h]="$(hx "$h" "$PATCH_CMD" host-info 2>/dev/null)"; B_START[$h]="$(started_at "$h")"
    [[ "${B_INFO[$h]}" == boot=* ]] || { log "PREFLIGHT $h: host-info unreadable"; exit 4; }
    log "PREFLIGHT $h: ${B_INFO[$h]} StartedAt=${B_START[$h]}"
  done
  for h in "${SEL[@]}"; do patch_host "$h"; done
  log "RESULT: PASS - ${SEL[*]} patched and gated"
}

# resume: after the local host rebooted (pft-patch-resume.service at boot)
cmd_resume() {
  local r h
  need_root
  [ -f "$RESUME_FILE" ] || { echo "pft-patch: nothing to resume"; exit 0; }
  load_conf
  r="$(cat "$RESUME_FILE")"
  RUN_ID="$(jq -r .run <<<"$r")"; h="$(jq -r .host <<<"$r")"; SIL="$(jq -r .silence <<<"$r")"; SIL_BODY="$(jq -r .silence_body <<<"$r")"
  [ -n "${H_MODE[$h]:-}" ] || { log "resume: host $h not in $CONF"; exit 3; }
  MAINT_HOST="${MAINT_HOST:-$h}"; SEL=("$h")
  rm -f "$RESUME_FILE"
  log "pft-patch resume $RUN_ID: $h rebooted (boot $(cut -c1-8 "$BOOT_ID_FILE" 2>/dev/null))"
  post_hook "$h" || { window_close "$h" fail; stop_run "$h" "post hook"; }
  if ! gate "$h" post; then window_close "$h" fail; status_line "$h" after; stop_run "$h" "post-gate"; fi
  status_line "$h" after
  window_close "$h" restarted
  log "DONE $h"
  log "RESULT: PASS - $h patched, rebooted and gated"
}

# ---------- main ----------

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  status) [ $# -le 1 ] || usage; [ $# = 0 ] || [ "$1" = --json ] || usage; status "$@"; exit $? ;;
  policy)
    sub="${1:-}"; [ $# -gt 0 ] && shift
    yes=0; for a in "$@"; do if [ "$a" = --yes ]; then yes=1; else usage; fi; done
    case "$sub" in
      apply) policy_apply "$yes" ;;
      rollback) policy_rollback "$yes" ;;
      show) policy_text ;;
      *) usage ;;
    esac ;;
  upgrade) upgrade "$@"; exit $? ;;
  host-info) [ $# = 0 ] || usage; host_info ;;
  run) cmd_run "$@" ;;
  resume) [ $# = 0 ] || usage; cmd_resume ;;
  *) usage ;;
esac
