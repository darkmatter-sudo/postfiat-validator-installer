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

die() { echo "pft-patch: $*" >&2; exit 2; }
usage() { sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 3; }
need_root() { [ "${PFT_PATCH_NOROOT:-0}" = 1 ] || [ "$(id -u)" = 0 ] || { echo "pft-patch: needs root" >&2; exit 4; }; }
sha() { sha256sum "$1" | cut -c1-64; }
aptdump_sha() { "$APT_CONFIG" dump 2>/dev/null | sha256sum | cut -c1-64; }

# ---------- readers (each prints data on stdout; rc 1 = could not read) ----------

# "pkg<TAB>class<TAB>old<TAB>new" for every Inst line of the simulation; class = security | other.
sim_updates() {
  local out
  out="$("$APT_GET" -s -o Debug::NoLocking=1 dist-upgrade 2>&1)" || { echo "apt-get -s failed: $(tail -1 <<<"$out")"; return 1; }
  awk '/^Inst /{
    pkg=$2; old=""; if ($3 ~ /^\[/) { old=$3; gsub(/[][]/, "", old) }
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
  *) usage ;;
esac
