#!/usr/bin/env bash
# pft-audittrail: real-time, tamper-evident audit trail for a Post Fiat node host. auditd watches (keyed -w)
# over the node config, keys, sshd, sudoers, Docker and the add-on units, execve logging for docker/systemctl/
# iptables run by a logged-in user (auid >= 1000 directly or through sudo, or a root login), time-change and module-load rules,
# plus persistent journald with Forward Secure Sealing (FSS). Complements pft-integrity's hourly hash compare:
# pft-integrity says WHAT changed, the audit trail says WHEN, by WHOM and with WHICH command. No node restart.
#
# Usage: pft-audittrail plan     [--container NAME] [--immutable]
#        sudo pft-audittrail apply --yes [--dry-run] [--container NAME] [--immutable] [--key-out FILE]
#        sudo pft-audittrail check [--verify-key-file FILE]
#        sudo pft-audittrail rollback --yes [--dry-run]
#        sudo pft-audittrail report [--since "YYYY-MM-DD HH:MM:SS"|today|recent|...] [--salt-file FILE]
#
#  plan      read-only. Discovers the watched paths from the installer defaults (node config volume of the
#            container, /opt/postfiatd compose files, sshd, sudoers, Docker, pft-*/postfiat-* units and add-on
#            configs) and prints the rules file, the journald drop-in and every step apply would take.
#  apply     --dry-run prints the same plus a diff against the installed files and changes nothing. Otherwise
#            (needs --yes): installs auditd if missing, writes RULES_FILE, loads it with augenrules, snapshots the
#            loaded pft-* rules, writes the journald drop-in (Storage=persistent, Seal=yes), generates FSS keys
#            once (`journalctl --setup-keys --interval SEAL_INTERVAL`), restarts journald and rotates. The
#            verification key is written ONLY to --key-out FILE (0600, required when keys are generated) and
#            never to stdout, so a tee'd log cannot leak it: move that file off-host and delete it here.
#            --immutable also writes IMMUTABLE_FILE (-e 2): the kernel then refuses rule changes until reboot.
#  check     auditd active, auditctl -s (enabled 1, or 2 with --immutable; lost counter), loaded pft-* rules equal
#            the apply snapshot and the rules file, journald drop-in + FSS key present, `journalctl --verify` all
#            PASS (with --verify-key-file the seals are verified too). Exit 0 = PASS, 1 = drift.
#  rollback  removes the rules files and loads the rest, removes the journald drop-in and the FSS key, restarts
#            journald, stops+removes auditd if apply installed it. Immutable kernel rules stay loaded until a
#            reboot: rollback then exits 2 and must be re-run after the reboot.
#  report    Markdown summary of audit events per pft-* key: counts by auid (hashed), by command, and the
#            watched objects (paths under pft-keys/pft-agent are redacted). Usernames other than root/unset are
#            replaced by u-<8 hex> = sha256(salt + name); the salt is a root-only file (SALT_FILE).
#
# Exit codes: 0 ok/PASS, 1 check failed, 2 rollback pending reboot, 3 usage/config error, 4 refused.
# Env: CONTAINER (postfiatd, else postfiatd-sentry)  NODE_DIR (/opt/postfiatd)  SEAL_INTERVAL (15min)
#      RULES_DIR (/etc/audit/rules.d)  JOURNALD_DIR (/etc/systemd/journald.conf.d)  JOURNAL_DIR (/var/log/journal)
#      STATE_DIR (/var/lib/pft-audittrail)  SALT_FILE (STATE_DIR/salt)  EXTRA_WATCHES ("path:key path:key")
#      AGENT_DIRS ("": dirs of automation agents -> key pft-agent)  PFT_AT_CONF (/etc/pft-audittrail.env, root-owned,
#      sourced first: keep host-specific paths there, not in the repo)
#      Test hooks: PFT_AT_TEST=1 (no root)  PFT_AT_ROOT (prefix for every host path)  PFT_AT_AUDITCTL / _AUSEARCH /
#      _AUGENRULES / _JOURNALCTL / _SYSTEMCTL / _APT / _DPKG / _DOCKER (commands)  PFT_AT_MACHINE_ID

# jq/awk programs are single-quoted on purpose. "A && B || die" is intended: die always exits.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

TEST="${PFT_AT_TEST:-}"
R="${PFT_AT_ROOT:-}"
# optional root-only local settings (e.g. AGENT_DIRS, EXTRA_WATCHES): host-specific paths stay out of the repo
CONF="${PFT_AT_CONF:-$R/etc/pft-audittrail.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = "$(id -u)" ] && . "$CONF"
CONTAINER="${CONTAINER:-}"
NODE_DIR="${NODE_DIR:-/opt/postfiatd}"
SEAL_INTERVAL="${SEAL_INTERVAL:-15min}"
RULES_DIR="${RULES_DIR:-/etc/audit/rules.d}"
JOURNALD_DIR="${JOURNALD_DIR:-/etc/systemd/journald.conf.d}"
JOURNAL_DIR="${JOURNAL_DIR:-/var/log/journal}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-audittrail}"
SALT_FILE="${SALT_FILE:-$STATE_DIR/salt}"
EXTRA_WATCHES="${EXTRA_WATCHES:-}"
AGENT_DIRS="${AGENT_DIRS:-}"   # automation/agent dirs to watch under key pft-agent (always redacted in output)
RULES_FILE="$RULES_DIR/pft-audittrail.rules"
IMMUTABLE_FILE="$RULES_DIR/zz-pft-audittrail-immutable.rules"   # sorts last: augenrules concatenates by name
DROPIN="$JOURNALD_DIR/pft-audittrail.conf"
KEYS="pft-cfg pft-keys pft-ssh pft-sudo pft-docker pft-units pft-agent pft-exec pft-time pft-modules pft-canary"
AUDITCTL="${PFT_AT_AUDITCTL:-auditctl}"
AUSEARCH="${PFT_AT_AUSEARCH:-ausearch}"
AUGENRULES="${PFT_AT_AUGENRULES:-augenrules}"
JOURNALCTL="${PFT_AT_JOURNALCTL:-journalctl}"
SYSTEMCTL="${PFT_AT_SYSTEMCTL:-systemctl}"
APT="${PFT_AT_APT:-apt-get}"
DPKG="${PFT_AT_DPKG:-dpkg}"
DOCKER="${PFT_AT_DOCKER:-docker}"

usage() { sed -n '8,12p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-audittrail: $1" >&2; exit "${2:-3}"; }
log() { echo "[$(date -u +%FT%TZ)] $*"; }
need_root() { [ -n "$TEST" ] || [ "$(id -u)" -eq 0 ] || die "$CMD needs root (sudo)" 3; }
machine_id() { if [ -n "${PFT_AT_MACHINE_ID:-}" ]; then echo "$PFT_AT_MACHINE_ID"; else cat /etc/machine-id; fi; }
fss_file() { echo "$R$JOURNAL_DIR/$(machine_id)/fss"; }
# An FSS key change (apply generating keys, rollback) must not reach a journal file that is still being written:
# journald reopens the active system.journal / user-*.journal after a restart. Tags from a new key appended to a file
# sealed under the old one fail verification ("Epoch sequence out of synchronization"), and with no key loaded a
# sealed active file cannot be reopened at all, so journald silently falls back to the volatile /run journal (both
# found live on the sentry). So: stop writing to /var (--relinquish-var), archive every sealed active file under
# journald's own archive name, change the key, restart, --flush back to /var (a fresh file is created).
archive_sealed_active() {
  local d a h sid hs hr base n=0
  d="$R$JOURNAL_DIR/$(machine_id)"
  "$JOURNALCTL" --relinquish-var >/dev/null 2>&1 || die "journalctl --relinquish-var failed (journald still writing to $JOURNAL_DIR)" 1
  for a in "$d"/system.journal "$d"/user-*.journal; do
    [ -e "$a" ] || continue
    h="$("$JOURNALCTL" --header --file="$a" 2>/dev/null)"
    grep -qE '^Compatible flags:.*SEALED' <<<"$h" || continue
    sid="$(sed -nE 's/^Sequential number ID: ([0-9a-f]{32})$/\1/p' <<<"$h")"
    hs="$(sed -nE 's/^Head sequential number: [0-9]+ \(([0-9a-f]+)\)$/\1/p' <<<"$h")"
    hr="$(sed -nE 's/^Head realtime timestamp: .*\(([0-9a-f]+)\)$/\1/p' <<<"$h")"
    [ -n "$sid" ] || die "cannot read the sequential number ID of $(basename "$a") (not archived)" 1
    base="$(basename "$a" .journal)"
    mv -n "$a" "$d/$base@$sid-$(printf %016x "0x${hs:-0}")-$(printf %016x "0x${hr:-0}").journal" || die "cannot archive $(basename "$a")" 1
    [ -e "$a" ] && die "$(basename "$a") still present after archiving (name collision?)" 1
    n=$((n + 1))
  done
  log "journald relinquished $JOURNAL_DIR; archived $n sealed active journal file(s) before the key change"
}
journald_restart_persistent() { # restart journald and bring it back to /var; FAIL if it stays on the volatile /run journal
  "$SYSTEMCTL" restart systemd-journald || return 1
  "$JOURNALCTL" --flush >/dev/null 2>&1 || return 1
  [ -e "$R$JOURNAL_DIR/$(machine_id)/system.journal" ]
}

pick_container() {
  [ -n "$CONTAINER" ] && return
  local c
  for c in postfiatd postfiatd-sentry; do
    if "$DOCKER" inspect "$c" >/dev/null 2>&1; then CONTAINER="$c"; return; fi
  done
  CONTAINER=none
}

watch_list() { # -> "key<TAB>path<TAB>perm" for every existing path (missing paths go to stderr as "skip")
  local cfg="" p k e
  if [ "$CONTAINER" != none ]; then
    cfg="$("$DOCKER" inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/postfiatd"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)"
  fi
  {
    [ -n "$cfg" ] && printf 'pft-cfg\t%s\twa\n' "$cfg"
    for p in "$R$NODE_DIR"/docker-compose*.yml; do [ -e "$p" ] && printf 'pft-cfg\t%s\twa\n' "${p#"$R"}"; done
    printf 'pft-cfg\t%s\twa\n' "$NODE_DIR/.env"
    # key material: validator-keys.json / *key* in the config volume, the guide's ~/.ripple, the add-ons' keys
    if [ -n "$cfg" ]; then
      for p in "$R$cfg"/*key* "$R$cfg"/*token*; do [ -e "$p" ] && printf 'pft-keys\t%s\twa\n' "${p#"$R"}"; done
    fi
    for p in /root/.ripple /etc/pft-watchdog /etc/pft-maint; do printf 'pft-keys\t%s\twa\n' "$p"; done
    for p in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh/authorized_keys; do printf 'pft-ssh\t%s\twa\n' "$p"; done
    for p in /etc/sudoers /etc/sudoers.d; do printf 'pft-sudo\t%s\twa\n' "$p"; done
    for p in /etc/docker /etc/systemd/system/docker.service.d /usr/bin/docker /usr/bin/dockerd /usr/bin/containerd; do
      printf 'pft-docker\t%s\twa\n' "$p"; done
    printf 'pft-units\t%s\twa\n' /etc/systemd/system
    for p in "$R"/usr/local/bin/pft-* "$R"/usr/local/bin/postfiat-* "$R"/usr/local/sbin/pft-* "$R"/usr/local/sbin/postfiat-*; do
      [ -e "$p" ] && printf 'pft-units\t%s\twa\n' "${p#"$R"}"; done
    for p in "$R"/etc/pft-*.env "$R"/etc/postfiat-*.env "$R"/etc/pft-divergence "$R"/etc/pft-integrity*; do
      [ -e "$p" ] && printf 'pft-units\t%s\twa\n' "${p#"$R"}"; done
    for p in $AGENT_DIRS; do printf 'pft-agent\t%s\twa\n' "$p"; done
    printf 'pft-time\t%s\twa\n' /etc/localtime
    printf 'pft-modules\t%s\tx\n' /usr/bin/kmod
    printf 'pft-canary\t%s\twa\n' "$STATE_DIR/canary"
    for e in $EXTRA_WATCHES; do printf '%s\t%s\twa\n' "${e##*:}" "${e%:*}"; done
  } | while IFS=$'\t' read -r k p e; do
    if [ -e "$R$p" ] || [ "$k" = pft-canary ]; then printf '%s\t%s\t%s\n' "$k" "$p" "$e"
    else echo "skip $k $p (absent)" >&2; fi
  done | sort -u -t$'\t' -k2,2 | sort -t$'\t' -k1,1 -k2,2
}

exe_of() { local p; p="$(command -v "$1" 2>/dev/null)" || return 1; readlink -f "$p"; }

render_rules() { # -> the rules file (deterministic for the same host)
  local k p e x
  echo "## pft-audittrail rules - generated by pft-audittrail.sh; edit the script, not this file"
  echo "## keys: $KEYS"
  watch_list 2>/dev/null | while IFS=$'\t' read -r k p e; do echo "-w $p -p $e -k $k"; done
  for x in docker systemctl iptables; do
    if [ -n "${PFT_AT_TEST:-}" ]; then e="/usr/bin/$x"; else e="$(exe_of "$x")" || continue; fi
    echo "-a always,exit -F arch=b64 -S execve -F exe=$e -F auid>=1000 -F auid!=unset -k pft-exec"
    echo "-a always,exit -F arch=b64 -S execve -F exe=$e -F auid=0 -k pft-exec"   # root SSH logins (services: auid unset)
  done | sort -u
  echo "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k pft-time"
  echo "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k pft-time"
  echo "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k pft-modules"
  echo "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k pft-modules"
}
rule_count() { grep -c '^-[wa] ' ; }

# Audit=yes: journald's default (Audit=no on systemd 249) turns kernel auditing OFF whenever journald restarts
render_dropin() { printf '# pft-audittrail: persistent, sealed journal; keep kernel auditing on\n[Journal]\nStorage=persistent\nSeal=yes\nAudit=yes\n'; }
audit_enabled() { "$AUDITCTL" -s 2>/dev/null | awk '$1=="enabled"{print $2}'; }

state_json() { cat "$R$STATE_DIR/state.json" 2>/dev/null || echo '{}'; }
auditd_installed() { "$DPKG" -s auditd 2>/dev/null | grep -q '^Status: install ok installed'; }

print_plan() { # IMMUTABLE
  local rules n
  rules="$(render_rules)"; n="$(rule_count <<<"$rules")"
  echo "pft-audittrail plan - container: $CONTAINER | auditd installed: $(auditd_installed && echo yes || echo no)"
  echo "watches by key:"; watch_list 2>/dev/null | cut -f1 | sort | uniq -c | sed 's/^ */  /'
  watch_list 2>&1 >/dev/null | sed 's/^/  /'
  echo "== $RULES_FILE ($n rules)"; redact_paths <<<"$rules"
  if [ "$1" = 1 ]; then echo "== $IMMUTABLE_FILE"; echo "-e 2"; else echo "== immutable: off (use --immutable for -e 2)"; fi
  echo "== $DROPIN"; render_dropin
  echo "== FSS: $(if [ -e "$(fss_file)" ]; then echo "key present, kept"; else echo "keys generated (interval $SEAL_INTERVAL), verification key -> --key-out FILE only"; fi)"
}

redact_paths() { # pft-keys / pft-agent paths are secret-adjacent: never print them
  sed -E 's#^(-w )[^ ]+( -p [a-z]+ -k (pft-keys|pft-agent))$#\1<redacted>\2#'
}

loaded_pft_rules() { "$AUDITCTL" -l 2>/dev/null | grep -E '(-k |key=)pft-' ; }

do_apply() { # YES DRY IMMUTABLE KEYOUT
  local rules dropin st installed=false gen=false n_loaded n_file en
  rules="$(render_rules)"; dropin="$(render_dropin)"
  if [ "$2" = 1 ]; then
    print_plan "$3"
    echo "== diff against installed files"
    diff -u <({ redact_paths < "$R$RULES_FILE"; } 2>/dev/null) <(redact_paths <<<"$rules") --label "installed $RULES_FILE" --label "new" || true
    diff -u "$R$DROPIN" <(echo "$dropin") --label "installed $DROPIN" --label "new" 2>/dev/null || true
    echo "dry-run: nothing changed"; return 0
  fi
  [ "$1" = 1 ] || die "apply changes audit + journald config; re-run with --yes (or --dry-run)" 4
  if [ ! -e "$(fss_file)" ] && [ -z "$4" ]; then die "no FSS key yet: apply generates one, pass --key-out FILE (root-only, move it off-host)" 4; fi
  if [ -n "$4" ] && [ -e "$4" ]; then die "--key-out $4 exists; refusing to overwrite a verification key" 4; fi
  st="$(state_json)"
  if ! auditd_installed; then
    log "installing auditd"
    DEBIAN_FRONTEND=noninteractive "$APT" install -y -q auditd >/dev/null || die "apt-get install auditd failed" 3
    installed=true
  else installed="$(jq -r '.installed_auditd // false' <<<"$st")"; fi
  mkdir -p "$R$STATE_DIR" "$R$RULES_DIR" "$R$JOURNALD_DIR" && chmod 700 "$R$STATE_DIR"
  [ -e "$R$STATE_DIR/canary" ] || echo "pft-audittrail canary: write here to test the audit pipeline" > "$R$STATE_DIR/canary"
  [ -e "$R$SALT_FILE" ] || { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$R$SALT_FILE"; chmod 600 "$R$SALT_FILE"; }
  printf '%s\n' "$rules" > "$R$RULES_FILE.tmp" && chmod 640 "$R$RULES_FILE.tmp" && mv "$R$RULES_FILE.tmp" "$R$RULES_FILE"
  if [ "$3" = 1 ]; then printf '## pft-audittrail: kernel audit config immutable until reboot\n-e 2\n' > "$R$IMMUTABLE_FILE"
  else rm -f "$R$IMMUTABLE_FILE"; fi
  log "loading rules ($(rule_count <<<"$rules") in $RULES_FILE, immutable=$([ "$3" = 1 ] && echo on || echo off))"
  "$AUGENRULES" --load >/dev/null 2>&1 || die "augenrules --load failed (see: auditctl -s; immutable from an earlier -e 2?)" 1
  loaded_pft_rules > "$R$STATE_DIR/rules.loaded"
  n_loaded="$(wc -l < "$R$STATE_DIR/rules.loaded")"; n_file="$(rule_count <<<"$rules")"
  [ "$n_loaded" -eq "$n_file" ] || die "loaded $n_loaded pft-* rules, rules file has $n_file" 1
  if [ ! -e "$R$DROPIN" ] || [ "$(cat "$R$DROPIN")" != "$dropin" ]; then echo "$dropin" > "$R$DROPIN"; fi
  if [ ! -e "$(fss_file)" ]; then
    archive_sealed_active
    ( umask 077; "$JOURNALCTL" --setup-keys --interval="$SEAL_INTERVAL" 2>/dev/null > "$4" ) || { rm -f "$4"; die "journalctl --setup-keys failed" 1; }
    [ -s "$4" ] || die "journalctl --setup-keys printed no verification key" 1
    gen=true
    log "FSS keys generated (interval $SEAL_INTERVAL); verification key written to --key-out file only (0600), sha256 prefix $(sha256sum "$4" | cut -c1-12): move it off-host and delete it here"
  fi
  journald_restart_persistent && "$JOURNALCTL" --rotate >/dev/null 2>&1 || die "journald restart/flush/rotate failed (system journal not back on $JOURNAL_DIR?)" 1
  en="$(audit_enabled)"
  case "$en" in 1|2) ;; *) die "kernel auditing is enabled=${en:-?} after the journald restart (expected 1 or 2)" 1 ;; esac
  jq -n --arg t "$(date -u +%FT%TZ)" --argjson inst "$installed" --argjson imm "$([ "$3" = 1 ] && echo true || echo false)" \
        --argjson n "$n_loaded" --arg c "$CONTAINER" --arg ks "$( [ "$gen" = true ] && sha256sum "$4" | cut -c1-12 || jq -r '.key_sha12 // ""' <<<"$st")" \
        '{applied_at:$t, installed_auditd:$inst, immutable:$imm, rules:$n, container:$c, key_sha12:$ks}' > "$R$STATE_DIR/state.json"
  log "apply done: $n_loaded rules loaded, journald sealed (Seal=yes, Storage=persistent)"
}

journal_verify() { # [KEYFILE] -> journalctl --verify output with the per-file paths reduced to basenames
  local k=()
  [ -n "${1:-}" ] && k=(--verify-key="$(cat "$1")")
  "$JOURNALCTL" --verify "${k[@]}" 2>&1 | sed -E 's#/[^ ]*/[0-9a-f]{32}/##g'   # no machine-id paths in output
}

do_check() { # KEYFILE
  local st fails=0 en lost exp live jv nokey bad
  st="$(state_json)"
  f() { echo "  [FAIL] $*"; fails=$((fails + 1)); }
  p() { echo "  [PASS] $*"; }
  echo "pft-audittrail check - $(date -u +%FT%TZ)"
  [ "$st" != '{}' ] || f "not applied (no $STATE_DIR/state.json)"
  if [ "$("$SYSTEMCTL" is-active auditd 2>/dev/null)" = active ]; then p "auditd active"; else f "auditd not active"; fi
  en="$(audit_enabled)"; lost="$("$AUDITCTL" -s 2>/dev/null | awk '$1=="lost"{print $2}')"
  exp=1; [ "$(jq -r '.immutable // false' <<<"$st")" = true ] && exp=2
  if [ "${en:-0}" = "$exp" ]; then p "audit enabled=$en (expected $exp)"; else f "audit enabled=${en:-?} (expected $exp)"; fi
  echo "  [INFO] lost events: ${lost:-?}"
  live="$(loaded_pft_rules)"
  if [ ! -e "$R$RULES_FILE" ]; then f "rules file $RULES_FILE missing"
  elif [ "$(rule_count < "$R$RULES_FILE")" -ne "$(grep -c . <<<"$live")" ]; then
    f "loaded pft-* rules $(grep -c . <<<"$live") != rules file $(rule_count < "$R$RULES_FILE")"
  else p "loaded pft-* rules = rules file ($(rule_count < "$R$RULES_FILE"))"; fi
  if [ -e "$R$STATE_DIR/rules.loaded" ] && [ "$live" = "$(cat "$R$STATE_DIR/rules.loaded")" ]; then p "loaded rules identical to apply snapshot"
  else f "loaded rules differ from apply snapshot:"; diff <(cat "$R$STATE_DIR/rules.loaded" 2>/dev/null) <(echo "$live") | grep '^[<>]' | redact_loaded | sed 's/^/      /'; fi
  if [ "$(cat "$R$DROPIN" 2>/dev/null)" = "$(render_dropin)" ]; then p "journald drop-in Storage=persistent Seal=yes"; else f "journald drop-in missing or changed"; fi
  if [ -e "$(fss_file)" ]; then p "FSS sealing key present"; else f "FSS sealing key missing"; fi
  # Without the (off-host) verification key journalctl refuses sealed files with "Required key not available"
  # before reading them: those are counted, not failed. Every other FAIL is drift. With the key, all must PASS.
  jv="$(journal_verify "${1:-}")"
  nokey="$(grep -c '^FAIL: .*(Required key not available)$' <<<"$jv")"
  [ -n "${1:-}" ] && nokey=0
  bad="$(grep -E -v '^PASS: |has sealing enabled but verification key has not been passed' <<<"$jv" | grep -v -E '^FAIL: .*\(Required key not available\)$' | grep -c .)"
  [ -n "${1:-}" ] && bad="$(grep -v '^PASS: ' <<<"$jv" | grep -c .)"
  if [ "$bad" -gt 0 ] || ! grep -q -E '^PASS: |Required key not available' <<<"$jv"; then
    f "journalctl --verify$([ -n "${1:-}" ] && echo ' --verify-key'):"; grep -v '^PASS: ' <<<"$jv" | head -6 | sed 's/^/      /'
  else p "journalctl --verify$([ -n "${1:-}" ] && echo ' --verify-key'): $(grep -c '^PASS: ' <<<"$jv") files PASS$([ "$nokey" -gt 0 ] && echo ", $nokey sealed file(s) need the off-host key (--verify-key-file) for seal verification")"; fi
  if [ "$fails" -eq 0 ]; then echo "RESULT: PASS -> exit 0"; return 0; fi
  echo "RESULT: FAIL ($fails) -> exit 1"; return 1
}
redact_loaded() { sed -E 's#(-w )[^ ]+( -p [a-z]+ -k (pft-keys|pft-agent))#\1<redacted>\2#; s#(dir|path)=[^ ]+( .*key=(pft-keys|pft-agent))#\1=<redacted>\2#'; }

do_rollback() { # YES DRY
  local st en en0
  st="$(state_json)"
  if [ "$2" = 1 ]; then
    echo "rollback would remove: $RULES_FILE $IMMUTABLE_FILE $DROPIN $(fss_file | sed "s#^$R##") $STATE_DIR"
    echo "auditd: $([ "$(jq -r '.installed_auditd // false' <<<"$st")" = true ] && echo "stopped + removed (installed by apply)" || echo "kept (was installed before apply)")"
    echo "dry-run: nothing changed"; return 0
  fi
  [ "$1" = 1 ] || die "rollback changes audit + journald config; re-run with --yes (or --dry-run)" 4
  en0="$(audit_enabled)"
  if [ -e "$(fss_file)" ]; then archive_sealed_active; fi
  rm -f "$R$RULES_FILE" "$R$IMMUTABLE_FILE" "$R$DROPIN" "$(fss_file)"
  log "removed rules files, journald drop-in, FSS key"
  if journald_restart_persistent; then log "journald restarted, writing to $JOURNAL_DIR (unsealed)"
  else log "WARN: journald restart/flush failed or no system.journal on $JOURNAL_DIR: check 'journalctl --header' and run 'journalctl --flush'"; fi
  en="$(audit_enabled)"
  # without our Audit=yes drop-in the restarted journald (Audit=no default) has just switched kernel auditing off
  if [ "$en0" = 1 ] && [ "$en" = 0 ]; then "$AUDITCTL" -e 1 >/dev/null 2>&1; en="$(audit_enabled)"; log "journald restart disabled kernel auditing; re-enabled: enabled=$en"; fi
  if [ "$en" = 2 ]; then
    log "kernel audit config is IMMUTABLE (enabled 2): loaded rules stay until reboot; reboot, then re-run rollback --yes"
    return 2
  fi
  if auditd_installed; then "$AUGENRULES" --load >/dev/null 2>&1 || "$AUDITCTL" -D >/dev/null 2>&1; fi
  if [ -n "$(loaded_pft_rules)" ]; then "$AUDITCTL" -D >/dev/null 2>&1; fi
  if [ "$(jq -r '.installed_auditd // false' <<<"$st")" = true ]; then
    "$AUDITCTL" -D >/dev/null 2>&1
    "$SYSTEMCTL" stop auditd >/dev/null 2>&1; "$APT" remove -y -q auditd >/dev/null 2>&1 || log "WARN: apt-get remove auditd failed"
    log "auditd stopped + removed (installed by apply; /var/log/audit kept)"
  fi
  [ -z "$(loaded_pft_rules)" ] || die "pft-* rules still loaded after rollback" 1
  rm -rf -- "$R${STATE_DIR:?}"
  log "rollback done: no pft-* rules loaded, journald drop-in and FSS key removed"
}

hash_user() { # SALT NAME -> root/unset/numbers stay, names -> u-<8 hex>
  case "$2" in root|unset|-1|4294967295|"") echo "${2:-unset}" ;; *) printf '%s%s' "$1" "$2" | sha256sum | cut -c1-8 | sed 's/^/u-/' ;; esac
}

do_report() { # SINCE SALTFILE
  local salt k rows n
  salt="$(cat "$2" 2>/dev/null)" || die "salt file $2 not readable (apply creates it; report needs root)" 3
  echo "# pft-audittrail report - $(date -u +%FT%TZ) - since: $1"
  echo
  echo "Usernames other than root/unset are hashed (u-<sha256(salt+name)[:8]>); objects under pft-keys/pft-agent are redacted."
  echo
  echo "| key | events | by auid | by command | objects |"
  echo "|---|---:|---|---|---|"
  for k in $KEYS; do
    # ausearch --format csv: 2 EVENT, 8 SUBJ_PRIME (auid), 13 OBJ_PRIME, 16 HOW (exe). --input-logs + </dev/null:
    # without them ausearch reads stdin whenever stdin is not a tty (it swallowed the rest of a heredoc once)
    rows="$("$AUSEARCH" --input-logs -k "$k" --start "$1" --format csv </dev/null 2>/dev/null | tail -n +2 |
      awk -F, -v k="$k" '{ n = split($16, x, "/"); o = ($2 == "CONFIG_CHANGE") ? "(rule change)" :
        ((k == "pft-keys" || k == "pft-agent") ? "<redacted>" : $13)
        # fd-based syscalls (fchmod/fchown on an open file) carry no path: name the action instead of printing ""
        if (o == "") o = "(no path: " $11 ")"; print $8 "\t" x[n] "\t" o }')"
    n="$(grep -c . <<<"$rows")"
    if [ "$n" -eq 0 ]; then echo "| $k | 0 | | | |"; continue; fi
    printf '| %s | %d | %s | %s | %s |\n' "$k" "$n" \
      "$(cut -f1 <<<"$rows" | while read -r u; do hash_user "$salt" "$u"; done | top5)" \
      "$(cut -f2 <<<"$rows" | top5)" "$(cut -f3 <<<"$rows" | top5)"
  done
}
top5() { sort | uniq -c | sort -k1,1nr -k2 | head -5 | awk '{c = $1; $1 = ""; sub(/^ /, ""); printf "%s%s (%d)", (NR > 1 ? ", " : ""), $0, c}'; }

CMD="${1:-}"; [ -n "$CMD" ] || { usage; exit 3; }; shift
YES=0; DRY=0; IMM=0; KEYOUT=""; VKEY=""; SINCE="today"; SALT="$SALT_FILE"
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;; --dry-run) DRY=1 ;; --immutable) IMM=1 ;;
    --container) CONTAINER="${2:?}"; shift ;; --key-out) KEYOUT="${2:?}"; shift ;;
    --verify-key-file) VKEY="${2:?}"; shift ;; --since) SINCE="${2:?}"; shift ;; --salt-file) SALT="${2:?}"; shift ;;
    -h|--help) usage; exit 0 ;; *) die "unknown option $1" 3 ;;
  esac; shift
done
case "$CMD" in
  plan) pick_container; print_plan "$IMM" ;;
  apply) need_root; pick_container; do_apply "$YES" "$DRY" "$IMM" "$KEYOUT" ;;
  check) need_root; do_check "$VKEY" ;;
  rollback) need_root; do_rollback "$YES" "$DRY" ;;
  report) need_root; do_report "$SINCE" "$R$SALT" ;;
  -h|--help|help) usage ;;
  *) usage; exit 3 ;;
esac
