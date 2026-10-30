#!/usr/bin/env bash
# pft-sshcrypto: audit the SSH algorithms and host keys a Post Fiat validator/sentry host offers, apply a hardened
# crypto policy safely (validated drop-in, reload not restart, new-session confirmation, timed automatic revert) and
# roll it back byte-identically.
#
# Usage: pft-sshcrypto audit [--json] [--no-probe] [--textfile-dir DIR]   grade sshd -T + host keys, loopback probes
#        sudo pft-sshcrypto apply [--policy FILE] [--revert-after SECS]   install the policy drop-in (see below)
#        sudo pft-sshcrypto rollback [--auto]                             restore the pre-apply files byte-identically
#        pft-sshcrypto status                                             state, snapshot, armed revert timer
#        sudo pft-sshcrypto pull                                          validator: copy the peer's textfile
#        pft-sshcrypto validate FILE HOST                                 exit 0 if FILE is an acceptable textfile
#        pft-sshcrypto policy-table | version
#
#  audit  1. `sshd -T` (the effective config of every file sshd will read), 2. `ssh-keygen -l` of every HostKey
#         (type + bits only; paths and fingerprints are never printed), 3. unless --no-probe: loopback-only handshake
#         probes. The grader's plan lists, per kind (kex/cipher/mac/hostkey), the first offered OK algorithm
#         (positive control) and a fixed list of weak algorithms. Each is offered ALONE by `ssh` to 127.0.0.1 (or
#         ::1) on the first configured port, user pft-sshcrypto-probe, no keys: "Permission denied" = negotiated,
#         "no matching ..." = rejected. A probe whose outcome contradicts sshd -T is a MISMATCH (the running daemon
#         is not serving the config on disk, e.g. no reload). Algorithms the local client lacks are skipped.
#         4. sshcrypto_grade.py grades every offered algorithm OK/WARN/FAIL (policy table: `policy-table`, README).
#         Output: one line per algorithm/key/probe + RESULT line; --json one object.
#         Exit: 0 everything OK; 1 any WARN or FAIL or probe mismatch; 2 audit error (sshd -T failed, unreadable
#         host key, probe could not run, no loopback listener).
#         Writes TEXTFILE_DIR/pft_sshcrypto_HOST.prom atomically on every run (also failed ones: up 0).
#  apply  1. refuse if a revert is already armed. 2. first apply only: snapshot sshd_config + every file in
#         sshd_config.d (sha256 manifest, a copy of DROPIN or "absent", sha256 of sshd -T) into STATE_DIR/pre.
#         3. write the policy (default LIBDIR/hardened.conf) to DROPIN; `sshd -t` must pass and `sshd -T` must show
#         every policy directive with exactly the policy value (an earlier drop-in could shadow it). On failure the
#         snapshot is restored at once (sshd was not reloaded, so nothing took effect).
#         4. arm the revert: transient timer pft-sshcrypto-revert.timer (systemd-run --on-active=REVERT_AFTER) that
#         runs `pft-sshcrypto rollback --auto`. 5. `systemctl reload ssh` (existing sessions are untouched).
#         6. confirm a NEW session: ssh with the default client algorithms, the loopback-only confirm key (forced
#         command, from="127.0.0.1,::1") and strict host key checking against this host's own .pub keys must print
#         the confirm token; then an audit with probes must show 0 mismatches and no audit error.
#         7. confirmed: stop the timer, record STATE_DIR/applied -> exit 0. Not confirmed: exit 3 and LEAVE the
#         timer armed; it rolls back at the deadline (no second login needed). Exit 2: refused/invalid policy.
#  rollback  restore DROPIN from STATE_DIR/pre (or delete it if it was absent), `sshd -t`, reload, then require the
#         sha256 manifest of sshd_config + sshd_config.d AND the sha256 of `sshd -T` to equal the snapshot, and a
#         confirmed new session. Then stop the timer, keep the snapshot as STATE_DIR/last-rollback, exit 0.
#         Exit 2 when there is nothing to roll back or a check fails.
#  pull   "$PULL_SSH cat -- REMOTE_DIR/pft_sshcrypto_PEER.prom" (timeout PULL_TIMEOUT), validate, rename into place.
#
# Config: /etc/pft-sshcrypto.env (KEY=VALUE, root-owned; PFT_SC_CONF overrides): HOST_LABEL (validator), PEER_LABEL
#   (sentry), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), REMOTE_DIR (same), REVERT_AFTER (120 s), PULL_SSH,
#   PULL_TIMEOUT (30), SSH_UNIT (ssh).
# Test hooks: PFT_SC_ROOT (prefix for /etc/ssh and /var/lib/pft-sshcrypto), PFT_SC_SSHD PFT_SC_SSH PFT_SC_KEYGEN
#   PFT_SC_SYSTEMCTL PFT_SC_SYSTEMD_RUN (commands), PFT_SC_LIB (dir with sshcrypto_grade.py + hardened.conf),
#   PFT_SC_NOW (epoch), PFT_SC_SELF (command the revert timer runs).
set -uo pipefail
umask 022
VERSION=1.0.0

HOST_LABEL=validator; PEER_LABEL=sentry; TEXTFILE_DIR=/var/lib/pft-exporter/textfile
REMOTE_DIR=/var/lib/pft-exporter/textfile; REVERT_AFTER=120; PULL_SSH=""; PULL_TIMEOUT=30; SSH_UNIT=ssh
MAX_BYTES=16384
CONF="${PFT_SC_CONF:-/etc/pft-sshcrypto.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|TEXTFILE_DIR|REMOTE_DIR|REVERT_AFTER|PULL_SSH|PULL_TIMEOUT|SSH_UNIT)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
      *) printf 'pft-sshcrypto: unknown key %s in %s\n' "$k" "$CONF" >&2; exit 2 ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi
ROOT="${PFT_SC_ROOT:-}"
SSHD="${PFT_SC_SSHD:-/usr/sbin/sshd}"
SSH="${PFT_SC_SSH:-ssh}"
KEYGEN="${PFT_SC_KEYGEN:-ssh-keygen}"
SYSTEMCTL="${PFT_SC_SYSTEMCTL:-systemctl}"
SYSTEMD_RUN="${PFT_SC_SYSTEMD_RUN:-systemd-run}"
LIBDIR="${PFT_SC_LIB:-/usr/local/lib/pft-sshcrypto}"
SELF="${PFT_SC_SELF:-/usr/local/bin/pft-sshcrypto}"
GRADER="$LIBDIR/sshcrypto_grade.py"
SSHDIR="$ROOT/etc/ssh"
DROPIN="$SSHDIR/sshd_config.d/10-pft-sshcrypto.conf"
STATE="$ROOT/var/lib/pft-sshcrypto"
PRE="$STATE/pre"
TIMER=pft-sshcrypto-revert
TOKEN=pft-sshcrypto-confirm-ok
PROBE_USER=pft-sshcrypto-probe

die() { printf 'pft-sshcrypto: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { if [ -n "${PFT_SC_NOW:-}" ]; then echo "$PFT_SC_NOW"; else date -u +%s; fi; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
log() { printf '%s %s\n' "$(ts)" "$*"; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
sha() { sha256sum < "$1" | cut -c1-64; }
if ! [[ "$REVERT_AFTER" =~ ^[0-9]+$ ]] || [ "$REVERT_AFTER" -lt 30 ]; then die "REVERT_AFTER must be >= 30 seconds"; fi
valid_label "$HOST_LABEL" || die "bad HOST_LABEL"

# manifest -> "sha256  name" for sshd_config and every regular file in sshd_config.d, sorted by name
manifest() {
  local f
  printf '%s  sshd_config\n' "$(sha "$SSHDIR/sshd_config")"
  for f in "$SSHDIR"/sshd_config.d/* "$SSHDIR"/sshd_config.d/.[!.]*; do
    [ -f "$f" ] && printf '%s  sshd_config.d/%s\n' "$(sha "$f")" "$(basename "$f")"
  done | sort -k2
}
effective_sha() { "$SSHD" -T 2>/dev/null | sha256sum | cut -c1-64; }

# loopback "ADDR PORT" from sshd -T output FILE, rc 1 if sshd listens on no loopback/wildcard address
loopback() {
  local port addr
  port="$(awk '$1=="port"{print $2; exit}' "$1")"
  while read -r _ addr; do
    case "$addr" in
      0.0.0.0:"$port"|127.0.0.1:"$port") echo "127.0.0.1 $port"; return 0 ;;
    esac
  done < <(grep '^listenaddress ' "$1")
  while read -r _ addr; do
    case "$addr" in
      "[::]:$port"|"[::1]:$port") echo "::1 $port"; return 0 ;;
    esac
  done < <(grep '^listenaddress ' "$1")
  return 1
}

# probe KIND ALG ADDR PORT NONAEAD -> negotiated | rejected | skipped | error:<first output line>
# (LogLevel INFO: at ERROR, ssh 8.9 prints nothing for "Unable to negotiate ... no matching ...")
probe() {
  local kind="$1" alg="$2" addr="$3" port="$4" nonaead="$5" opt out q
  case "$kind" in
    kex) opt=KexAlgorithms; q=kex ;; cipher) opt=Ciphers; q=cipher ;; mac) opt=MACs; q=mac ;;
    hostkey) opt=HostKeyAlgorithms; q=HostKeyAlgorithms ;; *) echo "error:unknown kind"; return ;;
  esac
  if ! "$SSH" -Q "$q" 2>/dev/null | grep -qxF "$alg"; then echo skipped; return; fi
  local extra=()
  if [ "$kind" = mac ]; then
    # a MAC is only used with a non-AEAD cipher; without one offered the MAC list is never negotiated
    [ -n "$nonaead" ] || { echo skipped; return; }
    extra=(-o "Ciphers=$nonaead")
  fi
  out="$(timeout 20 "$SSH" -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityFile=/dev/null \
    -o IdentityAgent=none -o PreferredAuthentications=publickey -o LogLevel=INFO "${extra[@]}" -o "$opt=$alg" \
    -p "$port" -l "$PROBE_USER" "$addr" true 2>&1 < /dev/null)"
  case "$out" in
    *"no matching"*) echo rejected ;;
    *"Permission denied (publickey"*) echo negotiated ;;
    *) echo "error:$(printf '%s' "$out" | head -1 | cut -c1-120)" ;;
  esac
}

# audit [--json] [--no-probe] [--textfile-dir DIR] -> grader exit code
audit() {
  local json=false probe_on=true tdir="$TEXTFILE_DIR" t rc p out bits type kind alg exp res lb addr port nonaead
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=true ;; --no-probe) probe_on=false ;;
      --textfile-dir) tdir="${2:?}"; shift ;;
      *) die "unknown audit option $1" ;;
    esac
    shift
  done
  t="$(mktemp -d)"; : > "$t/keys"; : > "$t/probes"; : > "$t/errors"
  if ! "$SSHD" -T > "$t/sshdT" 2> "$t/sshdT.err"; then
    printf 'sshd -T\t%s\n' "$(head -1 "$t/sshdT.err" | cut -c1-160)" >> "$t/errors"
    : > "$t/sshdT"
  fi
  while read -r _ p; do
    if ! out="$("$KEYGEN" -lf "$p" 2>/dev/null)"; then
      printf 'host key\tssh-keygen -l failed for one HostKey\n' >> "$t/errors"; continue
    fi
    bits="${out%% *}"; type="${out##*(}"; type="${type%)}"
    printf '%s\t%s\n' "$type" "$bits" >> "$t/keys"
  done < <(grep '^hostkey ' "$t/sshdT")
  if $probe_on && [ -s "$t/sshdT" ]; then
    if lb="$(loopback "$t/sshdT")"; then
      read -r addr port <<< "$lb"
      nonaead="$(awk '$1=="ciphers"{print $2; exit}' "$t/sshdT" | tr ',' '\n' | grep -E -- '-(ctr|cbc)$' | head -1)"
      while IFS=$'\t' read -r kind alg exp; do
        res="$(probe "$kind" "$alg" "$addr" "$port" "$nonaead" | tr '\t' ' ')"
        printf '%s\t%s\t%s\t%s\n' "$kind" "$alg" "$exp" "$res" >> "$t/probes"
      done < <(python3 "$GRADER" plan --sshd-t "$t/sshdT" --hostkeys "$t/keys")
    else
      printf 'probe\tsshd listens on no loopback or wildcard address (use --no-probe)\n' >> "$t/errors"
    fi
  fi
  local args=(grade --sshd-t "$t/sshdT" --hostkeys "$t/keys" --probes "$t/probes" --moduli "$SSHDIR/moduli"
    --extra-errors "$t/errors" --host "$HOST_LABEL" --now "$(now)" --metrics "$t/metrics")
  $json && args+=(--json)
  $json || echo "pft-sshcrypto audit - $(ts) host=$HOST_LABEL"
  python3 "$GRADER" "${args[@]}"; rc=$?
  if [ -s "$t/metrics" ] && [ -d "$tdir" ]; then
    {
      cat "$t/metrics"
      echo "# HELP pft_sshcrypto_policy_applied 1 if pft-sshcrypto apply is committed on this host."
      echo "# TYPE pft_sshcrypto_policy_applied gauge"
      echo "pft_sshcrypto_policy_applied{host=\"$HOST_LABEL\"} $([ -f "$STATE/applied" ] && echo 1 || echo 0)"
      echo "# HELP pft_sshcrypto_revert_pending 1 while an applied policy waits for confirmation or revert."
      echo "# TYPE pft_sshcrypto_revert_pending gauge"
      echo "pft_sshcrypto_revert_pending{host=\"$HOST_LABEL\"} $([ -f "$STATE/pending" ] && echo 1 || echo 0)"
    } > "$tdir/.pft_sshcrypto_$HOST_LABEL.prom.tmp" && mv -f "$tdir/.pft_sshcrypto_$HOST_LABEL.prom.tmp" "$tdir/pft_sshcrypto_$HOST_LABEL.prom"
  fi
  rm -rf "$t"
  return "$rc"
}

# confirm -> rc 0 if a NEW ssh session logs in with the confirm key and prints the token; reason on stdout otherwise
# (LogLevel INFO, not ERROR: at ERROR ssh 8.9 prints nothing for "Unable to negotiate", so the reason was empty;
# found by the first live drill, logs/08-host-run-validator-failed.log)
confirm() {
  local t lb addr port out
  t="$(mktemp)"
  "$SSHD" -T > "$t" 2>/dev/null || { rm -f "$t"; echo "sshd -T failed"; return 1; }
  lb="$(loopback "$t")" || { rm -f "$t"; echo "no loopback listener"; return 1; }
  rm -f "$t"
  read -r addr port <<< "$lb"
  if [ ! -f "$STATE/confirm_ed25519" ] || [ ! -f "$STATE/known_hosts" ]; then echo "confirm key missing (run install.sh)"; return 1; fi
  out="$(timeout 30 "$SSH" -F /dev/null -i "$STATE/confirm_ed25519" -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$STATE/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=pft-sshcrypto-loopback -o LogLevel=INFO -p "$port" \
    -l root "$addr" 2>&1 < /dev/null)"
  if [ "$(printf '%s' "$out" | tr -d '\r' | tail -1)" = "$TOKEN" ]; then return 0; fi
  printf '%s' "$out" | tr -d '\r' | head -1 | cut -c1-160
  return 1
}

restore_pre() { # put DROPIN back as it was in the snapshot
  if [ -f "$PRE/dropin.absent" ]; then rm -f "$DROPIN"; else cp -p "$PRE/dropin" "$DROPIN"; fi
}

apply() {
  local policy="$LIBDIR/hardened.conf" after="$REVERT_AFTER" d v eff why deadline rc
  while [ $# -gt 0 ]; do
    case "$1" in
      --policy) policy="${2:?}"; shift ;;
      --revert-after) after="${2:?}"; shift ;;
      *) die "unknown apply option $1" ;;
    esac
    shift
  done
  if ! [[ "$after" =~ ^[0-9]+$ ]] || [ "$after" -lt 30 ]; then die "--revert-after must be >= 30 seconds"; fi
  [ -f "$policy" ] || die "policy file $policy not found"
  [ -d "$SSHDIR/sshd_config.d" ] || die "$SSHDIR/sshd_config.d missing"
  grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf' "$SSHDIR/sshd_config" \
    || die "sshd_config does not Include sshd_config.d/*.conf"
  if "$SYSTEMCTL" is-active --quiet "$TIMER.timer" || [ -f "$STATE/pending" ]; then
    die "a revert is already armed ($STATE/pending); wait for it or run rollback"
  fi
  grep -qvE '^[[:space:]]*(#|$|(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms)[[:space:]])' "$policy" \
    && die "policy may only set KexAlgorithms, Ciphers, MACs, HostKeyAlgorithms"
  mkdir -p "$STATE"; chmod 700 "$STATE"
  if [ ! -d "$PRE" ]; then
    mkdir -p "$PRE.tmp"
    manifest > "$PRE.tmp/manifest"
    if [ -f "$DROPIN" ]; then cp -p "$DROPIN" "$PRE.tmp/dropin"; else : > "$PRE.tmp/dropin.absent"; fi
    effective_sha > "$PRE.tmp/effective.sha256"
    ts > "$PRE.tmp/taken_at"
    mv "$PRE.tmp" "$PRE"
    log "snapshot: $(wc -l < "$PRE/manifest") files, sshd -T sha256 $(cat "$PRE/effective.sha256")"
  else
    log "snapshot kept from $(cat "$PRE/taken_at") (rollback returns to the state before the first apply)"
  fi
  { echo "# pft-sshcrypto policy - managed file (same bytes on every apply), remove with: sudo pft-sshcrypto rollback"
    grep -vE '^[[:space:]]*(#|$)' "$policy"; } > "$DROPIN.tmp"
  chmod 644 "$DROPIN.tmp"; mv -f "$DROPIN.tmp" "$DROPIN"
  if ! why="$("$SSHD" -t 2>&1)"; then
    restore_pre; die "sshd -t rejected the policy, restored: $(printf '%s' "$why" | head -1)"
  fi
  eff="$("$SSHD" -T 2>/dev/null)"
  while read -r d v; do
    if [ "$(printf '%s\n' "$eff" | awk -v k="${d,,}" '$1==k{print $2; exit}')" != "$v" ]; then
      restore_pre; die "effective $d differs from the policy (shadowed by an earlier file?), restored"
    fi
  done < <(grep -vE '^[[:space:]]*(#|$)' "$policy")
  log "drop-in written and validated (sshd -t OK, sshd -T matches the policy), sha256 $(sha "$DROPIN")"
  deadline=$(( $(now) + after ))
  if ! "$SYSTEMD_RUN" --quiet --collect --unit="$TIMER" --on-active="${after}s" --timer-property=AccuracySec=1s \
       --description="pft-sshcrypto automatic revert" "$SELF" rollback --auto; then
    restore_pre; die "could not arm the revert timer, restored"
  fi
  echo "$deadline" > "$STATE/pending"
  log "revert armed: $TIMER.timer fires at $(date -u -d "@$deadline" +%FT%TZ) (${after}s)"
  if ! "$SYSTEMCTL" reload "$SSH_UNIT"; then
    log "reload failed; the armed timer will restore the snapshot"; exit 3
  fi
  log "reloaded $SSH_UNIT (existing sessions untouched)"
  if ! why="$(confirm)"; then
    log "CONFIRM FAILED: new session: $why"
    log "not committed: $TIMER.timer rolls back at $(date -u -d "@$deadline" +%FT%TZ)"
    exit 3
  fi
  log "confirmed: new session logged in (default client algorithms, strict host key check)"
  audit --textfile-dir "$TEXTFILE_DIR" > "$STATE/apply-audit.txt"; rc=$?
  tail -1 "$STATE/apply-audit.txt"
  if [ "$rc" -eq 2 ] || grep -q 'MISMATCH' "$STATE/apply-audit.txt"; then
    log "CONFIRM FAILED: post-reload audit (rc $rc); not committed, $TIMER.timer rolls back at the deadline"
    exit 3
  fi
  "$SYSTEMCTL" stop "$TIMER.timer" 2>/dev/null
  rm -f "$STATE/pending"
  sha "$DROPIN" > "$STATE/applied"
  audit --no-probe --textfile-dir "$TEXTFILE_DIR" > /dev/null
  log "APPLIED: revert timer stopped, policy committed (rollback: sudo pft-sshcrypto rollback)"
  return 0
}

rollback() {
  local auto=false why m_now e_now
  [ "${1:-}" = --auto ] && auto=true
  [ -d "$PRE" ] || die "nothing to roll back (no snapshot in $PRE)"
  $auto && log "automatic revert (timer) - applied policy was not confirmed"
  restore_pre
  if ! why="$("$SSHD" -t 2>&1)"; then die "sshd -t failed after restore: $(printf '%s' "$why" | head -1)"; fi
  "$SYSTEMCTL" reload "$SSH_UNIT" || die "reload $SSH_UNIT failed after restore"
  m_now="$(manifest)"; e_now="$(effective_sha)"
  if [ "$m_now" != "$(cat "$PRE/manifest")" ]; then
    diff <(cat "$PRE/manifest") <(printf '%s\n' "$m_now") | sed 's/^/  /'
    die "ROLLBACK FAILED: sshd config files differ from the snapshot"
  fi
  [ "$e_now" = "$(cat "$PRE/effective.sha256")" ] || die "ROLLBACK FAILED: sshd -T differs from the snapshot"
  log "files: $(wc -l < "$PRE/manifest") sha256-identical to the snapshot; sshd -T sha256 $e_now identical"
  if ! why="$(confirm)"; then die "ROLLBACK FAILED: restored, but a new session failed: $why"; fi
  log "confirmed: new session logged in after the rollback"
  $auto || "$SYSTEMCTL" stop "$TIMER.timer" 2>/dev/null
  rm -f "$STATE/pending" "$STATE/applied"
  rm -rf "$STATE/last-rollback"; mv "$PRE" "$STATE/last-rollback"
  audit --no-probe --textfile-dir "$TEXTFILE_DIR" > /dev/null
  log "ROLLBACK OK"
  return 0
}

status() {
  local st=none
  [ -f "$STATE/applied" ] && st=applied
  [ -f "$STATE/pending" ] && st="pending (revert at $(date -u -d "@$(cat "$STATE/pending")" +%FT%TZ))"
  echo "state: $st"
  if [ -d "$PRE" ]; then echo "snapshot: taken $(cat "$PRE/taken_at"), $(wc -l < "$PRE/manifest") files"; else echo "snapshot: none"; fi
  if "$SYSTEMCTL" is-active --quiet "$TIMER.timer"; then echo "revert timer: armed"; else echo "revert timer: not armed"; fi
  if [ -f "$DROPIN" ]; then echo "drop-in: present, sha256 $(sha "$DROPIN")"; else echo "drop-in: absent"; fi
}

# validate FILE HOST -> rc 0, or rc 1 with the first reason on stdout
validate() {
  local f="$1" h="$2" n
  [ -f "$f" ] || { echo "missing"; return 1; }
  [ "$(stat -c %s "$f")" -le "$MAX_BYTES" ] || { echo "larger than $MAX_BYTES bytes"; return 1; }
  n="$(grep -cvE '^(#.*|pft_sshcrypto_[a-z_]+\{host="'"$h"'"(,[a-z_]+="[a-z0-9_-]+")*\} [0-9.e+-]+)$' "$f")"
  [ "$n" -eq 0 ] || { echo "$n unexpected lines"; return 1; }
  grep -qE '^pft_sshcrypto_up\{host="'"$h"'"\} [01]$' "$f" || { echo "no up sample"; return 1; }
  return 0
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  tmp="$TEXTFILE_DIR/.pft_sshcrypto_$PEER_LABEL.prom.pull"
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned conf
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_sshcrypto_$PEER_LABEL.prom" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "pull from $PEER_LABEL failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then
    rm -f "$tmp"; die "pulled file rejected: $why" 2
  fi
  mv -f "$tmp" "$TEXTFILE_DIR/pft_sshcrypto_$PEER_LABEL.prom"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  audit) audit "$@" ;;
  apply) [ "$(id -u)" -eq 0 ] || [ -n "$ROOT" ] || die "apply needs root"; apply "$@" ;;
  rollback) [ "$(id -u)" -eq 0 ] || [ -n "$ROOT" ] || die "rollback needs root"; rollback "$@" ;;
  status) status ;;
  pull) pull ;;
  validate) [ $# -eq 2 ] || die "usage: pft-sshcrypto validate FILE HOST"; valid_label "$2" || die "bad host label"
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  policy-table) python3 "$GRADER" table ;;
  version) echo "pft-sshcrypto $VERSION" ;;
  *) die "usage: pft-sshcrypto audit|apply|rollback|status|pull|validate|policy-table|version (see the header)" ;;
esac
