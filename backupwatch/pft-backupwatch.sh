#!/usr/bin/env bash
# pft-backupwatch: backup freshness, integrity and restore-readiness monitor for a Post Fiat node (pft-backup archives).
# Read-only on the node: archives are read as in-memory tar streams by backupwatch_lib.py (nothing extracted), the
# container's config is read from its volume's host path (docker inspect), never with docker exec.
#
# Usage: sudo pft-backupwatch check [--json] [--offhost]   one line per check (OK/WARN/FAIL) + RESULT, or JSON
#        sudo pft-backupwatch replicate                    (validator) newest archive -> encrypted replica on the peer
#        sudo pft-backupwatch collect [--stdout]           textfile metrics (ROLE=archive: check; ROLE=replica: store)
#        sudo pft-backupwatch pull                         (validator) the peer's textfile via `serve metrics`
#        pft-backupwatch serve receive NAME PLAIN_SHA CIPHER_SHA | status | verify NAME | metrics   (what PEER_SSH runs)
#        pft-backupwatch version
#
#  check  fresh     newest pft-backup-<UTC>.tar.gz[.gpg] in BACKUP_DIR younger than MAX_AGE_H (WARN) / FAIL_AGE_H (FAIL)
#         size      >= MIN_BYTES (FAIL) and SIZE_LO..SIZE_HI x the previous archive (WARN)
#         sidecar   <archive>.sha256 present and equal
#         manifest  archive opens (gpg: PASSFILE), MANIFEST.sha256 matches every member, no unlisted member
#         content   members a restore needs (cfg, validators.txt, compose base, .env, every COMPOSE_FILE member: FAIL)
#                   and the firewall reference members (WARN if missing or holding a tool error)
#         drift     each archived config file vs the live host (postfiatd.cfg with the secret sections stripped)
#         offhost   (--offhost or OFFHOST=1) the peer holds a replica of the newest archive whose ciphertext sha256
#                   equals the one recorded at replication and whose decryption (peer identity, in memory) equals the
#                   archive's sidecar sha256. WARN: only an older archive is replicated. FAIL: none / peer down /
#                   mismatch / does not decrypt.
#  replicate  checks the newest archive against its sidecar, encrypts it to REPLICA_RECIPIENT with age into SCRATCH
#             (ciphertext only, removed afterwards), streams it to `serve receive` over PEER_SSH, and records
#             name + ciphertext sha256 + plaintext sha256 in STATE_DIR/replica.tsv once the peer confirms.
#  serve receive  stores stdin (ciphertext, at most REPLICA_MAX_BYTES) under REPLICA_DIR only if its sha256 is
#             CIPHER_SHA and `age -d` with REPLICA_IDENTITY gives PLAIN_SHA (plaintext only in a pipe); keeps the newest
#             REPLICA_KEEP replicas. status: one REPLICA line per stored replica. verify: re-hash + decrypt one replica.
#             metrics: prints this host's own pft_backupwatch_HOST_LABEL.prom (for the validator's pull).
#  collect  ROLE=archive: runs check --json (with --offhost if OFFHOST=1) and writes TEXTFILE_DIR/
#           pft_backupwatch_HOST_LABEL.prom atomically: up, collect timestamp, check_state{check} 0/1/2, archive age
#           and bytes, drift files / since / overdue (drift older than DRIFT_GRACE_H: no backup picked it up).
#           ROLE=replica: serve status + verify of the newest replica -> up, replicas, replica_newest_age_seconds,
#           replica_verify_ok. A run that cannot produce a result still writes up 0 (and exits 1).
#  pull     runs `serve metrics` over PEER_SSH, validates the text (only pft_backupwatch_* lines, host="PEER_LABEL",
#           an up and a collect timestamp sample) and renames it into TEXTFILE_DIR as pft_backupwatch_PEER_LABEL.prom.
#
# Exit codes: 0 all OK, 1 WARN, 2 FAIL (replicate/serve: refused or failed), 3 usage/config error.
# Conf: PFT_BW_CONF (/etc/pft-backupwatch.env, root-owned, sourced first): BACKUP_DIR (/var/backups/postfiat),
#       CONTAINER (postfiatd), MAX_AGE_H (26), FAIL_AGE_H (50), MIN_BYTES (4096), SIZE_LO (0.5), SIZE_HI (2.0),
#       PASSFILE (gpg archives only), SCRATCH (/dev/shm: gpg home / ciphertext scratch, removed after each run),
#       OFFHOST (0), PEER_SSH, PEER_TIMEOUT (120), REPLICA_RECIPIENT (age1..., the peer's), STATE_DIR
#       (/var/lib/pft-backupwatch), peer side: REPLICA_DIR (/var/lib/pft-backupwatch/replicas), REPLICA_IDENTITY
#       (/var/lib/pft-keyescrow/age.key), REPLICA_KEEP (7), REPLICA_MAX_BYTES (67108864); metrics: ROLE (archive),
#       HOST_LABEL (validator), PEER_LABEL (sentry), TEXTFILE_DIR (/var/lib/pft-exporter/textfile), DRIFT_GRACE_H (30)
# Test hooks: PFT_BW_HELPER (/usr/local/lib/pft-backupwatch/backupwatch_lib.py)  PFT_BW_NOW (epoch)
#             PFT_BW_DOCKER (docker)  PFT_BW_ROOT (/)  PFT_BW_AGE (age)

set -uo pipefail
umask 022
VERSION=1

CONF="${PFT_BW_CONF:-/etc/pft-backupwatch.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/postfiat}"
CONTAINER="${CONTAINER:-postfiatd}"
MAX_AGE_H="${MAX_AGE_H:-26}"
FAIL_AGE_H="${FAIL_AGE_H:-50}"
MIN_BYTES="${MIN_BYTES:-4096}"
SIZE_LO="${SIZE_LO:-0.5}"
SIZE_HI="${SIZE_HI:-2.0}"
PASSFILE="${PASSFILE:-}"
SCRATCH="${SCRATCH:-/dev/shm}"
OFFHOST="${OFFHOST:-0}"
PEER_SSH="${PEER_SSH:-}"
PEER_TIMEOUT="${PEER_TIMEOUT:-120}"
REPLICA_RECIPIENT="${REPLICA_RECIPIENT:-}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-backupwatch}"
REPLICA_DIR="${REPLICA_DIR:-/var/lib/pft-backupwatch/replicas}"
REPLICA_IDENTITY="${REPLICA_IDENTITY:-/var/lib/pft-keyescrow/age.key}"
REPLICA_KEEP="${REPLICA_KEEP:-7}"
REPLICA_MAX_BYTES="${REPLICA_MAX_BYTES:-67108864}"
ROLE="${ROLE:-archive}"
HOST_LABEL="${HOST_LABEL:-validator}"
PEER_LABEL="${PEER_LABEL:-sentry}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
DRIFT_GRACE_H="${DRIFT_GRACE_H:-30}"
HELPER="${PFT_BW_HELPER:-/usr/local/lib/pft-backupwatch/backupwatch_lib.py}"
DOCKER="${PFT_BW_DOCKER:-docker}"
ROOT="${PFT_BW_ROOT:-/}"
AGE="${PFT_BW_AGE:-age}"
NAME_RE='^pft-backup-[0-9]{8}T[0-9]{6}Z\.tar\.gz(\.gpg)?$'
HEX_RE='^[0-9a-f]{64}$'
HOST_RE='^[a-z][a-z0-9-]{0,31}$'

die() { printf 'pft-backupwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
posint() { [[ "$1" =~ ^[1-9][0-9]{0,8}$ ]]; }
num() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }
sha() { sha256sum | cut -c1-64; }

cfg_dir() { # host path of the container's /etc/postfiatd volume; empty if unknown (drift then says "unchecked")
  "$DOCKER" inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/postfiatd"}}{{.Source}}{{end}}{{end}}' 2>/dev/null
}

newest_archive() { # name of the newest archive pft-backup wrote, or nothing
  find "$BACKUP_DIR" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | grep -E "$NAME_RE" | LC_ALL=C sort | tail -n 1
}

peer() { # VERB ARGS... -> runs `pft-backupwatch serve VERB ...` on the peer
  [ -n "$PEER_SSH" ] || die "PEER_SSH is not set"
  # shellcheck disable=SC2086  # PEER_SSH is a command prefix on purpose (e.g. "runuser -u U -- ssh ... ALIAS")
  timeout "$PEER_TIMEOUT" $PEER_SSH pft-backupwatch serve "$@"
}

offhost_report() { # -> text for the helper: the peer's status + verify of the newest local archive, or PEER_DOWN
  local n out rc
  n="$(newest_archive)"
  out="$(peer status </dev/null 2>/dev/null)"; rc=$?
  if [ "$rc" != 0 ]; then echo "PEER_DOWN $rc"; return 0; fi
  printf '%s\n' "$out" | grep -E '^REPLICA '
  if [ -n "$n" ] && grep -q "^REPLICA $n " <<<"$out"; then
    peer verify "$n" </dev/null 2>/dev/null | grep -E '^VERIFY ' | tail -n 1
  fi
  return 0
}

cmd_check() {
  local json=0 out rc cfg off=()
  [ "$OFFHOST" = 1 ] && off=(1)
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;;
      --offhost) off=(1) ;;
      *) die "check: unknown argument '$1'" ;;
    esac
    shift
  done
  if ! { posint "$MAX_AGE_H" && posint "$FAIL_AGE_H" && [[ "$MIN_BYTES" =~ ^[0-9]{1,9}$ ]]; }; then
    die "MAX_AGE_H/FAIL_AGE_H/MIN_BYTES must be integers"
  fi
  if ! { num "$SIZE_LO" && num "$SIZE_HI"; }; then die "SIZE_LO/SIZE_HI must be numbers"; fi
  [ -f "$HELPER" ] || die "helper missing: $HELPER"
  cfg="$(cfg_dir)"
  local extra=()
  if [ "${#off[@]}" = 1 ]; then
    posint "$PEER_TIMEOUT" || die "PEER_TIMEOUT must be an integer"
    local rep; rep="$(mktemp "$SCRATCH/pft-bw-off.XXXXXX")" || die "cannot create scratch file in $SCRATCH"
    offhost_report > "$rep"
    extra=(--offhost "$rep" --replica-state "$STATE_DIR/replica.tsv")
  fi
  out="$(python3 "$HELPER" check --dir "$BACKUP_DIR" --now "${PFT_BW_NOW:-$(date +%s)}" --root "$ROOT" \
    --cfg-dir "$cfg" --passfile "$PASSFILE" --scratch "$SCRATCH" --max-age-h "$MAX_AGE_H" --fail-age-h "$FAIL_AGE_H" \
    --min-bytes "$MIN_BYTES" --size-lo "$SIZE_LO" --size-hi "$SIZE_HI" "${extra[@]}" </dev/null)"
  rc=$?
  [ "${#extra[@]}" = 0 ] || rm -f "${extra[1]}"
  if [ "$rc" -gt 2 ] || [ -z "$out" ]; then die "helper failed (rc $rc)" 3; fi
  if [ "$json" = 1 ]; then printf '%s\n' "$out"; return "$rc"; fi
  printf '%s\n' "$out" | python3 "$HELPER" render || die "cannot render helper output" 3
  return "$rc"
}

cmd_replicate() {
  local n a plain tmp csha out rc
  [ $# = 0 ] || die "replicate takes no arguments"
  [[ "$REPLICA_RECIPIENT" =~ ^age1[02-9ac-hj-np-z]{58}$ ]] || die "REPLICA_RECIPIENT must be the peer's age1... recipient"
  posint "$PEER_TIMEOUT" || die "PEER_TIMEOUT must be an integer"
  [ -n "$PEER_SSH" ] || die "PEER_SSH is not set"
  n="$(newest_archive)"; [ -n "$n" ] || die "no archive in $BACKUP_DIR" 2
  a="$BACKUP_DIR/$n"
  plain="$(cut -d' ' -f1 "$a.sha256" 2>/dev/null)"
  [[ "$plain" =~ $HEX_RE ]] || die "$n: sidecar missing or malformed; not replicated" 2
  [ "$(sha < "$a")" = "$plain" ] || die "$n: archive does not match its sidecar; not replicated" 2
  tmp="$(mktemp "$SCRATCH/pft-bw-rep.XXXXXX")" || die "cannot create scratch file in $SCRATCH" 2
  # shellcheck disable=SC2064  # expand $tmp now
  trap "rm -f '$tmp'" EXIT
  "$AGE" -r "$REPLICA_RECIPIENT" -o "$tmp" < "$a" || die "age encryption failed" 2
  csha="$(sha < "$tmp")"
  out="$(peer receive "$n" "$plain" "$csha" < "$tmp" 2>&1)"; rc=$?
  rm -f "$tmp"
  printf '%s\n' "$out" | grep -E '^(RECEIVED|PRUNED|pft-backupwatch:)' | sed 's/^/  peer: /'
  if [ "$rc" != 0 ] || ! grep -qx "RECEIVED $n $csha OK" <<<"$out"; then die "peer did not confirm $n (rc $rc)" 2; fi
  (umask 077; mkdir -p "$STATE_DIR") || die "cannot create $STATE_DIR" 2
  printf '%s\t%s\t%s\t%s\n' "$n" "$csha" "$plain" "$(date +%s)" >> "$STATE_DIR/replica.tsv"
  tail -n 50 "$STATE_DIR/replica.tsv" > "$STATE_DIR/.replica.tsv.new" && mv -f "$STATE_DIR/.replica.tsv.new" "$STATE_DIR/replica.tsv"
  echo "REPLICATED $n cipher_sha256 $csha plain_sha256 $plain"
}

serve_receive() { # NAME PLAIN CSHA; stdin = ciphertext
  local n="${1:-}" plain="${2:-}" csha="${3:-}" tmp got dec size f
  if ! { [[ "$n" =~ $NAME_RE ]] && [[ "$plain" =~ $HEX_RE ]] && [[ "$csha" =~ $HEX_RE ]]; }; then
    die "serve receive NAME PLAIN_SHA CIPHER_SHA"
  fi
  if ! { posint "$REPLICA_KEEP" && posint "$REPLICA_MAX_BYTES"; }; then die "REPLICA_KEEP/REPLICA_MAX_BYTES must be integers"; fi
  [ -s "$REPLICA_IDENTITY" ] || die "no age identity at $REPLICA_IDENTITY" 2
  if ! { (umask 077; mkdir -p "$REPLICA_DIR") && chmod 700 "$REPLICA_DIR"; }; then die "cannot create $REPLICA_DIR" 2; fi
  tmp="$(mktemp "$REPLICA_DIR/.in.XXXXXX")" || die "cannot create a temp file in $REPLICA_DIR" 2
  head -c "$((REPLICA_MAX_BYTES + 1))" > "$tmp"
  size="$(stat -c %s "$tmp")"
  if [ "$size" -gt "$REPLICA_MAX_BYTES" ]; then rm -f "$tmp"; echo "RECEIVED $n - TOO_BIG"; return 2; fi
  got="$(sha < "$tmp")"
  if [ "$got" != "$csha" ]; then rm -f "$tmp"; echo "RECEIVED $n $got SHA_MISMATCH"; return 2; fi
  dec="$("$AGE" -d -i "$REPLICA_IDENTITY" < "$tmp" 2>/dev/null | sha)"
  if [ "${PIPESTATUS[0]}" != 0 ] || [ "$dec" != "$plain" ]; then rm -f "$tmp"; echo "RECEIVED $n $got DECRYPT_MISMATCH"; return 2; fi
  mv -f "$tmp" "$REPLICA_DIR/$n.age"
  printf 'name=%s\ncipher_sha256=%s\nplain_sha256=%s\nreceived=%s\n' "$n" "$csha" "$plain" "$(date +%s)" > "$REPLICA_DIR/$n.age.meta"
  echo "RECEIVED $n $csha OK"
  find "$REPLICA_DIR" -maxdepth 1 -type f -name 'pft-backup-*.age' -printf '%f\n' | LC_ALL=C sort -r | tail -n "+$((REPLICA_KEEP + 1))" |
    while IFS= read -r f; do rm -f "$REPLICA_DIR/$f" "$REPLICA_DIR/$f.meta"; echo "PRUNED ${f%.age}"; done
}

meta() { sed -n "s/^$2=//p" "$REPLICA_DIR/$1.age.meta" 2>/dev/null; }

serve_status() {
  local f n
  find "$REPLICA_DIR" -maxdepth 1 -type f -name 'pft-backup-*.age' -printf '%f\n' 2>/dev/null | LC_ALL=C sort |
    while IFS= read -r f; do
      n="${f%.age}"
      echo "REPLICA $n $(meta "$n" cipher_sha256) $(meta "$n" plain_sha256) $(meta "$n" received)"
    done
  echo "END"
}

serve_verify() { # NAME
  local n="${1:-}" c p dec
  [[ "$n" =~ $NAME_RE ]] || die "serve verify NAME"
  [ -f "$REPLICA_DIR/$n.age" ] || { echo "VERIFY $n MISSING"; return 2; }
  c="$(meta "$n" cipher_sha256)"; p="$(meta "$n" plain_sha256)"
  [ "$(sha < "$REPLICA_DIR/$n.age")" = "$c" ] || { echo "VERIFY $n SHA_MISMATCH"; return 2; }
  dec="$("$AGE" -d -i "$REPLICA_IDENTITY" < "$REPLICA_DIR/$n.age" 2>/dev/null | sha)"
  if [ "${PIPESTATUS[0]}" != 0 ] || [ "$dec" != "$p" ]; then echo "VERIFY $n DECRYPT_FAIL"; return 2; fi
  echo "VERIFY $n OK"
}

write_atomic() { # DIR FILE CONTENT
  local tmp
  tmp="$(mktemp "$1/.$2.XXXXXX")" || return 1
  if printf '%s' "$3" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1/$2"; then return 0; fi
  rm -f "$tmp"; return 1
}

valid_prom() { # FILE LABEL -> empty + 0, or the reason + 1
  awk -v h="host=\"$2\"" '
    /^#/ || /^$/ { next }
    $0 !~ /^pft_backupwatch_[a-z_]+\{[^}]*\} -?[0-9]+(\.[0-9]+)?$/ { print "line " NR " is not a pft_backupwatch_ sample"; bad = 1; exit }
    index($0, h) == 0 { print "line " NR " is not labelled " h; bad = 1; exit }
    /^pft_backupwatch_up\{/ { up = 1 }
    /^pft_backupwatch_collect_timestamp_seconds\{/ { ts = 1 }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_backupwatch_up sample"; exit 1 }
      if (!ts) { print "no pft_backupwatch_collect_timestamp_seconds sample"; exit 1 }
    }' "$1"
}

cmd_collect() {
  local to_stdout=0 now json text rc=0 st
  while [ $# -gt 0 ]; do
    case "$1" in
      --stdout) to_stdout=1 ;;
      *) die "collect: unknown argument '$1'" ;;
    esac
    shift
  done
  [[ "$HOST_LABEL" =~ $HOST_RE ]] || die "bad HOST_LABEL"
  [[ "$DRIFT_GRACE_H" =~ ^[0-9]{1,6}$ ]] || die "DRIFT_GRACE_H must be an integer"
  [ -f "$HELPER" ] || die "helper missing: $HELPER"
  now="${PFT_BW_NOW:-$(date +%s)}"
  case "$ROLE" in
    archive)
      (umask 077; mkdir -p "$STATE_DIR") || die "cannot create $STATE_DIR" 1
      json="$(cmd_check --json 2>/dev/null)"
      text="$(printf '%s\n' "$json" | python3 "$HELPER" metrics --host "$HOST_LABEL" --now "$now" \
        --drift-state "$STATE_DIR/drift.since" --drift-grace-h "$DRIFT_GRACE_H")" || rc=1 ;;
    replica)
      st="$(serve_status 2>/dev/null)"
      local n; n="$(printf '%s\n' "$st" | awk '$1 == "REPLICA" { n = $2 } END { print n }')"
      [ -z "$n" ] || st+=$'\n'"$(serve_verify "$n" 2>/dev/null)"
      text="$(printf '%s\n' "$st" | python3 "$HELPER" replica-metrics --host "$HOST_LABEL" --now "$now")" || rc=1 ;;
    *) die "ROLE must be archive or replica" ;;
  esac
  [ -n "$text" ] || die "helper produced no metrics" 1
  if [ "$to_stdout" = 1 ]; then printf '%s' "$text"
  else write_atomic "$TEXTFILE_DIR" "pft_backupwatch_$HOST_LABEL.prom" "$text" || die "cannot write $TEXTFILE_DIR" 1
  fi
  return "$rc"
}

cmd_pull() {
  local tmp why
  [ $# = 0 ] || die "pull takes no arguments"
  [[ "$PEER_LABEL" =~ $HOST_RE ]] || die "bad PEER_LABEL"
  [ "$PEER_LABEL" != "$HOST_LABEL" ] || die "refusing to pull over this host's own textfile ($PEER_LABEL)"
  posint "$PEER_TIMEOUT" || die "PEER_TIMEOUT must be an integer"
  [ -n "$PEER_SSH" ] || die "PEER_SSH is not set"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-backupwatch-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  if ! peer metrics </dev/null > "$tmp" 2>/dev/null; then rm -f "$tmp"; die "fetch of the peer's metrics failed" 1; fi
  if ! why="$(valid_prom "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_backupwatch_$PEER_LABEL.prom"; }; then
    rm -f "$tmp"; die "rename failed" 1
  fi
}

cmd_serve() {
  local v="${1:-}"; shift || true
  case "$v" in
    receive) [ $# = 3 ] || die "serve receive NAME PLAIN_SHA CIPHER_SHA"; serve_receive "$@" ;;
    status) [ $# = 0 ] || die "serve status"; serve_status ;;
    verify) [ $# = 1 ] || die "serve verify NAME"; serve_verify "$1" ;;
    metrics) [ $# = 0 ] || die "serve metrics"; [[ "$HOST_LABEL" =~ $HOST_RE ]] || die "bad HOST_LABEL"
      cat -- "$TEXTFILE_DIR/pft_backupwatch_$HOST_LABEL.prom" || die "no metrics file" 2 ;;
    *) die "serve: unknown verb '$v' (receive | status | verify | metrics)" ;;
  esac
}

case "${1:-}" in
  check) shift; cmd_check "$@"; exit $? ;;
  replicate) shift; cmd_replicate "$@"; exit $? ;;
  collect) shift; cmd_collect "$@"; exit $? ;;
  pull) shift; cmd_pull "$@"; exit $? ;;
  serve) shift; cmd_serve "$@"; exit $? ;;
  version) echo "pft-backupwatch $VERSION"; exit 0 ;;
  ""|-h|--help) sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown command '$1' (check | replicate | collect | pull | serve | version)" ;;
esac
