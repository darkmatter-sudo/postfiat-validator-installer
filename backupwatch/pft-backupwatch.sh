#!/usr/bin/env bash
# pft-backupwatch: backup freshness, integrity and restore-readiness monitor for a Post Fiat node (pft-backup archives).
# Read-only on the node: archives are read as in-memory tar streams by backupwatch_lib.py (nothing extracted), the
# container's config is read from its volume's host path (docker inspect), never with docker exec.
#
# Usage: sudo pft-backupwatch check [--json]      one line per check (OK/WARN/FAIL) + RESULT, or the helper's JSON
#        pft-backupwatch version
#
#  check  fresh     newest pft-backup-<UTC>.tar.gz[.gpg] in BACKUP_DIR younger than MAX_AGE_H (WARN) / FAIL_AGE_H (FAIL)
#         size      >= MIN_BYTES (FAIL) and SIZE_LO..SIZE_HI x the previous archive (WARN)
#         sidecar   <archive>.sha256 present and equal
#         manifest  archive opens (gpg: PASSFILE), MANIFEST.sha256 matches every member, no unlisted member
#         content   members a restore needs (cfg, validators.txt, compose base, .env, every COMPOSE_FILE member: FAIL)
#                   and the firewall reference members (WARN if missing or holding a tool error)
#         drift     each archived config file vs the live host (postfiatd.cfg with the secret sections stripped)
#
# Exit codes: 0 all OK, 1 WARN, 2 FAIL, 3 usage/config error.
# Conf: PFT_BW_CONF (/etc/pft-backupwatch.env, root-owned, sourced first): BACKUP_DIR (/var/backups/postfiat),
#       CONTAINER (postfiatd), MAX_AGE_H (26), FAIL_AGE_H (50), MIN_BYTES (4096), SIZE_LO (0.5), SIZE_HI (2.0),
#       PASSFILE (gpg archives only), SCRATCH (/dev/shm: gpg's temporary home, removed after each check)
# Test hooks: PFT_BW_HELPER (/usr/local/lib/pft-backupwatch/backupwatch_lib.py)  PFT_BW_NOW (epoch)
#             PFT_BW_DOCKER (docker)  PFT_BW_ROOT (/)

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
HELPER="${PFT_BW_HELPER:-/usr/local/lib/pft-backupwatch/backupwatch_lib.py}"
DOCKER="${PFT_BW_DOCKER:-docker}"
ROOT="${PFT_BW_ROOT:-/}"

die() { printf 'pft-backupwatch: %s\n' "$1" >&2; exit "${2:-3}"; }
posint() { [[ "$1" =~ ^[1-9][0-9]{0,8}$ ]]; }
num() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }

cfg_dir() { # host path of the container's /etc/postfiatd volume; empty if unknown (drift then says "unchecked")
  "$DOCKER" inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/postfiatd"}}{{.Source}}{{end}}{{end}}' 2>/dev/null
}

cmd_check() {
  local json=0 out rc cfg
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=1 ;;
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
  out="$(python3 "$HELPER" check --dir "$BACKUP_DIR" --now "${PFT_BW_NOW:-$(date +%s)}" --root "$ROOT" \
    --cfg-dir "$cfg" --passfile "$PASSFILE" --scratch "$SCRATCH" --max-age-h "$MAX_AGE_H" --fail-age-h "$FAIL_AGE_H" \
    --min-bytes "$MIN_BYTES" --size-lo "$SIZE_LO" --size-hi "$SIZE_HI" </dev/null)"
  rc=$?
  if [ "$rc" -gt 2 ] || [ -z "$out" ]; then die "helper failed (rc $rc)" 3; fi
  if [ "$json" = 1 ]; then printf '%s\n' "$out"; return "$rc"; fi
  printf '%s\n' "$out" | python3 "$HELPER" render || die "cannot render helper output" 3
  return "$rc"
}

case "${1:-}" in
  check) shift; cmd_check "$@"; exit $? ;;
  version) echo "pft-backupwatch $VERSION"; exit 0 ;;
  ""|-h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown command '$1' (check | version)" ;;
esac
