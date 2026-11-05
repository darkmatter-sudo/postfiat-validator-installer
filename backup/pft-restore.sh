#!/usr/bin/env bash
# pft-restore: restore a pft-backup.sh archive onto this host and bring postfiatd back up.
#
#  1. verifies the sidecar <archive>.sha256 (if present) and, after extracting into a temp
#     dir, the archive's MANIFEST.sha256 (every file must match; unlisted files are refused)
#  2. decrypts *.gpg archives (PFT_BACKUP_PASSPHRASE_FILE or PFT_BACKUP_PASSPHRASE)
#  3. installs docker-compose.yml, .env and every COMPOSE_FILE member in .env (e.g. the confine/ apparmor/ seccomp/
#     hardening overlays) into COMPOSE_DIR (existing files kept as *.pre-restore-<ts>); compose then runs with
#     exactly that file set. An overlay whose host prerequisite is missing here (seccomp=FILE that does not exist,
#     apparmor=PROFILE not loaded) stops the restore before anything changes (exit 5), unless --defer-hardening:
#     then that overlay is left out of COMPOSE_FILE and named, with the add-on command that re-creates it
#  4. creates the container, copies postfiatd.cfg + validators.txt into its config volume,
#     starts it, and waits until server_state is "full" (or proposing) within --timeout
#  5. optional: --with-units installs the add-on units + helper scripts (daemon-reload, the
#     units are not enabled); --with-firewall installs the saved ufw user rules and reloads ufw
#
# Exit codes: 0 ok, 1 error, 2 usage, 3 verification failed, 4 timeout waiting for "full",
#   5 a hardening overlay cannot be applied on this host (see 3).
#
# Usage: sudo ./pft-restore.sh [--dry-run] [--timeout SECS] [--with-units] [--with-firewall] [--defer-hardening] ARCHIVE
# Env:   COMPOSE_DIR (/opt/postfiatd)  CONTAINER (postfiatd)  TIMEOUT (900)

set -euo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-/opt/postfiatd}"
CONTAINER="${CONTAINER:-postfiatd}"
TIMEOUT="${TIMEOUT:-900}"
DRY_RUN=0
WITH_UNITS=0
WITH_FIREWALL=0
DEFER=0
ARCHIVE=""

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $1"; exit "${2:-1}"; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }
run() { if [ "$DRY_RUN" -eq 1 ]; then log "DRY-RUN would run: $*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift ;;
    --with-units) WITH_UNITS=1 ;;
    --with-firewall) WITH_FIREWALL=1 ;;
    --defer-hardening) DEFER=1 ;;
    -h|--help) usage 0 ;;
    -*) log "unknown option: $1"; usage 2 ;;
    *) [ -z "$ARCHIVE" ] || usage 2; ARCHIVE="$1" ;;
  esac
  shift
done

[ -n "$ARCHIVE" ] || usage 2
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--timeout must be a positive integer." 2
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."
[ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
for c in docker tar sha256sum; do command -v "$c" >/dev/null || die "$c required."; done
docker compose version >/dev/null 2>&1 ||
  die "'docker compose' plugin missing (Ubuntu: apt-get install docker-compose-v2); nothing was changed."

OS_NAME="$(grep ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '"')"
log "OS: $OS_NAME"
[ "$DRY_RUN" -eq 1 ] && log "mode: DRY-RUN (verification runs, nothing on this host is changed)"
log "archive: $ARCHIVE"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. sidecar checksum of the archive itself
if [ -f "$ARCHIVE.sha256" ]; then
  want="$(cut -d' ' -f1 "$ARCHIVE.sha256")"
  have="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
  [ "$want" = "$have" ] || die "archive sha256 mismatch: sidecar $want, archive $have" 3
  log "archive sha256 OK ($have)"
else
  log "WARNING: no sidecar $ARCHIVE.sha256; relying on the internal manifest only"
fi

# 2. decrypt if needed
TARBALL="$ARCHIVE"
if [[ "$ARCHIVE" == *.gpg ]]; then
  command -v gpg >/dev/null || die "gpg required for encrypted archives."
  TARBALL="$WORK/archive.tar.gz"
  gpg_args=(--batch --quiet --pinentry-mode loopback --decrypt -o "$TARBALL")
  if [ -n "${PFT_BACKUP_PASSPHRASE_FILE:-}" ]; then
    gpg "${gpg_args[@]}" --passphrase-file "$PFT_BACKUP_PASSPHRASE_FILE" "$ARCHIVE" || die "gpg decrypt failed" 3
  elif [ -n "${PFT_BACKUP_PASSPHRASE:-}" ]; then
    printf '%s' "$PFT_BACKUP_PASSPHRASE" | gpg "${gpg_args[@]}" --passphrase-fd 0 "$ARCHIVE" || die "gpg decrypt failed" 3
  else
    die "encrypted archive: set PFT_BACKUP_PASSPHRASE_FILE or PFT_BACKUP_PASSPHRASE." 2
  fi
  log "decrypted"
fi

# 3. extract into a temp dir and verify the manifest
if tar -tzf "$TARBALL" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
  die "archive contains absolute or '..' paths; refusing" 3
fi
tar -C "$WORK" -xzf "$TARBALL" || die "tar extraction failed" 3
mapfile -t tops < <(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'pft-backup-*')
[ "${#tops[@]}" -eq 1 ] || die "unexpected archive layout" 3
SRC="${tops[0]}"
[ -f "$SRC/MANIFEST.sha256" ] || die "MANIFEST.sha256 missing" 3
log "verifying MANIFEST.sha256 ($(wc -l <"$SRC/MANIFEST.sha256") entries)"
if ! (cd "$SRC" && sha256sum --check --strict --quiet MANIFEST.sha256); then
  die "manifest verification FAILED; nothing was restored" 3
fi
extra="$(comm -13 <(awk '{print $2}' "$SRC/MANIFEST.sha256" | LC_ALL=C sort) \
  <(cd "$SRC" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort))"
[ -z "$extra" ] || die "files not listed in manifest: $extra" 3
log "manifest OK"
sed 's/^/  meta: /' "$SRC/META.txt"

F="$SRC/files"
[ -f "$F/etc/postfiatd/postfiatd.cfg" ] || die "postfiatd.cfg missing from archive" 3
[ -f "$F$COMPOSE_DIR/docker-compose.yml" ] || die "docker-compose.yml for $COMPOSE_DIR missing from archive" 3

# 3b. compose file set: COMPOSE_FILE from the archived .env, else the base pair. Check every overlay's host
# prerequisite BEFORE changing anything.
A="$F$COMPOSE_DIR"
cf="$(sed -n 's/^COMPOSE_FILE=//p' "$A/.env" 2>/dev/null | tail -1 | tr -d "\"'\r")"
[ -n "$cf" ] || cf="docker-compose.yml$([ -f "$A/docker-compose.override.yml" ] && echo :docker-compose.override.yml)"
fix_hint() { case "$1" in *seccomp*) echo "seccomp/ (sudo pft-seccomp apply --yes)" ;; *apparmor*) echo "apparmor/ (sudo pft-apparmor apply --yes)" ;; *) echo "the add-on that wrote $1" ;; esac; }
members=(); deferred=()
IFS=: read -r -a listed <<<"$cf"
for m in "${listed[@]}"; do
  [ -f "$A/$m" ] || die "COMPOSE_FILE member $m is not in the archive (made before backup/ saved overlays?); nothing was restored" 3
  miss=""
  while read -r sc; do [ -f "$sc" ] || miss="$miss seccomp profile $sc missing;"; done < <(sed -nE 's/.*seccomp=([^"'"'"' ]+).*/\1/p' "$A/$m" | grep -v '^unconfined$')
  while read -r aa; do
    grep -q "^$aa " /sys/kernel/security/apparmor/profiles 2>/dev/null || miss="$miss AppArmor profile $aa not loaded;"
  done < <(sed -nE 's/.*apparmor=([^"'"'"' ]+).*/\1/p' "$A/$m" | grep -v '^unconfined$')
  if [ -z "$miss" ]; then members+=("$m"); continue; fi
  if [ "$DEFER" -eq 1 ]; then deferred+=("$m"); log "DEFERRED overlay $m:$miss re-create it with $(fix_hint "$m")"
  else die "overlay $m cannot be applied on this host:$miss install + apply $(fix_hint "$m") first, or pass --defer-hardening; nothing was restored" 5; fi
done
EFFECTIVE="$(IFS=:; echo "${members[*]}")"
log "compose files: $EFFECTIVE${deferred[*]:+ (deferred: ${deferred[*]})}"
# compose resolves COMPOSE_FILE members against the CWD, not --project-directory (rebuild run 03: "stat
# /root/pfvi/docker-compose.yml"), so run it from COMPOSE_DIR.
dc() { run env -C "$COMPOSE_DIR" COMPOSE_FILE="$EFFECTIVE" docker compose --project-directory "$COMPOSE_DIR" "$@"; }

# 4. compose files
TS="$(date -u +%Y%m%dT%H%M%SZ)"
log "restore compose files -> $COMPOSE_DIR"
run mkdir -p "$COMPOSE_DIR" "$COMPOSE_DIR/logs"
for f in .env "${members[@]}"; do
  [ -f "$A/$f" ] || continue
  [ -f "$COMPOSE_DIR/$f" ] && run cp -p "$COMPOSE_DIR/$f" "$COMPOSE_DIR/$f.pre-restore-$TS"
  mode=0644; [ "$f" = .env ] && mode=0600
  run install -m "$mode" "$A/$f" "$COMPOSE_DIR/$f"
done
if [ "${#deferred[@]}" -gt 0 ] && grep -q '^COMPOSE_FILE=' "$A/.env"; then
  log "COMPOSE_FILE in $COMPOSE_DIR/.env without the deferred overlays: $EFFECTIVE"
  run sed -i "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$EFFECTIVE|" "$COMPOSE_DIR/.env"
fi

# 5. optional units / firewall
if [ "$WITH_UNITS" -eq 1 ]; then
  log "restore add-on units and helper scripts (not enabled)"
  while IFS= read -r p; do
    case "$p" in units-enabled.txt) continue ;; opt/postfiatd/*|etc/postfiatd/*) continue ;; esac
    run install -D -m "$(stat -c %a "$F/$p")" "$F/$p" "/$p"
  done < <(cd "$F" && find . -type f -printf '%P\n' | LC_ALL=C sort)
  run systemctl daemon-reload
  [ -f "$F/units-enabled.txt" ] && sed 's/^/  was enabled on source: /' "$F/units-enabled.txt"
else
  log "skip units (use --with-units)"
fi
if [ "$WITH_FIREWALL" -eq 1 ]; then
  command -v ufw >/dev/null || die "ufw not installed"
  log "restore ufw user rules"
  for r in user.rules user6.rules; do
    [ -f "$SRC/firewall/$r" ] || continue
    run cp -p "/etc/ufw/$r" "/etc/ufw/$r.pre-restore-$TS"
    run install -m 0640 "$SRC/firewall/$r" "/etc/ufw/$r"
  done
  run ufw reload
  log "DOCKER-USER rules are re-applied by postfiat-docker-user.service (restore with --with-units)"
else
  log "skip firewall (use --with-firewall; saved rules are in firewall/ of the archive)"
fi

# 6. container + config volume
log "create container and load config into its volume"
dc create
if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
  dc stop
fi
run docker cp "$F/etc/postfiatd/postfiatd.cfg" "$CONTAINER:/etc/postfiatd/postfiatd.cfg"
[ -f "$F/etc/postfiatd/validators.txt" ] &&
  run docker cp "$F/etc/postfiatd/validators.txt" "$CONTAINER:/etc/postfiatd/validators.txt"
START="$(date +%s)"
dc up -d

if [ "$DRY_RUN" -eq 1 ]; then
  log "DRY-RUN would wait up to ${TIMEOUT}s for server_state full"
  log "DRY-RUN complete; nothing changed"
  exit 0
fi

log "waiting up to ${TIMEOUT}s for server_state full"
state=unknown
last=""
while :; do
  el=$(( $(date +%s) - START ))
  state="$(docker exec "$CONTAINER" curl -s --max-time 10 http://localhost:5005/ -X POST \
    -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' 2>/dev/null |
    grep -o '"server_state":"[^"]*"' | cut -d'"' -f4 || true)"
  state="${state:-unreachable}"
  [ "$state" != "$last" ] && log "  t+${el}s server_state: $state" && last="$state"
  case "$state" in full|proposing|validating) break ;; esac
  [ "$el" -ge "$TIMEOUT" ] && die "server_state still '$state' after ${TIMEOUT}s" 4
  sleep 5
done
log "server_state: $state after $(( $(date +%s) - START ))s"
log "restore complete"
