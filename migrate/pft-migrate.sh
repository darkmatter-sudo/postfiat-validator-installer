#!/usr/bin/env bash
# pft-migrate: move a Docker postfiatd node (validator or sentry) to another host without ever running both copies.
#
# The bundle carries the node's identity and configuration (postfiatd.cfg incl. [node_seed]/[validator_token],
# validators.txt, every compose file + .env + COMPOSE_FILE overlay, the overlays' host files: seccomp JSON and
# AppArmor profile, the pft-cluster pinned seed). It is a tar encrypted with age to the TARGET's recipient; plaintext
# is only staged in RAM (STAGE_BASE, /dev/shm) and removed on exit. MANIFEST.sha256 inside, sidecar .sha256 outside.
# The ledger DB is not moved: the target syncs from the network.
#
# Usage (source = old host, target = new host):
#   pft-migrate.sh plan [--role validator|sentry] [--json]        read-only: what would move, checks
#   sudo pft-migrate.sh export --to AGE1..|RECIPIENTS_FILE --out DIR [--role R]
#                                         bundle DIR/pft-migrate-ID.age + .sha256; prints the bundle id
#   sudo pft-migrate.sh fence-source --bundle-id ID [--proof-out FILE]
#                                         stop the node, restart=no, compose guard, FENCED, pft-maint lock; prints
#                                         the fence proof (copy it to the other host)
#   sudo pft-migrate.sh import --bundle FILE --identity AGE_KEY_FILE [--skip-overlay NAME]... [--replace]
#                                         verify sidecar + manifest, install files, guard on, never starts the node
#   sudo pft-migrate.sh start-target --fence-proof FILE --source ADDR[:PORT]
#                                         refuses unless the proof is for the imported bundle and the source's peer
#                                         port does not answer; removes the guard and starts the node
#   pft-migrate.sh verify --expect-pubkey PUB [--since-proof FILE] [--timeout SEC]
#                                         wait for server_state full with that pubkey_node; prints downtime_s
#   sudo pft-migrate.sh rollback --bundle-id ID --fence-proof TARGET_PROOF --target ADDR[:PORT]
#                                         on the source, after `fence-source` on the target: refuses unless the target
#                                         is fenced and silent; restores .env byte-identical, restart policy, starts
#   pft-migrate.sh status                 FENCED / IMPORTED records of this host
#   ("fence" is an alias of fence-source: the target is fenced the same way before a rollback.)
#
# Exit: 0 ok | 1 check failed / timeout | 2 integrity or crypto error (sidecar, manifest, age, layout, pubkey
#       mismatch) | 3 usage | 4 refused by the fencing rules
# Env: STATE_DIR (/var/lib/pft-migrate)  STAGE_BASE (/dev/shm)  RPC_URL (http://127.0.0.1:5005/)  PEER_PORT (2559)
#      STOP_TIMEOUT (60)  LOCK_TTL (7200)  AGE (age)  DOCKER (docker)  MAINT (pft-maint; empty = no lock)
#      Test hooks: PFT_MIGRATE_ROOT (prefix of every host path)  PFT_MIGRATE_TEST=1 (no root check)
#      PFT_MIGRATE_RPC (cmd METHOD -> JSON)  PFT_MIGRATE_PROBE (cmd HOST PORT -> exit 0 if it answers)
#      PFT_MIGRATE_NOW (fixed epoch)  POLL_SEC (5)

# "A && B || die" is intended (die exits); single-quoted $ are literal (bash -c script, compose text)
# shellcheck disable=SC2015,SC2016
set -uo pipefail
umask 077

R="${PFT_MIGRATE_ROOT:-}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-migrate}"
STAGE_BASE="${STAGE_BASE:-/dev/shm}"
RPC_URL="${RPC_URL:-http://127.0.0.1:5005/}"
PEER_PORT="${PEER_PORT:-2559}"
STOP_TIMEOUT="${STOP_TIMEOUT:-60}"
LOCK_TTL="${LOCK_TTL:-7200}"
POLL_SEC="${POLL_SEC:-5}"
AGE="${AGE:-age}"
DOCKER="${DOCKER:-docker}"
MAINT="${MAINT-pft-maint}"
CFG_DEST=/etc/postfiatd
GUARD=docker-compose.migrate-fence.yml
FENCED="$STATE_DIR/FENCED"
IMPORTED="$STATE_DIR/IMPORTED"
AGE_RE='^age1[02-9ac-hj-np-z]{58}$'
ID_RE='^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$'
PUB_RE='^n9[1-9A-HJ-NP-Za-km-z]{48,52}$'

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $1"; exit "${2:-1}"; }
usage() { sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
now() { if [ -n "${PFT_MIGRATE_NOW:-}" ]; then echo "$PFT_MIGRATE_NOW"; else date -u +%s; fi; }
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
need_root() { [ "${PFT_MIGRATE_TEST:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] || die "run as root (sudo)." 3; }
kv() { sed -n "s/^$1=//p" "$2" 2>/dev/null | head -1; } # KEY FILE -> value of the first KEY= line

STAGE=""
cleanup() { [ -n "$STAGE" ] && rm -rf "$STAGE"; }
trap cleanup EXIT
mkstage() {
  [ -d "$STAGE_BASE" ] && [ -w "$STAGE_BASE" ] || die "STAGE_BASE $STAGE_BASE is not a writable directory" 3
  STAGE="$(mktemp -d "$STAGE_BASE/pft-migrate.XXXXXX")" || die "cannot create stage dir" 2
}

rpc() { # METHOD -> JSON answer (host-mapped RPC port, read-only methods only)
  if [ -n "${PFT_MIGRATE_RPC:-}" ]; then "$PFT_MIGRATE_RPC" "$1"; return; fi
  curl -s -m 5 -H 'Content-Type: application/json' -d "{\"method\":\"$1\",\"params\":[{}]}" "$RPC_URL" 2>/dev/null
}
info_field() { rpc server_info | jq -r ".result.info.$1 // empty" 2>/dev/null; }
probe() { # HOST PORT -> 0 if a TCP connect succeeds within 3 s
  if [ -n "${PFT_MIGRATE_PROBE:-}" ]; then "$PFT_MIGRATE_PROBE" "$1" "$2"; return; fi
  timeout 3 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>/dev/null
}
split_addr() { # ADDR[:PORT] -> sets AH, AP (no subshell: die must exit the tool)
  local a="$1"
  case "$a" in
    \[*\]:*) AH="${a%%]:*}"; AH="${AH#[}"; AP="${a##*]:}" ;;
    *:*:*) AH="$a"; AP="$PEER_PORT" ;;
    *:*) AH="${a%:*}"; AP="${a##*:}" ;;
    *) AH="$a"; AP="$PEER_PORT" ;;
  esac
  [[ "$AP" =~ ^[0-9]{1,5}$ ]] && [ -n "$AH" ] || die "bad address '$a' (want HOST[:PORT])" 3
}

# --- the node on this host ---------------------------------------------------------------------------------------
container_for() { # ROLE -> container name (ROLE is checked by set_role)
  case "$1" in sentry) echo postfiatd-sentry ;; *) echo postfiatd ;; esac
}
set_role() { case "$1" in validator|sentry) ROLE="$1" ;; *) die "--role must be validator or sentry" 3 ;; esac; }
detect_role() {
  [ -n "${ROLE:-}" ] && { echo "$ROLE"; return; }
  if "$DOCKER" inspect postfiatd-sentry >/dev/null 2>&1; then echo sentry; else echo validator; fi
}
label() { "$DOCKER" inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null; }
cfgvol_dir() { # CONTAINER -> host dir mounted at /etc/postfiatd
  local s
  s="$("$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "'"$CFG_DEST"'"}}{{.Source}}{{end}}{{end}}' "$1" 2>/dev/null)"
  [ -n "$s" ] && echo "$R$s"
}
cfgvol_name() {
  "$DOCKER" inspect -f '{{range .Mounts}}{{if eq .Destination "'"$CFG_DEST"'"}}{{.Name}}{{end}}{{end}}' "$1" 2>/dev/null
}
compose_members() { # COMPOSE_DIR -> every compose file compose loads (base pair, COMPOSE_FILE members), one per line
  local cf
  cf="$(sed -n 's/^COMPOSE_FILE=//p' "$1/.env" 2>/dev/null | tail -1 | tr -d "\"'\r")"
  { [ -n "$cf" ] && tr ':' '\n' <<<"$cf" || printf '%s\n' docker-compose.yml docker-compose.override.yml; } | awk 'NF && !seen[$0]++'
}
overlay_deps() { # COMPOSE_DIR -> "KIND PATH-OR-NAME FILE" for every host dependency named by a loaded compose file
  local d="$1" f
  while IFS= read -r f; do
    [ -f "$d/$f" ] || continue
    sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}seccomp=\([^"]*\)"\{0,1\}[[:space:]]*$/seccomp \1/p' "$d/$f" | sed "s|\$| $f|"
    sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}apparmor=\([^"]*\)"\{0,1\}[[:space:]]*$/apparmor \1/p' "$d/$f" | sed "s|\$| $f|"
  done < <(compose_members "$d")
}

# Bundle layout (paths inside the tar), checked again by import:
#   META  MANIFEST.sha256  cfgvol/<file>  compose/<file>  cluster/node_seed|node_pub  host/etc/pft-seccomp/<f>.json
#   host/etc/apparmor.d/pft-<name>
LAYOUT_RE='^\./(META|MANIFEST\.sha256|cfgvol/[A-Za-z0-9._-]+|compose/(\.env|[A-Za-z0-9._-]+\.ya?ml)|cluster/node_(seed|pub)|host/etc/pft-seccomp/[A-Za-z0-9._-]+\.json|host/etc/apparmor\.d/pft-[A-Za-z0-9._-]+)$'
DIR_RE='^\./((cfgvol|compose|cluster|host|host/etc|host/etc/pft-seccomp|host/etc/apparmor\.d)/?)?$'

collect() { # ROLE STAGE -> fills STAGE, prints one "PATH BYTES" per file; non-zero on a missing dependency
  local role="$1" st="$2" c dir vol f kind dep from rc=0
  c="$(container_for "$role")"
  "$DOCKER" inspect "$c" >/dev/null 2>&1 || die "container '$c' not found on this host" 1
  dir="$R$(label "$c" com.docker.compose.project.working_dir)"
  [ -f "$dir/docker-compose.yml" ] || die "compose dir of '$c' not found ($dir)" 1
  vol="$(cfgvol_dir "$c")"; [ -n "$vol" ] && [ -f "$vol/postfiatd.cfg" ] || die "no postfiatd.cfg in the config volume of '$c'" 1
  mkdir -p "$st/cfgvol" "$st/compose"
  for f in postfiatd.cfg validators.txt; do
    if [ -f "$vol/$f" ]; then cp -p "$vol/$f" "$st/cfgvol/$f"; echo "cfgvol/$f $(stat -c %s "$vol/$f")"
    elif [ "$f" = postfiatd.cfg ]; then rc=1; fi
  done
  while IFS= read -r f; do
    case "$f" in */* | ..* | "$GUARD") log "compose member '$f' not supported here"; rc=1; continue ;; esac
    if [ -f "$dir/$f" ]; then cp -p "$dir/$f" "$st/compose/$f"; echo "compose/$f $(stat -c %s "$dir/$f")"
    elif [ "$f" != docker-compose.override.yml ]; then log "COMPOSE_FILE lists $f but $dir/$f is missing"; rc=1; fi
  done < <(compose_members "$dir")
  [ -f "$dir/.env" ] && cp -p "$dir/.env" "$st/compose/.env" && echo "compose/.env $(stat -c %s "$dir/.env")"
  for f in node_seed node_pub; do
    [ -f "$R/var/lib/pft-cluster/$f" ] || continue
    mkdir -p "$st/cluster"; cp -p "$R/var/lib/pft-cluster/$f" "$st/cluster/$f"; echo "cluster/$f $(stat -c %s "$st/cluster/$f")"
  done
  while read -r kind dep from; do
    case "$kind" in
      seccomp) case "$dep" in /etc/pft-seccomp/*.json) ;; *) log "seccomp file $dep ($from) is outside /etc/pft-seccomp"; rc=1; continue ;; esac ;;
      apparmor) [[ "$dep" =~ ^pft-[A-Za-z0-9._-]+$ ]] || { log "AppArmor profile '$dep' ($from) is not a pft-* profile"; rc=1; continue; }
        dep="/etc/apparmor.d/$dep" ;;
    esac
    if [ -f "$R$dep" ]; then mkdir -p "$st/host$(dirname "$dep")"; cp -p "$R$dep" "$st/host$dep"; echo "host$dep $(stat -c %s "$R$dep")"
    else log "$from needs $dep, which is missing on this host"; rc=1; fi
  done < <(overlay_deps "$dir")
  return "$rc"
}

# --- plan ----------------------------------------------------------------------------------------------------------
cmd_plan() {
  local json=0 role c st list rc state pub fence="no"
  while [ $# -gt 0 ]; do case "$1" in --json) json=1 ;; --role) set_role "${2:-}"; shift ;; *) die "plan: unknown argument $1" 3 ;; esac; shift; done
  role="$(detect_role)"; c="$(container_for "$role")"
  mkstage
  list="$(collect "$role" "$STAGE/b")"; rc=$?
  state="$(info_field server_state)"; pub="$(info_field pubkey_node)"
  [ -f "$FENCED" ] && fence="yes ($(kv bundle_id "$FENCED"))"
  if [ "$json" = 1 ]; then
    jq -n --arg role "$role" --arg c "$c" --arg state "${state:-down}" --arg pub "${pub:-unknown}" --arg fence "$fence" \
      --arg seed "$([ -f "$STAGE/b/cluster/node_seed" ] && echo pinned || echo not-pinned)" --argjson ok "$([ "$rc" = 0 ] && echo true || echo false)" \
      --arg files "$list" '{role:$role,container:$c,server_state:$state,pubkey_node:$pub,node_seed:$seed,fenced:$fence,ok:$ok,
        files:($files|split("\n")|map(select(length>0)|split(" ")|{path:.[0],bytes:(.[1]|tonumber)}))}'
  else
    echo "pft-migrate plan - role $role, container $c"
    echo "  node: server_state ${state:-down}, pubkey_node ${pub:-unknown}"
    echo "  fenced: $fence"
    [ -f "$STAGE/b/cluster/node_seed" ] && echo "  identity: pinned by pft-cluster (moves with the bundle)" \
      || echo "  identity: NOT pinned ([node_seed] only if postfiatd.cfg has one; else pubkey_node changes on the target)"
    echo "  files in the bundle:"; sed 's/^/    /; s/ \([0-9]*\)$/  (\1 bytes)/' <<<"$list"
    command -v "$AGE" >/dev/null || { echo "  age: MISSING"; rc=1; }
    echo "RESULT: $([ "$rc" = 0 ] && echo "OK - ready to export" || echo "FAIL - fix the lines above first")"
  fi
  return "$rc"
}

# --- export --------------------------------------------------------------------------------------------------------
cmd_export() {
  local to="" out="" role c id st bundle pub state rargs=() n
  while [ $# -gt 0 ]; do
    case "$1" in --to) to="${2:-}"; shift ;; --out) out="${2:-}"; shift ;; --role) set_role "${2:-}"; shift ;; *) die "export: unknown argument $1" 3 ;; esac; shift
  done
  need_root
  [ -n "$to" ] && [ -n "$out" ] || die "export needs --to RECIPIENT and --out DIR" 3
  if [[ "$to" =~ $AGE_RE ]]; then rargs=(-r "$to")
  elif [ -f "$to" ] && grep -qE "$AGE_RE" "$to" && ! grep -q 'AGE-SECRET-KEY' "$to"; then rargs=(-R "$to")
  else die "--to: want an age recipient (age1...) or a file of recipients (never an identity)" 3; fi
  command -v "$AGE" >/dev/null || die "age is required" 3
  mkdir -p "$out" && [ -w "$out" ] || die "--out $out is not writable" 3
  role="$(detect_role)"; c="$(container_for "$role")"
  state="$(info_field server_state)"; pub="$(info_field pubkey_node)"
  [[ "$pub" =~ $PUB_RE ]] || die "cannot read pubkey_node from the running node (state '${state:-down}'): export reads it live" 1
  id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  mkstage; st="$STAGE/b"; mkdir -p "$st"
  collect "$role" "$st" >"$STAGE/list" || die "collect failed (run plan)" 1
  {
    echo "v=1"; echo "bundle_id=$id"; echo "created=$(iso "$(now)")"; echo "role=$role"; echo "container=$c"
    echo "service=$(label "$c" com.docker.compose.service)"; echo "project=$(label "$c" com.docker.compose.project)"
    echo "compose_dir=$(label "$c" com.docker.compose.project.working_dir)"; echo "cfg_volume=$(cfgvol_name "$c")"
    echo "image=$("$DOCKER" inspect -f '{{.Config.Image}}' "$c")"; echo "restart_policy=$("$DOCKER" inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c")"
    echo "source_pubkey=$pub"; echo "source_state=$state"; echo "not_moved=ledger database (re-syncs from the network)"
  } >"$st/META"
  (cd "$st" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum) >"$STAGE/MANIFEST.sha256"
  mv "$STAGE/MANIFEST.sha256" "$st/MANIFEST.sha256"
  n="$(wc -l <"$st/MANIFEST.sha256")"
  bundle="$out/pft-migrate-$id.age"
  tar -C "$st" --owner=0 --group=0 --numeric-owner -cf - . | "$AGE" "${rargs[@]}" -o "$bundle.tmp" || { rm -f "$bundle.tmp"; die "age encryption failed" 2; }
  mv "$bundle.tmp" "$bundle"; chmod 600 "$bundle"
  (cd "$out" && sha256sum "$(basename "$bundle")" >"$(basename "$bundle").sha256")
  mkdir -p "$STATE_DIR/exports"; chmod 700 "$STATE_DIR"
  { echo "bundle_id=$id"; echo "created=$(iso "$(now)")"; echo "role=$role"; echo "container=$c"; echo "pubkey=$pub"
    echo "files=$n"; echo "bundle_sha256=$(cut -c1-64 "$bundle.sha256")"; } >"$STATE_DIR/exports/$id.meta"
  log "bundle $bundle ($(stat -c %s "$bundle") bytes, $n files + manifest, encrypted to ${#rargs[@]} arg(s) of age)"
  log "sha256 $(cut -c1-64 "$bundle.sha256")"
  sed 's/^/  /' "$STAGE/list" >&2
  echo "$id"
}

# --- fence ---------------------------------------------------------------------------------------------------------
record_for() { # ID -> the local record that knows this bundle (export on a source, IMPORTED on a target)
  if [ -f "$STATE_DIR/exports/$1.meta" ]; then echo "$STATE_DIR/exports/$1.meta"
  elif [ -f "$IMPORTED" ] && [ "$(kv bundle_id "$IMPORTED")" = "$1" ]; then echo "$IMPORTED"; fi
}
guard_on() { # COMPOSE_DIR SERVICE ID: compose overlay that keeps `docker compose up` from running the node
  local d="$1" svc="$2" id="$3" cf
  printf '# written by pft-migrate: this copy of the node is FENCED (bundle %s).\n# Only `pft-migrate.sh start-target` or `rollback` removes it; do not edit COMPOSE_FILE by hand.\nservices:\n  %s:\n    restart: "no"\n    entrypoint: ["/pft-migrate-FENCED-%s"]\n' \
    "$id" "$svc" "$id" >"$d/$GUARD"
  chmod 644 "$d/$GUARD"
  cf="$(compose_members "$d" | grep -vx "$GUARD" | while IFS= read -r m; do [ -f "$d/$m" ] && echo "$m"; done | paste -sd: -)"
  if grep -q '^COMPOSE_FILE=' "$d/.env" 2>/dev/null; then sed -i "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$cf:$GUARD|" "$d/.env"
  else echo "COMPOSE_FILE=$cf:$GUARD" >>"$d/.env"; fi
}
guard_state() { # COMPOSE_DIR -> on|off
  if [ -f "$1/$GUARD" ] && compose_members "$1" | grep -qx "$GUARD"; then echo on; else echo off; fi
}

cmd_fence() {
  local id="" pout="" rec c dir svc st pol peer rpcs t
  while [ $# -gt 0 ]; do
    case "$1" in --bundle-id) id="${2:-}"; shift ;; --proof-out) pout="${2:-}"; shift ;; *) die "fence-source: unknown argument $1" 3 ;; esac; shift
  done
  need_root
  [[ "$id" =~ $ID_RE ]] || die "--bundle-id ID required (as printed by export)" 3
  rec="$(record_for "$id")"; [ -n "$rec" ] || die "bundle $id is not known on this host (no export or import record)" 4
  if [ -f "$FENCED" ] && [ "$(kv bundle_id "$FENCED")" != "$id" ]; then die "already FENCED for bundle $(kv bundle_id "$FENCED")" 4; fi
  c="$(kv container "$rec")"; "$DOCKER" inspect "$c" >/dev/null 2>&1 || die "container $c not found" 1
  dir="$R$(label "$c" com.docker.compose.project.working_dir)"; svc="$(label "$c" com.docker.compose.service)"
  [ -f "$dir/docker-compose.yml" ] && [ -n "$svc" ] || die "compose dir/service of $c not found" 1
  t="$(now)"
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  if [ ! -f "$FENCED" ]; then # first fence of this bundle: keep what rollback restores
    if [ -f "$dir/.env" ]; then cp -p "$dir/.env" "$STATE_DIR/env.pre-fence"; else rm -f "$STATE_DIR/env.pre-fence"; fi
    "$DOCKER" inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c" >"$STATE_DIR/restart.pre-fence"
  fi
  if [ -n "$MAINT" ] && command -v "$MAINT" >/dev/null; then
    "$MAINT" lock add pft-migrate --until "$((t + LOCK_TTL))" --reason "pft-migrate fence $id" >&2 || log "WARN: pft-maint lock failed"
  fi
  guard_on "$dir" "$svc" "$id"
  "$DOCKER" update --restart=no "$c" >/dev/null || die "docker update --restart=no failed" 1
  "$DOCKER" stop -t "$STOP_TIMEOUT" "$c" >/dev/null || die "docker stop $c failed" 1
  st="$("$DOCKER" inspect -f '{{.State.Status}}' "$c")"; pol="$("$DOCKER" inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$c")"
  if probe 127.0.0.1 "$PEER_PORT"; then peer=answers; else peer=closed; fi
  if [ -n "$(info_field server_state)" ]; then rpcs=answers; else rpcs=down; fi
  { echo "v=1"; echo "kind=pft-migrate-fence"; echo "bundle_id=$id"; echo "pubkey=$(kv pubkey "$rec")"; echo "container=$c"
    echo "fenced_at=$t"; echo "fenced_at_iso=$(iso "$t")"; echo "container_state=$st"; echo "restart_policy=$pol"
    echo "compose_guard=$(guard_state "$dir")"; echo "peer_port_local=$peer"; echo "rpc=$rpcs"; } >"$STAGE_BASE/.fence.$$"
  if [ "$st" != exited ] || [ "$pol" != no ] || [ "$peer" != closed ] || [ "$rpcs" != down ]; then
    cat "$STAGE_BASE/.fence.$$" >&2; rm -f "$STAGE_BASE/.fence.$$"; die "fence NOT proven (see above); the node may still run" 1
  fi
  [ -f "$FENCED" ] || mv "$STAGE_BASE/.fence.$$" "$FENCED"
  rm -f "$STAGE_BASE/.fence.$$"; chmod 644 "$FENCED"
  [ -n "$pout" ] && cp "$FENCED" "$pout" && chmod 644 "$pout"
  log "FENCED: $c exited, restart=no, compose guard on, peer port closed, RPC down (bundle $id)"
  cat "$FENCED"
}

check_proof() { # FILE ID PUB -> 0 if FILE is a complete fence proof for this bundle and key
  local f="$1" k
  [ -f "$f" ] || { log "fence proof $f not found"; return 1; }
  [ "$(kv kind "$f")" = pft-migrate-fence ] || { log "not a pft-migrate fence proof"; return 1; }
  [ "$(kv bundle_id "$f")" = "$2" ] || { log "proof is for bundle '$(kv bundle_id "$f")', not $2"; return 1; }
  [ "$(kv pubkey "$f")" = "$3" ] || { log "proof is for pubkey '$(kv pubkey "$f")', not the bundle's"; return 1; }
  for k in container_state=exited restart_policy=no compose_guard=on peer_port_local=closed rpc=down; do
    [ "$(kv "${k%%=*}" "$f")" = "${k#*=}" ] || { log "proof: ${k%%=*} is '$(kv "${k%%=*}" "$f")', want ${k#*=}"; return 1; }
  done
  [[ "$(kv fenced_at "$f")" =~ ^[0-9]+$ ]] || { log "proof: fenced_at missing"; return 1; }
}

# --- import --------------------------------------------------------------------------------------------------------
cmd_import() {
  local bundle="" idf="" replace=0 skip=() st id dir vol vname c svc proj f d bad k
  while [ $# -gt 0 ]; do
    case "$1" in --bundle) bundle="${2:-}"; shift ;; --identity) idf="${2:-}"; shift ;; --replace) replace=1 ;;
      --skip-overlay) skip+=("${2:?}"); shift ;; *) die "import: unknown argument $1" 3 ;; esac; shift
  done
  need_root
  [ -f "$bundle" ] && [ -f "$idf" ] || die "import needs --bundle FILE and --identity AGE_KEY_FILE" 3
  [ -f "$bundle.sha256" ] || die "sidecar $bundle.sha256 missing" 2
  [ "$(cut -c1-64 "$bundle.sha256")" = "$(sha256sum <"$bundle" | cut -c1-64)" ] || die "bundle sha256 does not match its sidecar (tampered or truncated)" 2
  mkstage
  "$AGE" -d -i "$idf" -o "$STAGE/b.tar" "$bundle" 2>"$STAGE/age.err" || { sed 's/^/  age: /' "$STAGE/age.err" >&2; die "age decryption failed (wrong identity or damaged bundle)" 2; }
  bad="$(tar -tvf "$STAGE/b.tar" 2>&1 | awk '$1 !~ /^[-d]/' )"; [ -z "$bad" ] || die "bundle holds links/devices: $bad" 2
  bad="$(tar -tf "$STAGE/b.tar" | grep -vE "$LAYOUT_RE" | grep -vE "$DIR_RE")"; [ -z "$bad" ] || die "unexpected path(s) in bundle: $(head -3 <<<"$bad" | tr '\n' ' ')" 2
  mkdir "$STAGE/b" && tar -xpf "$STAGE/b.tar" -C "$STAGE/b" --no-same-owner || die "cannot unpack bundle" 2
  rm -f "$STAGE/b.tar"
  st="$STAGE/b"; [ -f "$st/MANIFEST.sha256" ] && [ -f "$st/META" ] || die "bundle has no MANIFEST.sha256/META" 2
  (cd "$st" && sha256sum --strict --quiet -c MANIFEST.sha256 >"$STAGE/m.err" 2>&1) || { sed 's/^/  /' "$STAGE/m.err" >&2; die "manifest check failed" 2; }
  [ "$(cd "$st" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort)" = "$(awk '{print $2}' "$st/MANIFEST.sha256" | LC_ALL=C sort)" ] \
    || die "files in the bundle differ from its manifest" 2
  id="$(kv bundle_id "$st/META")"; [[ "$id" =~ $ID_RE ]] || die "META: bad bundle_id" 2
  [[ "$(kv source_pubkey "$st/META")" =~ $PUB_RE ]] || die "META: bad source_pubkey" 2
  c="$(kv container "$st/META")"; svc="$(kv service "$st/META")"; proj="$(kv project "$st/META")"; vname="$(kv cfg_volume "$st/META")"
  dir="$R$(kv compose_dir "$st/META")"
  for k in "$c" "$svc" "$proj" "$vname"; do [[ "$k" =~ ^[A-Za-z0-9_.-]+$ ]] || die "META: bad container/service/project/volume name" 2; done
  [[ "$(kv compose_dir "$st/META")" =~ ^/[A-Za-z0-9_./-]+$ ]] && [[ "$(kv compose_dir "$st/META")" != *..* ]] || die "META: bad compose_dir" 2
  log "bundle $id verified: sidecar ok, age ok, layout ok, manifest $(wc -l <"$st/MANIFEST.sha256") files ok"
  # fencing rules for this host
  if "$DOCKER" inspect "$c" >/dev/null 2>&1 && [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c")" = true ]; then
    die "container $c is RUNNING on this host: refusing to install a second copy" 4
  fi
  if [ -f "$FENCED" ] && [ "$(kv bundle_id "$FENCED")" = "$id" ]; then die "this host is FENCED for bundle $id (it is that bundle's source or was rolled back)" 4; fi
  for f in "${skip[@]}"; do
    [ -f "$st/compose/$f" ] && [ "$f" != docker-compose.yml ] || die "--skip-overlay $f: not an overlay in this bundle" 3
  done
  if [ -f "$dir/docker-compose.yml" ] && ! cmp -s "$dir/docker-compose.yml" "$st/compose/docker-compose.yml" && [ "$replace" = 0 ]; then
    die "$dir already has a different docker-compose.yml (use --replace to overwrite)" 4
  fi
  # host files the overlays need (seccomp JSON, AppArmor profile) unless that overlay is skipped
  if [ -d "$st/host" ]; then
    while IFS= read -r f; do
      d="/${f#host/}"
      if [ "${#skip[@]}" -gt 0 ] && grep -qF "${d##*/}" <(for k in "${skip[@]}"; do cat "$st/compose/$k"; done); then
        log "  skip $d (its overlay is skipped)"; continue
      fi
      mkdir -p "$R$(dirname "$d")"; install -m 0644 "$st/$f" "$R$d"; log "  + $d"
      if [[ "$d" == /etc/apparmor.d/* ]] && [ -z "$R" ]; then
        apparmor_parser -r -W "$d" || die "AppArmor profile $d did not load (use --skip-overlay for its overlay)" 1
      fi
    done < <(cd "$st" && find host -type f | LC_ALL=C sort)
  fi
  mkdir -p "$dir"; chmod 755 "$dir"
  for f in "$st"/compose/* "$st"/compose/.env; do
    [ -f "$f" ] || continue; install -m "$(stat -c %a "$f")" "$f" "$dir/$(basename "$f")"; log "  + $dir/$(basename "$f")"
  done
  for f in "${skip[@]}"; do
    sed -i "/^COMPOSE_FILE=/{s/\(=\|:\)$f\(:\|\$\)/\1\2/;s/::/:/g;s/=:/=/;s/:\$//}" "$dir/.env"; rm -f "$dir/$f"; log "  - overlay $f skipped"
  done
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  if [ -f "$dir/.env" ]; then cp -p "$dir/.env" "$STATE_DIR/env.imported"; else rm -f "$STATE_DIR/env.imported"; fi
  guard_on "$dir" "$svc" "$id"
  "$DOCKER" volume inspect "$vname" >/dev/null 2>&1 || "$DOCKER" volume create --label "com.docker.compose.project=$proj" \
    --label "com.docker.compose.volume=${vname#"${proj}"_}" "$vname" >/dev/null || die "cannot create volume $vname" 1
  vol="$R$("$DOCKER" volume inspect -f '{{.Mountpoint}}' "$vname")"; [ -d "$vol" ] || die "volume $vname has no mountpoint" 1
  for f in "$st"/cfgvol/*; do install -m "$(stat -c %a "$f")" "$f" "$vol/$(basename "$f")"; log "  + volume $vname/$(basename "$f")"; done
  if [ -d "$st/cluster" ]; then
    install -d -m 0700 "$R/var/lib/pft-cluster"
    for f in "$st"/cluster/*; do install -m 0600 "$f" "$R/var/lib/pft-cluster/$(basename "$f")"; log "  + /var/lib/pft-cluster/$(basename "$f")"; done
  fi
  { echo "bundle_id=$id"; echo "imported=$(iso "$(now)")"; echo "role=$(kv role "$st/META")"; echo "container=$c"
    echo "pubkey=$(kv source_pubkey "$st/META")"; echo "compose_dir=$(kv compose_dir "$st/META")"
    echo "skipped=${skip[*]:-}"; } >"$IMPORTED"
  chmod 644 "$IMPORTED"
  log "imported bundle $id; node NOT started (compose guard on); next: start-target --fence-proof ... --source ..."
  echo "$id"
}

# --- start-target --------------------------------------------------------------------------------------------------
cmd_start_target() {
  local proof="" src="" id pub dir h p t
  while [ $# -gt 0 ]; do
    case "$1" in --fence-proof) proof="${2:-}"; shift ;; --source) src="${2:-}"; shift ;; *) die "start-target: unknown argument $1" 3 ;; esac; shift
  done
  need_root
  [ -n "$proof" ] && [ -n "$src" ] || die "start-target needs --fence-proof FILE and --source ADDR[:PORT]" 3
  split_addr "$src"; h="$AH"; p="$AP"
  [ -f "$IMPORTED" ] || die "nothing imported on this host" 4
  id="$(kv bundle_id "$IMPORTED")"; pub="$(kv pubkey "$IMPORTED")"; dir="$R$(kv compose_dir "$IMPORTED")"
  if [ -f "$FENCED" ] && [ "$(kv bundle_id "$FENCED")" = "$id" ]; then die "this host is FENCED for bundle $id: start refused (only rollback unfences)" 4; fi
  check_proof "$proof" "$id" "$pub" || die "fence proof rejected: start refused" 4
  if probe "$h" "$p"; then die "the source still answers on its peer port ($p): start refused" 4; fi
  log "source fenced (proof $(kv fenced_at_iso "$proof")) and silent on port $p"
  if [ -f "$STATE_DIR/env.imported" ]; then cp -p "$STATE_DIR/env.imported" "$dir/.env"; else rm -f "$dir/.env"; fi
  rm -f "$dir/$GUARD"
  [ "$(guard_state "$dir")" = off ] || die "could not remove the compose guard" 1
  t="$(now)"
  (cd "$dir" && "$DOCKER" compose up -d) >&2 || die "docker compose up -d failed" 1
  echo "started_at=$t" >>"$IMPORTED"
  log "target started at $(iso "$t"); next: verify --expect-pubkey $pub --since-proof $proof"
}

# --- verify --------------------------------------------------------------------------------------------------------
cmd_verify() {
  local want="" proof="" tmo=1800 t0 t state pub
  while [ $# -gt 0 ]; do
    case "$1" in --expect-pubkey) want="${2:-}"; shift ;; --since-proof) proof="${2:-}"; shift ;; --timeout) tmo="${2:-}"; shift ;;
      *) die "verify: unknown argument $1" 3 ;; esac; shift
  done
  [[ "$want" =~ $PUB_RE ]] || die "--expect-pubkey n9... required" 3
  [[ "$tmo" =~ ^[0-9]+$ ]] || die "--timeout SEC" 3
  if [ -n "$proof" ]; then [[ "$(kv fenced_at "$proof")" =~ ^[0-9]+$ ]] || die "--since-proof: no fenced_at in $proof" 3; fi
  t0="$(now)"
  while :; do
    state="$(info_field server_state)"; pub="$(info_field pubkey_node)"
    if [ -n "$pub" ] && [ "$pub" != "$want" ]; then echo "pubkey_node=$pub"; die "pubkey_node is NOT the expected identity" 2; fi
    [ "$state" = full ] && break
    t="$(now)"; [ $((t - t0)) -ge "$tmo" ] && { echo "server_state=${state:-down}"; die "not full after ${tmo}s" 1; }
    if [ -n "${PFT_MIGRATE_NOW:-}" ]; then PFT_MIGRATE_NOW=$((PFT_MIGRATE_NOW + POLL_SEC)); else sleep "$POLL_SEC"; fi
  done
  t="$(now)"
  echo "server_state=full"; echo "pubkey_node=$pub (matches)"; echo "full_at=$(iso "$t")"; echo "waited_s=$((t - t0))"
  [ -n "$proof" ] && echo "downtime_s=$((t - $(kv fenced_at "$proof")))"
  return 0
}

# --- rollback (on the source) --------------------------------------------------------------------------------------
cmd_rollback() {
  local id="" proof="" tgt="" h p c dir pol t
  while [ $# -gt 0 ]; do
    case "$1" in --bundle-id) id="${2:-}"; shift ;; --fence-proof) proof="${2:-}"; shift ;; --target) tgt="${2:-}"; shift ;;
      *) die "rollback: unknown argument $1" 3 ;; esac; shift
  done
  need_root
  [[ "$id" =~ $ID_RE ]] && [ -n "$proof" ] && [ -n "$tgt" ] || die "rollback needs --bundle-id ID --fence-proof TARGET_PROOF --target ADDR[:PORT]" 3
  split_addr "$tgt"; h="$AH"; p="$AP"
  [ -f "$FENCED" ] && [ "$(kv bundle_id "$FENCED")" = "$id" ] || die "this host is not FENCED for bundle $id: nothing to roll back" 4
  [ -f "$STATE_DIR/exports/$id.meta" ] || die "rollback runs on the bundle's source (no export record for $id here)" 4
  check_proof "$proof" "$id" "$(kv pubkey "$FENCED")" || die "target fence proof rejected: rollback refused" 4
  [ "$(kv fenced_at "$proof")" -ge "$(kv fenced_at "$FENCED")" ] || die "target proof is older than this host's fence" 4
  if probe "$h" "$p"; then die "the target still answers on its peer port ($p): rollback refused" 4; fi
  c="$(kv container "$FENCED")"; dir="$R$(label "$c" com.docker.compose.project.working_dir)"
  [ -f "$dir/docker-compose.yml" ] || die "compose dir of $c not found" 1
  if [ -f "$STATE_DIR/env.pre-fence" ]; then cp -p "$STATE_DIR/env.pre-fence" "$dir/.env"; else rm -f "$dir/.env"; fi
  rm -f "$dir/$GUARD"
  [ "$(guard_state "$dir")" = off ] || die "could not remove the compose guard" 1
  pol="$(cat "$STATE_DIR/restart.pre-fence" 2>/dev/null)"; [ -n "$pol" ] || pol=unless-stopped
  "$DOCKER" update --restart="$pol" "$c" >/dev/null || die "docker update --restart=$pol failed" 1
  t="$(now)"
  (cd "$dir" && "$DOCKER" compose up -d) >&2 || die "docker compose up -d failed (guard removed, FENCED kept)" 1
  mv "$FENCED" "$STATE_DIR/rolled-back-$id"; rm -f "$STATE_DIR/env.pre-fence" "$STATE_DIR/restart.pre-fence"
  echo "rollback_started_at=$t" >>"$STATE_DIR/rolled-back-$id"
  if [ -n "$MAINT" ] && command -v "$MAINT" >/dev/null; then "$MAINT" lock rm pft-migrate >&2 || true; fi
  log "source unfenced and started (restart=$pol) at $(iso "$t"); next: verify --expect-pubkey $(kv pubkey "$STATE_DIR/rolled-back-$id") --since-proof $proof"
}

cmd_status() {
  if [ -f "$FENCED" ]; then echo "FENCED:"; sed 's/^/  /' "$FENCED"; else echo "FENCED: no"; fi
  if [ -f "$IMPORTED" ]; then echo "IMPORTED:"; sed 's/^/  /' "$IMPORTED"; else echo "IMPORTED: no"; fi
}

for c in jq sha256sum tar; do command -v "$c" >/dev/null || die "$c required" 3; done
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  plan) cmd_plan "$@" ;;
  export) cmd_export "$@" ;;
  fence-source|fence) cmd_fence "$@" ;;
  import) cmd_import "$@" ;;
  start-target) cmd_start_target "$@" ;;
  verify) cmd_verify "$@" ;;
  rollback) cmd_rollback "$@" ;;
  status) cmd_status ;;
  -h|--help|help) usage 0 ;;
  *) usage 3 ;;
esac
