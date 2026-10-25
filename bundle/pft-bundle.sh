#!/usr/bin/env bash
# pft-bundle.sh - read-only, sanitized diagnostics bundle for a Post Fiat validator or sentry host.
#
#   sudo bundle/pft-bundle.sh collect [--container NAME] [--out DIR] [--log-lines N] [--label NAME]
#                                     [--literal-env FILE]... [--redact WORD]... [--sign-key KEY] [--keep-raw DIR]
#   sudo bundle/pft-bundle.sh verify BUNDLE.tar.gz [--signers FILE] [--no-host-literals] [--literal-env FILE]...
#
# collect gathers OS/kernel, Docker image digest and container state, admin RPC summaries (server_info,
# server_state, peers, validator_list_sites, feature), postfiatd.cfg, the last N debug.log lines, disk/inode/
# memory, UFW status and the pft-*/postfiat* systemd units, runs everything through sanitize.py (IP, hostname
# and ntfy redaction, secret sections removed), re-scans the result and refuses to write a bundle if any seed,
# token or identity survived. Output: <out>/pft-bundle-<label>-<UTC>.tar.gz (0600) with MANIFEST.sha256.
# Nothing on the node is changed: RPC calls are read-only, files are read with cat/tail.
#
# verify extracts a bundle into a temp dir, checks that the member list matches MANIFEST.sha256 exactly, checks
# every hash, re-runs the secret/identity scan (with this host's identity literals unless --no-host-literals)
# and, with --signers, the ssh-keygen signature made by --sign-key.
#
# Identity literals: hostname, hostname -f, the container hostname (server_info hostid), global addresses of
# non-Docker interfaces, and NTFY_TOPIC/NTFY_URL/NTFY_TOKEN values from /etc/*.env, /etc/*/*.env and every
# --literal-env FILE. They are kept in a 0600 temp file and never written to the bundle or the terminal.
#
# Exit: 0 ok | 2 scan, manifest or signature failure (no bundle written by collect) | 3 usage | 4 prerequisite
set -uo pipefail
export TZ=UTC LC_ALL=C   # UTC timestamps everywhere; the host timezone is not part of the bundle

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZE="$HERE/sanitize.py"
CONTAINER="${CONTAINER:-postfiatd}" OUT=/var/tmp LOG_LINES=2000 LABEL="" SIGN_KEY="" SIGNERS="" KEEP_RAW=""
HOST_LITS=1 RPC_URL="${RPC_URL:-http://127.0.0.1:5005}"
LIT_ENVS=() REDACT=()

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-bundle: $1" >&2; exit "${2:-3}"; }

MODE="${1:-}"; [ $# -gt 0 ] && shift
BUNDLE=""
[ "$MODE" = verify ] && { BUNDLE="${1:-}"; [ $# -gt 0 ] && shift; }
while [ $# -gt 0 ]; do
  case "$1" in
    --container) CONTAINER="${2:?}"; shift ;;
    --out) OUT="${2:?}"; shift ;;
    --log-lines) LOG_LINES="${2:?}"; shift ;;
    --label) LABEL="${2:?}"; shift ;;
    --literal-env) LIT_ENVS+=("${2:?}"); shift ;;
    --redact) REDACT+=("${2:?}"); shift ;;
    --sign-key) SIGN_KEY="${2:?}"; shift ;;
    --signers) SIGNERS="${2:?}"; shift ;;
    --keep-raw) KEEP_RAW="${2:?}"; shift ;;
    --no-host-literals) HOST_LITS=0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done
case "$MODE" in collect|verify) ;; -h|--help|"") usage; exit 3 ;; *) die "unknown mode: $MODE" ;; esac
[[ "$LOG_LINES" =~ ^[0-9]+$ ]] || die "--log-lines must be a number"
command -v python3 >/dev/null || die "python3 required" 4
command -v jq >/dev/null || die "jq required" 4

WORK="$(mktemp -d /tmp/pft-bundle.XXXXXX)" || die "mktemp failed" 4
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
LITS="$WORK/literals"
( umask 077; : >"$LITS" )

# ---------- identity literals ----------
lit() { [ -n "$2" ] && printf '%s\t%s\n' "$1" "$2" >>"$LITS"; }
env_lits() { # FILE: NTFY_* values (quotes stripped); topic = last path segment of NTFY_URL
  local f="$1" k v
  [ -r "$f" ] || return 0
  while IFS='=' read -r k v; do
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    case "$k" in
      NTFY_TOPIC|NTFY_TOKEN) lit topic "$v" ;;
      NTFY_URL) lit topic "$v"; lit topic "${v##*/}" ;;
    esac
  done < <(grep -E '^(NTFY_TOPIC|NTFY_URL|NTFY_TOKEN)=' "$f" 2>/dev/null)
}
build_literals() {
  local h ip f
  for h in "$(hostname 2>/dev/null)" "$(hostname -f 2>/dev/null)" "$(hostname -s 2>/dev/null)"; do lit host "$h"; done
  h="$(docker inspect -f '{{.Config.Hostname}}' "$CONTAINER" 2>/dev/null)" && lit host "$h"
  while read -r ip; do lit ip "${ip%/*}"; done < <(ip -o addr show scope global 2>/dev/null |
    awk '$2 !~ /^(docker|br-|veth)/ {print $4}')
  for f in /etc/*.env /etc/*/*.env; do env_lits "$f"; done
  for f in "${LIT_ENVS[@]}"; do [ -r "$f" ] || die "--literal-env $f not readable" 4; env_lits "$f"; done
  for h in "${REDACT[@]}"; do lit host "$h"; done
}

# ---------- verify ----------
verify() {
  [ -f "$BUNDLE" ] || die "verify needs an existing BUNDLE.tar.gz"
  [ "$HOST_LITS" = 1 ] && build_literals
  for f in "${LIT_ENVS[@]}"; do [ "$HOST_LITS" = 1 ] || env_lits "$f"; done
  local names top x="$WORK/x" rc=0
  names="$(tar -tzf "$BUNDLE" 2>/dev/null)" || { echo "FAIL tar: not a readable tar.gz"; return 2; }
  if grep -qE '^/|(^|/)\.\.(/|$)' <<<"$names"; then echo "FAIL tar: absolute or .. member"; return 2; fi
  top="$(cut -d/ -f1 <<<"$names" | sort -u)"
  [ "$(wc -l <<<"$top")" = 1 ] || { echo "FAIL tar: expected one top-level directory"; return 2; }
  mkdir -p "$x"
  tar -xzf "$BUNDLE" -C "$x" --no-same-owner --no-same-permissions || { echo "FAIL tar: extract"; return 2; }
  cd "$x/$top" || return 2
  [ -f MANIFEST.sha256 ] || { echo "FAIL manifest: MANIFEST.sha256 missing"; return 2; }
  local listed actual
  listed="$(sed 's/^[0-9a-f]\{64\}  //' MANIFEST.sha256 | sort)"
  actual="$(find . -type f ! -name MANIFEST.sha256 ! -name MANIFEST.sha256.sig | sed 's|^\./||' | sort)"
  if [ "$listed" = "$actual" ]; then echo "PASS manifest: $(wc -l <<<"$actual") files, member list matches"
  else echo "FAIL manifest: member list differs"; diff <(echo "$listed") <(echo "$actual") | sed -n '1,20p'; rc=2; fi
  if sha256sum --quiet -c MANIFEST.sha256 >/dev/null 2>&1; then echo "PASS hashes: all sha256 match"
  else echo "FAIL hashes:"; sha256sum --quiet -c MANIFEST.sha256 2>&1 | sed -n '1,20p'; rc=2; fi
  if [ -n "$SIGNERS" ]; then
    if [ ! -f MANIFEST.sha256.sig ]; then echo "FAIL signature: bundle is not signed"; rc=2
    elif ssh-keygen -Y verify -f "$SIGNERS" -I pft-bundle -n pft-bundle -s MANIFEST.sha256.sig \
         <MANIFEST.sha256 >/dev/null 2>&1; then echo "PASS signature: MANIFEST.sha256 signed by an allowed signer"
    else echo "FAIL signature: does not verify against $SIGNERS"; rc=2; fi
  elif [ -f MANIFEST.sha256.sig ]; then echo "INFO signature: present, not checked (pass --signers)"; fi
  echo "INFO literals: $(cut -f1 "$LITS" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')(values not shown)"
  if python3 -I "$SANITIZE" scan . --literals "$LITS" | sed 's/^/  /'; [ "${PIPESTATUS[0]}" = 0 ]; then
    echo "PASS scan: no seed, token block, token or identity literal"
  else echo "FAIL scan: secret or identity survived"; rc=2; fi
  echo "RESULT: $([ $rc = 0 ] && echo PASS || echo FAIL) $(basename "$BUNDLE")"
  return $rc
}

# ---------- collect ----------
RAW="$WORK/raw"
item() { # NAME CMD... : stdout -> raw/NAME, one status line per item in meta/collect.log
  local name="$1" rc; shift
  mkdir -p "$(dirname "$RAW/$name")"
  if declare -F "$1" >/dev/null; then "$@" >"$RAW/$name" 2>&1; rc=$?   # functions time-limit their own calls
  else timeout 30 "$@" >"$RAW/$name" 2>&1; rc=$?; fi
  printf '%-28s rc=%-3s bytes=%s\n' "$name" "$rc" "$(stat -c %s "$RAW/$name")" >>"$RAW/meta/collect.log"
}
rpc() { timeout 20 docker exec "$CONTAINER" curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
          -d "{\"method\":\"$1\",\"params\":[{}]}" "$RPC_URL" | jq .; }
os_info() {
  echo "collected_utc: $(date -u +%FT%TZ)"
  echo "os: $(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release)"
  echo "kernel: $(uname -srm)"
  echo "uptime: $(uptime -p)"
  echo "loadavg: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "hostname: $(hostname)"
  echo "pft-bundle: $(sha256sum "$0" | cut -c1-12) sanitize.py: $(sha256sum "$SANITIZE" | cut -c1-12)"
}
container_info() {
  timeout 20 docker inspect "$CONTAINER" | jq '.[0] | {Name, Hostname: .Config.Hostname, Image: .Config.Image, ImageId: .Image,
    State: (.State | {Status, Running, StartedAt, OOMKilled, ExitCode, Health: .Health.Status}),
    RestartCount, Host: (.HostConfig | {NetworkMode, RestartPolicy, CapAdd, CapDrop, ReadonlyRootfs, PidsLimit,
    Memory, SecurityOpt, Privileged, PortBindings}), Mounts: [.Mounts[] | {Destination, RW, Type}]}'
}
image_info() {
  local img; img="$(timeout 20 docker inspect -f '{{.Image}}' "$CONTAINER")" || return 1
  timeout 20 docker image inspect "$img" | jq '.[0] | {Id, RepoTags, RepoDigests, Created, Architecture}'
  timeout 20 docker version --format 'docker server: {{.Server.Version}}'
}
units() {
  timeout 20 systemctl list-units 'pft-*' 'postfiat*' --all --no-pager --plain --no-legend || return 1
  echo; timeout 20 systemctl list-timers 'pft-*' 'postfiat*' --all --no-pager --no-legend
}
addons() { local f; for f in /usr/local/bin/pft-* /usr/local/bin/postfiat-* /usr/local/sbin/pft-*; do
  [ -f "$f" ] && printf '%s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "$(basename "$f")"; done; }

collect() {
  [ "$(id -u)" = 0 ] || die "collect must run as root (docker, ufw)" 4
  docker inspect "$CONTAINER" >/dev/null 2>&1 || die "container $CONTAINER not found" 4
  [ -n "$LABEL" ] || LABEL="$CONTAINER"
  [[ "$LABEL" =~ ^[A-Za-z0-9_.-]+$ ]] || die "--label: letters, digits, . _ - only"
  [ -z "$SIGN_KEY" ] || [ -r "$SIGN_KEY" ] || die "--sign-key $SIGN_KEY not readable" 4
  build_literals
  local ts name dir rc
  ts="$(date -u +%Y%m%dT%H%M%SZ)"; name="pft-bundle-$LABEL-$ts"
  mkdir -p "$RAW/meta"
  item meta/os.txt os_info
  item docker/container.json container_info
  item docker/image.txt image_info
  for m in server_info server_state peers validator_list_sites feature; do item "rpc/$m.json" rpc "$m"; done
  item config/postfiatd.cfg docker exec "$CONTAINER" cat /etc/postfiatd/postfiatd.cfg
  item logs/debug.log.tail docker exec "$CONTAINER" tail -n "$LOG_LINES" /var/log/postfiatd/debug.log
  item system/df.txt df -hT -x tmpfs -x devtmpfs -x overlay -x squashfs
  item system/df-inodes.txt df -i -x tmpfs -x devtmpfs -x overlay -x squashfs
  item system/memory.txt free -m
  item system/ufw.txt ufw status verbose
  item system/units.txt units
  item system/addons.txt addons
  if [ -n "$KEEP_RAW" ]; then ( umask 077; mkdir -p "$KEEP_RAW" && cp -a "$RAW/." "$KEEP_RAW/" ); fi
  dir="$WORK/out/$name"
  mkdir -p "$WORK/out"
  python3 -I "$SANITIZE" redact "$RAW" "$dir" --literals "$LITS" >"$WORK/redact.json" || die "sanitizer failed" 2
  if ! python3 -I "$SANITIZE" scan "$dir" --literals "$LITS" >"$WORK/scan.txt"; then
    sed 's/^/  /' "$WORK/scan.txt"
    echo "FAIL: secret or identity survived sanitizing; no bundle written (fail closed)"
    return 2
  fi
  cp "$WORK/redact.json" "$dir/meta/redactions.json"
  ( cd "$dir" && find . -type f ! -name 'MANIFEST.sha256*' | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum >MANIFEST.sha256 )
  if [ -n "$SIGN_KEY" ]; then
    ssh-keygen -Y sign -q -f "$SIGN_KEY" -n pft-bundle "$dir/MANIFEST.sha256" || die "signing failed" 2
  fi
  mkdir -p "$OUT"
  ( umask 077; tar -czf "$OUT/$name.tar.gz" -C "$WORK/out" "$name" ) || die "tar failed" 2
  echo "items: $(wc -l <"$RAW/meta/collect.log") ($(grep -vc 'rc=0 ' "$RAW/meta/collect.log") non-zero rc)"
  sed 's/^/  /' "$RAW/meta/collect.log"
  echo "redactions: $(jq -c .redactions "$WORK/redact.json")"
  echo "scan: 0 hit(s) after sanitizing"
  echo "manifest: $(wc -l <"$dir/MANIFEST.sha256") files$([ -n "$SIGN_KEY" ] && echo ", signed")"
  echo "bundle: $OUT/$name.tar.gz sha256=$(sha256sum "$OUT/$name.tar.gz" | cut -d' ' -f1)"
}

if [ "$MODE" = collect ]; then collect; else verify; fi
