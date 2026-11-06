#!/usr/bin/env bash
# pft-rebuild-drill: prove that a pinned commit of this repo rebuilds the live validator host (node + every add-on in
# rebuild/stack.list) in a fresh, resource-capped Ubuntu 22.04 LXD sandbox, then diff the sandbox against the live
# host's pft-integrity baseline and pft-fleet inventory (REPRODUCED / MISSING / EXTRA / DIFFERENT) and tear it down.
#
# Usage: pft-rebuild-drill stack [--json]                    the declared steps, validated (read-only)
#        sudo pft-rebuild-drill preflight --commit SHA        read-only host checks; exit 0 = a run may start
#        sudo pft-rebuild-drill run --commit SHA --yes [--keep] [--continue] [--json-out FILE]
#        sudo pft-rebuild-drill teardown --yes                remove every sandbox resource (idempotent)
#        sudo pft-rebuild-drill limits --dir RUN_DIR          re-check a run's SANDBOX_LIMIT lines against the live host
#        pft-rebuild-drill diff LIVE_MANIFEST SANDBOX_MANIFEST [--live-fleet J --sandbox-fleet J] [--json]
#
# The sandbox (names from the env below) is an unprivileged LXD container with security.nesting (Docker inside),
# limits.cpu/limits.memory/limits.processes and an LVM loop pool of RB_DISK (RB_POOL_DRIVER), on its own NAT-only IPv4 bridge. Host
# firewall: chain PFT-REBUILD (FORWARD, sandbox bridge only: tcp 80/443/2559/51235 out, replies in, LOG+DROP the
# rest) and PFT-REBUILD-IN (INPUT from the bridge: DHCP + DNS to LXD's dnsmasq only, everything else dropped, so the
# sandbox cannot reach the live node's admin ports or sshd). Nothing of the live node is shared: no volume, no port,
# no key, no ntfy topic (preflight refuses each, exit 4). The backup it restores is the newest nightly pft-backup
# archive (secret-free by default), with sentry peering stripped and the manifest rebuilt, so the sandbox node
# never peers with the live sentry.
#
# Exit codes: 0 run done and every MISSING/DIFFERENT item excepted, 1 open diff items, 2 a step or check failed,
#   3 usage/config error, 4 refused (preflight), 5 teardown incomplete.
# Env: RB_TEST=1 (offline tests: stubs via RB_LXC/RB_IPT, no root check)  RB_NAME (pftrb-sbx) RB_NET (pftrb0) RB_POOL (pftrb) RB_SUBNET (10.209.77.1/24) RB_CPU (2) RB_MEM (3GiB)
#      RB_VOLS (docker:/var/lib/docker:4GiB containerd:/var/lib/containerd:16GiB = NAME:PATH:SIZE custom volumes)
#      RB_DISK (25GiB) RB_PROCS (6000) RB_IMAGE (ubuntu:22.04) RB_FULL_TIMEOUT (3600) RB_STATE (/var/lib/pft-rebuild)
#      RB_REPO_URL (this repo on GitHub) BACKUP_DIR (/var/backups/postfiat) CONTAINER (postfiatd)
#      NTFY (https://ntfy.sh) RB_TOPIC_ENVS (env files holding the operator's ntfy topics; read, never printed)
#      RB_STACK (rebuild/stack.list; another file = a dev probe, printed in the run header)
#      RB_AUDIT_LOGS (/var/log/audit/audit.log*: host audit files for the apparmor-nested check)
#      RB_AA_LIVE (/etc/apparmor.d/pft-postfiatd) RB_SC_LIVE (/etc/pft-seccomp/pft-postfiatd.json): live profiles
set -uo pipefail
export TZ=UTC LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/rebuild_lib.py"; STACK="${RB_STACK:-$HERE/stack.list}"; EXC="$HERE/exceptions.list"
SBX="${RB_NAME:-pftrb-sbx}"; NET="${RB_NET:-pftrb0}"; POOL="${RB_POOL:-pftrb}"; SUBNET="${RB_SUBNET:-10.209.77.1/24}"
POOL_DRIVER="${RB_POOL_DRIVER:-lvm}"; VOLS="${RB_VOLS:-docker:/var/lib/docker:4GiB containerd:/var/lib/containerd:16GiB}"; CPU="${RB_CPU:-2}"; MEM="${RB_MEM:-3GiB}"; DISK="${RB_DISK:-25GiB}"; PROCS="${RB_PROCS:-6000}"
IMAGE="${RB_IMAGE:-ubuntu:22.04}"; FULL_TIMEOUT="${RB_FULL_TIMEOUT:-3600}"; STATE="${RB_STATE:-/var/lib/pft-rebuild}"
REPO_URL="${RB_REPO_URL:-https://github.com/darkmatter-sudo/postfiat-validator-installer.git}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/postfiat}"; CONTAINER="${CONTAINER:-postfiatd}"; NTFY="${NTFY:-https://ntfy.sh}"
TOPIC_ENVS="${RB_TOPIC_ENVS:-/etc/pft-integrity.env /etc/pft-maint/ntfy.env /etc/pft-watchdog/ntfy.env /etc/postfiat-monitor.env /opt/pft-agent/config.env}"
CHAIN=PFT-REBUILD; CHAIN_IN=PFT-REBUILD-IN; LIVE_PORTS="2559 5005 51235"
AUDIT_LOGS="${RB_AUDIT_LOGS:-/var/log/audit/audit.log*}"
AA_LIVE="${RB_AA_LIVE:-/etc/apparmor.d/pft-postfiatd}"; SC_LIVE="${RB_SC_LIVE:-/etc/pft-seccomp/pft-postfiatd.json}"
LXC="${RB_LXC:-lxc}"; IPT="${RB_IPT:-iptables}"; NFT="${RB_NFT:-nft}"; DOCKER="${RB_DOCKER:-docker}"

usage() { sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 3; }
ts() { date -u +%FT%TZ; }
log() { echo "[$(ts)] $*"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
to_bytes() { numfmt --from=iec-i "${1%B}" 2>/dev/null; } # 3GiB / 25GiB -> bytes; empty on a bad value
need_root() { [ "${RB_TEST:-0}" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 3; }; }
sx() { "$LXC" exec "$SBX" --cwd /root/pfvi --env PATH=/root/pfvi/rebuild/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin --env RB_BACKUP="${SBX_BACKUP:-}" --env RB_FULL_TIMEOUT="$FULL_TIMEOUT" --env DEBIAN_FRONTEND=noninteractive -- "$@" </dev/null; } # stdin: run 01 lost the step loop to lxc exec

live_state() { "$DOCKER" exec "$CONTAINER" curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }
sbx_state() { sx docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }

# Operator topics: read from env files, kept in a 0600 file, never printed.
read_topics() { # OUTFILE
  for f in $TOPIC_ENVS; do [ -r "$f" ] && sed -nE 's/^(NTFY_TOPIC|TOPIC)=//p; s|^NTFY_URL=.*/||p' "$f"; done \
    | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$1"
}
topic_msgs_since() { # TOPICFILE EPOCH -> total message count (-1 if a topic could not be read)
  local n=0 t out
  while read -r t; do
    out="$(curl -s --max-time 20 "$NTFY/$t/json?poll=1&since=$2")" || { echo -1; return; }
    n=$((n + $(printf '%s\n' "$out" | jq -c 'select(.event == "message")' 2>/dev/null | wc -l)))
  done < "$1"
  echo "$n"
}

# Host-state snapshot for the teardown proof: everything the drill creates must be gone afterwards.
host_snapshot() {
  "$LXC" list --format csv -c n 2>/dev/null | sed 's/^/instance /'
  "$LXC" network list --format csv 2>/dev/null | awk -F, '$3 == "YES" {print "network " $1}'
  "$LXC" storage list --format csv 2>/dev/null | cut -d, -f1 | sed 's/^/pool /'
  "$LXC" image list --format csv -c f 2>/dev/null | sed 's/^/image /'
  "$IPT" -S 2>/dev/null | sed 's/^/ipt filter /'
  "$IPT" -t nat -S 2>/dev/null | sed 's/^/ipt nat /'
  nft list tables 2>/dev/null | sed 's/^/nft /'
  ip -o link show 2>/dev/null | awk -F': ' '{print "link " $2}' | sed 's/@.*//' | grep -v '^link veth'
  losetup -a 2>/dev/null | sed -E 's/^([^:]+):.*\((.*)\)$/loop \2/'
  ss -Hltn 2>/dev/null | awk '{print "listen " $4}' | sort -u
  find /var/snap/lxd/common/lxd/disks /var/snap/lxd/common/lxd/storage-pools -mindepth 1 -maxdepth 1 -printf 'lxdfs %p\n' 2>/dev/null
}

cmd_teardown() {
  log "teardown: instance $SBX, network $NET, pool $POOL, image cache, chains $CHAIN/$CHAIN_IN"
  if "$LXC" info "$SBX" >/dev/null 2>&1; then "$LXC" delete --force "$SBX" && echo "  instance deleted"; fi
  if [ -s "$STATE/image.fp" ]; then
    "$LXC" image delete "$(cat "$STATE/image.fp")" 2>/dev/null && echo "  cached image deleted"; rm -f "$STATE/image.fp"
  fi
  if "$LXC" network show "$NET" >/dev/null 2>&1; then "$LXC" network delete "$NET" && echo "  network deleted"; fi
  local v vn
  for v in $VOLS; do # custom volumes outlive the instance and block the pool delete
    vn="rb-${v%%:*}"
    if "$LXC" storage volume show "$POOL" "$vn" >/dev/null 2>&1; then
      "$LXC" storage volume delete "$POOL" "$vn" && echo "  volume $vn deleted"
    fi
  done
  if "$LXC" storage show "$POOL" >/dev/null 2>&1; then "$LXC" storage delete "$POOL" && echo "  pool deleted"; fi
  for spec in "FORWARD -i $NET -j $CHAIN" "FORWARD -o $NET -j $CHAIN" "INPUT -i $NET -j $CHAIN_IN"; do
    # shellcheck disable=SC2086
    while "$IPT" -C $spec >/dev/null 2>&1; do "$IPT" -D $spec && echo "  removed jump: $spec"; done
  done
  for c in "$CHAIN" "$CHAIN_IN"; do
    if "$IPT" -S "$c" >/dev/null 2>&1; then "$IPT" -F "$c" && "$IPT" -X "$c" && echo "  removed chain $c"; fi
  done
  # LXD creates `table inet lxd` with its first managed network and leaves it (empty) behind (run 01); delete it
  # only if this host had none before the run (marker written at setup).
  if [ -f "$STATE/nft-lxd.created" ] && "$NFT" list table inet lxd >/dev/null 2>&1; then
    if "$NFT" list table inet lxd | grep -q 'chain '; then echo "  table inet lxd still has chains - left alone"
    else "$NFT" delete table inet lxd && rm -f "$STATE/nft-lxd.created" && echo "  removed empty nft table inet lxd"; fi
  fi
  local left=()
  "$LXC" info "$SBX" >/dev/null 2>&1 && left+=("instance $SBX")
  "$LXC" network show "$NET" >/dev/null 2>&1 && left+=("network $NET")
  for v in $VOLS; do "$LXC" storage volume show "$POOL" "rb-${v%%:*}" >/dev/null 2>&1 && left+=("volume rb-${v%%:*}"); done
  "$LXC" storage show "$POOL" >/dev/null 2>&1 && left+=("pool $POOL")
  "$IPT" -S "$CHAIN" >/dev/null 2>&1 && left+=("chain $CHAIN")
  "$IPT" -S "$CHAIN_IN" >/dev/null 2>&1 && left+=("chain $CHAIN_IN")
  [ -f "$STATE/nft-lxd.created" ] && "$NFT" list table inet lxd >/dev/null 2>&1 && left+=("nft table inet lxd")
  if [ "${#left[@]}" -gt 0 ]; then echo "  teardown INCOMPLETE: ${left[*]}"; return 1; fi
  echo "  teardown complete: no sandbox resource left"
}

fw_setup() {
  "$IPT" -N "$CHAIN" && "$IPT" -N "$CHAIN_IN" || return 1
  "$IPT" -A "$CHAIN" -o "$NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  "$IPT" -A "$CHAIN" -i "$NET" ! -o "$NET" -p tcp -m multiport --dports 80,443,2559,51235 -j ACCEPT
  "$IPT" -A "$CHAIN" -i "$NET" -m limit --limit 6/min -j LOG --log-prefix "pft-rebuild-drop: "
  "$IPT" -A "$CHAIN" -j DROP
  "$IPT" -A "$CHAIN_IN" -p udp --dport 67 -j ACCEPT
  "$IPT" -A "$CHAIN_IN" -p udp --dport 53 -j ACCEPT
  "$IPT" -A "$CHAIN_IN" -p tcp --dport 53 -j ACCEPT
  "$IPT" -A "$CHAIN_IN" -j DROP
  "$IPT" -I FORWARD 1 -i "$NET" -j "$CHAIN" && "$IPT" -I FORWARD 1 -o "$NET" -j "$CHAIN" \
    && "$IPT" -I INPUT 1 -i "$NET" -j "$CHAIN_IN"
}

newest_backup() { find "$BACKUP_DIR" -maxdepth 1 -name 'pft-backup-*.tar.gz' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-; }

# Sanitize the newest nightly archive: refuse key material, strip sentry peering, neutralise HOSTNAME, rebuild the
# manifest exactly like pft-backup.sh. ARCHIVE OUTDIR -> prints the new archive path.
sanitize_backup() {
  local src="$1" out="$2" w top cfg env
  w="$(mktemp -d)"; tar -C "$w" -xzf "$src" || { rm -rf "$w"; return 1; }
  top="$(find "$w" -mindepth 1 -maxdepth 1 -type d | head -1)"
  cfg="$top/files/etc/postfiatd/postfiatd.cfg"
  [ -f "$cfg" ] || { echo "  archive has no postfiatd.cfg" >&2; rm -rf "$w"; return 1; }
  if grep -qE '^\[(validator_token|validation_seed|node_seed)\]' "$cfg"; then
    echo "  archive carries key material (made with --include-secrets?) - refusing" >&2; rm -rf "$w"; return 4
  fi
  awk '/^\[/{skip = ($0 ~ /^\[(ips_fixed|peer_private|cluster_nodes)\]/)} !skip' "$cfg" > "$cfg.new" && mv "$cfg.new" "$cfg"
  env="$(find "$top/files" -path '*/postfiatd/.env' | head -1)"
  [ -n "$env" ] && sed -i "s/^HOSTNAME=.*/HOSTNAME=$SBX/" "$env"
  rm -f "$top/MANIFEST.sha256"
  (cd "$top" && find . -type f -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum) > "$w/MANIFEST.sha256"
  mv "$w/MANIFEST.sha256" "$top/MANIFEST.sha256"
  mkdir -p "$out"; tar -C "$w" -czf "$out/$(basename "$src")" "$(basename "$top")"
  (cd "$out" && sha256sum "$(basename "$src")" > "$(basename "$src").sha256")
  rm -rf "$w"; echo "$out/$(basename "$src")"
}

cmd_preflight() { # host-side, read-only
  local commit="$1" rc=0 s
  log "preflight (read-only), commit $commit"
  command -v "$LXC" >/dev/null && "$LXC" info >/dev/null 2>&1; check "LXD available" "$?"
  for c in jq curl python3 "$IPT" nft ss git; do command -v "$c" >/dev/null || { check "tool $c present" 1; rc=1; }; done
  s="$(live_state)"; case "$s" in full|proposing) check "live node $CONTAINER server_state $s" 0 ;; *) check "live node $CONTAINER server_state $s" 1 ;; esac
  if command -v pft-integrity >/dev/null; then pft-integrity verify >/dev/null 2>&1; check "live pft-integrity verify PASS" "$?"; fi
  for r in "instance:$SBX:info" "network:$NET:network show" "pool:$POOL:storage show"; do
    IFS=: read -r kind nm sub <<<"$r"
    # shellcheck disable=SC2086
    if "$LXC" $sub "$nm" >/dev/null 2>&1; then check "no leftover $kind $nm (run teardown first)" 1; else check "no leftover $kind $nm" 0; fi
  done
  if "$IPT" -S "$CHAIN" >/dev/null 2>&1; then check "no leftover chain $CHAIN" 1; else check "no leftover chain $CHAIN" 0; fi
  if ip -4 route | grep -qF "${SUBNET%.*}."; then check "subnet $SUBNET unused on the host" 1; else check "subnet $SUBNET unused on the host" 0; fi
  local avail_kb need_kb
  local mem_b disk_b; mem_b="$(to_bytes "$MEM")"; disk_b="$(to_bytes "$DISK")"
  [ -n "$mem_b" ] && [ -n "$disk_b" ]; check "RB_MEM=$MEM and RB_DISK=$DISK parse as sizes" "$?"
  avail_kb="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"; need_kb=$(( ${mem_b:-0} / 1024 + 1048576 ))
  [ -n "$mem_b" ] && [ "$avail_kb" -ge "$need_kb" ]; check "MemAvailable $((avail_kb / 1024)) MiB >= sandbox cap + 1 GiB" "$?"
  local free_b need_b
  free_b="$(df -B1 --output=avail /var/snap 2>/dev/null | tail -1 | tr -d ' ')"; need_b=$(( ${disk_b:-0} + 10 * 1024 ** 3 ))
  [ -n "$disk_b" ] && [ "${free_b:-0}" -ge "$need_b" ]; check "free disk $((free_b / 1024 ** 3)) GiB >= RB_DISK + 10 GiB" "$?"
  [ -n "$(newest_backup)" ]; check "nightly backup archive present in $BACKUP_DIR" "$?"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; check "commit is a full 40-hex SHA" "$?"
  if git -C "$HERE" rev-parse HEAD >/dev/null 2>&1; then # the host-side tool must run the same bytes as the sandbox
    [ "$(git -C "$HERE" rev-parse HEAD)" = "$commit" ] && [ -z "$(git -C "$HERE" status --porcelain -- . 2>/dev/null)" ]
    check "this checkout is clean at $commit" "$?"
  fi
  local code; code="$(curl -s -o /dev/null -w '%{http_code}' "${REPO_URL%.git}/commit/$commit")"
  [ "$code" = 200 ]; check "commit public on GitHub" "$?" "HTTP $code"
  python3 "$LIB" stack "$STACK" >/dev/null; check "stack.list valid" "$?"
  local tf; tf="$(mktemp)"; read_topics "$tf"; [ -s "$tf" ]; check "operator ntfy topics found ($(wc -l < "$tf"), not printed)" "$?"; rm -f "$tf"
  [ "$FAILS" = 0 ] && [ "$rc" = 0 ]
}

# A SANDBOX_LIMIT is only accepted for a hardening step if the live host shows that the same committed profile
# works there: the live node runs it from the same bytes, and (apparmor-nested) every DENIED record for it in the
# step's time span is in the sandbox's own AppArmor namespace on the HOST audit log, none on the live node.
cmd_limits() { # RUN_DIR (steps/NNN-step.log + NNN-step.start)
  local d="$1" f st line n=0 since lim
  for f in "$d"/steps/*.log; do
    [ -f "$f" ] || continue
    st="$(basename "$f" .log)"
    while IFS= read -r line; do
      n=$((n + 1)); echo "  ${st#*-}: $line"; lim="$(sed -E 's/^SANDBOX_LIMIT ([a-z-]+):.*/\1/' <<<"$line")"
      case "$lim" in
        apparmor-nested)
          since="$(cat "$d/steps/$st.start" 2>/dev/null)"
          [[ "$since" =~ ^[0-9]+$ ]]; check "apparmor-nested: step start time recorded" "$?" "${since:-none}"
          # shellcheck disable=SC2086 # AUDIT_LOGS is a glob list
          cat $AUDIT_LOGS 2>/dev/null </dev/null > "$d/aa-audit.txt"
          python3 "$LIB" aa-nested "$d/aa-audit.txt" --sandbox "$SBX" --profile pft-postfiatd --since "${since:-0}" </dev/null | sed 's/^/    /'
          check "apparmor-nested: DENIED only in the sandbox namespace (host audit log)" "${PIPESTATUS[0]}"
          rm -f "$d/aa-audit.txt"
          cmp -s "$AA_LIVE" "$HERE/../apparmor/profile/pft-postfiatd"; check "apparmor-nested: live $AA_LIVE = committed profile bytes" "$?"
          [ "$("$DOCKER" inspect -f '{{.AppArmorProfile}}' "$CONTAINER" 2>/dev/null)" = pft-postfiatd ]
          check "apparmor-nested: live $CONTAINER runs pft-postfiatd" "$?" ;;
        kernel-audit)
          cmp -s "$SC_LIVE" "$HERE/../seccomp/profile/pft-postfiatd.json"; check "kernel-audit: live $SC_LIVE = committed profile bytes" "$?"
          "$DOCKER" inspect -f '{{json .HostConfig.SecurityOpt}}' "$CONTAINER" 2>/dev/null | grep -q '"seccomp={'
          check "kernel-audit: live $CONTAINER runs a custom seccomp profile" "$?" ;;
        kernel-log) : ;; # nothing to prove on the live host: the timer state is a documented exception
        *) check "known limit name in: $line" 1 ;;
      esac
    done < <(grep -E '^SANDBOX_LIMIT ' "$f")
  done
  echo "  $n SANDBOX_LIMIT line(s)"
}

cmd_run() {
  local commit="$1" keep="$2" cont="$3" jsonout="$4" RUNID W t_start
  need_root
  RUNID="$(date -u +%Y%m%dT%H%M%SZ)"; W="$STATE/$RUNID"; mkdir -p "$W/steps"; chmod 700 "$STATE" "$W"
  t_start="$(date -u +%s)"
  echo "OS: $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"') | kernel $(uname -r) | lxd $("$LXC" version 2>/dev/null | awk '/Server/ {print $3}')"
  echo "run $RUNID commit $commit sandbox $SBX cpu=$CPU mem=$MEM disk=$DISK procs=$PROCS image=$IMAGE"
  echo "stack: ${STACK#"$HERE/"} sha256 $(sha256sum < "$STACK" | cut -c1-64)"
  echo; echo "== 0. preflight"
  cmd_preflight "$commit" || { echo "preflight failed - nothing changed"; exit 4; }
  read_topics "$W/topics"; chmod 600 "$W/topics"
  host_snapshot > "$W/host-before.txt"
  cp /var/lib/pft-integrity/manifest.tsv "$W/live-manifest.tsv"
  command -v pft-fleet >/dev/null && pft-fleet inventory --json --hosts validator > "$W/live-fleet.json" 2>/dev/null
  echo "  host snapshot: $(wc -l < "$W/host-before.txt") items; live baseline: $(grep -vc '^#' "$W/live-manifest.tsv") rows"

  echo; echo "== 1. sandbox infrastructure"
  trap '[ "${KEEP:-0}" = 1 ] || cmd_teardown' EXIT; KEEP="$keep"
  "$NFT" list table inet lxd >/dev/null 2>&1 || : > "$STATE/nft-lxd.created"
  # lvm (ext4 on a thin LV in a loop file): Docker inside the sandbox cannot mount overlayfs on btrfs in an
  # unprivileged container (run 02: "failed to extract layer ... to overlayfs"); RB_DISK caps the loop file.
  "$LXC" storage create "$POOL" "$POOL_DRIVER" size="$DISK" >/dev/null; check "pool $POOL ($POOL_DRIVER loop, size $DISK)" "$?"
  "$LXC" network create "$NET" ipv4.address="$SUBNET" ipv4.nat=true ipv6.address=none >/dev/null; check "bridge $NET NAT-only IPv4 $SUBNET" "$?"
  fw_setup; check "firewall chains $CHAIN (forward) / $CHAIN_IN (input) for $NET only" "$?"
  "$LXC" init "$IMAGE" "$SBX" -s "$POOL" -n "$NET" -c security.nesting=true -c security.syscalls.intercept.mknod=true \
    -c security.syscalls.intercept.setxattr=true -c limits.cpu="$CPU" -c limits.memory="$MEM" -c limits.processes="$PROCS" >/dev/null
  check "instance $SBX created (not started)" "$?"
  # Docker's data dirs on their own custom volumes of the sandbox pool: the LVM rootfs is an IDMAPPED mount, and
  # overlayfs (Docker 29's containerd snapshotter, also overlay2) cannot use idmapped lower dirs on 5.15 (run 08
  # probe: "failed to mount ... overlay ... invalid argument"). Custom volumes are uid-shifted, not idmapped.
  local v vn vp vs
  for v in $VOLS; do
    IFS=: read -r vn vp vs <<<"$v"
    "$LXC" storage volume create "$POOL" "rb-$vn" size="$vs" >/dev/null \
      && "$LXC" config device add "$SBX" "rb-$vn" disk pool="$POOL" source="rb-$vn" path="$vp" >/dev/null
    check "custom volume rb-$vn ($vs) on $POOL at $vp" "$?"
  done
  # only an image this run downloaded is deleted at teardown (a pre-existing cache is left alone)
  comm -13 <(grep '^image ' "$W/host-before.txt" | cut -d' ' -f2 | sort) <("$LXC" image list --format csv -c f | sort) \
    | head -1 > "$STATE/image.fp"
  pft-integrity verify >/dev/null 2>&1; check "live pft-integrity verify still PASS with the sandbox infrastructure up" "$?"
  [ "$FAILS" = 0 ] || { echo "setup failed"; exit 2; }

  echo; echo "== 2. sandbox isolation preflight"
  local BK SAN
  BK="$(newest_backup)"; SAN="$(sanitize_backup "$BK" "$W/backup")"; check "backup sanitized (keys refused, peering stripped)" "$?"
  [ -n "$SAN" ] || exit 2
  ( umask 077; printf 'NTFY_URL=http://127.0.0.1:9/rebuild-blackhole\nNTFY_TOPIC=rebuild-blackhole\n' > "$W/ntfy.env" )
  tar -xzOf "$SAN" --wildcards '*/postfiatd.cfg' > "$W/sandbox-postfiatd.cfg"
  "$LXC" query "/1.0/instances/$SBX?recursion=1" > "$W/instance.json"; "$LXC" query "/1.0/networks/$NET" > "$W/network.json"
  local targs=(); while read -r t; do targs+=(--live-topic "$t"); done < "$W/topics"
  python3 "$LIB" preflight "$W/instance.json" "$W/network.json" "${targs[@]}" \
    --sandbox-file "$W/ntfy.env" --sandbox-file "$W/sandbox-postfiatd.cfg" | sed 's/^/  /'
  [ "${PIPESTATUS[0]}" = 0 ] || { echo "isolation preflight refused - tearing down"; exit 4; }
  for p in $LIVE_PORTS; do
    grep -q "listen:.*:$p$" <<<"$("$LXC" config device show "$SBX")" && { check "no host listener for live port $p" 1; exit 4; }
  done
  check "no sandbox device exposes $LIVE_PORTS" 0

  echo; echo "== 3. start + network"
  "$LXC" start "$SBX"; check "sandbox started" "$?"
  local i ok=1
  for i in $(seq 1 60); do sx getent hosts github.com >/dev/null 2>&1 && { ok=0; break; }; sleep 3; done
  check "sandbox DNS + IPv4 up" "$ok" "$((i * 3)) s"
  sx cloud-init status --wait >/dev/null 2>&1; check "cloud-init finished" "$?"
  sx bash -c 'curl -s -m 5 -o /dev/null http://'"${SUBNET%/*}"':5005 || exit 0; exit 1' ; check "sandbox cannot reach host admin port 5005 via the bridge" "$?"
  sx bash -c 'timeout 5 bash -c "</dev/tcp/'"${SUBNET%/*}"'/22" 2>/dev/null && exit 1 || exit 0'; check "sandbox cannot reach host sshd via the bridge" "$?"

  echo; echo "== 4. checkout pinned commit inside the sandbox"
  sx bash -c "apt-get -qq update && apt-get -qq install -y git jq >/dev/null" ; check "git + jq installed" "$?"
  "$LXC" exec "$SBX" -- bash -c "git clone -q '$REPO_URL' /root/pfvi && git -C /root/pfvi checkout -q '$commit'"
  local head; head="$(sx git rev-parse HEAD 2>/dev/null)"; [ "$head" = "$commit" ]; check "sandbox HEAD = $commit" "$?"
  [ "$head" = "$commit" ] || exit 2
  "$LXC" exec "$SBX" -- mkdir -p /root/rb/backup /etc/pft-rebuild
  "$LXC" file push --quiet "$SAN" "$SAN.sha256" "$SBX/root/rb/backup/" \
    && "$LXC" file push --quiet "$W/ntfy.env" "$SBX/etc/pft-rebuild/ntfy.env" --mode 0600
  check "sanitized backup + blackhole ntfy.env pushed" "$?"
  SBX_BACKUP="/root/rb/backup/$(basename "$SAN")"

  echo; echo "== 5. install steps (rebuild/stack.list @ $commit)"
  printf 'order\tstep\trc\tseconds\n' > "$W/timings.tsv"
  local order step cmd b64 t0 dt src log_ ttf=""
  while IFS=$'\t' read -r order step b64; do
    cmd="$(printf '%s' "$b64" | base64 -d)"
    log_="$W/steps/$(printf '%03d' "$order")-$step.log"; t0="$(date -u +%s)"; echo "$t0" > "${log_%.log}.start"
    sx bash -c "$cmd" > "$log_" 2>&1; src=$?; dt=$(( $(date -u +%s) - t0 ))
    printf '%s\t%s\t%s\t%s\n' "$order" "$step" "$src" "$dt" >> "$W/timings.tsv"
    printf 'STEP %3s %-13s rc=%-3s %5ss  $ %s\n' "$order" "$step" "$src" "$dt" "$cmd"
    [ "$step" = restore ] && ttf="$(sed -n 's/^TIME_TO_FULL //p' "$log_")"
    if [ "$src" != 0 ]; then
      FAILS=$((FAILS + 1)); echo "  --- last 25 lines of $step ---"; tail -25 "$log_" | sed 's/^/  | /'
      [ "$cont" = 1 ] || break
    fi
  done < <(python3 "$LIB" stack "$STACK" --rows)
  echo "TIME_TO_FULL ${ttf:-n/a} s (restore step start -> server_state full, cap $FULL_TIMEOUT s)"
  echo "sandbox server_state now: $(sbx_state)"
  echo; echo "== 5b. sandbox limits vs the live host"
  cmd_limits "$W"

  echo; echo "== 6. diff sandbox vs live"
  # Re-collect the sandbox manifest from its final state: the last accept can predate later steps, and run 28's
  # rolled-back egress jump hid behind the manifest that `rebaseline` wrote before aaapply.
  sx pft-integrity baseline >/dev/null 2>&1
  check "sandbox manifest re-collected after the last step (pft-integrity baseline in the sandbox)" "$?"
  "$LXC" file pull "$SBX/var/lib/pft-integrity/manifest.tsv" "$W/sandbox-manifest.tsv" 2>/dev/null
  local fargs=()
  if [ -s "$W/live-fleet.json" ] && sx pft-fleet inventory --json --hosts validator > "$W/sandbox-fleet.json" 2>/dev/null \
     && jq -e .addons "$W/sandbox-fleet.json" >/dev/null 2>&1; then
    fargs=(--live-fleet "$W/live-fleet.json" --sandbox-fleet "$W/sandbox-fleet.json")
  else echo "  sandbox pft-fleet inventory unavailable: diff uses pft-integrity items only"; fi
  local drc=3
  if [ -s "$W/sandbox-manifest.tsv" ]; then
    python3 "$LIB" diff "$W/live-manifest.tsv" "$W/sandbox-manifest.tsv" "${fargs[@]}" --exceptions "$EXC" --json > "$W/diff.json"
    python3 "$LIB" diff "$W/live-manifest.tsv" "$W/sandbox-manifest.tsv" "${fargs[@]}" --exceptions "$EXC"; drc=$?
    [ -n "$jsonout" ] && cp "$W/diff.json" "$jsonout"
  else echo "  no sandbox baseline (baseline step not reached)"; FAILS=$((FAILS + 1)); fi

  echo; echo "== 7. teardown"
  if [ "$keep" = 1 ]; then echo "  --keep: sandbox left running for inspection"; else
    cmd_teardown; check "teardown removed every sandbox resource" "$?"; trap - EXIT
    host_snapshot > "$W/host-after.txt"
    python3 "$LIB" teardown "$W/host-before.txt" "$W/host-after.txt" | sed 's/^/  /'
    [ "${PIPESTATUS[0]}" = 0 ]; check "teardown complete (host snapshot identical)" "$?"
  fi

  echo; echo "== 8. live host after"
  local s; s="$(live_state)"; case "$s" in full|proposing) check "live server_state $s" 0 ;; *) check "live server_state $s" 1 ;; esac
  pft-integrity verify | tail -1 | sed 's/^/  /'; check "live pft-integrity verify PASS" "${PIPESTATUS[0]}"
  local n; n="$(topic_msgs_since "$W/topics" "$t_start")"; [ "$n" = 0 ]; check "operator ntfy topics: $n messages since run start" "$?"
  echo; echo "per-step timings: $W/timings.tsv; per-step logs: $W/steps/"
  if [ "$FAILS" != 0 ]; then echo "RESULT: FAIL ($FAILS checks/steps failed, diff rc $drc)"; exit 2; fi
  echo "RESULT: PASS (diff rc $drc)"; exit "$drc"
}

[ $# -ge 1 ] || usage
sub="$1"; shift
commit=""; yes=0; keep=0; cont=0; jsonout=""; json=(); rdir=""
case "$sub" in
  stack) [ "${1:-}" = --json ] && json=(--json); exec python3 "$LIB" stack "$STACK" "${json[@]}" ;;
  diff) exec python3 "$LIB" diff "$@" ;;
esac
while [ $# -gt 0 ]; do
  case "$1" in
    --commit) commit="${2:?}"; shift ;;
    --yes) yes=1 ;;
    --keep) keep=1 ;;
    --continue) cont=1 ;;
    --json-out) jsonout="${2:?}"; shift ;;
    --dir) rdir="${2:?}"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option $1" >&2; exit 3 ;;
  esac
  shift
done
case "$sub" in
  preflight) need_root; [ -n "$commit" ] || usage; cmd_preflight "$commit"; r=$?
    echo "PREFLIGHT: $([ "$r" = 0 ] && echo READY || echo NOT READY) ($FAILS failed)"; exit $((r == 0 ? 0 : 4)) ;;
  run) if [ -z "$commit" ] || [ "$yes" != 1 ]; then echo "run needs --commit SHA --yes" >&2; exit 3; fi
    cmd_run "$commit" "$keep" "$cont" "$jsonout" ;;
  limits) need_root; if [ -z "$rdir" ] || [ ! -d "$rdir/steps" ]; then usage; fi; cmd_limits "$rdir"
    [ "$FAILS" = 0 ]; exit $(( $? == 0 ? 0 : 2 )) ;;
  teardown) need_root; [ "$yes" = 1 ] || { echo "teardown needs --yes" >&2; exit 3; }
    cmd_teardown; exit $(( $? == 0 ? 0 : 5 )) ;;
  -h|--help|help) usage ;;
  *) usage ;;
esac
