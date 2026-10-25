#!/usr/bin/env bash
# pft-egress: default-deny OUTBOUND policy for a bridge-networked postfiatd container. New connections the
# container opens are allowed only to its DNS resolvers (53), to peer ports (2559 + ports from [ips]/[ips_fixed]
# + ports of outbound peer connections seen now) and to the validator-list site ports (443); everything else is
# LOGged (rate-limited) and DROPped. Replies to inbound peers are untouched (conntrack ESTABLISHED,RELATED).
# No container or node restart. Run it on a SENTRY first.
#
# Usage: pft-egress plan     [--container NAME] [--json]
#        sudo pft-egress apply --yes [--container NAME] [--dry-run] [--deadman MIN] [--foreground]
#        sudo pft-egress check [--container NAME]
#        sudo pft-egress rollback --yes [--container NAME]
#        sudo pft-egress watch --container NAME        (the dead-man; apply starts it as a transient unit)
#        sudo pft-egress reapply --container NAME      (boot/timer persistence: re-render with the current IP)
#        sudo pft-egress probe --container NAME --target HOST:PORT [--target ...]
#
#  plan      read-only. Inspects the live container (network mode, bridge, IP, IPv6, /etc/resolv.conf,
#            postfiatd.cfg [ips]/[ips_fixed], validators.txt [validator_list_sites], `ss` established outbound
#            connections in its netns) and prints the allowlist and the exact iptables-restore input.
#  apply     --dry-run prints the rendered rules and a diff against the live chain and changes nothing.
#            Otherwise refuses (exit 4) unless --yes, a pft-maint window is active with DEADMAN*60 + MAINT_MARGIN
#            seconds left and no data-collection lock, the node is full and peers >= MIN_PEERS. Then loads the
#            PFT-EGRESS chain with `iptables-restore --noflush` (atomic), inserts one jump at DOCKER-USER position 1
#            (once), saves state, installs pft-egress-reapply@NAME.{service,timer} (boot + every 5 min, no-op when
#            nothing drifted) and starts the dead-man: for DEADMAN minutes (10) it polls server_info every POLL_SEC;
#            BAD_POLLS (3) consecutive polls with server_state not full or peers < baseline-PEER_SLACK -> rollback.
#            Re-running apply with an unchanged plan changes nothing ("no change").
#  check     chain present and equal to the applied snapshot, jump at DOCKER-USER 1 for the current IP, timer
#            enabled, DROP counters, recent drop log lines, server_state and peers. Exit 0 = PASS.
#  rollback  removes every jump and the chain, disables the units, stops a running dead-man, verifies removal.
#  probe     one TCP connect per target from inside the container (docker exec, bash /dev/tcp, 5 s timeout).
#
# Exit codes: 0 ok/PASS, 1 check failed / dead-man rolled back, 3 usage/config error, 4 refused, 5 rollback failed.
# Env: CONTAINER (postfiatd)  CHAIN (PFT-EGRESS)  PEER_PORT (2559)  EXTRA_TCP_PORTS ("")  DEADMAN_MIN (10)
#      POLL_SEC (30)  BAD_POLLS (3)  PEER_SLACK (1)  MIN_PEERS (3)  MAINT_MARGIN (300)  LOG_LIMIT (6/min)
#      CFG_DIR (/etc/postfiatd in the container)  STATE_DIR (/var/lib/pft-egress)  SBIN (/usr/local/sbin)
#      UNIT_DIR (/etc/systemd/system)
#      Test hooks: PFT_EGRESS_TEST=1 (no root, no units started)  PFT_EGRESS_NOW_FILE (fake clock)
#      PFT_EGRESS_IPT / _IPT_RESTORE / _DOCKER / _MAINT / _SYSTEMCTL / _SYSTEMD_RUN / _JOURNAL (commands)
#      PFT_EGRESS_RPC_CMD (prints server_info .result)  PFT_EGRESS_SS_CMD (prints `ss -Htn state established`)

# jq programs are single-quoted on purpose. "A && B || die" is intended: die always exits.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
umask 022

CONTAINER="${CONTAINER:-postfiatd}"
CHAIN="${CHAIN:-PFT-EGRESS}"
PEER_PORT="${PEER_PORT:-2559}"
EXTRA_TCP_PORTS="${EXTRA_TCP_PORTS:-}"
DEADMAN_MIN="${DEADMAN_MIN:-10}"
POLL_SEC="${POLL_SEC:-30}"
BAD_POLLS="${BAD_POLLS:-3}"
PEER_SLACK="${PEER_SLACK:-1}"
MIN_PEERS="${MIN_PEERS:-3}"
MAINT_MARGIN="${MAINT_MARGIN:-300}"
LOG_LIMIT="${LOG_LIMIT:-6/min}"
LOG_PREFIX="pft-egress-drop: "
CFG_DIR="${CFG_DIR:-/etc/postfiatd}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-egress}"
SBIN="${SBIN:-/usr/local/sbin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
TEST="${PFT_EGRESS_TEST:-}"
IPT="${PFT_EGRESS_IPT:-iptables}"
IPT_RESTORE="${PFT_EGRESS_IPT_RESTORE:-iptables-restore}"
DOCKER="${PFT_EGRESS_DOCKER:-docker}"
MAINT="${PFT_EGRESS_MAINT:-pft-maint}"
SYSTEMCTL="${PFT_EGRESS_SYSTEMCTL:-systemctl}"
SYSTEMD_RUN="${PFT_EGRESS_SYSTEMD_RUN:-systemd-run}"
JOURNAL="${PFT_EGRESS_JOURNAL:-journalctl}"

usage() { sed -n '7,14p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "pft-egress: $1" >&2; exit "${2:-3}"; }
now() { if [ -n "${PFT_EGRESS_NOW_FILE:-}" ]; then cat "$PFT_EGRESS_NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${PFT_EGRESS_NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) > "$PFT_EGRESS_NOW_FILE"; else sleep "$1"; fi; }
iso() { date -u -d "@$1" +%FT%TZ; }
log() { echo "[$(iso "$(now)")] $*"; }
need_root() { [ -n "$TEST" ] || [ "$(id -u)" -eq 0 ] || die "$CMD needs root (sudo)" 3; }

server_info() { # -> .result.info JSON, {} when the RPC does not answer (time taken when the answer arrives)
  local r
  if [ -n "${PFT_EGRESS_RPC_CMD:-}" ]; then r="$("$PFT_EGRESS_RPC_CMD" server_info)"
  else r="$("$DOCKER" exec "$CONTAINER" curl -s --max-time 5 http://127.0.0.1:5005/ -X POST \
              -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' 2>/dev/null \
            | jq -c '.result // empty' 2>/dev/null)"; fi
  [ -n "$r" ] || r='{}'
  jq -c '.info // {}' <<<"$r" 2>/dev/null || echo '{}'
}
is_full() { case "$1" in full|validating|proposing) return 0 ;; esac; return 1; }

maint_gate() { # NEED_SEC -> "ok <remaining>" or "refuse <reason>"
  local j w rem nl
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "refuse pft-maint status failed (is pft-maint installed?)"; return; }
  w="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"
  rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"; [[ "$rem" =~ ^[0-9]+$ ]] || rem=0
  nl="$(jq -r '.locks | length' <<<"$j" 2>/dev/null)"; [[ "$nl" =~ ^[0-9]+$ ]] || nl=1
  if [ "$w" != active ]; then echo "refuse no active pft-maint window (window=$w); run: sudo pft-maint start --ttl 30m --reason ..."
  elif [ "$rem" -lt "$1" ]; then echo "refuse window has ${rem}s left, apply needs DEADMAN+MAINT_MARGIN=${1}s"
  elif [ "$nl" -gt 0 ]; then echo "refuse $nl pft-maint data-collection lock(s) held: $(jq -r '.locks | join("; ")' <<<"$j")"
  else echo "ok $rem"; fi
}

# ---------- plan ----------
ss_established() { # PID -> ss -Htn state established (inside the container netns)
  if [ -n "${PFT_EGRESS_SS_CMD:-}" ]; then "$PFT_EGRESS_SS_CMD"; else nsenter -t "$1" -n ss -Htn state established; fi
}

# Parses one INI-style [section] from stdin: non-empty, non-comment lines until the next [section].
ini_section() { awk -v s="[$1]" '$0 == s {on = 1; next} /^\[/ {on = 0} on && NF && $1 !~ /^#/'; }

discover_json() { # -> one JSON document describing the container's network and what it talks to
  local I pid mode net ip ip6 br resolv cfg vlf vl ss
  I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0] // empty')"
  [ -n "$I" ] || die "container $CONTAINER not found" 3
  [ "$(jq -r .State.Running <<<"$I")" = true ] || die "container $CONTAINER is not running" 3
  mode="$(jq -r .HostConfig.NetworkMode <<<"$I")"
  case "$mode" in host|none|container:*) die "network mode '$mode' is not supported (needs a bridge network; see README limits)" 3 ;; esac
  net="$(jq -r '.NetworkSettings.Networks | keys | if length == 1 then .[0] else "MULTI" end' <<<"$I")"
  [ "$net" != MULTI ] || die "container is on several networks; not supported" 3
  ip="$(jq -r --arg n "$net" '.NetworkSettings.Networks[$n].IPAddress' <<<"$I")"
  ip6="$(jq -r --arg n "$net" '.NetworkSettings.Networks[$n].GlobalIPv6Address // ""' <<<"$I")"
  br="$("$DOCKER" network inspect "$net" 2>/dev/null | jq -r --arg n "$net" '.[0] | .Options["com.docker.network.bridge.name"] // (if $n == "bridge" then "docker0" else "br-" + .Id[0:12] end)')"
  pid="$(jq -r .State.Pid <<<"$I")"
  resolv="$("$DOCKER" exec "$CONTAINER" cat /etc/resolv.conf 2>/dev/null)"
  cfg="$("$DOCKER" exec "$CONTAINER" cat "$CFG_DIR/postfiatd.cfg" 2>/dev/null)"
  vlf="$(ini_section validators_file <<<"$cfg" | head -1)"; vlf="${vlf:-validators.txt}"; [[ "$vlf" == /* ]] || vlf="$CFG_DIR/$vlf"
  vl="$("$DOCKER" exec "$CONTAINER" cat "$vlf" 2>/dev/null)"
  ss="$(ss_established "$pid")"
  jq -n --arg c "$CONTAINER" --arg mode "$mode" --arg net "$net" --arg ip "$ip" --arg ip6 "$ip6" --arg br "$br" \
        --arg resolv "$resolv" --arg ips "$( { ini_section ips; ini_section ips_fixed; } <<<"$cfg")" \
        --arg vl "$(ini_section validator_list_sites <<<"$vl"$'\n'"$(ini_section validator_list_sites <<<"$cfg")")" \
        --arg ss "$ss" --argjson pp "$PEER_PORT" '
    def port_of_url: capture("^(?<s>[a-z]+)://[^/:]+(:(?<p>[0-9]+))?") | if .p then (.p|tonumber) elif .s == "http" then 80 else 443 end;
    { container: $c, network_mode: $mode, network: $net, ip: $ip, ipv6: $ip6, bridge: $br,
      resolvers: [$resolv | splits("\n") | select(test("^nameserver ")) | split(" ")[1]] | unique,
      cfg_peer_ports: [$ips | splits("\n") | select(length > 0) | (split(" ") | map(select(length > 0))) as $f
                       | if ($f | length) >= 2 then ($f[1] | tonumber? // $pp) else $pp end] | unique,
      vl_sites: [$vl | splits("\n") | select(test("^https?://"))] | unique,
      vl_ports: [$vl | splits("\n") | select(test("^https?://")) | port_of_url] | unique,
      established: [$ss | splits("\n") | select(length > 0) | split(" ") | map(select(length > 0))
                    | {local: .[2], remote: .[3]}
                    | .lport = (.local | sub(".*:"; "") | tonumber) | .rport = (.remote | sub(".*:"; "") | tonumber)],
    } | .outbound_ports = ([.established[] | select(.lport != $pp) | .rport] | unique)
      | .inbound_conns = ([.established[] | select(.lport == $pp)] | length)'
}

plan_json() { # DISCOVER_JSON -> policy JSON
  jq -c --argjson pp "$PEER_PORT" --arg extra "$EXTRA_TCP_PORTS" '
    . as $d
    | { container, ip, bridge, network,
        resolvers: [.resolvers[] | select(test("^[0-9.]+$") and (test("^127\\.") | not))],
        resolvers_seen: (.resolvers | length),
        tcp_ports: ([$pp] + .cfg_peer_ports + .outbound_ports + .vl_ports
                    + [$extra | splits("[ ,]+") | select(length > 0) | tonumber]) | unique,
        warnings: ([ (if .ipv6 != "" then "container has a global IPv6 address (\(.ipv6)): IPv6 egress is NOT filtered" else empty end),
                     (.resolvers[] | select(test("^127\\.")) | "resolver \(.) is loopback (Docker embedded DNS): lookups leave via dockerd on the host, not this chain"),
                     (if (.resolvers | length) == 0 then "no nameserver in /etc/resolv.conf: DNS will be blocked" else empty end),
                     (if (.vl_sites | length) == 0 then "no [validator_list_sites] found: validator-list fetch port not derived" else empty end) ]) }' <<<"$1"
}

render_rules() { # POLICY -> iptables-restore --noflush input for the chain only (the jump is managed separately)
  jq -r --arg ch "$CHAIN" --arg lim "$LOG_LIMIT" --arg pfx "$LOG_PREFIX" '
    "*filter", ":\($ch) - [0:0]", "-F \($ch)",
    "-A \($ch) -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"pft-egress replies\" -j RETURN",
    (.resolvers[] as $r | ("udp", "tcp") | "-A \($ch) -d \($r)/32 -p \(.) -m \(.) --dport 53 -m comment --comment \"pft-egress dns\" -j RETURN"),
    "-A \($ch) -p tcp -m multiport --dports \(.tcp_ports | map(tostring) | join(",")) -m comment --comment \"pft-egress peers+vl\" -j RETURN",
    "-A \($ch) -m limit --limit \($lim) --limit-burst 10 -j LOG --log-prefix \"\($pfx)\" --log-level 4",
    "-A \($ch) -m comment --comment \"pft-egress default deny\" -j DROP",
    "COMMIT"' <<<"$1"
}
jump_spec() { # POLICY -> the DOCKER-USER jump rule spec (as words, one per line)
  jq -r --arg ch "$CHAIN" '"-s", "\(.ip)/32", "-i", .bridge, "!", "-o", .bridge, "-m", "comment", "--comment", "pft-egress:\(.container)", "-j", $ch' <<<"$1"
}
jump_lines() { "$IPT" -S DOCKER-USER 2>/dev/null | grep -n -- "-j $CHAIN\$"; } # "<pos+1>:<rule>" (line 1 is -N)

print_plan() { # DISCOVER POLICY
  jq -r '"container:   \(.container) network \(.network) (bridge \(.bridge)) ip \(.ip)\(if .ipv6 != "" then " ipv6 " + .ipv6 else "" end)",
    "resolvers:   \(.resolvers | join(" "))",
    "cfg peers:   ports \(.cfg_peer_ports | map(tostring) | join(" ")) ([ips]/[ips_fixed])",
    "vl sites:    \(.vl_sites | join(" ")) -> ports \(.vl_ports | map(tostring) | join(" "))",
    "connections: \(.established | length) established, \(.inbound_conns) inbound, outbound remote ports \(.outbound_ports | map(tostring) | join(" "))"' <<<"$1"
  jq -r '"allowlist:   replies (ESTABLISHED,RELATED); DNS 53/udp+tcp to \(.resolvers | join(" ")); tcp \(.tcp_ports | map(tostring) | join(","))",
    "everything else: LOG (rate-limited) + DROP", (.warnings[] | "WARNING: \(.)")' <<<"$2"
}

# ---------- state, units ----------
state_file() { echo "$STATE_DIR/$CONTAINER.json"; }
self_path() { if [ -n "$TEST" ]; then echo "$0"; else echo "$SBIN/pft-egress"; fi; }

install_units() {
  local s; s="$(self_path)"
  if [ -z "$TEST" ] && [ "$(readlink -f "$0")" != "$(readlink -f "$s")" ]; then install -m 0755 "$0" "$s" || return 1; fi
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/pft-egress-reapply@.service" <<EOF
[Unit]
Description=pft-egress: re-apply the egress policy for container %i
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$s reapply --container %i
EOF
  cat > "$UNIT_DIR/pft-egress-reapply@.timer" <<'EOF'
[Unit]
Description=pft-egress: re-apply the egress policy for container %i at boot and every 5 min (no-op without drift)

[Timer]
OnBootSec=60
OnUnitActiveSec=300

[Install]
WantedBy=timers.target
EOF
  "$SYSTEMCTL" daemon-reload && "$SYSTEMCTL" enable --now "pft-egress-reapply@$CONTAINER.timer" >/dev/null 2>&1
}

load_policy() { # POLICY -> loads the chain and makes sure exactly one jump exists at DOCKER-USER 1
  local P="$1" j
  render_rules "$P" | "$IPT_RESTORE" --noflush || return 1
  mapfile -t j < <(jump_spec "$P")
  # drop jumps that point at the chain but no longer match (IP or bridge changed), then insert the current one
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    if [ "${l#*:}" != "-A DOCKER-USER ${j[*]}" ] || [ "${l%%:*}" != 2 ]; then
      read -r -a w <<<"${l#*:-A DOCKER-USER }"; "$IPT" -D DOCKER-USER "${w[@]}" 2>/dev/null
    fi
  done < <(jump_lines | sed 's/"//g')
  "$IPT" -C DOCKER-USER "${j[@]}" >/dev/null 2>&1 || "$IPT" -I DOCKER-USER 1 "${j[@]}" || return 1
  [ "$(jump_lines | head -1 | cut -d: -f1)" = 2 ] || { "$IPT" -D DOCKER-USER "${j[@]}"; "$IPT" -I DOCKER-USER 1 "${j[@]}"; }
}

do_rollback() {
  local l w rc=0
  log "rollback: removing jump(s) and chain $CHAIN"
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    read -r -a w <<<"${l#*:-A DOCKER-USER }"; "$IPT" -D DOCKER-USER "${w[@]}" || rc=5
  done < <(jump_lines | sed 's/"//g' | sort -t: -k1,1nr)
  if "$IPT" -S "$CHAIN" >/dev/null 2>&1; then "$IPT" -F "$CHAIN" && "$IPT" -X "$CHAIN" || rc=5; fi
  "$SYSTEMCTL" disable --now "pft-egress-reapply@$CONTAINER.timer" >/dev/null 2>&1
  [ -n "${NO_STOP_DEADMAN:-}" ] || "$SYSTEMCTL" stop "pft-egress-deadman@$CONTAINER" >/dev/null 2>&1
  [ -f "$(state_file)" ] && mv -f "$(state_file)" "$(state_file).rolled-back"
  if [ -n "$(jump_lines)" ] || "$IPT" -S "$CHAIN" >/dev/null 2>&1; then log "rollback RESULT: FAIL - chain or jump still present"; return 5; fi
  [ "$rc" -eq 0 ] && log "rollback RESULT: PASS - no $CHAIN chain, no DOCKER-USER jump, reapply timer disabled"
  return "$rc"
}

watch_deadman() { # uses state file: baseline, deadline
  local S base floor dl bad=0 info st pe
  S="$(cat "$(state_file)")" || die "no state for $CONTAINER" 3
  base="$(jq -r .baseline_peers <<<"$S")"; floor=$(( base - PEER_SLACK )); dl="$(jq -r .deadman_until_epoch <<<"$S")"
  log "dead-man: until $(iso "$dl"), rollback after $BAD_POLLS consecutive polls with state != full or peers < $floor (baseline $base - slack $PEER_SLACK)"
  while [ "$(now)" -lt "$dl" ]; do
    nap "$POLL_SEC"
    info="$(server_info)"; st="$(jq -r '.server_state // "down"' <<<"$info")"; pe="$(jq -r '.peers // 0' <<<"$info")"
    if is_full "$st" && [ "$pe" -ge "$floor" ]; then bad=0; log "dead-man poll: $st peers $pe ok"
    else bad=$((bad + 1)); log "dead-man poll: $st peers $pe BAD ($bad/$BAD_POLLS)"; fi
    if [ "$bad" -ge "$BAD_POLLS" ]; then log "dead-man: TRIPPED - rolling back"; NO_STOP_DEADMAN=1 do_rollback; return 1; fi
  done
  jq -c --arg t "$(iso "$(now)")" '.deadman_passed_at = $t' "$(state_file)" > "$(state_file).tmp" && mv "$(state_file).tmp" "$(state_file)"
  log "dead-man: PASS - policy kept"
}

# ---------- main ----------
CMD="${1:-}"; [ $# -gt 0 ] && shift
YES=0; JSON=0; DRY=0; FG=0; TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --container) CONTAINER="$2"; shift 2 ;; --yes) YES=1; shift ;; --json) JSON=1; shift ;;
    --dry-run) DRY=1; shift ;; --deadman) DEADMAN_MIN="$2"; shift 2 ;; --foreground) FG=1; shift ;;
    --target) TARGETS+=("$2"); shift 2 ;; -h|--help) usage; exit 0 ;;
    *) die "unknown argument $1" 3 ;;
  esac
done
[[ "$DEADMAN_MIN" =~ ^[0-9]+$ && "$POLL_SEC" =~ ^[0-9]+$ && "$PEER_SLACK" =~ ^[0-9]+$ ]] || die "DEADMAN/POLL_SEC/PEER_SLACK must be integers"
command -v jq >/dev/null || die "jq is required"

case "$CMD" in
  plan)
    D="$(discover_json)" || exit 3; P="$(plan_json "$D")"
    if [ "$JSON" = 1 ]; then jq -c --argjson p "$P" '{discover: ., policy: $p}' <<<"$D"; exit 0; fi
    print_plan "$D" "$P"
    echo "iptables-restore --noflush input:"; render_rules "$P" | sed 's/^/  | /'
    echo "DOCKER-USER jump (position 1): $(jump_spec "$P" | tr '\n' ' ')"
    ;;
  apply)
    need_root
    D="$(discover_json)" || exit 3; P="$(plan_json "$D")"
    if [ "$DRY" = 1 ]; then
      print_plan "$D" "$P"
      echo "dry run - nothing changed. diff live chain (-) vs rendered (+):"
      diff <("$IPT" -S "$CHAIN" 2>/dev/null | sed '1{/^-N /d}') <(render_rules "$P" | grep '^-A ') | grep '^[<>]' | sed 's/^</  -/; s/^>/  +/'
      mapfile -t J < <(jump_spec "$P")
      if "$IPT" -C DOCKER-USER "${J[@]}" >/dev/null 2>&1; then echo "  jump: present"; else echo "  jump: + -I DOCKER-USER 1 $(jump_spec "$P" | tr '\n' ' ')"; fi
      exit 0
    fi
    [ "$YES" = 1 ] || die "apply changes the firewall; re-run with --yes (or --dry-run)" 4
    GATE="$(maint_gate $(( DEADMAN_MIN * 60 + MAINT_MARGIN )))"
    case "$GATE" in ok*) ;; *) die "REFUSED: ${GATE#refuse }" 4 ;; esac
    INFO="$(server_info)"; ST="$(jq -r '.server_state // "down"' <<<"$INFO")"; PE="$(jq -r '.peers // 0' <<<"$INFO")"
    is_full "$ST" || die "REFUSED: node is $ST, not full" 4
    [ "$PE" -ge "$MIN_PEERS" ] || die "REFUSED: peers $PE < MIN_PEERS $MIN_PEERS" 4
    [ "$(jq '.resolvers_seen' <<<"$P")" -gt 0 ] || die "REFUSED: no nameserver in the container resolv.conf, DNS would break" 4
    SF="$(state_file)"; mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR"
    if [ -f "$SF" ] && [ "$(jq -c .policy "$SF")" = "$(jq -c 'del(.warnings, .resolvers_seen)' <<<"$P")" ] \
       && [ "$("$IPT" -S "$CHAIN" 2>/dev/null)" = "$(jq -r '.live_rules | join("\n")' "$SF")" ] \
       && [ "$(jump_lines | head -1 | cut -d: -f1)" = 2 ] && [ "$(jump_lines | wc -l)" = 1 ]; then
      log "apply: no change (policy, chain and jump already match $SF)"; exit 0
    fi
    log "apply on $CONTAINER; maintenance gate: $GATE; pre: server_state=$ST peers=$PE"
    log "policy: $(jq -c 'del(.warnings, .resolvers_seen)' <<<"$P")"
    jq -r '.warnings[] | "WARNING: \(.)"' <<<"$P"
    trap 'log "interrupted"; do_rollback; exit 6' INT TERM
    load_policy "$P" || { log "loading rules failed"; do_rollback; exit 1; }
    LIVE="$("$IPT" -S "$CHAIN")"
    jq -n --argjson p "$(jq -c 'del(.warnings, .resolvers_seen)' <<<"$P")" --arg live "$LIVE" --argjson b "$PE" \
      --argjson dl $(( $(now) + DEADMAN_MIN * 60 )) --arg t "$(iso "$(now)")" \
      '{policy: $p, live_rules: ($live | split("\n")), baseline_peers: $b, applied_at: $t, deadman_until_epoch: $dl}' > "$SF"
    log "chain $CHAIN loaded ($(grep -c '^-A' <<<"$LIVE") rules), jump at DOCKER-USER 1; state $SF"
    install_units || { log "installing persistence units failed"; do_rollback; exit 1; }
    log "persistence: pft-egress-reapply@$CONTAINER.timer enabled ($(self_path) reapply)"
    trap - INT TERM
    if [ "$FG" = 1 ] || [ -n "$TEST" ]; then watch_deadman; exit $?; fi
    "$SYSTEMD_RUN" --unit="pft-egress-deadman@$CONTAINER" --collect -E "PEER_SLACK=$PEER_SLACK" -E "POLL_SEC=$POLL_SEC" \
      -E "BAD_POLLS=$BAD_POLLS" "$(self_path)" watch --container "$CONTAINER" >/dev/null \
      || { log "could not start the dead-man unit"; do_rollback; exit 1; }
    log "dead-man started as transient unit pft-egress-deadman@$CONTAINER (journalctl -u it); apply RESULT: PASS (pending dead-man)"
    ;;
  watch) need_root; watch_deadman; exit $? ;;
  reapply)
    need_root
    SF="$(state_file)"; [ -f "$SF" ] || exit 0
    I="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -c '.[0] // empty')"
    NET="$(jq -r '.policy.network' "$SF")"; IP="$(jq -r --arg n "$NET" '.NetworkSettings.Networks[$n].IPAddress // ""' <<<"$I")"
    [ -n "$IP" ] || { log "reapply: $CONTAINER has no IP on $NET yet"; exit 1; }
    P="$(jq -c --arg ip "$IP" '.policy | .ip = $ip' "$SF")"
    mapfile -t J < <(jump_spec "$P")
    if [ "$("$IPT" -S "$CHAIN" 2>/dev/null)" = "$(jq -r '.live_rules | join("\n")' "$SF")" ] \
       && "$IPT" -C DOCKER-USER "${J[@]}" >/dev/null 2>&1 && [ "$(jump_lines | head -1 | cut -d: -f1)" = 2 ] \
       && [ "$(jump_lines | wc -l)" = 1 ]; then exit 0; fi
    log "reapply: drift found (chain changed, jump missing/moved/duplicated, or container IP now $IP) - reloading"
    load_policy "$P" || exit 1
    jq -c --argjson p "$P" --arg live "$("$IPT" -S "$CHAIN")" '.policy = $p | .live_rules = ($live | split("\n"))' "$SF" > "$SF.tmp" && mv "$SF.tmp" "$SF"
    log "reapply: done"
    ;;
  check)
    need_root
    SF="$(state_file)"; fails=0
    chk() { if [ "$1" = 0 ]; then echo "  [PASS] $2"; else echo "  [FAIL] $2"; fails=$((fails + 1)); fi; }
    echo "pft-egress check $CONTAINER - $(iso "$(now)")"
    [ -f "$SF" ]; chk $? "state file present"
    [ -f "$SF" ] || { echo "RESULT: FAIL (not applied)"; exit 1; }
    P="$(jq -c .policy "$SF")"
    LIVE="$("$IPT" -S "$CHAIN" 2>/dev/null)"
    [ "$LIVE" = "$(jq -r '.live_rules | join("\n")' "$SF")" ]; chk $? "chain $CHAIN matches the applied snapshot ($(grep -c '^-A' <<<"$LIVE") rules)"
    IP="$("$DOCKER" inspect "$CONTAINER" 2>/dev/null | jq -r --arg n "$(jq -r .network <<<"$P")" '.[0].NetworkSettings.Networks[$n].IPAddress // ""')"
    [ "$IP" = "$(jq -r .ip <<<"$P")" ]; chk $? "container IP unchanged since apply"
    mapfile -t J < <(jump_spec "$P")
    "$IPT" -C DOCKER-USER "${J[@]}" >/dev/null 2>&1 && [ "$(jump_lines | head -1 | cut -d: -f1)" = 2 ] \
      && [ "$(jump_lines | wc -l)" = 1 ]; chk $? "exactly one jump, at DOCKER-USER position 1"
    [ "$("$SYSTEMCTL" is-enabled "pft-egress-reapply@$CONTAINER.timer" 2>/dev/null)" = enabled ]; chk $? "reapply timer enabled"
    CNT="$("$IPT" -L "$CHAIN" -v -n -x 2>/dev/null | awk '$3 == "DROP" {print $1 " pkts " $2 " bytes"}')"
    echo "  [INFO] default-deny DROP counter: ${CNT:-n/a}"
    DL="$("$JOURNAL" -k --since "-1h" --no-pager -o cat 2>/dev/null | grep -F "$LOG_PREFIX")"
    echo "  [INFO] drop log lines in the last hour: $(grep -c . <<<"$DL")$( [ -n "$DL" ] && echo "; by DPT: $(grep -oE 'DPT=[0-9]+' <<<"$DL" | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s(%s) ", $2, $1}')")"
    INFO="$(server_info)"; ST="$(jq -r '.server_state // "down"' <<<"$INFO")"; PE="$(jq -r '.peers // 0' <<<"$INFO")"
    is_full "$ST"; chk $? "server_state $ST"
    B="$(jq -r .baseline_peers "$SF")"; [ "$PE" -ge "$B" ]; chk $? "peers $PE >= baseline $B"
    [ "$fails" -eq 0 ] && { echo "RESULT: PASS"; exit 0; }
    echo "RESULT: FAIL ($fails)"; exit 1
    ;;
  rollback)
    need_root
    [ "$YES" = 1 ] || die "rollback changes the firewall; re-run with --yes" 4
    do_rollback; exit $?
    ;;
  probe)
    [ "${#TARGETS[@]}" -gt 0 ] || die "probe needs --target HOST:PORT" 3
    for t in "${TARGETS[@]}"; do
      h="${t%:*}"; p="${t##*:}"; s="$(date -u +%s)"  # real clock: the elapsed time shows DROP (5 s) vs refused
      if "$DOCKER" exec "$CONTAINER" timeout 5 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then r=CONNECTED; else r=BLOCKED_OR_FAILED; fi
      echo "probe $(iso "$s") $CONTAINER -> $h:$p $r ($(( $(date -u +%s) - s ))s)"
    done
    ;;
  *) usage >&2; exit 3 ;;
esac
