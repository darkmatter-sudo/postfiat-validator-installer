#!/usr/bin/env bash
# pft-fwaudit: compare a host's declared inbound policy with its effective exposure (read-only audit).
# UFW rules alone do not say what is reachable: Docker-published ports are DNATed on the FORWARD path where UFW's
# INPUT rules never apply (DOCKER-USER decides), docker-proxy serves a family Docker did not DNAT on the INPUT path,
# `*` listeners are dual-stack, and nftables tables outside iptables-nft can add their own hooks. This captures the
# rulesets and sockets once into a bundle and fwaudit_eval.py walks the real chains for each listener.
#
# Usage: sudo pft-fwaudit collect [--out FILE]                         write a capture bundle (default: stdout)
#        sudo pft-fwaudit audit [--role validator|sentry] [--json] [--bundle FILE]
#                                                                      exit 0 PASS, 1 WARN, 2 FAIL, 3 usage, 4 capture
#        pft-fwaudit version
#
#  collect  runs, each into its own `### $ CMD` / `### rc=N` section: ufw status verbose, iptables-save,
#           ip6tables-save, nft list ruleset, ss -H -tulpn, docker ps (names/ports), ip -br addr. Nothing is changed
#           and nothing is sent anywhere; no docker exec into any container.
#  audit    collects (or reads --bundle) and grades it against POLICY_DIR/ROLE.policy with peer sources from PEERS.
#
# Conf: PFT_FWA_CONF (/etc/pft-fwaudit.env, root-owned): ROLE (validator), POLICY_DIR (/usr/local/lib/pft-fwaudit/policy),
#       PEERS (/etc/pft-fwaudit.peers: NAME=CIDR[,CIDR] lines, kept off the public repo), CMD_TIMEOUT (20)
# Test hooks: PFT_FWA_EVAL (/usr/local/lib/pft-fwaudit/fwaudit_eval.py)

set -uo pipefail
umask 077
VERSION=1

CONF="${PFT_FWA_CONF:-/etc/pft-fwaudit.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
ROLE="${ROLE:-validator}"
POLICY_DIR="${POLICY_DIR:-/usr/local/lib/pft-fwaudit/policy}"
PEERS="${PEERS:-/etc/pft-fwaudit.peers}"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"
EVAL="${PFT_FWA_EVAL:-/usr/local/lib/pft-fwaudit/fwaudit_eval.py}"

die() { printf 'pft-fwaudit: %s\n' "$1" >&2; exit "${2:-3}"; }

section() { # CMD...: one bundle section; the command's own rc is recorded, stderr is kept out of the body
  local rc
  printf '### $ %s\n' "$*"
  timeout "$CMD_TIMEOUT" "$@" 2>/dev/null
  rc=$?
  printf '### rc=%s\n' "$rc"
}

collect() {
  section ufw status verbose
  section iptables-save
  section ip6tables-save
  section nft list ruleset
  section ss -H -tulpn
  section docker ps --format '{{.Names}}\t{{.Ports}}'
  section ip -br addr
}

need_root() { [ "$(id -u)" = 0 ] || die "must run as root (reads netfilter rules and socket owners)" 3; }

cmd="${1:-}"; shift || true
case "$cmd" in
  collect)
    need_root
    out=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --out) out="${2:?}"; shift 2 ;;
        *) die "unknown option $1" ;;
      esac
    done
    if [ -n "$out" ]; then collect > "$out" || die "cannot write $out" 4; else collect; fi
    ;;
  audit)
    json=() bundle=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --role) ROLE="${2:?}"; shift 2 ;;
        --json) json=(--json); shift ;;
        --bundle) bundle="${2:?}"; shift 2 ;;
        *) die "unknown option $1" ;;
      esac
    done
    [[ "$ROLE" =~ ^[a-z][a-z0-9-]*$ ]] || die "bad role $ROLE"
    policy="$POLICY_DIR/$ROLE.policy"
    [ -f "$policy" ] || die "no policy for role $ROLE ($policy)"
    peers=()
    [ -f "$PEERS" ] && peers=(--peers "$PEERS")
    if [ -z "$bundle" ]; then
      need_root
      tmp="$(mktemp -d)" || die "mktemp failed" 4
      trap 'rm -rf "$tmp"' EXIT
      bundle="$tmp/bundle"
      collect > "$bundle" || die "capture failed" 4
    fi
    python3 -I "$EVAL" audit "$bundle" "$policy" "${peers[@]}" "${json[@]}"
    exit $?
    ;;
  version) echo "pft-fwaudit $VERSION" ;;
  *) sed -n '8,12p' "$0" >&2; exit 3 ;;
esac
