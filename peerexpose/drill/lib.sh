# shellcheck shell=bash
# Parsers shared by live-run.sh and test-drill.sh (sourced). Input: a redacted pft-peerexpose output file.
# parse_result FILE -> last "RESULT: WORDS" verdict in upper case (APPLIED, ROLLED BACK, NO CHANGE, ...), empty if none
parse_result() { grep -oE '^([0-9TZ:-]+ )?RESULT: [A-Z][A-Z ]*[A-Z]' "$1" | tail -1 | sed 's/^.*RESULT: //'; }
# parse_viol FILE -> violation count of the last audit summary line, empty if none
parse_viol() { sed -nE 's/^RESULT: ([0-9]+) violation\(s\), ([0-9]+) error\(s\)$/\1/p' "$1" | tail -1; }
# peer_has ADDR KEY < peers-RPC-JSON -> "true" if a peer has address ADDR (any port, IPv4-mapped too) or node key KEY
# (exact). A peer that connects inbound through docker-proxy is listed as the bridge gateway, so only its key matches.
peer_has() {
  local pj; pj="$(cat)"
  if grep -Eq "(^|[^0-9.])${1//./\\.}([]:]|$)" < <(jq -r '.result.peers[]?.address // empty' <<<"$pj" 2>/dev/null) \
     || { [ -n "$2" ] && grep -qxF -- "$2" < <(jq -r '.result.peers[]?.public_key // empty' <<<"$pj" 2>/dev/null); }; then
    echo true
  else echo false; fi
}
# has_block < postfiatd.cfg -> "true" if the config carries a pft-peerexpose managed block (MARK in pft-peerexpose.sh)
has_block() { if grep -qE '^# pft-peerexpose managed block( |$)'; then echo true; else echo false; fi; }
