# shellcheck shell=bash
# Parsers shared by live-run.sh and test-drill.sh (sourced). Input: a redacted pft-peerexpose output file.
# parse_result FILE -> last "RESULT: WORDS" verdict in upper case (APPLIED, ROLLED BACK, NO CHANGE, ...), empty if none
parse_result() { grep -oE '^([0-9TZ:-]+ )?RESULT: [A-Z][A-Z ]*[A-Z]' "$1" | tail -1 | sed 's/^.*RESULT: //'; }
# parse_viol FILE -> violation count of the last audit summary line, empty if none
parse_viol() { sed -nE 's/^RESULT: ([0-9]+) violation\(s\), ([0-9]+) error\(s\)$/\1/p' "$1" | tail -1; }
