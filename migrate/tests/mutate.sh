#!/usr/bin/env bash
# Mutation check for tests/run-tests.sh: each mutant removes one safety check from pft-migrate.sh; the suite must
# FAIL for every one. Mutants are written under the user cache dir (exec-able), never into the repo.
# Usage: tests/mutate.sh      exit 0 = every mutant killed
# shellcheck disable=SC2016 # the mutant patterns are literal source text
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/../pft-migrate.sh"
D="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/pft-migrate-mut.XXXXXX")"; trap 'rm -rf "$D"' EXIT
M="$D/pft-migrate.sh"; K=0; S=0
mut() { # NAME FROM TO
  python3 -I -c 'import sys; s=open(sys.argv[1]).read(); a=sys.argv[2]
if a not in s: sys.exit("mutant pattern not found: " + a)
open(sys.argv[4],"w").write(s.replace(a, sys.argv[3], 1))' "$SRC" "$2" "$3" "$M" || { echo "NOT-APPLIED $1"; S=$((S + 1)); return; }
  local r; r="$(bash "$HERE/run-tests.sh" "$M" 2>&1 | tail -1)"
  case "$r" in *" 0 failed"*) echo "SURVIVED $1: $r"; S=$((S + 1)) ;; *) echo "killed   $1: $r"; K=$((K + 1)) ;; esac
}
mut "no source probe" 'if probe "$h" "$p"; then die "the source still answers' 'if false; then die "the source still answers'
mut "no target probe" 'if probe "$h" "$p"; then die "the target still answers' 'if false; then die "the target still answers'
mut "no sidecar check" '|| die "bundle sha256 does not match its sidecar (tampered or truncated)" 2' '|| true'
mut "no layout check" '[ -z "$bad" ] || die "unexpected path(s)' 'true || die "unexpected path(s)'
mut "no manifest check" '|| { sed '"'"'s/^/  /'"'"' "$STAGE/m.err" >&2; die "manifest check failed" 2; }' '|| true'
mut "no extra-file check" '|| die "files in the bundle differ from its manifest" 2' '|| true'
mut "no link check" "awk '\$1 !~ /^[-d]/' " "awk '0'"
mut "no guard on fence" '  guard_on "$dir" "$svc" "$id"
  "$DOCKER" update' '  "$DOCKER" update'
mut "no proof check (start)" 'check_proof "$proof" "$id" "$pub" || die' 'true || die'
mut "proof ignores container_state" 'for k in container_state=exited restart_policy=no' 'for k in restart_policy=no'
mut "rollback keeps restart=no" '"$DOCKER" update --restart="$pol" "$c"' 'true'
mut "import over running copy" 'die "container $c is RUNNING on this host' 'log "container $c is RUNNING on this host'
mut "start on fenced host" 'then die "this host is FENCED for bundle $id: start refused' 'then log "x'
mut "verify ignores identity" 'if [ -n "$pub" ] && [ "$pub" != "$want" ]' 'if false'
mut "rollback ignores proof age" '|| die "target proof is older than this host'"'"'s fence" 4' '|| true'
mut "export accepts identity file" "&& ! grep -q 'AGE-SECRET-KEY' \"\$to\"" ""
echo "MUTANTS: $K killed, $S survived/not applied"
[ "$S" = 0 ]
