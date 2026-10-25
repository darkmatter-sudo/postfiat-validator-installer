#!/usr/bin/env bash
# Offline checks for divergence/: shellcheck, fake-RPC suite (+ its 2 mutants), exporter textfile unit tests,
# ruff, promtool check/test of ../alerts/divergence.rules.yml, and one rule mutant that must FAIL promtool:
#   M3 rules: PFTLedgerDiverged without `for: 2m` -> the 1-check-blip test fails
# Usage: check.sh      Env: DOCKER (default "docker", e.g. DOCKER="sudo docker"), PROM_IMAGE
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERTS="$(dirname "$HERE")/alerts"
read -r -a DOCKER <<< "${DOCKER:-docker}"
PROM_IMAGE="${PROM_IMAGE:-prom/prometheus:v3.5.0}"
fail=0
step() { printf '\n== %s\n' "$*"; }
promtool() { "${DOCKER[@]}" run --rm -v "$1:/w:ro" -w /w --entrypoint promtool "$PROM_IMAGE" "${@:2}"; }
cd "$HERE" || exit 2

step "shellcheck"
if shellcheck ./*.sh tests/*.sh; then echo "shellcheck clean:" ./*.sh tests/*.sh; else fail=1; fi
step "fake-RPC suite (tests/run-tests.sh)"
bash tests/run-tests.sh || fail=1
step "exporter textfile unit tests"
PFT_RPC_URL=http://127.0.0.1:9 python3 -m unittest discover -s tests -v 2>&1 || fail=1
step "ruff check (divergence/)"
ruff check . || fail=1
step "promtool check rules + test rules (../alerts/divergence.*)"
promtool "$ALERTS" check rules divergence.rules.yml || fail=1
promtool "$ALERTS" test rules divergence.tests.yml || fail=1

step "M3 mutation: PFTLedgerDiverged without for: 2m (promtool must FAIL)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; chmod 755 "$tmp"
cp "$ALERTS/divergence.rules.yml" "$ALERTS/divergence.tests.yml" "$tmp/"
sed -i '/expr: pft_divergence_state/{n;/for: 2m/d}' "$tmp/divergence.rules.yml"
chmod 644 "$tmp"/*
if cmp -s "$ALERTS/divergence.rules.yml" "$tmp/divergence.rules.yml"; then echo "FAIL: mutation did not apply"; fail=1
elif promtool "$tmp" test rules divergence.tests.yml > "$tmp/m3.out" 2>&1; then echo "FAIL: mutant passed"; fail=1
elif grep -q 'name: PFTLedgerDiverged stays quiet for a 1-check blip' "$tmp/m3.out"; then
  grep -E '^ +name: ' "$tmp/m3.out" | sed 's/^ *//; s/, *$//' | sort -u
  echo "caught: the 1-check-blip test failed on the mutant"
else echo "FAIL: mutant failed for another reason:"; head -5 "$tmp/m3.out"; fail=1; fi

[ "$fail" -eq 0 ] && { printf '\nCHECK PASS\n'; exit 0; }
printf '\nCHECK FAIL\n'; exit 1
