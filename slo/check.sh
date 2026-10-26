#!/usr/bin/env bash
# Offline checks for slo/: promtool check + test rules, CLI/exporter unit tests, ruff, shellcheck,
# plus three mutation controls that must FAIL (tests that cannot fail prove nothing):
#   M1 rules: drop the maintenance exclusion from pft:sli_bad:bool -> promtool maintenance test fails
#   M2 CLI:   classify() ignores maintenance                     -> unit tests fail
#   M3 drill: drill_check.py accepts a stale [FIRING] message    -> drill checker tests fail
#   M4 drill: restore expires the non-SLO silence when Prometheus lists no alerts (the run-2 leak, pre-5dd2f5f)
#                                                                -> drill restore tests fail
# Usage: check.sh        Env: DOCKER (default "docker", e.g. DOCKER="sudo docker"), PROM_IMAGE
# Exit 0 only if every check passes and all four mutations are caught.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
read -r -a DOCKER <<< "${DOCKER:-docker}"
PROM_IMAGE="${PROM_IMAGE:-prom/prometheus:v3.5.0}"
fail=0
step() { printf '\n== %s\n' "$*"; }
promtool() { "${DOCKER[@]}" run --rm -v "$1:/w:ro" -w /w --entrypoint promtool "$PROM_IMAGE" "${@:2}"; }

cd "$HERE" || exit 2
step "tests.yml is up to date with gen_tests.py"
if python3 gen_tests.py | cmp -s - tests.yml; then echo "tests.yml matches"; else echo "FAIL: regenerate tests.yml"; fail=1; fi

step "promtool check rules slo.rules.yml"
promtool "$HERE" check rules slo.rules.yml || fail=1

step "promtool test rules tests.yml"
promtool "$HERE" test rules tests.yml || fail=1

step "unit tests (python3 -m unittest)"
python3 -m unittest discover -s tests -v 2>&1 || fail=1

step "ruff check (slo/)"
ruff check . || fail=1

step "shellcheck"
if shellcheck ./*.sh; then echo "shellcheck clean:" ./*.sh; else fail=1; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 755 "$tmp"   # promtool runs as nobody in the container; a 700 dir would "fail" for the wrong reason

step "M1 mutation: pft:sli_bad:bool without the maintenance exclusion (promtool must FAIL)"
cp slo.rules.yml tests.yml "$tmp/"
sed -i 's|expr: (1 - pft:sli_good:bool) \* pft:sli_eligible:bool|expr: (1 - pft:sli_good:bool)|' "$tmp/slo.rules.yml"
if cmp -s slo.rules.yml "$tmp/slo.rules.yml"; then echo "FAIL: mutation did not apply"; fail=1
elif promtool "$tmp" test rules tests.yml > "$tmp/m1.out" 2>&1; then echo "FAIL: mutant passed"; fail=1
elif grep -q 'name: maintenance-window' "$tmp/m1.out"; then
  grep -E '^ +(name|alertname): ' "$tmp/m1.out" | sed 's/^ *//; s/, *$//' | paste - - | sort -u
  echo "caught: maintenance-window test failed on the mutant"
else echo "FAIL: mutant failed for another reason:"; head -5 "$tmp/m1.out"; fail=1; fi

step "M2 mutation: CLI classify() ignores maintenance (unit tests must FAIL)"
mkdir -p "$tmp/m2"
cp -r tests pft_slo_report.py drill_check.py "$tmp/m2/"
sed -i 's|    if comp\["maint"\].get(t) == 1 or any(s <= t < e for s, e in maint_spans):|    if False:|' \
  "$tmp/m2/pft_slo_report.py"
sed -i 's|"\.\.", "\.\.", "exporter"|"'"$HERE"'", "..", "exporter"|' "$tmp/m2/tests/test_exporter_maint.py"
if cmp -s pft_slo_report.py "$tmp/m2/pft_slo_report.py"; then echo "FAIL: mutation did not apply"; fail=1
elif (cd "$tmp/m2" && python3 -m unittest discover -s tests > "$tmp/m2.out" 2>&1); then echo "FAIL: mutant passed"; fail=1
elif grep -q '^ERROR:' "$tmp/m2.out"; then echo "FAIL: mutant errored (not an assertion):"; grep '^ERROR:' "$tmp/m2.out"; fail=1
else grep -E '^FAIL:' "$tmp/m2.out" | sed 's/ (.*//'; echo "caught: assertion failures only"; fi

step "M3 mutation: drill checker accepts a [FIRING] message from before the alert fired (tests must FAIL)"
mkdir -p "$tmp/m3"
cp -r tests drill_check.py "$tmp/m3/"
sed -i 's|any(m\["time"\] >= fire\["t"\] - 60 for m in fm)|bool(fm)|' "$tmp/m3/drill_check.py"
if cmp -s drill_check.py "$tmp/m3/drill_check.py"; then echo "FAIL: mutation did not apply"; fail=1
elif (cd "$tmp/m3" && python3 -m unittest discover -s tests -p 'test_drill_check.py' > "$tmp/m3.out" 2>&1); then echo "FAIL: mutant passed"; fail=1
elif grep -q '^ERROR:' "$tmp/m3.out"; then echo "FAIL: mutant errored (not an assertion):"; grep '^ERROR:' "$tmp/m3.out"; fail=1
else grep -E '^FAIL:' "$tmp/m3.out" | sed 's/ (.*//'; echo "caught: assertion failures only"; fi

step "M4 mutation: restore expires the non-SLO silence on an empty Prometheus alert list (tests must FAIL)"
mkdir -p "$tmp/m4"
cp -r tests drill_lib.sh "$tmp/m4/"
sed -i 's|^  else echo "Alertmanager silence ${1:0:8} kept until its end time (60m; never expired early)"; fi$|  elif [ -z "$active" ]; then curl -s -X DELETE "$AM/api/v2/silence/$1" -o /dev/null -w "expired (HTTP %{http_code})\\n"\n  else echo "left to run out (60m)"; fi|' \
  "$tmp/m4/drill_lib.sh"
if cmp -s drill_lib.sh "$tmp/m4/drill_lib.sh"; then echo "FAIL: mutation did not apply"; fail=1
elif (cd "$tmp/m4" && python3 -m unittest discover -s tests -p 'test_drill_restore.py' > "$tmp/m4.out" 2>&1); then echo "FAIL: mutant passed"; fail=1
elif grep -q '^ERROR:' "$tmp/m4.out"; then echo "FAIL: mutant errored (not an assertion):"; grep '^ERROR:' "$tmp/m4.out"; fail=1
else grep -E '^FAIL:' "$tmp/m4.out" | sed 's/ (.*//'; grep -m1 -o 'silence expired early: .*' "$tmp/m4.out"; echo "caught: assertion failures only"; fi

printf '\nRESULT: %s\n' "$([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
