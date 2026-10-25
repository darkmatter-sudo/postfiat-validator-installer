#!/usr/bin/env bash
# Offline fake-RPC tests for pft-divergence.sh. No network, no docker, no ssh: stub `curl`, `docker`, `ssh` and
# `sudo` on PATH answer from per-source fixture files (STUB/<source>/<method>[.<n>].json, n = call number), so
# a transient error is "the first call fails, the next one succeeds". The ssh and docker stubs run the real
# command line the script builds, so the docker:/ssh: quoting is exercised too.
# Then two mutation controls that must FAIL the suite: no re-query before DIVERGED, and no RPC retries.
# Usage: bash tests/run-tests.sh [SCRIPT]     Exit 0 only if every case passes and both mutants are caught.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$(readlink -f "${1:-$HERE/../pft-divergence.sh}")"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
# stub curl: answer from $STUB/<source>/ ; source = $STUB_SRC (set by the docker stub) or the URL host
body=""; url=""
while [ $# -gt 0 ]; do case "$1" in -d) body="$2"; shift ;; --max-time|-H) shift ;; -s) ;; *) url="$1" ;; esac; shift; done
src="${STUB_SRC:-$(sed -E 's#^https?://([^/:]+).*#\1#' <<<"$url")}"
m="$(jq -r .method <<<"$body")"; idx="$(jq -r '.params[0].ledger_index // empty' <<<"$body")"
key="$m${idx:+-$idx}"
d="$STUB/$src"; n=$(( $(cat "$d/$key.count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$d/$key.count"
echo "$src $key" >> "$STUB/calls"
f="$d/$key.$n.json"; [ -f "$f" ] || f="$d/$key.json"
[ -f "$f" ] || exit 7
[ "$(cat "$f")" != TIMEOUT ] || exit 28
cat "$f"
EOF
cat > "$BIN/docker" <<'EOF'
#!/usr/bin/env bash
[ "$1" = exec ] || exit 1
STUB_SRC="$2" exec "${@:3}"
EOF
cat > "$BIN/ssh" <<'EOF'
#!/usr/bin/env bash
# stub ssh: drop options, run the remote command string locally (with the stubs on PATH)
while [ "${1:-}" = -o ]; do shift 2; done
echo "ssh-host $1" >> "$STUB/calls"
exec bash -c "$2"
EOF
cat > "$BIN/sudo" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -n ] && shift
exec "$@"
EOF
chmod +x "$BIN"/*

H1=$(printf 'A%.0s' {1..64}); H2=$(printf 'B%.0s' {1..64}); AH=$(printf 'C%.0s' {1..64}); TH=$(printf '0%.0s' {1..64})
info() { printf '{"result":{"status":"success","info":{"server_state":"full","validated_ledger":{"seq":%s},"complete_ledgers":"%s"}}}' "$1" "$2"; }
ledger() { # idx ledger_hash [account_hash]
  printf '{"result":{"status":"success","validated":true,"ledger_index":%s,"ledger_hash":"%s","ledger":{"ledger_hash":"%s","account_hash":"%s","transaction_hash":"%s"}}}' \
    "$1" "$2" "$2" "${3:-$AH}" "$TH"
}
rpcerr() { printf '{"result":{"status":"error","error":"%s","request":{}}}' "$1"; }
SRC3="validator=docker:valc sentry=ssh:relayhost:sentryc public=http:https://public.test/"

fresh() { # default fixtures: three sources, validated 1000/1001/1002, same hashes at 1000 and 800
  rm -rf "$T/stub" "$T/out"; mkdir -p "$T/stub"/{valc,sentryc,public.test} "$T/out"
  local s seq=1000
  for s in valc sentryc public.test; do
    info "$seq" "500-1002" > "$T/stub/$s/server_info.json"; seq=$((seq + 1))
    ledger 1000 "$H1" > "$T/stub/$s/ledger-1000.json"
    ledger 800 "$H1" > "$T/stub/$s/ledger-800.json"
  done
  : > "$T/stub/calls"
}
run() { # args... -> RC, OUT, ERR, PROM
  PATH="$BIN:$PATH" STUB="$T/stub" PFT_DIVERGENCE_CONF=/nonexistent bash "$SCRIPT" --backoff "0 0 0" \
    --textfile "$T/out/div.prom" --state "$T/out/state.json" "$@" > "$T/out/stdout" 2> "$T/out/stderr"
  RC=$?; OUT="$(cat "$T/out/stdout")"; ERR="$(cat "$T/out/stderr")"; PROM="$(cat "$T/out/div.prom" 2>/dev/null)"
}
pass=0; fail=0; cur=""
case_() { cur="$1"; printf '\n== %s\n' "$1"; }
ok() { # description, command...
  if "${@:2}"; then pass=$((pass + 1)); echo "  ok   $1"; else fail=$((fail + 1)); echo "  FAIL $1 [$cur]"; fi
}
has() { grep -qF -- "$2" <<<"$1"; }
show() { echo "  stdout: $OUT"; [ -z "$ERR" ] || while IFS= read -r l; do echo "  stderr: $l"; done <<<"$ERR"; }

case_ "1 AGREE: three sources, same hashes at tip and deep"
fresh; run --sources "$SRC3"; show
ok "exit 0" test "$RC" -eq 0
ok "AGREE tip=1000 deep=800 retries=0" has "$OUT" " AGREE tip=1000 deep=800 retries=0 validator=AGREE sentry=AGREE public=AGREE hash=AAAAAAAAAAAAAAAA"
ok "ssh source went through ssh to relayhost" has "$(cat "$T/stub/calls")" "ssh-host relayhost"
ok "metric validator 0" has "$PROM" 'pft_divergence_state{source="validator"} 0'
ok "metric sentry 0" has "$PROM" 'pft_divergence_state{source="sentry"} 0'
ok "metric overall 0" has "$PROM" 'pft_divergence_overall_state 0'
ok "last_agree_ledger 1000" has "$PROM" 'pft_divergence_last_agree_ledger 1000'
ok "checked deep 800" has "$PROM" 'pft_divergence_checked_ledger{depth="deep"} 800'
ok "no stderr" test -z "$ERR"

case_ "2 DIVERGED: sentry has another ledger_hash at tip, confirmed after 2 re-queries"
fresh; ledger 1000 "$H2" > "$T/stub/sentryc/ledger-1000.json"; echo '{"last_agree_ledger":990}' > "$T/out/state.json"
run --sources "$SRC3"; show
ok "exit 2" test "$RC" -eq 2
ok "sentry DIVERGED with field + both hashes" has "$OUT" "sentry=DIVERGED(tip 1000 ledger_hash BBBBBBBBBBBBBBBB != majority AAAAAAAAAAAAAAAA)"
ok "validator AGREE" has "$OUT" "validator=AGREE sentry=" && ok "public AGREE" has "$OUT" " public=AGREE"
ok "overall DIVERGED" has "$OUT" " DIVERGED tip=1000"
ok "re-query 1/2 printed" has "$ERR" "mismatch at tip 1000 (2 distinct hash sets), re-query 1/2 in 0s"
ok "re-query 2/2 printed" has "$ERR" "re-query 2/2"
ok "sentry asked 3 times for 1000" test "$(grep -c 'sentryc ledger-1000' "$T/stub/calls")" -eq 3
ok "metric sentry 1" has "$PROM" 'pft_divergence_state{source="sentry"} 1'
ok "metric validator 0" has "$PROM" 'pft_divergence_state{source="validator"} 0'
ok "metric overall 1" has "$PROM" 'pft_divergence_overall_state 1'
ok "last_agree_ledger kept at 990" has "$PROM" 'pft_divergence_last_agree_ledger 990'

case_ "3 transient public-RPC error that recovers -> AGREE, not DIVERGED"
fresh; rpcerr lgrNotFound > "$T/stub/public.test/ledger-1000.1.json"
run --sources "$SRC3"; show
ok "exit 0" test "$RC" -eq 0
ok "AGREE, retries=1" has "$OUT" " AGREE tip=1000 deep=800 retries=1 "
ok "retry printed" has "$ERR" "retry public ledger 1000 1/3 in 0s: lgrNotFound"
ok "metric public 0" has "$PROM" 'pft_divergence_state{source="public"} 0'
ok "metric retries 1" has "$PROM" 'pft_divergence_retries 1'

case_ "4 persistent public-RPC error -> UNKNOWN (public), others still AGREE"
fresh; rpcerr internal > "$T/stub/public.test/ledger-1000.json"
run --sources "$SRC3"; show
ok "exit 1" test "$RC" -eq 1
ok "public UNKNOWN with reason" has "$OUT" "public=UNKNOWN(tip ledger 1000: internal)"
ok "overall UNKNOWN" has "$OUT" " UNKNOWN tip=1000"
ok "validator, sentry AGREE" has "$OUT" "validator=AGREE sentry=AGREE"
ok "three retries then give up" has "$ERR" "giving up public ledger 1000 after 4 attempts: internal"
ok "retry 3/3 printed" has "$ERR" "retry public ledger 1000 3/3 in 0s: internal"
ok "metric public 2" has "$PROM" 'pft_divergence_state{source="public"} 2'
ok "metric overall 2" has "$PROM" 'pft_divergence_overall_state 2'

case_ "5 index outside complete_ledgers -> UNKNOWN for that source, no ledger query sent"
fresh; info 1001 "900-1001" > "$T/stub/sentryc/server_info.json"
run --sources "$SRC3"; show
ok "exit 1" test "$RC" -eq 1
ok "sentry UNKNOWN outside complete_ledgers" has "$OUT" "sentry=UNKNOWN(deep 800 outside complete_ledgers 900-1001)"
ok "sentry never asked for 800" test "$(grep -c 'sentryc ledger-800' "$T/stub/calls")" -eq 0
ok "validator, public AGREE" has "$OUT" "validator=AGREE" && ok "public AGREE" has "$OUT" "public=AGREE"
ok "metric sentry 2" has "$PROM" 'pft_divergence_state{source="sentry"} 2'

case_ "6 transient hash mismatch (wrong answer once) -> AGREE after re-query"
fresh; ledger 800 "$H2" > "$T/stub/public.test/ledger-800.1.json"
run --sources "$SRC3"; show
ok "exit 0" test "$RC" -eq 0
ok "AGREE" has "$OUT" " AGREE tip=1000"
ok "resolved on re-query 1" has "$ERR" "mismatch at deep 800 resolved on re-query 1"

case_ "7 two sources disagree, no majority -> both DIVERGED"
fresh; ledger 800 "$H1" "$H2" > "$T/stub/public.test/ledger-800.json"
run --sources "validator=docker:valc public=http:https://public.test/"; show
ok "exit 2" test "$RC" -eq 2
ok "validator DIVERGED on account_hash (no majority)" has "$OUT" "validator=DIVERGED(deep 800 account_hash CCCCCCCCCCCCCCCC != BBBBBBBBBBBBBBBB)"
ok "public DIVERGED too" has "$OUT" "public=DIVERGED(deep 800 account_hash BBBBBBBBBBBBBBBB != CCCCCCCCCCCCCCCC)"

case_ "8 public server_info times out on every try -> public UNKNOWN, the other two compared"
fresh; echo TIMEOUT > "$T/stub/public.test/server_info.json"
run --sources "$SRC3"; show
ok "exit 1" test "$RC" -eq 1
ok "public UNKNOWN no answer" has "$OUT" "public=UNKNOWN(server_info: no answer)"
ok "tip from the two that answered" has "$OUT" " UNKNOWN tip=1000 deep=800 retries=3 validator=AGREE sentry=AGREE"

case_ "9 only one source answers -> all UNKNOWN, nothing compared"
fresh; echo TIMEOUT > "$T/stub/public.test/server_info.json"; echo TIMEOUT > "$T/stub/sentryc/server_info.json"
run --sources "$SRC3"; show
ok "exit 1" test "$RC" -eq 1
ok "validator UNKNOWN fewer than 2" has "$OUT" "validator=UNKNOWN(fewer than 2 sources answered server_info)"
ok "no ledger queries" test "$(grep -c ledger- "$T/stub/calls")" -eq 0
ok "metric overall 2" has "$PROM" 'pft_divergence_overall_state 2'

case_ "10 not-validated / wrong-index answers are errors, not hashes"
fresh; printf '{"result":{"status":"success","validated":false,"ledger_index":1000,"ledger":{"ledger_hash":"%s","account_hash":"%s","transaction_hash":"%s"}}}' "$H2" "$AH" "$TH" \
  > "$T/stub/sentryc/ledger-1000.json"; ledger 799 "$H1" > "$T/stub/public.test/ledger-800.json"
run --sources "$SRC3"; show
ok "sentry UNKNOWN not validated" has "$OUT" "sentry=UNKNOWN(tip ledger 1000: ledger 1000 not validated)"
ok "public UNKNOWN wrong index" has "$OUT" "public=UNKNOWN(deep ledger 800: answered ledger 799 for 800)"
ok "no DIVERGED" test "$RC" -eq 1

case_ "11 --json output"
fresh; ledger 1000 "$H2" > "$T/stub/sentryc/ledger-1000.json"
run --sources "$SRC3" --json; show
ok "valid JSON, state DIVERGED" test "$(jq -r .state <<<"$OUT")" = DIVERGED
ok "3 sources, sentry DIVERGED" test "$(jq -r '[.sources[]|.state]|join(",")' <<<"$OUT")" = "AGREE,DIVERGED,AGREE"
ok "sentry tip hash in JSON" test "$(jq -r '.sources[1].tip_ledger_hash' <<<"$OUT")" = "$H2"

case_ "12 usage errors -> exit 3"
fresh; run --sources "validator=docker:valc"; ok "one source" test "$RC" -eq 3
run --sources "a=docker:x b=ftp:y"; ok "unknown kind" test "$RC" -eq 3
run --sources "a=docker:x a=docker:y"; ok "duplicate name" test "$RC" -eq 3
run --sources "a=docker:x;rm b=docker:y"; ok "shell metachar in container" test "$RC" -eq 3
run --sources "a=docker:x b=ssh:onlyhost"; ok "ssh without container" test "$RC" -eq 3
run --sources "$SRC3" --depth x; ok "non-numeric depth" test "$RC" -eq 3
run --sources "$SRC3" --check-config; ok "--check-config exits 0 and queries nothing" test "$RC" -eq 0 -a ! -s "$T/stub/calls"
ok "--check-config lists the ssh source" has "$OUT" "source sentry: ssh relayhost:sentryc"

printf '\nsuite: %d passed, %d failed (%s, sha256 %s)\n' "$pass" "$fail" "$(basename "$SCRIPT")" "$(sha256sum "$SCRIPT" | cut -c1-12)"
[ -n "${PFT_DIV_NO_MUTANTS:-}" ] && exit $(( fail > 0 ))

mutant() { # name sed-expr expected-failing-case
  local m="$T/mutant-$1.sh"
  sed "$2" "$SCRIPT" > "$m"
  if cmp -s "$SCRIPT" "$m"; then echo "FAIL mutation $1 did not apply"; return 1; fi
  PFT_DIV_NO_MUTANTS=1 bash "${BASH_SOURCE[0]}" "$m" > "$T/m.out" 2>&1 && { echo "FAIL mutant $1 passed the suite"; return 1; }
  if grep -q "FAIL .*\[$3" "$T/m.out"; then
    echo "caught mutant $1: $(grep -c '  FAIL ' "$T/m.out") failing checks, incl. case '$3':"
    grep '  FAIL ' "$T/m.out" | sed 's/^/    /' | head -4
  else echo "FAIL mutant $1 failed, but not in case $3"; return 1; fi
}
printf '\n== mutation controls (the suite must FAIL on each)\n'
mfail=0
# shellcheck disable=SC2016  # sed patterns match literal $vars in the script
mutant no-requery 's/\[ "\$c" -lt "\$CONFIRM" \] || break/break/' "6 transient hash mismatch" || mfail=1
# shellcheck disable=SC2016
mutant no-retry 's/if \[ "\$n" -ge "\${#WAITS\[@\]}" \]; then/if true; then/' "3 transient public-RPC error" || mfail=1
[ "$fail" -eq 0 ] && [ "$mfail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "FAILED"; exit 1
