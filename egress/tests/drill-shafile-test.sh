#!/usr/bin/env bash
# Regression test for the drills' notifier backup bookkeeping (no root, no network, nothing outside a temp dir).
# Bug found in the validator live drill 2026-10-26: shafile() keyed on the parent dir name, so /etc/pft-integrity.env
# and /etc/postfiat-monitor.env shared one sha file and the restore check printed NO for both.
# 1  shafile() from each drill script gives a distinct name for every notifier env path the drills redirect
# 2  redirect + restore loop (same commands as the drills, paths under a temp dir) restores byte-identical files
#    and the per-file sha check says yes for each. Run: bash tests/drill-shafile-test.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 3
pass=0; fail=0
ok() { if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "ok   $3"; else fail=$((fail+1)); echo "FAIL $3 (got '$1', want '$2')"; fi; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
for s in drill-sentry.sh drill-rollback.sh; do
  eval "$(grep -E '^shafile\(\)' "$s" | sed "s|/run/|$T/run-|")"
  names="$(for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/postfiat-monitor.env /etc/pft-maint/ntfy.env; do shafile "$f"; done)"
  ok "$(sort -u <<<"$names" | wc -l)" 4 "$s: 4 notifier paths -> 4 distinct sha files"
  mkdir -p "$T/etc/pft-watchdog"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=real-a\nNODE_LABEL=x\n' > "$T/etc/pft-integrity.env"
  printf 'NTFY_TOPIC=real-b\nNTFY_SERVER=https://ntfy.sh\nREMIND_MINUTES=60\n' > "$T/etc/postfiat-monitor.env"
  printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=real-c\n' > "$T/etc/pft-watchdog/ntfy.env"
  ENVS=("$T/etc/pft-watchdog/ntfy.env" "$T/etc/pft-integrity.env" "$T/etc/postfiat-monitor.env")
  orig="$(cat "${ENVS[@]}" | sha256sum)"
  for f in "${ENVS[@]}"; do sf="$(shafile "$f")"; sha256sum < "$f" > "$sf"; cp -p "$f" "$f.pre-egress-drill"
    { grep -vE '^(NTFY_TOPIC|NTFY_TOKEN|NTFY_SERVER|NTFY_URL)=' "$f.pre-egress-drill" || true
      printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=throwaway\n'; } > "$f"; done
  ok "$(cat "${ENVS[@]}" | grep -c '^NTFY_TOPIC=throwaway$')" 3 "$s: all 3 redirected"
  ok "$(grep -c '^REMIND_MINUTES=60$' "$T/etc/postfiat-monitor.env")" 1 "$s: non-NTFY settings kept during redirect"
  res=""; for f in "${ENVS[@]}"; do mv -f "$f.pre-egress-drill" "$f"
    res="$res$([ "$(sha256sum < "$f")" = "$(cat "$(shafile "$f")")" ] && echo yes || echo NO) "; rm -f "$(shafile "$f")"; done
  ok "$res" "yes yes yes " "$s: per-file sha check after restore"
  ok "$(cat "${ENVS[@]}" | sha256sum)" "$orig" "$s: restored bytes identical"
  rm -rf "${T:?}/etc" "${T:?}"/run-*
done
echo "drill-shafile-test: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
