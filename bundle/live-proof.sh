#!/usr/bin/env bash
# live-proof.sh CONTAINER LABEL - live proof for pft-bundle on this host (run as root from the repo root):
#   node state + pft-integrity before, collect, verify, then count how often each real identity (hostname,
#   global addresses, ntfy topics/tokens) appears in the raw collection and in the extracted bundle.
#   Only counts and labels are printed, never the values. A planted control line proves the counter works.
#   Node state + integrity after must match. The bundle and raw copy are deleted at the end.
set -uo pipefail
C="${1:-postfiatd}" L="${2:-validator-host}"
export TZ=UTC
echo "== pft-bundle live proof $(date -u +%FT%TZ) | OS: $(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release) | container: $C | label: $L"
echo "== script sha256: pft-bundle.sh $(sha256sum bundle/pft-bundle.sh | cut -c1-16) sanitize.py $(sha256sum bundle/sanitize.py | cut -c1-16) live-proof.sh $(sha256sum "$0" | cut -c1-16)"
nodestate() {
  local s
  s="$(timeout 20 docker exec "$C" curl -s --max-time 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 |
       jq -r '.result.info.server_state')"
  echo "server_state=$s $(docker inspect -f 'status={{.State.Status}} started={{.State.StartedAt}} restarts={{.RestartCount}}' "$C")"
}
integ() { pft-integrity verify 2>&1 | grep '^RESULT'; }

echo "-- before"
S1="$(nodestate)"; I1="$(integ)"; echo "$S1"; echo "pft-integrity: $I1"

W="$(mktemp -d /var/tmp/pft-bundle-proof.XXXXXX)"; chmod 700 "$W"
trap 'rm -rf "$W"' EXIT
echo "+ bash bundle/pft-bundle.sh collect --container $C --label $L --out $W --keep-raw $W/raw"
bash bundle/pft-bundle.sh collect --container "$C" --label "$L" --out "$W" --keep-raw "$W/raw"; rc=$?
echo "collect exit=$rc"
B="$(ls "$W"/*.tar.gz 2>/dev/null)"
[ -n "$B" ] || { echo "RESULT: FAIL no bundle"; exit 2; }
echo "+ bash bundle/pft-bundle.sh verify $B"
bash bundle/pft-bundle.sh verify "$B"; vrc=$?
echo "verify exit=$vrc"
mkdir "$W/x" && tar -xzf "$B" -C "$W/x"

echo "-- identity hit counts (case-insensitive fixed-string grep -o over every file; values never printed)"
ids=() labels=()
add() { local v="$2" i; [ -n "$v" ] || return 0; for i in "${ids[@]}"; do [ "$i" = "$v" ] && return 0; done
        ids+=("$v"); labels+=("$1"); }
for h in "$(hostname)" "$(hostname -f)"; do add hostname "$h"; done
n=0; while read -r ip; do n=$((n+1)); add "public-ip-$n" "${ip%/*}"; done < <(ip -o addr show scope global |
  awk '$2 !~ /^(docker|br-|veth)/ {print $4}')
n=0; while IFS= read -r v; do [ -n "$v" ] || continue; n=$((n+1)); add "ntfy-value-$n" "$v"; done < <(
  grep -hE '^NTFY_(TOPIC|TOKEN|URL)=' /etc/*.env /etc/*/*.env 2>/dev/null |
  sed 's/^NTFY_URL=.*\/\([^/]*\)$/\1/; s/^NTFY_[A-Z]*=//; s/^["'\'']//; s/["'\'']$//' | sort -u)
fail=0
for i in "${!ids[@]}"; do
  v="${ids[$i]}"
  raw="$(grep -rFoi -- "$v" "$W/raw" | wc -l)"
  bun="$(grep -rFoi -- "$v" "$W/x" | wc -l)"
  printf 'control line: x %s x\n' "$v" >"$W/control.txt"
  ctl="$(grep -Foi -- "$v" "$W/control.txt" | wc -l)"
  printf '  %-14s raw_hits=%-4s bundle_hits=%-3s control_hits=%s\n' "${labels[$i]}" "$raw" "$bun" "$ctl"
  [ "$bun" = 0 ] && [ "$ctl" = 1 ] || fail=1
done
rm -f "$W/control.txt"
echo "-- bundle files: $(find "$W/x" -type f | wc -l), size $(stat -c %s "$B") bytes"

echo "-- after"
S2="$(nodestate)"; I2="$(integ)"; echo "$S2"; echo "pft-integrity: $I2"
if [ "$S1" = "$S2" ]; then echo "PASS node state unchanged"; else echo "FAIL node state changed"; fail=1; fi
if [ "$I1" = "$I2" ] && [ "${I2#RESULT: PASS}" != "$I2" ]; then echo "PASS integrity PASS before and after"
else echo "FAIL integrity"; fail=1; fi
[ "${S2%% *}" = server_state=full ] || { echo "FAIL not full"; fail=1; }
[ "$rc" = 0 ] && [ "$vrc" = 0 ] || fail=1
echo "RESULT: $([ $fail = 0 ] && echo PASS || echo FAIL) live proof on $L"
exit $fail
