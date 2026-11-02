# Sourced by run-tests.sh (uses its fresh/run/expect/avc/ok/ko, $E, $NOW). ack-denials: a drill's deliberate DENIED
# records are acknowledged up to a time; later records still count; a bad ack file never hides anything.
# shellcheck shell=bash disable=SC2016,SC2015
ACKF() { echo "$E/root/var/lib/pft-apparmor/denials-ack.json"; }

fresh; avc $((NOW - 100)) DENIED pft-postfiatd open /etc/gshadow; avc $((NOW - 40)) DENIED pft-postfiatd exec /usr/bin/id
run audit; expect "ack: before, 2 DENIED -> WARN" denials WARN "^  \[WARN\] denials +2 DENIED"
run ack-denials --reason "drill negative controls" --until $((NOW - 50))
[ "$RC" = 4 ] && [ ! -e "$(ACKF)" ] && ok "ack: refused without --yes, nothing written" || ko "ack no yes: rc=$RC" "$OUT"
run ack-denials --reason "drill negative controls" --until $((NOW - 50)) --yes
[ "$RC" = 0 ] && grep -q ': 1 DENIED record(s) for pft-postfiatd after 0 up to' <<<"$OUT" \
  && [ "$(jq -c '{profile, until, records, reason}' "$(ACKF)")" = "{\"profile\":\"pft-postfiatd\",\"until\":$((NOW - 50)),\"records\":1,\"reason\":\"drill negative controls\"}" ] \
  && ok "ack: 1 record up to --until acknowledged, file written" || ko "ack: rc=$RC" "$OUT"
run audit; expect "ack: the record after --until still counts (WARN 1)" denials WARN "^  \[WARN\] denials +1 DENIED.*exec /usr/bin/id x1.*acknowledged: drill negative controls"
run ack-denials --reason "second" --until $((NOW - 60)) --yes
[ "$RC" = 4 ] && grep -q 'already acknowledged' <<<"$OUT" && ok "ack: an --until not after the last ack is refused" || ko "ack older: rc=$RC" "$OUT"
run ack-denials --reason "second" --yes
[ "$RC" = 0 ] && grep -q ': 1 DENIED record(s) for pft-postfiatd after '$((NOW - 50))' up to '"$NOW" <<<"$OUT" \
  && ok "ack: default --until is now; counts only records after the previous ack" || ko "ack second: rc=$RC" "$OUT"
run audit
[ "$RC" = 0 ] && expect "ack: all acknowledged -> PASS, reason shown" denials PASS "0 DENIED.*acknowledged: second" || ko "ack audit: rc=$RC" "$OUT"
run audit --json
[ "$(jq -r '.denied_acknowledged_until' <<<"$OUT")" = "$NOW" ] && ok "ack: --json carries denied_acknowledged_until" || ko "ack json" "$OUT"

fresh; avc $((NOW - 100)) DENIED pft-postfiatd open /etc/gshadow
run ack-denials --reason x --until $((NOW + 100)) --yes; [ "$RC" = 3 ] && ok "ack: --until in the future refused" || ko "ack future: rc=$RC" "$OUT"
run ack-denials --reason x --until abc --yes; [ "$RC" = 3 ] && ok "ack: non-numeric --until refused" || ko "ack abc: rc=$RC" "$OUT"
run ack-denials --yes; [ "$RC" = 3 ] && grep -q -- '--reason' <<<"$OUT" && ok "ack: --reason required" || ko "ack no reason: rc=$RC" "$OUT"
run ack-denials --reason "$(printf 'a\nb')" --yes; [ "$RC" = 3 ] && ok "ack: non-printable reason refused" || ko "ack nl: rc=$RC" "$OUT"
run ack-denials --reason "$(printf '%0201d' 0)" --yes; [ "$RC" = 3 ] && ok "ack: reason over 200 chars refused" || ko "ack long: rc=$RC" "$OUT"
[ ! -e "$(ACKF)" ] && ok "ack: refused calls wrote nothing" || ko "ack refused wrote" "$(cat "$(ACKF)")"
if [ "$(id -u)" != 0 ]; then
  OUT="$(env -u PFT_AA_ROOT bash "$TOOL" ack-denials --reason x --yes 2>&1)"; RC=$?
  [ "$RC" = 4 ] && grep -q 'needs root' <<<"$OUT" && ok "ack: needs root on a real host" || ko "ack root: rc=$RC" "$OUT"
fi

# a bad ack file hides nothing and is a finding of its own
for bad in 'garbage' '[]' '{"profile":"pft-postfiatd","until":"1793600000","reason":"x"}' \
  '{"profile":"pft-other","until":1793600000,"reason":"x"}' '{"profile":"pft-postfiatd","until":1793600000}'; do
  fresh; avc $((NOW - 100)) DENIED pft-postfiatd open /etc/gshadow; mkdir -p "$(dirname "$(ACKF)")"; printf '%s\n' "$bad" > "$(ACKF)"
  run audit
  expect "bad ack file ${bad:0:30}: denials-ack FAIL" denials-ack FAIL "malformed"
  expect "bad ack file ${bad:0:30}: the DENIED record still counts" denials WARN "1 DENIED"
done
fresh; avc $((NOW - 100)) DENIED pft-postfiatd open /etc/gshadow; mkdir -p "$(dirname "$(ACKF)")"
printf '{"profile":"pft-postfiatd","until":%s,"reason":"old"}\n' $((NOW - 90000)) > "$(ACKF)"; run audit
expect "ack older than the audit window: no effect, no note" denials WARN "1 DENIED event\(s\) in the last 86400s: open /etc/gshadow x1$"
