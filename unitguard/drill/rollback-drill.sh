#!/usr/bin/env bash
# Live auto-rollback drill: re-apply UNIT with a deliberately broken copy of its profile over the working unitguard
# drop-in, and prove pft-unitguard puts the working drop-in back (byte-identical) and the unit runs again.
# Default break: drop the User=/Group= lines (the mistake probe run 1 caught for pft-logship-vacuum: root with an
# empty CapabilityBoundingSet cannot read the 0640 journal files, so the unit fails).
# Usage: sudo bash drill/rollback-drill.sh [UNIT (pft-logship-vacuum.service)] [SED_BREAK ('/^\(User\|Group\)=/d')]
# Exit 0 = every assertion PASS. Needs the working drop-in already applied. Changes nothing on success.
# assert expressions are single-quoted on purpose (eval'd later); arc is read inside one of them.
# shellcheck disable=SC2016,SC2034
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
U="${1:-pft-logship-vacuum.service}"
BREAK="${2:-/^\(User\|Group\)=/d}"
DP="/etc/systemd/system/$U.d/50-unitguard.conf"
fails=0
assert() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }
[ -f "$DP" ] || { echo "no working drop-in at $DP - apply first"; exit 3; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp "$HERE/profiles/$U.conf" "$W/"
sed -i "$BREAK" "$W/$U.conf"
echo "broken profile: $U.conf with sed '$BREAK' (diff vs the real profile):"
diff "$HERE/profiles/$U.conf" "$W/$U.conf"
before="$(sha256sum "$DP" | cut -d' ' -f1)"
echo "working drop-in sha256 before: $before"
bash "$HERE/pft-unitguard.sh" audit --units "${U%.service}" | tail -1
echo "\$ PROFILE_DIR=<tmp broken copy> pft-unitguard.sh apply $U"
PROFILE_DIR="$W" bash "$HERE/pft-unitguard.sh" apply "$U"; rc=$?
echo "apply exit $rc"
after="$(sha256sum "$DP" 2>/dev/null | cut -d' ' -f1)"
echo "working drop-in sha256 after:  ${after:-<missing>}"
assert "apply refused the broken profile (exit 1)" '[ "$rc" = 1 ]'
assert "working drop-in restored byte-identical" '[ "$before" = "$after" ]'
assert "no broken directives left in the drop-in" 'grep -q "^User=" "$DP" || ! grep -q "^User=" "$HERE/profiles/$U.conf"'
assert "unit re-run after rollback ends Result=success" '[ "$(systemctl show -p Result --value "$U")" = success ]'
assert "no leftover .prev backup" '[ -z "$(ls /var/lib/pft-unitguard/*.prev 2>/dev/null)" ]'
echo "\$ pft-unitguard.sh audit --units ${U%.service}"
bash "$HERE/pft-unitguard.sh" audit --units "${U%.service}"; arc=$?
assert "audit after: drop-in installed and meets its target (exit 0)" '[ "$arc" = 0 ]'
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo "FAIL ($fails)")"
[ "$fails" = 0 ]
