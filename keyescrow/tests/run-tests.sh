#!/usr/bin/env bash
# Offline tests for `pft-keyescrow inventory` against a fake root (PFT_KEYESCROW_ROOT): every inventory state
# (ok/perm/missing/absent/unreadable, symlink, bad machine-id), host filtering, escrow drift (same/drift/new, never),
# --json, --textfile (values, atomic write), exit codes, zero secret bytes in any output (with positive controls),
# and that every citation of the built-in registry still names its path in the cited source line.
# No root, no network. Temp files go under TEST_TMPDIR (default ~/.cache): /tmp is noexec on hosts hardened by ../mounts.
# Usage: bash keyescrow/tests/run-tests.sh [path/to/pft-keyescrow.sh]
# shellcheck disable=SC2016,SC2034,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-keyescrow.sh}"
REPO="$(cd "$HERE/../.." && pwd)"
BASE="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$BASE"
T="$(mktemp -d "$BASE/pft-keyescrow-tests.XXXXXX")"; trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -20; return 0; }
check() { local name="$1"; shift; if ( eval "$*" ) >/dev/null 2>&1; then ok "$name"; else bad "$name" "$OUT"; fi; }
ME="$(id -un)"; MYG="$(id -gn)"
MID=0123456789abcdef0123456789abcdef
SECRET_MARK="sKEYESCROWTESTSECRET$RANDOM$RANDOM"

# A test registry: same shape as the built-in one, owned by the test user.
fresh() { # [HOST_LABEL]
  N=$((N + 1)); E="$T/e$N"; mkdir -p "$E/root/etc" "$E/root/var/lib/pft-exporter/textfile"
  printf '%s\n' "$MID" > "$E/root/etc/machine-id"
  printf 'HOST_LABEL=%s\n' "${1:-validator}" > "$E/root/etc/pft-keyescrow.env"
  cat > "$E/registry.tsv" <<REG
a:seed	both	/var/lib/a/seed	600	$ME	$MYG	req	x:1
a:key	both	/etc/a/host.key	640	$ME	-	req	x:2
j:fss	both	/var/log/journal/@MID@/fss	600	$ME	$MYG	req	x:3
v:only	validator	/etc/v.env	600	$ME	$MYG	req	x:4
s:only	sentry	/etc/s.env	600	$ME	$MYG	req	x:5
o:opt	both	/etc/o/ntfy.env	600	$ME	$MYG	opt	x:6
REG
  export PFT_KEYESCROW_ROOT="$E/root" PFT_KEYESCROW_REGISTRY="$E/registry.tsv"
  unset PFT_KEYESCROW_CONF STATE_DIR TEXTFILE_DIR
}
put() { # PATH MODE [CONTENT]: create a file under the fake root
  mkdir -p "$(dirname "$E/root$1")"; printf '%s\n' "${3:-$SECRET_MARK $1}" > "$E/root$1"; chmod "$2" "$E/root$1"
}
populate() { put /var/lib/a/seed 600; put /etc/a/host.key 640; put "/var/log/journal/$MID/fss" 600; put /etc/v.env 600; put /etc/s.env 600; }
run() { OUT="$(timeout 30 bash "$TOOL" "$@" 2>&1)"; RC=$?; }
row() { grep -E "^  \[[a-z]+\] +$1 " <<<"$OUT"; }
state_of() { row "$1" | sed -E 's/^  \[([a-z]+)\].*/\1/'; }
escrow_of() { row "$1" | sed -E 's/.* escrow ([a-z-]+) .*/\1/'; }
fpkey() { mkdir -p "$E/root/var/lib/pft-keyescrow"; printf '%064d\n' 7 > "$E/root/var/lib/pft-keyescrow/fp_key"; chmod 600 "$E/root/var/lib/pft-keyescrow/fp_key"; }
fp_of() { row "$1" | sed -E 's/.* fp ([0-9a-f]{16}|n\/a) .*/\1/'; }

# --- bare host: every required item missing ------------------------------------------------------------------
fresh; run inventory
check "bare: exit 2" '[ "$RC" = 2 ]'
check "bare: required items missing" '[ "$(state_of a:seed)" = missing ] && [ "$(state_of j:fss)" = missing ] && [ "$(state_of v:only)" = missing ]'
check "bare: optional item absent, not missing" '[ "$(state_of o:opt)" = absent ]'
check "bare: result line counts" 'grep -q "^RESULT: ok 0, perm 0, missing 4, unreadable 0, absent(optional) 1; escrow drift 0, new 0, evolving 0 -> exit 2$" <<<"$OUT"'
check "bare: last escrow never" 'grep -q "| last escrow never$" <<<"$OUT"'

# --- host filter ---------------------------------------------------------------------------------------------
check "validator: sentry-only item not listed" '! row s:only'
fresh sentry; run inventory
check "sentry: validator-only item not listed, sentry-only listed" '! row v:only && row s:only'

# --- all present, no fp_key, never escrowed --------------------------------------------------------------------
fresh; populate; run inventory
check "present: exit 1 (never escrowed)" '[ "$RC" = 1 ]'
check "present: all ok" '[ "$(state_of a:seed)" = ok ] && [ "$(state_of a:key)" = ok ] && [ "$(state_of j:fss)" = ok ] && [ "$(state_of v:only)" = ok ]'
check "present: no fp_key -> fp n/a, escrow new" '[ "$(fp_of a:seed)" = n/a ] && [ "$(escrow_of a:seed)" = new ]'
check "present: counts" 'grep -q "^RESULT: ok 4, perm 0, missing 0, unreadable 0, absent(optional) 1; escrow drift 0, new 4, evolving 0 -> exit 1$" <<<"$OUT"'
check "present: owners never printed" '! grep -qw "$ME" <<<"$OUT"'

# --- perm findings ---------------------------------------------------------------------------------------------
fresh; populate; chmod 644 "$E/root/var/lib/a/seed"; run inventory
check "mode 644 (want 600): perm, exit 2" '[ "$RC" = 2 ] && [ "$(state_of a:seed)" = perm ] && row a:seed | grep -q "mode 644 (want 600), owner ok, group ok"'
fresh; populate; sed -i "1s/\t$ME\t/\troot\t/" "$E/registry.tsv"; run inventory
check "owner differs: perm, owner BAD, name not printed" '[ "$RC" = 2 ] && row a:seed | grep -q "owner BAD, group ok" && ! grep -qw root <<<"$(row a:seed)"'
fresh; populate; sed -i "1s/\t$MYG\treq/\tsystemd-journal-remote\treq/" "$E/registry.tsv"; run inventory
check "group differs: perm, group BAD" '[ "$RC" = 2 ] && row a:seed | grep -q "owner ok, group BAD"'
check "group '-' is not checked (a:key)" '[ "$(state_of a:key)" = ok ]'
fresh; populate; rm "$E/root/etc/v.env"; ln -s "$E/root/etc/s.env" "$E/root/etc/v.env"; run inventory
check "symlink: perm 'not a regular file'" '[ "$RC" = 2 ] && row v:only | grep -q "not a regular file"'
fresh; populate; mkdir -p "$E/root/etc/o/ntfy.env"; run inventory
check "directory in place of an optional file: perm" '[ "$(state_of o:opt)" = perm ]'

# --- unreadable (mode matches the registry, but the caller cannot read it) ---------------------------------------
fresh; populate; sed -i "1s/\t600\t/\t000\t/" "$E/registry.tsv"; chmod 000 "$E/root/var/lib/a/seed"; run inventory
if [ "$(id -u)" = 0 ]; then ok "unreadable: skipped (root reads mode 000)"; else
  check "unreadable: state + exit 2, no fingerprint" '[ "$RC" = 2 ] && [ "$(state_of a:seed)" = unreadable ] && [ "$(fp_of a:seed)" = n/a ]'
fi

# --- machine-id ------------------------------------------------------------------------------------------------
fresh; populate; echo "not-an-id" > "$E/root/etc/machine-id"; run inventory
check "bad machine-id: fss missing (no path guessed), exit 2" '[ "$RC" = 2 ] && [ "$(state_of j:fss)" = missing ]'

# --- escrow state: fingerprints, same / drift / new ---------------------------------------------------------------
fresh; populate; fpkey; run inventory
FP_SEED="$(fp_of a:seed)"
check "fp_key: 16-hex fingerprints" '[[ "$FP_SEED" =~ ^[0-9a-f]{16}$ ]]'
check "fingerprint is keyed: differs from sha256(file)" '[ "$FP_SEED" != "$(sha256sum < "$E/root/var/lib/a/seed" | cut -c1-16)" ]'
check "fingerprint = sha256(fp_key || file)" '[ "$FP_SEED" = "$({ cat "$E/root/var/lib/pft-keyescrow/fp_key"; cat "$E/root/var/lib/a/seed"; } | sha256sum | cut -c1-16)" ]'
{ echo "# escrowed_at=1790000000"; for id in a:seed a:key j:fss v:only; do printf '%s\t%s\n' "$id" "$(fp_of "$id")"; done; } > "$E/root/var/lib/pft-keyescrow/escrowed.tsv"
run inventory
check "escrowed + unchanged: exit 0, all same" '[ "$RC" = 0 ] && [ "$(escrow_of a:seed)" = same ] && [ "$(escrow_of v:only)" = same ]'
check "last escrow time printed (UTC)" 'grep -q "| last escrow 2026-09-21T14:13:20Z$" <<<"$OUT"'
printf 'x' >> "$E/root/var/lib/a/seed"; run inventory
check "one byte appended: drift, exit 1" '[ "$RC" = 1 ] && [ "$(escrow_of a:seed)" = drift ] && [ "$(escrow_of a:key)" = same ]'
check "drift counted" 'grep -q "escrow drift 1, new 0, evolving 0 -> exit 1$" <<<"$OUT"'
# evolving items (conf EVOLVING): journald rewrites the FSS sealing key in place every seal interval
fresh; populate; fpkey; run inventory
{ echo "# escrowed_at=1790000000"; for id in a:seed a:key j:fss v:only; do printf '%s\t%s\n' "$id" "$(fp_of "$id")"; done; } > "$E/root/var/lib/pft-keyescrow/escrowed.tsv"
printf 'evolved' >> "$E/root/var/log/journal/$MID/fss"; run inventory --textfile
check "evolving control: without EVOLVING a changed j:fss is drift" '[ "$RC" = 1 ] && [ "$(escrow_of j:fss)" = drift ]'
printf 'EVOLVING=x:other j:fss\n' >> "$E/root/etc/pft-keyescrow.env"; run inventory --textfile
check "EVOLVING item changed: escrow evolving, not drift, exit 0" '[ "$RC" = 0 ] && [ "$(escrow_of j:fss)" = evolving ] && grep -q "escrow drift 0, new 0, evolving 1 -> exit 0$" <<<"$OUT"'
check "EVOLVING item changed: textfile drift_items 0" 'grep -qx "pft_keyescrow_drift_items{node=\"validator\"} 0" "$E/root/var/lib/pft-exporter/textfile/pft_keyescrow.prom"'
printf 'x' >> "$E/root/var/lib/a/seed"; run inventory
check "EVOLVING does not hide drift of other items" '[ "$RC" = 1 ] && [ "$(escrow_of a:seed)" = drift ] && [ "$(escrow_of j:fss)" = evolving ] && grep -q "escrow drift 1, new 0, evolving 1 -> exit 1$" <<<"$OUT"'
sed -i '/^j:fss/d' "$E/root/var/lib/pft-keyescrow/escrowed.tsv"; run inventory
check "EVOLVING item never escrowed: still new" '[ "$(escrow_of j:fss)" = new ] && grep -q "new 1, evolving 0" <<<"$OUT"'
printf 'EVOLVING=j:fs xj:fss\n' >> "$E/root/etc/pft-keyescrow.env"; printf 'j:fss\t0000000000000000\n' >> "$E/root/var/lib/pft-keyescrow/escrowed.tsv"; run inventory
check "EVOLVING matches whole ids only (j:fs and xj:fss do not cover j:fss)" '[ "$(escrow_of j:fss)" = drift ]'
sed -i '/^EVOLVING=/d' "$E/root/etc/pft-keyescrow.env"; sed -i 's/^j:fss\t/journald:fss\t/' "$E/registry.tsv" "$E/root/var/lib/pft-keyescrow/escrowed.tsv"; run inventory
check "default EVOLVING (no conf line) is journald:fss" '[ "$(escrow_of journald:fss)" = evolving ]'
fresh; populate; fpkey; run inventory
{ echo "# escrowed_at=1790000000"; for id in a:seed a:key j:fss v:only; do printf '%s\t%s\n' "$id" "$(fp_of "$id")"; done; } > "$E/root/var/lib/pft-keyescrow/escrowed.tsv"
sed -i '/^v:only/d' "$E/root/var/lib/pft-keyescrow/escrowed.tsv"; run inventory
check "item missing from the escrow manifest: new" '[ "$(escrow_of v:only)" = new ]'
sed -i 's/^# escrowed_at=.*/# escrowed_at=soon/' "$E/root/var/lib/pft-keyescrow/escrowed.tsv"; run inventory
check "garbage escrowed_at: treated as never" 'grep -q "| last escrow never$" <<<"$OUT" && [ "$RC" = 1 ]'

# --- --json ------------------------------------------------------------------------------------------------------
fresh; populate; fpkey; run inventory --json
check "json: valid, host, exit" 'jq -e ".host == \"validator\" and .exit == 1 and .last_escrow_epoch == 0" <<<"$OUT"'
check "json: one object per applicable item" '[ "$(jq ".items | length" <<<"$OUT")" = 5 ]'
check "json: item fields" 'jq -e ".items[] | select(.id == \"a:seed\") | .state == \"ok\" and .escrow == \"new\" and (.fingerprint | test(\"^[0-9a-f]{16}$\")) and .cite == \"x:1\"" <<<"$OUT"'
check "json: optional absent item" 'jq -e ".items[] | select(.id == \"o:opt\") | .state == \"absent\" and .need == \"opt\"" <<<"$OUT"'
chmod 644 "$E/root/etc/v.env"; run inventory --json
check "json: perm finding carries exit 2 and detail" '[ "$RC" = 2 ] && jq -e ".exit == 2 and (.items[] | select(.id == \"v:only\") | .state == \"perm\" and (.detail | test(\"mode 644\")))" <<<"$OUT"'

# --- --textfile --------------------------------------------------------------------------------------------------
fresh; populate; fpkey; chmod 644 "$E/root/etc/v.env"; run inventory --textfile
P="$E/root/var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "textfile: written, 0644" '[ -f "$P" ] && [ "$(stat -c %a "$P")" = 644 ]'
check "textfile: state counts" 'grep -qx "pft_keyescrow_items{node=\"validator\",state=\"ok\"} 3" "$P" && grep -qx "pft_keyescrow_items{node=\"validator\",state=\"perm\"} 1" "$P" && grep -qx "pft_keyescrow_items{node=\"validator\",state=\"absent\"} 1" "$P"'
check "textfile: drift items (never escrowed = 4 new)" 'grep -qx "pft_keyescrow_drift_items{node=\"validator\"} 4" "$P"'
check "textfile: last escrow 0, exit code 2" 'grep -qx "pft_keyescrow_last_escrow_timestamp_seconds{node=\"validator\"} 0" "$P" && grep -qx "pft_keyescrow_inventory_exit_code{node=\"validator\"} 2" "$P"'
check "textfile: collect timestamp recent" '[ $(( $(date -u +%s) - $(sed -n "s/^pft_keyescrow_collect_timestamp_seconds{node=\"validator\"} //p" "$P") )) -lt 60 ]'
check "textfile: no temp file left" '[ -z "$(find "$E/root/var/lib/pft-exporter/textfile" -name ".pft_keyescrow*")" ]'
check "textfile: every sample line has a HELP'd metric" '[ "$(grep -c "^# HELP" "$P")" = 5 ]'
chmod 555 "$E/root/var/lib/pft-exporter/textfile"; run inventory --textfile
if [ "$(id -u)" = 0 ]; then ok "textfile dir not writable: skipped as root"; else
  check "textfile dir not writable: exit 2, named" '[ "$RC" = 2 ] && grep -q "cannot write" <<<"$OUT"'
fi
chmod 755 "$E/root/var/lib/pft-exporter/textfile"

# --- zero secret bytes in any output (with positive controls) -----------------------------------------------------
fresh; populate; fpkey
ALL="$(bash "$TOOL" inventory 2>&1; bash "$TOOL" inventory --json 2>&1; bash "$TOOL" inventory --textfile 2>&1; cat "$E/root/var/lib/pft-exporter/textfile/pft_keyescrow.prom")"
check "positive control: the marker is in the secret files" 'grep -rqF "$SECRET_MARK" "$E/root/var/lib/a" "$E/root/etc/v.env"'
check "positive control: a grep for the marker finds it in a string that has it" 'grep -qF "$SECRET_MARK" <<<"x $SECRET_MARK y"'
check "no secret bytes in text, json, textfile output" '! grep -qF "$SECRET_MARK" <<<"$ALL"'
check "fp_key bytes never printed" '! grep -qF "$(cat "$E/root/var/lib/pft-keyescrow/fp_key")" <<<"$ALL"'

# --- usage -------------------------------------------------------------------------------------------------------
fresh; run inventory --bogus
check "unknown option: exit 3" '[ "$RC" = 3 ] && grep -q "unknown option --bogus" <<<"$OUT"'
printf 'HOST_LABEL=relay\n' > "$E/root/etc/pft-keyescrow.env"; run inventory
check "bad HOST_LABEL: exit 3" '[ "$RC" = 3 ] && grep -q "HOST_LABEL must be validator or sentry" <<<"$OUT"'
run; check "no command: exit 3 + usage" '[ "$RC" = 3 ] && grep -q "Usage: pft-keyescrow inventory" <<<"$OUT"'

# --- the built-in registry: shape and source citations --------------------------------------------------------------
unset PFT_KEYESCROW_REGISTRY
REGTXT="$(sed -n "/^  cat <<'REG'$/,/^REG$/p" "$TOOL" | sed '1d;$d')"
check "registry: 15 rows, 8 tab-separated fields each" '[ "$(wc -l <<<"$REGTXT")" = 15 ] && [ "$(awk -F"\t" "NF != 8" <<<"$REGTXT" | wc -l)" = 0 ]'
check "registry: unique ids" '[ -z "$(cut -f1 <<<"$REGTXT" | sort | uniq -d)" ]'
check "registry: modes are 3 octal digits, need is req|opt, hosts both|validator|sentry" '[ "$(awk -F"\t" "\$4 !~ /^[0-7][0-7][0-7]\$/ || \$7 !~ /^(req|opt)\$/ || \$2 !~ /^(both|validator|sentry)\$/" <<<"$REGTXT" | wc -l)" = 0 ]'
while IFS=$'\t' read -r id _ path _ _ _ _ cite; do
  f="${cite%:*}"; l="${cite##*:}"; want="$(basename "$path")"
  [ "$path" = "@ALERTS@" ] && want=NTFY_ENV_FILE
  src="$(sed -n "${l}p" "$REPO/$f" 2>/dev/null)"
  if [ -n "$src" ] && grep -qF -- "$want" <<<"$src"; then ok "cite $id: $cite names $want"
  else bad "cite $id: $cite does not name $want" "$src"; fi
done <<<"$REGTXT"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
