#!/usr/bin/env bash
# Offline tests for keygen / set-peer / seal / serve / escrow / verify with the REAL age binary and two fake hosts
# (validator root VA, sentry root SE). PEER_SSH is a stub that runs the sentry's copy of the tool against SE, so the
# whole two-way flow (seal, push, receive + in-memory check, ack, peer seal, export, pull, verify) runs end to end.
# Covers: secrets never printed or written in plaintext (positive controls), refusals (no peer, bad inventory,
# wrong recipient, own label, unknown verb, foreign/odd envelopes), one-byte tamper of ciphertext, a re-hashed
# tamper (age authentication catches it), generation pruning (KEEP), drift after a change; restore in both
# directions (pft-maint gate, dry run, backups, mode fix, rebuilt identity, forged payload, tampered held copy).
# Needs: age, age-keygen, python3, jq. No root, no network. Temp under TEST_TMPDIR (default ~/.cache).
# Usage: bash keyescrow/tests/run-escrow-tests.sh [path/to/pft-keyescrow.sh]
# shellcheck disable=SC2016,SC2034,SC2001,SC2012
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-keyescrow.sh}"
export PFT_KEYESCROW_HELPER="${PFT_KEYESCROW_HELPER:-$HERE/../keyescrow_tar.py}"
BASE="${TEST_TMPDIR:-$HOME/.cache}"; mkdir -p "$BASE"
T="$(mktemp -d "$BASE/pft-keyescrow-etests.XXXXXX")"; trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -30; return 0; }
check() { local name="$1"; shift; if ( eval "$*" ) >/dev/null 2>&1; then ok "$name"; else bad "$name" "$OUT"; fi; }
for b in age age-keygen python3 jq; do command -v "$b" >/dev/null || { echo "missing $b"; exit 2; }; done
echo "age $(age --version)"
ME="$(id -un)"; MYG="$(id -gn)"
MARK="sESCROWSECRET$RANDOM$RANDOM"

mkhost() { # NAME LABEL
  local H="$T/$1"
  mkdir -p "$H/root/etc" "$H/root/var/lib/pft-exporter/textfile"
  printf '%s\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$H/root/etc/machine-id"
  printf 'HOST_LABEL=%s\n' "$2" > "$H/root/etc/pft-keyescrow.env"; chmod 600 "$H/root/etc/pft-keyescrow.env"
  cat > "$H/registry.tsv" <<REG
c:seed	both	/var/lib/c/node_seed	600	$ME	$MYG	req	x:1
l:key	both	/etc/l/host.key	640	$ME	-	req	x:2
j:fss	both	/var/log/journal/@MID@/fss	600	$ME	$MYG	req	x:3
n:env	$2	/etc/n/ntfy.env	600	$ME	$MYG	req	x:4
o:opt	both	/etc/o/opt.env	600	$ME	$MYG	opt	x:5
REG
  local mid; mid="$(cat "$H/root/etc/machine-id")"
  for f in /var/lib/c/node_seed /etc/l/host.key "/var/log/journal/$mid/fss" /etc/n/ntfy.env; do
    mkdir -p "$(dirname "$H/root$f")"; printf '%s %s %s\n' "$MARK" "$1" "$f" > "$H/root$f"
  done
  chmod 600 "$H/root/var/lib/c/node_seed" "$H/root/var/log/journal/$mid/fss" "$H/root/etc/n/ntfy.env"
  chmod 640 "$H/root/etc/l/host.key"
}
mkhost va validator; mkhost se sentry
VA="$T/va"; SE="$T/se"
mkdir -p "$T/bin"
cat > "$T/bin/fakessh" <<STUB
#!/usr/bin/env bash
# stands in for "ssh relay sudo -n pft-keyescrow": runs the sentry's copy against the sentry root
exec env -u STATE_DIR -u TEXTFILE_DIR -u PFT_KEYESCROW_CONF PFT_KEYESCROW_ROOT="$SE/root" \\
  PFT_KEYESCROW_REGISTRY="$SE/registry.tsv" PFT_KEYESCROW_REMOTE= bash "$TOOL" "\$@"
STUB
chmod +x "$T/bin/fakessh"
on() { # va|se COMMAND...: run the tool as that host
  local H="$T/$1"; shift
  OUT="$(env PFT_KEYESCROW_ROOT="$H/root" PFT_KEYESCROW_REGISTRY="$H/registry.tsv" PFT_KEYESCROW_REMOTE= \
    timeout 120 bash "$TOOL" "$@" 2>&1)"; RC=$?
}
conf() { printf '%s=%s\n' "$2" "$3" >> "$T/$1/root/etc/pft-keyescrow.env"; }
SD() { echo "$T/$1/root/var/lib/pft-keyescrow"; }

# --- keygen ------------------------------------------------------------------------------------------------------
on va keygen
check "keygen: exit 0, recipient printed" '[ "$RC" = 0 ] && grep -qE "^age recipient: age1[02-9ac-hj-np-z]{58}$" <<<"$OUT"'
check "keygen: identity + fp_key 0600, state dir 0700" '[ "$(stat -c %a "$(SD va)/age.key")" = 600 ] && [ "$(stat -c %a "$(SD va)/fp_key")" = 600 ] && [ "$(stat -c %a "$(SD va)")" = 700 ]'
check "keygen: identity never printed" '! grep -q "AGE-SECRET-KEY" <<<"$OUT" && grep -q "AGE-SECRET-KEY" "$(SD va)/age.key"'
IDSHA="$(sha256sum < "$(SD va)/age.key")"
on va keygen
check "keygen again: refused (exit 4), identity unchanged" '[ "$RC" = 4 ] && [ "$(sha256sum < "$(SD va)/age.key")" = "$IDSHA" ]'
on se keygen
on va pubkey; VAPUB="$OUT"; on se pubkey; SEPUB="$OUT"
check "pubkey: both hosts, different" '[[ "$VAPUB" =~ ^age1 ]] && [[ "$SEPUB" =~ ^age1 ]] && [ "$VAPUB" != "$SEPUB" ]'

# --- set-peer ----------------------------------------------------------------------------------------------------
on va set-peer age1notakey
check "set-peer: malformed refused (exit 3)" '[ "$RC" = 3 ]'
on va set-peer "$VAPUB"
check "set-peer: own recipient refused" '[ "$RC" = 3 ] && grep -q "own recipient" <<<"$OUT"'
on va seal
check "seal without a peer: refused (exit 4)" '[ "$RC" = 4 ] && grep -q "PEER_RECIPIENT not set" <<<"$OUT"'
on va set-peer "$SEPUB"; on se set-peer "$VAPUB"
check "set-peer: conf line written, conf 0600" 'grep -qx "PEER_RECIPIENT=$SEPUB" "$VA/root/etc/pft-keyescrow.env" && [ "$(stat -c %a "$VA/root/etc/pft-keyescrow.env")" = 600 ]'

# --- seal --------------------------------------------------------------------------------------------------------
on va seal
G1="$(sed -n 's/^SEALED gen=\([0-9TZ]*\) .*/\1/p' <<<"$OUT")"
check "seal: exit 0, 4 items" '[ "$RC" = 0 ] && grep -qE "^SEALED gen=[0-9]{8}T[0-9]{6}Z host=validator items=4 " <<<"$OUT"'
check "seal: outbox gen committed (age + meta), no temp files" '[ -s "$(SD va)/outbox/gen-$G1.age" ] && [ -s "$(SD va)/outbox/gen-$G1.meta" ] && [ -z "$(find "$(SD va)" -name "*.tmp")" ]'
check "seal: meta fields" 'M="$(SD va)/outbox/gen-$G1.meta"; grep -qx "host=validator" "$M" && grep -qx "items=4" "$M" && grep -qx "recipient=$SEPUB" "$M" && [ "$(grep -c "^fp	" "$M")" = 4 ] && grep -qx "cipher_sha256=$(sha256sum < "$(SD va)/outbox/gen-$G1.age" | cut -c1-64)" "$M"'
check "seal: ciphertext and meta hold no secret bytes, meta no plain sha256 of a secret" '! grep -qF "$MARK" "$(SD va)/outbox/gen-$G1.age" "$(SD va)/outbox/gen-$G1.meta" && ! grep -qF "$(sha256sum < "$VA/root/var/lib/c/node_seed" | cut -c1-64)" "$(SD va)/outbox/gen-$G1.meta"'
check "positive control: the marker is in the source secret" 'grep -qF "$MARK" "$VA/root/var/lib/c/node_seed"'
check "seal: only the PEER can decrypt (sentry identity ok, validator identity fails)" 'age -d -i "$(SD se)/age.key" "$(SD va)/outbox/gen-$G1.age" | python3 -I "$PFT_KEYESCROW_HELPER" check --host validator --gen "$G1" && ! age -d -i "$(SD va)/age.key" "$(SD va)/outbox/gen-$G1.age" >/dev/null 2>&1'
check "decrypted payload carries the exact secret bytes (in memory)" 'age -d -i "$(SD se)/age.key" "$(SD va)/outbox/gen-$G1.age" | grep -aqF "$MARK va /var/lib/c/node_seed"'
chmod 644 "$VA/root/etc/n/ntfy.env"; on va seal
check "seal with a perm finding: refused (exit 4), item named, nothing new" '[ "$RC" = 4 ] && grep -q "\[perm\] n:env" <<<"$OUT" && [ "$(ls "$(SD va)/outbox/"*.meta | wc -l)" = 1 ]'
chmod 600 "$VA/root/etc/n/ntfy.env"
mv "$(SD va)/fp_key" "$T/fp_key.va"; on va seal
check "seal without fp_key: refused (exit 4), nothing new" '[ "$RC" = 4 ] && grep -q "no fp_key" <<<"$OUT" && [ "$(ls "$(SD va)/outbox/"*.meta | wc -l)" = 1 ]'
mv "$T/fp_key.va" "$(SD va)/fp_key"

# --- escrow end to end -------------------------------------------------------------------------------------------
on va escrow
check "escrow: refused without PEER_SSH (exit 4)" '[ "$RC" = 4 ] && grep -q "PEER_SSH not set" <<<"$OUT"'
conf va PEER_SSH "$T/bin/fakessh"
sleep 1; on va escrow
ESC1="$OUT"
check "escrow: PASS both directions" '[ "$RC" = 0 ] && grep -qx "RESULT: PASS - both directions sealed, held and verified" <<<"$OUT"'
check "escrow: sentry verified the validator gen in memory (4 items ok)" 'grep -qE "^  \| VERIFIED from=validator gen=[0-9TZ]+ items=4$" <<<"$OUT" && [ "$(grep -c "^  |     item .* ok$" <<<"$OUT")" = 4 ]'
check "escrow: validator verified the sentry gen (4 items ok) and the sentry acked" 'grep -qE "^  VERIFIED from=sentry gen=[0-9TZ]+ items=4$" <<<"$OUT" && grep -qE "^  \| ACKED gen=[0-9TZ]+ items=4$" <<<"$OUT"'
check "escrow: each side holds one verified generation of the other" '[ "$(ls "$(SD se)/store/validator/"*.meta | wc -l)" = 1 ] && [ "$(ls "$(SD va)/store/sentry/"*.meta | wc -l)" = 1 ] && grep -qx "result=ok" "$(SD se)"/store/validator/*.verified && grep -qx "result=ok" "$(SD va)"/store/sentry/*.verified'
on va inventory; check "after escrow: validator inventory exit 0, all same" '[ "$RC" = 0 ] && [ "$(grep -cE "escrow same +fp" <<<"$OUT")" = 4 ] && ! grep -qE "escrow (new|drift) +fp" <<<"$OUT"'
on se inventory; check "after escrow: sentry inventory exit 0, all same" '[ "$RC" = 0 ] && [ "$(grep -cE "escrow same +fp" <<<"$OUT")" = 4 ] && ! grep -qE "escrow (new|drift) +fp" <<<"$OUT"'
check "no plaintext secret anywhere in either STATE_DIR (outbox, store, escrowed.tsv)" '[ "$(find "$(SD va)" "$(SD se)" -type f | wc -l)" -ge 12 ] && ! grep -raqF "$MARK" "$(SD va)" "$(SD se)"'
check "positive control: the same recursive grep finds the marker in a secret dir" 'grep -raqF "$MARK" "$VA/root/var/lib/c"'
check "no secret bytes in the escrow output" '! grep -qF "$MARK" <<<"$ESC1" && ! grep -q "AGE-SECRET-KEY" <<<"$ESC1"'
check "held generations 0600 in 0700 dirs" '[ -z "$(find "$(SD se)/store" -type f ! -perm 600)" ] && [ "$(stat -c %a "$(SD se)/store/validator")" = 700 ]'

# --- drift, re-escrow, pruning ------------------------------------------------------------------------------------
printf 'rotated\n' >> "$VA/root/var/lib/c/node_seed"
on va inventory; check "changed secret: drift, exit 1" '[ "$RC" = 1 ] && grep -qE "^  \[ok\] +c:seed +escrow drift" <<<"$OUT"'
conf se KEEP 2
sleep 1; on va escrow; sleep 1; on va escrow
on va inventory; check "re-escrow: drift gone, exit 0" '[ "$RC" = 0 ]'
check "KEEP=2 on the sentry: 2 generations held after 3 escrows" '[ "$(ls "$(SD se)/store/validator/"*.meta | wc -l)" = 2 ] && [ "$(ls "$(SD se)/store/validator/"*.age | wc -l)" = 2 ]'
check "KEEP default 7 on the validator: 3 held" '[ "$(ls "$(SD va)/store/sentry/"*.meta | wc -l)" = 3 ]'

# --- verify + tamper ----------------------------------------------------------------------------------------------
on se verify --textfile
P="$SE/root/var/lib/pft-exporter/textfile/pft_keyescrow_held.prom"
check "verify: newest ok, exit 0, textfile ok=1 generations=2" '[ "$RC" = 0 ] && grep -qx "pft_keyescrow_held_verify_ok{node=\"sentry\",peer=\"validator\"} 1" "$P" && grep -qx "pft_keyescrow_held_generations{node=\"sentry\",peer=\"validator\"} 2" "$P"'
NEW="$(ls "$(SD se)"/store/validator/gen-*.age | sort | tail -1)"
cp "$NEW" "$T/orig.age"
python3 - "$NEW" <<'PYEOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0x01; open(p, "wb").write(bytes(b))
PYEOF
check "tamper fixture: exactly one byte differs" '[ "$(cmp -l "$T/orig.age" "$NEW" | wc -l)" = 1 ]'
on se verify --textfile
check "one-byte tamper: sha256 MISMATCH, exit 2, textfile ok=0" '[ "$RC" = 2 ] && grep -q "ciphertext sha256 MISMATCH" <<<"$OUT" && grep -qx "pft_keyescrow_held_verify_ok{node=\"sentry\",peer=\"validator\"} 0" "$P"'
M="${NEW%.age}.meta"; cp "$M" "$T/orig.meta"
sed -i "s/^cipher_sha256=.*/cipher_sha256=$(sha256sum < "$NEW" | cut -c1-64)/" "$M"
on se verify
check "tamper + re-hashed meta: age authentication fails, VERIFY FAILED, exit 2" '[ "$RC" = 2 ] && grep -q "VERIFY FAILED from=validator" <<<"$OUT" && ! grep -q "ciphertext sha256 MISMATCH" <<<"$OUT"'
cp "$T/orig.age" "$NEW"; cp "$T/orig.meta" "$M"
on se verify --all
check "restored: --all checks both generations, exit 0" '[ "$RC" = 0 ] && grep -q "RESULT: 2 generation(s) checked, 0 failed" <<<"$OUT"'

# --- receive refusals ---------------------------------------------------------------------------------------------
G="$(ls "$(SD va)"/outbox/gen-*.meta | sort | tail -1)"; G="${G##*/gen-}"; G="${G%.meta}"
before="$(ls "$(SD se)/store/validator" | sort)"
mkdir -p "$T/env1"; cp "$(SD va)/outbox/gen-$G.meta" "$(SD va)/outbox/gen-$G.age" "$T/env1/"; echo x > "$T/env1/extra"
OUT="$(tar -C "$T/env1" -cf - "gen-$G.meta" "gen-$G.age" extra | "$T/bin/fakessh" serve receive validator 2>&1)"; RC=$?
check "receive: extra member rejected" '[ "$RC" = 2 ] && grep -q "unexpected member" <<<"$OUT"'
sed -i 's/^cipher_bytes=.*/cipher_bytes=1/' "$T/env1/gen-$G.meta"
OUT="$(tar -C "$T/env1" -cf - "gen-$G.meta" "gen-$G.age" | "$T/bin/fakessh" serve receive validator 2>&1)"; RC=$?
check "receive: size differs from meta rejected" '[ "$RC" = 2 ] && grep -q "size differs" <<<"$OUT"'
OUT="$(tar -C "$(SD va)/outbox" -cf - "gen-$G.meta" "gen-$G.age" | "$T/bin/fakessh" serve receive validator 2>&1)"; RC=$?
check "receive: a generation already held is rejected" '[ "$RC" = 2 ] && grep -q "already held" <<<"$OUT"'
check "receive refusals: held set unchanged, no temp files" '[ "$(ls "$(SD se)/store/validator" | sort)" = "$before" ] && [ -z "$(find "$(SD se)/store" -name ".incoming*")" ]'
OUT="$(tar -C "$(SD va)/outbox" -cf - "gen-$G.meta" "gen-$G.age" | "$T/bin/fakessh" serve receive sentry 2>&1)"; RC=$?
check "serve receive with the host's own label: refused (exit 3)" '[ "$RC" = 3 ]'
OUT="$("$T/bin/fakessh" serve cat /etc/shadow 2>&1)"; RC=$?
check "serve: unknown verb refused (exit 3)" '[ "$RC" = 3 ] && grep -q "unknown verb" <<<"$OUT"'
OUT="$("$T/bin/fakessh" serve ack 20990101T000000Z 2>&1)"; RC=$?
check "serve ack of a generation never sealed: refused (exit 4)" '[ "$RC" = 4 ]'
OUT="$("$T/bin/fakessh" serve export "../../etc" 2>&1)"; RC=$?
check "serve export of a non-generation name: refused (exit 4)" '[ "$RC" = 4 ]'

# --- the pulled generation fails here / the ack fails: nothing is recorded on the sentry ------------------------------
cp "$(SD se)/escrowed.tsv" "$T/se-esc.before"
OTHER2="$(age-keygen 2>/dev/null | sed -n 's/^# public key: //p')"
conf se PEER_RECIPIENT "$OTHER2"
sleep 1; on va escrow
check "sentry sealed to a wrong recipient: pull/verify FAIL here, exit 2, no ack" '[ "$RC" = 2 ] && grep -q "FAIL pull/verify here" <<<"$OUT" && ! grep -q "ACKED gen=.* items=" <<<"$(sed -n "/== 2\./,\$p" <<<"$OUT")"'
check "...and the sentry's escrowed.tsv is unchanged" 'cmp -s "$T/se-esc.before" "$(SD se)/escrowed.tsv"'
conf se PEER_RECIPIENT "$VAPUB"
cat > "$T/bin/fakessh-noack" <<STUB2
#!/usr/bin/env bash
# like fakessh, but the ack verb fails (a lost connection at the last step)
[ "\$2" = ack ] && { echo "connection lost" >&2; exit 255; }
exec "$T/bin/fakessh" "\$@"
STUB2
chmod +x "$T/bin/fakessh-noack"; conf va PEER_SSH "$T/bin/fakessh-noack"
sleep 1; on va escrow
check "ack fails: escrow FAIL (exit 2), sentry escrowed.tsv unchanged" '[ "$RC" = 2 ] && grep -q "FAIL ack on sentry" <<<"$OUT" && cmp -s "$T/se-esc.before" "$(SD se)/escrowed.tsv"'
conf va PEER_SSH "$T/bin/fakessh"

# --- wrong recipient: the peer cannot verify, nothing is recorded as escrowed --------------------------------------
cp "$(SD va)/escrowed.tsv" "$T/esc.before"
OTHER="$(age-keygen 2>/dev/null | sed -n 's/^# public key: //p')"
sed -i "s/^PEER_RECIPIENT=.*/PEER_RECIPIENT=$OTHER/" "$VA/root/etc/pft-keyescrow.env"
sleep 1; on va escrow
check "wrong recipient: escrow FAIL (exit 2), sentry VERIFY FAILED" '[ "$RC" = 2 ] && grep -q "VERIFY FAILED from=validator" <<<"$OUT" && grep -q "FAIL push/verify on sentry" <<<"$OUT"'
check "wrong recipient: escrowed.tsv not updated" 'cmp -s "$T/esc.before" "$(SD va)/escrowed.tsv"'
check "wrong recipient: the undecryptable generation was discarded, good ones kept" 'grep -q "discarded gen" <<<"$OUT" && [ "$(ls "$(SD se)/store/validator/"*.meta | wc -l)" = 2 ] && [ -z "$(grep -l "result=bad" "$(SD se)"/store/validator/*.verified)" ]'

# --- restore ------------------------------------------------------------------------------------------------------
cat > "$T/bin/pft-maint" <<'STUBMAINT'
#!/usr/bin/env bash
# stub: window state from <host root>/etc/maint-window (absent = none)
w="$(cat "$PFT_KEYESCROW_ROOT/etc/maint-window" 2>/dev/null || echo none)"
printf '{"time":"x","window":"%s","locks":[]}\n' "$w"
STUBMAINT
chmod +x "$T/bin/pft-maint"; export PFT_KEYESCROW_MAINT="$T/bin/pft-maint"
window() { if [ "$2" = none ]; then rm -f "$T/$1/root/etc/maint-window"; else echo "$2" > "$T/$1/root/etc/maint-window"; fi; }
SESEED="$SE/root/var/lib/c/node_seed"; cp "$SESEED" "$T/se-seed.orig"
VANTFY="$VA/root/etc/n/ntfy.env"; cp "$VANTFY" "$T/va-ntfy.orig"
on va restore --host sentry --item c:seed
check "restore without --yes: refused (exit 3)" '[ "$RC" = 3 ] && grep -q "add --yes" <<<"$OUT"'
rm "$SESEED"; on va restore --host sentry --item c:seed --yes
check "restore outside a window: refused on the sentry, FAIL, seed still absent" '[ "$RC" = 2 ] && grep -q "outside a maintenance window" <<<"$OUT" && [ ! -e "$SESEED" ]'
window se expired; on va restore --host sentry --item c:seed --yes
check "restore with an EXPIRED window: refused" '[ "$RC" = 2 ] && grep -q "window=expired" <<<"$OUT" && [ ! -e "$SESEED" ]'
window se none; on va restore --host sentry --item c:seed --dry-run
check "restore --dry-run (no window needed): plan only, nothing written" '[ "$RC" = 0 ] && grep -q "item c:seed would be restored (was absent)" <<<"$OUT" && [ ! -e "$SESEED" ]'
window se active; on va restore --host sentry --item c:seed --yes
check "sentry node_seed restore: PASS" '[ "$RC" = 0 ] && grep -q "item c:seed restored (was absent) (mode 600, backup none)" <<<"$OUT" && grep -qx "RESULT: PASS - restore on sentry" <<<"$OUT"'
check "restored seed byte-identical, 0600" 'cmp -s "$SESEED" "$T/se-seed.orig" && [ "$(stat -c %a "$SESEED")" = 600 ]'
check "restore output: after-scan shows c:seed ok, no secret bytes printed" 'grep -q "after: \[ok\] c:seed" <<<"$OUT" && ! grep -qF "$MARK" <<<"$OUT"'
printf 'corrupted\n' > "$SESEED"; chmod 600 "$SESEED"
on va restore --host sentry --yes
check "restore all items over a corrupted seed: seed restored with backup, others unchanged" '[ "$RC" = 0 ] && grep -q "item c:seed restored (mode 600, backup kept)" <<<"$OUT" && [ "$(grep -c "unchanged$" <<<"$OUT")" = 3 ] && cmp -s "$SESEED" "$T/se-seed.orig"'
BK="$(find "$(SD se)/restore-backups" -type f -name c_seed | tail -1)"
check "backup holds the replaced (corrupted) file, 0600 in a 0700 dir" '[ -n "$BK" ] && [ "$(cat "$BK")" = corrupted ] && [ "$(stat -c %a "$BK")" = 600 ] && [ "$(stat -c %a "$(dirname "$BK")")" = 700 ]'
chmod 644 "$SESEED"; on va restore --host sentry --item c:seed --yes
check "same bytes, wrong mode: mode/owner fixed, no backup" '[ "$RC" = 0 ] && grep -q "item c:seed mode/owner fixed (mode 600, backup none)" <<<"$OUT" && [ "$(stat -c %a "$SESEED")" = 600 ]'
window se none
rm "$VANTFY"; window va active; on va restore --host validator --item n:env --yes
check "validator self-restore (sentry re-encrypts its copy): PASS, byte-identical" '[ "$RC" = 0 ] && grep -q "item n:env restored (was absent)" <<<"$OUT" && cmp -s "$VANTFY" "$T/va-ntfy.orig"'
window va none
rm "$(SD se)/age.key" "$(SD se)/age.pub"; on se keygen; NEWSE="$(sed -n 's/^age recipient: //p' <<<"$OUT")"
check "sentry rebuilt identity: new recipient" '[[ "$NEWSE" =~ ^age1 ]] && [ "$NEWSE" != "$SEPUB" ]'
printf 'lost\n' > "$SESEED"; chmod 600 "$SESEED"; window se active
on va restore --host sentry --item c:seed --yes
check "restore to a REBUILT identity (re-encrypted to the new recipient): PASS" '[ "$RC" = 0 ] && cmp -s "$SESEED" "$T/se-seed.orig"'
on va restore --host sentry --item x:nope --yes
check "unknown item: refused, nothing changed" '[ "$RC" = 2 ] && grep -q "item x:nope is not in this generation" <<<"$OUT" && cmp -s "$SESEED" "$T/se-seed.orig"'
mkdir -p "$T/forge"; printf 'evil\n' > "$T/forge/x"
FORGED="$(printf 'c:seed\t%s\n' "$T/forge/x" | python3 -I "$PFT_KEYESCROW_HELPER" pack --host sentry --gen 20990101T000000Z 2>/dev/null | age -r "$NEWSE" | base64 -w0)"
rm "$T/forge/x"
OUT="$(base64 -d <<<"$FORGED" | "$T/bin/fakessh" serve restore-apply 2>&1)"; RC=$?
check "forged payload (allowed id, foreign path): refused, foreign path not written" '[ "$RC" = 2 ] && grep -q "is not this host.s registry path" <<<"$OUT" && [ ! -e "$T/forge/x" ] && cmp -s "$SESEED" "$T/se-seed.orig"'
HELD="$(ls "$(SD va)"/store/sentry/gen-*.age | sort | tail -1)"; cp "$HELD" "$T/held.orig"
printf 'X' | dd of="$HELD" bs=1 seek=200 conv=notrunc 2>/dev/null
printf 'lost\n' > "$SESEED"
on va restore --host sentry --item c:seed --yes
check "tampered held copy: reseal refused, restore FAIL, nothing written" '[ "$RC" = 2 ] && grep -q "reseal refused" <<<"$OUT" && [ "$(cat "$SESEED")" = lost ]'
cp "$T/held.orig" "$HELD"; window se none

# --- guards without a natural trigger: crafted inputs ---------------------------------------------------------------
NG="$(ls "$(SD va)/outbox/"*.meta | wc -l)"
PFT_KEYESCROW_AGE=false on va seal
check "seal: age failing in the pipe -> exit 2, nothing committed" '[ "$RC" = 2 ] && grep -q "seal failed" <<<"$OUT" && [ "$(ls "$(SD va)/outbox/"*.meta | wc -l)" = "$NG" ] && [ -z "$(find "$(SD va)/outbox" -name "*.tmp")" ]'
PFT_KEYESCROW_MAINT="$T/bin/no-such-pft-maint" on va restore --host validator --item n:env --yes
check "restore: pft-maint missing -> refused (fail closed)" '[ "$RC" = 2 ] && grep -q "pft-maint not installed" <<<"$OUT"'
craft() { # MODE -> a payload tar on stdout, built by hand (python), item bytes "abc"
  python3 -I - "$1" <<'PYEOF'
import hashlib, io, json, sys, tarfile
mode = sys.argv[1]
data = b"abc"
items = [{"id": "c:seed", "path": "/x", "mode": "600", "uid": 0, "gid": 0, "size": 3,
          "sha256": hashlib.sha256(b"abd" if mode == "badsha" else data).hexdigest()}]
man = json.dumps({"v": 1, "host": "sentry", "gen": "20990101T000000Z", "items": items}).encode()
out = sys.stdout.buffer
with tarfile.open(fileobj=out, mode="w|") as tf:
    for name, b in [("MANIFEST", man), ("items/0", data)] + ([("items/9", b"zz")] if mode == "extra" else []):
        ti = tarfile.TarInfo(name); ti.size = len(b); tf.addfile(ti, io.BytesIO(b))
PYEOF
}
OUT="$(craft badsha | python3 -I "$PFT_KEYESCROW_HELPER" check 2>&1)"; RC=$?
check "check: an item whose bytes differ from its MANIFEST sha256 -> MISMATCH, exit 2" '[ "$RC" = 2 ] && grep -q "item c:seed MISMATCH(sha256)" <<<"$OUT"'
OUT="$(craft extra | python3 -I "$PFT_KEYESCROW_HELPER" check 2>&1)"; RC=$?
check "check: an extra member -> bad, exit 2" '[ "$RC" = 2 ] && grep -q "items/9 not in MANIFEST" <<<"$OUT"'
OUT="$(craft ok | python3 -I "$PFT_KEYESCROW_HELPER" check 2>&1)"; RC=$?
check "check control: the same hand-built payload without the defect passes" '[ "$RC" = 0 ] && grep -q "ok=1 bad=0" <<<"$OUT"'
OUT="$(printf 'n:env\t%s\n' "$VANTFY" | python3 -I "$PFT_KEYESCROW_HELPER" pack --host validator --gen 20990101T000000Z 2>/dev/null | age -r "$NEWSE" | "$T/bin/fakessh" serve restore-apply --dry-run 2>&1)"; RC=$?
check "restore-apply: a payload for ANOTHER host is refused" '[ "$RC" = 2 ] && grep -q "payload is for host .validator., this is .sentry." <<<"$OUT"'
chmod 4600 "$SESEED"
SUIDP="$(printf 'c:seed\t%s\n' "$SESEED" | python3 -I "$PFT_KEYESCROW_HELPER" pack --host sentry --gen 20990101T000000Z 2>/dev/null | age -r "$NEWSE" | base64 -w0)"
chmod 600 "$SESEED"
OUT="$(base64 -d <<<"$SUIDP" | "$T/bin/fakessh" serve restore-apply --dry-run 2>&1)"; RC=$?
check "restore-apply: a setuid mode in the MANIFEST is refused" '[ "$RC" = 2 ] && grep -q "refusing mode 4600" <<<"$OUT" && [ "$(stat -c %a "$SESEED")" = 600 ]'
G="$(ls "$(SD va)"/outbox/gen-*.meta | sort | tail -1)"; G="${G##*/gen-}"; G="${G%.meta}"
rm -rf "$T/env2"; mkdir -p "$T/env2"; cp "$(SD va)/outbox/gen-$G.meta" "$(SD va)/outbox/gen-$G.age" "$T/env2/"
printf 'X' | dd of="$T/env2/gen-$G.age" bs=1 seek=100 conv=notrunc 2>/dev/null
rm -f "$(SD se)/store/validator/gen-$G."*
OUT="$(tar -C "$T/env2" -cf - "gen-$G.meta" "gen-$G.age" | "$T/bin/fakessh" serve receive validator 2>&1)"; RC=$?
check "receive: ciphertext that differs from its meta sha256 is rejected, nothing kept" '[ "$RC" = 2 ] && grep -q "ciphertext sha256 differs" <<<"$OUT" && [ ! -e "$(SD se)/store/validator/gen-$G.meta" ]'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
