#!/usr/bin/env bash
# Tests for bundle/: sanitizer unit tests, shellcheck, and collect/verify end-to-end with a fake docker
# (tests/stub/docker serving tests/fixtures). collect needs root (ufw, docker), so the CLI tests use sudo.
# Run from the repo root: bash bundle/tests/run-tests.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 3
B=bundle T="$(mktemp -d /tmp/pft-bundle-test.XXXXXX)"
trap 'sudo rm -rf "$T"' EXIT
pass=0 fail=0
ok() { if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "ok   $3"; else fail=$((fail+1)); echo "FAIL $3 (got $1, want $2)"; fi; }
indent() { sed 's/^/   | /'; }
has() { if grep -qF -- "$2" <<<"$1"; then echo 1; else echo 0; fi; }
STUBENV=(env "PATH=$PWD/$B/tests/stub:$PATH" "STUB_DIR=$PWD/$B/tests/fixtures")
collect() { sudo "${STUBENV[@]}" bash "$B/pft-bundle.sh" collect --redact stub-host-9 \
              --literal-env "$B/tests/fixtures/ntfy.env" --label test "$@"; }
verify() { sudo bash "$B/pft-bundle.sh" verify "$@" --no-host-literals --literal-env "$B/tests/fixtures/ntfy.env"; }
repack() { # DIR OUT: rebuild a bundle from an extracted dir (manifest left as is unless REHASH=1)
  local d="$1"; if [ "${REHASH:-0}" = 1 ]; then ( cd "$d"/* && find . -type f ! -name 'MANIFEST*' | sed 's|^\./||' |
    LC_ALL=C sort | xargs -d '\n' sha256sum >MANIFEST.sha256 ); fi
  sudo tar -czf "$2" -C "$d" "$(ls "$d")"; }

echo "== unit tests (sanitize.py)"
python3 -I -m unittest discover -s "$B/tests" -q 2>&1 | tail -3
ok "${PIPESTATUS[0]}" 0 "unit tests"
echo "== shellcheck"
shellcheck "$B/pft-bundle.sh" "$B/tests/run-tests.sh" "$B/tests/stub/docker" "$B/live-proof.sh"; ok $? 0 "shellcheck clean"

echo "== collect, clean fixtures"
out="$(collect --out "$T/out1")"; rc=$?
sed -n '/^items/p;/^redactions/p;/^scan/p;/^manifest/p' <<<"$out"
ok $rc 0 "collect exit 0"
bundle="$(ls "$T"/out1/*.tar.gz 2>/dev/null)"
ok "$(sudo stat -c %a "$bundle" 2>/dev/null)" 600 "bundle mode 0600"
ok "$(grep -c 'rc=0 ' <<<"$out")" 16 "all 16 items collected with rc=0"
mkdir "$T/x1" && sudo tar -xzf "$bundle" -C "$T/x1" && sudo chown -R "$(id -u)" "$T/x1"
all="$(cat "$T"/x1/*/*/* 2>/dev/null)"
for s in stub-host-9 c0ffee123456 stub-topic-xyz 198.51.100.23 203.0.113.10 203.0.113.77 2001:db8::7 \
         eyJtYW5pZmVzdCI6 ZmFrZS10b2tlbi not-a-real-password shfArahZT9Q9ckTf3s1psJ7C7qzVN; do
  ok "$(has "$all" "$s")" 0 "bundle has no '$s'"
done
for s in "admin = 127.0.0.1" "admin_password = <redacted>" \
         "# [validator_token] section removed" "<ntfy-url>" "ConsensusPhase::accepted" "<host-"; do
  ok "$(has "$all" "$s")" 1 "bundle keeps/has '$s'"
done
peers="$(cat "$T"/x1/*/rpc/peers.json)"
ok "$(grep -cE '"<ip-[0-9]+>:2559"' <<<"$peers")" 1 "peer IPv4 tokenized"
ok "$(grep -cE '"\[<ip-[0-9]+>\]:51235"' <<<"$peers")" 1 "peer IPv6 tokenized"
ok "$(grep -cE '^<ip-[0-9]+> 2559$' "$T"/x1/*/config/postfiatd.cfg)" 1 "[ips_fixed] address tokenized"
t1="$(grep -oE '<ip-[0-9]+>:51235' <<<"$peers")"; t2="$(grep -oE '"HostIp": "<ip-[0-9]+>"' "$T"/x1/*/docker/container.json)"
ok "${t2//[^0-9]/}" "$(tr -dc 0-9 <<<"${t1%%:*}")" "same address -> same token across files (${t1%%:*})"
ok "$(grep -c . "$T"/x1/*/MANIFEST.sha256)" "$(find "$T"/x1/*/ -type f ! -name 'MANIFEST*' | wc -l)" "manifest lists every file"

echo "== verify, clean bundle"
v="$(verify "$bundle")"; ok $? 0 "verify exit 0"; indent <<<"$v"

echo "== fail closed: planted fake seed in debug.log"
out="$(sudo "${STUBENV[@]}" STUB_DEBUG=debug-planted.log bash "$B/pft-bundle.sh" collect \
       --redact stub-host-9 --label test --out "$T/out2")"; rc=$?
indent <<<"$out"
ok $rc 2 "collect exit 2"
ok "$(find "$T/out2" -name '*.tar.gz' 2>/dev/null | wc -l)" 0 "no bundle written"
ok "$(has "$out" "HIT logs/debug.log.tail:3 seed")" 1 "hit reported as file:line class"
ok "$(has "$out" sEdTM1uX8pu2do5XvTnutH6HsouMaM2)" 0 "seed value not printed"

echo "== verify negatives"
cp -r "$T/x1" "$T/x2"; echo tampered >>"$T"/x2/*/system/df.txt; repack "$T/x2" "$T/tampered.tar.gz"
v="$(verify "$T/tampered.tar.gz")"; ok $? 2 "tampered file -> exit 2"; ok "$(has "$v" "FAIL hashes")" 1 "FAIL hashes"
cp -r "$T/x1" "$T/x3"; echo extra >"$(echo "$T"/x3/*)/extra.txt"; repack "$T/x3" "$T/extra.tar.gz"
v="$(verify "$T/extra.tar.gz")"; ok $? 2 "unlisted file -> exit 2"; ok "$(has "$v" "FAIL manifest")" 1 "FAIL manifest"
cp -r "$T/x1" "$T/x4"; echo "late line sn3nxiW7v8KXzPzAqzyHXbSSKNuN9" >>"$T"/x4/*/logs/debug.log.tail
REHASH=1 repack "$T/x4" "$T/seed.tar.gz"
v="$(verify "$T/seed.tar.gz")"; ok $? 2 "seed in re-hashed bundle -> exit 2"; ok "$(has "$v" "seed")" 1 "scan names class seed"
ok "$(has "$v" sn3nxiW7v8KXzPzAqzyHXbSSKNuN9)" 0 "seed value not printed by verify"
cp -r "$T/x1" "$T/x5"; echo "topic stub-topic-xyz" >>"$T"/x5/*/system/units.txt; REHASH=1 repack "$T/x5" "$T/topic.tar.gz"
v="$(verify "$T/topic.tar.gz")"; ok $? 2 "topic literal -> exit 2"; ok "$(has "$v" literal_topic)" 1 "scan names literal_topic"
python3 -I -c 'import io,sys,tarfile
t=tarfile.open(sys.argv[1],"w:gz"); i=tarfile.TarInfo("b/../../evil"); d=b"x\n"; i.size=len(d); t.addfile(i,io.BytesIO(d))' "$T/dotdot.tar.gz"
v="$(verify "$T/dotdot.tar.gz")"; ok $? 2 ".. member -> exit 2"; ok "$(has "$v" "FAIL tar")" 1 "FAIL tar"

echo "== signature"
ssh-keygen -q -t ed25519 -N '' -C test -f "$T/k1" && ssh-keygen -q -t ed25519 -N '' -C other -f "$T/k2"
echo "pft-bundle $(cat "$T/k1.pub")" >"$T/signers"; echo "pft-bundle $(cat "$T/k2.pub")" >"$T/signers-other"
sudo chmod 644 "$T/k1"
collect --out "$T/out3" --sign-key "$T/k1" >/dev/null; ok $? 0 "signed collect exit 0"
sb="$(ls "$T"/out3/*.tar.gz)"
v="$(verify "$sb" --signers "$T/signers")"; ok $? 0 "verify signed, right signer"; ok "$(has "$v" "PASS signature")" 1 "PASS signature"
v="$(verify "$sb" --signers "$T/signers-other")"; ok $? 2 "wrong signer -> exit 2"
v="$(verify "$bundle" --signers "$T/signers")"; ok $? 2 "unsigned bundle with --signers -> exit 2"

echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
