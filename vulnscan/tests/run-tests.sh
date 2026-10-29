#!/usr/bin/env bash
# Offline tests for pft-vulnscan.sh + vulnscan_parse.py: stub curl, stub oscap (writes a results file built by
# make_fixture.py), stub dpkg-query, fake clock, temp cache/textfile dirs. No root; nothing on the host changes.
# Section 9 additionally runs the REAL oscap (if installed) on a fixture feed that points at the installed `bash`
# package: known-old positive control (true) and fixed-package / absent-package controls (false).
#   bash vulnscan/tests/run-tests.sh [SCRIPT [PARSER]]   (defaults ../pft-vulnscan.sh ../vulnscan_parse.py)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; L/J are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-vulnscan.sh}"
P="${2:-$HERE/../vulnscan_parse.py}"
MK="$HERE/make_fixture.py"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }   # NAME CONDITION (subshell: an exit in it is a FAIL)
has()   { grep -qxF -- "$2" "$1"; }                              # FILE LINE (exact)
NOW=4070908800    # 2099-01-01T00:00:00Z = the fixture feed's default <oval:timestamp>
L='host="validator"'
mkdir -p "$T/bin" "$T/tf" "$T/cache" "$T/srv"

# stub curl: mode in $T/curl_mode (200 | 304 | fail); serves $T/srv/feed.xml.bz2; records its args in $T/curl_args
cat > "$T/bin/curl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" > "$T/curl_args"
out=""; esave=""
while [ \$# -gt 0 ]; do
  case "\$1" in -o) out="\$2"; shift ;; --etag-save) esave="\$2"; shift ;; --etag-compare|-w|--max-time) shift ;; esac
  shift
done
case "\$(cat "$T/curl_mode")" in
  200) cp "$T/srv/feed.xml.bz2" "\$out"; echo '"etag-1"' > "\$esave"; printf 200 ;;
  304) : > "\$esave"; printf 304 ;;
  fail) echo "curl: (6) Could not resolve host: security-metadata.canonical.com" >&2; printf 000; exit 6 ;;
esac
EOF
# stub oscap: `oscap oval eval --results R FEED`; extra make_fixture args in $T/oscap_args; fails if $T/oscap_fail
cat > "$T/bin/oscap" <<EOF
#!/bin/bash
[ -e "$T/oscap_fail" ] && { echo "OpenSCAP Error: Unable to open file" >&2; exit 1; }
[ "\$1 \$2 \$3" = "oval eval --results" ] || exit 9
# shellcheck disable=SC2046
python3 -I "$MK" results "\$5" "\$4" \$(cat "$T/oscap_args" 2>/dev/null) || exit 1
echo "Evaluation done."
EOF
# stub dpkg-query: prints $T/kernels
cat > "$T/bin/dpkg-query" <<EOF
#!/bin/sh
cat "$T/kernels"
EOF
chmod +x "$T/bin/"*
printf 'linux-image-5.15.0-198-generic ii \nlinux-image-5.15.0-202-generic ii \nlinux-image-5.15.0-99-generic rc \n' > "$T/kernels"
printf 'CACHE_DIR=%s\nTEXTFILE_DIR=%s\n' "$T/cache" "$T/tf" > "$T/conf"

serve() { # [make_fixture feed args] -> $T/srv/feed.xml.bz2
  python3 -I "$MK" feed "$T/srv/feed.xml" "$@" && python3 -I -c 'import bz2, sys
open(sys.argv[2], "wb").write(bz2.compress(open(sys.argv[1], "rb").read()))' "$T/srv/feed.xml" "$T/srv/feed.xml.bz2"
}
run() { # [scan args] -> $T/out, $T/err, $T/rc  (env: UNAME, NOWV)
  PFT_VS_CONF="$T/conf" PFT_VS_CURL="$T/bin/curl" PFT_VS_OSCAP="${OSCAP_CMD:-$T/bin/oscap}" PFT_VS_DPKG_QUERY="$T/bin/dpkg-query" \
  PFT_VS_PARSER="$P" PFT_VS_NOW="${NOWV:-$NOW}" PFT_VS_UNAME_R="${UNAME:-5.15.0-202-generic}" PFT_VS_ROOT="$T/root" \
    bash "$S" scan "$@" > "$T/out" 2> "$T/err"
  echo $? > "$T/rc"
}
OUT="$T/tf/pft_vulnscan_validator.prom"
rc() { [ "$(cat "$T/rc")" = "$1" ]; }
up0() { has "$OUT" "pft_vulnscan_up{$L} 0" && ! grep -q '^pft_vulnscan_affected_usns' "$OUT"; }

echo "== 1. first scan: fetch (200), stub oscap, two affected USNs"
serve; echo 200 > "$T/curl_mode"; rm -f "$T/oscap_args"
run
check "rc 1 (findings)" 'rc 1'
check "fetch: fetched" 'grep -q "fetch: fetched" "$T/out"'
check "no --etag-compare without a cache" '! grep -q -- "--etag-compare" "$T/curl_args"'
check "row USN-9001-1 high archive, 2 CVEs, both binaries" 'grep -Eq "^USN-9001-1 +high +archive +2 +liboldpkg1 0:1.0-1 -> 2.0-1ubuntu0.1, oldpkg 0:1.0-1 -> 2.0-1ubuntu0.1$" "$T/out"'
check "row USN-9002-1 medium esm" 'grep -Eq "^USN-9002-1 +medium +esm +1 +esmpkg " "$T/out"'
check "fixed-package USN-9003-1 not reported" '! grep -q "USN-9003-1" "$T/out"'
check "RESULT line" 'grep -qx "RESULT: 2 affected USNs (0 critical, 1 high, 1 medium, 0 low, 0 negligible, 0 none, 0 unknown; 1 fixable only via Ubuntu Pro/ESM), 3 CVEs; reboot owed: no -> exit 1" "$T/out"'
check "metric up 1" 'has "$OUT" "pft_vulnscan_up{$L} 1"'
check "metric high/archive 1" 'has "$OUT" "pft_vulnscan_affected_usns{$L,severity=\"high\",fix=\"archive\"} 1"'
check "metric medium/esm 1" 'has "$OUT" "pft_vulnscan_affected_usns{$L,severity=\"medium\",fix=\"esm\"} 1"'
check "metric critical/archive 0" 'has "$OUT" "pft_vulnscan_affected_usns{$L,severity=\"critical\",fix=\"archive\"} 0"'
check "21 affected_usns series (7 severities x 3)" '[ "$(grep -c "^pft_vulnscan_affected_usns{" "$OUT")" = 21 ]'
check "metric cves 3" 'has "$OUT" "pft_vulnscan_affected_cves{$L} 3"'
check "last_success = now" 'has "$OUT" "pft_vulnscan_last_success_timestamp_seconds{$L} $NOW"'
check "feed timestamp = fixture <oval:timestamp>" 'has "$OUT" "pft_vulnscan_feed_timestamp_seconds{$L} $NOW"'
check "feed.meta sha256 = served file" 'grep -qx "sha256=$(sha256sum < "$T/srv/feed.xml.bz2" | cut -c1-64)" "$T/cache/feed.meta"'
check "textfile validates" 'PFT_VS_CONF=/nonexistent bash "$S" validate "$OUT" validator'
check "no temp files left" '[ "$(find "$T/tf" "$T/cache" -name ".*" -newer "$T/conf" | wc -l)" = 0 ]'

echo "== 2. --json (findings-producing)"
echo 304 > "$T/curl_mode"
run --json
check "rc 1" 'rc 1'
check "JSON: ok, exit_code 1, 2 findings, fix fields, versions, kernel" 'python3 -I -c "import json, sys
d = json.load(open(sys.argv[1]))
assert d[\"ok\"] is True and d[\"exit_code\"] == 1 and d[\"affected_usns\"] == 2 and d[\"host\"] == \"validator\"
f = {x[\"usn\"]: x for x in d[\"findings\"]}
assert f[\"USN-9001-1\"][\"fix\"] == \"archive\" and f[\"USN-9002-1\"][\"fix\"] == \"esm\"
assert f[\"USN-9001-1\"][\"cves\"] == [\"CVE-2099-0001\", \"CVE-2099-0002\"]
p = f[\"USN-9001-1\"][\"packages\"][1]
assert p == {\"binary\": \"oldpkg\", \"installed\": \"0:1.0-1\", \"fixed\": \"2.0-1ubuntu0.1\", \"pocket\": \"jammy\", \"source\": \"oldpkg\"}, p
assert d[\"kernel\"][\"reboot_owed\"] is False and len(d[\"feed_sha256\"]) == 64
" "$T/out"'
check "JSON output is one line, nothing else on stdout" '[ "$(wc -l < "$T/out")" = 1 ]'

echo "== 3. ETag caching: 304 keeps the cache"
run
check "rc 1" 'rc 1'
check "--etag-compare sent" 'grep -q -- "--etag-compare $T/cache/feed.etag" "$T/curl_args"'
check "fetch: not modified" 'grep -q "fetch: not modified" "$T/out"'

echo "== 4. clean host (fixed-package controls only)"
echo "--odd 900010000000=false --odd 900020000000=false" > "$T/oscap_args"
run
check "rc 0" 'rc 0'
check "RESULT 0 affected, exit 0" 'grep -qx "RESULT: 0 affected USNs (0 critical, 0 high, 0 medium, 0 low, 0 negligible, 0 none, 0 unknown; 0 fixable only via Ubuntu Pro/ESM), 0 CVEs; reboot owed: no -> exit 0" "$T/out"'
check "no table header" '! grep -q "^USN " "$T/out"'
check "metric cves 0" 'has "$OUT" "pft_vulnscan_affected_cves{$L} 0"'

echo "== 5. kernel / reboot owed"
UNAME=5.15.0-198-generic run
check "older running kernel: rc 1 with 0 USNs" 'rc 1'
check "kernel line" 'grep -qx "kernel   running 5.15.0-198-generic, newest installed 5.15.0-202-generic, reboot-required flag absent -> reboot owed: YES" "$T/out"'
check "kernel_outdated 1, reboot_owed 1" 'has "$OUT" "pft_vulnscan_kernel_outdated{$L} 1" && has "$OUT" "pft_vulnscan_reboot_owed{$L} 1"'
check "removed (rc) kernel ignored: 5.15.0-99 is not newest by sort -V" 'grep -q "newest installed 5.15.0-202-generic" "$T/out"'
UNAME=5.15.0-210-generic run
check "running NEWER than installed (e.g. a removed package): not outdated" 'rc 0 && has "$OUT" "pft_vulnscan_kernel_outdated{$L} 0"'
mkdir -p "$T/root/var/run"; touch "$T/root/var/run/reboot-required"
run
check "reboot-required flag: rc 1, owed 1, outdated 0" 'rc 1 && has "$OUT" "pft_vulnscan_reboot_owed{$L} 1" && has "$OUT" "pft_vulnscan_kernel_outdated{$L} 0"'
rm -f "$T/root/var/run/reboot-required"
run
check "flag removed: rc 0, owed 0" 'rc 0 && has "$OUT" "pft_vulnscan_reboot_owed{$L} 0"'
rm -f "$T/oscap_args"

echo "== 6. negative controls: every scan error is exit 2 + up 0, last_success carried over"
neg() { # NAME EXPECTED-MESSAGE (check() evals in its own frame: copy the message to a local first)
  local msg="$2"
  check "$1: rc 2" 'rc 2'
  check "$1: message '$2'" 'grep -qF -- "$msg" "$T/err" && grep -qF -- "RESULT: ERROR - " "$T/out"'
  check "$1: up 0, no affected series" 'up0'
  check "$1: last_success carried ($NOW)" 'has "$OUT" "pft_vulnscan_last_success_timestamp_seconds{$L} $NOW"'
  check "$1: last_run = this run" 'has "$OUT" "pft_vulnscan_last_run_timestamp_seconds{$L} ${NOWV:-$NOW}"'
}
NOWV=$((NOW + 8 * 86400)) run
NOWV=$((NOW + 8 * 86400)) neg "stale feed (8 days)" "feed is stale: timestamp 2099-01-01T00:00:00 is 8 days old (limit 7)"
check "stale feed: feed timestamp still exported" 'has "$OUT" "pft_vulnscan_feed_timestamp_seconds{$L} $NOW"'
NOWV=$((NOW + 7 * 86400)) run
check "feed exactly 7 days old: accepted (rc 1)" 'rc 1'
run   # back to a success at NOW, so every negative below must carry last_success = NOW
check "reset: success at NOW" 'rc 1 && has "$OUT" "pft_vulnscan_last_success_timestamp_seconds{$L} $NOW"'
echo "--omit 900030000000" > "$T/oscap_args"; run
neg "results missing a definition" "results do not match the feed: 1 definitions without a result"
echo "--odd 900030000000=error" > "$T/oscap_args"; run
neg "definition evaluated to error" "1 definitions evaluated to 'error'"
echo "--odd 900040000000=unknown" > "$T/oscap_args"; run
neg "definition evaluated to unknown" "1 definitions evaluated to 'unknown'"
echo "--inventory false" > "$T/oscap_args"; run
neg "inventory false (wrong release feed)" "inventory definition is 'false'"
echo "--dup 900010000000" > "$T/oscap_args"; run
neg "duplicate result" "results hold oval:com.ubuntu.jammy:def:900010000000 twice"
rm -f "$T/oscap_args"; touch "$T/oscap_fail"; run
neg "oscap fails" "oscap oval eval failed (rc 1: OpenSCAP Error: Unable to open file"
rm -f "$T/oscap_fail"
OSCAP_CMD=/nonexistent/oscap run
neg "oscap not installed" "/nonexistent/oscap not installed"
OSCAP_CMD=/nonexistent/oscap run --json
check "--json on error: one JSON line, ok false, exit 2" 'rc 2 && [ "$(wc -l < "$T/out")" = 1 ] && python3 -I -c "import json, sys
d = json.load(open(sys.argv[1])); assert d[\"ok\"] is False and d[\"exit_code\"] == 2 and d[\"error\"] == \"/nonexistent/oscap not installed\"" "$T/out"'

echo "== 7. corrupt / truncated / tampered feeds"
cp "$T/cache/feed.xml.bz2" "$T/good.bz2"; cp "$T/cache/feed.meta" "$T/good.meta"
head -c 300 "$T/good.bz2" > "$T/srv/feed.xml.bz2"; echo 200 > "$T/curl_mode"; run
check "truncated download refused, cache kept: rc 1 on the cached feed" 'rc 1 && grep -q "fetch: FAILED: downloaded file is not a complete bzip2 stream (cache kept)" "$T/out"'
check "cache unchanged after the bad download" 'cmp -s "$T/good.bz2" "$T/cache/feed.xml.bz2" && cmp -s "$T/good.meta" "$T/cache/feed.meta"'
echo fail > "$T/curl_mode"; run
check "network failure, cache kept: rc 1, reason shown" 'rc 1 && grep -q "fetch: FAILED: download failed (curl rc 6" "$T/out"'
printf 'X' | dd of="$T/cache/feed.xml.bz2" bs=1 seek=100 conv=notrunc 2>/dev/null; run
neg "cached feed tampered (1 byte)" "does not match feed.meta"
cp "$T/good.bz2" "$T/cache/feed.xml.bz2"
python3 -I "$MK" feed "$T/srv/full.xml"; head -c 4000 "$T/srv/full.xml" > "$T/srv/feed.xml"
python3 -I -c 'import bz2, sys; open(sys.argv[2], "wb").write(bz2.compress(open(sys.argv[1], "rb").read()))' "$T/srv/feed.xml" "$T/srv/feed.xml.bz2"
echo 200 > "$T/curl_mode"; run
neg "valid bz2 of a truncated XML" "feed does not parse"
serve --ts ""; run
neg "feed without <oval:timestamp>" "feed has no <oval:timestamp>"
check "no timestamp: feed timestamp metric 0" 'has "$OUT" "pft_vulnscan_feed_timestamp_seconds{$L} 0"'
rm -rf "$T/cache"; mkdir "$T/cache"; echo fail > "$T/curl_mode"; run
neg "no cache and no network" "no cached feed in $T/cache"
echo "garbage" > "$T/srv/feed.xml.bz2"; echo 200 > "$T/curl_mode"; run
neg "first download not bzip2" "no cached feed in $T/cache (fetch: FAILED: downloaded file is not a complete bzip2 stream"

echo "== 8. validate + pull"
printf 'pft_vulnscan_up{host="sentry"} 1\npft_vulnscan_last_run_timestamp_seconds{host="sentry"} 5\n' > "$T/ok.prom"
check "validate: good sentry file" 'bash "$S" validate "$T/ok.prom" sentry'
check "validate: wrong host label -> exit 2 + reason" '! bash "$S" validate "$T/ok.prom" validator > "$T/v" && grep -qx "line 1: first label is not host=\"validator\"" "$T/v"'
printf 'node_cpu{host="sentry"} 1\n' >> "$T/ok2.prom"; cat "$T/ok.prom" >> "$T/ok2.prom"
check "validate: foreign metric" '! bash "$S" validate "$T/ok2.prom" sentry > "$T/v" && grep -q "not a pft_vulnscan_ sample" "$T/v"'
printf 'pft_vulnscan_up{host="sentry"} 1\npft_vulnscan_last_run_timestamp_seconds{host="sentry"} abc\n' > "$T/bad.prom"
check "validate: malformed value" '! bash "$S" validate "$T/bad.prom" sentry > "$T/v" && grep -q "malformed sample" "$T/v"'
printf 'pft_vulnscan_last_run_timestamp_seconds{host="sentry"} 5\n' > "$T/noup.prom"
check "validate: no up sample" '! bash "$S" validate "$T/noup.prom" sentry > "$T/v" && grep -q "no pft_vulnscan_up sample" "$T/v"'
mkdir -p "$T/remote"; cp "$T/ok.prom" "$T/remote/pft_vulnscan_sentry.prom"
printf '#!/bin/sh\n# fake ssh: "cat -- FILE" on the remote = local cat\nshift; cat "$@"\n' > "$T/bin/fakessh"; chmod +x "$T/bin/fakessh"
printf 'TEXTFILE_DIR=%s\nREMOTE_DIR=%s\nPULL_SSH=%s\n' "$T/tf" "$T/remote" "$T/bin/fakessh" > "$T/pconf"
PFT_VS_CONF="$T/pconf" bash "$S" pull; echo $? > "$T/rc"
check "pull: rc 0, file copied" 'rc 0 && cmp -s "$T/ok.prom" "$T/tf/pft_vulnscan_sentry.prom"'
cp "$T/bad.prom" "$T/remote/pft_vulnscan_sentry.prom"
PFT_VS_CONF="$T/pconf" bash "$S" pull 2> "$T/err"; echo $? > "$T/rc"
check "pull: invalid remote file -> rc 2, old file kept" 'rc 2 && grep -q "validation failed: line 2: malformed sample" "$T/err" && cmp -s "$T/ok.prom" "$T/tf/pft_vulnscan_sentry.prom"'
rm -f "$T/remote/pft_vulnscan_sentry.prom"
PFT_VS_CONF="$T/pconf" bash "$S" pull 2> "$T/err"; echo $? > "$T/rc"
check "pull: fetch failure -> rc 1, old file kept, no temp left" 'rc 1 && cmp -s "$T/ok.prom" "$T/tf/pft_vulnscan_sentry.prom" && [ -z "$(find "$T/tf" -name ".pull-*")" ]'

echo "== 9. real oscap on a fixture feed (known-old / fixed-package / absent-package controls on the installed bash)"
if command -v oscap >/dev/null; then
  rm -rf "$T/cache"; mkdir "$T/cache"
  serve --real --ts "$(date -u +%FT%T)"; echo 200 > "$T/curl_mode"
  OSCAP_CMD=oscap NOWV="$(date -u +%s)" UNAME="$(uname -r)" run --json
  check "real oscap: rc 1" 'rc 1'
  check "real oscap: known-old USN-9001-1 (bash < 99:1.0) true with binary bash, archive" 'python3 -I -c "import json, sys
d = json.load(open(sys.argv[1])); f = {x[\"usn\"]: x for x in d[\"findings\"]}
assert set(f) == {\"USN-9001-1\", \"USN-9002-1\"}, set(f)
assert [p[\"binary\"] for p in f[\"USN-9001-1\"][\"packages\"]] == [\"bash\"] and f[\"USN-9001-1\"][\"fix\"] == \"archive\"
assert f[\"USN-9002-1\"][\"fix\"] == \"esm\" and f[\"USN-9001-1\"][\"packages\"][0][\"installed\"].startswith(\"0:5.1\")
" "$T/out"'
  check "real oscap: fixed-package USN-9003-1 (bash >= 0:1.0) and absent package USN-9004-1 not reported" '! grep -q "USN-900[34]-1" "$T/out"'
else
  bad "real oscap: oscap not installed (section 9 needs it)"
fi

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
