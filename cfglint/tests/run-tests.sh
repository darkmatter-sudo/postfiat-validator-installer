#!/usr/bin/env bash
# Offline tests for pft-cfglint: fixture configs -> exit code + exact findings (via --json), registry facts, and
# (when SRC=<postfiatd checkout> is set) provenance: every key site in the registry must contain that key literal.
# Usage: bash tests/run-tests.sh [path/to/cfglint.py]   (the mutation harness passes a mutated copy)
# Prints one PASS/FAIL line per check and a RESULT line; exit 0 only if every check passed.
# shellcheck disable=SC2016  # backticks in grep patterns are literal
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LINT="${1:-$HERE/../cfglint.py}"
REG="$HERE/../registry.json"
WRAP="$HERE/../pft-cfglint.sh"
FX="$HERE/fixtures"
PASS=0; FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ok()  { PASS=$((PASS + 1)); echo "PASS $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $1${2:+ -- $2}"; }
# rc_is NAME WANT GOT [extra condition command...]
rc_is() {
  local name="$1" want="$2" got="$3"; shift 3
  if [ "$got" = "$want" ] && { [ $# -eq 0 ] || "$@"; }; then ok "$name"; else bad "$name" "rc $got, want $want"; fi
}

# lint FIXTURE -> $WORK/out.json, $WORK/rc
lint() { python3 -I "$LINT" --registry "$REG" --json "$@" > "$WORK/out.json" 2> "$WORK/err"; echo $? > "$WORK/rc"; }

# expect NAME FIXTURE RC PYEXPR [extra lint args]: PYEXPR is evaluated with f = findings list, j = whole JSON
expect() {
  local name="$1" fx="$2" want="$3" expr="$4"; shift 4
  lint "$@" "$FX/$fx"
  local rc; rc="$(cat "$WORK/rc")"
  if [ "$rc" != "$want" ]; then bad "$name" "exit $rc, want $want"; return; fi
  if python3 -I - "$WORK/out.json" "$expr" <<'EOF'
import json, sys
j = json.load(open(sys.argv[1])); f = j["findings"]
def has(code, line=None, key=None, sug=None, sev=None):
    return any(x["code"] == code and (line is None or x["line"] == line) and (key is None or x.get("key") == key)
               and (sug is None or x.get("suggestion") == sug) and (sev is None or x["severity"] == sev) for x in f)
sys.exit(0 if eval(sys.argv[2]) else 1)
EOF
  then ok "$name"; else bad "$name" "$(tr -d '\n' < "$WORK/out.json" | head -c 300)"; fi
}

# --- linter behaviour on fixtures --------------------------------------------------------------------------
expect clean-config-exit-0        clean.cfg        0 'f == [] and j["exit"] == 0'
expect vl-enable-flagged          vl-enable.cfg    1 'has("unread-documented-key", 2, "enable", "enabled", "error") and len(f) == 1'
expect vl-enable-cites-example    vl-enable.cfg    1 '"postfiatd-example.cfg:1367" in f[0]["message"]'
expect vl-enabled-clean           vl-enabled.cfg   0 'f == []'
expect unknown-section-suggest    typo-section.cfg 1 'has("unknown-section", 1, sug="overlay", sev="error") and len(f) == 1'
expect unknown-key-suggest        typo-key.cfg     1 'has("unknown-key", 2, "ip_limt", "ip_limit", "error") and len(f) == 1'
expect duplicate-key              dup-key.cfg      1 'has("duplicate-key", 3, "ip_limit", sev="warn") and len(f) == 1'
expect duplicate-section          dup-section.cfg  1 'has("duplicate-section", 5, sev="warn") and has("duplicate-key", 6, "enabled") and len(f) == 2'
expect empty-value                empty-value.cfg  1 'has("empty-value", 2, "ip_limit", sev="error") and len(f) == 1'
expect plain-value-in-keys        plain-in-keys.cfg 1 'has("not-key-value", 2, sev="warn") and len(f) == 1'
expect line-before-section        no-section.cfg   1 'has("no-section", 1, sev="error") and len(f) == 1'
expect port-section-key-typo      port-typo.cfg    1 'has("unknown-key", 7, "admn", "admin") and len(f) == 1'
expect port-section-not-in-server port-unlisted.cfg 1 'has("unknown-section", 1, sug="port_grpc") and len(f) == 1'
expect tq-documented-unread       tq-unread.cfg    1 'has("unread-documented-key", 2, "zero_basefee_transaction_feelevel")'
expect comment-handling           comments.cfg     1 'has("empty-value", 3, "public_ip") and len(f) == 1'
expect crlf-line-endings          crlf.cfg         1 'has("unread-documented-key", 4, "enable") and len(f) == 1'
expect build-mismatch-warns       vl-enabled.cfg   1 'has("registry-mismatch", 0, sev="warn") and len(f) == 1' --build-commit 0000000000000000000000000000000000000000
expect build-match-quiet          vl-enabled.cfg   0 'f == []' --build-commit 32723c15e686a2088f2c83017a6ff909d93822cd

# --- exit 2 paths ------------------------------------------------------------------------------------------
lint "$FX/empty.cfg";          rc_is empty-input-exit-2 2 "$(cat "$WORK/rc")"
lint "$FX/does-not-exist.cfg"; rc_is missing-file-exit-2 2 "$(cat "$WORK/rc")"
python3 -I "$LINT" --json "$FX/clean.cfg" >/dev/null 2>&1; rc_is no-registry-exit-2 2 $?
echo '{"schema":"other"}' > "$WORK/badreg.json"
python3 -I "$LINT" --registry "$WORK/badreg.json" "$FX/clean.cfg" >/dev/null 2>&1; rc_is bad-registry-schema-exit-2 2 $?
# the flag is the only positional-looking argument, so a parser that took it as the cfg path would fail on open()
# instead: require the usage message, not just exit 2
python3 -I "$LINT" --registry "$REG" --bogus >/dev/null 2> "$WORK/err"
rc_is unknown-flag-exit-2 2 $? grep -q '^usage: ' "$WORK/err"

# --- text output and secrecy -------------------------------------------------------------------------------
python3 -I "$LINT" --registry "$REG" "$FX/vl-enable.cfg" > "$WORK/txt"; rc=$?
if [ "$rc" = 1 ] && grep -q 'did you mean `enabled`' "$WORK/txt" && grep -q '^RESULT: 1 error(s), 0 warning(s) -> exit 1$' "$WORK/txt"
then ok text-output; else bad text-output "rc $rc"; fi
printf '[overlay]\nip_limt=SECRETVALUE123\n[validator_token]\nSECRETTOKEN==\n' > "$WORK/secret.cfg"
python3 -I "$LINT" --registry "$REG" "$WORK/secret.cfg" > "$WORK/s1"; python3 -I "$LINT" --registry "$REG" --json "$WORK/secret.cfg" > "$WORK/s2"
if ! grep -q SECRET "$WORK/s1" "$WORK/s2" && grep -q ip_limt "$WORK/s1"; then ok values-never-printed; else bad values-never-printed; fi

# --- wrapper ------------------------------------------------------------------------------------------------
if [ "${1:-}" = "" ]; then
  bash "$WRAP" --file "$FX/vl-enable.cfg" > "$WORK/w"; rc_is wrapper-file-mode 1 $? grep -q unread-documented-key "$WORK/w"
  bash "$WRAP" --file "$FX/clean.cfg" --json > "$WORK/w"; rc_is wrapper-json-clean 0 $? grep -q '"exit": 0' "$WORK/w"
  bash "$WRAP" --nope >/dev/null 2>&1; rc_is wrapper-usage-exit-2 2 $?
  bash "$WRAP" --file "$FX/clean.cfg" --ssh somehost >/dev/null 2>&1; rc_is wrapper-file-ssh-exclusive 2 $?
fi

# --- registry facts -----------------------------------------------------------------------------------------
if python3 -I - "$REG" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1])); s = r["sections"]
checks = [
    r["source"]["commit"] == "32723c15e686a2088f2c83017a6ff909d93822cd",
    list(s["vl"]["keys"]) == ["enabled"],
    s["vl"]["keys"]["enabled"] == ["src/xrpld/overlay/detail/OverlayImpl.cpp:1625"],
    {"section": "vl", "key": "enable", "documented_at": "cfg/postfiatd-example.cfg:1367"} in r["documented_unread"],
    s["crawl"]["kind"] == "mixed" and s["overlay"]["kind"] == "keys" and s["validator_token"]["kind"] == "values",
    "verify_endpoints" in s["overlay"]["keys"] and "minimum_escalation_multiplier" in s["transaction_queue"]["keys"],
    "admin" in r["port_section"]["keys"] and "secure_gateway" in r["port_section"]["keys"],
    all(v["sites"] for v in s.values()),
]
sys.exit(0 if all(checks) else 1)
EOF
then ok registry-facts; else bad registry-facts; fi

# --- extractor guard on a synthetic source tree (no checkout needed) -----------------------------------------
if [ "${1:-}" = "" ]; then
  if bash "$HERE/extractor-guard.sh" > "$WORK/g" 2>&1; then ok extractor-guard-synthetic
  else bad extractor-guard-synthetic "$(grep '^FAIL' "$WORK/g" | paste -sd, -)"; fi
fi

# --- provenance against the source tree (optional: SRC=<checkout at the registry commit>) ------------------
if [ -n "${SRC:-}" ] && [ "${1:-}" = "" ]; then
  if python3 -I - "$REG" "$SRC" <<'EOF'
import json, subprocess, sys
r = json.load(open(sys.argv[1])); src = sys.argv[2]
head = subprocess.run(["git", "-C", src, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
assert head == r["source"]["commit"], "source checkout is not at the registry commit"
n = bad = 0
specs = [(k, v) for sec in r["sections"].values() for k, v in sec["keys"].items()] + list(r["port_section"]["keys"].items())
for key, sites in specs:
    for site in sites:
        path, line = site.rsplit(":", 1)
        text = open(f"{src}/{path}").read().splitlines()
        window = "\n".join(text[int(line) - 1:int(line) + 2])
        n += 1
        if '"%s"' % key not in window:
            bad += 1; print("  provenance miss:", key, site)
print("  provenance: %d key sites checked, %d misses" % (n, bad))
sys.exit(1 if bad or n == 0 else 0)
EOF
  then ok registry-provenance; else bad registry-provenance; fi
  if python3 -I "$HERE/../extract_registry.py" "$SRC" | cmp -s - "$REG"; then ok registry-regenerates-identically
  else bad registry-regenerates-identically; fi
fi

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
