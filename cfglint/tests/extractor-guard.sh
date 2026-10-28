#!/usr/bin/env bash
# Extractor guard test on a synthetic source tree (no postfiatd checkout needed):
#   G1 an orphan key read (no section site nearby, no file mapping) -> exit 1 + "unattributed" on stderr
#   G2 the same tree with the orphan removed -> exit 0, registry has [demo] key "alpha" and documented_unread demo.beta
# Usage: bash tests/extractor-guard.sh [path/to/extract_registry.py]   Prints PASS/FAIL lines + RESULT; exit 0 if all pass.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EXTRACT="${1:-$HERE/../extract_registry.py}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
res() { if [ "$2" = yes ]; then PASS=$((PASS + 1)); echo "PASS $1"; else FAIL=$((FAIL + 1)); echo "FAIL $1"; fi; }

T="$WORK/src"
mkdir -p "$T/src/xrpld/core" "$T/src/xrpld/app" "$T/src/libxrpl" "$T/cfg"
printf '#define SECTION_DEMO "demo"\n' > "$T/src/xrpld/core/ConfigSections.h"
printf 'void f(Config& config)\n{\n    auto const& s = config.section(SECTION_DEMO);\n    set(x, "alpha", s);\n}\n' > "$T/src/xrpld/app/Demo.cpp"
printf '# [demo]\n#\n#   alpha = <n>\n#   beta = <n>\n' > "$T/cfg/postfiatd-example.cfg"
{
  printf 'void g(Section const& p)\n{\n'
  for _ in $(seq 1 70); do printf '    noop();\n'; done
  printf '    set(y, "orphan", p);\n}\n'
} > "$T/src/xrpld/app/Orphan.cpp"
git -C "$T" init -q && git -C "$T" add -A && git -C "$T" -c user.name=t -c user.email=t@t commit -qm t

python3 -I "$EXTRACT" "$T" > "$WORK/out" 2> "$WORK/err"; rc=$?
if [ "$rc" = 1 ] && grep -q 'unattributed' "$WORK/err" && grep -q 'Orphan.cpp:73 orphan' "$WORK/err"; then res G1-orphan-key-fails yes
else res G1-orphan-key-fails no; fi

git -C "$T" rm -q src/xrpld/app/Orphan.cpp && git -C "$T" -c user.name=t -c user.email=t@t commit -qm t2
python3 -I "$EXTRACT" "$T" > "$WORK/out" 2> "$WORK/err"; rc=$?
if [ "$rc" = 0 ] && python3 -I -c '
import json, sys
r = json.load(open(sys.argv[1]))
ok = r["sections"]["demo"]["keys"] == {"alpha": ["src/xrpld/app/Demo.cpp:4"]} \
     and r["documented_unread"] == [{"section": "demo", "key": "beta", "documented_at": "cfg/postfiatd-example.cfg:4"}]
sys.exit(0 if ok else 1)' "$WORK/out"; then res G2-clean-tree-registry yes; else res G2-clean-tree-registry no; fi

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
