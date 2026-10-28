#!/usr/bin/env bash
# Mutation check for cfglint.py: each mutant is an exact text replacement in a copy of the helper; the offline
# suite (tests/run-tests.sh <copy>) must FAIL on it. A mutant counts as caught only if it was applied (old text
# occurs exactly once), the suite printed at least one FAIL line and a RESULT line, and exited non-zero.
# Usage: [SRC=<postfiatd checkout at the registry commit>] bash tests/mutate.sh
# With SRC set, extractor mutants (E*) also run: an extractor mutant is caught if the mutated extract_registry.py
# fails tests/extractor-guard.sh, exits non-zero on the real source, or its registry differs from registry.json.
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LINT_PY="$HERE/../cfglint.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# id@@description@@exact old text (must occur exactly once)@@new text
MUTANTS=(
  'C1@@key regex accepts an empty value@@=\s*(.*\S+)\s*$")  # BasicConfig.cpp re1@@=\s*(.*)\s*$")  # BasicConfig.cpp re1'
  'C2@@documented-but-unread keys reported as plain unknown@@            if (sec, key) in unread:@@            if False:'
  'C3@@no closest-match suggestions@@cutoff=0.6)@@cutoff=0.99)'
  'C4@@duplicate keys not reported@@        if prev:@@        if False:'
  'C5@@duplicate sections not reported@@        if name in seen:@@        if False:'
  'C6@@key checks run inside value-list sections@@            continue  # value-list sections@@            pass  # value-list sections'
  'C7@@[server] port names not treated as sections@@            ports.add(strip_comment(line))@@            pass'
  'C8@@warnings do not set exit 1@@    rc = 1 if any(f["severity"] in ("error", "warn") for f in findings) else 0@@    rc = 1 if any(f["severity"] in ("error",) for f in findings) else 0'
  'C9@@trailing comments not stripped@@        return val[:i].strip()@@        return val'
  'C10@@build/registry mismatch not checked@@    if build_commit and build_commit != reg["source"]["commit"]:@@    if False:'
  'C11@@lines before the first section ignored@@    if any(sec == "" for sec, _, _ in lines):@@    if False:'
  'C12@@plain values in key sections ignored@@            elif sp["kind"] == "keys":@@            elif False:'
  'C13@@empty values ignored@@            if e and sp["kind"] != "values":@@            if False:'
  'C14@@unknown keys accepted@@        if key not in sp["keys"]:@@        if False:'
  'C15@@unknown sections accepted@@        if spec(name) is None:@@        if False:'
  'C16@@value printed in a finding@@                    "postfiatd never reads this key in [%s]" % sec,@@                    "postfiatd never reads this key in [%s] %s" % (sec, m.group(2)),'
  'C17@@registry schema not checked@@        if reg.get("schema") != "pft-cfglint-registry/1":@@        if False:'
  'C18@@comment-only config accepted@@    if parse(text) == ([], []):@@    if False:'
  'C19@@unknown flags accepted@@            elif a.startswith("-") and a != "-":@@            elif False:'
  'C20@@suggestion drawn from the wrong candidate set@@            sug = suggest(key, sp["keys"])@@            sug = suggest(key, secs)'
)

caught=0; total=0
for m in "${MUTANTS[@]}"; do
  id="${m%%@@*}"; rest="${m#*@@}"; desc="${rest%%@@*}"
  total=$((total + 1))
  cp "$LINT_PY" "$WORK/m.py"
  if ! python3 -I - "$WORK/m.py" "$m" <<'EOF'
import sys
path, spec = sys.argv[1], sys.argv[2]
_, _, old, new = spec.split("@@")
src = open(path).read()
if src.count(old) != 1:
    sys.exit(1)
open(path, "w").write(src.replace(old, new, 1))
EOF
  then
    echo "MUTANT $id NOT APPLIED ($desc)"; continue
  fi
  bash "$HERE/run-tests.sh" "$WORK/m.py" > "$WORK/out" 2>&1; rc=$?
  fails="$(grep -c '^FAIL ' "$WORK/out")"
  if [ "$rc" -ne 0 ] && [ "$fails" -gt 0 ] && grep -q '^RESULT: ' "$WORK/out"; then
    caught=$((caught + 1))
    echo "MUTANT $id CAUGHT ($desc): $(grep '^FAIL ' "$WORK/out" | cut -d' ' -f2 | paste -sd, -)"
  else
    echo "MUTANT $id NOT CAUGHT ($desc): rc=$rc fails=$fails"
  fi
done
EXTRACTOR_MUTANTS=(
  'E1@@4-argument set(v, default, "k", s) not matched@@(?:[\w.:]+\s*,\s*)?@@'
  'E2@@values() through a bound variable not seen@@                    b = BIND_RE.search(line[: m.start()])@@                    b = None'
  'E3@@variable rebinding not respected@@                            if k > 0 and bind.search(x):@@                            if False:'
  'E4@@section headings with a trailing tag (EXPERIMENTAL) skipped@@\](?:\s+[A-Z][A-Z ]*)?\s*$"@@\]\s*$"'
  'E5@@unattributed key sites dropped silently@@        return 1\n    # every SECTION_@@        pass\n    # every SECTION_'
  'E6@@NOT_CONFIG exclusions ignored@@                if any(rel == f for f, _ in NOT_CONFIG):@@                if False:'
)
if [ -n "${SRC:-}" ]; then
  # control: the unmutated extractor must reproduce the committed registry, or every E mutant would "pass" vacuously
  if python3 -I "$HERE/../extract_registry.py" "$SRC" | cmp -s - "$HERE/../registry.json"; then
    echo "CONTROL extractor (unmutated) reproduces registry.json: yes"
  else
    echo "CONTROL extractor (unmutated) reproduces registry.json: NO -> extractor mutants not run"; exit 1
  fi
  for m in "${EXTRACTOR_MUTANTS[@]}"; do
    id="${m%%@@*}"; rest="${m#*@@}"; desc="${rest%%@@*}"
    total=$((total + 1))
    cp "$HERE/../extract_registry.py" "$WORK/e.py"
    if ! python3 -I - "$WORK/e.py" "$m" <<'EOF2'
import sys
path, spec = sys.argv[1], sys.argv[2]
_, _, old, new = spec.split("@@")
old, new = old.replace("\\n", "\n"), new.replace("\\n", "\n")
src = open(path).read()
if src.count(old) != 1:
    sys.exit(1)
open(path, "w").write(src.replace(old, new, 1))
EOF2
    then
      echo "MUTANT $id NOT APPLIED ($desc)"; continue
    fi
    python3 -I "$WORK/e.py" "$SRC" > "$WORK/reg.json" 2> "$WORK/err"; rc=$?
    bash "$HERE/extractor-guard.sh" "$WORK/e.py" > "$WORK/guard" 2>&1; grc=$?
    if [ "$grc" -ne 0 ]; then
      caught=$((caught + 1)); echo "MUTANT $id CAUGHT ($desc): extractor-guard $(grep '^FAIL' "$WORK/guard" | cut -d' ' -f2 | paste -sd, -)"
    elif [ "$rc" -ne 0 ]; then
      caught=$((caught + 1)); echo "MUTANT $id CAUGHT ($desc): extractor exit $rc: $(head -c 160 "$WORK/err" | tr '\n' ' ')"
    elif ! cmp -s "$WORK/reg.json" "$HERE/../registry.json"; then
      caught=$((caught + 1))
      echo "MUTANT $id CAUGHT ($desc): registry differs ($(diff "$WORK/reg.json" "$HERE/../registry.json" | grep -c '^[<>]') lines)"
    else
      echo "MUTANT $id NOT CAUGHT ($desc): identical registry"
    fi
  done
fi
echo "MUTANTS: $caught/$total caught"
[ "$caught" -eq "$total" ]
