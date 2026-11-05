#!/usr/bin/env bash
# Offline test of the `#@ check:` line in profiles/pft-integrity.service.conf with stub systemctl/journalctl.
# Exit 1 (WARN) may pass only when the unit's own invocation logged exactly one WARN: its own new drop-in.
# Usage: bash tests/test-integrity-check.sh [profile]. Stubs live in a temp dir under tests/ (/tmp may be noexec).
set -uo pipefail
T="$(cd "$(dirname "$0")" && pwd)"
P="${1:-$T/../profiles/pft-integrity.service.conf}"
S="$(mktemp -d "$T/.chk.XXXXXX")"; trap 'rm -rf "$S"' EXIT
mkdir "$S/bin"
cat > "$S/bin/systemctl" <<EOF
#!/bin/sh
case "\$*" in *Result*) echo success ;; *ExecMainStatus*) cat "$S/status" ;; *InvocationID*) echo abc123 ;; *) exit 9 ;; esac
EOF
cat > "$S/bin/journalctl" <<EOF
#!/bin/sh
case "\$*" in *_SYSTEMD_INVOCATION_ID=abc123*) cat "$S/journal" ;; *) exit 9 ;; esac
EOF
chmod 0755 "$S/bin/systemctl" "$S/bin/journalctl"
echo 7 > "$S/status"
[ "$(PATH="$S/bin:$PATH" systemctl show -p ExecMainStatus --value x)" = 7 ] || { echo "FAIL stubs not executable here"; exit 1; }
c="$(sed -n 's/^#@ check: //p' "$P" | head -1)"
pass=0; fail=0
t() { echo "$2" > "$S/status"; printf '%b' "$3" > "$S/journal"
  PATH="$S/bin:$PATH" bash -c "$c" > /dev/null 2>&1; local r=$?
  if [ "$r" = "$4" ]; then pass=$((pass+1)); echo "PASS $1 (rc $r)"; else fail=$((fail+1)); echo "FAIL $1 (rc $r, want $4)"; fi; }
H='pft-integrity verify - x\n'
OWN='  [WARN] dropin:pft-integrity.service.d/50-unitguard.conf  added    new file\n'
t "exit 0 passes" 0 "${H}RESULT: PASS\n" 0
t "exit 1, only its own drop-in added: pass" 1 "${H}${OWN}RESULT: WARN\n" 0
t "exit 1, another unit's drop-in added: fail" 1 "${H}  [WARN] dropin:pft-backup.service.d/50-unitguard.conf  added    new file\n" 1
t "exit 1, own drop-in + another WARN: fail" 1 "${H}${OWN}  [WARN] fw:ufw  changed  sha256\n" 1
t "exit 1, own drop-in changed (not added): fail" 1 "${H}  [WARN] dropin:pft-integrity.service.d/50-unitguard.conf  changed  sha256\n" 1
t "exit 1, FAIL line: fail" 1 "${H}  [FAIL] dropin:pft-integrity.service.d/50-unitguard.conf  added    new file\n" 1
t "exit 1, no WARN line (e.g. sandbox read error): fail" 1 "${H}error: cannot read\n" 1
t "exit 2: fail" 2 "${H}${OWN}" 1
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
