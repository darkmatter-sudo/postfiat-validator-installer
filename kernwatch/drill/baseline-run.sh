#!/usr/bin/env bash
# kernwatch step 4: recorded, read-only two-host report over the 24 h real-kernel-log baseline window.
#
#   bash kernwatch/drill/baseline-run.sh 2>&1 | tee LOG      (agent user, repo root; sudo -n, `ssh relay`)
#
# Changes nothing on either host. For each host (validator = this box, sentry = relay):
#   1  installed pft-kernwatch / helper / catalogue sha256 == this checkout (fleet manifest paths)
#   2  `pft-kernwatch report` over START..END (installed tool, same catalogue the alerts use): records, boots,
#      malformed, truncated, per-severity counts and every matched pattern (redacted excerpts only)
#   3  the same window grouped by redacted message shape (drill/baseline_shapes.py), so the records no pattern
#      matched are accounted for: no raw kernel line, address, port or PID is printed
# Output goes through peerexpose/drill/redact.py (host addresses, user, hostnames) after a positive control.
# Env: RELAY (relay) START (2026-11-04T07:17:00Z, end of the recorded install) END (2026-11-05T07:17:00Z)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"; cd "$REPO" || exit 3
REDACT="$REPO/peerexpose/drill/redact.py"; SHAPES="$HERE/baseline_shapes.py"
RELAY="${RELAY:-relay}"
START="${START:-2026-11-04T07:17:00Z}"; END="${END:-2026-11-05T07:17:00Z}"
jt() { local t="${1%Z}"; echo "${t/T/ } UTC"; } # ISO UTC -> journalctl time with explicit zone
JS="$(jt "$START")"; JE="$(jt "$END")"

SEC="$(mktemp -d)"; chmod 700 "$SEC"; LIT="$SEC/literals.tsv"; : > "$LIT"; chmod 600 "$LIT"
trap 'rm -rf "$SEC"' EXIT
R() { ssh -T -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "$@"; }
L() { bash -c "$1"; }
on() { if [ "$1" = relay ]; then R "$2"; else L "$2"; fi; } # HOST CMDSTRING
lb() { if [ "$1" = relay ]; then echo sentry; else echo validator; fi; }
HN="$(hostname)"; RHN="$(R hostname 2>/dev/null)"; [ -n "$RHN" ] || RHN="$HN"
red() { python3 -u "$REDACT" filter --literals "$LIT" | sed -E "s#$HOME#~#g; s#$HN#<host>#g; s#$RHN#<host>#g"; }
FAILS=0
check() { if [ "$1" = 0 ]; then echo "CHECK ok   $2"; else echo "CHECK FAIL $2"; FAILS=$((FAILS + 1)); fi; }

echo "pft-kernwatch 24 h baseline report - $(date -u +%FT%TZ) - $(lsb_release -ds)"
echo "repo HEAD $(git rev-parse HEAD) (clean: $([ -z "$(git status --short)" ] && echo yes || echo no))"
for f in kernwatch/drill/baseline-run.sh kernwatch/drill/baseline_shapes.py kernwatch/pft-kernwatch.sh \
  kernwatch/kernwatch_parse.py kernwatch/catalogue.tsv peerexpose/drill/redact.py; do
  echo "sha256 $(sha256sum "$f" | cut -c1-64) $f"
done
echo "window $START .. $END (journalctl --since '$JS' --until '$JE')"

echo; echo "== 0. redaction literals + positive control"
printf 'user\t%s\n' "$(id -un)" >> "$LIT"
# shellcheck disable=SC2016 # expanded on the relay
VIP="$(R 'echo "${SSH_CLIENT%% *}"')"; [ -z "$VIP" ] || printf 'ip\t%s\n' "$VIP" >> "$LIT"
SIP="$(R 'ip -4 route get 1.1.1.1 2>/dev/null | sed -nE "s/.* src ([0-9.]+).*/\1/p"')"; [ -z "$SIP" ] || printf 'ip\t%s\n' "$SIP" >> "$LIT"
RHOST="$(ssh -G "$RELAY" | awk '$1 == "hostname" { print $2 }')"; [ -z "$RHOST" ] || printf 'ip\t%s\n' "$RHOST" >> "$LIT"
echo "  literals: $(cut -f1 "$LIT" | sort | uniq -c | awk '{printf "%s %s, ", $1, $2}' | sed 's/, $//') (values not printed)"
python3 -u "$REDACT" control --literals "$LIT" | sed 's/^/  /'; RCTL="${PIPESTATUS[0]}"
[ "$RCTL" -eq 0 ] || { echo "  redaction positive control FAILED - stopping" >&2; exit 3; }

for h in local relay; do
  n="$(lb "$h")"
  echo; echo "== $n: 1. installed files match this checkout"
  for p in "kernwatch/pft-kernwatch.sh /usr/local/bin/pft-kernwatch" \
    "kernwatch/kernwatch_parse.py /usr/local/lib/pft-kernwatch/kernwatch_parse.py" \
    "kernwatch/catalogue.tsv /usr/local/lib/pft-kernwatch/catalogue.tsv"; do
    src="${p% *}"; dst="${p#* }"
    want="$(sha256sum "$src" | cut -c1-64)"; got="$(on "$h" "sha256sum $dst" 2>/dev/null | cut -c1-64)"
    echo "  $dst ${got:-missing}"
    check "$([ "$got" = "$want" ] && echo 0 || echo 1)" "$n: $dst == $src"
  done

  echo; echo "== $n: 2. pft-kernwatch report over the window (installed tool)"
  echo "\$ [$n] sudo -n pft-kernwatch report --since '$JS' --until '$JE' --format tsv"
  out="$(on "$h" "sudo -n pft-kernwatch report --since '$JS' --until '$JE' --format tsv" 2>&1)"; rc=$?
  printf '%s\n' "$out" | red | sed 's/^/  /'; echo "  (exit $rc)"
  check "$rc" "$n: report exit 0 (not truncated, journal readable)"
  bs="$(sed -n 's/^# by_severity\t//p' <<<"$out")"
  echo "  by_severity: $bs"

  echo; echo "== $n: 3. all records in the window by redacted shape"
  echo "\$ [$n] sudo -n journalctl -k --since '$JS' --until '$JE' -o json --no-pager | baseline_shapes.py"
  on "$h" "sudo -n journalctl -k --since '$JS' --until '$JE' -o json --no-pager" 2>/dev/null \
    | python3 -I "$SHAPES" | red | sed 's/^/  /'
  rc="${PIPESTATUS[0]}"; echo "  (exit $rc)"
  check "$rc" "$n: journalctl -k readable for the whole window"
done

echo; echo "baseline-run done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
exit "$FAILS"
