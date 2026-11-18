#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2024  # remote commands single-quoted on purpose; redirects go to agent-owned repo files
# Recorded end of the two-host collection window of valwatch (task_34064fdaf85b26153cf88a4ea94515db). Read-only on
# both hosts: it changes no unit, config or node and only reads the collectors' hour files and runs the installed
# `pft-valwatch report` / `compare`. Writes into the repo working tree only:
#   valwatch/data/window.env              the window (FROM/TO) and thresholds of the live reports
#   valwatch/data/ROLE/*.jsonl.gz         the hour files the window needs (gzip -n, byte-exact copies)
#   valwatch/reports/ROLE.{txt,json,detail.json}   live `sudo pft-valwatch report --from --to` per host
#   valwatch/reports/compare.{txt,json}   `pft-valwatch compare` of the two detail files
#   1. installed files = repo HEAD (sha256), collectors active since before FROM, NRestarts.
#   2. live reports on each host.   3. snapshot of the hour files, sha256 on host = sha256 of the unpacked copy.
#   4. collection span + record counts per host from the copies.   5. offline rebuild (drill/offline-rebuild.sh).
#   6. cross-host compare.   7. promtool test rules (prom/prometheus:v3.5.0, already on the host, --network none).
#   bash valwatch/drill/collect-run.sh 2>&1 | tee LOG     (from the repo root, as the agent user, after TO)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
SHA="$(git rev-parse HEAD)"
ME="$(id -un)"; HN="$(hostname)"
FROM="${FROM:-1795033560}"; TO="${TO:-1795041000}"   # 2026-11-18T20:26:00Z .. 22:30:00Z (journal 20:36Z)
VC=postfiatd; SC=postfiatd-sentry; DD=/var/lib/pft-valwatch
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@" </dev/null; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
gate() { [ "$FAILS" = 0 ] || { echo "RESULT: FAIL - $FAILS check(s) failed, stopping after step $1"; exit 1; }; }
V=valwatch; D=$V/data; RP=$V/reports
echo "valwatch collection window close - $(date -u +%FT%TZ) - repo HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
[ -z "$(git status --short)" ] || { echo "dirty tree - stopping"; exit 3; }
[ "$(date -u +%s)" -gt "$TO" ] || { echo "window not over (TO=$TO) - stopping"; exit 3; }
echo "window FROM=$FROM ($(date -u -d "@$FROM" +%FT%TZ)) TO=$TO ($(date -u -d "@$TO" +%FT%TZ)) = $(( (TO - FROM) / 60 )) min"
check "window >= 2 h" "$([ $((TO - FROM)) -ge 7200 ] && echo 0 || echo 1)" "$((TO - FROM)) s"

echo; echo "== 1. installed = HEAD, collectors"
x "sha256sum $V/pft-valwatch.sh $V/valwatch.py $V/drill/offline-rebuild.sh"
want="$(sha256sum < $V/pft-valwatch.sh | cut -c1-64) $(sha256sum < $V/valwatch.py | cut -c1-64)"
x "sha256sum /usr/local/bin/pft-valwatch /usr/local/lib/pft-valwatch/valwatch.py; R 'sha256sum /usr/local/bin/pft-valwatch /usr/local/lib/pft-valwatch/valwatch.py'"
n="$(grep -c -e "${want% *}  /usr/local/bin/pft-valwatch" -e "${want#* }  /usr/local/lib/pft-valwatch/valwatch.py" <<<"$XOUT")"
check "installed script + helper = HEAD on both hosts" "$([ "$n" = 4 ] && echo 0 || echo 1)" "$n/4 matching"
prop='-p ActiveState -p ActiveEnterTimestampMonotonic -p ActiveEnterTimestamp -p NRestarts'
x "systemctl show pft-valwatch@$VC.service $prop; R 'systemctl show pft-valwatch@$SC.service $prop'"
nact="$(grep -c '^ActiveState=active$' <<<"$XOUT")"
check "collector active on both hosts" "$([ "$nact" = 2 ] && echo 0 || echo 1)" "$nact/2"
nr="$(grep -c '^NRestarts=0$' <<<"$XOUT")"
check "collector NRestarts 0 on both hosts" "$([ "$nr" = 2 ] && echo 0 || echo 1)" "$nr/2"
ok=0
while read -r ts; do
  e="$(date -u -d "$ts" +%s 2>/dev/null)" || { ok=1; continue; }
  [ "$e" -lt "$FROM" ] || ok=1
done < <(sed -n 's/^ActiveEnterTimestamp=//p' <<<"$XOUT")
check "both collectors active since before FROM" "$ok"
gate 1

echo; echo "== 2. live reports (sudo pft-valwatch report --from FROM --to TO)"
mkdir -p "$RP" "$D/validator" "$D/sentry"
for kind in txt json detail.json; do
  case "$kind" in txt) opt="" ;; json) opt="--json" ;; detail.json) opt="--detail" ;; esac
  echo "\$ sudo -n pft-valwatch report --container $VC --from $FROM --to $TO $opt > $RP/validator.$kind"
  sudo -n pft-valwatch report --container "$VC" --from "$FROM" --to "$TO" $opt > "$RP/validator.$kind"; rc=$?
  check "validator report $kind exit 0" "$rc" "$(wc -c < "$RP/validator.$kind") bytes"
  echo "\$ R 'sudo -n pft-valwatch report --container $SC --from $FROM --to $TO $opt' > $RP/sentry.$kind"
  R "sudo -n pft-valwatch report --container $SC --from $FROM --to $TO $opt" > "$RP/sentry.$kind"; rc=$?
  check "sentry report $kind exit 0" "$rc" "$(wc -c < "$RP/sentry.$kind") bytes"
done
x "cat $RP/validator.txt"
x "cat $RP/sentry.txt"
gate 2

echo; echo "== 3. snapshot of the hour files the window reads (FROM-2h .. TO)"
{ echo "# window and thresholds of reports/*.txt|json (valwatch/drill/collect-run.sh)"
  echo "FROM=$FROM"; echo "TO=$TO"
  for k in WARN_DELAY_MS MIN_PARTICIPATION MIN_MARGIN; do
    vl="$(sed -n "s/^$k=\([^ #]*\).*/\1/p" /etc/pft-valwatch.env)"; vs="$(R "sed -n 's/^$k=\([^ #]*\).*/\1/p' /etc/pft-valwatch.env")"
    if [ -z "$vl" ] || [ "$vl" != "$vs" ]; then echo "# $k differs or unset: validator '$vl' sentry '$vs'"; FAILS=$((FAILS + 1)); fi
    echo "$k=$vl"
  done; } > "$D/window.env"
x "cat $D/window.env"
check "thresholds equal on both hosts" "$FAILS"
hours=(); h=$(( (FROM - 7200) / 3600 * 3600 ))
while [ "$h" -le "$TO" ]; do hours+=("valwatch-$(date -u -d "@$h" +%Y%m%dT%H).jsonl"); h=$((h + 3600)); done
echo "hour files that can overlap the window: ${hours[*]}"
for role in validator sentry; do
  if [ "$role" = validator ]; then c=$VC; else c=$SC; fi
  for f in "${hours[@]}"; do
    if [ "$role" = validator ]; then
      sudo -n test -f "$DD/$c/$f" || { echo "  $role: $f absent (collector not running yet)"; continue; }
      sudo -n cat "$DD/$c/$f" | gzip -n -9 > "$D/$role/$f.gz"; src="$(sudo -n sha256sum < "$DD/$c/$f" | cut -c1-64)"
    else
      R "sudo -n test -f $DD/$c/$f" || { echo "  $role: $f absent (collector not running yet)"; continue; }
      R "sudo -n cat $DD/$c/$f" | gzip -n -9 > "$D/$role/$f.gz"; src="$(R "sudo -n sha256sum < $DD/$c/$f" | cut -c1-64)"
    fi
    cpy="$(gzip -dc "$D/$role/$f.gz" | sha256sum | cut -c1-64)"
    check "$role $f copy = host file" "$([ "$src" = "$cpy" ] && echo 0 || echo 1)" "sha256 $cpy, gz $(wc -c < "$D/$role/$f.gz") bytes"
  done
done
x "sha256sum $D/*/*.gz $RP/*"
gate 3

echo; echo "== 4. collection span and records per host (from the copies)"
span() { # ROLE -> first/last record time, records by type inside [FROM, TO], connect events
  for gz in "$D/$1"/*.gz; do gzip -dc "$gz"; done | python3 -I -c '
import json, sys
a, b = int(sys.argv[1]) * 1000, int(sys.argv[2]) * 1000
first = last = None; n = {}; ev = []
for line in sys.stdin:
    try:
        d = json.loads(line)
    except ValueError:
        n["bad"] = n.get("bad", 0) + 1; continue
    r = d.get("r", 0)
    first = r if first is None else min(first, r); last = r if last is None else max(last, r)
    if a <= r <= b:
        n[d.get("t")] = n.get(d.get("t"), 0) + 1
        if d.get("t") == "C": ev.append(d.get("ev"))
print("first_record", first // 1000, "last_record", last // 1000)
print("covers_window", int(first <= a and last >= b))
print("in_window", " ".join(f"{k}={v}" for k, v in sorted(n.items())), "C_events", ev)
' "$FROM" "$TO"
}
for role in validator sentry; do
  x "span $role"
  check "$role records cover FROM..TO" "$(grep -q '^covers_window 1$' <<<"$XOUT" && echo 0 || echo 1)"
done
gate 4

echo; echo "== 5. offline rebuild from the committed copies"
x "TMPDIR=\$HOME/.cache bash $V/drill/offline-rebuild.sh"
check "offline rebuild byte-identical (6 outputs)" "$XRC"
gate 5

echo; echo "== 6. cross-host compare (common ledger indexes)"
echo "\$ pft-valwatch compare $RP/validator.detail.json $RP/sentry.detail.json > $RP/compare.txt"
pft-valwatch compare "$RP/validator.detail.json" "$RP/sentry.detail.json" > "$RP/compare.txt"; crc=$?
echo "\$ pft-valwatch compare $RP/validator.detail.json $RP/sentry.detail.json --json > $RP/compare.json"
pft-valwatch compare "$RP/validator.detail.json" "$RP/sentry.detail.json" --json > "$RP/compare.json"; jrc=$?
x "cat $RP/compare.txt"
check "compare AGREE (exit 0, text and json)" "$([ "$crc" = 0 ] && [ "$jrc" = 0 ] && echo 0 || echo 1)" "exit $crc/$jrc"
gate 6

echo; echo "== 7. promtool test rules at HEAD"
x "sudo -n docker run --rm --network none --entrypoint promtool -v $REPO/alerts:/w:ro -w /w prom/prometheus:v3.5.0 test rules valwatch.tests.yml"
check "promtool SUCCESS" "$XRC"

echo; x "sha256sum $D/window.env $D/*/*.gz $RP/*"
echo "RESULT: $([ "$FAILS" = 0 ] && echo PASS || echo FAIL) - $FAILS check(s) failed"
[ "$FAILS" = 0 ]
