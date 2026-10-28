#!/usr/bin/env bash
# Offline tests for pft-timesync-pull.sh: relabel accepts the real metrics format and rejects every malformed or
# spoofing input with exit 2; pull writes atomically, keeps the previous copy on fetch/validation failure and leaves
# no temp files; the output passes the pft exporter's own textfile line check. No root, no network, no ssh.
# Usage: tests/pull-tests.sh [path/to/pft-timesync-pull.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-timesync-pull.sh}"
EXPORTER="$HERE/../../exporter/pft_exporter.py"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | tail -8; }
run() { OUT="$(PFT_TS_PULL_CONF="$T/none.env" bash "$TOOL" "$@" 2>&1)"; RC=$?; }
expect() { # NAME RC REGEX
  if [ "$RC" = "$2" ] && grep -qE -- "$3" <<<"$OUT"; then ok "$1"; else ko "$1 (rc=$RC want $2, /$3/)" "$OUT"; fi
}

# fixture in the exact format cmd_metrics writes (copied from a live pft_timesync.prom, 2026-10-28)
cat > "$T/good.prom" <<'EOF'
# HELP pft_timesync_state Audit result: 0 OK, 1 WARN, 2 CRIT
# TYPE pft_timesync_state gauge
pft_timesync_state 0
# HELP pft_timesync_daemon Active time daemon (1 for the active one)
# TYPE pft_timesync_daemon gauge
pft_timesync_daemon{daemon="chrony"} 1
# HELP pft_timesync_check Per-check state: 0 PASS/INFO, 1 WARN, 2 CRIT
# TYPE pft_timesync_check gauge
pft_timesync_check{check="conflicting-daemons"} 0
pft_timesync_check{check="root-dispersion"} 0
# HELP pft_timesync_offset_seconds System clock minus NTP time (chrony only)
# TYPE pft_timesync_offset_seconds gauge
pft_timesync_offset_seconds -0.000680615
# HELP pft_timesync_nts_sources NTS-authenticated reachable sources
# TYPE pft_timesync_nts_sources gauge
pft_timesync_nts_sources 5
# HELP pft_timesync_synced 1 if a source is selected / NTPSynchronized=yes
# TYPE pft_timesync_synced gauge
pft_timesync_synced 1
# HELP pft_timesync_collect_timestamp_seconds Unix time of this collection
# TYPE pft_timesync_collect_timestamp_seconds gauge
pft_timesync_collect_timestamp_seconds 1793225491
EOF
variant() { # NAME SED-EXPR -> $T/NAME.prom
  sed "$2" "$T/good.prom" > "$T/$1.prom"
}

# --- relabel: good input
run relabel "$T/good.prom" sentry; expect "relabel real-format file -> exit 0" 0 '^pft_timesync_state\{host="sentry"\} 0$'
samples="$(grep -vc '^#' <<<"$OUT")"; want="$(grep -vc '^#' "$T/good.prom")"
[ "$samples" = "$want" ] && ok "every sample kept ($samples)" || ko "every sample kept ($samples vs $want)" "$OUT"
[ "$(grep -v '^#' <<<"$OUT" | grep -vc '{host="sentry"[,}]')" = 0 ] && ok "host label is the FIRST label of every sample" || ko "host label first" "$OUT"
grep -qx 'pft_timesync_daemon{host="sentry",daemon="chrony"} 1' <<<"$OUT" && ok "existing labels kept after host" || ko "existing labels kept" "$OUT"
grep -qx 'pft_timesync_offset_seconds{host="sentry"} -0.000680615' <<<"$OUT" && ok "negative value kept byte-exact" || ko "negative value" "$OUT"
[ "$(grep -c '^# \(HELP\|TYPE\) ' <<<"$OUT")" = "$(grep -c '^# \(HELP\|TYPE\) ' "$T/good.prom")" ] && ok "HELP/TYPE lines kept" || ko "HELP/TYPE kept" "$OUT"
printf '%s\n' "$OUT" > "$T/relabelled.prom"
if python3 -I -c '
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r"^SAMPLE_RE = (re\.compile\(.*\))$", src, re.M)
rx = eval(m.group(1))
bad = [l for l in open(sys.argv[2]).read().splitlines() if l.strip() and not l.startswith("#") and not rx.match(l)]
sys.exit(1 if bad or not m else 0)' "$EXPORTER" "$T/relabelled.prom"; then ok "output passes the exporter's SAMPLE_RE (file would not be skipped)"
else ko "output passes the exporter's SAMPLE_RE"; fi
variant comments 's/^# HELP pft_timesync_state .*/&\n# some other comment\n\n/'
run relabel "$T/comments.prom" sentry; expect "plain comments and blank lines dropped -> exit 0" 0 '^pft_timesync_state\{host="sentry"\} 0$'
grep -q 'some other comment' <<<"$OUT" && ko "plain comment dropped" "$OUT" || ok "plain comment dropped"

# --- relabel: rejections (NAME | SED | expected reason)
while IFS='|' read -r name sedx re; do
  [ -z "$name" ] && continue
  variant x "$sedx"
  run relabel "$T/x.prom" sentry; expect "reject: $name -> exit 2" 2 "$re"
  grep -q '{host=' <<<"$OUT" && ko "reject: $name prints no samples" "$OUT" || ok "reject: $name prints no samples"
done <<'EOF'
peer sets its own host label|s/^pft_timesync_state 0$/pft_timesync_state{host="validator"} 0/|already has a host label
host label not first|s/{daemon="chrony"}/{daemon="chrony",host="validator"}/|already has a host label
foreign metric sample|s/^pft_timesync_synced 1$/node_time_seconds 1/|not a pft_timesync_ sample
foreign HELP line|s/^# HELP pft_timesync_synced /# HELP pft_up /|HELP/TYPE for a foreign metric
non-numeric value|s/^pft_timesync_nts_sources 5$/pft_timesync_nts_sources five/|malformed value
NaN value|s/^pft_timesync_nts_sources 5$/pft_timesync_nts_sources NaN/|malformed value
trailing garbage after value|s/^pft_timesync_synced 1$/pft_timesync_synced 1 1793225491 x/|malformed value
quote breaks out of a label|s/{check="root-dispersion"}/{check="a\\"} 1\\npft_up 0 #"}/|malformed labels
unclosed label set|s/{daemon="chrony"}/{daemon="chrony"/|malformed labels
second label set|s/{daemon="chrony"}/{daemon="chrony"}{x="y"}/|malformed (labels|value)
no pft_timesync_state|/^pft_timesync_state 0$/d|no pft_timesync_state sample
no collect timestamp|/^pft_timesync_collect_timestamp_seconds /d|no pft_timesync_collect_timestamp_seconds sample
EOF
: > "$T/empty.prom"; run relabel "$T/empty.prom" sentry; expect "reject: empty file -> exit 2" 2 'empty file'
{ cat "$T/good.prom"; for _ in $(seq 1 3000); do echo "# HELP pft_timesync_x padding padding"; done; } > "$T/big.prom"
run relabel "$T/big.prom" sentry; expect "reject: file over MAX_BYTES -> exit 2" 2 'bytes > MAX_BYTES 65536'
run relabel "$T/good.prom" 'Sentry;rm'; expect "bad host label -> exit 3" 3 'bad host label'
run relabel "$T/missing.prom" sentry; expect "missing file -> exit 2" 2 'not a regular file'

# --- pull with a stub transport: PULL_SSH is a command line; "cat -- REMOTE_FILE" is appended
D="$T/textfile"; mkdir -p "$D"
cat > "$T/ssh-ok" <<EOF
#!/usr/bin/env bash
# stub: ignores the remote path, serves the fixture named in \$FIX
exec cat -- "\${FIX:-$T/good.prom}"
EOF
printf '#!/usr/bin/env bash\nexit 255\n' > "$T/ssh-fail"; printf '#!/usr/bin/env bash\nsleep 5\n' > "$T/ssh-hang"
chmod +x "$T/ssh-ok" "$T/ssh-fail" "$T/ssh-hang"
pull() { OUT="$(PFT_TS_PULL_CONF="$T/none.env" TEXTFILE_DIR="$D" PULL_TIMEOUT="${TO:-20}" PULL_SSH="$1" bash "$TOOL" pull "${@:2}" 2>&1)"; RC=$?; }
DST="$D/pft_timesync_peer_sentry.prom"
pull "$T/ssh-ok"; expect "pull ok -> exit 0" 0 'pft_timesync_peer_sentry.prom ok \(8 samples\)'
cmp -s "$DST" "$T/relabelled.prom" && ok "pulled file = relabel output" || ko "pulled file = relabel output" "$(diff "$DST" "$T/relabelled.prom")"
[ "$(stat -c %a "$DST")" = 644 ] && ok "pulled file mode 644 (exporter reads it)" || ko "pulled file mode $(stat -c %a "$DST")"
pull "$T/ssh-ok" --host sentry-2; expect "pull --host sentry-2 -> its own file" 0 'pft_timesync_peer_sentry-2.prom ok'
grep -q '{host="sentry-2"}' "$D/pft_timesync_peer_sentry-2.prom" && ok "--host sets the label" || ko "--host sets the label"
rm -f "$D/pft_timesync_peer_sentry-2.prom"
cp "$DST" "$T/prev.prom"
pull "$T/ssh-fail"; expect "fetch failure -> exit 1" 1 'fetch of .* failed or timed out; kept the previous copy'
cmp -s "$DST" "$T/prev.prom" && ok "fetch failure keeps the previous copy byte-identical" || ko "fetch failure keeps previous copy"
TO=1 pull "$T/ssh-hang"; expect "hung transport -> timeout, exit 1" 1 'failed or timed out'
cmp -s "$DST" "$T/prev.prom" && ok "timeout keeps the previous copy byte-identical" || ko "timeout keeps previous copy"
variant spoof 's/^pft_timesync_state 0$/pft_timesync_state{host="validator"} 0/'
FIX="$T/spoof.prom" pull "$T/ssh-ok"; expect "spoofing peer file -> exit 2" 2 'rejected the peer file: line 3: sample already has a host label'
cmp -s "$DST" "$T/prev.prom" && ok "rejected file keeps the previous copy byte-identical" || ko "rejected file keeps previous copy"
[ -z "$(find "$D" -name '.*' -type f)" ] && ok "no temp files left in the textfile dir" || ko "temp files left: $(find "$D" -name '.*' -type f)"
pull ""; expect "PULL_SSH unset -> exit 3" 3 'PULL_SSH is not set'
OUT="$(PFT_TS_PULL_CONF="$T/none.env" TEXTFILE_DIR="$T/nodir" PULL_SSH="$T/ssh-ok" bash "$TOOL" pull 2>&1)"; RC=$?
expect "missing textfile dir -> exit 3" 3 'textfile dir .* missing'
# a conf file not owned by root is ignored (it could point PULL_SSH anywhere)
printf 'PULL_SSH=%s\n' "$T/ssh-ok" > "$T/user.env"
OUT="$(PFT_TS_PULL_CONF="$T/user.env" TEXTFILE_DIR="$D" bash "$TOOL" pull 2>&1)"; RC=$?
if [ "$(id -u)" != 0 ]; then expect "non-root-owned conf is not sourced -> exit 3" 3 'PULL_SSH is not set'; fi
run bogus; expect "unknown command -> exit 3" 3 'usage:'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
