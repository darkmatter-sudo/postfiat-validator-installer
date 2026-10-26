#!/usr/bin/env bash
# "cond && ok || bad" is intended: ok() always returns 0, so bad runs only when cond fails.
# shellcheck disable=SC2015
# Offline tests for pft-logship-dockerlog.py - no root, no docker, no journald. docker is a stub that records its
# arguments and prints a feed file (like `docker logs --since` it may repeat lines the bridge already wrote).
# fixtures/dockerlog-validator.txt: 12 real `docker logs --timestamps` lines from the validator (no addresses).
# Usage: bash logship/tests/test-dockerlog.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DL="${PFT_LS_DL_SCRIPT:-$HERE/../pft-logship-dockerlog.py}"   # run the suite against another build
FX="$HERE/fixtures/dockerlog-validator.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }

cat > "$WORK/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$DL_ARGS"
cat "$DL_FEED"
[ -n "${DL_HOLD:-}" ] && exec sleep "$DL_HOLD"
exit "${DL_RC:-0}"
STUB
chmod +x "$WORK/docker"
export PFT_LS_DOCKER="$WORK/docker" PFT_LS_DL_STATE="$WORK/state" DL_ARGS="$WORK/args" DL_FEED="$WORK/feed"
ST="$WORK/state/postfiatd.state"
msgs() { cut -d' ' -f2- "$1"; }            # expected bridge output: the lines without docker's timestamp
dl() { python3 "$DL" postfiatd 2>"$WORK/err"; }
fresh() { rm -rf "$WORK/state"; }

# 1. no state: start at "now" (--tail 0), write every line without docker's timestamp, save the last one
fresh; cp "$FX" "$WORK/feed"
out="$(dl)"; rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "$(msgs "$FX")" ] && ok "fresh start: 12 real lines written, docker timestamp stripped" || bad "fresh: rc=$rc"
grep -qx 'logs -f --timestamps --tail 0 postfiatd' "$WORK/args" && ok "fresh start asks docker for --tail 0 (now, no history scan)" || bad "args: $(cat "$WORK/args")"
last="$(tail -n 1 "$FX" | cut -d' ' -f1)"
want="$(python3 -c 'import calendar,sys;d,f=sys.argv[1].rstrip("Z").split(".");import time
print(calendar.timegm(time.strptime(d,"%Y-%m-%dT%H:%M:%S"))*10**9+int(f.ljust(9,"0")))' "$last")"
[ "$(cat "$ST")" = "$want 1" ] && ok "state = last line's timestamp in ns + count 1" || bad "state: $(cat "$ST") want $want 1"

# 2. resume: docker repeats the whole feed (--since is inclusive and may overlap); only lines 9..12 are new
fresh; head -n 8 "$FX" > "$WORK/feed"; dl >/dev/null
cp "$FX" "$WORK/feed"
out="$(dl)"; rc=$?
[ "$out" = "$(tail -n 4 "$FX" | cut -d' ' -f2-)" ] && ok "resume after line 8: exactly lines 9-12, no repeats" || bad "resume: $out"
grep -q "^logs -f --timestamps --since $(sed -n 8p "$FX" | cut -d' ' -f1) postfiatd$" "$WORK/args" && ok "resume asks --since <line 8 timestamp> (9-digit ns)" || bad "resume args: $(cat "$WORK/args")"
grep -q '4 written, 8 skipped' "$WORK/err" && ok "stderr counts 4 written, 8 skipped" || bad "counts: $(cat "$WORK/err")"

# 3. several lines with the SAME timestamp: a stop after the 2nd of 3 must resume with the 3rd, not drop it
fresh
printf '2026-10-26T11:09:26.795101695Z a\n2026-10-26T11:09:26.795101695Z b\n' > "$WORK/feed"; dl >/dev/null
[ "$(cat "$ST")" = "1793012966795101695 2" ] && ok "two lines at one timestamp -> state count 2" || bad "same-ts state: $(cat "$ST")"
printf '2026-10-26T11:09:26.795101695Z a\n2026-10-26T11:09:26.795101695Z b\n2026-10-26T11:09:26.795101695Z c\n2026-10-26T11:09:27Z d\n' > "$WORK/feed"
out="$(dl)"
[ "$out" = "$(printf 'c\nd')" ] && ok "same-timestamp resume: c and d written, a and b skipped" || bad "same-ts: $out"

# 4. trimmed RFC3339Nano fractions compare as numbers: 11:09:27Z (= .000) is older than 11:09:27.5Z
fresh
printf '2026-10-26T11:09:27.5Z e\n' > "$WORK/feed"; dl >/dev/null
printf '2026-10-26T11:09:27Z old\n2026-10-26T11:09:27.5Z e\n2026-10-26T11:09:27.50001Z f\n' > "$WORK/feed"
out="$(dl)"
[ "$out" = f ] && ok "trimmed fractions: only f (27.50001 > 27.5 > 27) written" || bad "trimmed: $out"

# 5. docker's own messages have no timestamp: stderr only, not the journal, not the state
fresh
printf 'Error response from daemon: No such container: postfiatd\n' > "$WORK/feed"
out="$(DL_RC=1 dl)"; rc=$?
[ "$rc" -eq 1 ] && [ -z "$out" ] && grep -q 'No such container' "$WORK/err" && [ ! -f "$ST" ] && ok "docker error -> exit 1, stderr only, no state" || bad "error: rc=$rc out=$out"

# 6. SIGTERM while docker still streams: flush + save, state = last written line
fresh; cp "$FX" "$WORK/feed"
DL_HOLD=30 python3 "$DL" postfiatd > "$WORK/o6" 2>"$WORK/err" & pid=$!
for _ in $(seq 50); do [ "$(wc -l < "$WORK/o6")" -ge 12 ] && break; sleep 0.1; done
kill -TERM "$pid"; wait "$pid"; rc=$?
[ "$rc" -eq 0 ] && [ "$(cat "$ST")" = "$want 1" ] && ok "SIGTERM mid-stream: exit 0, state saved at line 12" || bad "sigterm: rc=$rc state=$(cat "$ST" 2>/dev/null)"
pgrep -f "sleep 30" -P "$pid" >/dev/null && bad "docker stub left running" || ok "no docker process left after SIGTERM"

# 7. SIGKILL (no save at exit): resume repeats at most the unsaved lines and never drops one
fresh; head -n 6 "$FX" > "$WORK/feed"; dl > "$WORK/o7a"             # saved at line 6
cp "$FX" "$WORK/feed"
PFT_LS_DL_SAVE=3600 DL_HOLD=30 python3 "$DL" postfiatd >> "$WORK/o7a" 2>/dev/null & pid=$!
for _ in $(seq 50); do [ "$(wc -l < "$WORK/o7a")" -ge 12 ] && break; sleep 0.1; done
kill -KILL "$pid"; wait "$pid" 2>/dev/null; pkill -f "sleep 30" 2>/dev/null
dl >> "$WORK/o7a"                                                    # restart, same feed
[ "$(sort -u "$WORK/o7a" | wc -l)" -eq 12 ] && ok "SIGKILL + restart: all 12 lines present (no gap)" || bad "sigkill gap: $(sort -u "$WORK/o7a" | wc -l)"
# lines 7-12 were written after the last save: a restart may repeat them (if they had left the stdout buffer) but
# nothing else. Here the killed run's unflushed buffer died with it, so the expected count is 0..6, not exactly 6.
dups=$(( $(wc -l < "$WORK/o7a") - 12 ))
[ "$dups" -ge 0 ] && [ "$dups" -le 6 ] && ok "SIGKILL + restart: $dups repeats (bound: the 6 lines since the last save)" || bad "dups=$dups"

# 8. a corrupt state file is ignored (start from now), never a crash
fresh; mkdir -p "$WORK/state"; printf 'garbage\n' > "$ST"; cp "$FX" "$WORK/feed"
out="$(dl)"; rc=$?
[ "$rc" -eq 0 ] && grep -q -- '--tail 0 ' "$WORK/args" && ok "corrupt state -> from now, exit 0" || bad "corrupt: rc=$rc"

# 9. container name is validated (it ends up in argv and a file name)
out="$(python3 "$DL" '../x' 2>&1)"; rc=$?
[ "$rc" -eq 3 ] && ok "bad container name -> exit 3" || bad "name: rc=$rc"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
