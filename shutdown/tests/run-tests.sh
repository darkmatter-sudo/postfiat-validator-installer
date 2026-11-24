#!/usr/bin/env bash
# Offline tests for pft-shutdown.sh audit: a good compose host and a good `docker run` host PASS; every finding
# F1..F6 FAILs on its own bad fixture with its named reason and its own exit bit; must-fail controls (a fixture
# that is bad in two findings gives the OR of both bits; an unreadable container exits 64; bad usage exits 65);
# REQUIRED from the measure state (p100 x factor, floor, --required); --json; duration parsers. No root, no docker.
# Usage: tests/run-tests.sh [path/to/pft-shutdown.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-shutdown.sh}"
T="$(mktemp -d -p "${TEST_TMPDIR:-${HOME:-/tmp}/.cache}" 2>/dev/null || mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -15 | sed 's/^/     | /'; }

# Fake host in $E: root/ (PFT_SHUTDOWN_ROOT), s/inspect.json, s/image-signal, s/compose.json, s/units, bin/
fresh() { # ROLE: compose | run
  N=$((N + 1)); E="$T/e$N"; mkdir -p "$E/root/etc/docker" "$E/root/usr/local/sbin" "$E/s" "$E/bin"
  echo '{"live-restore":true,"no-new-privileges":true}' > "$E/root/etc/docker/daemon.json"
  if [ "$1" = compose ]; then
    mkdir -p "$E/root/opt/postfiatd"
    jq -n '[{Id:"abc123", Image:"sha256:img", Name:"/postfiatd",
      Config:{StopSignal:null, StopTimeout:30, Labels:{"com.docker.compose.project.working_dir":"/opt/postfiatd",
        "com.docker.compose.project.config_files":"/opt/postfiatd/docker-compose.yml,/opt/postfiatd/docker-compose.shutdown.yml",
        "com.docker.compose.service":"postfiatd"}}}]' > "$E/s/inspect.json"
    echo '{"services":{"postfiatd":{"image":"x","stop_grace_period":"30s"}}}' > "$E/s/compose.json"
    export CONTAINER=postfiatd
  else
    jq -n '[{Id:"def456", Image:"sha256:img", Name:"/postfiatd-sentry", Config:{StopTimeout:30, Labels:{}}}]' > "$E/s/inspect.json"
    printf '#!/bin/sh\n# recreate\ndocker run --stop-timeout=30 x\n' > "$E/root/usr/local/sbin/pft-confine"
    export CONTAINER=postfiatd-sentry
  fi
  printf 'docker.service TimeoutStopUSec infinity\ndocker-abc123.scope TimeoutStopUSec 1min 30s\ndocker-abc123.scope KillSignal 15\ndocker-def456.scope TimeoutStopUSec 1min 30s\ndocker-def456.scope KillSignal 15\n' > "$E/s/units"
  : > "$E/s/image-signal"
  cat > "$E/bin/docker" <<B
#!/usr/bin/env bash
S="$E/s"
case "\$1" in
  inspect) [ "\$2" = "\$(cat "\$S/name" 2>/dev/null || echo "\$2")" ] || exit 1; cat "\$S/inspect.json" ;;
  image) cat "\$S/image-signal" ;;
  compose) cat "\$S/compose.json" ;;
  *) exit 1 ;;
esac
B
  cat > "$E/bin/systemctl" <<B
#!/usr/bin/env bash
# show UNIT -p PROP --value
awk -v u="\$2" -v p="\$4" '\$1 == u && \$2 == p { \$1 = ""; \$2 = ""; sub(/^ +/, ""); print; f = 1 } END { exit !f }' "$E/s/units"
B
  chmod 755 "$E/bin/docker" "$E/bin/systemctl"
  export PFT_SHUTDOWN_ROOT="$E/root" PFT_SHUTDOWN_DOCKER="$E/bin/docker" PFT_SHUTDOWN_SYSTEMCTL="$E/bin/systemctl"
  unset STATE_DIR MIN_TIMEOUT SAFETY_FACTOR RECREATE_TOOLS
}
ins() { jq "$1" "$E/s/inspect.json" > "$E/s/i.tmp" && mv "$E/s/i.tmp" "$E/s/inspect.json"; }
unitset() { sed -i "s/^$1 $2 .*/$1 $2 $3/" "$E/s/units"; }
run() { OUT="$(bash "$TOOL" "$@" 2>&1)"; RC=$?; }
expect() { # NAME RC REGEX
  if [ "$RC" = "$2" ] && grep -qE -- "$3" <<<"$OUT"; then ok "$1"; else ko "$1 (rc=$RC want $2, /$3/)" "$OUT"; fi
}
nofail() { grep -q '\[FAIL' <<<"$OUT" && ko "$1: no FAIL lines" "$OUT" || ok "$1: no FAIL lines"; }

# --- good hosts
fresh compose; run audit; expect "compose host good -> PASS" 0 '^RESULT: PASS$'; nofail "compose host good"
expect "compose F3 reads stop_grace_period" 0 '\[PASS\] F3 compose stop_grace_period 30s >= required 30s'
fresh run; run audit; expect "run host good -> PASS" 0 '^RESULT: PASS$'; nofail "run host good"
expect "run F3 names the recreate tool" 0 '\[PASS\] F3 docker run container: recreate tooling carries --stop-timeout \(/usr/local/sbin/pft-confine\)'
expect "reboot path uses the scope" 0 '\[PASS\] F6 reboot \(live-restore\): .*SIGKILL after 90s'

# --- one bad fixture per finding: ROLE | setup | exit | FAIL line regex
while IFS='|' read -r name role setup want_rc want; do
  [ -z "$name" ] && continue
  fresh "$role"; eval "$setup"; run audit
  expect "$name -> exit $want_rc" "$want_rc" "$want"
  bits=0; b=$want_rc; while [ "$b" -gt 0 ]; do bits=$((bits + (b & 1))); b=$((b >> 1)); done
  [ "$(grep -c '\[FAIL' <<<"$OUT")" = "$bits" ] && ok "$name: $bits FAIL line(s), one per exit bit" || ko "$name: $bits FAIL line(s)" "$OUT"
done <<'CASES'
F1 container SIGKILL|compose|ins '.[0].Config.StopSignal="SIGKILL"'|1|\[FAIL\] F1 stop signal SIGKILL: postfiatd only shuts down cleanly
F1 image SIGQUIT|run|echo SIGQUIT > "$E/s/image-signal"|1|\[FAIL\] F1 stop signal SIGQUIT
F2 unset timeout|compose|ins '.[0].Config.StopTimeout=null'|2|\[FAIL\] F2 container StopTimeout unset -> Docker default 10s < required 30s
F2 short timeout|run|ins '.[0].Config.StopTimeout=29'|2|\[FAIL\] F2 container StopTimeout 29s < required 30s
F3 grace unset|compose|echo '{"services":{"postfiatd":{"image":"x"}}}' > "$E/s/compose.json"|4|\[FAIL\] F3 compose stop_grace_period unset -> 10s < required 30s: the next compose up
F3 grace short|compose|echo '{"services":{"postfiatd":{"stop_grace_period":"29s"}}}' > "$E/s/compose.json"|4|\[FAIL\] F3 compose stop_grace_period 29s < required 30s
F3 service missing|compose|echo '{"services":{"other":{}}}' > "$E/s/compose.json"|4|\[FAIL\] F3 compose project /opt/postfiatd: cannot read service postfiatd
F3 grace garbage|compose|echo '{"services":{"postfiatd":{"stop_grace_period":"soon"}}}' > "$E/s/compose.json"|4|\[FAIL\] F3 compose stop_grace_period 'soon' unparseable
F3 run no tool|run|printf 'docker run x\n' > "$E/root/usr/local/sbin/pft-confine"|4|\[FAIL\] F3 docker run container: no recreate tool carries --stop-timeout
F4 lr off short (reboot chain too)|compose|echo '{"live-restore":false}' > "$E/root/etc/docker/daemon.json"|40|\[FAIL\] F4 live-restore off, dockerd shutdown-timeout unset -> 15s < required 30s
F4 lr off 29 (reboot chain too)|run|echo '{"shutdown-timeout":29}' > "$E/root/etc/docker/daemon.json"|40|\[FAIL\] F4 live-restore off, dockerd shutdown-timeout 29s < required 30s
F5 unit short|compose|unitset docker.service TimeoutStopUSec 20s|16|\[FAIL\] F5 docker.service TimeoutStopUSec 20s < required 30s
F5 unit unreadable|run|unitset docker.service TimeoutStopUSec bogus|16|\[FAIL\] F5 docker.service TimeoutStopUSec unreadable
F6 scope short|compose|unitset docker-abc123.scope TimeoutStopUSec 25s|32|\[FAIL\] F6 reboot \(live-restore\): container scope SIGKILLs after 25s < required 30s
F6 scope signal|run|unitset docker-def456.scope KillSignal 9|32|\[FAIL\] F6 reboot: container scope KillSignal 9 is not SIGTERM/SIGINT
CASES

# --- controls: combined findings OR their bits; reboot budget with live-restore off is the minimum of the chain
fresh compose; ins '.[0].Config.StopTimeout=null'; unitset docker-abc123.scope TimeoutStopUSec 5s; run audit
expect "F2+F6 -> exit 34" 34 'RESULT: FAIL - exit 34'
fresh compose; echo '{"live-restore":false,"shutdown-timeout":60}' > "$E/root/etc/docker/daemon.json"; ins '.[0].Config.StopTimeout=20'; run audit
expect "lr off: reboot = min chain 20s -> F2+F6 exit 34" 34 '\[FAIL\] F6 reboot \(live-restore off\): budget 20s < required 30s'
fresh compose; echo '{"live-restore":false,"shutdown-timeout":60}' > "$E/root/etc/docker/daemon.json"; run audit
expect "lr off, all long -> PASS" 0 '\[PASS\] F6 reboot \(live-restore off\): .* 30s >= required 30s'
fresh compose; echo nobody > "$E/s/name"; run audit
expect "container missing -> 64" 64 'cannot inspect container postfiatd'
fresh compose; echo '{bad' > "$E/root/etc/docker/daemon.json"; run audit
expect "daemon.json invalid -> 64" 64 'daemon.json is not valid JSON'
fresh compose; run audit --required 0; expect "--required 0 -> usage 65" 65 'Usage: pft-shutdown audit'
run frobnicate; expect "unknown command -> usage 65" 65 'Usage:'

# --- REQUIRED from measurements
fresh compose; export STATE_DIR="$E/root/var/lib/pft-shutdown"; mkdir -p "$STATE_DIR"
echo '{"runs":[{"stop_s":4.2,"clean":true},{"stop_s":11.1,"clean":true},{"stop_s":60,"clean":false}]}' > "$STATE_DIR/measure-postfiatd.json"
run audit; expect "p100 11.1 x 3 = 34 (unclean run ignored)" 6 'required stop budget: 34s \(p100 11.1s x 3 = 34s, floor 30s \(2 clean runs\)\)'
expect "34 > 30 -> F2+F3 fail" 6 '\[FAIL\] F2 container StopTimeout 30s < required 34s'
SAFETY_FACTOR=2 run audit; expect "factor 2 -> floor 30 wins -> PASS" 0 'required stop budget: 30s \(p100 11.1s x 2 = 23s, floor 30s'
echo '{"runs":[{"stop_s":9,"clean":false}]}' > "$STATE_DIR/measure-postfiatd.json"
run audit; expect "no clean run -> default" 0 'default \(no clean run in'
run audit --required 45; expect "--required 45 overrides" 6 'required stop budget: 45s \(--required\)'

# --- --json
fresh compose; ins '.[0].Config.StopTimeout=null'; run audit --json
if [ "$RC" = 2 ] && jq -e '.result=="FAIL" and .exit==2 and .required_s==30 and (.checks|length)==6
   and ([.checks[]|select(.status=="FAIL")|.id]==["F2"])' <<<"$OUT" >/dev/null; then ok "--json F2"; else ko "--json F2" "$OUT"; fi
fresh run; run audit --json
jq -e '.result=="PASS" and .container=="postfiatd-sentry" and (.checks|all(.status=="PASS"))' <<<"$OUT" >/dev/null \
  && ok "--json good run host" || ko "--json good run host" "$OUT"

# --- parsers (sourced functions via a tiny driver)
P="$(sed -n '/^span_s()/,/^}/p; /^dur_s()/,/^}/p' "$TOOL")"
chkp() { local got; got="$(bash -c "$P; $1 '$2'" 2>/dev/null)"; [ "$got" = "$3" ] && ok "$1 '$2' = $3" || ko "$1 '$2' = $3 (got '$got')"; }
chkp span_s "1min 30s" 90; chkp span_s infinity inf; chkp span_s 500ms 1; chkp span_s "1h 2min 3s" 3723; chkp span_s 90 90
chkp dur_s 1m30s 90; chkp dur_s 45s 45; chkp dur_s 2m 120; chkp dur_s 1h 3600; chkp dur_s 1500ms 2; chkp dur_s 10 ""

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
