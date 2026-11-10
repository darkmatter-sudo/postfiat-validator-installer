#!/usr/bin/env bash
# kill -9 resume drill for a running histarchive follower unit (no alerting involved: only the follower is killed).
# Usage: bash drill/kill-resume.sh UNIT WORKDIR   (WORKDIR holds archive/ and follow.log; the unit has Restart=on-failure)
# Kill 1: SIGKILL the main process; the unit restarts it after RestartSec. Kill 2: SIGKILL, then append a torn
# half-line to the active file before the restart (a crash between write() and the newline), so resume must cut it.
# Each kill checks: the archive bytes before the kill are an unchanged prefix afterwards (torn bytes excepted), the
# follower logs RESUME at last+1, it archives new ledgers, and a full offline verify PASSes with contiguous indexes
# and no gap entry. Prints CHECK ok/FAIL lines and a RESULT line; exit 0 only if every check is ok.
set -uo pipefail
UNIT="${1:?unit}"; W="${2:?workdir}"
cd "$W" || exit 2
PY="python3 code/histarchive.py"
fails=0; n=0
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
check() { n=$((n + 1)); if eval "$2"; then echo "CHECK ok   $1"; else echo "CHECK FAIL $1"; fails=$((fails + 1)); fi; }
active() { find archive/active -name '*.jsonl' | sort | tail -n 1; }
last() { python3 -c 'import json; print(json.load(open("archive/status.json"))["last"])'; }
mainpid() { systemctl show -p MainPID --value "$UNIT"; }
wait_resumed() { # OLDPID: wait (<= 90 s) for a new main PID that has archived at least 2 ledgers after RESUME
  local i
  for i in $(seq 1 90); do
    sleep 1
    p="$(mainpid)"
    if [ "$p" != 0 ] && [ "$p" != "$1" ] && [ "$(python3 -c 'import json; print(json.load(open("archive/status.json"))["pid"])')" = "$p" ] \
      && [ "$(python3 -c 'import json; print(json.load(open("archive/status.json"))["archived_this_run"])')" -ge 2 ]; then
      echo "resumed after ${i}s: new main PID archived $(python3 -c 'import json; print(json.load(open("archive/status.json"))["archived_this_run"])') ledgers"
      return 0
    fi
  done
  echo "not resumed within 90 s"; return 1
}

echo "kill -9 resume drill - $(date -u +%FT%TZ) | unit $UNIT"
echo "code sha256: $(sha256sum code/histarchive.py | cut -c1-64) code/histarchive.py"
x "systemctl show -p Restart -p RestartUSec -p ActiveState $UNIT"
for k in 1 2; do
  echo
  echo "== kill $k: SIGKILL$([ "$k" = 2 ] && echo ' + torn half-line appended before the restart')"
  a="$(active)"; before_last="$(last)"; pid="$(mainpid)"
  # copy the active file at the moment of the kill: it must be a byte prefix of the file afterwards
  x "sudo systemctl kill --kill-who=main -s KILL $UNIT"
  sleep 0.3
  cp "$a" "drill-prefix-$k.jsonl"
  pre_last="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1],"rb").read().rstrip(b"\n").split(b"\n")[-1])["i"])' "drill-prefix-$k.jsonl")"
  echo "killed PID $pid; archived up to $pre_last at the kill (status.json said $before_last before it)"
  torn=0
  if [ "$k" = 2 ]; then
    # the first 37 bytes of the next ledger's line, no newline
    printf '{"d":"%s","h":"%s' "$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n' | tr a-f A-F)" "AB" >> "$a"
    torn="$(( $(stat -c %s "$a") - $(stat -c %s "drill-prefix-$k.jsonl") ))"
    echo "appended $torn torn bytes to $a"
  fi
  wait_resumed "$pid"; rc=$?
  check "kill $k: follower restarted by systemd and archived new ledgers" "[ $rc = 0 ]"
  x "grep -n 'RESUME' follow.log | tail -n 3"
  check "kill $k: RESUME at ledger $((pre_last + 1))" "grep -q 'RESUME at ledger $((pre_last + 1)) ' follow.log"
  if [ "$k" = 2 ]; then
    check "kill 2: resume cut exactly the $torn torn bytes" "grep -q 'RESUME cut torn last line of $(basename "$(dirname "$a")")/$(basename "$a") ($torn bytes)' follow.log"
  else
    check "kill 1: no torn line to cut" "! tail -n 6 follow.log | grep -q 'RESUME cut torn'"
  fi
  check "kill $k: pre-kill bytes are an unchanged prefix" "cmp -s -n $(stat -c %s "drill-prefix-$k.jsonl") drill-prefix-$k.jsonl $a"
  x "$PY verify --dir archive | tail -n 3"
  check "kill $k: full offline verify PASS" "$PY verify --dir archive > /dev/null"
  check "kill $k: no gap recorded" "[ ! -s archive/gaps.jsonl ]"
  dup="$(python3 -c 'import json,glob
seen=[]
for f in sorted(glob.glob("archive/active/*.jsonl")):
    seen += [json.loads(x)["i"] for x in open(f) if x.strip()]
print(len(seen) - len(set(seen)), len(seen), (max(seen) - min(seen) + 1) if seen else 0)')"
  echo "active lines: duplicates $(cut -d' ' -f1 <<<"$dup"), lines $(cut -d' ' -f2 <<<"$dup"), index span $(cut -d' ' -f3 <<<"$dup")"
  check "kill $k: no duplicate index and lines == index span (no gap)" "[ \"$(cut -d' ' -f1 <<<"$dup")\" = 0 ] && [ \"$(cut -d' ' -f2 <<<"$dup")\" = \"$(cut -d' ' -f3 <<<"$dup")\" ]"
  rm -f "drill-prefix-$k.jsonl"
  sleep 5
done
echo
echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) - $((n - fails))/$n checks ok"
[ "$fails" = 0 ]
