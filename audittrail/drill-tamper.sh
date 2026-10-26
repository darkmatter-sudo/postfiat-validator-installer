#!/usr/bin/env bash
# Tamper drills 1 + 2 for pft-audittrail, run from the VERIFYING host (the one that holds the other host's FSS
# verification key, root-only). Nothing on the target is modified except one line appended to its canary file.
#  1. write to the target's canary (a watched test file) -> ausearch -k pft-canary shows the event with auid,
#     and pft-audittrail report counts it (auid hashed unless root/unset).
#  2. copy the target's sealed journal files here, verify them with the off-host key (expect PASS), byte-flip one
#     COPY, verify it again (expect FAIL), and verify the target's live files again (expect PASS).
# journalctl reads the key only from --verify-key=, so verification runs here, never on the target.
# Usage: sudo bash drill-tamper.sh --ssh relay --label sentry-host --key CURRENT.vkey [--key OLDER.vkey ...] [--since UTC]
#  --key may repeat: every rollback + re-apply starts a new FSS key, and archives sealed under an older key verify only
#  with that key (keep them all off-host). The byte-flip uses a file of the FIRST (current) key. --since "YYYY-MM-DD
#  HH:MM:SS" (UTC) skips sealed files whose last entry is older (listed, not verified).
# /etc/os-release is the host's. "A && B || C" lines are intended (echo never fails). Single-quoted remote
# commands expand on the target (SC2016); the byte-flip builds a one-byte printf octal escape (SC2059).
# shellcheck disable=SC1091,SC2015,SC2016,SC2059
set -uo pipefail
SSH=""; LABEL=""; KEY=""; KEYS=(); SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in --ssh) SSH="$2"; shift ;; --label) LABEL="$2"; shift ;; --key) KEYS+=("$2"); KEY="${KEY:-$2}"; shift ;; --since) SINCE="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 3 ;; esac; shift
done
if [ -z "$SSH" ] || [ -z "$LABEL" ] || [ -z "$KEY" ]; then echo "usage: $0 --ssh HOST --label NAME --key FILE" >&2; exit 3; fi
[ "$(id -u)" -eq 0 ] || { echo "needs root (reads the key)" >&2; exit 3; }
SSH_USER="$(sudo -u "${SUDO_USER:-root}" ssh -G "$SSH" 2>/dev/null | awk '$1=="user"{print $2}')"
TOOL=/usr/local/sbin/pft-audittrail
W="$(mktemp -d /root/pft-at-drill.XXXX)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
res() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "  -> PASS: $2"; else fail=$((fail + 1)); echo "  -> FAIL: $2"; fi; }
sshr() { sudo -u "${SUDO_USER:-root}" ssh -o BatchMode=yes "$SSH" "$@" </dev/null; }   # </dev/null: never hand our stdin on

echo "# OS (verifier): $(. /etc/os-release; echo "$PRETTY_NAME") | $(date -u +%FT%TZ) | target $LABEL: $(sshr '. /etc/os-release; echo "$PRETTY_NAME"')"
echo "script sha256: drill-tamper.sh $(sha256sum "$0" | cut -c1-64) | target pft-audittrail $(sshr "sha256sum $TOOL" | cut -c1-64)"
for k in "${KEYS[@]}"; do echo "key: off-host copy, sha256 prefix $(sha256sum "$k" | cut -c1-12)$([ "$k" = "$KEY" ] && echo " (current)") (content never printed)"; done
[ -z "$SINCE" ] || echo "since: $SINCE UTC (sealed files whose last entry is older are listed, not verified)"

echo; echo "== 1. watched test file: canary write -> ausearch -k pft-canary (with auid)"
M="pft-audittrail drill $(date -u +%FT%TZ) $RANDOM"
echo "\$ ssh $LABEL 'echo \"<marker>\" | sudo tee -a /var/lib/pft-audittrail/canary'   (ssh login user: $([ "$SSH_USER" = root ] && echo root || echo "<user, auid>=1000>"))"
sshr "echo '$M' | sudo tee -a /var/lib/pft-audittrail/canary >/dev/null"; sleep 2
echo "\$ ssh $LABEL 'sudo ausearch --input-logs -k pft-canary -i -ts recent' | grep -E 'type=(SYSCALL|PATH)' (last event)"
sshr "sudo ausearch --input-logs -k pft-canary -i -ts recent" > "$W/as.txt" 2>&1
awk '/^----/{b=""} {b=b $0 "\n"} END{printf "%s", b}' "$W/as.txt" | grep -E '^type=(SYSCALL|PATH)' \
  | sed -E 's/ (inode|dev|a[0-3]|ppid|pid|ses)=[^ ]+//g' | sed -E "s/(auid|uid|euid|suid|fsuid|ouid)=([a-z_][a-z0-9_-]*)/\1=\2/g" > "$W/last.txt"
if [ "$SSH_USER" != root ]; then sed -i -E "s/=$SSH_USER( |$)/=<user>\1/g" "$W/last.txt"; fi
cat "$W/last.txt"
grep -q 'name=/var/lib/pft-audittrail/canary' "$W/last.txt" && grep -q 'key=pft-canary' "$W/last.txt" && grep -qE ' auid=[^ ]+' "$W/last.txt" \
  && ! grep -q 'auid=unset' "$W/last.txt"; res $? "canary write logged under key pft-canary with a real auid"
echo "\$ ssh $LABEL 'sudo pft-audittrail report --since recent' | grep pft-canary"
sshr "sudo $TOOL report --since recent" > "$W/report.md"; grep -E '^\| (key|pft-canary) ' "$W/report.md"
grep -qE '^\| pft-canary \| [1-9]' "$W/report.md"; res $? "report counts the canary event"

echo; echo "== 2. sealed journal: off-host verify, byte-flip a COPY, live stays PASS"
MID="$(sshr 'cat /etc/machine-id')"
sshr "sudo bash -c 'ls -1 /var/log/journal/$MID/'" | grep -E '^system(@.*)?\.journal$' > "$W/files"
mkdir -p "$W/j"; n=0; sealed=""
while read -r f; do   # header read on the target (no key needed); copy only the sealed files
  h="$(sshr "sudo journalctl --header --file=/var/log/journal/$MID/$f" 2>/dev/null)"
  grep -qi 'compatible flags:.*sealed' <<<"$h" || continue
  if [ -n "$SINCE" ] && [ "$f" != system.journal ]; then
    tl="$(sed -nE 's/^Tail realtime timestamp: .*\(([0-9a-f]+)\)$/\1/p' <<<"$h")"
    if [ -n "$tl" ] && [ $((16#$tl / 1000000)) -lt "$(date -u -d "$SINCE" +%s)" ]; then
      echo "  older than --since, not verified: $f (last entry $(date -u -d "@$((16#$tl / 1000000))" +%FT%TZ))"; continue; fi
  fi
  sshr "sudo cat /var/log/journal/$MID/$f" > "$W/j/$f"; sealed="$sealed $f"; n=$((n + 1))
done < "$W/files"
echo "$LABEL has $(wc -l < "$W/files") system journal files, $n sealed (header 'Compatible flags: SEALED'); copied the sealed ones"
[ "$n" -gt 0 ]; res $? "target has sealed journal files"
vfk() { journalctl --verify --verify-key="$(cat "$2")" --file="$1" 2>&1 | sed -E "s#$W/j/##g; s#/[^ ]*/[0-9a-f]{32}/##g"; return "${PIPESTATUS[0]}"; }
vf() { vfk "$1" "$KEY"; }
whichkey() { local k; for k in "${KEYS[@]}"; do vfk "$1" "$k" >/dev/null && { sha256sum "$k" | cut -c1-12; return 0; }; done; return 1; }
ok=0; cur=""
for f in $sealed; do
  echo "\$ journalctl --verify --verify-key=<off-host key> --file=$LABEL:$f"
  if kk="$(whichkey "$W/j/$f")"; then
    for k in "${KEYS[@]}"; do [ "$(sha256sum "$k" | cut -c1-12)" = "$kk" ] && vfk "$W/j/$f" "$k" | tail -1; done; echo "   (key $kk)"
    [ "$kk" = "$(sha256sum "$KEY" | cut -c1-12)" ] && cur="$cur $f"
  else ok=1; vf "$W/j/$f" | tail -2; echo "   FAIL with every key given"; fi
done
res $ok "every sealed file PASSes off-host verification with one of the keys"
A=""
# flip the newest sealed ARCHIVED file of the current key if there is one (the active file keeps growing while we copy)
for f in $cur; do [ -z "$A" ] || [ "$f" != system.journal ] && A="$f"; done
cp "$W/j/$A" "$W/flipped.journal"; SZ="$(stat -c %s "$W/flipped.journal")"; OFF=$((SZ / 2))
B="$(dd if="$W/flipped.journal" bs=1 skip="$OFF" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')"
printf "$(printf '\\%03o' $(( B ^ 255 )))" | dd of="$W/flipped.journal" bs=1 seek="$OFF" conv=notrunc 2>/dev/null
echo "flipped 1 byte (0x$(printf %02x "$B") -> 0x$(printf %02x $(( B ^ 255 )))) at offset $OFF of $SZ in a COPY of $A"
echo "\$ journalctl --verify --verify-key=<off-host key> --file=flipped.journal"
vf "$W/flipped.journal" | sed "s#$W/##g" | tail -4; rc=${PIPESTATUS[0]}; echo "exit $rc (expect non-zero)"
[ "$rc" -ne 0 ]; res $? "byte-flipped copy FAILs verification"
echo "\$ re-copy + verify the live sealed files of $LABEL"
# the ACTIVE system.journal is being written while `cat` copies it, so a copy can be torn mid-append: retry it up
# to 3 times and print every attempt; archived files are immutable and get exactly one try
ok=0; for f in $sealed; do
  tries=1; [ "$f" = system.journal ] && tries=3
  for t in $(seq 1 "$tries"); do
    sshr "sudo cat /var/log/journal/$MID/$f" > "$W/j/$f.again"
    if kk="$(whichkey "$W/j/$f.again")"; then echo "  $f: PASS (key $kk)$([ "$t" -gt 1 ] && echo ", copy $t")"; break; fi
    echo "  $f: copy $t/$tries FAIL with every key given: $(vf "$W/j/$f.again" | grep -v '^=>' | tail -2 | tr '\n' ' ')"
    [ "$t" -eq "$tries" ] && ok=1; sleep 2
  done
done
res $ok "live sealed journal files still PASS"
echo "\$ ssh $LABEL 'sudo pft-audittrail check'"; sshr "sudo $TOOL check" | sed 's/^/  /'; res "${PIPESTATUS[0]}" "pft-audittrail check PASS on $LABEL after the drills"
echo; echo "drill-tamper: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
