#!/usr/bin/env bash
# Tamper drills 1 + 2 for pft-audittrail. The FSS verification key of the TARGET lives only on the VERIFIER
# (the other host, root-only) and is never copied anywhere. Nothing on the target is modified except one line
# appended to its canary file.
#  1. write to the target's canary (a watched test file) -> ausearch -k pft-canary shows the event with auid,
#     and pft-audittrail report counts it (auid hashed unless root/unset).
#  2. copy the target's sealed journal files to the verifier, verify them there with the off-host key (expect
#     PASS), byte-flip one COPY, verify it again (expect FAIL), and verify the target's live files again (expect PASS).
# journalctl reads the key only from --verify-key=, so verification always runs on the verifier, never on the target.
# Two transports, same checks:
#  sudo bash drill-tamper.sh --ssh relay --label sentry-host --key CURRENT.vkey [--key OLDER.vkey ...] [--since UTC]
#     run ON the verifier; the target is reached with `ssh HOST`; --key paths are local.
#  sudo bash drill-tamper.sh --verifier relay --label validator-host --key CURRENT.vkey [--key ...] [--since UTC]
#     run ON the target (for a verifier that has no ssh route back to the target); journal copies are streamed to a
#     temp dir on `ssh HOST`, verified there, and deleted; --key paths are paths ON the verifier.
#  --key may repeat: every rollback + re-apply starts a new FSS key, and archives sealed under an older key verify only
#  with that key (keep them all off-host). The byte-flip uses a file of the FIRST (current) key. --since "YYYY-MM-DD
#  HH:MM:SS" (UTC) skips sealed files whose last entry is older (listed, not verified).
# /etc/os-release is the host's. "A && B || C" lines are intended (echo never fails). Single-quoted remote
# commands expand on the far side (SC2016); the byte-flip builds a one-byte printf octal escape (SC2059).
# shellcheck disable=SC1091,SC2015,SC2016,SC2059
set -uo pipefail
SSH=""; VER=""; LABEL=""; KEY=""; KEYS=(); SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in --ssh) SSH="$2"; shift ;; --verifier) VER="$2"; shift ;; --label) LABEL="$2"; shift ;;
    --key) KEYS+=("$2"); KEY="${KEY:-$2}"; shift ;; --since) SINCE="$2"; shift ;;
    *) echo "unknown option $1" >&2; exit 3 ;; esac; shift
done
if [ -z "$LABEL" ] || [ -z "$KEY" ] || { [ -z "$SSH" ] && [ -z "$VER" ]; } || { [ -n "$SSH" ] && [ -n "$VER" ]; }; then
  echo "usage: $0 (--ssh TARGET | --verifier HOST) --label NAME --key FILE [--key FILE ...] [--since UTC]" >&2; exit 3; fi
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 3; }
asu() { sudo -u "${SUDO_USER:-root}" "$@"; }
TOOL=/usr/local/sbin/pft-audittrail
pass=0; fail=0
res() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "  -> PASS: $2"; else fail=$((fail + 1)); echo "  -> FAIL: $2"; fi; }
# T CMD: run on the target. V CMD: run on the verifier (V reads stdin, T never does). </dev/null: never hand our
# stdin on (ausearch reads stdin when it is not a tty).
if [ -n "$SSH" ]; then
  LOGIN_USER="$(asu ssh -G "$SSH" 2>/dev/null | awk '$1=="user"{print $2}')"
  T() { asu ssh -o BatchMode=yes "$SSH" "$1" </dev/null; }
  V() { bash -c "$1"; }
  VW="$(mktemp -d /root/pft-at-drill.XXXX)"
  VDESC="this host"
else
  LOGIN_USER="${SUDO_USER:-root}"
  T() { bash -c "$1" </dev/null; }
  V() { asu ssh -o BatchMode=yes "$VER" "$1"; }
  VW="$(V 'mktemp -d /root/pft-at-drill.XXXX' </dev/null)" || { echo "cannot create a temp dir on the verifier" >&2; exit 3; }
  case "$VW" in /root/pft-at-drill.*) ;; *) echo "unexpected verifier temp dir" >&2; exit 3 ;; esac
  VDESC="verifier host"
fi
W="$(mktemp -d)"   # local scratch (no key material); VW = the verifier's temp dir (journal copies)
if [ -n "$VER" ]; then trap 'rm -rf "$W"; V "rm -rf $VW" </dev/null' EXIT; else trap 'rm -rf "$W" "$VW"' EXIT; fi
KS=(); for k in "${KEYS[@]}"; do s="$(V "sha256sum '$k'" </dev/null | cut -c1-12)"; [ -n "$s" ] || { echo "key not readable on the verifier: $k" >&2; exit 3; }; KS+=("$s"); done

echo "# OS (verifier, $VDESC): $(V '. /etc/os-release; echo "$PRETTY_NAME"' </dev/null) | $(date -u +%FT%TZ) | target $LABEL: $(T '. /etc/os-release; echo "$PRETTY_NAME"')"
echo "script sha256: drill-tamper.sh $(sha256sum "$0" | cut -c1-64) | target pft-audittrail $(T "sha256sum $TOOL" | cut -c1-64)"
echo "mode: $([ -n "$SSH" ] && echo "run on the verifier, target over ssh" || echo "run on the target, journal copies streamed to the verifier over ssh")"
for i in "${!KEYS[@]}"; do echo "key: off-host copy on the verifier, sha256 prefix ${KS[$i]}$([ "$i" = 0 ] && echo " (current)") (content never printed)"; done
[ -z "$SINCE" ] || echo "since: $SINCE UTC (sealed files whose last entry is older are listed, not verified)"

echo; echo "== 1. watched test file: canary write -> ausearch -k pft-canary (with auid)"
M="pft-audittrail drill $(date -u +%FT%TZ) $RANDOM"
echo "\$ [$LABEL] echo \"<marker>\" | sudo tee -a /var/lib/pft-audittrail/canary   (login user: $([ "$LOGIN_USER" = root ] && echo root || echo "<user, auid>=1000>"))"
if [ -n "$SSH" ]; then T "echo '$M' | sudo tee -a /var/lib/pft-audittrail/canary >/dev/null"
else asu bash -c "echo '$M' | sudo tee -a /var/lib/pft-audittrail/canary >/dev/null" </dev/null; fi
sleep 2
echo "\$ [$LABEL] sudo ausearch --input-logs -k pft-canary -i -ts recent | grep -E 'type=(SYSCALL|PATH)' (last event)"
T "sudo ausearch --input-logs -k pft-canary -i -ts recent" > "$W/as.txt" 2>&1
awk '/^----/{b=""} {b=b $0 "\n"} END{printf "%s", b}' "$W/as.txt" | grep -E '^type=(SYSCALL|PATH)' \
  | sed -E 's/ (inode|dev|a[0-3]|ppid|pid|ses)=[^ ]+//g' > "$W/last.txt"
if [ "$LOGIN_USER" != root ]; then sed -i -E "s/=$LOGIN_USER( |$)/=<user>\1/g" "$W/last.txt"; fi
cat "$W/last.txt"
grep -q 'name=/var/lib/pft-audittrail/canary' "$W/last.txt" && grep -q 'key=pft-canary' "$W/last.txt" && grep -qE ' auid=[^ ]+' "$W/last.txt" \
  && ! grep -q 'auid=unset' "$W/last.txt"; res $? "canary write logged under key pft-canary with a real auid"
echo "\$ [$LABEL] sudo pft-audittrail report --since recent | grep pft-canary"
T "sudo $TOOL report --since recent" > "$W/report.md"; grep -E '^\| (key|pft-canary) ' "$W/report.md"
grep -qE '^\| pft-canary \| [1-9]' "$W/report.md"; res $? "report counts the canary event"

echo; echo "== 2. sealed journal: off-host verify, byte-flip a COPY, live stays PASS"
MID="$(T 'cat /etc/machine-id')"
T "sudo bash -c 'ls -1 /var/log/journal/$MID/'" | grep -E '^system(@.*)?\.journal$' > "$W/files"
V "mkdir -p $VW/j" </dev/null; n=0; sealed=""
cp_to_v() { T "sudo cat /var/log/journal/$MID/$1" | V "cat > $VW/j/$2"; }   # target file -> verifier copy
while read -r f; do   # header read on the target (no key needed); copy only the sealed files
  h="$(T "sudo journalctl --header --file=/var/log/journal/$MID/$f" 2>/dev/null)"
  grep -qi 'compatible flags:.*sealed' <<<"$h" || continue
  if [ -n "$SINCE" ] && [ "$f" != system.journal ]; then
    tl="$(sed -nE 's/^Tail realtime timestamp: .*\(([0-9a-f]+)\)$/\1/p' <<<"$h")"
    if [ -n "$tl" ] && [ $((16#$tl / 1000000)) -lt "$(date -u -d "$SINCE" +%s)" ]; then
      echo "  older than --since, not verified: $f (last entry $(date -u -d "@$((16#$tl / 1000000))" +%FT%TZ))"; continue; fi
  fi
  cp_to_v "$f" "$f"; sealed="$sealed $f"; n=$((n + 1))
done < "$W/files"
echo "$LABEL has $(wc -l < "$W/files") system journal files, $n sealed (header 'Compatible flags: SEALED'); copied the sealed ones to the verifier"
[ "$n" -gt 0 ]; res $? "target has sealed journal files"
# vfk FILE(in VW/j) KEYPATH: verify on the verifier; output with temp dirs and machine-id paths stripped
vfk() { V "journalctl --verify --verify-key=\"\$(cat '$2')\" --file=$VW/j/$1" </dev/null 2>&1 | sed -E "s#$VW/j/##g; s#/[^ ]*/[0-9a-f]{32}/##g"; return "${PIPESTATUS[0]}"; }
vf() { vfk "$1" "$KEY"; }
whichkey() { local i; for i in "${!KEYS[@]}"; do vfk "$1" "${KEYS[$i]}" >/dev/null && { echo "${KS[$i]}"; return 0; }; done; return 1; }
# the ACTIVE system.journal is being written while `cat` copies it, so a copy can be torn mid-append (seen on the
# busier validator journal): recopy it up to 3 times and print every attempt; archived files are immutable and get
# exactly one try. recopy F: called after a failed verify of the copy of F; returns 0 if a fresh copy verifies.
recopy() {
  local t; [ "$1" = system.journal ] || return 1
  for t in 2 3; do sleep 2; cp_to_v "$1" "$1"; kk="$(whichkey "$1")" && { echo "   copy $t/3 of the active file: PASS"; return 0; }
    echo "   copy $t/3 of the active file FAIL with every key given: $(vf "$1" | grep -v '^=>' | tail -2 | tr '\n' ' ')"; done
  return 1
}
ok=0; cur=""
for f in $sealed; do
  echo "\$ journalctl --verify --verify-key=<off-host key> --file=$LABEL:$f"
  kk="$(whichkey "$f")" || { [ "$f" = system.journal ] && echo "   copy 1/3 of the active file FAIL with every key given: $(vf "$f" | grep -v '^=>' | tail -2 | tr '\n' ' ')"; recopy "$f"; } \
    || { ok=1; vf "$f" | tail -2; echo "   FAIL with every key given"; continue; }
  for i in "${!KEYS[@]}"; do [ "${KS[$i]}" = "$kk" ] && vfk "$f" "${KEYS[$i]}" | tail -1; done; echo "   (key $kk)"
  [ "$kk" = "${KS[0]}" ] && cur="$cur $f"
done
res $ok "every sealed file PASSes off-host verification with one of the keys"
A=""
# flip the newest sealed ARCHIVED file of the current key if there is one (the active file keeps growing while we copy)
for f in $cur; do [ -z "$A" ] || [ "$f" != system.journal ] && A="$f"; done
if [ -z "$A" ]; then res 1 "byte-flipped copy FAILs verification (no verified file of the current key to flip)"; else
# the flip happens on the verifier copy (no key needed for it, but it keeps the target untouched)
OUT="$(V "set -e; cp $VW/j/$A $VW/j/flipped.journal; SZ=\$(stat -c %s $VW/j/flipped.journal); OFF=\$((SZ / 2));
  B=\$(dd if=$VW/j/flipped.journal bs=1 skip=\$OFF count=1 2>/dev/null | od -An -tu1 | tr -d ' ');
  printf \"\$(printf '\\\\%03o' \$(( B ^ 255 )))\" | dd of=$VW/j/flipped.journal bs=1 seek=\$OFF conv=notrunc 2>/dev/null;
  echo \$B \$OFF \$SZ" </dev/null)"
read -r B OFF SZ <<<"$OUT"
echo "flipped 1 byte (0x$(printf %02x "$B") -> 0x$(printf %02x $(( B ^ 255 )))) at offset $OFF of $SZ in a COPY of $A"
echo "\$ journalctl --verify --verify-key=<off-host key> --file=flipped.journal"
vf flipped.journal | tail -4; rc=${PIPESTATUS[0]}; echo "exit $rc (expect non-zero)"
# a missing or unreadable copy also exits non-zero: require journalctl's own corruption/seal verdict on the file
vf flipped.journal > "$W/flip.txt"; grep -qE 'FAIL: flipped\.journal \((Bad message|Required key|Input/output)' "$W/flip.txt" \
  && ! grep -q 'Failed to open' "$W/flip.txt" && [ "$rc" -ne 0 ]; res $? "byte-flipped copy FAILs verification (corruption verdict on the flipped file)"
fi
echo "\$ re-copy + verify the live sealed files of $LABEL"
ok=0; for f in $sealed; do
  tries=1; [ "$f" = system.journal ] && tries=3
  for t in $(seq 1 "$tries"); do
    cp_to_v "$f" "$f.again"
    if kk="$(whichkey "$f.again")"; then echo "  $f: PASS (key $kk)$([ "$t" -gt 1 ] && echo ", copy $t")"; break; fi
    echo "  $f: copy $t/$tries FAIL with every key given: $(vf "$f.again" | grep -v '^=>' | tail -2 | tr '\n' ' ')"
    [ "$t" -eq "$tries" ] && ok=1; sleep 2
  done
done
res $ok "live sealed journal files still PASS"
echo "\$ [$LABEL] sudo pft-audittrail check"; T "sudo $TOOL check" | sed 's/^/  /'; res "${PIPESTATUS[0]}" "pft-audittrail check PASS on $LABEL after the drills"
echo; echo "drill-tamper: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
