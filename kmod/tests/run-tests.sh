#!/usr/bin/env bash
# Offline tests for pft-kmod.sh: stub modprobe (stub_modprobe.py: fake modprobe.d, module tree, built-ins), stub docker
# (container state + server_info), stub pft-maint (status --json), fake /proc and fake clock. No root; nothing on the
# host changes. Every apply/rollback guard has its own test whose input passes every OTHER guard.
#   bash kmod/tests/run-tests.sh [SCRIPT]   (default ../pft-kmod.sh)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT/RC/F/re/before are read there
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-kmod.sh}"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${T:?}"' EXIT
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; [ -z "${KMOD_FAILFAST:-}" ] || exit 1; }   # FAILFAST: mutants.py
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }
export KMOD_T="$T" PFT_KM_TEST=1 PFT_KM_ROOT="$T/root" PFT_KM_UNAME_R=test PFT_KM_NOW=4070908800
export PFT_KM_MODPROBE="$T/bin/modprobe" PFT_KM_DOCKER="$T/bin/docker" PFT_KM_MAINT="$T/bin/pft-maint"
export CONF_FILE="$T/md/60-pft-kmod.conf" STATE_DIR="$T/state" TEXTFILE_DIR="$T/tf" PFT_KM_CONF="$T/pft-kmod.env"
mkdir -p "$T/bin" "$T/md" "$T/tf" "$T/root/proc/sys/kernel" "$T/root/lib/modules/test"
printf '#!/bin/sh\nexec python3 -I %s "$@"\n' "$HERE/stub_modprobe.py" > "$T/bin/modprobe"
# stub docker: inspect -> $T/running (true); exec C postfiatd server_info -> $T/node ("full 10"); after CONF_FILE is
# written, $T/node_after (if present) replaces $T/node (a node that breaks because of the apply)
cat > "$T/bin/docker" <<EOF
#!/bin/bash
case "\$1" in
  inspect) cat "$T/running" ;;
  exec) f="$T/node"; [ -e "$T/node_after" ] && [ -e "$CONF_FILE" ] && f="$T/node_after"
        read -r st p < "\$f"; printf '{"result":{"info":{"server_state":"%s","peers":%s}}}\n' "\$st" "\$p" ;;
  *) exit 9 ;;
esac
EOF
# stub pft-maint: status --json -> $T/maint.json
printf '#!/bin/sh\n[ "$1 $2" = "status --json" ] || exit 9\ncat %s/maint.json\n' "$T" > "$T/bin/pft-maint"
chmod +x "$T/bin/"*

DENY_ABSENT="cramfs freevxfs jffs2 hfs hfsplus rds n_hdlc"
reset() { # the fixture: a host like the live validator, before apply
  rm -rf "$T/md" "$T/state" "$T/tf" "$T/node_after"; mkdir -p "$T/md" "$T/tf"
  : > "$T/pft-kmod.env"
  printf 'install algif_aead /bin/false\n' > "$T/md/disable-algif_aead.conf"
  printf 'blacklist ax25\nblacklist x25\n' > "$T/md/blacklist-rare-network.conf"
  {
    for m in overlay bridge br_netfilter veth llc stp x_tables ip_tables ip6_tables iptable_filter iptable_nat \
             ip6table_filter ip6table_nat xt_conntrack xt_addrtype xt_tcpudp xt_multiport xt_limit xt_recent xt_comment \
             xt_LOG nf_reject_ipv4 nf_reject_ipv6 ipt_REJECT ip6t_REJECT tls xfrm_user nf_tables nfnetlink \
             nf_defrag_ipv4 nf_defrag_ipv6 libcrc32c udf usb_storage tipc atm can ieee802154 appletalk x25 ax25 netrom rose zfs; do
      echo "$m"
    done
    echo "nf_conntrack nf_defrag_ipv4 nf_defrag_ipv6 libcrc32c"; echo "nf_nat nf_conntrack"; echo "xt_MASQUERADE nf_nat x_tables"
    echo "nft_compat nf_tables x_tables"; echo "nft_chain_nat nf_tables nf_nat"; echo "nft_masq nf_tables nf_nat"
    echo "xt_nat nf_nat"; echo "dccp libcrc32c"; echo "sctp libcrc32c"
  } > "$T/tree"
  printf 'kernel/fs/squashfs/squashfs.ko\nkernel/crypto/crc32c_generic.ko\n' > "$T/root/lib/modules/test/modules.builtin"
  printf '%s 16384 0 - Live 0x0\n' overlay bridge stp llc veth nf_conntrack nf_nat x_tables ip_tables xt_MASQUERADE tls zfs \
    > "$T/root/proc/modules"
  echo /sbin/modprobe > "$T/root/proc/sys/kernel/modprobe"; echo 0 > "$T/root/proc/sys/kernel/modules_disabled"
  echo true > "$T/running"; echo "full 10" > "$T/node"
  printf '{"window":"active","remaining_sec":1500,"locks":[]}\n' > "$T/maint.json"
}
run() { OUT="$("$S" "$@" 2>&1)"; RC=$?; }
nconf() { [ -e "$CONF_FILE" ] && sha256sum < "$CONF_FILE" | cut -c1-64 || echo absent; }
refused() { # NAME EXPECTED-REASON-REGEX ARGS... : apply refused (exit 4), reason matches, CONF_FILE unchanged
  local name="$1" re="$2" before; shift 2
  before="$(nconf)"; run "$@"
  check "$name: exit 4" '[ "$RC" = 4 ]'
  check "$name: reason" 'grep -qE "REFUSED - .*$re" <<<"$OUT"'
  check "$name: CONF_FILE unchanged" '[ "$(nconf)" = "$before" ]'
}

echo "== 1. audit before apply (fixture = live validator shape)"
reset; run audit
check "audit exit 1 (findings)" '[ "$RC" = 1 ]'
check "13 loadable deny modules FAIL" '[ "$(grep -c "^FAIL  deny:.*loadable" <<<"$OUT")" = 13 ]'
check "7 absent deny modules WARN" '[ "$(grep -c "^WARN  deny:.*not in this kernel" <<<"$OUT")" = 7 ]'
for m in $DENY_ABSENT; do check "absent: $m is WARN" 'grep -qE "^WARN  deny:$m " <<<"$OUT"'; done
check "autoload PASS" 'grep -q "^PASS  autoload" <<<"$OUT"'
check "required PASS" 'grep -q "^PASS  required" <<<"$OUT"'
check "managed WARN (missing)" 'grep -q "^WARN  managed .*missing" <<<"$OUT"'
check "RESULT line" 'grep -q "^RESULT: FINDINGS - deny 20: 0 enforced, 0 loaded, 13 loadable, 7 absent, 0 builtin; required blocked 0; autoload ok -> exit 1" <<<"$OUT"'
run audit --json
check "json parses, exit 1, 23 checks" '[ "$RC" = 1 ] && [ "$(jq -r ".exit, (.checks|length)" <<<"$OUT" | tr "\n" " ")" = "1 23 " ]'
run audit --textfile
F="$T/tf/pft_kmod_validator.prom"
check "textfile written" '[ -s "$F" ]'
check "metrics: up 1, loadable 13, absent 7, enforced 0, managed 0" 'grep -qx "pft_kmod_up{host=\"validator\"} 1" "$F" && grep -qx "pft_kmod_deny_modules{host=\"validator\",state=\"loadable\"} 13" "$F" && grep -qx "pft_kmod_deny_modules{host=\"validator\",state=\"absent\"} 7" "$F" && grep -qx "pft_kmod_deny_modules{host=\"validator\",state=\"enforced\"} 0" "$F" && grep -qx "pft_kmod_managed{host=\"validator\"} 0" "$F"'
check "metrics: last_run = clock" 'grep -qx "pft_kmod_last_run_timestamp_seconds{host=\"validator\"} 4070908800" "$F"'
check "own textfile passes validate" '"$S" validate "$F" validator'
check "textfile < 2 KiB (jobwatch/exporter budget untouched: separate file)" '[ "$(stat -c %s "$F")" -lt 2048 ]'

echo "== 2. audit classifications"
reset; echo "dccp 16384 0 - Live 0x0" >> "$T/root/proc/modules"; run audit
check "loaded deny module FAIL" 'grep -qE "^FAIL  deny:dccp +loaded now" <<<"$OUT"'
reset; echo "kernel/net/sctp/sctp.ko" >> "$T/root/lib/modules/test/modules.builtin"; run audit
check "builtin deny module INFO" 'grep -qE "^INFO  deny:sctp +built into" <<<"$OUT"'
reset; echo /tmp/evil > "$T/root/proc/sys/kernel/modprobe"; run audit
check "autoload bypass FAIL" 'grep -qE "^FAIL  autoload +kernel.modprobe=/tmp/evil" <<<"$OUT"'
run audit --textfile; check "autoload_ok 0 metric" 'grep -qx "pft_kmod_autoload_ok{host=\"validator\"} 0" "$T/tf/pft_kmod_validator.prom"'
reset; echo 1 > "$T/root/proc/sys/kernel/modules_disabled"; run audit
check "modules_disabled INFO" 'grep -qE "^INFO  autoload +kernel.modules_disabled=1" <<<"$OUT"'
reset; printf 'install nf_conntrack /bin/false\n' > "$T/md/99-other.conf"; run audit
check "a foreign rule that blocks a required dependency FAILs required:*" 'grep -qE "^FAIL  required:(nf_nat|xt_MASQUERADE|nf_conntrack)" <<<"$OUT"'
run audit --textfile; check "required_blocked metric > 0" 'grep -qE "^pft_kmod_required_blocked\{host=\"validator\"\} [1-9]" "$T/tf/pft_kmod_validator.prom"'
reset; printf 'KEEP=sctp usb-storage\nEXTRA_DENY=bogusfs\n' > "$T/pft-kmod.env"; run list
check "KEEP drops sctp and usb-storage, EXTRA_DENY adds bogusfs" '! grep -qE "^(sctp|usb-storage) " <<<"$OUT" && grep -q "^bogusfs " <<<"$OUT" && [ "$(grep -c . <<<"$OUT")" = 19 ]'
reset; PFT_KM_MODPROBE=/nonexistent run audit --textfile
check "modprobe missing: exit 2, up 0, no findings series" '[ "$RC" = 2 ] && grep -qx "pft_kmod_up{host=\"validator\"} 0" "$T/tf/pft_kmod_validator.prom" && ! grep -q deny_modules "$T/tf/pft_kmod_validator.prom"'

echo "== 3. apply guards (each refusal: exit 4, nothing written)"
reset; refused "no --yes" "add --yes" apply
reset; printf '{"window":"none","remaining_sec":null,"locks":[]}\n' > "$T/maint.json"; refused "no maint window" "no active pft-maint window" apply --yes
reset; printf '{"window":"active","remaining_sec":300,"locks":[]}\n' > "$T/maint.json"; refused "window too short" "300 s left" apply --yes
reset; printf '{"window":"active","remaining_sec":1500,"locks":["statewatch until x"]}\n' > "$T/maint.json"; refused "lock held" "lock" apply --yes
reset; echo "syncing 10" > "$T/node"; refused "node not full" "node not healthy" apply --yes
reset; echo "full 0" > "$T/node"; refused "no peers" "node not healthy" apply --yes
reset; echo false > "$T/running"; refused "container not running" "node not healthy" apply --yes
reset; echo /tmp/evil > "$T/root/proc/sys/kernel/modprobe"; refused "autoload bypassed" "is not modprobe" apply --yes
reset; echo "tipc 16384 0 - Live 0x0" >> "$T/root/proc/modules"; refused "deny module loaded" "tipc is loaded" apply --yes
reset; echo "kernel/net/can/can.ko" >> "$T/root/lib/modules/test/modules.builtin"; refused "deny module builtin" "can is built into" apply --yes
reset; printf 'EXTRA_DENY=br_netfilter\n' > "$T/pft-kmod.env"; refused "deny module REQUIRED (not loaded)" "br_netfilter is REQUIRED" apply --yes
reset; echo "myvpn 16384 0 - Live 0x0" >> "$T/root/proc/modules"; echo "myvpn sctp" >> "$T/tree"; refused "deny module is a dependency of a loaded module" "sctp is a dependency" apply --yes
reset; printf 'EXTRA_REQUIRED=lxdnet\n' > "$T/pft-kmod.env"; echo "lxdnet dccp" >> "$T/tree"; refused "deny module is a dependency of EXTRA_REQUIRED" "dccp is a dependency" apply --yes
reset; mkdir -p "$STATE_DIR"; echo '{"id":"20990101T000000Z"}' > "$STATE_DIR/apply.json"; refused "last apply still in place" "still in place" apply --yes

echo "== 4. apply, audit after, idempotence"
reset; run apply --dry-run
check "dry-run exit 0, writes nothing" '[ "$RC" = 0 ] && [ ! -e "$CONF_FILE" ] && grep -q "dry-run: guards pass" <<<"$OUT"'
run apply --yes
check "apply exit 0" '[ "$RC" = 0 ]'
check "verify ok line" 'grep -q "verify ok: 20 deny modules resolve to install /bin/false" <<<"$OUT"'
check "CONF_FILE has 20 install + 20 blacklist lines" '[ "$(grep -c "^install .* /bin/false$" "$CONF_FILE")" = 20 ] && [ "$(grep -c "^blacklist " "$CONF_FILE")" = 20 ]'
check "apply record kept (sha_before absent)" '[ "$(jq -r .sha_before "$STATE_DIR/apply.json")" = absent ]'
run audit
check "audit after: exit 0, 20 enforced" '[ "$RC" = 0 ] && grep -q "RESULT: PASS - deny 20: 20 enforced, 0 loaded, 0 loadable, 0 absent" <<<"$OUT"'
check "audit after: managed PASS" 'grep -q "^PASS  managed" <<<"$OUT"'
check "stub: dccp now resolves to install /bin/false (refused load)" '[ "$("$PFT_KM_MODPROBE" --show-depends dccp)" = "install /bin/false " ]'
check "stub: allowed-module control (sctp dep libcrc32c, overlay) still insmod" '"$PFT_KM_MODPROBE" --show-depends overlay | grep -q "^insmod .*overlay.ko"'
refused "second apply refused while applied" "still in place" apply --yes
echo "# hand edit" >> "$CONF_FILE"; run audit
check "drifted CONF_FILE: managed WARN" 'grep -q "^WARN  managed .*differs" <<<"$OUT"'

echo "== 5. post-apply verify failure restores byte-identical"
reset; printf '# operator file\ninstall dccp /bin/true\n' > "$CONF_FILE"; chmod 640 "$CONF_FILE"; touch -d @1000000000 "$CONF_FILE"
before="$(nconf)"; VERIFY_INJECT=required run apply --yes
check "inject required: exit 1" '[ "$RC" = 1 ]'
check "inject required: VERIFY FAILED names required:overlay" 'grep -q "VERIFY FAILED: required:\[overlay" <<<"$OUT"'
check "restored byte-identical, mode and mtime kept" '[ "$(nconf)" = "$before" ] && [ "$(stat -c "%a %Y" "$CONF_FILE")" = "640 1000000000" ]'
check "no apply record after a restore" '[ ! -e "$STATE_DIR/apply.json" ]'
reset; printf 'install dccp /sbin/modprobe --ignore-install dccp\n' > "$T/md/99-override.conf"; run apply --yes
check "a later file overrides our dccp rule: exit 1, VERIFY FAILED deny:dccp, removed again" '[ "$RC" = 1 ] && grep -q "VERIFY FAILED: deny:dccp" <<<"$OUT" && [ ! -e "$CONF_FILE" ]'
reset; echo "syncing 3" > "$T/node_after"; run apply --yes
check "node breaks after write: exit 1, removed again (did not exist)" '[ "$RC" = 1 ] && grep -q "VERIFY FAILED: node:" <<<"$OUT" && [ ! -e "$CONF_FILE" ]'

echo "== 6. rollback"
reset; printf '# operator file\nblacklist dccp\n' > "$CONF_FILE"; chmod 640 "$CONF_FILE"; before="$(nconf)"
run apply --yes; check "apply over an existing file" '[ "$RC" = 0 ] && [ "$(nconf)" != "$before" ]'
run rollback; check "rollback without --yes refused" '[ "$RC" = 4 ] && [ "$(nconf)" != "$before" ]'
printf '{"window":"none","locks":[]}\n' > "$T/maint.json"; run rollback --yes
check "rollback without window refused" '[ "$RC" = 4 ] && [ "$(nconf)" != "$before" ]'
printf '{"window":"active","remaining_sec":1500,"locks":[]}\n' > "$T/maint.json"; run rollback --yes
check "rollback exit 0, byte-identical, mode 640" '[ "$RC" = 0 ] && [ "$(nconf)" = "$before" ] && [ "$(stat -c %a "$CONF_FILE")" = 640 ]'
check "apply record archived" '[ ! -e "$STATE_DIR/apply.json" ] && ls "$STATE_DIR"/rolled-back-*.json >/dev/null'
run rollback --yes; check "second rollback refused (no apply on record)" '[ "$RC" = 4 ]'
run apply --yes; check "re-apply after rollback" '[ "$RC" = 0 ] && grep -q "verify ok" <<<"$OUT"'
reset; run apply --yes; run rollback --yes
check "rollback of a fresh apply removes the file" '[ "$RC" = 0 ] && [ ! -e "$CONF_FILE" ]'
reset; printf 'old\n' > "$CONF_FILE"; run apply --yes; printf 'tampered\n' > "$(jq -r .backup "$STATE_DIR/apply.json")"; run rollback --yes
check "tampered backup: exit 5 ROLLBACK MISMATCH" '[ "$RC" = 5 ] && grep -q "ROLLBACK MISMATCH" <<<"$OUT"'

echo "== 7. pull / validate"
reset; "$S" audit --textfile >/dev/null 2>&1; G="$T/good.prom"; sed 's/host="validator"/host="sentry"/' "$T/tf/pft_kmod_validator.prom" > "$G"
check "validate good sentry file" '"$S" validate "$G" sentry >/dev/null'
check "validate wrong host" '! "$S" validate "$G" validator >/dev/null'
sed 's/^pft_kmod_up/node_up/' "$G" > "$T/v1"; check "validate foreign metric" '! "$S" validate "$T/v1" sentry >/dev/null'
grep -v "^pft_kmod_up" "$G" > "$T/v2"; check "validate missing up" '! "$S" validate "$T/v2" sentry >/dev/null'
grep -v "^pft_kmod_last_run" "$G" > "$T/v3"; check "validate missing last_run" '! "$S" validate "$T/v3" sentry >/dev/null'
# too big but otherwise valid (repeated valid samples), so only the size cap can refuse it
{ cat "$G"; for _ in $(seq 700); do grep "^pft_kmod_up" "$G"; done; } > "$T/v4"
check "validate too big (valid content, $(stat -c %s "$T/v4") bytes)" '[ "$(stat -c %s "$T/v4")" -gt 16384 ] && ! "$S" validate "$T/v4" sentry >/dev/null'
{ cat "$G"; for _ in $(seq 300); do grep "^pft_kmod_up" "$G"; done; } > "$T/v5"
check "validate just under the cap (valid content, $(stat -c %s "$T/v5") bytes) passes" '[ "$(stat -c %s "$T/v5")" -le 16384 ] && "$S" validate "$T/v5" sentry >/dev/null'
printf '#!/bin/sh\nshift 2; cat %s\n' "$G" > "$T/bin/fakessh"; chmod +x "$T/bin/fakessh"
printf 'PULL_SSH=%s\n' "$T/bin/fakessh" > "$T/pft-kmod.env"; run pull
check "pull ok" '[ "$RC" = 0 ] && cmp -s "$G" "$T/tf/pft_kmod_sentry.prom"'
printf '#!/bin/sh\nexit 255\n' > "$T/bin/fakessh"; run pull
check "pull fetch failure: exit 1, old copy kept" '[ "$RC" = 1 ] && cmp -s "$G" "$T/tf/pft_kmod_sentry.prom"'
printf '#!/bin/sh\ncat %s\n' "$T/v1" > "$T/bin/fakessh"; run pull
check "pull invalid file: exit 2, old copy kept, no temp left" '[ "$RC" = 2 ] && cmp -s "$G" "$T/tf/pft_kmod_sentry.prom" && [ -z "$(ls -A "$T/tf" | grep "^\.")" ]'

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
