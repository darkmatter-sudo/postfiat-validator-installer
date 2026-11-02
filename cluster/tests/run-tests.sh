#!/usr/bin/env bash
# Offline tests for pft-cluster.sh against a fake host (tests/stubs.sh + fake_node.py): audit grading of every check
# (absent/duplicate/commented/unmanaged sections, malformed keys and entries, modes, live identity, membership,
# reports, seed exposure), --json / --prom / validate / pull, keygen (0600, never printed), set-peer, plan,
# apply (refusals, dry run, idempotency, re-apply), every health-gate condition with automatic rollback,
# explicit rollback, and the integrity accept filter. No root, no docker, no network.
# Usage: tests/run-tests.sh [path/to/pft-cluster.sh]
# "A && ok || ko" is intended: ok/ko always return 0.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="${1:-$HERE/../pft-cluster.sh}"
# shellcheck source-path=SCRIPTDIR source=stubs.sh
. "$HERE/stubs.sh"
# /tmp is noexec on a host hardened by ../mounts, and the stubs must execute: default to the user cache dir
TBASE="${TEST_TMPDIR:-${XDG_CACHE_HOME:-$HOME/.cache}}"; mkdir -p "$TBASE"
T="$(mktemp -d "$TBASE/pft-cluster-tests.XXXXXX")"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0; N=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -25; }
fresh() { N=$((N + 1)); E="$T/e$N"; mk_env "$E"; use_env "$E"; CFG="$E/root$VOL/postfiatd.cfg"; ST="$E/root/var/lib/pft-cluster"; }
run() { OUT="$(timeout 60 bash "$TOOL" "$@" 2>&1)"; RC=$?; }
line() { grep -E "^  \[[A-Z]+ *\] $1 " <<<"$OUT"; }
st() { line "$1" | sed -E 's/^ *\[([A-Z]+) *\].*/\1/'; }
expect() { # NAME CHECK STATUS [DETAIL-REGEX]
  local s; s="$(st "$2")"
  if [ "$s" = "$3" ] && { [ -z "${4:-}" ] || line "$2" | grep -qE "$4"; }; then ok "$1"; else ko "$1 (want $3${4:+ /$4/}, got '${s}')" "$(line "$2")"; fi
}
restarts() { cat "$E/s/restarts" 2>/dev/null || echo 0; }
noseed() { # NAME TEXT: the stored seed must not appear in TEXT
  if [ -f "$ST/node_seed" ] && grep -qFf "$ST/node_seed" <<<"$2"; then ko "$1: SEED PRINTED" ""; else ok "$1: seed not printed"; fi
}
keyed() { run keygen; run set-peer "$PEER_NEW" sentry; } # this host has a seed, knows the peer's pinned key
peer_pinned() { echo "$PEER_NEW" > "$E/s/peer_pub"; touch "$E/s/peer_lists_us"; } # the sentry applied first
applied() { keyed; peer_pinned; run apply --yes; }

# --- audit: bare host -------------------------------------------------------------------------------------------
fresh; run audit
[ "$RC" = 1 ] && ok "bare: exit 1" || ko "bare: exit $RC" "$OUT"
expect "bare: no seed" seed:stored FAIL 'keygen'
expect "bare: no [node_seed]" cfg:node_seed FAIL 'wallet.db'
expect "bare: commented [node_seed] lines ignored" cfg:mode INFO 'holds no seed'
expect "bare: no PEER_PUBKEY" cfg:cluster_nodes FAIL 'PEER_PUBKEY not set'
expect "bare: live key not pinned" live:pubkey FAIL 'not the pinned key'
expect "bare: no member" live:cluster FAIL
expect "bare: peer not a member" live:peer FAIL
expect "bare: no reports" live:reports FAIL
expect "bare: no seed to look for" secret:exposure INFO
grep -q 'RESULT: FAIL - 7 finding' <<<"$OUT" && ok "bare: 7 findings" || ko "bare: count" "$(tail -1 <<<"$OUT")"
grep -q '/var/lib/docker' <<<"$OUT" && ko "bare: host path printed" "$OUT" || ok "bare: no host path in output"
[ "$(restarts)" = 0 ] && ! grep -q '^docker restart' "$E/s/calls" && ok "audit: never restarts" || ko "audit restarted"

run audit --json --prom "$E/s/c.prom"
J="$(sed -n '/^{/,$p' <<<"$OUT")"
[ "$RC" = 1 ] && [ "$(jq -r .findings <<<"$J")" = 7 ] && [ "$(jq -r .result <<<"$J")" = FAIL ] && [ "$(jq -r .host <<<"$J")" = validator ] \
  && [ "$(jq -r '[.checks[] | select(.id=="live:peer")][0].status' <<<"$J")" = FAIL ] && ok "json: findings 7, live:peer FAIL" || ko "json" "$OUT"
grep -qx 'pft_cluster_findings{host="validator"} 7' "$E/s/c.prom" && grep -qx 'pft_cluster_peer_clustered{host="validator"} 0' "$E/s/c.prom" \
  && grep -qx 'pft_cluster_check{host="validator",check="live:peer",status="FAIL"} 0' "$E/s/c.prom" && ! grep -q 'cfg:mode' "$E/s/c.prom" \
  && ok "prom: findings 7, clustered 0, INFO not exported" || ko "prom" "$(cat "$E/s/c.prom")"
[ "$(stat -c %a "$E/s/c.prom")" = 644 ] && [ -z "$(find "$E/s" -name 'c.prom.*')" ] && ok "prom: 0644, no temp left" || ko "prom mode/temp"
run validate "$E/s/c.prom" validator; [ "$RC" = 0 ] && ok "validate: own textfile accepted" || ko "validate own" "$OUT"
run validate "$E/s/c.prom" sentry; [ "$RC" = 2 ] && ok "validate: wrong host label rejected" || ko "validate host" "$OUT"
{ cat "$E/s/c.prom"; echo 'node_cpu_seconds_total 1'; } > "$E/s/x.prom"; run validate "$E/s/x.prom" validator
[ "$RC" = 2 ] && grep -q '1 unexpected lines' <<<"$OUT" && ok "validate: foreign line rejected" || ko "validate foreign" "$OUT"
grep -v last_run "$E/s/c.prom" > "$E/s/y.prom"; run validate "$E/s/y.prom" validator
[ "$RC" = 2 ] && grep -q 'no last_run' <<<"$OUT" && ok "validate: no last_run rejected" || ko "validate last_run" "$OUT"

# --textfile: label from the conf
printf 'HOST_LABEL=sentry\nPEER_LABEL=validator\n' > "$E/root/etc/pft-cluster.env"; run audit --textfile
[ -f "$E/root/var/lib/pft-exporter/textfile/pft_cluster_sentry.prom" ] && grep -q 'host="sentry"' "$E/root/var/lib/pft-exporter/textfile/pft_cluster_sentry.prom" \
  && ok "textfile: pft_cluster_<HOST_LABEL>.prom" || ko "textfile" "$OUT"
printf 'HOST_LABEL=Bad Label\n' > "$E/root/etc/pft-cluster.env"; run audit; [ "$RC" = 2 ] && ok "conf: bad HOST_LABEL -> exit 2" || ko "bad label rc=$RC" "$OUT"
printf 'HOST_LABEL=validator\nPEER_TAG=a;b\n' > "$E/root/etc/pft-cluster.env"; run audit; [ "$RC" = 2 ] && ok "conf: bad PEER_TAG -> exit 2" || ko "bad tag rc=$RC" "$OUT"
fresh; touch "$E/s/nocfgmount"; run audit; [ "$RC" = 2 ] && grep -q 'cannot find postfiatd.cfg' <<<"$OUT" && ok "audit: no config mount -> exit 2" || ko "no cfg mount rc=$RC" "$OUT"

# --- keygen / pubkey / set-peer ---------------------------------------------------------------------------------
fresh; run keygen
[ "$RC" = 0 ] && [ "$(stat -c %a "$ST")" = 700 ] && [ "$(stat -c %a "$ST/node_seed")" = 600 ] && [ "$(stat -c %a "$ST/fp_key")" = 600 ] \
  && grep -qxE 's[1-9A-HJ-NP-Za-km-z]{28}' "$ST/node_seed" && ok "keygen: seed 0600 in 0700 dir, fp_key 0600" || ko "keygen" "$OUT $(ls -la "$ST")"
noseed "keygen" "$OUT"
grep -qE 'pinned key node:[0-9a-f]{12}' <<<"$OUT" && ! grep -qE 'n9[A-Za-z0-9]{40}' <<<"$OUT" && ok "keygen: key printed as fingerprint only" || ko "keygen fp" "$OUT"
[ "$(find "$ST" -name '.keygen.*' | wc -l)" = 0 ] && ok "keygen: temp dir removed" || ko "keygen temp" "$(ls -la "$ST")"
S1="$(sha256sum < "$ST/node_seed")"; run keygen
[ "$RC" = 0 ] && grep -q 'already stored' <<<"$OUT" && [ "$(sha256sum < "$ST/node_seed")" = "$S1" ] && ok "keygen: idempotent, seed kept" || ko "keygen twice" "$OUT"
run pubkey; [ "$RC" = 0 ] && [ "$OUT" = "$(cat "$ST/node_pub")" ] && ok "pubkey: prints the pinned public key" || ko "pubkey" "$OUT"
noseed "pubkey" "$OUT"
grep -q 'validation_create' "$E/s/calls" && ! grep -qFf "$ST/node_seed" "$E/s/calls" && ok "keygen: no command line carried the seed" || ko "keygen argv" "$(cat "$E/s/calls")"
fresh; touch "$E/s/vc_bad"; run keygen
[ "$RC" = 2 ] && [ ! -e "$ST/node_seed" ] && [ ! -e "$ST/node_pub" ] && [ "$(find "$ST" -name '.keygen.*' | wc -l)" = 0 ] \
  && ok "keygen: RPC error -> exit 2, nothing stored" || ko "keygen bad" "$OUT"
fresh; run pubkey; [ "$RC" = 2 ] && ok "pubkey: none stored -> exit 2" || ko "pubkey none" "$OUT"
run set-peer n9short; [ "$RC" = 3 ] && ok "set-peer: malformed key -> exit 3" || ko "set-peer bad" "$OUT"
run set-peer "n9SentryPinnedKeyAfterItsOwnApplyxxxxxxxxxxxxxxxxx0"; [ "$RC" = 3 ] && ok "set-peer: base58-invalid char (0) -> exit 3" || ko "set-peer b58" "$OUT"
run set-peer "$PEER_NEW" 'bad tag'; [ "$RC" = 3 ] && ok "set-peer: bad tag -> exit 3" || ko "set-peer tag" "$OUT"
run set-peer "$PEER_NEW" sentry
[ "$RC" = 0 ] && grep -qx "PEER_PUBKEY=$PEER_NEW" "$E/root/etc/pft-cluster.env" && grep -qx 'PEER_TAG=sentry' "$E/root/etc/pft-cluster.env" \
  && [ "$(stat -c %a "$E/root/etc/pft-cluster.env")" = 600 ] && ok "set-peer: conf updated, 0600" || ko "set-peer" "$OUT"
run set-peer "$PEER_OLD" sentry; [ "$(grep -c '^PEER_PUBKEY=' "$E/root/etc/pft-cluster.env")" = 1 ] && grep -qx "PEER_PUBKEY=$PEER_OLD" "$E/root/etc/pft-cluster.env" \
  && ok "set-peer: replaces, no duplicate line" || ko "set-peer twice" "$(cat "$E/root/etc/pft-cluster.env")"

# --- plan / refusals ---------------------------------------------------------------------------------------------
fresh; keyed; run plan
[ "$RC" = 0 ] && grep -q '\[node_seed\]' <<<"$OUT" && grep -q '<seed: redacted' <<<"$OUT" && grep -qE 'node:[0-9a-f]{12} sentry' <<<"$OUT" \
  && ok "plan: block shown, seed redacted, peer as fingerprint" || ko "plan" "$OUT"
noseed "plan" "$OUT"
S0="$(sha256sum < "$CFG")"
run apply; [ "$RC" = 4 ] && grep -q 'pass --yes' <<<"$OUT" && ok "apply: no --yes -> exit 4" || ko "apply no yes" "$OUT"
rm "$E/s/maint"; run apply --yes; [ "$RC" = 4 ] && grep -q 'no active pft-maint window' <<<"$OUT" && ok "apply: no pft-maint window -> exit 4" || ko "apply no window" "$OUT"
touch "$E/s/maint"
[ "$(sha256sum < "$CFG")" = "$S0" ] && [ "$(restarts)" = 0 ] && ok "refusals: config unchanged, no restart" || ko "refusal changed something"
fresh; run set-peer "$PEER_NEW"; run apply --yes; [ "$RC" = 4 ] && grep -q 'no valid stored seed' <<<"$OUT" && ok "apply: no seed -> exit 4" || ko "apply no seed" "$OUT"
fresh; run keygen; run apply --yes; [ "$RC" = 4 ] && grep -q 'PEER_PUBKEY not set' <<<"$OUT" && ok "apply: no PEER_PUBKEY -> exit 4" || ko "apply no peer" "$OUT"
run set-peer "$(cat "$ST/node_pub")"; run apply --yes; [ "$RC" = 4 ] && grep -q "own key" <<<"$OUT" && ok "apply: own key as peer -> exit 4" || ko "apply own key" "$OUT"
fresh; keyed; printf '\n[node_seed]\nsHandWrittenSeedxxxxxxxxxxxxxx\n' >> "$CFG"; run apply --yes
[ "$RC" = 4 ] && grep -q 'unmanaged \[node_seed\]' <<<"$OUT" && ok "apply: unmanaged [node_seed] -> refused" || ko "apply unmanaged seed" "$OUT"
run plan; [ "$RC" = 4 ] && ok "plan: unmanaged [node_seed] -> REFUSE exit 4" || ko "plan refuse" "$OUT"
fresh; keyed; printf '\n  [cluster_nodes]  \n%s other\n' "$PEER_OLD" >> "$CFG"; run apply --yes
[ "$RC" = 4 ] && grep -q 'unmanaged \[cluster_nodes\]' <<<"$OUT" && ok "apply: unmanaged [cluster_nodes] (indented header) -> refused" || ko "apply unmanaged cluster" "$OUT"
fresh; keyed; printf '%s\n' "# BEGIN pft-cluster (managed; edit with pft-cluster, see cluster/README.md)" >> "$CFG"; run apply --yes
[ "$RC" = 4 ] && grep -q 'markers broken' <<<"$OUT" && ok "apply: BEGIN without END -> refused" || ko "apply markers" "$OUT"

# --- apply: success, idempotency, re-apply ------------------------------------------------------------------------
fresh; keyed; cp -p "$CFG" "$E/s/orig.cfg"; peer_pinned
run apply --yes --dry-run
[ "$RC" = 0 ] && grep -q '^+\[cluster_nodes\]' <<<"$OUT" && grep -q '^+<seed: redacted>' <<<"$OUT" && cmp -s "$CFG" "$E/s/orig.cfg" && [ "$(restarts)" = 0 ] \
  && ok "dry run: diff with seed redacted, nothing changed" || ko "dry run" "$OUT"
noseed "dry run" "$OUT"
run apply --yes --require-peer
[ "$RC" = 0 ] && grep -q 'apply: done' <<<"$OUT" && [ "$(restarts)" = 1 ] && ok "apply: exit 0, one restart" || ko "apply rc=$RC" "$OUT"
noseed "apply" "$OUT"
grep -q 'health: PASS' <<<"$OUT" && grep -q 'connected cluster=true, report' <<<"$OUT" && ok "apply: gate PASS incl. --require-peer" || ko "apply gate" "$OUT"
[ "$(stat -c %a "$CFG")" = 600 ] && [ "$(grep -c '^\[node_seed\]$' "$CFG")" = 1 ] && grep -qx "$PEER_NEW sentry" "$CFG" && ok "apply: block written, cfg 0600" || ko "apply cfg" "$(tail -8 "$CFG")"
B="$(find "$ST/backups" -name 'postfiatd.cfg.2*' ! -name '*.pubkey' ! -name '*.meta')"
[ -n "$B" ] && cmp -s "$B" "$E/s/orig.cfg" && [ "$(stat -c %a "$B")" = 600 ] && [ "$(stat -c %a "$ST/backups")" = 700 ] && [ "$(cat "$B.pubkey")" = "$WALLET_PUB" ] \
  && ok "apply: backup byte-identical, 0600, pre-apply key recorded" || ko "backup" "$(ls -la "$ST/backups")"
diff <(head -n "$(wc -l < "$E/s/orig.cfg")" "$CFG") "$E/s/orig.cfg" >/dev/null && ok "apply: every original line kept in order" || ko "apply changed other lines"
[ -z "$(find "$(dirname "$CFG")" -name '.postfiatd.cfg.pft-cluster')" ] && [ -z "$(find "$ST" -name '.cand.*')" ] && ok "apply: no temp files left" || ko "temp left"
grep -q 'integrity: accepted (cfgvol:postfiatd.cfg only)' <<<"$OUT" && [ -f "$E/s/accepted" ] && ok "apply: integrity accepted (config item only)" || ko "integrity" "$OUT"
run audit
[ "$RC" = 0 ] && grep -q 'RESULT: PASS' <<<"$OUT" && ok "after apply: audit PASS (9 checks)" || ko "after audit rc=$RC" "$OUT"
expect "after: live:pubkey pinned" live:pubkey PASS '= pinned key'
expect "after: reports" live:reports PASS 'counts this node'
expect "after: secret absent" secret:exposure PASS
run audit --prom "$E/s/a.prom"; grep -qx 'pft_cluster_peer_clustered{host="validator"} 1' "$E/s/a.prom" && grep -qx 'pft_cluster_findings{host="validator"} 0' "$E/s/a.prom" \
  && ok "after: prom clustered 1, findings 0" || ko "after prom" "$(cat "$E/s/a.prom")"
! grep -qFf "$ST/node_seed" "$E/s/a.prom" && ok "after: seed not in textfile" || ko "seed in textfile"
S2="$(sha256sum < "$CFG")"; run apply --yes
[ "$RC" = 0 ] && grep -q 'already applied' <<<"$OUT" && [ "$(restarts)" = 1 ] && [ "$(sha256sum < "$CFG")" = "$S2" ] && ok "apply: idempotent (no restart, no change)" || ko "idempotent" "$OUT"
run set-peer "$PEER_OLD" sentry; run apply --yes
[ "$RC" = 0 ] && [ "$(grep -c '^# BEGIN pft-cluster' "$CFG")" = 1 ] && grep -qx "$PEER_OLD sentry" "$CFG" && ! grep -q "$PEER_NEW" "$CFG" && ok "re-apply: block replaced, one block" || ko "re-apply" "$OUT"
run set-peer "$PEER_NEW" sentry; run apply --yes
[ "$(sha256sum < "$CFG")" = "$S2" ] && ok "re-apply: back to the first block byte-identical (no blank-line growth)" || ko "re-apply growth" "$(diff <(tail -12 "$CFG") /dev/null)"

# --- gate failures -> automatic rollback --------------------------------------------------------------------------
gate_case() { # NAME SETUP-CMDS GREP-REGEX [apply args...]: apply must roll back (exit 1) to the original file and key
  local name="$1" setup="$2" rx="$3"; shift 3
  fresh; keyed; cp -p "$CFG" "$E/s/orig.cfg"; peer_pinned; eval "$setup"
  run apply --yes "$@"
  if [ "$RC" = 1 ] && grep -q 'automatic rollback' <<<"$OUT" && grep -q 'rollback: health: PASS' <<<"$OUT" && cmp -s "$CFG" "$E/s/orig.cfg" \
     && [ "$(stat -c %a "$CFG")" = 644 ] && grep -qE "$rx" <<<"$OUT" \
     && [ "$(jq -r .result.info.pubkey_node <<<"$("$E/bin/rpc" postfiatd server_info)")" = "$WALLET_PUB" ]; then ok "gate: $name -> rolled back, exit 1"
  else ko "gate: $name (rc=$RC)" "$OUT"; fi
}
gate_case "injected miss" 'export PFT_CLUSTER_INJECT=health' 'injected=health'
gate_case "server_state never full" 'touch "$E/s/bad_when_seeded"' 'server_state=connected'
gate_case "peer not reporting (--require-peer)" 'rm "$E/s/peer_lists_us"' 'report_age=none' --require-peer
gate_case "peer connected without cluster flag (--require-peer)" 'echo "$PEER_OLD" > "$E/s/peer_pub"' 'peer_cluster=0' --require-peer
gate_case "report too old (--require-peer)" 'echo 900 > "$E/s/peer_age"' 'report_age=900' --require-peer
gate_case "pft daemon stopped" 'echo pft-senders-tx.service > "$E/s/inactive"' 'inactive daemons: pft-senders-tx.service'
gate_case "ssh handshake lost" 'touch "$E/s/sshd_bad"' 'ssh=0'
gate_case "peer port not listening" 'touch "$E/s/nopeerport"' 'FAIL after'
fresh; keyed; peer_pinned; cp -p "$CFG" "$E/s/orig.cfg"; touch "$E/s/restart_fail"; run apply --yes
[ "$RC" = 5 ] && cmp -s "$CFG" "$E/s/orig.cfg" && grep -q 'docker restart postfiatd FAILED' <<<"$OUT" && ok "gate: restart fails -> config restored, rollback restart fails -> exit 5" || ko "restart fail rc=$RC" "$OUT"
fresh; keyed; peer_pinned; touch "$E/s/bad_always"; run apply --yes
[ "$RC" = 5 ] && grep -q 'rollback: health: FAIL' <<<"$OUT" && ok "gate: node unhealthy after rollback too -> exit 5" || ko "rollback fail rc=$RC" "$OUT"
fresh; keyed; peer_pinned; cp -p "$CFG" "$E/s/orig.cfg"; echo "$PEER_NEW" > "$E/s/peer_pub"
printf 'HOST_LABEL=validator\nPEER_LABEL=sentry\nPEER_PUBKEY=%s\nPEER_TAG=sentry\n' "$PEER_NEW" > "$E/root/etc/pft-cluster.env"
# a seed the node rejects (here: one validation_create never made) -> postfiatd does not start -> rollback
echo "sNotMadeByThisNodexxxxxxxxxxxx" > "$ST/node_seed"; run apply --yes
[ "$RC" = 1 ] && cmp -s "$CFG" "$E/s/orig.cfg" && grep -q 'server_state=unknown' <<<"$OUT" && ok "gate: node does not start with the new config -> rolled back" || ko "nostart rc=$RC" "$OUT"
fresh; keyed; peer_pinned; cp -p "$CFG" "$E/s/orig.cfg"; touch "$E/s/no_cluster"; run apply --yes
[ "$RC" = 1 ] && cmp -s "$CFG" "$E/s/orig.cfg" && grep -q 'member=0' <<<"$OUT" && ok "gate: node ignores [cluster_nodes] -> rolled back" || ko "no_cluster rc=$RC" "$OUT"
fresh; keyed; peer_pinned; cp -p "$CFG" "$E/s/orig.cfg"; echo "$PEER_OLD" > "$ST/node_pub"; echo "$PEER_NEW" > "$E/s/peer_pub"
run set-peer "$WALLET_PUB" validator; run apply --yes
[ "$RC" = 1 ] && cmp -s "$CFG" "$E/s/orig.cfg" && grep -qE 'pubkey_node node:[0-9a-f]{12} want node:[0-9a-f]{12}' <<<"$OUT" && ok "gate: live key is not the stored key -> rolled back" || ko "wrong key rc=$RC" "$OUT"
fresh; applied; echo n9kmjWFeu6Yh6mrvyRXGYbmD8dsBZ8VqRPAbdMnvsgVeZvqe8Bsr > "$E/s/wallet_pub"; run rollback --yes
[ "$RC" = 5 ] && grep -q 'rollback: health: FAIL' <<<"$OUT" && ok "rollback: node comes back on another key (wallet.db changed) -> exit 5" || ko "rollback key rc=$RC" "$OUT"
fresh; applied; run set-peer "$PEER_OLD" sentry; run apply --yes --dry-run
[ "$RC" = 0 ] && grep -qE '^ <seed: redacted>' <<<"$OUT" && [ "$(grep -cE '^[-+]node:[0-9a-f]{12} sentry$' <<<"$OUT")" = 2 ] \
  && [ "$(grep -E '^[-+]node:' <<<"$OUT" | cut -c2- | sort -u | wc -l)" = 2 ] && ok "dry run after apply: seed context redacted, old/new key as distinct fingerprints" || ko "dry run applied" "$OUT"
noseed "dry run after apply" "$OUT"
fresh; keyed; peer_pinned; printf '  [WARN] unit:pft-other.service    changed  sha256\n' >> "$E/s/integrity.out"; run apply --yes
[ "$RC" = 0 ] && grep -q 'integrity: NOT accepted - changed items besides the config: unit:pft-other.service' <<<"$OUT" && [ ! -f "$E/s/accepted" ] \
  && ok "integrity: other changed items -> not accepted" || ko "integrity filter" "$OUT"
fresh; keyed; peer_pinned; printf 'pft-integrity verify\nRESULT: PASS\n' > "$E/s/integrity.out"; run apply --yes
grep -q 'integrity: baseline already current' <<<"$OUT" && [ ! -f "$E/s/accepted" ] && ok "integrity: nothing changed -> no accept" || ko "integrity none" "$OUT"

# --- explicit rollback --------------------------------------------------------------------------------------------
fresh; run rollback --yes; [ "$RC" = 2 ] && grep -q 'no config backup' <<<"$OUT" && ok "rollback: no backup -> exit 2" || ko "rollback none rc=$RC" "$OUT"
fresh; cp -p "$CFG" "$E/s/orig.cfg"; applied
run rollback; [ "$RC" = 4 ] && ok "rollback: no --yes -> exit 4" || ko "rollback no yes" "$OUT"
rm "$E/s/maint"; run rollback --yes; [ "$RC" = 4 ] && grep -q 'REFUSED' <<<"$OUT" && [ "$(stat -c %a "$CFG")" = 600 ] && ok "rollback: no window -> exit 4, unchanged" || ko "rollback window" "$OUT"
touch "$E/s/maint"; R0="$(restarts)"; run rollback --yes
[ "$RC" = 0 ] && cmp -s "$CFG" "$E/s/orig.cfg" && [ "$(stat -c %a "$CFG")" = 644 ] && [ "$(restarts)" = $((R0 + 1)) ] && grep -q 'rollback: done' <<<"$OUT" \
  && [ "$(jq -r .result.info.pubkey_node <<<"$("$E/bin/rpc" postfiatd server_info)")" = "$WALLET_PUB" ] && ok "rollback: byte-identical, 0644, pre-apply key back" || ko "rollback rc=$RC" "$OUT"
grep -q "pubkey_node $(PFT_CLUSTER_ROOT="$E/root" bash "$TOOL" audit 2>/dev/null | grep -oE 'pubkey_node node:[0-9a-f]{12}' | cut -d' ' -f2)" <<<"$OUT" && ok "rollback: gate printed the restored key" || ko "rollback key line" "$OUT"
run audit; expect "after rollback: cfg has no seed" cfg:node_seed FAIL 'no \[node_seed\]'
run apply --yes --require-peer; [ "$RC" = 0 ] && [ "$(grep -c '^# BEGIN pft-cluster' "$CFG")" = 1 ] && ok "re-apply after rollback: exit 0" || ko "re-apply after rollback" "$OUT"
fresh; applied; touch "$E/s/bad_always"; run rollback --yes; [ "$RC" = 5 ] && ok "rollback: gate fails -> exit 5" || ko "rollback gate rc=$RC" "$OUT"

# --- audit grading of broken states -------------------------------------------------------------------------------
fresh; applied
chmod 644 "$CFG"; run audit; expect "audit: seed in a 0644 config" cfg:mode FAIL 'mode 644'
chmod 600 "$CFG"; chmod 755 "$ST"; run audit; expect "audit: state dir 0755" seed:stored FAIL 'dir 755'
chmod 700 "$ST"; chmod 640 "$ST/node_seed"; run audit; expect "audit: seed file 0640" seed:stored FAIL 'file 640'
chmod 600 "$ST/node_seed"; SEED_UID=0 run audit; expect "audit: seed not owned by SEED_UID" seed:stored FAIL 'uid'
cp "$ST/node_seed" "$E/s/seed.bak"; cat "$E/s/seed.bak" "$E/s/seed.bak" > "$ST/node_seed"; run audit; expect "audit: two-line seed file" seed:stored FAIL 'malformed'
cp "$E/s/seed.bak" "$ST/node_seed"
sed -i "s/^\(s[1-9A-HJ-NP-Za-km-z]\{28\}\)\$/\1Z/" "$CFG"; run audit; expect "audit: config seed differs from stored" cfg:node_seed FAIL 'differs'
fresh; applied; printf '\n[node_seed]\nsSecondSeedxxxxxxxxxxxxxxxxxx\n' >> "$CFG"; run audit; expect "audit: two [node_seed] sections" cfg:node_seed FAIL '2 \[node_seed\]'
fresh; applied; printf '\n[cluster_nodes]\n%s extra\n' "$PEER_OLD" >> "$CFG"; run audit; expect "audit: unmanaged [cluster_nodes] merged" cfg:cluster_nodes WARN 'outside'
fresh; applied; sed -i "s/^$PEER_NEW sentry\$/$PEER_NEW sentry\nnot-a-key here/" "$CFG"; run audit; expect "audit: malformed entry" cfg:cluster_nodes FAIL '1 malformed'
fresh; applied; sed -i "s/^$PEER_NEW sentry\$/$PEER_OLD sentry/" "$CFG"; run audit; expect "audit: PEER_PUBKEY not listed" cfg:cluster_nodes FAIL 'not listed'
fresh; applied; echo 900 > "$E/s/peer_age"; run audit; expect "audit: stale report" live:reports FAIL '900 s ago'
fresh; applied; rm "$E/s/peer_connected"; run audit; expect "audit: peer disconnected" live:peer FAIL 'not connected'
expect "audit: disconnected -> no report" live:reports FAIL
fresh; applied; echo "$PEER_OLD" > "$E/s/peer_pub"; run audit; expect "audit: peer runs another key" live:peer FAIL 'not connected'
fresh; applied; sed '/^# BEGIN pft-cluster/,$d' "$CFG" > "$E/s/loaded.cfg"
run audit; expect "audit: config written, restart pending" live:pubkey FAIL 'restart pending'
expect "audit: member not loaded" live:cluster FAIL 'not loaded'
fresh; applied; touch "$E/s/down"; run audit; expect "audit: node down" live:pubkey FAIL 'no server_info answer'
expect "audit: node down -> peers" live:cluster FAIL 'no peers answer'
# secret exposure: each place on its own
for place in inspect ps log textfile; do
  fresh; applied
  case "$place" in
    inspect) printf ',"NODE_SEED=%s"' "$(cat "$ST/node_seed")" > "$E/s/inspect_extra"; want=docker-inspect ;;
    ps) printf 'postfiatd --nodeid %s\n' "$(cat "$ST/node_seed")" > "$E/s/ps"; want=process-args ;;
    log) printf 'Config: node_seed=%s\n' "$(cat "$ST/node_seed")" > "$E/s/log"; want=container-log ;;
    textfile) printf '# %s\n' "$(cat "$ST/node_seed")" > "$E/root/var/lib/pft-exporter/textfile/leak.prom"; want=textfile ;;
  esac
  run audit; expect "audit: seed exposed in $place" secret:exposure FAIL "$want"
  grep -qFf "$ST/node_seed" <<<"$OUT" && ko "audit $place: seed printed" "" || ok "audit $place: finding does not print the seed"
done

# --- pull ---------------------------------------------------------------------------------------------------------
fresh; printf 'HOST_LABEL=validator\nPEER_LABEL=sentry\nPULL_SSH=%s\n' "$E/bin/fakessh" > "$E/root/etc/pft-cluster.env"
printf 'HOST_LABEL=sentry\n' > "$E/s/sentry.env"
PFT_CLUSTER_CONF="$E/s/sentry.env" TEXTFILE_DIR="$E/s" timeout 30 bash "$TOOL" audit --prom "$E/s/peer.prom" >/dev/null 2>&1
run pull; TF="$E/root/var/lib/pft-exporter/textfile/pft_cluster_sentry.prom"
[ "$RC" = 0 ] && cmp -s "$TF" "$E/s/peer.prom" && [ "$(stat -c %a "$TF")" = 644 ] && ok "pull: valid peer file installed 0644" || ko "pull rc=$RC" "$OUT"
echo 'evil_metric 1' >> "$E/s/peer.prom"; cp "$TF" "$E/s/before.prom"; run pull
[ "$RC" = 2 ] && grep -q 'rejected' <<<"$OUT" && cmp -s "$TF" "$E/s/before.prom" && [ -z "$(find "$E/root/var/lib/pft-exporter/textfile" -name '.pft_cluster_*')" ] \
  && ok "pull: foreign line rejected, old file kept, temp removed" || ko "pull reject rc=$RC" "$OUT"
touch "$E/s/ssh_fail"; run pull; [ "$RC" = 1 ] && grep -q 'pull from sentry failed' <<<"$OUT" && ok "pull: ssh failure -> exit 1" || ko "pull ssh rc=$RC" "$OUT"
printf 'HOST_LABEL=validator\n' > "$E/root/etc/pft-cluster.env"; run pull; [ "$RC" = 2 ] && grep -q 'PULL_SSH not set' <<<"$OUT" && ok "pull: no PULL_SSH -> exit 2" || ko "pull no ssh" "$OUT"

# --- usage --------------------------------------------------------------------------------------------------------
run bogus; [ "$RC" = 3 ] && grep -q 'Usage:' <<<"$OUT" && ok "usage: unknown command -> help, exit 3" || ko "usage rc=$RC" "$OUT"
run audit --nope; [ "$RC" = 3 ] && ok "usage: unknown option -> exit 3" || ko "usage opt rc=$RC" "$OUT"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
