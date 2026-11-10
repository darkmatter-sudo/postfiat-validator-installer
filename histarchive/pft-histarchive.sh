#!/usr/bin/env bash
# pft-histarchive - keep validated ledger history that online_delete prunes: follow, verify, replicate, restore-verify.
#
# Usage: pft-histarchive follow                  run the follower (what pft-histarchive.service runs)
#        pft-histarchive metrics                 status.json -> textfile (cheap; every timer run)
#        pft-histarchive verify [--json]         full offline verification of the local archive (+ textfile)
#        pft-histarchive status                  follower progress, segments, head of the MANIFEST chain
#        sudo pft-histarchive keygen             age identity for replica encryption (STATE_DIR, 0600, never printed)
#        sudo pft-histarchive replicate          encrypt sealed segments + metadata, push new files to the peer,
#                                                peer checks them, compare the peer's copy with ours (+ textfile)
#        sudo pft-histarchive verify-replica     ask the peer for its replica index + check, compare (+ textfile)
#        sudo pft-histarchive restore-verify [--from-dir DIR]
#                                                fetch the replica from the peer (or read DIR), check every cipher
#                                                sha256, decrypt into a scratch dir, verify it offline, and compare
#                                                its MANIFEST head and segments with the local archive
#        pft-histarchive crosscheck [ARGS]       seeded sample vs the public RPC (histarchive.py crosscheck)
#        sudo pft-histarchive periodic           timer entry point: metrics; verify if due; replicate if due
#        pft-histarchive serve VERB ...          what PEER_SSH runs on the peer: receive NAME | index | check | export NAME
#        pft-histarchive replica-check           (peer) check the local replica dir against its REPLICA.json
# Exit: 0 ok | 1 verification FAIL / replica mismatch | 2 runtime error | 3 usage | 4 not configured
# Env:  PFT_HISTARCHIVE_CONF (/etc/pft-histarchive.env), STATE_DIR, TEXTFILE_DIR, PFT_HISTARCHIVE_HELPER, AGE,
#       PFT_HISTARCHIVE_REMOTE (how the peer's copy is invoked through PEER_SSH; default "sudo -n pft-histarchive")
# Conf: HOST_LABEL (validator|sentry), RPC_URL, PEER_SSH (validator only), EXTRA_RECIPIENTS (space-separated age
#       recipients that may also decrypt the replica, e.g. an offline operator key), VERIFY_EVERY_H (24),
#       REPLICATE_EVERY_H (24)
# "A && B || die" is intended throughout (die exits / the handler returns).
# shellcheck disable=SC2015
set -uo pipefail
R="${PFT_HISTARCHIVE_ROOT:-}"
CONF="${PFT_HISTARCHIVE_CONF:-$R/etc/pft-histarchive.env}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-histarchive}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
ARCHIVE="$STATE_DIR/archive"
OUTBOX="$STATE_DIR/outbox"
REPLICA="$STATE_DIR/replica"
IDF="$STATE_DIR/age.key"
AGEPUB="$STATE_DIR/age.pub"
AGE="${AGE:-age}"
AGE_KEYGEN="${AGE_KEYGEN:-age-keygen}"
SSH_TIMEOUT="${SSH_TIMEOUT:-600}"
REMOTE_CMD="${PFT_HISTARCHIVE_REMOTE-sudo -n pft-histarchive}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${PFT_HISTARCHIVE_HELPER:-}" ]; then HELPER="$PFT_HISTARCHIVE_HELPER"
elif [ -f "$HERE/histarchive.py" ]; then HELPER="$HERE/histarchive.py"
else HELPER=/usr/local/lib/pft-histarchive/histarchive.py; fi
PY="${PYTHON:-python3}"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
[[ "$HOST_LABEL" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || { echo "pft-histarchive: bad HOST_LABEL" >&2; exit 4; }
RPC_URL="$(conf_get RPC_URL)"; RPC_URL="${RPC_URL:-http://127.0.0.1:5005/}"
PEER_SSH="$(conf_get PEER_SSH)"
EXTRA_RECIPIENTS="$(conf_get EXTRA_RECIPIENTS)"
VERIFY_EVERY_H="$(conf_get VERIFY_EVERY_H)"; VERIFY_EVERY_H="${VERIFY_EVERY_H:-24}"
REPLICATE_EVERY_H="$(conf_get REPLICATE_EVERY_H)"; REPLICATE_EVERY_H="${REPLICATE_EVERY_H:-24}"
AGE_RE='^age1[02-9ac-hj-np-z]{58}$'
NAME_RE='^([0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl\.gz|meta-[0-9a-f]{16}\.tar)\.age$'

ts() { date -u +%FT%TZ; }
die() { echo "pft-histarchive: $1" >&2; exit "${2:-3}"; }
helper() { "$PY" -u "$HELPER" "$@"; }

prom_write() { # NAME: stdin -> TEXTFILE_DIR/NAME.prom atomically (skipped when the dir does not exist)
  [ -d "$TEXTFILE_DIR" ] || { cat > /dev/null; return 0; }
  local tmp="$TEXTFILE_DIR/.$1.prom.$$"
  cat > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/$1.prom"
}

stamp_get() { [ -f "$STATE_DIR/$1" ] && cat "$STATE_DIR/$1" || echo 0; }
stamp_set() { date +%s > "$STATE_DIR/$1.tmp" && mv -f "$STATE_DIR/$1.tmp" "$STATE_DIR/$1"; }

head_entry() { # newest MANIFEST entry hash (empty when no segment is sealed yet)
  [ -s "$ARCHIVE/MANIFEST.jsonl" ] || return 0
  tail -n 1 "$ARCHIVE/MANIFEST.jsonl" | "$PY" -c 'import json,sys; print(json.loads(sys.stdin.read())["entry"])'
}

# ------------------------------------------------------------------ local

cmd_follow() { exec "$PY" -u "$HELPER" follow --dir "$ARCHIVE" --rpc "$RPC_URL" --rate 4 --progress 3600 \
  --log "$STATE_DIR/follow.log"; }

cmd_metrics() {
  local st="$ARCHIVE/status.json"
  [ -f "$st" ] || { echo "no status.json yet ($st)"; return 0; }
  "$PY" - "$st" "$HOST_LABEL" <<'PYEOF' | prom_write pft_histarchive_follow
import json, sys
s = json.load(open(sys.argv[1]))
host = sys.argv[2]
for name, help_, v in (
    ("pft_histarchive_last_ingest_timestamp_seconds", "unix time the follower wrote its newest ledger", s["ingest_unix"]),
    ("pft_histarchive_follow_last_ledger", "newest ledger the follower archived", s["last"]),
    ("pft_histarchive_lag_ledgers", "validated ledgers not yet archived at the last write", s["lag"]),
    ("pft_histarchive_follow_gaps", "gap ranges recorded by the follower", s["gaps"]),
):
    print(f'# HELP {name} {help_}\n# TYPE {name} gauge\n{name}{{host="{host}"}} {v}')
PYEOF
  echo "metrics: follower last ledger $("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["last"])' "$st")"
}

cmd_verify() {
  local tf="$STATE_DIR/.verify.prom" rc
  helper verify --dir "$ARCHIVE" --textfile "$tf" --host "$HOST_LABEL" "$@"; rc=$?
  if [ -f "$tf" ]; then prom_write pft_histarchive < "$tf"; rm -f "$tf"; fi
  [ "$rc" = 0 ] && stamp_set last-verify
  return "$rc"
}

cmd_status() { helper status --dir "$ARCHIVE"; }

cmd_keygen() {
  [ -e "$IDF" ] && die "age identity already exists ($IDF); keygen never replaces it" 4
  mkdir -p "$STATE_DIR"
  (umask 077; "$AGE_KEYGEN" -o "$IDF.tmp" 2>/dev/null) || { rm -f "$IDF.tmp"; die "age-keygen failed" 2; }
  mv -f "$IDF.tmp" "$IDF"
  "$AGE_KEYGEN" -y "$IDF" > "$AGEPUB" 2>/dev/null || die "age-keygen -y failed" 2
  [[ "$(cat "$AGEPUB")" =~ $AGE_RE ]] || die "age-keygen printed no valid recipient" 2
  echo "age identity: created (0600, never printed)"
  echo "age recipient: $(cat "$AGEPUB")"
}

recipients() { # -r args for age: our own recipient + EXTRA_RECIPIENTS
  local r
  [ -r "$AGEPUB" ] && [[ "$(cat "$AGEPUB")" =~ $AGE_RE ]] || die "no age recipient (run keygen)" 4
  printf -- '-r\n%s\n' "$(cat "$AGEPUB")"
  for r in $EXTRA_RECIPIENTS; do
    [[ "$r" =~ $AGE_RE ]] || die "EXTRA_RECIPIENTS: '$r' is not an age recipient" 4
    printf -- '-r\n%s\n' "$r"
  done
}

encrypt() { # SRC DEST: age-encrypt to the recipients via a temp file
  local -a ra; mapfile -t ra < <(recipients) || return 2
  [ "${#ra[@]}" -ge 2 ] || return 2
  "$AGE" "${ra[@]}" -o "$2.tmp" "$1" && mv -f "$2.tmp" "$2" || { rm -f "$2.tmp"; return 2; }
}

build_outbox() { # encrypt new sealed segments and the current metadata; write REPLICA.json. Prints a summary.
  local day seg n=0 meta tmpd
  mkdir -p "$OUTBOX"
  while read -r day seg; do
    [ -f "$OUTBOX/$day.jsonl.gz.age" ] && continue
    encrypt "$ARCHIVE/$seg" "$OUTBOX/$day.jsonl.gz.age" || { echo "FAIL encrypt $seg"; return 2; }
    n=$((n + 1))
  done < <("$PY" -c 'import json,sys
for x in open(sys.argv[1]):
    if x.strip():
        e = json.loads(x); print(e["day"], e["segment"])' "$ARCHIVE/MANIFEST.jsonl")
  meta="meta-$(cat "$ARCHIVE/MANIFEST.jsonl" "$ARCHIVE/gaps.jsonl" "$ARCHIVE/state.json" 2>/dev/null | sha256sum | cut -c1-16).tar.age"
  if [ ! -f "$OUTBOX/$meta" ]; then
    tmpd="$(mktemp -d -p "$STATE_DIR" .meta.XXXXXX)"
    local -a mf=(MANIFEST.jsonl state.json); [ -f "$ARCHIVE/gaps.jsonl" ] && mf+=(gaps.jsonl)
    tar -C "$ARCHIVE" --format=ustar --owner=0 --group=0 --mtime=@0 -cf "$tmpd/meta.tar" "${mf[@]}" \
      && encrypt "$tmpd/meta.tar" "$OUTBOX/$meta" || { rm -rf "$tmpd"; echo "FAIL encrypt metadata"; return 2; }
    rm -rf "$tmpd"
    find "$OUTBOX" -maxdepth 1 -name 'meta-*.tar.age' ! -name "$meta" -delete
  fi
  "$PY" - "$OUTBOX" "$meta" "$(head_entry)" <<'PYEOF' > "$OUTBOX/REPLICA.json.tmp" && mv -f "$OUTBOX/REPLICA.json.tmp" "$OUTBOX/REPLICA.json"
import hashlib, json, os, sys, time
d, meta, head = sys.argv[1:4]
files = {}
for f in sorted(os.listdir(d)):
    if f.endswith(".jsonl.gz.age") or f == meta:
        with open(os.path.join(d, f), "rb") as fh:
            files[f] = hashlib.sha256(fh.read()).hexdigest()
print(json.dumps({"v": 1, "files": files, "meta": meta, "head_entry": head or None, "built_unix": int(time.time())}, sort_keys=True, indent=1))
PYEOF
  echo "outbox: $n new segment(s) encrypted; metadata $meta; files $(find "$OUTBOX" -maxdepth 1 -name '*.age' | wc -l); head_entry $(head_entry | cut -c1-16)"
}

peer() { # VERB ARGS... : run serve on the peer through PEER_SSH
  [ -n "$PEER_SSH" ] || die "PEER_SSH not set (see $CONF)" 4
  # shellcheck disable=SC2086 # PEER_SSH / REMOTE_CMD are command lines from the root-owned conf
  timeout "$SSH_TIMEOUT" $PEER_SSH $REMOTE_CMD serve "$@"
}


cmd_replicate() {
  local have name rc fails=0
  echo "pft-histarchive replicate - $(ts) | $HOST_LABEL -> peer"
  [ -s "$ARCHIVE/MANIFEST.jsonl" ] || { echo "nothing sealed yet: no replica to build"; return 0; }
  echo "== 1. encrypt (age) sealed segments + metadata into the outbox"
  build_outbox | sed 's/^/  /'; [ "${PIPESTATUS[0]}" = 0 ] || return 2
  echo "== 2. push files the peer does not hold yet"
  have="$(peer index < /dev/null)" || { echo "  FAIL peer index"; return 2; }
  while read -r name; do
    if "$PY" -c 'import json,sys; sys.exit(0 if sys.argv[1] in (json.loads(sys.stdin.read()).get("cipher") or {}) else 1)' "$name" <<<"$have"; then continue; fi
    peer receive "$name" < "$OUTBOX/$name" > /dev/null; rc=$?
    echo "  sent $name ($(stat -c %s "$OUTBOX/$name") bytes) rc $rc"; [ "$rc" = 0 ] || fails=$((fails + 1))
  done < <("$PY" -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["files"]))' "$OUTBOX/REPLICA.json")
  peer receive REPLICA.json < "$OUTBOX/REPLICA.json" > /dev/null || fails=$((fails + 1))
  echo "  sent REPLICA.json (head_entry $(head_entry | cut -c1-16))"
  echo "== 3. the peer checks its copy; compare with ours"
  compare_replica | sed "s/^/  /"; [ "${PIPESTATUS[0]}" = 0 ] || fails=$((fails + 1))
  [ "$fails" = 0 ] && stamp_set last-replicate
  echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) - replicate fails $fails"
  [ "$fails" = 0 ]
}

compare_replica() { # local REPLICA.json vs the peer index (+ textfile); 0 same, 1 differs
  local idx rc ok=0
  idx="$(peer index < /dev/null 2> "$STATE_DIR/.peer.err")"; rc=$?
  if [ "$rc" != 0 ]; then echo "FAIL peer index (rc $rc): $(head -c 300 "$STATE_DIR/.peer.err")"; ok=1
  else helper replica-compare --local "$OUTBOX/REPLICA.json" <<<"$idx" || ok=1
  fi
  printf '# HELP pft_histarchive_replica_ok 1 if the peer holds every encrypted file with the expected sha256\n# TYPE pft_histarchive_replica_ok gauge\npft_histarchive_replica_ok{host="%s"} %s\n# HELP pft_histarchive_replica_check_timestamp_seconds unix time of the last replica comparison\n# TYPE pft_histarchive_replica_check_timestamp_seconds gauge\npft_histarchive_replica_check_timestamp_seconds{host="%s"} %s\n' \
    "$HOST_LABEL" "$([ "$ok" = 0 ] && echo 1 || echo 0)" "$HOST_LABEL" "$(date +%s)" | prom_write pft_histarchive_replica
  return "$ok"
}

cmd_verify_replica() {
  echo "pft-histarchive verify-replica - $(ts) | local REPLICA.json vs the peer's copy"
  [ -f "$OUTBOX/REPLICA.json" ] || die "no local REPLICA.json (run replicate first)" 4
  compare_replica
}

cmd_restore_verify() {
  local src="" scratch rc fails=0 name sha
  [ "${1:-}" = --from-dir ] && { src="${2:-}"; [ -d "$src" ] || die "--from-dir: not a directory"; }
  [ -r "$IDF" ] || die "no age identity ($IDF): restore needs it" 4
  echo "pft-histarchive restore-verify - $(ts) | source: ${src:+dir}${src:-peer replica}"
  scratch="$(mktemp -d -p "$STATE_DIR" restore.XXXXXX)" || die "mktemp failed" 2
  trap 'rm -rf "$scratch"' RETURN
  mkdir -p "$scratch/cipher" "$scratch/archive/segments"
  echo "== 1. fetch REPLICA.json and every listed file"
  if [ -n "$src" ]; then cp "$src/REPLICA.json" "$scratch/cipher/" || return 2
  else peer export REPLICA.json < /dev/null > "$scratch/cipher/REPLICA.json" || { echo "  FAIL export REPLICA.json"; return 2; }
  fi
  while read -r name sha; do
    if [ -n "$src" ]; then cp "$src/$name" "$scratch/cipher/$name" 2>/dev/null
    else peer export "$name" < /dev/null > "$scratch/cipher/$name"; fi
    if [ "$(sha256sum < "$scratch/cipher/$name" | cut -c1-64)" != "$sha" ]; then
      echo "  FAIL $name: fetched copy sha256 differs from REPLICA.json"; fails=$((fails + 1)); continue
    fi
    case "$name" in
      meta-*) "$AGE" -d -i "$IDF" "$scratch/cipher/$name" | tar -C "$scratch/archive" -xf - ;;
      *) "$AGE" -d -i "$IDF" -o "$scratch/archive/segments/${name%.age}" "$scratch/cipher/$name" ;;
    esac || { echo "  FAIL $name: does not decrypt with this host's identity"; fails=$((fails + 1)); }
  done < <("$PY" -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k, v in sorted(d["files"].items()): print(k, v)' "$scratch/cipher/REPLICA.json")
  echo "  fetched $(find "$scratch/cipher" -maxdepth 1 -name '*.age' | wc -l) encrypted files; decrypted $(find "$scratch/archive/segments" -maxdepth 1 -name '*.gz' | wc -l) segments"
  echo "== 2. offline verification of the restored copy (sealed segments only)"
  helper verify --dir "$scratch/archive" --sealed-only | sed 's/^/  /'; rc="${PIPESTATUS[0]}"
  [ "$rc" = 0 ] || fails=$((fails + 1))
  echo "== 3. restored copy vs the local archive"
  "$PY" - "$scratch/archive/MANIFEST.jsonl" "$ARCHIVE/MANIFEST.jsonl" <<'PYEOF' || fails=$((fails + 1))
import json, sys
def load(p):
    try:
        return [json.loads(x) for x in open(p) if x.strip()]
    except OSError:
        return None
rest, loc = load(sys.argv[1]), load(sys.argv[2])
if rest is None:
    print("  FAIL restored copy has no MANIFEST.jsonl"); sys.exit(1)
loc_by = {e["day"]: e for e in loc or []}
bad = 0
for e in rest:
    l = loc_by.get(e["day"])
    same = l is not None and l["entry"] == e["entry"] and l["sha256_gz"] == e["sha256_gz"]
    bad += not same
    print(f"  {'SAME' if same else 'DIFF'} {e['day']} ledgers {e['first']}-{e['last']} entry {e['entry'][:16]}")
head = rest[-1]["entry"] if rest else None
in_local = any(x["entry"] == head for x in loc or [])
print(f"  restored head_entry {str(head)[:16]} {'is' if in_local else 'is NOT'} in the local MANIFEST chain")
sys.exit(1 if bad or not in_local else 0)
PYEOF
  echo "RESULT: $([ "$fails" = 0 ] && echo PASS || echo FAIL) - restore-verify fails $fails"
  [ "$fails" = 0 ]
}

cmd_periodic() {
  local now rc=0 due
  now="$(date +%s)"
  cmd_metrics || rc=2
  due=$(( now - $(stamp_get last-verify) >= VERIFY_EVERY_H * 3600 ))
  if [ "$due" = 1 ] || [ "$(head_entry)" != "$(cat "$STATE_DIR/verified-head" 2>/dev/null)" ]; then
    cmd_verify | tail -n 1 || rc=1
    head_entry > "$STATE_DIR/verified-head"
  fi
  if [ "$rc" = 1 ]; then echo "replicate skipped: the local archive did not verify"
  elif [ "$HOST_LABEL" = validator ] && [ -n "$PEER_SSH" ] && [ -r "$AGEPUB" ]; then
    due=$(( now - $(stamp_get last-replicate) >= REPLICATE_EVERY_H * 3600 ))
    if [ "$due" = 1 ] || [ "$(head_entry)" != "$(cat "$STATE_DIR/replicated-head" 2>/dev/null)" ]; then
      if cmd_replicate | tail -n 1; then head_entry > "$STATE_DIR/replicated-head"; else rc=1; fi
    fi
  fi
  return "$rc"
}

# ------------------------------------------------------------------ peer side

cmd_receive() { # NAME < bytes: store one replica file (names are checked; REPLICA.json last)
  local name="$1"
  [ "$name" = REPLICA.json ] || [[ "$name" =~ $NAME_RE ]] || die "receive: refusing name '$name'"
  mkdir -p "$REPLICA"
  cat > "$REPLICA/.$name.tmp" && mv -f "$REPLICA/.$name.tmp" "$REPLICA/$name" || die "receive: write failed" 2
  if [ "$name" = REPLICA.json ]; then # drop metadata generations the new index no longer lists
    "$PY" -c 'import json,os,sys
d = json.load(open(os.path.join(sys.argv[1], "REPLICA.json")))
for f in os.listdir(sys.argv[1]):
    if f.startswith("meta-") and f.endswith(".age") and f not in d["files"]:
        os.unlink(os.path.join(sys.argv[1], f))' "$REPLICA"
  fi
  echo "stored $name"
}

cmd_index() { # JSON: the replica's REPLICA.json, the sha256 of every *.age file, and replica-check output
  local check rc
  mkdir -p "$REPLICA"
  check="$(cmd_replica_check 2>&1)"; rc=$?
  "$PY" -c 'import json,os,sys
d = sys.argv[1]
rep = json.load(open(os.path.join(d, "REPLICA.json"))) if os.path.exists(os.path.join(d, "REPLICA.json")) else None
cipher = json.loads(sys.argv[2]) if sys.argv[2] else {}
print(json.dumps({"replica": rep, "cipher": cipher, "check_rc": int(sys.argv[3]), "check": sys.argv[4]}))' \
    "$REPLICA" "$(helper cipher-index --dir "$REPLICA")" "$rc" "$check"
}

cmd_replica_check() {
  [ -f "$REPLICA/REPLICA.json" ] || { echo "RESULT: FAIL - no REPLICA.json in the replica dir"; return 1; }
  helper replica-check --dir "$REPLICA"
}

cmd_serve() { # the only verbs PEER_SSH may run on this host
  local v="${1:-}"; shift || true
  case "$v" in
    receive) [ $# = 1 ] || die "serve receive NAME"; cmd_receive "$1" ;;
    index) [ $# = 0 ] || die "serve index"; cmd_index ;;
    check) [ $# = 0 ] || die "serve check"; cmd_replica_check ;;
    export) [ $# = 1 ] || die "serve export NAME"
            { [ "$1" = REPLICA.json ] || [[ "$1" =~ $NAME_RE ]]; } || die "export: refusing name '$1'"
            cat -- "$REPLICA/$1" ;;
    *) die "serve: unknown verb '$v' (receive|index|check|export)" ;;
  esac
}

cmd="${1:-}"; shift || true
case "$cmd" in
  follow) cmd_follow ;;
  metrics) cmd_metrics ;;
  verify) cmd_verify "$@" ;;
  status) cmd_status ;;
  keygen) cmd_keygen ;;
  replicate) cmd_replicate ;;
  verify-replica) cmd_verify_replica ;;
  restore-verify) cmd_restore_verify "$@" ;;
  crosscheck) helper crosscheck --dir "$ARCHIVE" "$@" ;;
  periodic) cmd_periodic ;;
  serve) cmd_serve "$@" ;;
  replica-check) cmd_replica_check ;;
  -h|--help|help) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' ;;
  *) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 3 ;;
esac
