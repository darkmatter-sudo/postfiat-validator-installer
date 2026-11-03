#!/usr/bin/env bash
# pft-keyescrow: keep the add-on secrets of a validator and its sentry recoverable after the loss of either host,
# without plaintext ever leaving the host it belongs to. Each host encrypts its own secrets to the PEER's age public
# key and stores N generations there; the peer can check a generation against its manifest but cannot read it.
#
# This file is step 1 (read-only inventory). Every secret path comes from a source line of an add-on in this repo
# (REGISTRY below, column "cite"; tests/run-tests.sh checks every citation still names the path).
#
# Usage: pft-keyescrow inventory [--json] [--textfile]   read-only; root to read 0600 files
#        sudo pft-keyescrow keygen          fp_key + age identity in STATE_DIR (0600), prints the age recipient
#        pft-keyescrow pubkey               this host's age recipient (age1..., public)
#        sudo pft-keyescrow set-peer AGE1   store the peer's age recipient (PEER_RECIPIENT) in the conf
#        sudo pft-keyescrow seal            encrypt this host's ok items to the peer -> STATE_DIR/outbox/gen-G.{age,meta}
#        sudo pft-keyescrow escrow          (host with PEER_SSH) both directions: seal + push + peer verifies; peer
#                                           seals + pull + verify here; each side records what the other holds
#        sudo pft-keyescrow verify [--all] [--textfile]   re-check held generations (sha256 + decrypt in memory)
#        pft-keyescrow serve VERB ...       what PEER_SSH runs on the peer: receive LABEL | seal | export GEN | ack GEN
#
# Inventory, per declared item that applies to this host (HOST_LABEL):
#   ok        present, mode/owner/group exactly as declared, readable
#   perm      present but mode, owner or group differ (exit 2)
#   missing   required item absent (exit 2)
#   absent    optional item absent (INFO, e.g. /etc/pft-maint/ntfy.env falls back to the monitor env by design)
#   unreadable present but this caller cannot read it (run as root; exit 2)
# Escrow state, per present item: fingerprint = first 16 hex of sha256(FP_KEY || file bytes) (keyed, so a published
# fingerprint of a low-entropy secret such as an ntfy topic cannot be brute-forced), compared with the fingerprint
# recorded by the last escrow (STATE_DIR/escrowed.tsv): same | drift (changed since the escrow) | new (never escrowed).
# Without FP_KEY (before keygen) fingerprints are "n/a" and every item is "new". drift/new/never-escrowed: exit 1.
# Owners/groups are never printed (the alerts ntfy env belongs to a login user): only ok / BAD.
#
# Exit: 0 all ok and escrowed | 1 escrow drift / not escrowed | 2 perm/missing/unreadable | 3 usage
# Env:  PFT_KEYESCROW_ROOT (test root prefix), PFT_KEYESCROW_CONF (/etc/pft-keyescrow.env),
#       PFT_KEYESCROW_REGISTRY (a registry file instead of the built-in one), STATE_DIR, TEXTFILE_DIR
# Conf: HOST_LABEL (validator|sentry), ALERTS_NTFY_ENV + ALERTS_NTFY_OWNER (validator: the alert stack's NTFY_ENV_FILE
#       and its owner), VALKEYS_DIR (only if the validator master key directory is kept on this host; default: offline)
# "A && B || die" is intended throughout (die exits); sed indents multi-line captured output.
# shellcheck disable=SC2015,SC2001
set -uo pipefail
R="${PFT_KEYESCROW_ROOT:-}"
CONF="${PFT_KEYESCROW_CONF:-$R/etc/pft-keyescrow.env}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-keyescrow}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
FPF="$STATE_DIR/fp_key"
ESCROWED="$STATE_DIR/escrowed.tsv"
IDF="$STATE_DIR/age.key"
AGEPUB="$STATE_DIR/age.pub"
OUTBOX="$STATE_DIR/outbox"
STORE="$STATE_DIR/store"
AGE="${PFT_KEYESCROW_AGE:-age}"
AGE_KEYGEN="${PFT_KEYESCROW_AGE_KEYGEN:-age-keygen}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${PFT_KEYESCROW_HELPER:-}" ]; then HELPER="$PFT_KEYESCROW_HELPER"
elif [ -f "$HERE/keyescrow_tar.py" ]; then HELPER="$HERE/keyescrow_tar.py"
else HELPER=/usr/local/lib/pft-keyescrow/keyescrow_tar.py; fi
REMOTE_CMD="${PFT_KEYESCROW_REMOTE-sudo -n pft-keyescrow}" # how the peer's copy is invoked through PEER_SSH
SSH_TIMEOUT="${SSH_TIMEOUT:-120}"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
PEER_LABEL="$(conf_get PEER_LABEL)"
[ -n "$PEER_LABEL" ] || { [ "$HOST_LABEL" = sentry ] && PEER_LABEL=validator || PEER_LABEL=sentry; }
PEER_RECIPIENT="$(conf_get PEER_RECIPIENT)"
PEER_SSH="$(conf_get PEER_SSH)"
KEEP="$(conf_get KEEP)"; KEEP="${KEEP:-7}"
ALERTS_NTFY_ENV="$(conf_get ALERTS_NTFY_ENV)"
ALERTS_NTFY_OWNER="$(conf_get ALERTS_NTFY_OWNER)"
VALKEYS_DIR="$(conf_get VALKEYS_DIR)"

die() { echo "pft-keyescrow: $*" >&2; exit "${2:-3}"; }
ts() { date -u +%FT%TZ; }

# id  hosts  path  mode  owner  group  need  cite   (tab-separated; "-" = empty; @MID@ = /etc/machine-id,
# @ALERTS@ / @ALERTS_OWNER@ / @VALKEYS@ = conf values; an item whose path needs an unset conf value is "absent")
registry() {
  if [ -n "${PFT_KEYESCROW_REGISTRY:-}" ]; then cat "$PFT_KEYESCROW_REGISTRY"; return; fi
  cat <<'REG'
cluster:node_seed	both	/var/lib/pft-cluster/node_seed	600	root	root	req	cluster/pft-cluster.sh:78
cluster:fp_key	both	/var/lib/pft-cluster/fp_key	600	root	root	req	cluster/pft-cluster.sh:80
cluster:env	both	/etc/pft-cluster.env	600	root	root	req	cluster/install.sh:17
logship:env	both	/etc/pft-logship.env	600	root	root	req	logship/pft-logship.sh:40
logship:host_key	both	/etc/pft-logship/tls/host.key	640	root	systemd-journal-remote	req	logship/pft-logship.sh:115
logship:ca_key	validator	/etc/pft-logship/ca/ca.key	600	root	root	req	logship/pft-logship.sh:237
journald:fss	both	/var/log/journal/@MID@/fss	600	root	systemd-journal	req	audittrail/pft-audittrail.sh:87
alertpath:hmac	both	/etc/pft-alertpath/hmac.key	600	root	root	req	alertpath/pft-alertpath.sh:168
watchdog:hmac	both	/etc/pft-watchdog/hmac.key	600	root	root	req	watchdog/pft-heartbeat.sh:14
ntfy:monitor	validator	/etc/postfiat-monitor.env	600	root	root	req	monitor/install-monitor.sh:15
ntfy:maint	both	/etc/pft-maint/ntfy.env	600	root	root	opt	maint/install.sh:36
ntfy:alertpath	sentry	/etc/pft-alertpath/ntfy.env	600	root	root	req	alertpath/pft-alertpath.sh:300
ntfy:watchdog	sentry	/etc/pft-watchdog/ntfy.env	600	root	root	req	watchdog/install.sh:12
ntfy:alerts	validator	@ALERTS@	600	@ALERTS_OWNER@	-	opt	alerts/run-stack.sh:13
valkeys:keys	validator	@VALKEYS@/validator-keys.json	600	-	-	opt	valkeys/pft-valkeys.sh:33
REG
}

machine_id() { tr -d '[:space:]' < "$R/etc/machine-id" 2>/dev/null; }
resolve() { # PATH-TEMPLATE -> host path ("" if a needed conf value is unset)
  local p="$1" mid
  case "$p" in
    *@MID@*) mid="$(machine_id)"; [[ "$mid" =~ ^[0-9a-f]{32}$ ]] || { echo ""; return; }; p="${p//@MID@/$mid}" ;;
  esac
  case "$p" in
    @ALERTS@) [ -n "$ALERTS_NTFY_ENV" ] || { echo ""; return; }; echo "$R$ALERTS_NTFY_ENV"; return ;;
    @VALKEYS@/*) [ -n "$VALKEYS_DIR" ] || { echo ""; return; }; echo "$R$VALKEYS_DIR/${p#@VALKEYS@/}"; return ;;
  esac
  echo "$R$p"
}
applies() { [ "$1" = both ] || [ "$1" = "$HOST_LABEL" ]; }
fingerprint() { # FILE -> 16 hex keyed with FP_KEY | n/a
  if [ ! -r "$FPF" ] || [ ! -s "$FPF" ]; then echo "n/a"; return; fi
  { cat "$FPF"; cat "$1"; } | sha256sum | cut -c1-16
}
escrowed_fp() { [ -r "$ESCROWED" ] && awk -F'\t' -v k="$1" '$1 == k { f = $2 } END { if (f != "") print f }' "$ESCROWED"; }
escrowed_at() { # epoch of the last escrow (0 = never)
  local t
  t="$([ -r "$ESCROWED" ] && sed -n 's/^# escrowed_at=\([0-9]\{1,\}\)$/\1/p' "$ESCROWED" | tail -1)"
  echo "${t:-0}"
}

scan() { # sets ROWS (one line per applicable item), SEAL_LIST (id<TAB>path of ok items), FPS (id<TAB>fp), N_*, LAST
  local id hosts tpl mode owner group need cite p st fp esc have_m have_o have_g own grp why e
  n_ok=0; n_perm=0; n_missing=0; n_absent=0; n_unread=0; n_drift=0; n_new=0; ROWS=""; SEAL_LIST=""; FPS=""
  [[ "$HOST_LABEL" =~ ^(validator|sentry)$ ]] || die "HOST_LABEL must be validator or sentry (got '$HOST_LABEL')"
  LAST="$(escrowed_at)"
  while IFS=$'\t' read -r id hosts tpl mode owner group need cite; do
    [ -z "$id" ] || [[ "$id" == \#* ]] && continue
    applies "$hosts" || continue
    [ "$owner" = "@ALERTS_OWNER@" ] && owner="${ALERTS_NTFY_OWNER:--}"
    p="$(resolve "$tpl")"; fp="n/a"; esc="-"; why=""
    if [ -z "$p" ] || { [ ! -e "$p" ] && [ ! -L "$p" ]; }; then
      if [ "$need" = opt ]; then st=absent; n_absent=$((n_absent + 1)); why="optional, not on this host"
      else st=missing; n_missing=$((n_missing + 1)); why="required, not found"; fi
    elif [ -L "$p" ] || [ ! -f "$p" ]; then
      st=perm; n_perm=$((n_perm + 1)); why="not a regular file"
    else
      have_m="$(stat -c %a "$p")"; have_o="$(stat -c %U "$p")"; have_g="$(stat -c %G "$p")"
      own=ok; grp=ok
      [ "$owner" != "-" ] && [ "$have_o" != "$owner" ] && own=BAD
      [ "$group" != "-" ] && [ "$have_g" != "$group" ] && grp=BAD
      if [ "$((8#$have_m))" != "$((8#$mode))" ] || [ "$own" = BAD ] || [ "$grp" = BAD ]; then
        st=perm; n_perm=$((n_perm + 1)); why="mode $have_m (want $mode), owner $own, group $grp"
      elif [ ! -r "$p" ]; then
        st=unreadable; n_unread=$((n_unread + 1)); why="cannot read (run as root)"
      else
        st=ok; n_ok=$((n_ok + 1)); why="mode $have_m, owner ok, group ok"
        SEAL_LIST+="$id"$'\t'"$p"$'\n'
      fi
      if [ -r "$p" ]; then
        fp="$(fingerprint "$p")"
        [ "$st" = ok ] && FPS+="$id"$'\t'"$fp"$'\n'
        e="$(escrowed_fp "$id")"
        if [ -z "$e" ] || [ "$fp" = n/a ]; then esc=new; n_new=$((n_new + 1))
        elif [ "$e" = "$fp" ]; then esc=same
        else esc=drift; n_drift=$((n_drift + 1)); fi
      fi
    fi
    ROWS+="$id"$'\t'"$st"$'\t'"$esc"$'\t'"$fp"$'\t'"$need"$'\t'"$cite"$'\t'"$why"$'\n'
  done < <(registry)
  SCAN_RC=0
  [ $((n_drift + n_new)) -gt 0 ] || [ "$LAST" = 0 ] && SCAN_RC=1
  [ $((n_perm + n_missing + n_unread)) -gt 0 ] && SCAN_RC=2
  return 0
}

cmd_inventory() {
  local json=0 tf=0 rc rows last id st esc fp need cite why
  while [ $# -gt 0 ]; do
    case "$1" in --json) json=1 ;; --textfile) tf=1 ;; *) die "inventory: unknown option $1" ;; esac
    shift
  done
  scan; rc="$SCAN_RC"; rows="$ROWS"; last="$LAST"
  if [ "$json" = 1 ]; then
    printf '%s' "$rows" | jq -R -s --arg host "$HOST_LABEL" --arg t "$(ts)" --argjson last "$last" --argjson rc "$rc" '
      { host: $host, time: $t, last_escrow_epoch: $last, exit: $rc,
        items: [ split("\n")[] | select(length > 0) | split("\t")
                 | { id: .[0], state: .[1], escrow: .[2], fingerprint: .[3], need: .[4], cite: .[5], detail: .[6] } ] }'
  else
    local when=never
    [ "$last" = 0 ] || when="$(date -u -d "@$last" +%FT%TZ)"
    echo "pft-keyescrow inventory - $(ts) | host $HOST_LABEL | last escrow $when"
    printf '%s' "$rows" | while IFS=$'\t' read -r id st esc fp need cite why; do
      printf '  %-10s %-18s escrow %-5s fp %-16s %s  (%s)\n' "[$st]" "$id" "$esc" "$fp" "$why" "$cite"
    done
    echo "RESULT: ok $n_ok, perm $n_perm, missing $n_missing, unreadable $n_unread, absent(optional) $n_absent; escrow drift $n_drift, new $n_new -> exit $rc"
  fi
  if [ "$tf" = 1 ]; then
    local lab="node=\"$HOST_LABEL\"" out tmp
    out="$TEXTFILE_DIR/pft_keyescrow.prom"; tmp="$(mktemp "$TEXTFILE_DIR/.pft_keyescrow.prom.XXXXXX")" || die "cannot write $TEXTFILE_DIR" 2
    {
      printf '# HELP pft_keyescrow_items Declared secret items on this host, by inventory state.\n# TYPE pft_keyescrow_items gauge\n'
      printf 'pft_keyescrow_items{%s,state="%s"} %s\n' "$lab" ok "$n_ok" "$lab" perm "$n_perm" "$lab" missing "$n_missing" \
        "$lab" unreadable "$n_unread" "$lab" absent "$n_absent"
      printf '# HELP pft_keyescrow_drift_items Present items whose fingerprint differs from the last escrow, or never escrowed.\n# TYPE pft_keyescrow_drift_items gauge\n'
      printf 'pft_keyescrow_drift_items{%s} %s\n' "$lab" $((n_drift + n_new))
      printf '# HELP pft_keyescrow_last_escrow_timestamp_seconds Time of the last successful escrow to the peer (0 = never).\n# TYPE pft_keyescrow_last_escrow_timestamp_seconds gauge\n'
      printf 'pft_keyescrow_last_escrow_timestamp_seconds{%s} %s\n' "$lab" "$last"
      printf '# HELP pft_keyescrow_inventory_exit_code Exit code of the last inventory run.\n# TYPE pft_keyescrow_inventory_exit_code gauge\n'
      printf 'pft_keyescrow_inventory_exit_code{%s} %s\n' "$lab" "$rc"
      printf '# HELP pft_keyescrow_collect_timestamp_seconds Time of the last inventory run.\n# TYPE pft_keyescrow_collect_timestamp_seconds gauge\n'
      printf 'pft_keyescrow_collect_timestamp_seconds{%s} %s\n' "$lab" "$(date -u +%s)"
    } > "$tmp"
    if ! chmod 644 "$tmp" || ! mv -f "$tmp" "$out"; then rm -f "$tmp"; die "cannot write $out" 2; fi
  fi
  return "$rc"
}

GEN_RE='^[0-9]{8}T[0-9]{6}Z$'
AGE_RE='^age1[02-9ac-hj-np-z]{58}$'
valid_label() { [[ "$1" =~ ^(validator|sentry)$ ]]; }
need_dirs() { (umask 077; mkdir -p "$STATE_DIR" "$OUTBOX" "$STORE") || die "cannot create $STATE_DIR" 2; chmod 700 "$STATE_DIR" "$OUTBOX" "$STORE"; }
gens_in() { # DIR -> complete generations (a .meta exists = committed), oldest first
  local f
  for f in "$1"/gen-*.meta; do [ -f "$f" ] || continue; f="${f##*/gen-}"; echo "${f%.meta}"; done | sort
}
meta_get() { sed -n "s/^$2=//p" "$1" | head -1; }
prune() { # DIR KEEP: drop the oldest complete generations beyond KEEP, and stale temp files
  local d="$1" k="$2" n g
  n="$(gens_in "$d" | wc -l)"
  gens_in "$d" | head -n "$((n > k ? n - k : 0))" | while read -r g; do rm -f "$d/gen-$g.meta" "$d/gen-$g.age" "$d/gen-$g.verified"; echo "  pruned gen $g"; done
  find "$d" -maxdepth 1 -name '.*.tmp' -mmin +60 -delete 2>/dev/null
  return 0
}
conf_set() { # KEY VALUE: replace or append in the conf, atomically, 0600
  local tmp
  tmp="$(mktemp "$CONF.XXXXXX")" || die "cannot write $CONF" 2
  { [ -f "$CONF" ] && grep -v "^$1=" "$CONF"; printf '%s=%s\n' "$1" "$2"; } > "$tmp"
  chmod 600 "$tmp" && mv -f "$tmp" "$CONF" || { rm -f "$tmp"; die "cannot write $CONF" 2; }
}

cmd_keygen() {
  [ -e "$IDF" ] && die "age identity already exists ($IDF); keygen never replaces it" 4
  need_dirs
  if [ -s "$FPF" ]; then echo "fp_key: kept"
  else (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$FPF") || die "cannot write fp_key" 2; echo "fp_key: created (0600)"; fi
  (umask 077; "$AGE_KEYGEN" -o "$IDF.tmp" 2>/dev/null) || { rm -f "$IDF.tmp"; die "age-keygen failed" 2; }
  mv -f "$IDF.tmp" "$IDF" || die "cannot write $IDF" 2
  "$AGE_KEYGEN" -y "$IDF" > "$AGEPUB" 2>/dev/null || die "age-keygen -y failed" 2
  chmod 644 "$AGEPUB"
  [[ "$(cat "$AGEPUB")" =~ $AGE_RE ]] || die "age-keygen printed no valid recipient" 2
  echo "age identity: created (0600, never printed)"
  echo "age recipient: $(cat "$AGEPUB")"
}
cmd_pubkey() { [ -r "$AGEPUB" ] && [[ "$(cat "$AGEPUB")" =~ $AGE_RE ]] || die "no age recipient (run keygen)" 4; cat "$AGEPUB"; }
cmd_set_peer() {
  [[ "${1:-}" =~ $AGE_RE ]] || die "set-peer: want an age recipient (age1 + 58 chars)"
  [ -r "$AGEPUB" ] && [ "$(cat "$AGEPUB")" = "$1" ] && die "set-peer: that is this host's own recipient"
  conf_set PEER_RECIPIENT "$1"
  echo "PEER_RECIPIENT set for $PEER_LABEL"
}

cmd_seal() {
  local gen err tmp sha bytes n rc
  [ -s "$FPF" ] || die "no fp_key (run keygen)" 4
  [[ "$PEER_RECIPIENT" =~ $AGE_RE ]] || die "PEER_RECIPIENT not set or malformed (run set-peer)" 4
  scan
  if [ "$SCAN_RC" = 2 ]; then
    printf '%s' "$ROWS" | awk -F'\t' '$2 == "perm" || $2 == "missing" || $2 == "unreadable" { print "  [" $2 "] " $1 ": " $7 }'
    die "seal refused: inventory has perm/missing/unreadable items; fix them first (nothing sealed)" 4
  fi
  [ -n "$SEAL_LIST" ] || die "seal refused: no ok items" 4
  need_dirs
  gen="$(date -u +%Y%m%dT%H%M%SZ)"
  while [ -e "$OUTBOX/gen-$gen.meta" ]; do sleep 1; gen="$(date -u +%Y%m%dT%H%M%SZ)"; done
  tmp="$OUTBOX/.gen-$gen.age.tmp"; err="$(mktemp "$STATE_DIR/.seal-err.XXXXXX")"
  (
    umask 077
    printf '%s' "$SEAL_LIST" | python3 -I "$HELPER" pack --host "$HOST_LABEL" --gen "$gen" 2>"$err" \
      | "$AGE" -r "$PEER_RECIPIENT" -o "$tmp"
    exit $((PIPESTATUS[0] + PIPESTATUS[1] + PIPESTATUS[2]))
  ); rc=$?
  if [ "$rc" != 0 ] || [ ! -s "$tmp" ]; then
    sed 's/^/  /' "$err"; rm -f "$tmp" "$err"; die "seal failed (pack/age exit $rc); nothing committed" 2
  fi
  rm -f "$err"
  sha="$(sha256sum < "$tmp" | cut -c1-64)"; bytes="$(stat -c %s "$tmp")"; n="$(printf '%s' "$SEAL_LIST" | grep -c .)"
  (
    umask 077
    printf 'v=1\nhost=%s\ngen=%s\ncreated=%s\ncipher_sha256=%s\ncipher_bytes=%s\nrecipient=%s\nitems=%s\n' \
      "$HOST_LABEL" "$gen" "$(date -u +%s)" "$sha" "$bytes" "$PEER_RECIPIENT" "$n"
    printf '%s' "$FPS" | awk -F'\t' 'NF == 2 { print "fp\t" $1 "\t" $2 }'
  ) > "$OUTBOX/.gen-$gen.meta.tmp" || die "cannot write meta" 2
  mv -f "$tmp" "$OUTBOX/gen-$gen.age" && mv -f "$OUTBOX/.gen-$gen.meta.tmp" "$OUTBOX/gen-$gen.meta" || die "cannot commit gen $gen" 2
  prune "$OUTBOX" 2 >/dev/null
  echo "SEALED gen=$gen host=$HOST_LABEL items=$n cipher_bytes=$bytes cipher_sha256=${sha:0:16}"
}

record_escrowed() { # GEN: the peer holds and verified this outbox generation -> ESCROWED (fingerprints at seal time)
  local m="$OUTBOX/gen-$1.meta" tmp
  [[ "$1" =~ $GEN_RE ]] && [ -f "$m" ] || die "no sealed generation $1 in the outbox" 4
  tmp="$(mktemp "$STATE_DIR/.escrowed.XXXXXX")" || die "cannot write $ESCROWED" 2
  { printf '# escrowed_at=%s\n# gen=%s\n' "$(date -u +%s)" "$1"; awk -F'\t' '$1 == "fp" { print $2 "\t" $3 }' "$m"; } > "$tmp"
  chmod 600 "$tmp" && mv -f "$tmp" "$ESCROWED" || { rm -f "$tmp"; die "cannot write $ESCROWED" 2; }
  echo "ACKED gen=$1 items=$(meta_get "$m" items)"
}

verify_gen() { # FROM GEN -> prints, writes gen-G.verified; rc 0 ok, 2 bad
  local d="$STORE/$1" g="$2" have want out rc
  want="$(meta_get "$d/gen-$g.meta" cipher_sha256)"
  have="$(sha256sum < "$d/gen-$g.age" 2>/dev/null | cut -c1-64)"
  if [ -z "$want" ] || [ "$have" != "$want" ]; then
    echo "  gen $g: ciphertext sha256 MISMATCH (meta ${want:0:16}, file ${have:0:16})"; rc=2
  else
    out="$("$AGE" -d -i "$IDF" "$d/gen-$g.age" 2>&1 | python3 -I "$HELPER" check --host "$1" --gen "$g" 2>&1)"
    rc=$?
    [ "$rc" = 0 ] || rc=2
    sed 's/^/  /' <<<"$out"
  fi
  (umask 077; printf 'verified_at=%s\nresult=%s\n' "$(date -u +%s)" "$([ "$rc" = 0 ] && echo ok || echo bad)" > "$d/gen-$g.verified")
  if [ "$rc" = 0 ]; then echo "VERIFIED from=$1 gen=$g items=$(meta_get "$d/gen-$g.meta" items)"
  else echo "VERIFY FAILED from=$1 gen=$g"; fi
  return "$rc"
}

cmd_receive() { # FROM, stdin = tar of gen-G.meta + gen-G.age
  local from="${1:-}" out g rc
  valid_label "$from" && [ "$from" != "$HOST_LABEL" ] || die "receive: FROM must be the peer's label (not $HOST_LABEL)"
  [ -s "$IDF" ] || die "no age identity (run keygen)" 4
  need_dirs; (umask 077; mkdir -p "$STORE/$from"); chmod 700 "$STORE/$from"
  out="$(python3 -I "$HELPER" receive "$STORE/$from" --host "$from" 2>&1)"; rc=$?
  echo "$out"
  [ "$rc" = 0 ] || { echo "RECEIVE FAILED from=$from"; return 2; }
  g="$(sed -n 's/^RECEIVED gen=\([0-9TZ]*\) .*/\1/p' <<<"$out")"
  verify_gen "$from" "$g"; rc=$?
  if [ "$rc" != 0 ]; then # never let a generation that failed its first check displace a good one
    rm -f "$STORE/$from/gen-$g.age" "$STORE/$from/gen-$g.meta" "$STORE/$from/gen-$g.verified"
    echo "  discarded gen $g (failed verify on receive)"
    return "$rc"
  fi
  prune "$STORE/$from" "$KEEP"
}

cmd_export() {
  [[ "${1:-}" =~ $GEN_RE ]] && [ -f "$OUTBOX/gen-$1.meta" ] && [ -f "$OUTBOX/gen-$1.age" ] || die "export: no sealed generation ${1:-}" 4
  tar -C "$OUTBOX" --format=ustar -cf - "gen-$1.meta" "gen-$1.age"
}

cmd_serve() { # the only verbs PEER_SSH may run on this host
  local v="${1:-}"; shift || true
  case "$v" in
    receive) [ $# = 1 ] || die "serve receive LABEL"; cmd_receive "$1" ;;
    seal) [ $# = 0 ] || die "serve seal"; cmd_seal ;;
    export) [ $# = 1 ] || die "serve export GEN"; cmd_export "$1" ;;
    ack) [ $# = 1 ] || die "serve ack GEN"; record_escrowed "$1" ;;
    *) die "serve: unknown verb '$v' (receive|seal|export|ack)" ;;
  esac
}

peer() { # VERB ARGS... : run serve on the peer through PEER_SSH
  # shellcheck disable=SC2086 # PEER_SSH / REMOTE_CMD are command lines from the root-owned conf
  timeout "$SSH_TIMEOUT" $PEER_SSH $REMOTE_CMD serve "$@"
}

cmd_escrow() {
  local out g g2 fails=0 rc
  [ -n "$PEER_SSH" ] || die "PEER_SSH not set (see $CONF)" 4
  echo "pft-keyescrow escrow - $(ts) | host $HOST_LABEL <-> peer $PEER_LABEL | keep $KEEP generations"
  echo "== 1. seal here, push to $PEER_LABEL, $PEER_LABEL decrypts in memory and checks every item"
  out="$(cmd_seal 2>&1)"; rc=$?; sed 's/^/  /' <<<"$out"
  g="$(sed -n 's/^SEALED gen=\([0-9TZ]*\) .*/\1/p' <<<"$out")"
  if [ "$rc" != 0 ] || [ -z "$g" ]; then fails=$((fails + 1)); echo "  FAIL seal here"
  else
    out="$(tar -C "$OUTBOX" --format=ustar -cf - "gen-$g.meta" "gen-$g.age" | peer receive "$HOST_LABEL" 2>&1)"; rc=$?
    sed 's/^/  | /' <<<"$out"
    if [ "$rc" = 0 ] && grep -qx "VERIFIED from=$HOST_LABEL gen=$g items=[0-9]*" <<<"$out"; then
      record_escrowed "$g" | sed 's/^/  /'
    else fails=$((fails + 1)); echo "  FAIL push/verify on $PEER_LABEL (exit $rc)"; fi
  fi
  echo "== 2. $PEER_LABEL seals, pull here, decrypt in memory and check every item, ack"
  out="$(peer seal </dev/null 2>&1)"; rc=$?; sed 's/^/  | /' <<<"$out"
  g2="$(sed -n 's/^SEALED gen=\([0-9TZ]*\) .*/\1/p' <<<"$out")"
  if [ "$rc" != 0 ] || [ -z "$g2" ]; then fails=$((fails + 1)); echo "  FAIL seal on $PEER_LABEL"
  else
    out="$(peer export "$g2" </dev/null | cmd_receive "$PEER_LABEL" 2>&1)"; rc=$?
    sed 's/^/  /' <<<"$out"
    if [ "$rc" = 0 ] && grep -qx "VERIFIED from=$PEER_LABEL gen=$g2 items=[0-9]*" <<<"$out"; then
      out="$(peer ack "$g2" </dev/null 2>&1)"; rc=$?; sed 's/^/  | /' <<<"$out"
      grep -qx "ACKED gen=$g2 items=[0-9]*" <<<"$out" && [ "$rc" = 0 ] || { fails=$((fails + 1)); echo "  FAIL ack on $PEER_LABEL"; }
    else fails=$((fails + 1)); echo "  FAIL pull/verify here (exit $rc)"; fi
  fi
  if [ "$fails" = 0 ]; then echo "RESULT: PASS - both directions sealed, held and verified"; return 0; fi
  echo "RESULT: FAIL - $fails step(s) failed"; return 2
}

cmd_verify() {
  local all=0 tf=0 from g gens newest ok total=0 bad=0 lines=""
  while [ $# -gt 0 ]; do
    case "$1" in --all) all=1 ;; --textfile) tf=1 ;; *) die "verify: unknown option $1" ;; esac
    shift
  done
  [ -s "$IDF" ] || die "no age identity (run keygen)" 4
  echo "pft-keyescrow verify - $(ts) | host $HOST_LABEL"
  for from in validator sentry; do
    [ "$from" = "$HOST_LABEL" ] && continue
    gens="$(gens_in "$STORE/$from" 2>/dev/null)"
    newest="$(tail -1 <<<"$gens")"
    if [ -z "$newest" ]; then echo "  no generation held for $from"; ok=0
    else
      ok=1
      for g in $gens; do
        [ "$all" = 1 ] || [ "$g" = "$newest" ] || continue
        total=$((total + 1))
        if ! verify_gen "$from" "$g"; then bad=$((bad + 1)); [ "$g" = "$newest" ] && ok=0; fi
      done
    fi
    lines+="pft_keyescrow_held_generations{node=\"$HOST_LABEL\",peer=\"$from\"} $(grep -c . <<<"$gens")"$'\n'
    lines+="pft_keyescrow_held_newest_timestamp_seconds{node=\"$HOST_LABEL\",peer=\"$from\"} $([ -n "$newest" ] && meta_get "$STORE/$from/gen-$newest.meta" created || echo 0)"$'\n'
    lines+="pft_keyescrow_held_verify_ok{node=\"$HOST_LABEL\",peer=\"$from\"} $ok"$'\n'
  done
  if [ "$tf" = 1 ]; then
    local out="$TEXTFILE_DIR/pft_keyescrow_held.prom" tmp
    tmp="$(mktemp "$TEXTFILE_DIR/.pft_keyescrow_held.prom.XXXXXX")" || die "cannot write $TEXTFILE_DIR" 2
    {
      printf '# HELP pft_keyescrow_held_generations Complete escrow generations this host holds for the peer.\n# TYPE pft_keyescrow_held_generations gauge\n'
      grep '^pft_keyescrow_held_generations' <<<"$lines"
      printf '# HELP pft_keyescrow_held_newest_timestamp_seconds Seal time of the newest held generation (0 = none).\n# TYPE pft_keyescrow_held_newest_timestamp_seconds gauge\n'
      grep '^pft_keyescrow_held_newest' <<<"$lines"
      printf '# HELP pft_keyescrow_held_verify_ok 1 if the newest held generation passed sha256 + in-memory decrypt check.\n# TYPE pft_keyescrow_held_verify_ok gauge\n'
      grep '^pft_keyescrow_held_verify_ok' <<<"$lines"
      printf '# HELP pft_keyescrow_verify_timestamp_seconds Time of the last verify run.\n# TYPE pft_keyescrow_verify_timestamp_seconds gauge\n'
      printf 'pft_keyescrow_verify_timestamp_seconds{node="%s"} %s\n' "$HOST_LABEL" "$(date -u +%s)"
    } > "$tmp"
    if ! chmod 644 "$tmp" || ! mv -f "$tmp" "$out"; then rm -f "$tmp"; die "cannot write $out" 2; fi
  fi
  echo "RESULT: $total generation(s) checked, $bad failed -> exit $([ "$bad" = 0 ] && echo 0 || echo 2)"
  [ "$bad" = 0 ] || return 2
}

usage() { sed -n '/^# Usage:/,/^#$/p' "$0" | sed '$d' >&2; exit 3; }
case "${1:-}" in
  inventory) shift; cmd_inventory "$@"; exit $? ;;
  keygen) cmd_keygen; exit $? ;;
  pubkey) cmd_pubkey; exit $? ;;
  set-peer) shift; cmd_set_peer "$@"; exit $? ;;
  seal) cmd_seal; exit $? ;;
  escrow) cmd_escrow; exit $? ;;
  verify) shift; cmd_verify "$@"; exit $? ;;
  serve) shift; cmd_serve "$@"; exit $? ;;
  *) usage ;;
esac
