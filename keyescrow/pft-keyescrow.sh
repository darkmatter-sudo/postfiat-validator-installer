#!/usr/bin/env bash
# pft-keyescrow: keep the add-on secrets of a validator and its sentry recoverable after the loss of either host,
# without plaintext ever leaving the host it belongs to. Each host encrypts its own secrets to the PEER's age public
# key and stores N generations there; the peer can check a generation against its manifest but cannot read it.
#
# This file is step 1 (read-only inventory). Every secret path comes from a source line of an add-on in this repo
# (REGISTRY below, column "cite"; tests/run-tests.sh checks every citation still names the path).
#
# Usage: pft-keyescrow inventory [--json] [--textfile]   read-only; root to read 0600 files
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
set -uo pipefail
R="${PFT_KEYESCROW_ROOT:-}"
CONF="${PFT_KEYESCROW_CONF:-$R/etc/pft-keyescrow.env}"
STATE_DIR="${STATE_DIR:-$R/var/lib/pft-keyescrow}"
TEXTFILE_DIR="${TEXTFILE_DIR:-$R/var/lib/pft-exporter/textfile}"
FPF="$STATE_DIR/fp_key"
ESCROWED="$STATE_DIR/escrowed.tsv"
conf_get() { [ -f "$CONF" ] && sed -n "s/^$1=//p" "$CONF" | tail -1 | sed -E 's/^"(.*)"$/\1/'; return 0; }
HOST_LABEL="$(conf_get HOST_LABEL)"; HOST_LABEL="${HOST_LABEL:-validator}"
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

cmd_inventory() {
  local json=0 tf=0 id hosts tpl mode owner group need cite p st fp esc have_m have_o have_g own grp why
  local n_ok=0 n_perm=0 n_missing=0 n_absent=0 n_unread=0 n_drift=0 n_new=0 rows="" last
  while [ $# -gt 0 ]; do
    case "$1" in --json) json=1 ;; --textfile) tf=1 ;; *) die "inventory: unknown option $1" ;; esac
    shift
  done
  [[ "$HOST_LABEL" =~ ^(validator|sentry)$ ]] || die "HOST_LABEL must be validator or sentry (got '$HOST_LABEL')"
  last="$(escrowed_at)"
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
      fi
      if [ -r "$p" ]; then
        fp="$(fingerprint "$p")"
        local e; e="$(escrowed_fp "$id")"
        if [ -z "$e" ] || [ "$fp" = n/a ]; then esc=new; n_new=$((n_new + 1))
        elif [ "$e" = "$fp" ]; then esc=same
        else esc=drift; n_drift=$((n_drift + 1)); fi
      fi
    fi
    rows+="$id"$'\t'"$st"$'\t'"$esc"$'\t'"$fp"$'\t'"$need"$'\t'"$cite"$'\t'"$why"$'\n'
  done < <(registry)

  local rc=0
  [ $((n_drift + n_new)) -gt 0 ] || [ "$last" = 0 ] && rc=1
  [ $((n_perm + n_missing + n_unread)) -gt 0 ] && rc=2
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

case "${1:-}" in
  inventory) shift; cmd_inventory "$@"; exit $? ;;
  *) sed -n '9,10p' "$0" >&2; exit 3 ;;
esac
