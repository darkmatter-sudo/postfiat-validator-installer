#!/usr/bin/env bash
# pft-fwaudit: compare a host's declared inbound policy with its effective exposure, and narrow UFW to it.
# UFW rules alone do not say what is reachable: Docker-published ports are DNATed on the FORWARD path where UFW's
# INPUT rules never apply (DOCKER-USER decides), docker-proxy serves a family Docker did not DNAT on the INPUT path,
# `*` listeners are dual-stack, and nftables tables outside iptables-nft can add their own hooks. This captures the
# rulesets and sockets once into a bundle and fwaudit_eval.py walks the real chains for each listener.
#
# Usage: sudo pft-fwaudit collect [--out FILE]                         write a capture bundle (default: stdout)
#        sudo pft-fwaudit audit [--role R] [--json] [--bundle FILE] [--textfile]
#                                                     exit 0 PASS, 1 WARN, 2 FAIL, 3 usage/policy, 4 capture
#        sudo pft-fwaudit plan [--role R] [--json] [--bundle FILE]     exit 0 nothing to do, 1 actions, 2 manual items
#        sudo pft-fwaudit apply --yes [--role R] [--dry-run] [--deadman MIN] [--foreground]
#        sudo pft-fwaudit rollback --yes
#        sudo pft-fwaudit watch                                        (the dead-man; apply starts it as a unit)
#        sudo pft-fwaudit pull                         validator: copy the peer's textfile (PULL_SSH in the env file)
#        pft-fwaudit validate FILE HOST                the check pull applies to a fetched textfile
#        pft-fwaudit version
#
#  collect  runs, each into its own `### $ CMD` / `### rc=N` section: ufw status verbose, iptables-save,
#           ip6tables-save, nft list ruleset, ss -H -tulpn, docker ps (names/ports), ip -br addr. Nothing is changed
#           and nothing is sent anywhere; no docker exec into any container.
#  audit    collects (or reads --bundle) and grades it against POLICY_DIR/ROLE.policy with peer sources from PEERS.
#           --textfile also writes TEXTFILE_DIR/pft_fwaudit_HOST.prom (atomic rename): pft_fwaudit_up (0 = capture or
#           policy error, then only up + timestamp), pft_fwaudit_last_run_timestamp_seconds and, when graded,
#           pft_fwaudit_verdict (0/1/2), pft_fwaudit_findings{severity}, pft_fwaudit_finding_class{class,severity}
#           (every class, 0 when absent) and pft_fwaudit_exposed{family,state} (reachable family/proto/port count).
#  pull     runs "$PULL_SSH cat -- REMOTE_DIR/pft_fwaudit_PEER.prom" (timeout PULL_TIMEOUT), validates it (only
#           pft_fwaudit_ samples whose first label is host="PEER", up + timestamp present, <= MAX_BYTES) and renames
#           it into TEXTFILE_DIR; a failed fetch or validation leaves the previous copy (it then goes stale).
#  plan     read-only: the UFW changes apply would make (fwaudit_eval.py plan). Only narrowing changes are planned:
#           delete UFW allows behind undeclared/stale exposure, per-source allows instead of a too-broad one, LIMIT
#           for a declared-limited port, default deny incoming. Docker/DOCKER-USER/nftables items are MANUAL.
#  apply    --dry-run prints the plan and changes nothing. Otherwise refuses (exit 4) unless --yes, a pft-maint
#           window is active with DEADMAN*60 + MAINT_MARGIN seconds left and no data-collection lock, the node is
#           full with peers >= MIN_PEERS, and no earlier apply is still pending. Then snapshots /etc/ufw/user.rules,
#           user6.rules and /etc/default/ufw, runs the planned ufw commands (adds first, deletes by rule numbers
#           re-read before each delete), re-audits (every planned finding gone, every declared exposure still
#           reachable, else rollback) and starts the dead-man: for DEADMAN minutes (10) a poll every POLL_SEC (30);
#           BAD_POLLS (3) consecutive polls with the node not full, peers < baseline - PEER_SLACK, or a declared
#           exposure (SSH included) gone -> rollback. No plan actions = "no change", exit 0.
#  rollback restores the snapshot files, `ufw reload`, checks their sha256 against the snapshot, stops the dead-man.
#
# Exit codes (apply/rollback/watch): 0 ok, 1 apply failed and rolled back / dead-man rolled back, 3 usage/config,
#            4 refused, 5 rollback failed, 6 interrupted (rolled back).
# Conf: PFT_FWA_CONF (/etc/pft-fwaudit.env, root-owned): ROLE (validator), POLICY_DIR (/usr/local/lib/pft-fwaudit/policy),
#       PEERS (/etc/pft-fwaudit.peers: NAME=CIDR[,CIDR] lines, kept off the public repo), CMD_TIMEOUT (20),
#       CONTAINER (role default: validator postfiatd, sentry postfiatd-sentry; any other role postfiatd),
#       RPC_URL ("" = `docker exec CONTAINER curl` on its loopback, as pft-selfheal does),
#       DEADMAN_MIN (10), POLL_SEC (30), BAD_POLLS (3), PEER_SLACK (1), MIN_PEERS (3), MAINT_MARGIN (300),
#       STATE_DIR (/var/lib/pft-fwaudit), UFW_DIR (/etc/ufw), UFW_DEFAULT (/etc/default/ufw),
#       HOST_LABEL (= ROLE), TEXTFILE_DIR (/var/lib/pft-exporter/textfile); pull: PEER_LABEL (sentry), PULL_SSH
#       (command line that runs `cat` on the peer), PULL_TIMEOUT (30), REMOTE_DIR (/var/lib/pft-exporter/textfile),
#       MAX_BYTES (65536)
# Test hooks: PFT_FWA_EVAL (/usr/local/lib/pft-fwaudit/fwaudit_eval.py), PFT_FWA_TEST=1 (no root check),
#       PFT_FWA_COLLECT (command printing a bundle), PFT_FWA_UFW / _MAINT / _SYSTEMCTL / _SYSTEMD_RUN (commands),
#       PFT_FWA_RPC_CMD (prints server_info JSON), PFT_FWA_DOCKER (docker command), PFT_FWA_NOW_FILE (fake clock)

set -uo pipefail
umask 077
VERSION=3

CONF="${PFT_FWA_CONF:-/etc/pft-fwaudit.env}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && [ "$(stat -c %u "$CONF")" = 0 ] && . "$CONF"
ROLE="${ROLE:-validator}"
POLICY_DIR="${POLICY_DIR:-/usr/local/lib/pft-fwaudit/policy}"
PEERS="${PEERS:-/etc/pft-fwaudit.peers}"
CMD_TIMEOUT="${CMD_TIMEOUT:-20}"
CONTAINER="${CONTAINER:-}" # defaults by ROLE after option parsing
RPC_URL="${RPC_URL:-}"
DEADMAN_MIN="${DEADMAN_MIN:-10}"
POLL_SEC="${POLL_SEC:-30}"
BAD_POLLS="${BAD_POLLS:-3}"
PEER_SLACK="${PEER_SLACK:-1}"
MIN_PEERS="${MIN_PEERS:-3}"
MAINT_MARGIN="${MAINT_MARGIN:-300}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-fwaudit}"
UFW_DIR="${UFW_DIR:-/etc/ufw}"
UFW_DEFAULT="${UFW_DEFAULT:-/etc/default/ufw}"
HOST_LABEL="${HOST_LABEL:-}" # defaults to ROLE after option parsing
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
PEER_LABEL="${PEER_LABEL:-sentry}"
PULL_SSH="${PULL_SSH:-}"
PULL_TIMEOUT="${PULL_TIMEOUT:-30}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
MAX_BYTES="${MAX_BYTES:-65536}"
EVAL="${PFT_FWA_EVAL:-/usr/local/lib/pft-fwaudit/fwaudit_eval.py}"
TEST="${PFT_FWA_TEST:-}"
UFW="${PFT_FWA_UFW:-ufw}"
MAINT="${PFT_FWA_MAINT:-pft-maint}"
SYSTEMCTL="${PFT_FWA_SYSTEMCTL:-systemctl}"
SYSTEMD_RUN="${PFT_FWA_SYSTEMD_RUN:-systemd-run}"
DOCKER="${PFT_FWA_DOCKER:-docker}"
UNIT=fwaudit-deadman # outside the pft-* namespace: a transient pft-* unit would show up as NEW in pft-schedaudit
SNAP_FILES=("$UFW_DIR/user.rules" "$UFW_DIR/user6.rules" "$UFW_DEFAULT")

die() { printf 'pft-fwaudit: %s\n' "$1" >&2; exit "${2:-3}"; }
now() { if [ -n "${PFT_FWA_NOW_FILE:-}" ]; then cat "$PFT_FWA_NOW_FILE"; else date -u +%s; fi; }
nap() { if [ -n "${PFT_FWA_NOW_FILE:-}" ]; then echo $(( $(now) + $1 )) > "$PFT_FWA_NOW_FILE"; else sleep "$1"; fi; }
iso() { date -u -d "@$1" +%FT%TZ; }
log() { echo "[$(iso "$(now)")] $*"; }

section() { # CMD...: one bundle section; the command's own rc is recorded, stderr is kept out of the body
  local rc
  printf '### $ %s\n' "$*"
  timeout "$CMD_TIMEOUT" "$@" 2>/dev/null
  rc=$?
  printf '### rc=%s\n' "$rc"
}

collect() {
  if [ -n "${PFT_FWA_COLLECT:-}" ]; then "$PFT_FWA_COLLECT"; return; fi
  section ufw status verbose
  section iptables-save
  section ip6tables-save
  section nft list ruleset
  section ss -H -tulpn
  section docker ps --format '{{.Names}}\t{{.Ports}}'
  section ip -br addr
}

need_root() { [ -n "$TEST" ] || [ "$(id -u)" = 0 ] || die "must run as root (reads netfilter rules and socket owners)" 3; }

TMP="" # made once by the main shell (fresh_bundle runs in $(...) subshells, which must not own the cleanup trap)
tmpdir() { [ -n "$TMP" ] || { TMP="$(mktemp -d)" || die "mktemp failed" 4; trap 'rm -rf "$TMP"' EXIT; }; }

eval_cmd() { # SUBCMD BUNDLE [--json]: fwaudit_eval.py against this role's policy and peers; prints, returns its rc
  local sub="$1" b="$2" policy peers=()
  shift 2
  policy="$POLICY_DIR/$ROLE.policy"
  [ -f "$policy" ] || die "no policy for role $ROLE ($policy)"
  [ -f "$PEERS" ] && peers=(--peers "$PEERS")
  python3 -I "$EVAL" "$sub" "$b" "$policy" "${peers[@]}" "$@"
}

fresh_bundle() { # -> path of a new capture bundle
  local b
  [ -n "$TMP" ] || die "internal: no scratch dir" 4
  b="$(mktemp -p "$TMP" bundle.XXXXXX)" || die "mktemp failed" 4
  collect > "$b" || die "capture failed" 4
  printf '%s' "$b"
}

# ---------- remediation ----------
state_file() { printf '%s/state.json' "$STATE_DIR"; }

server_obs() { # -> "STATE PEERS" ("down 0" when the RPC does not answer)
  local ans
  if [ -n "${PFT_FWA_RPC_CMD:-}" ]; then ans="$("$PFT_FWA_RPC_CMD")"
  elif [ -n "$RPC_URL" ]; then
    ans="$(curl -s --max-time 8 -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' \
      "$RPC_URL" 2>/dev/null)"
  else
    ans="$(timeout 13 "$DOCKER" exec "$CONTAINER" curl -s --max-time 8 \
      -H 'Content-Type: application/json' -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:5005/ 2>/dev/null)"
  fi
  jq -r '.result.info | "\(.server_state // "down") \(.peers // 0)"' <<<"$ans" 2>/dev/null | grep -E '^[a-z_]+ [0-9]+$' \
    || echo "down 0"
}
is_full() { case "$1" in full|validating|proposing) return 0 ;; esac; return 1; }
node_source() { # -> "ok <how>" or "refuse <reason>": can server_obs reach a node at all (before reading its state)?
  # a wrong CONTAINER made every apply refuse as "node is down" and every dead-man poll BAD (exposure drill, 2026-11-14)
  if [ -n "${PFT_FWA_RPC_CMD:-}" ]; then echo "ok test rpc command"; return; fi
  if [ -n "$RPC_URL" ]; then echo "ok RPC_URL $RPC_URL"; return; fi
  if [ "$(timeout 13 "$DOCKER" inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = true ]; then
    echo "ok docker exec $CONTAINER"
  else echo "refuse container '$CONTAINER' is not running on this host (set CONTAINER or RPC_URL in $CONF)"; fi
}

maint_gate() { # NEED_SEC -> "ok <remaining>" or "refuse <reason>"
  local j w rem nl
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "refuse pft-maint status failed (is pft-maint installed?)"; return; }
  w="$(jq -r '.window // "none"' <<<"$j" 2>/dev/null)"
  rem="$(jq -r '.remaining_sec // 0' <<<"$j" 2>/dev/null)"; [[ "$rem" =~ ^[0-9]+$ ]] || rem=0
  nl="$(jq -r '.locks | length' <<<"$j" 2>/dev/null)"; [[ "$nl" =~ ^[0-9]+$ ]] || nl=1
  if [ "$w" != active ]; then echo "refuse no active pft-maint window (window=$w); run: sudo pft-maint start --ttl 30m --reason ..."
  elif [ "$rem" -lt "$1" ]; then echo "refuse window has ${rem}s left, apply needs DEADMAN*60+MAINT_MARGIN=${1}s"
  elif [ "$nl" -gt 0 ]; then echo "refuse $nl pft-maint data-collection lock(s) held"
  else echo "ok $rem"; fi
}

snap_sums() { local f; for f in "${SNAP_FILES[@]}"; do sha256sum < "$f" | cut -d' ' -f1; done; }

snapshot() { # copy the UFW files apply may change into STATE_DIR/snapshot
  local f i=0
  rm -rf "$STATE_DIR/snapshot" && mkdir -p "$STATE_DIR/snapshot" || return 1
  for f in "${SNAP_FILES[@]}"; do
    [ -f "$f" ] || { log "snapshot: $f missing"; return 1; }
    cp -p "$f" "$STATE_DIR/snapshot/$i" || return 1
    i=$((i + 1))
  done
  snap_sums > "$STATE_DIR/snapshot/SHA256" || return 1
}

do_rollback() {
  local f i=0 rc=0
  [ -f "$STATE_DIR/snapshot/SHA256" ] || { log "rollback: no snapshot in $STATE_DIR/snapshot"; return 5; }
  log "rollback: restoring ${SNAP_FILES[*]} from $STATE_DIR/snapshot and reloading ufw"
  for f in "${SNAP_FILES[@]}"; do cp -p "$STATE_DIR/snapshot/$i" "$f" || rc=5; i=$((i + 1)); done
  "$UFW" reload >/dev/null || { log "rollback: ufw reload failed"; rc=5; }
  [ -n "${NO_STOP_DEADMAN:-}" ] || "$SYSTEMCTL" stop "$UNIT" >/dev/null 2>&1
  if [ "$(snap_sums)" != "$(cat "$STATE_DIR/snapshot/SHA256")" ]; then log "rollback RESULT: FAIL - restored files differ from the snapshot"; return 5; fi
  [ -f "$(state_file)" ] && jq -c --arg t "$(iso "$(now)")" '.result = "rolled-back" | .rolled_back_at = $t' "$(state_file)" \
    > "$(state_file).tmp" && mv -f "$(state_file).tmp" "$(state_file)"
  [ "$rc" -eq 0 ] && log "rollback RESULT: PASS - ufw files equal the snapshot (sha256), ufw reloaded"
  return "$rc"
}

run_action() { # one plan action (JSON) -> runs its ufw command(s); returns non-zero on any failure
  local a="$1" op n nums argv=()
  op="$(jq -r .op <<<"$a")"
  if [ "$op" != delete ]; then
    mapfile -t argv < <(jq -r '.argv[]' <<<"$a")
    [ "${argv[0]}" = ufw ] || { log "refusing non-ufw argv: ${argv[*]}"; return 1; }
    log "+ ${argv[*]}"
    "$UFW" "${argv[@]:1}" || return 1
    return 0
  fi
  local sel=() fam proto port
  fam="$(jq -r .family <<<"$a")"; proto="$(jq -r .proto <<<"$a")"; port="$(jq -r .port <<<"$a")"
  [ "$(jq -r .from_any_only <<<"$a")" = true ] && sel+=(--from-any)
  [ "$(jq -r '.keep // ""' <<<"$a")" != "" ] && sel+=(--keep "$(jq -r .keep <<<"$a")")
  [ "$(jq -r '.except_from // [] | length' <<<"$a")" -gt 0 ] && sel+=(--except-from "$(jq -r '.except_from | join(",")' <<<"$a")")
  nums="$("$UFW" status numbered | python3 -I "$EVAL" ufwnum "$fam" "$proto" "$port" "${sel[@]}")" || return 1
  [ -n "$nums" ] || { log "delete $proto/$port $fam: no matching ufw rule"; return 1; }
  while :; do # re-read the numbering before every delete; the highest match goes first
    n="${nums%% *}"
    log "+ ufw --force delete $n   ($proto/$port $fam, $(jq -r .why <<<"$a"))"
    "$UFW" --force delete "$n" >/dev/null || return 1
    nums="$("$UFW" status numbered | python3 -I "$EVAL" ufwnum "$fam" "$proto" "$port" "${sel[@]}")" || return 1
    [ -n "$nums" ] || break
  done
}

declared_keys() { jq -r '[.exposure[] | select(.declared) | "\(.family)/\(.proto)/\(.port)"] | sort | join(" ")' <<<"$1"; }
planned_keys() { jq -r '[.actions[] | select(.port) | "\(.why):\(.family)/\(.proto)/\(.port)"] | unique | sort | .[]' <<<"$1"; }
finding_keys() { jq -r '[.findings[] | select(.port) | "\(.class):\(.family)/\(.proto)/\(.port)"] | unique | sort | .[]' <<<"$1"; }

keep_check() { # KEEP -> "ok" or the missing declared exposures (one fresh capture)
  local b aj have missing="" k
  b="$(fresh_bundle)"; aj="$(eval_cmd audit "$b" --json)"
  [ -n "$aj" ] || { echo "audit failed"; return; }
  have=" $(declared_keys "$aj") "
  for k in $1; do [[ "$have" == *" $k "* ]] || missing+=" $k"; done
  if [ -z "$missing" ]; then echo ok; else echo "missing:$missing"; fi
}

watch_deadman() {
  local S base floor dl keep bad=0 st pe kc
  S="$(cat "$(state_file)" 2>/dev/null)" || die "no apply state in $STATE_DIR" 3
  ROLE="$(jq -r .role <<<"$S")"
  base="$(jq -r .baseline_peers <<<"$S")"; floor=$(( base - PEER_SLACK )); dl="$(jq -r .deadman_until_epoch <<<"$S")"
  keep="$(jq -r '.keep | join(" ")' <<<"$S")"
  log "dead-man: until $(iso "$dl"), rollback after $BAD_POLLS consecutive polls with state != full, peers < $floor (baseline $base - slack $PEER_SLACK) or a declared exposure gone ($keep)"
  while [ "$(now)" -lt "$dl" ]; do
    nap "$POLL_SEC"
    read -r st pe <<<"$(server_obs)"; kc="$(keep_check "$keep")"
    if is_full "$st" && [ "$pe" -ge "$floor" ] && [ "$kc" = ok ]; then bad=0; log "dead-man poll: $st peers $pe declared $kc"
    else bad=$((bad + 1)); log "dead-man poll: $st peers $pe declared $kc BAD ($bad/$BAD_POLLS)"; fi
    if [ "$bad" -ge "$BAD_POLLS" ]; then log "dead-man: TRIPPED - rolling back"; NO_STOP_DEADMAN=1 do_rollback; return 1; fi
  done
  jq -c --arg t "$(iso "$(now)")" '.result = "kept" | .deadman_passed_at = $t' "$(state_file)" > "$(state_file).tmp" \
    && mv -f "$(state_file).tmp" "$(state_file)"
  log "dead-man: PASS - changes kept (snapshot stays in $STATE_DIR/snapshot for a manual rollback)"
}

prechecks() { # AUDIT_JSON -> one line per apply guard, as a real apply would see it now (a dry run never refuses)
  local g src st pe k
  g="$(maint_gate $(( DEADMAN_MIN * 60 + MAINT_MARGIN )))"; echo "pre-check maintenance window: $g"
  src="$(node_source)"; echo "pre-check node source: $src"
  case "$src" in
    ok*) read -r st pe <<<"$(server_obs)"
      if is_full "$st" && [ "$pe" -ge "$MIN_PEERS" ]; then echo "pre-check node: ok $st, peers $pe (MIN_PEERS $MIN_PEERS)"
      else echo "pre-check node: refuse $st, peers $pe (MIN_PEERS $MIN_PEERS)"; fi ;;
    *) echo "pre-check node: refuse no node source" ;;
  esac
  case "$( [ -f "$(state_file)" ] && jq -r '.result // ""' "$(state_file)")" in
    pending) echo "pre-check earlier apply: refuse still pending its dead-man ($(state_file))" ;;
    *) echo "pre-check earlier apply: ok none pending" ;;
  esac
  k=" $(declared_keys "$1") "
  if [[ "$k" == *" v4/tcp/22 "* ]]; then echo "pre-check ssh v4/tcp/22: ok reachable declared exposure"
  else echo "pre-check ssh v4/tcp/22: refuse not a reachable declared exposure"; fi
}

do_apply() { # DRY FG
  local dry="$1" fg="$2" b pj aj gate st pe keep a post left src
  b="$(fresh_bundle)"
  pj="$(eval_cmd plan "$b" --json)"; [ -n "$pj" ] || die "plan failed" 3
  aj="$(eval_cmd audit "$b" --json)"
  if [ "$dry" = 1 ]; then eval_cmd plan "$b"; prechecks "$aj"; echo "dry run - nothing changed"; return 0; fi
  [ "$(jq '.actions | length' <<<"$pj")" -gt 0 ] || { log "apply: no change (plan has no actions; $(jq '.manual | length' <<<"$pj") manual item(s))"; return 0; }
  [ "$YES" = 1 ] || die "apply changes the firewall; re-run with --yes (or --dry-run)" 4
  if [ -f "$(state_file)" ] && [ "$(jq -r '.result // ""' "$(state_file)")" = pending ]; then
    die "REFUSED: an earlier apply is still pending its dead-man ($(state_file)); wait or rollback" 4
  fi
  gate="$(maint_gate $(( DEADMAN_MIN * 60 + MAINT_MARGIN )))"
  case "$gate" in ok*) ;; *) die "REFUSED: ${gate#refuse }" 4 ;; esac
  src="$(node_source)"; case "$src" in ok*) ;; *) die "REFUSED: ${src#refuse }" 4 ;; esac
  read -r st pe <<<"$(server_obs)"
  is_full "$st" || die "REFUSED: node is $st, not full" 4
  [ "$pe" -ge "$MIN_PEERS" ] || die "REFUSED: peers $pe < MIN_PEERS $MIN_PEERS" 4
  keep="$(declared_keys "$aj")"
  [[ " $keep " == *" v4/tcp/22 "* ]] || die "REFUSED: SSH (v4/tcp/22) is not a reachable declared exposure before the change" 4
  mkdir -p "$STATE_DIR" || die "cannot create $STATE_DIR"
  snapshot || die "snapshot failed, nothing changed" 5
  jq -n --argjson plan "$pj" --arg keep "$keep" --argjson b "$pe" --argjson dl $(( $(now) + DEADMAN_MIN * 60 )) \
    --arg t "$(iso "$(now)")" --arg role "$ROLE" \
    '{role: $role, plan: $plan, keep: ($keep | split(" ") | map(select(length > 0))), baseline_peers: $b,
      applied_at: $t, deadman_until_epoch: $dl, result: "pending"}' > "$(state_file)"
  log "apply ($ROLE); maintenance gate: $gate; pre: server_state=$st peers=$pe; declared exposure kept: $keep"
  trap 'log "interrupted"; do_rollback; exit 6' INT TERM
  while IFS= read -r a; do
    run_action "$a" || { log "apply: action failed: $(jq -c . <<<"$a")"; do_rollback; exit 1; }
  done < <(jq -c '.actions[]' <<<"$pj")
  b="$(fresh_bundle)"; post="$(eval_cmd audit "$b" --json)"
  left="$(comm -12 <(planned_keys "$pj") <(finding_keys "$post"))"
  if [ -n "$left" ]; then log "apply: re-audit still finds: $(tr '\n' ' ' <<<"$left")"; do_rollback; exit 1; fi
  if [ "$(keep_check "$keep")" != ok ]; then log "apply: re-audit lost a declared exposure: $(keep_check "$keep")"; do_rollback; exit 1; fi
  log "re-audit: verdict $(jq -r .verdict <<<"$post"), every planned finding gone, declared exposure intact"
  trap - INT TERM
  if [ "$fg" = 1 ]; then watch_deadman; return $?; fi
  "$SYSTEMD_RUN" --unit="$UNIT" --collect -p "Environment=PFT_FWA_CONF=$CONF" "$(readlink -f "$0")" watch >/dev/null \
    || { log "could not start the dead-man unit"; do_rollback; exit 1; }
  log "dead-man started as transient unit $UNIT (journalctl -u $UNIT); apply RESULT: PASS (pending dead-man)"
}

# ---------- textfile metrics / pull ----------
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }

metrics() { # UP TS [AUDIT_JSON] -> textfile body
  local L="host=\"$HOST_LABEL\"" c sev
  printf '# HELP pft_fwaudit_up 1 = the last audit captured the host and graded it against its policy.\n'
  printf '# TYPE pft_fwaudit_up gauge\npft_fwaudit_up{%s} %s\n' "$L" "$1"
  printf '# HELP pft_fwaudit_last_run_timestamp_seconds Unix time of the last audit run.\n'
  printf '# TYPE pft_fwaudit_last_run_timestamp_seconds gauge\npft_fwaudit_last_run_timestamp_seconds{%s} %s\n' "$L" "$2"
  [ "$1" = 1 ] || return 0
  printf '# HELP pft_fwaudit_verdict Audit verdict: 0 PASS, 1 WARN, 2 FAIL.\n# TYPE pft_fwaudit_verdict gauge\n'
  jq -r --arg L "$L" '"pft_fwaudit_verdict{\($L)} \({"PASS": 0, "WARN": 1, "FAIL": 2}[.verdict])"' <<<"$3"
  printf '# HELP pft_fwaudit_findings Findings of the last audit by severity.\n# TYPE pft_fwaudit_findings gauge\n'
  for sev in fail warn info; do
    jq -r --arg L "$L" --arg s "$sev" \
      '"pft_fwaudit_findings{\($L),severity=\"\($s)\"} \([.findings[] | select(.severity == ($s | ascii_upcase))] | length)"' <<<"$3"
  done
  printf '# HELP pft_fwaudit_finding_class Findings of the last audit by class (every class, 0 when absent).\n'
  printf '# TYPE pft_fwaudit_finding_class gauge\n'
  while read -r c sev; do
    jq -r --arg L "$L" --arg c "$c" --arg s "$sev" \
      '"pft_fwaudit_finding_class{\($L),class=\"\($c)\",severity=\"\($s | ascii_downcase)\"} \([.findings[] | select(.class == $c)] | length)"' <<<"$3"
  done < <(python3 -I "$EVAL" classes)
  printf '# HELP pft_fwaudit_exposed Reachable (family, proto, port) entries by family and state.\n'
  printf '# TYPE pft_fwaudit_exposed gauge\n'
  jq -r --arg L "$L" '.exposure as $e | ["v4", "v6"][] as $f | ["open", "limited", "sources"][] as $s |
    "pft_fwaudit_exposed{\($L),family=\"\($f)\",state=\"\($s)\"} \([$e[] | select(.family == $f and .state == $s)] | length)"' <<<"$3"
}

write_textfile() { # CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_fwaudit_$HOST_LABEL.XXXXXX" 2>/dev/null)" || { echo "pft-fwaudit: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { printf '%s\n' "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_fwaudit_$HOST_LABEL.prom"; }; then
    rm -f "$t"; echo "pft-fwaudit: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

audit_textfile() { # BUNDLE|"" -> prints the audit (human or --json), writes the textfile, returns the audit's rc
  local b="$1" t0 aj rc body
  t0="$(now)"
  if [ -z "$b" ]; then
    b="$(mktemp -p "$TMP" bundle.XXXXXX)" || die "mktemp failed" 4
    if ! collect > "$b"; then write_textfile "$(metrics 0 "$t0")"; die "capture failed" 4; fi
  fi
  aj="$(eval_cmd audit "$b" --json)"; rc=$?
  if [ "$rc" -gt 2 ] || ! jq -e '.verdict and .exposure and .findings' >/dev/null 2>&1 <<<"$aj"; then
    write_textfile "$(metrics 0 "$t0")"
    [ "$rc" -gt 2 ] || rc=4
    echo "pft-fwaudit: audit error (rc=$rc), wrote up 0" >&2
    return "$rc"
  fi
  body="$(metrics 1 "$t0" "$aj")" || { write_textfile "$(metrics 0 "$t0")"; return 4; }
  write_textfile "$body" || return 4
  if [ "${#json[@]}" -gt 0 ]; then printf '%s\n' "$aj"; else eval_cmd audit "$b"; fi
  return "$rc"
}

validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"; [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_fwaudit_[a-z_]+ / || /^$/ { next }
    {
      if (match($0, /^pft_fwaudit_[a-z_]+\{/) == 0) { printf "line %d: not a pft_fwaudit_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_fwaudit_up\{/) up = 1
      if ($0 ~ /^pft_fwaudit_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_fwaudit_up sample"; exit 1 }
      if (!ts) { print "no pft_fwaudit_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL"
  [ "$PEER_LABEL" != "$HOST_LABEL" ] || die "refusing to pull over this host's own textfile ($PEER_LABEL)"
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)"
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT"
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-fwaudit-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_fwaudit_$PEER_LABEL.prom" >"$tmp" 2>/dev/null </dev/null; then
    rm -f "$tmp"; die "fetch of pft_fwaudit_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_fwaudit_$PEER_LABEL.prom"; }; then rm -f "$tmp"; die "rename failed" 1; fi
}

# ---------- main ----------
cmd="${1:-}"; shift || true
if [ "$cmd" = validate ]; then # FILE HOST: positional, before option parsing
  [ $# -eq 2 ] || die "usage: pft-fwaudit validate FILE HOST"
  valid_label "$2" || die "bad host label $2"
  why="$(validate "$1" "$2")" || { echo "INVALID: $why"; exit 1; }
  echo "OK"; exit 0
fi
json=() bundle="" out="" YES=0 DRY=0 FG=0 TF=0
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="${2:?}"; shift 2 ;;
    --json) json=(--json); shift ;;
    --textfile) TF=1; shift ;;
    --bundle) bundle="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --foreground) FG=1; shift ;;
    --deadman) DEADMAN_MIN="${2:?}"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$ROLE" =~ ^[a-z][a-z0-9-]*$ ]] || die "bad role $ROLE"
HOST_LABEL="${HOST_LABEL:-$ROLE}"
if [ -z "$CONTAINER" ]; then case "$ROLE" in sentry) CONTAINER=postfiatd-sentry ;; *) CONTAINER=postfiatd ;; esac; fi
valid_label "$HOST_LABEL" || die "bad HOST_LABEL $HOST_LABEL"
for v in DEADMAN_MIN POLL_SEC BAD_POLLS PEER_SLACK MIN_PEERS MAINT_MARGIN; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || die "$v must be an integer"
done

case "$cmd" in
  collect)
    need_root
    if [ -n "$out" ]; then collect > "$out" || die "cannot write $out" 4; else collect; fi
    ;;
  audit|plan)
    tmpdir
    if [ "$TF" = 1 ]; then
      [ "$cmd" = audit ] || die "--textfile is an audit option"
      [ -n "$bundle" ] || need_root
      audit_textfile "$bundle"; exit $?
    fi
    if [ -z "$bundle" ]; then need_root; bundle="$(fresh_bundle)"; fi
    eval_cmd "$cmd" "$bundle" "${json[@]}"
    exit $?
    ;;
  apply) need_root; tmpdir; command -v jq >/dev/null || die "jq is required"; do_apply "$DRY" "$FG"; exit $? ;;
  watch) need_root; tmpdir; watch_deadman; exit $? ;;
  rollback)
    need_root
    [ "$YES" = 1 ] || die "rollback changes the firewall; re-run with --yes" 4
    do_rollback; exit $?
    ;;
  pull) need_root; pull ;;
  version) echo "pft-fwaudit $VERSION" ;;
  *) sed -n '8,17p' "$0" >&2; exit 3 ;;
esac
