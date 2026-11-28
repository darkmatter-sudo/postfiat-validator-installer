#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # ok() evals its single-quoted test at call time, so the variables it reads look unused
# domain-test: does a guide copy's "`domain` is empty in `validator_info`" re-run give the node a NEWER manifest?
# Runs sections 5-7 of the guide copy (fresh keys, domain A, token injection) in a THROWAWAY compose project on the
# SENTRY, then re-runs set_domain with domain B the way that copy's Troubleshooting entry says, injects the token, and
# records token_sequence, validator_info domain/seq/master_key and server_info pubkey_validator after two same-volume
# restarts (task_58670ccd9d10dc7c2f07a8d3daec6a8a).
#   EXPECT=pass|fail bash domain-rerun/domain-test.sh GUIDE 2>&1 | tee LOG   (validator, agent user; reaches the
#   sentry with `ssh relay`; GUIDE = one copy of content/validator-setup.md, e.g. from `git show REF:content/...`)
# Re-run flow: if the entry has the re-run blocks (T1 set_domain from the newest key file + T2 read-only sequence
# check), the flow is 06a(B) T1 T2 06c 06d 07a 07b and the token is injected only if T2 printed "sequence increase OK";
# otherwise (main: the entry only says "Re-run validator-keys set_domain") it is the guide's set_domain block of
# section 6: 06a(B) 06b 06c 06d 07a 07b.
# RERUN PASS = after the re-run restart AND after one more `docker compose restart` (same volumes): validator_info
# domain = B, seq > the seq after the first setup, master_key = the set_domain public key, and server_info
# pubkey_validator = that key. Exit 0 only if every harness CHECK is ok AND the verdict equals EXPECT.
# Never touches the validator's postfiatd or the sentry's postfiatd-sentry: the throwaway project lives in
# /var/tmp/pftdom-<random> on the sentry, uses the image postfiatd-sentry already runs (no pull), its container is
# test-pftdom-<random> (host tools pick a container named exactly postfiatd, so that name stays free), network_mode
# none, user "0:0" and the guide compose file's three mounts as project volumes (removed with down -v).
# The guide blocks run in one sentry shell per step, with exactly these edits, printed as a diff:
# `docker exec postfiatd ` -> `docker exec test-pftdom-<r> `, ` postfiatd:/` -> ` test-pftdom-<r>:/` (docker cp), and
# for the re-run only the domain in 06a: example.com -> example.org. The shell starts with `umask 022`.
#  S0 preflight  both live containers: ID + StartedAt + state; integrity PASS both; no test-pftdom container,
#                volume or dir; no sentry alert above info; schedaudit clean; next sentry pft-integrity run >= 15 min
#                away; operator topics found
#  S1 quiet      Alertmanager silence host="sentry"; pft-maint window with [MAINT] to a throwaway topic
#  S2 project    compose project up, server_info answers before any key exists
#  S3 setup      blocks 05 06a 06b 06c 06d 07a 07b (domain A = example.com); STATE first-setup
#  S4 re-run     the copy's re-run flow with domain B = example.org; STATE after-rerun-restart
#  S5 restart    `docker compose restart` of the project (same volumes); STATE after-second-restart
#  S6 control    (copies with T1/T2 only) the newest key file moved aside: T1 then re-signs from validator-keys.json
#                and T2 must refuse (exit != 0, no OK line) while the node keeps its seq; then T1+T2 again as the entry
#                says (each run starts from the file the previous run saved, which already holds domain B, so T1
#                takes its create_token branch) until T2 prints OK; nothing injected
#  S7 verdict    RERUN PASS / FAIL with the reasons
#  S8 cleanup    compose down -v, dir removed; containers + volumes on the sentry = S0
#  S9 end        live containers same ID + StartedAt and state; integrity PASS both; schedaudit clean; window ended,
#                pft-maint target restored; silence expired once no new sentry alert is pending or firing, then 3 min
#                without one; throwaway got the 2 [MAINT]; every operator topic 0 messages
# Every STATE line: key files (token_sequence, domain, public_key only; never secret_key or manifest), validator_info domain seq
# master_key, server_info server_state pubkey_validator. Token lines of set_domain output never reach the log.
# Env: RELAY (relay)  SIL_MIN (45)  TASK (task_58670ccd)  EXPECT (pass)
set -uo pipefail
RELAY="${RELAY:-relay}"; SIL_MIN="${SIL_MIN:-45}"; TASK="${TASK:-task_58670ccd}"; EXPECT="${EXPECT:-pass}"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
DOM_A=example.com; DOM_B=example.org
GUIDE="${1:-}"
[ -f "$GUIDE" ] || { echo "usage: EXPECT=pass|fail bash $0 GUIDE" >&2; exit 2; }
case "$EXPECT" in pass | fail) ;; *) echo "EXPECT must be pass or fail" >&2; exit 2 ;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
ME="$(id -un)"; HN="$(hostname)"
SN="$(ssh -o LogLevel=ERROR -o BatchMode=yes "$RELAY" hostname </dev/null)"
RID="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
D="/var/tmp/pftdom-$RID"; CN="test-pftdom-$RID"; PJ="pftdom-$RID"
TT="pft-drill-domrerun-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#\b$SN\b#<sentry>#g; s#\b(127\.0\.0\.1)\b#@LOOPBACK@#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#@LOOPBACK@#127.0.0.1#g; s#$TT#<throwaway-topic>#g"; }
# token lines of set_domain output (and any [validator_token] block) never reach the log
tokred() { awk '/^\[validator_token\]/ {print; t=1; next} t && NF == 0 {t=0} t {print "<validator_token line withheld>"; next} {print}'; }
ts() { date -u +%FT%TZ; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*" </dev/null; }
RS() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*"; } # with stdin
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok() { if eval "$1"; then echo 0; else echo 1; fi; }
step() { echo; echo "== $(ts) $*"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | tokred | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
W="$(mktemp -d -p "$HOME/.cache")"; X="$W/x"; B="$W/run"; mkdir "$B"; OPS="$(mktemp -p "$HOME/.cache")"; chmod 600 "$OPS"
# G LABEL BLOCK...: the edited copies of guide blocks, in ONE sentry shell, as one paste session
G() {
  local label="$1" f; shift
  echo "\$ ssh relay bash -s   <<< umask 022 + POSTFIATD_DIR=$D + cd + $label"
  for f in "$@"; do echo "  --- $f sha256 $(sha256sum "$B/$f" | cut -c1-16)"; sed 's/^/  | /' "$B/$f"; done
  XOUT="$( { echo "umask 022; echo \"shell umask \$(umask)\"; export POSTFIATD_DIR=$D; cd \"\$POSTFIATD_DIR\""
    for f in "$@"; do cat "$B/$f"; done; } | RS bash -s 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | tokred | red | sed 's/^/  /'; echo "  (exit $XRC)"
}
real() { # name ID StartedAt state for one live container
  if [ "$1" = validator ]; then
    echo "validator postfiatd $(sudo -n docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd) $(curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state)"
  else
    echo "sentry postfiatd-sentry $(R "docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd-sentry") $(R "docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r .result.info.server_state)"
  fi
}
inventory() { R "docker ps -a --format '{{.Names}}' | sort; docker volume ls -q | sort | md5sum"; }
vols() { R "docker inspect -f '{{range .Mounts}}{{if .Name}}{{.Name}}{{println}}{{end}}{{end}}' $CN" | sort | paste -sd' ' -; }
rpc() { R "docker exec $CN curl -s -m 5 -d '{\"method\":\"$1\"}' http://127.0.0.1:5005" 2>/dev/null; }

NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-domrerun
SWAPPED=0; MAINT=0; HAD=0; SIL=""; PROJ=0
since="$(date -u +%s)"
restore() {
  if [ "$PROJ" = 1 ]; then
    echo "\$ (restore) compose down -v + remove the throwaway dir on the sentry"
    R "cd $D 2>/dev/null && docker compose down -v -t 10 2>&1 | tail -3; rm -rf $D" | sed 's/^/  /'
    PROJ=0
  fi
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
# sentry alerts pending or firing in Prometheus (sentry rules are evaluated on the validator; AM never sees pending)
sentry_alerts() {
  local j; j="$(curl -s -m 10 "$PROM/api/v1/alerts")"
  if [ -z "$j" ] || ! jq -e '.status == "success"' >/dev/null <<<"$j"; then echo "@prometheus-unreadable@"; return; fi
  jq -r '[.data.alerts[] | select(.labels.host == "sentry") | .labels.alertname] | unique | .[]' <<<"$j"
}
PRE=""; ends=""
unsilence() { # expire the run's silence once nothing new for the sentry is active (else it runs out on its own)
  [ -n "$SIL" ] || return 0
  local p="" late=""
  for _ in $(seq 1 60); do
    p="$(sentry_alerts | grep -vxF -e "${PRE:-@none@}" | paste -sd, -)"
    [ -z "$p" ] && break; echo "$(ts) sentry alerts pending/firing that were not at S0: $p (wait 20 s)"; sleep 20
  done
  check "no sentry alert pending or firing before the silence ends, other than those active at S0" "$(ok '[ -z "$p" ]')" "${p:-none}"
  if [ -z "$p" ]; then x "curl -s -m 10 -XDELETE '$AM/api/v2/silence/$SIL' -o /dev/null -w 'expire silence http %{http_code}'"
  else echo "silence ${SIL:0:8} kept until $ends (something active)"; fi
  SIL=""
  for _ in $(seq 1 9); do
    sleep 20; late="$(sentry_alerts | grep -vxF -e "${PRE:-@none@}" | paste -sd, -)"; [ -z "$late" ] || break
  done
  check "no new sentry alert in the 3 minutes after the silence ended" "$(ok '[ -z "$late" ]')" "${late:-none}"
}
trap 'restore; unsilence; rm -rf "$W" "$OPS"' EXIT

# STATE LABEL: key files + validator_info + server_info; sets VI_DOM VI_SEQ VI_MK SI_PK SI_ST
VI_DOM=""; VI_SEQ=""; VI_MK=""; SI_PK=""; SI_ST=""
state() {
  local kf vi si
  kf="$(R "cd $D && for f in validator-keys.json validator-keys.domain.json validator-keys.backup-*.json; do [ -f \"\$f\" ] || continue
      echo \"KEYFILE \$f token_sequence=\$(jq -r .token_sequence \"\$f\") domain=\$(jq -r '.domain // \"none\"' \"\$f\") public_key=\$(jq -r .public_key \"\$f\") mode=\$(stat -c %a \"\$f\")\"; done")"
  printf '%s\n' "$kf" | sed "s/^/  [$1] /"
  vi="$(rpc validator_info)"; si="$(rpc server_info)"
  VI_DOM="$(jq -r '.result.domain // "none"' <<<"$vi" 2>/dev/null)"; VI_SEQ="$(jq -r '.result.seq // "none"' <<<"$vi" 2>/dev/null)"
  VI_MK="$(jq -r '.result.master_key // "none"' <<<"$vi" 2>/dev/null)"
  SI_PK="$(jq -r '.result.info.pubkey_validator // "none"' <<<"$si" 2>/dev/null)"; SI_ST="$(jq -r '.result.info.server_state // "none"' <<<"$si" 2>/dev/null)"
  echo "STATE $1 domain=${VI_DOM:-none} seq=${VI_SEQ:-none} master_key=${VI_MK:-none} pubkey_validator=${SI_PK:-none} server_state=${SI_ST:-none} set_domain_public_key=${PK:-none}"
  [ -n "$vi" ] || echo "  [$1] validator_info: no answer"
  jq -e '.result.error' >/dev/null 2>&1 <<<"$vi" && echo "  [$1] validator_info error: $(jq -r '.result.error' <<<"$vi")"
  return 0
}
# wait for the restarted throwaway to answer server_info with a non-empty pubkey_validator (max 120 s)
waitnode() {
  local i k=""
  for i in $(seq 1 40); do k="$(rpc server_info | jq -r '.result.info.pubkey_validator // empty' 2>/dev/null)"; [ -n "$k" ] && break; sleep 3; done
  echo "  [$1] server_info answered after $i poll(s) (pubkey_validator $([ -n "$k" ] && echo present || echo none))"
  [ -n "$k" ] || R "docker ps -a --filter name=$CN --format '{{.Names}} {{.Status}}'; tail -n 5 $D/logs/debug.log 2>/dev/null" | red | sed "s/^/  [$1] /"
  return 0
}
manifestlog() { # manifest lines the node logged since the run started (host-side log mount)
  echo "  [$1] debug.log manifest lines (last 6):"; R "grep -i 'manifest' $D/logs/debug.log 2>/dev/null | tail -n 6" | red | sed "s/^/    /"
}

REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo none)"
echo "domain-rerun domain-test - $(ts) - repo HEAD $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo none) (clean: $([ -z "$(git -C "$REPO" status --short 2>/dev/null)" ] && echo yes || echo NO)) - EXPECT=$EXPECT"
echo "sha256: domain-test.sh $(sha256sum "$0" | cut -c1-64)"
echo "        extract_domain.py $(sha256sum "$HERE/extract_domain.py" | cut -c1-64)"
echo "        guide $(sha256sum "$GUIDE" | cut -c1-64)"
echo "sentry: $(R 'lsb_release -ds; docker --version; docker compose version; jq --version' | paste -sd' ' -)"
echo "throwaway project: $D (project $PJ, container $CN, network none); domain A $DOM_A, domain B $DOM_B"

step "extract sections 5-7 and the Troubleshooting re-run blocks"
x "python3 -I '$HERE/extract_domain.py' '$X' '$GUIDE'"; check "extract" "$XRC"
[ "$XRC" = 0 ] || exit 1
mapfile -t BL < "$X/blocks.txt"; mapfile -t TB < "$X/rerun.txt"
echo "section 5-7 blocks: ${BL[*]}"; echo "re-run blocks of the domain entry: ${TB[*]:-none (entry has no command block)}"
HAST=0; [ "${#TB[@]}" = 2 ] && HAST=1
for f in "${BL[@]}" "${TB[@]}"; do sed "s/docker exec postfiatd /docker exec $CN /g; s# postfiatd:/# $CN:/#g" "$X/$f" > "$B/$f"; done
sed "s/\"$DOM_A\"/\"$DOM_B\"/" "$B/06a-domain.sh" > "$B/06a-domain-B.sh"
echo "edits (diff guide -> run):"
for f in "${BL[@]}" "${TB[@]}"; do diff "$X/$f" "$B/$f" >/dev/null && continue; echo "  $f:"; diff "$X/$f" "$B/$f" | sed 's/^/    /'; done
echo "  06a-domain.sh -> 06a-domain-B.sh (re-run only):"; diff "$X/06a-domain.sh" "$B/06a-domain-B.sh" | sed 's/^/    /'
check "06a sets domain A in the guide and B in the re-run copy" "$(ok 'grep -qx "export VALIDATOR_DOMAIN=\"$DOM_A\"" "$X/06a-domain.sh" && grep -qx "export VALIDATOR_DOMAIN=\"$DOM_B\"" "$B/06a-domain-B.sh"')"
check "no run block still names the container postfiatd (only paths and file names)" "$(ok '! grep -qE "docker (exec|cp) ([^ ]* )?postfiatd( |:)" "$B"/*.sh')"
x "cd '$B' && shellcheck --version | sed -n 's/^version: //p' && shellcheck -s bash -e SC2164 ${BL[*]} ${TB[*]}"
echo "  (shellcheck of the edited run copies; SC2164 = the guide's bare cd \"\$POSTFIATD_DIR\" lines)"
if [ "$HAST" = 1 ]; then
  x "cd '$X' && shellcheck -s bash -e SC2164 ${TB[*]} && echo 're-run blocks shellcheck clean'"
  check "the entry's re-run blocks (guide text) are shellcheck clean" "$XRC"
fi
if [ "$HAST" = 1 ]; then FLOW=(06a-domain-B.sh "${TB[0]}" "${TB[1]}" 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh); FLOWN="Troubleshooting re-run blocks"
else FLOW=(06a-domain-B.sh 06b-setdomain.sh 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh); FLOWN="section 6 set_domain block (entry has no command block)"; fi
echo "re-run flow: $FLOWN: ${FLOW[*]}"

step "S0 preflight"
V0="$(real validator)"; S0="$(real sentry)"; echo "$V0"; echo "$S0"
check "S0 validator postfiatd full or proposing" "$(ok '[[ "$V0" =~ (full|proposing)$ ]]')"
check "S0 sentry postfiatd-sentry full" "$(ok '[[ "$S0" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S0 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S0 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'docker ps -a --format {{.Names}} | grep -cE \"^(postfiatd|test-pftdom-.*)\$\"; docker volume ls -q | grep -c pftdom; ls -d /var/tmp/pftdom-* 2>/dev/null | wc -l'"
check "S0 sentry has no postfiatd or test-pftdom container, no pftdom volume or dir" "$(ok '[ "$(paste -sd, <<<"$XOUT")" = 0,0,0 ]')"
x "curl -s -m 10 '$PROM/api/v1/alerts' | jq -r '[.data.alerts[] | select(.labels.host == \"sentry\" and .labels.severity != \"info\") | .labels.alertname] | length'"
check "S0 no sentry alert above severity info pending or firing" "$(ok '[ "$(tail -1 <<<"$XOUT")" = 0 ]')"
x "R 'pft-schedaudit audit | tail -1'"; check "S0 sentry schedaudit: 0 unexpected" "$(ok 'grep -q "unexpected_findings=0 new=0 removed=0" <<<"$XOUT"')"
x "R 'systemctl show -p NextElapseUSecRealtime --value pft-integrity.timer'"
NEXT="$(date -u -d "$(tail -1 <<<"$XOUT")" +%s 2>/dev/null || echo 0)"; GAP=$(( (NEXT - $(date -u +%s)) / 60 ))
check "S0 next sentry pft-integrity run >= 15 min away" "$(ok '[ "$GAP" -ge 15 ]')" "$GAP min"
PRE="$(sentry_alerts)"; echo "sentry alerts already active before the run (left alone): $(paste -sd, - <<<"${PRE:-none}")"
INV0="$(inventory)"; echo "container names + volume list md5 (sentry):"; red <<<"$INV0" | sed 's/^/  /'
IMG="$(R "docker inspect -f '{{.Image}}' postfiatd-sentry")"; echo "image of postfiatd-sentry (used as is, no pull): $IMG"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env /etc/postfiat-monitor.env; do sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "S0 operator topics found" "$(ok '[ -s "$OPS" ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: preflight failed ($FAILS), nothing changed"; exit 1; }

step "S1 quiet: silence host=sentry, pft-maint window to a throwaway topic"
ends="$(date -u -d "+$SIL_MIN min" +%FT%TZ)"
body="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK domain-rerun throwaway node on the sentry" \
  '{matchers: [{name: "host", value: "sentry", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "pft-agent", comment: $c}')"
SIL="$(curl -s -m 10 -XPOST -H 'Content-Type: application/json' -d "$body" "$AM/api/v2/silences" | jq -r '.silenceID // empty')"
echo "silence ${SIL:0:8} host=sentry until $ends"; check "S1 silence created" "$(ok '[ -n "$SIL" ]')"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1; check "S1 throwaway pft-maint target installed" "$XRC"
if [ "$SWAPPED" != 1 ] || [ -z "$SIL" ]; then echo "RESULT: stopping before any change"; exit 1; fi
x "sudo -n pft-maint start --ttl 45m --reason '$TASK domain-rerun throwaway node on the sentry'"
[ "$XRC" = 0 ] && MAINT=1; check "S1 pft-maint window open" "$XRC"
for _ in $(seq 1 12); do R 'pft-maint active' >/dev/null 2>&1 && break; sleep 10; done
x "R 'pft-maint active && echo sentry window active'"; check "S1 sentry has the window" "$XRC"
[ "$FAILS" = 0 ] || { echo "RESULT: quiet setup failed ($FAILS)"; exit 1; }

step "S2 throwaway compose project (the guide compose file's mounts and user, no ports, network none)"
PROJ=1
COMPOSE="$(printf '%s\n' 'services:' '  postfiatd:' "    image: $IMG" "    container_name: $CN" '    network_mode: none' \
  '    volumes:' '      - postfiatd-config:/etc/postfiatd' '      - postfiatd-data:/var/lib/postfiatd/db' \
  '      - ./logs:/var/log/postfiatd' '    user: "0:0"' '    restart: "no"' '    labels:' '      org.postfiat.test: domain-rerun' \
  'volumes:' '  postfiatd-config:' '  postfiatd-data:')"
x "printf '%s\n' \"\$COMPOSE\" | RS 'mkdir -m 755 $D && mkdir $D/logs && cat > $D/docker-compose.yml && cat $D/docker-compose.yml'"
x "R 'cd $D && docker compose up -d 2>&1 && docker inspect -f \"{{.Name}} {{.Config.User}} {{.HostConfig.NetworkMode}} {{.State.Status}}\" $CN && docker inspect -f \"{{range .Mounts}}{{.Destination}}={{.Type}}:{{.Name}} {{end}}\" $CN'"
check "S2 throwaway container running, user 0:0, network none" "$(ok 'grep -q "^/$CN 0:0 none running$" <<<"$XOUT"')"
VOLS="$(vols)"; echo "  named volumes: $VOLS"
for _ in $(seq 1 30); do [ -n "$(rpc server_info | jq -r '.result.info.server_state // empty' 2>/dev/null)" ] && break; sleep 2; done
J="$(rpc server_info)"; echo "  server_info before keys: server_state=$(jq -r '.result.info.server_state // "none"' <<<"$J" 2>/dev/null) pubkey_validator=$(jq -r '.result.info.pubkey_validator // "none"' <<<"$J" 2>/dev/null)"
check "S2 server_info answers before any key exists" "$(ok '[ -n "$(jq -r ".result.info.server_state // empty" <<<"$J" 2>/dev/null)" ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: project setup failed ($FAILS)"; exit 1; }

step "S3 first setup: guide sections 5-7 with domain A ($DOM_A)"
RUN1=(05-keys.sh 06a-domain.sh 06b-setdomain.sh 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh)
G "${RUN1[*]}" "${RUN1[@]}"
check "S3 guide blocks exit 0" "$XRC"
PK="$(R "sed -n 's/^# validator public key: //p' $D/set-domain-output.txt | head -n 1")"
echo "  set_domain public key: $PK"
check "S3 set_domain produced a public key" "$(ok '[[ "$PK" =~ ^n[1-9A-HJ-NP-Za-km-z]{40,60}$ ]]')"
waitnode S3; state first-setup; SEQ1="$VI_SEQ"
check "S3 first setup: domain A, seq >= 1, master_key and pubkey_validator = set_domain key" \
  "$(ok '[ "$VI_DOM" = "$DOM_A" ] && [[ "$SEQ1" =~ ^[0-9]+$ ]] && [ "$SEQ1" -ge 1 ] && [ "$VI_MK" = "$PK" ] && [ "$SI_PK" = "$PK" ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: first setup failed ($FAILS)"; exit 1; }

step "S4 re-run with domain B ($DOM_B): $FLOWN"
INJECT=1
if [ "$HAST" = 1 ]; then
  G "06a(B) ${TB[*]}" 06a-domain-B.sh "${TB[@]}"
  T2RC="$XRC"; echo "  re-run blocks exit $T2RC"
  if grep -qx "sequence increase OK" <<<"$XOUT"; then echo "  T2 printed 'sequence increase OK': inject"
  else INJECT=0; echo "  T2 did not print 'sequence increase OK': the entry says do not inject"; fi
  check "S4 re-run blocks exit 0 and T2 printed 'sequence increase OK'" "$(ok '[ "$T2RC" = 0 ] && [ "$INJECT" = 1 ]')"
  [ "$INJECT" = 1 ] && G "06a(B) 06c 06d 07a 07b" 06a-domain-B.sh 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh
else
  G "${FLOW[*]}" "${FLOW[@]}"
fi
check "S4 re-run guide blocks exit 0" "$XRC"
PK2="$(R "sed -n 's/^# validator public key: //p' $D/set-domain-output.txt | head -n 1")"
echo "  set_domain public key of the re-run: $PK2 (same identity: $([ "$PK2" = "$PK" ] && echo yes || echo NO))"
check "S4 re-run kept the same master key" "$(ok '[ "$PK2" = "$PK" ]')"
waitnode S4; state after-rerun-restart; DOM2="$VI_DOM"; SEQ2="$VI_SEQ"; MK2="$VI_MK"; SPK2="$SI_PK"
manifestlog S4

step "S5 second same-volume restart (docker compose restart)"
x "R 'cd $D && docker compose restart 2>&1 | tail -2'"
VOLS2="$(vols)"; echo "  named volumes after the restart: $VOLS2"
check "S5 restart used the same two named volumes" "$(ok '[ -n "$VOLS" ] && [ "$(wc -w <<<"$VOLS")" = 2 ] && [ "$VOLS2" = "$VOLS" ]')"
waitnode S5; state after-second-restart; DOM3="$VI_DOM"; SEQ3="$VI_SEQ"; MK3="$VI_MK"; SPK3="$SI_PK"
manifestlog S5

if [ "$HAST" = 1 ]; then
  step "S6 control: the entry's check refuses a re-run from an older key file, then recovers as the entry says"
  x "R 'cd $D && mv validator-keys.domain.json control-aside.domain.json && ls validator-keys*.json'"
  G "06a(B) ${TB[*]} (older key file only)" 06a-domain-B.sh "${TB[@]}"
  C1RC="$XRC"; C1OUT="$XOUT"
  check "S6 T2 refused the older key file (exit != 0, no OK line)" "$(ok '[ "$C1RC" != 0 ] && ! grep -qx "sequence increase OK" <<<"$C1OUT"')" "exit $C1RC"
  state control-refused
  check "S6 node seq unchanged (nothing injected)" "$(ok '[ "$VI_SEQ" = "$SEQ3" ]')"
  TRIES=0; C2=1; CT=0
  while [ "$TRIES" -lt 4 ]; do
    TRIES=$((TRIES + 1)); G "06a(B) ${TB[*]} (again, try $TRIES)" 06a-domain-B.sh "${TB[@]}"
    grep -q "^Update rippled.cfg file with these values" <<<"$XOUT" && CT=$((CT + 1))
    if [ "$XRC" = 0 ] && grep -qx "sequence increase OK" <<<"$XOUT"; then C2=0; break; fi
  done
  check "S6 repeating the two blocks reached 'sequence increase OK' without injecting" "$C2" "$TRIES more run(s)"
  check "S6 the repeats used create_token (key file already held domain B)" "$(ok '[ "$CT" -ge 1 ]')" "$CT run(s)"
  state control-recovered
  check "S6 node seq still unchanged" "$(ok '[ "$VI_SEQ" = "$SEQ3" ]')"
fi

step "S7 verdict"
WHY=()
[ "$DOM2" = "$DOM_B" ] || WHY+=("after-rerun-restart domain=$DOM2 (want $DOM_B)")
[[ "$SEQ2" =~ ^[0-9]+$ ]] && [ "$SEQ2" -gt "$SEQ1" ] || WHY+=("after-rerun-restart seq=$SEQ2 (want > $SEQ1)")
[ "$MK2" = "$PK" ] || WHY+=("after-rerun-restart master_key=$MK2")
[ "$SPK2" = "$PK" ] || WHY+=("after-rerun-restart pubkey_validator=$SPK2")
[ "$DOM3" = "$DOM_B" ] || WHY+=("after-second-restart domain=$DOM3 (want $DOM_B)")
[[ "$SEQ3" =~ ^[0-9]+$ ]] && [ "$SEQ3" -gt "$SEQ1" ] || WHY+=("after-second-restart seq=$SEQ3 (want > $SEQ1)")
[ "$MK3" = "$PK" ] || WHY+=("after-second-restart master_key=$MK3")
[ "$SPK3" = "$PK" ] || WHY+=("after-second-restart pubkey_validator=$SPK3")
echo "first setup seq=$SEQ1 domain=$DOM_A; after re-run: seq=$SEQ2 domain=$DOM2; after second restart: seq=$SEQ3 domain=$DOM3"
if [ "${#WHY[@]}" = 0 ]; then VERDICT=pass; echo "RERUN PASS: the node runs the new manifest (domain $DOM_B, higher seq, master key) after both restarts"
else VERDICT=fail; echo "RERUN FAIL: $(IFS=';'; echo "${WHY[*]}")"; fi

step "S8 cleanup of the throwaway project"
x "R 'cd $D && docker compose down -v -t 10 2>&1; rm -rf $D; ls -d $D 2>&1'"
PROJ=0
check "S8 sentry containers + volumes = S0" "$(ok '[ "$(inventory)" = "$INV0" ]')"

step "S9 end state"
x "R 'pft-jobwatch collect >/dev/null 2>&1; echo jobwatch collect \$?; pft-schedaudit collect >/dev/null 2>&1; echo schedaudit collect \$?; pft-schedaudit audit | tail -1'"
check "S9 sentry schedaudit: 0 unexpected, 0 new, 0 removed" "$(ok 'grep -q "unexpected_findings=0 new=0 removed=0" <<<"$XOUT"')"
V1="$(real validator)"; S1="$(real sentry)"; echo "$V1"; echo "$S1"
check "S9 validator postfiatd: same ID + StartedAt, full or proposing" "$(ok '[ "${V1% *}" = "${V0% *}" ] && [[ "$V1" =~ (full|proposing)$ ]]')"
check "S9 sentry postfiatd-sentry: same ID + StartedAt, full" "$(ok '[ "${S1% *}" = "${S0% *}" ] && [[ "$S1" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S9 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S9 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "S9 pft-maint target back to its pre-run state" "$(ok '[ "$ORIG_SHA" = "$NOW_SHA" ]')"
unsilence
x "sleep 5; curl -s -m 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .title'"
check "S9 throwaway topic got the [MAINT] start and end messages" "$(ok '[ "$(grep -c "^\[MAINT\]" <<<"$XOUT")" = 2 ]')"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s -m 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator topic #$i: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "S9 operator topics received nothing during the run" "$(ok '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
echo
echo "domain-test done $(ts): harness checks failed: $FAILS; RERUN ${VERDICT^^} (expected ${EXPECT^^})"
if [ "$FAILS" = 0 ] && [ "$VERDICT" = "$EXPECT" ]; then echo "RESULT: PASS (harness clean, re-run verdict as expected)"; exit 0; fi
echo "RESULT: FAIL"; exit 1
