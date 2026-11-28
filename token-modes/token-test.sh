#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # ok() evals its single-quoted test at call time, so the variables it reads look unused
# token-test: run sections 5-7 of a validator guide copy (fresh keys, set_domain, token injection) in a THROWAWAY
# compose project on the SENTRY and fail on any token-bearing file that is not mode 600
# (task_6d3b1e0ff8d46d0acfff398e4d86d0d4).
#   EXPECT=pass|fail bash token-modes/token-test.sh GUIDE 2>&1 | tee LOG   (validator, agent user; reaches the sentry
#   with `ssh relay`; GUIDE = one copy of content/validator-setup.md, e.g. from `git show REF:content/...`)
# EXPECT is the mode verdict this guide copy should get (fail for the published main, pass for the fix). Exit 0 only
# if every harness CHECK is ok AND the mode verdict equals EXPECT; the last line says which.
# Never touches the validator's postfiatd or the sentry's postfiatd-sentry: the throwaway project lives in
# /var/tmp/pfttok-<random> on the sentry, uses the image postfiatd-sentry already runs (no pull), its container is
# test-pfttok-<random> (host tools pick a container named exactly postfiatd, so that name stays free), network_mode
# none, user "0:0" and the guide compose file's three mounts as project volumes (removed with down -v).
# The guide blocks run in one sentry shell as one paste session, with exactly these edits, printed as a diff:
# `docker exec postfiatd ` -> `docker exec test-pfttok-<r> ` and ` postfiatd:/` -> ` test-pfttok-<r>:/` (docker cp).
# The shell starts with `umask 022` (Ubuntu's default) and POSTFIATD_DIR set to the project dir.
#  S0 preflight  both live containers: ID + StartedAt + state; integrity PASS both; no test-pfttok container,
#                volume or dir; no sentry alert above info; schedaudit clean; next sentry pft-integrity run >= 25 min
#                away (a throwaway of the node image must not be up while it runs); operator topics found
#  S1 quiet      Alertmanager silence host="sentry"; pft-maint window with [MAINT] to a throwaway topic
#  S2 project    compose project up, server_info answers before any key exists
#  S3 guide      blocks 05, 06a-06d, 07a, 07b (+ 07c verifier if the copy has it)
#  S4 modes      every file the sections write, host + container: mode, owner, token-bearing yes/no (grep -c only;
#                no token or key byte is printed; token lines in set_domain output are replaced by a marker)
#  S5 startup    server_info answers with pubkey_validator = the set_domain public key (the 600 config was read);
#                container user from inspect; config readable for that user, not readable for uid 65534
#  S6 removal    block 07d (if present): "config copies removed", both copies gone
#  S7 rerun      (copies with 07c only) the host token files and both config copies set to 644 as an older guide
#                left them, then sections 5-7 again with a new identity (a rerun of 6-7 alone re-signs from the
#                original validator-keys.json and reuses its token sequence, which is outside this test); modes,
#                startup with the new public key, removal again
#  S8 verdict    MODES PASS when every token-bearing file seen in S4/S7 is 600, else MODES FAIL with the list
#  S9 cleanup    compose down -v, dir removed; containers + volumes on the sentry = S0
#  S10 end       live containers same ID + StartedAt and state; integrity PASS both; schedaudit clean; window ended,
#                pft-maint target restored; silence expired once no new sentry alert is pending or firing, then 3 min
#                without one; throwaway got the 2 [MAINT]; every operator topic 0 messages
# Env: RELAY (relay)  SIL_MIN (40)  TASK (task_6d3b1e0f)  EXPECT (pass)
set -uo pipefail
RELAY="${RELAY:-relay}"; SIL_MIN="${SIL_MIN:-40}"; TASK="${TASK:-task_6d3b1e0f}"; EXPECT="${EXPECT:-pass}"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090
GUIDE="${1:-}"
[ -f "$GUIDE" ] || { echo "usage: EXPECT=pass|fail bash $0 GUIDE" >&2; exit 2; }
case "$EXPECT" in pass | fail) ;; *) echo "EXPECT must be pass or fail" >&2; exit 2 ;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
ME="$(id -un)"; HN="$(hostname)"
SN="$(ssh -o LogLevel=ERROR -o BatchMode=yes "$RELAY" hostname </dev/null)"
RID="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
D="/var/tmp/pfttok-$RID"; CN="test-pfttok-$RID"; PJ="pfttok-$RID"
TT="pft-drill-tokmodes-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
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
sinfo() { R "docker exec $CN curl -s -m 5 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" 2>/dev/null; }

NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-tokmodes
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

# MODES: one line per file: "MODE <where> <path> <mode> <owner:group> token=<yes|no|key>"
TOKFAIL=()
modes() { # $1 = label
  local out where path mode tok
  out="$(R "cd $D && for f in validator-keys.json validator-keys.domain.json validator-token.block set-domain-output.txt postfiatd.cfg postfiatd.cfg.new; do
      if [ -e \$f ]; then case \$f in validator-keys*) t=key ;; *) if grep -q '^\[validator_token\]' \$f; then t=yes; else t=no; fi ;; esac
        echo \"MODE host \$f \$(stat -c '%a %U:%G' \$f) token=\$t\"; else echo \"MODE host \$f absent\"; fi
    done
    c=/etc/postfiatd/postfiatd.cfg
    if docker exec $CN grep -q '^\[validator_token\]' \$c; then t=yes; else t=no; fi
    echo \"MODE container \$c \$(docker exec $CN stat -c '%a %U:%G' \$c) token=\$t\"
    if docker exec $CN test -e /root/.ripple; then echo \"MODE container /root/.ripple present\"; else echo 'MODE container /root/.ripple absent'; fi")"
  printf '%s\n' "$out" | sed "s/^/  [$1] /"
  while read -r _ where path mode _ tok; do
    case "$tok" in token=yes | token=key) [ "$mode" = 600 ] || TOKFAIL+=("$1:$where:$path:$mode") ;; esac
  done <<<"$out"
  MOUT="$out"
}
startup() { # $1 = label: wait for server_info with pubkey_validator = PK
  local j="" s="" k="" i
  for i in $(seq 1 40); do
    j="$(sinfo)"; s="$(jq -r '.result.info.server_state // empty' <<<"$j" 2>/dev/null)"
    k="$(jq -r '.result.info.pubkey_validator // empty' <<<"$j" 2>/dev/null)"
    [ -n "$k" ] && [ "$k" = "$PK" ] && break; sleep 3
  done
  echo "  [$1] server_info after ${i} poll(s): server_state=${s:-none} build_version=$(jq -r '.result.info.build_version // "none"' <<<"$j" 2>/dev/null) pubkey_validator=${k:-none}"
  check "$1 throwaway node started and server_info answers with pubkey_validator = set_domain public key" "$(ok '[ -n "$s" ] && [ "$k" = "$PK" ]')"
}

REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo none)"
echo "token-modes token-test - $(ts) - repo HEAD $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo none) (clean: $([ -z "$(git -C "$REPO" status --short 2>/dev/null)" ] && echo yes || echo NO)) - EXPECT=$EXPECT"
echo "sha256: token-test.sh $(sha256sum "$0" | cut -c1-64)"
echo "        extract_token.py $(sha256sum "$HERE/extract_token.py" | cut -c1-64)"
echo "        guide $(sha256sum "$GUIDE" | cut -c1-64)"
echo "sentry: $(R 'lsb_release -ds; docker --version; docker compose version' | paste -sd' ' -)"
echo "throwaway project: $D (project $PJ, container $CN, network none)"

step "extract sections 5-7"
x "python3 -I '$HERE/extract_token.py' '$X' '$GUIDE'"; check "extract sections 5-7" "$XRC"
[ "$XRC" = 0 ] || exit 1
mapfile -t BL < "$X/blocks.txt"; echo "blocks: ${BL[*]}"
HASV=0; [ -f "$X/07c-verify.sh" ] && HASV=1; HASR=0; [ -f "$X/07d-remove.sh" ] && HASR=1
for f in "${BL[@]}"; do sed "s/docker exec postfiatd /docker exec $CN /g; s# postfiatd:/# $CN:/#g" "$X/$f" > "$B/$f"; done
echo "container-name edit (diff guide -> run):"
for f in "${BL[@]}"; do diff "$X/$f" "$B/$f" >/dev/null && continue; echo "  $f:"; diff "$X/$f" "$B/$f" | sed 's/^/    /'; done
x "cd '$B' && grep -c postfiatd ${BL[*]} | paste -sd' ' -; grep -h -o 'docker [a-z]* [^ ]*postfiatd[^ ]*' ${BL[*]} | sort -u"
check "no block still names the container postfiatd (only paths and file names)" "$(ok '! grep -qE "docker (exec|cp) ([^ ]* )?postfiatd( |:)" "$B"/*.sh')"
x "cd '$B' && shellcheck --version | sed -n 's/^version: //p' && shellcheck -s bash -e SC2164 ${BL[*]}"
echo "  (shellcheck of the edited run copies; SC2164 = the guide's bare cd \"\$POSTFIATD_DIR\" lines)"

step "S0 preflight"
V0="$(real validator)"; S0="$(real sentry)"; echo "$V0"; echo "$S0"
check "S0 validator postfiatd full or proposing" "$(ok '[[ "$V0" =~ (full|proposing)$ ]]')"
check "S0 sentry postfiatd-sentry full" "$(ok '[[ "$S0" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S0 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S0 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'docker ps -a --format {{.Names}} | grep -cE \"^(postfiatd|test-pfttok-.*)\$\"; docker volume ls -q | grep -c pfttok; ls -d /var/tmp/pfttok-* 2>/dev/null | wc -l'"
check "S0 sentry has no postfiatd or test-pfttok container, no pfttok volume or dir" "$(ok '[ "$(paste -sd, <<<"$XOUT")" = 0,0,0 ]')"
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
body="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK token-modes throwaway node on the sentry" \
  '{matchers: [{name: "host", value: "sentry", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "pft-agent", comment: $c}')"
SIL="$(curl -s -m 10 -XPOST -H 'Content-Type: application/json' -d "$body" "$AM/api/v2/silences" | jq -r '.silenceID // empty')"
echo "silence ${SIL:0:8} host=sentry until $ends"; check "S1 silence created" "$(ok '[ -n "$SIL" ]')"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1; check "S1 throwaway pft-maint target installed" "$XRC"
if [ "$SWAPPED" != 1 ] || [ -z "$SIL" ]; then echo "RESULT: stopping before any change"; exit 1; fi
x "sudo -n pft-maint start --ttl 40m --reason '$TASK token-modes throwaway node on the sentry'"
[ "$XRC" = 0 ] && MAINT=1; check "S1 pft-maint window open" "$XRC"
for _ in $(seq 1 12); do R 'pft-maint active' >/dev/null 2>&1 && break; sleep 10; done
x "R 'pft-maint active && echo sentry window active'"; check "S1 sentry has the window" "$XRC"
[ "$FAILS" = 0 ] || { echo "RESULT: quiet setup failed ($FAILS)"; exit 1; }

step "S2 throwaway compose project (the guide compose file's mounts and user, no ports, network none)"
PROJ=1
COMPOSE="$(printf '%s\n' 'services:' '  postfiatd:' "    image: $IMG" "    container_name: $CN" '    network_mode: none' \
  '    volumes:' '      - postfiatd-config:/etc/postfiatd' '      - postfiatd-data:/var/lib/postfiatd/db' \
  '      - ./logs:/var/log/postfiatd' '    user: "0:0"' '    restart: "no"' '    labels:' '      org.postfiat.test: token-modes' \
  'volumes:' '  postfiatd-config:' '  postfiatd-data:')"
x "printf '%s\n' \"\$COMPOSE\" | RS 'mkdir -m 755 $D && mkdir $D/logs && cat > $D/docker-compose.yml && cat $D/docker-compose.yml'"
x "R 'cd $D && docker compose up -d 2>&1 && docker inspect -f \"{{.Name}} {{.Config.User}} {{.HostConfig.NetworkMode}} {{.State.Status}}\" $CN && docker inspect -f \"{{range .Mounts}}{{.Destination}}={{.Type}}:{{.Name}} {{end}}\" $CN'"
check "S2 throwaway container running, user 0:0, network none" "$(ok 'grep -q "^/$CN 0:0 none running$" <<<"$XOUT"')"
for _ in $(seq 1 30); do [ -n "$(sinfo | jq -r '.result.info.server_state // empty' 2>/dev/null)" ] && break; sleep 2; done
J="$(sinfo)"; echo "  server_info before keys: server_state=$(jq -r '.result.info.server_state // "none"' <<<"$J" 2>/dev/null) pubkey_validator=$(jq -r '.result.info.pubkey_validator // "none"' <<<"$J" 2>/dev/null)"
check "S2 server_info answers before any key exists" "$(ok '[ -n "$(jq -r ".result.info.server_state // empty" <<<"$J" 2>/dev/null)" ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: project setup failed ($FAILS)"; exit 1; }

step "S3 guide sections 5-7 (one paste session)"
RUN1=(05-keys.sh 06a-domain.sh 06b-setdomain.sh 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh)
[ "$HASV" = 1 ] && RUN1+=(07c-verify.sh)
G "${RUN1[*]}" "${RUN1[@]}"
check "S3 guide blocks exit 0" "$XRC"
PK="$(R "sed -n 's/^# validator public key: //p' $D/set-domain-output.txt | head -n 1")"
echo "  set_domain public key: $PK"
check "S3 set_domain produced a public key" "$(ok '[[ "$PK" =~ ^n[1-9A-HJ-NP-Za-km-z]{40,60}$ ]]')"
[ "$HASV" = 1 ] && check "S3 guide verifier printed 'token file modes OK'" "$(ok 'grep -qx "token file modes OK" <<<"$XOUT"')"

step "S4 modes after sections 5-7"
modes first

step "S5 startup with the injected config"
startup S5
x "R 'docker inspect -f \"config user {{.Config.User}}\" $CN; docker top $CN -o user,pid,comm | sed 1d | head -3'"
x "R 'docker exec -u 0:0 $CN test -r /etc/postfiatd/postfiatd.cfg && echo \"readable for 0:0 (the node user)\"; docker exec -u 65534:65534 $CN test -r /etc/postfiatd/postfiatd.cfg && echo \"readable for 65534\" || echo \"not readable for 65534\"'"
check "S5 config readable for the container user 0:0" "$(ok 'grep -qx "readable for 0:0 (the node user)" <<<"$XOUT"')"
R65="$(grep -o '^not readable for 65534$\|^readable for 65534$' <<<"$XOUT")"; echo "  uid 65534: $R65"

if [ "$HASR" = 1 ]; then
  step "S6 removal of the config copies (blocks 06c for PUBLIC_KEY + 07d)"
  G "06c-proof.sh 07d-remove.sh" 06c-proof.sh 07d-remove.sh
  check "S6 'config copies removed' printed, both copies gone" "$(ok 'grep -qx "config copies removed" <<<"$XOUT" && [ "$(R "ls $D/postfiatd.cfg $D/postfiatd.cfg.new 2>/dev/null | wc -l")" = 0 ]')"
fi

if [ "$HASV" = 1 ]; then
  step "S7 rerun of sections 5-7 (new identity) over files an older guide left at 644"
  OLDPK="$PK"; LEFT="validator-keys.json validator-keys.domain.json validator-token.block set-domain-output.txt postfiatd.cfg postfiatd.cfg.new"
  x "R 'cd $D && touch postfiatd.cfg postfiatd.cfg.new && chmod 644 $LEFT && stat -c \"%a %n\" $LEFT'"
  check "S7 six leftover host files at 644" "$(ok '[ "$(grep -c "^644 " <<<"$XOUT")" = 6 ]')"
  RUN2=(05-keys.sh 06a-domain.sh 06b-setdomain.sh 06c-proof.sh 06d-token.sh 07a-inject.sh 07b-cleanup.sh 07c-verify.sh)
  G "${RUN2[*]}" "${RUN2[@]}"
  check "S7 guide blocks exit 0" "$XRC"
  PK="$(R "sed -n 's/^# validator public key: //p' $D/set-domain-output.txt | head -n 1")"
  echo "  set_domain public key (new identity): $PK"
  check "S7 new public key, different from S3" "$(ok '[[ "$PK" =~ ^n[1-9A-HJ-NP-Za-km-z]{40,60}$ ]] && [ "$PK" != "$OLDPK" ]')"
  check "S7 guide verifier printed 'token file modes OK'" "$(ok 'grep -qx "token file modes OK" <<<"$XOUT"')"
  modes rerun
  check "S7 rerun: host postfiatd.cfg now carries the token (copied from the injected container config)" "$(ok 'grep -q "^MODE host postfiatd.cfg [0-9]* [^ ]* token=yes$" <<<"$MOUT"')"
  startup S7
  if [ "$HASR" = 1 ]; then
    G "06c-proof.sh 07d-remove.sh" 06c-proof.sh 07d-remove.sh
    check "S7 'config copies removed' printed, both copies gone" "$(ok 'grep -qx "config copies removed" <<<"$XOUT" && [ "$(R "ls $D/postfiatd.cfg $D/postfiatd.cfg.new 2>/dev/null | wc -l")" = 0 ]')"
  fi
fi

step "S8 verdict"
if [ "${#TOKFAIL[@]}" = 0 ]; then VERDICT=pass; echo "MODES PASS: every token-bearing file is 600"
else VERDICT=fail; echo "MODES FAIL: token-bearing files not 600: ${TOKFAIL[*]}"; fi
echo "  config readable for uid 65534 in the container: $R65"

step "S9 cleanup of the throwaway project"
x "R 'cd $D && docker compose down -v -t 10 2>&1; rm -rf $D; ls -d $D 2>&1'"
PROJ=0
check "S9 sentry containers + volumes = S0" "$(ok '[ "$(inventory)" = "$INV0" ]')"

step "S10 end state"
x "R 'pft-jobwatch collect >/dev/null 2>&1; echo jobwatch collect \$?; pft-schedaudit collect >/dev/null 2>&1; echo schedaudit collect \$?; pft-schedaudit audit | tail -1'"
check "S10 sentry schedaudit: 0 unexpected, 0 new, 0 removed" "$(ok 'grep -q "unexpected_findings=0 new=0 removed=0" <<<"$XOUT"')"
V1="$(real validator)"; S1="$(real sentry)"; echo "$V1"; echo "$S1"
check "S10 validator postfiatd: same ID + StartedAt, full or proposing" "$(ok '[ "${V1% *}" = "${V0% *}" ] && [[ "$V1" =~ (full|proposing)$ ]]')"
check "S10 sentry postfiatd-sentry: same ID + StartedAt, full" "$(ok '[ "${S1% *}" = "${S0% *}" ] && [[ "$S1" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S10 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S10 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "S10 pft-maint target back to its pre-run state" "$(ok '[ "$ORIG_SHA" = "$NOW_SHA" ]')"
unsilence
x "sleep 5; curl -s -m 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .title'"
check "S10 throwaway topic got the [MAINT] start and end messages" "$(ok '[ "$(grep -c "^\[MAINT\]" <<<"$XOUT")" = 2 ]')"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s -m 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator topic #$i: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "S10 operator topics received nothing during the run" "$(ok '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
echo
echo "token-test done $(ts): harness checks failed: $FAILS; MODES ${VERDICT^^} (expected ${EXPECT^^})"
if [ "$FAILS" = 0 ] && [ "$VERDICT" = "$EXPECT" ]; then echo "RESULT: PASS (harness clean, mode verdict as expected)"; exit 0; fi
echo "RESULT: FAIL"; exit 1
