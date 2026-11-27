#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2034  # ok() evals its single-quoted test at call time, so the variables it reads look unused
# sentry-proof: live test of the validator guide's section 10 upgrade record, digest-pinned rollback and return to the
# rolling tag, in a THROWAWAY compose project on the SENTRY (task_8ab4d4e6ec984527f1895c675fc84c59).
#   bash upstream-rollback/sentry-proof.sh EXTRACT_DIR 2>&1 | tee LOG   (validator, agent user; reaches the sentry
#   with `ssh relay`; EXTRACT_DIR = extract_rollback.py output of the PR-branch guide)
# Never touches the validator's postfiatd or the sentry's postfiatd-sentry: the throwaway project lives in
# /var/tmp/pftrb-<random> on the sentry, its container is named postfiatd (the name the guide's blocks use, free on the
# sentry), runs `sleep infinity` with network_mode none, and uses three LOCAL images that share the real image's
# layers: OLD = the sentry's real image under a local rolling tag (it carries the real RepoDigest), NEW and FIXED =
# `docker commit` copies with a label (their RepoDigest is the local name; there is no registry copy).
# The guide blocks run unchanged through `ssh relay bash -s`, except: (a) every rolling-tag `docker compose pull`
# becomes `docker tag <NEW|FIXED> <local rolling tag>` (the release is simulated; there is no registry for a local
# tag), (b) the rollback's REC= placeholder line is set to the record under test. Both edits are printed as diffs.
# The pinned `docker compose pull` (override present) is run unchanged against Docker Hub and must be a no-op.
#  S0 preflight     both real containers: ID + StartedAt + state full; integrity PASS both; no postfiatd/pftrb
#                   container, image or dir on the sentry; image inventory; operator topics found
#  S1 quiet         Alertmanager silence host="sentry"; pft-maint window with [MAINT] to a throwaway topic; sentry
#                   pft-integrity.timer paused (transient re-arm failsafe)
#  S2 project       throwaway compose project on OLD; images NEW and FIXED committed
#  S3 record        guide blocks 01 + 02: record file = OLD image ID + real RepoDigest, "recorded" line printed
#  S4 upgrade       guide blocks 01 + 03 (pull -> tag NEW; 03 has no cd of its own): container recreated on NEW
#  S5 controls      C1 record with the container renamed away (no postfiatd; on this containerd image store
#                   even committed images carry a RepoDigest): no "recorded" line; C2 rollback with that record: "no
#                   repo_digest", nothing changed; C3 existing override: "exists: not changed", override bytes and
#                   container unchanged, last two lines differ
#  S6 rollback      guide block 06 with the S3 record: config shows the digest, container recreated on OLD, the
#                   last two lines equal, override = exactly the three published lines
#  S7 pinned pull   guide `docker compose pull` with the override: exit 0, image inventory unchanged, then
#                   `docker compose up -d`: same container ID and image
#  S8 return        guide blocks 01 + 02 (record the pinned image) + 07 (pull -> tag FIXED): override gone, config
#                   shows the -light-latest tag, container on FIXED
#  S9 shellcheck    every extracted block: clean with -e SC2164; without it the only findings are SC2164 on the
#                   `cd "$POSTFIATD_DIR"` lines
#  S10 cleanup      compose down, NEW/FIXED and the local tag removed, dir removed; image inventory = S0
#  S11 end          both real containers: same ID + StartedAt, full; integrity timer re-armed; sentry schedaudit clean;
#                   integrity PASS both; window ended, real pft-maint target restored; silence expired once no new
#                   sentry alert is active, then 3 minutes without one; throwaway got the 2 [MAINT]; operator topics 0
# The integrity failsafe is a sleeping transient SERVICE, not a timer: pft-schedaudit reports a transient timer as an
# unexpected scheduled entry (dry run, 2026-11-27).
# Every command is printed with its output and exit code; CHECK lines carry the verdict. Exit 0 = every CHECK ok.
# Env: RELAY (relay)  SIL_MIN (45)  TASK (task_8ab4d4e6)
set -uo pipefail
RELAY="${RELAY:-relay}"; SIL_MIN="${SIL_MIN:-45}"; TASK="${TASK:-task_8ab4d4e6}"
AM=http://127.0.0.1:9093
X="${1:-}"
BLOCKS=(01-dircheck.sh 02-record.sh 03-upgrade.sh 04-workdir.sh 05-verify.sh 06-rollback.sh 07-return.sh)
for f in "${BLOCKS[@]}"; do [ -f "$X/$f" ] || { echo "usage: bash $0 EXTRACT_DIR (missing $X/$f)" >&2; exit 2; }; done
X="$(cd "$X" && pwd)"
ME="$(id -un)"; HN="$(hostname)"
SN="$(ssh -o LogLevel=ERROR -o BatchMode=yes "$RELAY" hostname </dev/null)"
RID="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
D="/var/tmp/pftrb-$RID"; TAG="localhost/pftrb/postfiatd:testnet-light-latest"; NEWT="localhost/pftrb/postfiatd:new-$RID"
FIXT="localhost/pftrb/postfiatd:fixed-$RID"; REARM="pftrb-integrity-rearm-$RID"
TT="pft-drill-rollback-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#\b$SN\b#<sentry>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
ts() { date -u +%FT%TZ; }
R() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*" </dev/null; }
RS() { ssh -o LogLevel=ERROR -o ConnectTimeout=10 -o BatchMode=yes "$RELAY" "export TZ=UTC; $*"; } # with stdin
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
ok() { if eval "$1"; then echo 0; else echo 1; fi; }
step() { echo; echo "== $(ts) $*"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
# G LABEL FILE...: run guide block files (already edited copies if any) in ONE sentry shell, as one paste session
G() {
  local label="$1"; shift
  echo "\$ ssh relay bash -s   <<< export POSTFIATD_DIR=$D + $label"
  for f in "$@"; do echo "  --- $(basename "$f") sha256 $(sha256sum "$f" | cut -c1-16)"; sed 's/^/  | /' "$f"; done
  XOUT="$( { echo "export POSTFIATD_DIR=$D"; cat "$@"; } | RS bash -s 2>&1)"; XRC=$?
  printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"
}
# E NAME SED-EXPR: edited copy of a block in $W, with the diff printed
W="$(mktemp -d)"; OPS="$(mktemp)"; chmod 600 "$OPS"
E() { sed "$2" "$X/$1" > "$W/$1"; echo "  edit of $1 for this test (diff guide -> run):"; diff "$X/$1" "$W/$1" | sed 's/^/    /'; }
cid() { R "docker inspect -f '{{.Id}}' postfiatd 2>/dev/null"; }
cimg() { R "docker inspect -f '{{.Image}}' postfiatd 2>/dev/null"; }
real() { # name ID StartedAt state for one real container
  if [ "$1" = validator ]; then
    echo "validator postfiatd $(sudo -n docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd) $(sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 | jq -r .result.info.server_state)"
  else
    echo "sentry postfiatd-sentry $(R "docker inspect -f '{{.Id}} {{.State.StartedAt}}' postfiatd-sentry") $(R "docker exec postfiatd-sentry curl -s -m 10 -d '{\"method\":\"server_info\"}' http://127.0.0.1:5005" | jq -r .result.info.server_state)"
  fi
}
inventory() { R "docker images --no-trunc --format '{{.ID}} {{.Repository}}:{{.Tag}}' | sort; docker ps -a --format '{{.Names}}' | sort"; }

NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-rollback
SWAPPED=0; MAINT=0; HAD=0; PAUSED=0; SIL=""; PROJ=0
since="$(date -u +%s)"
restore() {
  if [ "$PROJ" = 1 ]; then
    echo "\$ (restore) compose down + remove throwaway images and dir on the sentry"
    R "docker rm -f pftrb-mk-new-$RID pftrb-mk-fixed-$RID pftrb-hold-$RID 2>/dev/null; cd $D 2>/dev/null && docker compose down -t 2 2>&1 | tail -2; docker rmi $TAG $NEWT $FIXT 2>&1 | grep -c Untagged; rm -rf $D" | sed 's/^/  /'
    PROJ=0
  fi
  if [ "$PAUSED" = 1 ]; then
    echo "\$ (restore) sentry: systemctl start pft-integrity.timer; stop $REARM.service"
    R "systemctl start pft-integrity.timer; systemctl stop $REARM.service 2>/dev/null; systemctl is-active pft-integrity.timer" | sed 's/^/  /'
    PAUSED=0
  fi
  if [ "$MAINT" = 1 ]; then echo "\$ sudo -n pft-maint end"; sudo -n pft-maint end 2>&1 | red | sed 's/^/  /'; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    if [ "$HAD" = 1 ]; then echo "\$ sudo -n mv -f \$BK \$NE   (restore the real target)"; sudo -n mv -f "$BK" "$NE"
    else echo "\$ sudo -n rm -f \$NE   (no ntfy.env before: pft-maint falls back to the real monitor target again)"; sudo -n rm -f "$NE"; fi
    SWAPPED=0
  fi
}
sentry_alerts() { curl -s -m 10 "$AM/api/v2/alerts?active=true" | jq -r '[.[] | select(.labels.host == "sentry") | .labels.alertname] | unique | .[]'; }
PRE=""
unsilence() { # expire the run's silence once nothing for the sentry is active (else it runs out on its own)
  [ -n "$SIL" ] || return 0
  local p=""
  for _ in $(seq 1 30); do
    p="$(sentry_alerts | grep -vxF -e "${PRE:-@none@}" | paste -sd, -)"
    [ -z "$p" ] && break; echo "$(ts) sentry alerts active that were not active at S0: $p (wait 20 s)"; sleep 20
  done
  check "no sentry alert active before the silence ends, other than those already active at S0" "$(ok '[ -z "$p" ]')" "${p:-none}"
  if [ -z "$p" ]; then x "curl -s -m 10 -XDELETE '$AM/api/v2/silence/$SIL' -o /dev/null -w 'expire silence http %{http_code}'"
  else echo "silence ${SIL:0:8} kept until $ends (something active)"; fi
  SIL=""
  local late=""
  for _ in $(seq 1 9); do
    sleep 20; late="$(sentry_alerts | grep -vxF -e "${PRE:-@none@}" | paste -sd, -)"; [ -z "$late" ] || break
  done
  check "no new sentry alert in the 3 minutes after the silence ended" "$(ok '[ -z "$late" ]')" "${late:-none}"
}
trap 'restore; unsilence; rm -rf "$W" "$OPS"' EXIT

REPO="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo none)"
echo "upstream-rollback sentry-proof - $(ts) - repo HEAD $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo none) (clean: $([ -z "$(git -C "$REPO" status --short 2>/dev/null)" ] && echo yes || echo NO))"
echo "sha256: sentry-proof.sh $(sha256sum "$0" | cut -c1-64)"
for f in "${BLOCKS[@]}" section.txt; do echo "        $f $(sha256sum "$X/$f" | cut -c1-64)"; done
echo "sentry: $(R 'lsb_release -ds; docker --version; docker compose version' | paste -sd' ' -)"
echo "throwaway project: $D (container postfiatd, network none), local tags $TAG $NEWT $FIXT"

step "S0 preflight"
V0="$(real validator)"; S0="$(real sentry)"; echo "$V0"; echo "$S0"
check "S0 validator postfiatd full or proposing" "$(ok '[[ "$V0" =~ (full|proposing)$ ]]')"
check "S0 sentry postfiatd-sentry full" "$(ok '[[ "$S0" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S0 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S0 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'docker ps -a --format {{.Names}} | grep -cx postfiatd; docker images --format {{.Repository}} | grep -c pftrb; ls -d /var/tmp/pftrb-* 2>/dev/null | wc -l'"
check "S0 sentry has no postfiatd container, pftrb image or pftrb dir" "$(ok '[ "$(paste -sd, <<<"$XOUT")" = 0,0,0 ]')"
x "curl -s -m 10 '$AM/api/v2/alerts?active=true' | jq -r '[.[] | select(.labels.host == \"sentry\" and .labels.severity != \"info\") | .labels.alertname] | length'"
check "S0 no sentry alert above severity info active" "$(ok '[ "$(tail -1 <<<"$XOUT")" = 0 ]')"
x "R 'pft-schedaudit audit | tail -1'"; check "S0 sentry schedaudit: 0 unexpected" "$(ok 'grep -q "unexpected_findings=0 new=0 removed=0" <<<"$XOUT"')"
PRE="$(sentry_alerts)"; echo "sentry alerts already active before the run (left alone): $(paste -sd, - <<<"${PRE:-none}")"
INV0="$(inventory)"; echo "image + container inventory (sentry):"; red <<<"$INV0" | sed 's/^/  /'
OLD="$(R "docker inspect -f '{{.Image}}' postfiatd-sentry")"
ODIG="$(R "docker image inspect -f '{{index .RepoDigests 0}}' $OLD")"
echo "OLD = image of postfiatd-sentry: $OLD, RepoDigests[0] $ODIG"
check "S0 OLD image has a RepoDigest" "$(ok '[[ "$ODIG" == *@sha256:* ]]')"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env /etc/postfiat-monitor.env; do sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"
check "S0 operator topics found" "$(ok '[ -s "$OPS" ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: preflight failed ($FAILS), nothing changed"; exit 1; }

step "S1 quiet: silence, pft-maint window to a throwaway topic, sentry integrity timer paused"
ends="$(date -u -d "+$SIL_MIN min" +%FT%TZ)"
body="$(jq -nc --arg s "$(ts)" --arg e "$ends" --arg c "$TASK upgrade-rollback throwaway project on the sentry" \
  '{matchers: [{name: "host", value: "sentry", isRegex: false, isEqual: true}], startsAt: $s, endsAt: $e, createdBy: "pft-agent", comment: $c}')"
SIL="$(curl -s -m 10 -XPOST -H 'Content-Type: application/json' -d "$body" "$AM/api/v2/silences" | jq -r '.silenceID // empty')"
echo "silence ${SIL:0:8} host=sentry until $ends"; check "S1 silence created" "$(ok '[ -n "$SIL" ]')"
ORIG_SHA=absent
if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
echo "real $NE present before: $HAD"
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1; check "S1 throwaway pft-maint target installed" "$XRC"
if [ "$SWAPPED" != 1 ] || [ -z "$SIL" ]; then echo "RESULT: stopping before any change"; exit 1; fi
x "sudo -n pft-maint start --ttl 45m --reason '$TASK upgrade-rollback throwaway project on the sentry'"
[ "$XRC" = 0 ] && MAINT=1; check "S1 pft-maint window open" "$XRC"
for _ in $(seq 1 12); do R 'pft-maint active' >/dev/null 2>&1 && break; sleep 10; done
x "R 'pft-maint active && echo sentry window active'"; check "S1 sentry has the window" "$XRC"
x "R 'systemd-run --collect --unit $REARM /bin/sh -c \"sleep 3000; systemctl start pft-integrity.timer\" 2>&1 && systemctl stop pft-integrity.timer && systemctl is-active pft-integrity.timer; systemctl is-active $REARM.service'"
PAUSED=1; check "S1 sentry pft-integrity.timer inactive, re-arm failsafe active" "$(ok '[ "$(paste -sd, <<<"$(tail -2 <<<"$XOUT")")" = inactive,active ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: quiet setup failed ($FAILS)"; exit 1; }

step "S2 throwaway compose project on OLD; NEW and FIXED images committed"
PROJ=1
COMPOSE="$(printf '%s\n' 'services:' '  postfiatd:' "    image: $TAG" '    container_name: postfiatd' '    network_mode: none' \
  '    init: true' '    entrypoint: ["sleep", "infinity"]' '    restart: "no"')"
x "printf '%s\n' \"\$COMPOSE\" | RS 'mkdir -m 700 $D && cat > $D/docker-compose.yml && cat $D/docker-compose.yml'"
x "R 'docker tag $OLD $TAG && for t in new fixed; do c=\$(docker create --name pftrb-mk-\$t-$RID $OLD true) && docker commit --change \"LABEL org.postfiat.rollbacktest=\$t\" \$c localhost/pftrb/postfiatd:\$t-$RID >/dev/null && docker rm -f \$c >/dev/null; done'"
check "S2 images tagged and committed" "$XRC"
NEW="$(R "docker image inspect -f '{{.Id}}' $NEWT")"; FIX="$(R "docker image inspect -f '{{.Id}}' $FIXT")"
echo "NEW $NEW (RepoDigests $(R "docker image inspect -f '{{json .RepoDigests}}' $NEW"))"
echo "FIXED $FIX (RepoDigests $(R "docker image inspect -f '{{json .RepoDigests}}' $FIX"))"
check "S2 OLD, NEW, FIXED are three different image IDs" "$(ok '[ -n "$NEW" ] && [ -n "$FIX" ] && [ "$(printf "%s\n" "$OLD" "$NEW" "$FIX" | sort -u | wc -l)" = 3 ]')"
x "R 'cd $D && docker compose up -d 2>&1 && docker compose config | grep image:'"
C0="$(cid)"; echo "container postfiatd $C0 image $(cimg)"
check "S2 throwaway container runs on OLD" "$(ok '[ "$(cimg)" = "$OLD" ] && [ "$(R "docker inspect -f {{.State.Status}}/{{.HostConfig.NetworkMode}} postfiatd")" = running/none ]')"
[ "$FAILS" = 0 ] || { echo "RESULT: project setup failed ($FAILS)"; exit 1; }

step "S3 record before the upgrade (guide blocks 01 + 02, unchanged)"
G "01-dircheck.sh + 02-record.sh" "$X/01-dircheck.sh" "$X/02-record.sh"
REC1="$(grep -o 'recorded pre-upgrade-[0-9TZ]*\.txt' <<<"$XOUT" | cut -d' ' -f2)"
echo "record file: ${REC1:-none}"; x "R 'cat $D/$REC1'"
check "S3 'recorded' line printed, file name pre-upgrade-<UTC>.txt" "$(ok '[[ "$REC1" =~ ^pre-upgrade-[0-9]{8}T[0-9]{6}Z\.txt$ ]]')"
check "S3 record = OLD image ID + real RepoDigest" "$(ok '[ "$XOUT" = "$(printf "image_id=%s\nrepo_digest=%s" "$OLD" "$ODIG")" ]')"

step "S4 upgrade (guide block 03; the rolling-tag pull becomes a local tag move to NEW)"
E 03-upgrade.sh "s#^docker compose pull\$#docker tag $NEW $TAG#"
G "01-dircheck.sh + 03-upgrade.sh (edited; 03 runs in the node directory 01 changed to)" "$X/01-dircheck.sh" "$W/03-upgrade.sh"
C1="$(cid)"; echo "container postfiatd $C1 image $(cimg)"
check "S4 container recreated on NEW" "$(ok '[ "$(cimg)" = "$NEW" ] && [ "$C1" != "$C0" ]')"
G "04-workdir.sh" "$X/04-workdir.sh"; check "S4 guide block 04 finds the project dir" "$(ok '[ "$XOUT" = "$D" ]')"

step "S5 controls"
sleep 1
x "R 'docker rename postfiatd pftrb-hold-$RID && echo \"containers named postfiatd: \$(docker ps -a --format {{.Names}} | grep -cx postfiatd)\"'"
G "C1: 01 + 02 with no container named postfiatd" "$X/01-dircheck.sh" "$X/02-record.sh"
check "C1 no 'recorded' line when no postfiatd container runs" "$(ok '! grep -q "^recorded " <<<"$XOUT"')"
x "R 'docker rename pftrb-hold-$RID postfiatd && docker inspect -f {{.Id}} postfiatd'"
check "C1 container renamed back, same ID" "$(ok '[ "$(cid)" = "$C1" ]')"
RECB="$(R "cd $D && ls -t pre-upgrade-*.txt | head -1")"; x "R 'cat $D/$RECB'"
check "C1 its record has an empty repo_digest" "$(ok '[ "$RECB" != "$REC1" ] && grep -qx "repo_digest=" <<<"$XOUT"')"
E 06-rollback.sh "s#^REC=pre-upgrade-YYYYMMDDTHHMMSSZ.txt\$#REC=$RECB#"
G "C2: 06 with the incomplete record" "$W/06-rollback.sh"
check "C2 'no repo_digest' printed, no override written, container unchanged" "$(ok 'grep -q "^no repo_digest in $RECB: nothing changed$" <<<"$XOUT" && [ "$(R "test -e $D/docker-compose.override.yml && echo yes || echo no")" = no ] && [ "$(cid)" = "$C1" ]')"
x "printf '%s\n' 'services:' '  postfiatd:' '    labels:' '      operator.note: my own override' | RS 'cat > $D/docker-compose.override.yml && sha256sum $D/docker-compose.override.yml'"
OVS="$(cut -c1-64 <<<"$XOUT")"
E 06-rollback.sh "s#^REC=pre-upgrade-YYYYMMDDTHHMMSSZ.txt\$#REC=$REC1#"
G "C3: 06 with an existing override" "$W/06-rollback.sh"
L2="$(tail -2 <<<"$XOUT" | paste -sd' ' -)"
check "C3 'exists: not changed' printed" "$(ok 'grep -qx "docker-compose.override.yml exists: not changed, add the image line by hand" <<<"$XOUT"')"
check "C3 override bytes unchanged, container unchanged, last two lines differ" "$(ok '[ "$(R "sha256sum $D/docker-compose.override.yml" | cut -c1-64)" = "$OVS" ] && [ "$(cid)" = "$C1" ] && [ "$L2" = "$NEW $OLD" ]')"
x "R 'rm $D/docker-compose.override.yml && cd $D && docker compose config | grep -c operator.note'"
check "C3 control override removed again" "$(ok '[ "$(tail -1 <<<"$XOUT")" = 0 ]')"

step "S6 rollback (guide block 06 with the S3 record)"
G "06-rollback.sh (REC set)" "$W/06-rollback.sh"
L2="$(tail -2 <<<"$XOUT" | paste -sd' ' -)"
C2="$(cid)"; echo "container postfiatd $C2 image $(cimg)"
check "S6 docker compose config shows the recorded digest" "$(ok 'grep -qx "    image: $ODIG" <<<"$XOUT"')"
check "S6 container recreated on OLD; last two lines equal" "$(ok '[ "$(cimg)" = "$OLD" ] && [ "$C2" != "$C1" ] && [ "$L2" = "$OLD $OLD" ]')"
x "R 'cat $D/docker-compose.override.yml'"
check "S6 override = the three published lines with the digest" "$(ok '[ "$XOUT" = "$(printf "services:\n  postfiatd:\n    image: %s" "$ODIG")" ]')"

step "S7 pinned pull is a no-op (guide 'docker compose pull' with the override, unchanged, against Docker Hub)"
INV1="$(inventory)"
x "R 'cd $D && docker compose pull 2>&1'"; check "S7 docker compose pull exit 0" "$XRC"
check "S7 image + container inventory unchanged by the pull" "$(ok '[ "$(inventory)" = "$INV1" ]')"
x "R 'cd $D && docker compose up -d 2>&1'"
check "S7 docker compose up -d keeps the same container on OLD" "$(ok '[ "$(cid)" = "$C2" ] && [ "$(cimg)" = "$OLD" ]')"

step "S8 return to the rolling tag (record first, then guide block 07; the pull becomes a tag move to FIXED)"
sleep 1
G "01 + 02 (record the pinned image)" "$X/01-dircheck.sh" "$X/02-record.sh"
REC2="$(grep -o 'recorded pre-upgrade-[0-9TZ]*\.txt' <<<"$XOUT" | cut -d' ' -f2)"
check "S8 pinned image recorded (OLD, digest)" "$(ok '[ -n "$REC2" ] && [ "$REC2" != "$REC1" ] && grep -qx "image_id=$OLD" <<<"$XOUT" && grep -qx "repo_digest=$ODIG" <<<"$XOUT"')"
E 07-return.sh "s#^docker compose pull\$#docker tag $FIX $TAG#"
G "07-return.sh (edited)" "$W/07-return.sh"
C3="$(cid)"; echo "container postfiatd $C3 image $(cimg)"
check "S8 config shows the -light-latest tag again" "$(ok 'grep -qx "    image: $TAG" <<<"$XOUT"')"
check "S8 override gone; container recreated on FIXED" "$(ok '[ "$(R "test -e $D/docker-compose.override.yml && echo yes || echo no")" = no ] && [ "$(cimg)" = "$FIX" ] && [ "$C3" != "$C2" ]')"

step "S9 shellcheck of every extracted block (shellcheck $(shellcheck --version | sed -n 's/^version: //p'), on the validator)"
x "cd '$X' && shellcheck -s bash -e SC2164 ${BLOCKS[*]}"; check "S9 shellcheck -e SC2164 clean on all ${#BLOCKS[@]} blocks" "$XRC"
x "cd '$X' && shellcheck -s bash -f gcc ${BLOCKS[*]}"
check "S9 without the exclusion: only SC2164, only on cd \"\$POSTFIATD_DIR\" lines (01:1, 06:1, 07:1)" "$(ok '[ "$(grep -c . <<<"$XOUT")" = 3 ] && [ "$(grep -c "^0[167]-[a-z]*\.sh:1:1: warning: .*\[SC2164\]$" <<<"$XOUT")" = 3 ]')"

step "S10 cleanup of the throwaway project"
x "R 'cd $D && docker compose down -t 2 2>&1; docker rmi $TAG $NEWT $FIXT 2>&1; rm -rf $D; ls -d $D 2>&1'"
PROJ=0
check "S10 image + container inventory = S0" "$(ok '[ "$(inventory)" = "$INV0" ]')"
x "R 'docker image inspect -f \"{{json .RepoTags}} {{json .RepoDigests}}\" $OLD'"

step "S11 end state"
x "R 'systemctl start pft-integrity.timer && systemctl stop $REARM.service; systemctl is-active pft-integrity.timer; systemctl is-active $REARM.service'"
PAUSED=0; check "S11 sentry pft-integrity.timer re-armed, failsafe gone" "$(ok '[ "$(paste -sd, <<<"$(tail -2 <<<"$XOUT")")" = active,inactive ]')"
x "R 'pft-jobwatch collect >/dev/null 2>&1; echo jobwatch collect \$?; pft-schedaudit collect >/dev/null 2>&1; echo schedaudit collect \$?; pft-schedaudit audit | tail -1'"
check "S11 sentry schedaudit: 0 unexpected, 0 new, 0 removed" "$(ok 'grep -q "unexpected_findings=0 new=0 removed=0" <<<"$XOUT"')"
V1="$(real validator)"; S1="$(real sentry)"; echo "$V1"; echo "$S1"
check "S11 validator postfiatd: same ID + StartedAt, full or proposing" "$(ok '[ "${V1% *}" = "${V0% *}" ] && [[ "$V1" =~ (full|proposing)$ ]]')"
check "S11 sentry postfiatd-sentry: same ID + StartedAt, full" "$(ok '[ "${S1% *}" = "${S0% *}" ] && [[ "$S1" =~ full$ ]]')"
x "sudo -n pft-integrity verify | tail -1"; check "S11 validator integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
x "R 'pft-integrity verify | tail -1'"; check "S11 sentry integrity PASS" "$(ok 'grep -q "RESULT: PASS" <<<"$XOUT"')"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "S11 pft-maint target back to its pre-run state" "$(ok '[ "$ORIG_SHA" = "$NOW_SHA" ]')"
unsilence
x "sleep 5; curl -s -m 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r 'select(.event == \"message\") | .title'"
check "S11 throwaway topic got the [MAINT] start and end messages" "$(ok '[ "$(grep -c "^\[MAINT\]" <<<"$XOUT")" = 2 ]')"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s -m 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator topic #$i: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "S11 operator topics received nothing during the run" "$(ok '[ "$OPN" = 0 ]')" "$i topic(s), $OPN with messages"
echo; echo "sentry-proof done $(ts): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
