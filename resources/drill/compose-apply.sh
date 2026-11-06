#!/usr/bin/env bash
# compose-apply: recorded apply of resources/docker-compose.resources.yml on the VALIDATOR (operator directive
# 2026-11-06). Since 2026-11-02 postfiatd's CPU weight (cpu_shares 8192) and memory floor (mem_reservation) were
# live-only `docker update` values: pft-seccomp/pft-confine carry them over when they re-create the container, but a
# plain `docker compose up -d` (upgrade, rollout, rebuild, restore) would drop them. This makes them part of the
# compose project: the overlay file goes next to the other overlays and into COMPOSE_FILE in .env, then
# `docker compose up -d` re-creates the container (one planned node restart) inside a pft-maint window.
# Quiet for the operator: pft-maint's [MAINT] start/end go to a throwaway topic (real target restored + compared);
# pft-maint suppresses postfiat-monitor, pft-integrity and the sentry's pft-watchdog; an Alertmanager silence covers
# everything but PFTAlertPipelineWatchdog for the window; every operator topic is read back at the end (must be 0).
#   bash resources/drill/compose-apply.sh 2>&1 | tee LOG    (repo root, agent user; sudo -n)
# Env: RES_FILE (resources/docker-compose.resources.yml) FULL_WAIT (1800 s) WIN (45m) PREFLIGHT_ONLY=1
# shellcheck disable=SC2016  # single-quoted commands are expanded by eval in x()
set -uo pipefail
export TZ=UTC
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
SHA="$(git rev-parse HEAD)"; SHORT="$(git rev-parse --short HEAD)"
AM=http://127.0.0.1:9093; PROM=http://127.0.0.1:9090; D=/opt/postfiatd
RES_FILE="${RES_FILE:-resources/docker-compose.resources.yml}"; FULL_WAIT="${FULL_WAIT:-1800}"; WIN="${WIN:-45m}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-0}"
WANT_CS=8192; WANT_MR=1610612736 # 1536m
ME="$(id -un)"; HN="$(hostname)"
TASK=directive-20261106-resources
TT="pft-drill-res-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
red() { sed -E "s#$HOME#~#g; s#\b$ME\b#<user>#g; s#$HN#<host>#g; s#$RHN#<host>#g; s#\b([0-9]{1,3}\.){3}[0-9]{1,3}\b#<redacted-ip>#g; s#$TT#<throwaway-topic>#g"; }
XRC=0; XOUT=""
x() { echo "\$ $*" | red; XOUT="$(eval "$*" 2>&1)"; XRC=$?; printf '%s\n' "$XOUT" | red | sed 's/^/  /'; echo "  (exit $XRC)"; }
FAILS=0
check() { if [ "$2" = 0 ]; then echo "CHECK ok   $1${3:+ ($3)}"; else echo "CHECK FAIL $1${3:+ ($3)}"; FAILS=$((FAILS + 1)); fi; }
state() { sudo -n docker exec postfiatd curl -s -m 10 -d '{"method":"server_info"}' http://127.0.0.1:5005 2>/dev/null | jq -r '.result.info.server_state // "down"' 2>/dev/null || echo down; }
res() { sudo -n docker inspect postfiatd --format '{{.HostConfig.CpuShares}} {{.HostConfig.MemoryReservation}}' 2>/dev/null; }
NE=/etc/pft-maint/ntfy.env; BK=/etc/pft-maint/ntfy.env.pre-resources
SWAPPED=0; MAINT=0; HAD=0; SIL=""; ENV_BK=""
since="$(date -u +%s)"
OPS="$(mktemp)"; chmod 600 "$OPS"
restore() {
  if [ "$MAINT" = 1 ]; then sudo -n pft-maint end --reason "$TASK done" >/dev/null 2>&1 && echo "  pft-maint window ended"; MAINT=0; fi
  if [ "$SWAPPED" = 1 ]; then
    sleep 5 # let the [MAINT] end message leave on the throwaway target
    if [ "$HAD" = 1 ]; then sudo -n mv "$BK" "$NE"; else sudo -n rm -f "$NE"; fi
    SWAPPED=0; echo "  pft-maint target restored"
  fi
}
cleanup() { restore; rm -f "$OPS"; }
trap cleanup EXIT
trap 'echo "interrupted"; exit 6' INT TERM

echo "resources compose-apply - $(date -u +%FT%TZ) - $(lsb_release -ds) - HEAD $SHA (clean: $([ -z "$(git status --short)" ] && echo yes || echo NO))"
echo "sha256 $(sha256sum < "$RES_FILE" | cut -c1-64) $RES_FILE"; echo "sha256 $(sha256sum < "$0" | cut -c1-64) $0"
echo "== this file"; sed 's/^/  | /' "$RES_FILE"

echo; echo "== 0. preflight (changes nothing)"
[ -z "$(git status --short)" ] && [ "$(git rev-parse origin/main)" = "$SHA" ]; check "clean tree, HEAD pushed" $?
x "sudo -n pft-integrity verify | tail -1"; check "pft-integrity PASS before" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
x "state"; check "validator full or proposing" "$(grep -qE '^(full|proposing)$' <<<"$XOUT" && echo 0 || echo 1)"
x "res"; check "live values before = wanted ($WANT_CS $WANT_MR; set by docker update 2026-11-02, kept by pft-seccomp re-creates)" "$([ "$XOUT" = "$WANT_CS $WANT_MR" ] && echo 0 || echo 1)"
cgv() { local id f; id="$(sudo -n docker inspect postfiatd --format '{{.Id}}')"; f="/sys/fs/cgroup/system.slice/docker-$id.scope"; echo "$(cat "$f/cpu.weight") $(cat "$f/memory.low")"; }
x "cgv"; CG_OLD="$XOUT"; check "cgroup cpu.weight + memory.low read (before)" "$([ -n "$CG_OLD" ] && echo 0 || echo 1)" "$CG_OLD"
x "sudo -n sed -n 's/^COMPOSE_FILE=//p' $D/.env"; CF_OLD="$XOUT"
check "COMPOSE_FILE set, overlay not in it yet" "$([ -n "$CF_OLD" ] && ! grep -q docker-compose.resources.yml <<<"$CF_OLD" && echo 0 || echo 1)"
x "sudo -n grep -rlE 'cpu_shares|mem_reservation' $D/*.yml | wc -l"; check "no compose file sets cpu_shares/mem_reservation yet" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "sudo -n docker compose --project-directory $D $(tr ':' '\n' <<<"$CF_OLD" | sed "s#^#-f $D/#" | tr '\n' ' ') -f $REPO/$RES_FILE config 2>/dev/null | grep -E '^ +(cpu_shares|mem_reservation):'"
check "merged config (current overlays + this file) has cpu_shares 8192 + mem_reservation 1610612736" "$(grep -q 'cpu_shares: 8192' <<<"$XOUT" && grep -q 'mem_reservation: "1610612736"' <<<"$XOUT" && echo 0 || echo 1)"
x "curl -s $AM/api/v2/silences | jq -r '[.[] | select(.status.state == \"active\")] | length'"
check "no active Alertmanager silence (nothing else owns the window)" "$([ "$XOUT" = 0 ] && echo 0 || echo 1)"
x "sudo -n pft-maint status | head -3"
{ for f in /etc/postfiat-monitor.env /etc/pft-integrity.env; do sudo -n sed -n 's/^NTFY_TOPIC=//p' "$f" 2>/dev/null; done
  R 'for f in /etc/pft-watchdog/ntfy.env /etc/pft-integrity.env /etc/pft-alertpath/ntfy.env; do sudo -n sed -n "s/^NTFY_TOPIC=//p" $f 2>/dev/null; done'
  sed -n 's|^NTFY_URL=.*/||p' "$HOME/.config/pft-alerts/ntfy.env" 2>/dev/null
  sed -n 's/^NTFY_TOPIC=//p' /opt/pft-agent/config.env 2>/dev/null
} | tr -d "\"'\r" | grep -E '^[A-Za-z0-9_-]{8,}$' | sort -u > "$OPS"
echo "operator topics to read back: $(wc -l < "$OPS") (not printed)"; check "operator topics found" "$([ -s "$OPS" ] && echo 0 || echo 1)"
[ "$FAILS" = 0 ] || { echo "preflight failed - stopping before any change"; exit 3; }
[ "$PREFLIGHT_ONLY" = 1 ] && { echo "PREFLIGHT_ONLY: ready, nothing changed"; exit 0; }

echo; echo "== 1. silence (all but the pipeline watchdog) + pft-maint window, [MAINT] to a throwaway topic"
ends="$(date -u -d "+${WIN%m} min +10 min" +%FT%TZ)"
SBODY="$(jq -nc --arg s "$(date -u +%FT%TZ)" --arg e "$ends" --arg c "$TASK planned postfiatd re-create (compose resources overlay)" \
  '{matchers: [{name: "alertname", value: ".+", isRegex: true, isEqual: true}, {name: "alertname", value: "PFTAlertPipelineWatchdog", isRegex: false, isEqual: false}], startsAt: $s, endsAt: $e, createdBy: "resources-apply", comment: $c}')"
SIL="$(curl -s --max-time 10 -H 'Content-Type: application/json' -X POST "$AM/api/v2/silences" -d "$SBODY" | jq -r '.silenceID // empty')"
check "Alertmanager silence until $ends" "$([ -n "$SIL" ] && echo 0 || echo 1)"
ORIG_SHA=absent; if sudo -n test -e "$NE"; then HAD=1; ORIG_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
x "{ [ \$HAD = 0 ] || sudo -n cp -p \$NE \$BK; } && printf 'NTFY_SERVER=https://ntfy.sh\nNTFY_TOPIC=%s\n' \"\$TT\" | sudo -n tee \$NE >/dev/null && sudo -n chmod 600 \$NE && sudo -n stat -c '%a %U' \$NE"
[ "$XRC" = 0 ] && SWAPPED=1; check "throwaway pft-maint target installed" "$XRC"
if [ "$SWAPPED" != 1 ] || [ -z "$SIL" ]; then echo "no silence/throwaway target - stopping before the window"; exit 3; fi
x "sudo -n pft-maint start --ttl $WIN --reason '$TASK: compose resources overlay, planned postfiatd re-create'"
[ "$XRC" = 0 ] && MAINT=1; check "pft-maint window open" "$XRC"
w=0; until R "sudo -n pft-maint active" >/dev/null 2>&1; do w=$((w + 10)); [ "$w" -le 420 ] || break; sleep 10; done
R "sudo -n pft-maint active" >/dev/null 2>&1; check "sentry has the window (watchdog channel) after ${w}s" "$?"
[ "$FAILS" = 0 ] || exit 3

echo; echo "== 2. install the overlay, add it to COMPOSE_FILE, docker compose up -d"
ENV_BK="$D/.env.pre-resources-$(date -u +%Y%m%dT%H%M%SZ)"
x "sudo -n cp -p $D/.env $ENV_BK && sudo -n install -m 644 -o root -g root $REPO/$RES_FILE $D/docker-compose.resources.yml && sudo -n sed -i 's#^COMPOSE_FILE=.*#&:docker-compose.resources.yml#' $D/.env && sudo -n sed -n 's/^COMPOSE_FILE=//p' $D/.env"
check "overlay installed, COMPOSE_FILE = old + :docker-compose.resources.yml (old .env kept as backup)" "$([ "$XRC" = 0 ] && [ "$XOUT" = "$CF_OLD:docker-compose.resources.yml" ] && echo 0 || echo 1)"
t0="$(date -u +%s)"
x "(cd $D && sudo -n docker compose up -d 2>&1 | { grep -v 'attribute .version. is obsolete' || true; })"
check "docker compose up -d exit 0" "$XRC"
s=down; while [ $(( $(date -u +%s) - t0 )) -lt "$FULL_WAIT" ]; do s="$(state)"; case "$s" in full|proposing) break ;; esac; sleep 15; done
echo "  $(date -u +%FT%TZ): server_state $s after $(( $(date -u +%s) - t0 ))s"
check "validator back to full after the re-create" "$(case "$s" in full|proposing) echo 0 ;; *) echo 1 ;; esac)"

echo; echo "== 3. verify"
x "res"; check "container: CpuShares $WANT_CS, MemoryReservation $WANT_MR (now from compose)" "$([ "$XOUT" = "$WANT_CS $WANT_MR" ] && echo 0 || echo 1)"
x "sudo -n docker inspect postfiatd --format '{{index .Config.Labels \"com.docker.compose.project.config_files\"}}' | tr ',' '\n' | sed 's#.*/##'"
check "compose labels list the overlay" "$(grep -qx docker-compose.resources.yml <<<"$XOUT" && echo 0 || echo 1)"
x "sudo -n docker inspect postfiatd --format '{{json .HostConfig.SecurityOpt}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}}' | sed -E 's/seccomp=[^\"]*/seccomp=<profile>/'"
check "earlier overlays still applied (no-new-privileges, apparmor, seccomp, memory limit)" "$(grep -q no-new-privileges <<<"$XOUT" && grep -q apparmor=pft-postfiatd <<<"$XOUT" && grep -q seccomp= <<<"$XOUT" && grep -q 'mem=2415919104' <<<"$XOUT" && echo 0 || echo 1)"
x "cgv"; check "new container's cgroup: cpu.weight + memory.low equal to before ($CG_OLD)" "$([ "$XOUT" = "$CG_OLD" ] && echo 0 || echo 1)"
x "sudo -n pft-integrity verify | grep -E 'WARN|FAIL|RESULT' | sed -E 's/[0-9a-f]{12,}/<sha>/g'"
UNEXP="$(grep -E '^\s*\[(WARN|FAIL)\]' <<<"$XOUT" | grep -vE '\] (compose:\.env|compose:docker-compose\.resources\.yml|container:postfiatd) ' || true)"
check "integrity: changed items are only compose:.env, compose:docker-compose.resources.yml, container:postfiatd" "$([ -z "$UNEXP" ] && echo 0 || echo 1)" "${UNEXP:+unexpected: $UNEXP}"
if [ -z "$UNEXP" ]; then
  x "sudo -n pft-integrity accept --reason '$TASK: docker-compose.resources.yml (cpu_shares 8192, mem_reservation 1536m) in COMPOSE_FILE, postfiatd re-created @$SHORT' | tail -2; sudo -n pft-integrity verify | tail -1"
  check "pft-integrity PASS after accept" "$(grep -q 'RESULT: PASS' <<<"$XOUT" && echo 0 || echo 1)"
fi

echo; echo "== 4. end window, restore the real target, read back"
restore
NOW_SHA=absent; if sudo -n test -e "$NE"; then NOW_SHA="$(sudo -n sha256sum "$NE" | cut -c1-64)"; fi
check "pft-maint target back to its pre-run state" "$([ "$ORIG_SHA" = "$NOW_SHA" ] && echo 0 || echo 1)"
x "sudo -n systemctl start pft-keyescrow.service; grep -h '^pft_keyescrow_drift_items{node=\"validator\"}' /var/lib/pft-exporter/textfile/pft_keyescrow.prom"
check "pft-keyescrow re-run: validator drift_items 0" "$(grep -q '} 0$' <<<"$XOUT" && echo 0 || echo 1)"
echo "  waiting 120 s for restart-related alerts to resolve under the silence"; sleep 120
x "curl -s $PROM/api/v1/alerts | jq -r '.data.alerts[] | select(.labels.alertname != \"PFTAlertPipelineWatchdog\") | \"\(.labels.alertname) \(.state)\"' | sort | uniq -c"
check "no alert pending or firing (besides the pipeline watchdog) before the silence ends" "$([ -z "$XOUT" ] && echo 0 || echo 1)"
curl -s --max-time 10 -o /dev/null -w "  silence expired: HTTP %{http_code}\n" -X DELETE "$AM/api/v2/silence/$SIL"
x "sleep 5; curl -s --max-time 15 \"https://ntfy.sh/\$TT/json?poll=1&since=$since\" | jq -r '.title'"
check "the [MAINT] start and end messages reached the throwaway topic" "$([ "$(grep -c '^\[MAINT\]' <<<"$XOUT")" -ge 2 ] && echo 0 || echo 1)"
i=0; OPN=0
while read -r t; do
  i=$((i + 1)); n="$(curl -s --max-time 20 "https://ntfy.sh/$t/json?poll=1&since=$since" | jq -c 'select(.event == "message")' | wc -l)"
  echo "  operator #$i topic: $n message(s)"; [ "$n" = 0 ] || OPN=$((OPN + 1))
done < "$OPS"
check "operator topics received nothing during the run" "$([ "$OPN" = 0 ] && echo 0 || echo 1)" "$i topic(s), $OPN with messages"
x "sudo -n postfiat-health | tail -3"
check "postfiat-health HEALTHY" "$(grep -q 'RESULT: HEALTHY' <<<"$XOUT" && echo 0 || echo 1)"
echo; echo "compose-apply done $(date -u +%FT%TZ): $FAILS check(s) failed -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
