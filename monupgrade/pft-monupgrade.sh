#!/usr/bin/env bash
# shellcheck disable=SC2015  # `test && ok || fail` chains: the ok/check/log helpers always return 0
# pft-monupgrade: reversible upgrades of the pinned Prometheus + Alertmanager images of the loopback monitoring
# stack (../alerts/run-stack.sh: containers pft-prometheus, pft-alertmanager; `docker run`, no compose file).
#
# Usage: pft-monupgrade plan [--out FILE] [--no-pull]
#        pft-monupgrade apply --plan FILE --yes      (inside a pft-maint window, alerts routed to NTFY_TEST_URL)
#        pft-monupgrade rollback --yes               (undo the last apply; same guards)
#
#  plan   records the running image ref, image id and repo digest of each container, selects a target tag per
#         image and pins it to its registry digest, pulls the target BY DIGEST (no container is touched; the image
#         store gains one image per target -> `pft-integrity accept` afterwards) and checks the live configuration
#         against it: promtool check config (prometheus.yml with the same /etc/pft-alerts + /etc/pft-slo mounts
#         as the live container), promtool check rules (every rule_files entry of prometheus.yml), promtool test
#         rules (every *.tests.yml next to them), amtool check-config. The same checks run with the CURRENT image
#         first as a control: a check that fails on both images is a config problem, not an upgrade blocker.
#         Target selection (per image, unless TARGET_PROM / TARGET_AM = vX.Y.Z or vX.Y.Z@sha256:...): the highest
#         vX.Y.Z tag (no suffix: no -rc, no -distroless) of the same major as the running tag, pushed at least
#         MIN_AGE_DAYS ago. The digest is the tag's manifest-list digest from Docker Hub; after the pull the local
#         RepoDigests must contain it, then it is tagged REPO:TAG locally.
#         Exit: 0 an upgrade is available and every target check passed; 3 nothing to upgrade (both current);
#         4 a target check failed (reasons listed); 1 error (reasons listed); 2 usage.
#         Every failure prints `FAIL <image> reason=<name>`, names: container-missing, current-unpinned,
#         hub-unreachable, no-target, pull-failed, digest-mismatch, tag-failed, promtool-check-config,
#         promtool-check-rules, promtool-test-rules, amtool-check-config (a CONTROL failure prints `CONTROL-FAIL` with the same names).
#
# Env: DOCKER (default "docker"), ALERTS_DIR (default ../alerts), SLO_DIR (default ../slo), PROM_CONTAINER,
#      AM_CONTAINER, PROM_REPO (prom/prometheus), AM_REPO (prom/alertmanager), TARGET_PROM, TARGET_AM,
#      MIN_AGE_DAYS (14), HUB_URL (https://hub.docker.com/v2/repositories), HUB_TAGS_DIR (tests: read
#      <repo with / as _>.json instead of the hub), NOW (epoch, tests).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
read -r -a DOCKER <<< "${DOCKER:-docker}"
ALERTS_DIR="$(readlink -f "${ALERTS_DIR:-$HERE/../alerts}")"
SLO_DIR="${SLO_DIR-$HERE/../slo}"
[ -n "$SLO_DIR" ] && [ -d "$SLO_DIR" ] && SLO_DIR="$(readlink -f "$SLO_DIR")" || SLO_DIR=""
PROM_CONTAINER="${PROM_CONTAINER:-pft-prometheus}"
AM_CONTAINER="${AM_CONTAINER:-pft-alertmanager}"
PROM_REPO="${PROM_REPO:-prom/prometheus}"
AM_REPO="${AM_REPO:-prom/alertmanager}"
MIN_AGE_DAYS="${MIN_AGE_DAYS:-14}"
HUB_URL="${HUB_URL:-https://hub.docker.com/v2/repositories}"
NOW="${NOW:-$(date -u +%s)}"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
FAILS=()
fail() { FAILS+=("$1 reason=$2"); printf 'FAIL %s reason=%s%s\n' "$1" "$2" "${3:+ ($3)}"; }

# --- current state ----------------------------------------------------------------------------------------------

# current NAME -> "ref<TAB>image-id<TAB>repo-digest" (repo-digest "-" when the image has none for REPO)
current() {
  local name="$1" repo="$2" ref id dig
  ref="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$name" 2>/dev/null)" || return 1
  id="$("${DOCKER[@]}" inspect -f '{{.Image}}' "$name" 2>/dev/null)" || return 1
  dig="$("${DOCKER[@]}" image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$id" 2>/dev/null \
    | awk -v r="$repo@" 'index($0, r) == 1 { print substr($0, length(r) + 1); exit }')"
  printf '%s\t%s\t%s\n' "$ref" "$id" "${dig:--}"
}

# tag_of REF -> vX.Y.Z of "repo:vX.Y.Z" or "repo:vX.Y.Z@sha256:..." (empty if none)
tag_of() {
  local r="${1%%@*}"
  case "$r" in *:*) r="${r##*:}" ;; *) r="" ;; esac
  [[ "$r" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && printf '%s\n' "$r"
}

# --- target selection -------------------------------------------------------------------------------------------

hub_tags() {
  local repo="$1"
  if [ -n "${HUB_TAGS_DIR:-}" ]; then
    cat "$HUB_TAGS_DIR/${repo//\//_}.json"
    return
  fi
  curl -fsS --max-time 20 --retry 2 "$HUB_URL/$repo/tags?page_size=100&ordering=last_updated"
}

# select_target REPO CURRENT_TAG -> "tag<TAB>digest<TAB>pushed" or nothing (rc 0) / rc 1 hub error
select_target() {
  local repo="$1" cur="$2" j major
  j="$(hub_tags "$repo")" || return 1
  [ -n "$j" ] && jq -e '.results | type == "array"' >/dev/null 2>&1 <<<"$j" || return 1
  major="${cur#v}"; major="${major%%.*}"
  jq -r --arg maj "$major" --argjson now "$NOW" --argjson age "$MIN_AGE_DAYS" '
    .results[]
    | select(.name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
    | select((.name | ltrimstr("v") | split(".")[0]) == $maj)
    | select((.digest // "") | test("^sha256:[0-9a-f]{64}$"))
    | ((.tag_last_pushed // .last_updated) | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) as $t
    | select($now - $t >= $age * 86400)
    | "\(.name)\t\(.digest)\t\($t | todate)"' <<<"$j" | sort -V | tail -n 1
}

# --- checks -------------------------------------------------------------------------------------------------------

# rule files of prometheus.yml as container paths (globs expanded against the host dirs)
rule_files() {
  local f
  awk '/^rule_files:/ { on = 1; next } on && /^[^ #-]/ { on = 0 } on && $1 == "-" { print $2 }' \
    "$ALERTS_DIR/prometheus.yml" | while read -r f; do
    case "$f" in
      /etc/pft-alerts/*) compgen -G "$ALERTS_DIR/${f#/etc/pft-alerts/}" | sed "s#^$ALERTS_DIR#/etc/pft-alerts#" ;;
      /etc/pft-slo/*) [ -n "$SLO_DIR" ] && compgen -G "$SLO_DIR/${f#/etc/pft-slo/}" | sed "s#^$SLO_DIR#/etc/pft-slo#" ;;
      *) printf '%s\n' "$f" ;;
    esac
  done
}

# test_files DIR -> tests.yml and *.tests.yml names (relative: promtool resolves their rule_files from the workdir)
test_files() {
  local f
  for f in "$1"/tests.yml "$1"/*.tests.yml; do [ -f "$f" ] && printf '%s\n' "${f##*/}"; done
  return 0
}

tool() { # tool IMAGE ENTRYPOINT WORKDIR ARGS... (read-only mounts, no network, nobody)
  local img="$1" ep="$2" wd="$3"; shift 3
  local m=(-v "$ALERTS_DIR:/etc/pft-alerts:ro")
  [ -n "$SLO_DIR" ] && m+=(-v "$SLO_DIR:/etc/pft-slo:ro")
  # promtool test rules writes a scratch TSDB under /tmp: give the read-only container a nobody-writable tmpfs
  "${DOCKER[@]}" run --rm --network none --read-only --tmpfs /tmp:rw,mode=1777,size=256m --cap-drop ALL \
    --security-opt no-new-privileges --user 65534:65534 "${m[@]}" -w "$wd" --entrypoint "$ep" "$img" "$@"
}

# run_checks LABEL PROM_IMAGE AM_IMAGE KIND(FAIL|CONTROL-FAIL) -> rc 0 all pass
run_checks() {
  local label="$1" pimg="$2" aimg="$3" kind="$4" bad=0 out rc rules=() tests_a=() tests_s=()
  report() { # report CHECK RC OUT IMAGE
    local n
    n="$(printf '%s\n' "$3" | grep -c . || true)"
    if [ "$2" -eq 0 ]; then
      printf '  %-9s %-22s PASS (%s output lines)\n' "$label" "$1" "$n"
    else
      bad=1
      printf '  %-9s %-22s rc=%s\n' "$label" "$1" "$2"
      printf '%s\n' "$3" | grep -iE 'error|fail|unmarshal|invalid' | head -n 8 | sed 's/^/      | /'
      if [ "$kind" = FAIL ]; then fail "$4" "$1"; else printf 'CONTROL-FAIL %s reason=%s\n' "$4" "$1"; fi
    fi
  }
  mapfile -t rules < <(rule_files)
  out="$(tool "$pimg" promtool /etc/pft-alerts check config /etc/pft-alerts/prometheus.yml 2>&1)"; rc=$?
  report promtool-check-config "$rc" "$out" prometheus
  out="$(tool "$pimg" promtool /etc/pft-alerts check rules "${rules[@]}" 2>&1)"; rc=$?
  report promtool-check-rules "$rc" "$out" prometheus
  printf '  %-9s %-22s %s rule files\n' "$label" "(rule files)" "${#rules[@]}"
  mapfile -t tests_a < <(test_files "$ALERTS_DIR")
  out="$(tool "$pimg" promtool /etc/pft-alerts test rules "${tests_a[@]}" 2>&1)"; rc=$?
  if [ -n "$SLO_DIR" ] && [ "$rc" -eq 0 ]; then
    mapfile -t tests_s < <(test_files "$SLO_DIR")
    if [ "${#tests_s[@]}" -gt 0 ]; then
      out+=$'\n'"$(tool "$pimg" promtool /etc/pft-slo test rules "${tests_s[@]}" 2>&1)"; rc=$?
    fi
  fi
  report promtool-test-rules "$rc" "$out" prometheus
  printf '  %-9s %-22s %s+%s test files, %s SUCCESS lines\n' "$label" "(test files)" "${#tests_a[@]}" \
    "${#tests_s[@]}" "$(printf '%s\n' "$out" | grep -c 'SUCCESS' || true)"
  out="$(tool "$aimg" amtool /etc/pft-alerts check-config /etc/pft-alerts/alertmanager.yml 2>&1)"; rc=$?
  report amtool-check-config "$rc" "$out" alertmanager
  return "$bad"
}

# --- plan ---------------------------------------------------------------------------------------------------------

# pull_pinned NAME REPO TAG DIGEST -> rc 0 when the pulled image's RepoDigests contain REPO@DIGEST
pull_pinned() {
  local name="$1" repo="$2" tag="$3" dig="$4" out
  if [ "$NO_PULL" -eq 0 ]; then
    out="$("${DOCKER[@]}" pull -q "$repo:$tag@$dig" 2>&1)" || { fail "$name" pull-failed "$out"; return 1; }
  fi
  out="$("${DOCKER[@]}" image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$repo@$dig" 2>/dev/null)" \
    || { fail "$name" pull-failed "image $repo@$dig not in the local store"; return 1; }
  grep -qxF "$repo@$dig" <<<"$out" || { fail "$name" digest-mismatch "RepoDigests: $(tr '\n' ' ' <<<"$out")"; return 1; }
  if [ "$NO_PULL" -eq 0 ]; then
    # `pull repo:tag@digest` leaves the image untagged; tag it so `docker image ls` (pft-imagescan, pft-fleet) lists
    # the verified digest under its tag
    out="$("${DOCKER[@]}" tag "$repo@$dig" "$repo:$tag" 2>&1)" || { fail "$name" tag-failed "$out"; return 1; }
  fi
  printf '  %-12s %s %s:%s, RepoDigests contain %s\n' "$name" "$([ "$NO_PULL" -eq 0 ] && echo pulled || echo present)" "$repo" "$tag" "$dig"
}

plan() {
  local out_file="" i a b c
  NO_PULL=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out_file="${2:?--out FILE}"; shift 2 ;;
      --no-pull) NO_PULL=1; shift ;;
      *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
  done
  log "pft-monupgrade plan (alerts dir $(basename "$ALERTS_DIR"), slo dir ${SLO_DIR:+$(basename "$SLO_DIR")}, min age ${MIN_AGE_DAYS} d)"
  declare -A ref iid dig tag ttag tdig tpushed
  local names=(prometheus alertmanager) cont=("$PROM_CONTAINER" "$AM_CONTAINER") repos=("$PROM_REPO" "$AM_REPO")
  local overrides=("${TARGET_PROM:-}" "${TARGET_AM:-}") n line
  for i in 0 1; do
    n="${names[$i]}"
    if ! line="$(current "${cont[$i]}" "${repos[$i]}")"; then
      fail "$n" container-missing "${cont[$i]}"; continue
    fi
    IFS=$'\t' read -r a b c <<<"$line"
    ref[$n]="$a"; iid[$n]="$b"; dig[$n]="$c"
    tag[$n]="$(tag_of "${ref[$n]}")"
    printf 'CURRENT %-12s container=%s ref=%s id=%s digest=%s\n' "$n" "${cont[$i]}" "${ref[$n]}" "${iid[$n]}" "${dig[$n]}"
    if [ -z "${tag[$n]}" ] || [ "${dig[$n]}" = - ]; then fail "$n" current-unpinned "ref ${ref[$n]}"; continue; fi
    if [ -n "${overrides[$i]}" ]; then
      ttag[$n]="${overrides[$i]%%@*}"
      case "${overrides[$i]}" in *@sha256:*) tdig[$n]="${overrides[$i]#*@}" ;; *) tdig[$n]="" ;; esac
      tpushed[$n]="override"
      if [ -z "${tdig[$n]}" ]; then
        if ! line="$(hub_tags "${repos[$i]}" | jq -r --arg t "${ttag[$n]}" '.results[] | select(.name == $t) | .digest')"; then
          fail "$n" hub-unreachable; continue
        fi
        tdig[$n]="$line"
      fi
      [[ "${ttag[$n]}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "${tdig[$n]}" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || { fail "$n" no-target "override ${overrides[$i]} not vX.Y.Z with a sha256 digest"; continue; }
    else
      if ! line="$(select_target "${repos[$i]}" "${tag[$n]}")"; then fail "$n" hub-unreachable; continue; fi
      [ -n "$line" ] || { fail "$n" no-target "no vX.Y.Z tag of major ${tag[$n]%%.*} older than ${MIN_AGE_DAYS} d"; continue; }
      IFS=$'\t' read -r a b c <<<"$line"
      ttag[$n]="$a"; tdig[$n]="$b"; tpushed[$n]="$c"
    fi
    printf 'TARGET  %-12s tag=%s digest=%s pushed=%s\n' "$n" "${ttag[$n]}" "${tdig[$n]}" "${tpushed[$n]}"
  done
  [ "${#FAILS[@]}" -eq 0 ] || { log "RESULT: ERROR - ${FAILS[*]}"; return 1; }

  local up=()
  for n in "${names[@]}"; do
    if [ "${tdig[$n]}" = "${dig[$n]}" ] || [ "$(printf '%s\n%s\n' "${tag[$n]}" "${ttag[$n]}" | sort -V | tail -n1)" = "${tag[$n]}" ]; then
      printf 'UPTODATE %-12s running %s is the target or newer\n' "$n" "${tag[$n]}"
      ttag[$n]="${tag[$n]}"; tdig[$n]="${dig[$n]}"
    else
      up+=("$n")
    fi
  done
  if [ "${#up[@]}" -eq 0 ]; then
    log "RESULT: UP TO DATE - nothing to upgrade -> exit 3"; return 3
  fi
  local i_ok=1
  for i in 0 1; do
    n="${names[$i]}"
    [ "${tdig[$n]}" = "${dig[$n]}" ] && continue
    pull_pinned "$n" "${repos[$i]}" "${ttag[$n]}" "${tdig[$n]}" || i_ok=0
  done
  [ "$i_ok" -eq 1 ] || { log "RESULT: ERROR - ${FAILS[*]}"; return 1; }

  local cur_p="${PROM_REPO}@${dig[prometheus]}" cur_a="${AM_REPO}@${dig[alertmanager]}"
  local tgt_p="${PROM_REPO}:${ttag[prometheus]}@${tdig[prometheus]}" tgt_a="${AM_REPO}:${ttag[alertmanager]}@${tdig[alertmanager]}"
  log "control: checks with the CURRENT images"
  local ctrl=PASS
  run_checks current "$cur_p" "$cur_a" CONTROL-FAIL || ctrl=FAIL
  log "checks with the TARGET images"
  run_checks target "$tgt_p" "$tgt_a" FAIL
  if [ -n "$out_file" ]; then
    jq -n --arg at "$(date -u +%FT%TZ)" --arg ctrl "$ctrl" \
      --arg pc "${ref[prometheus]}" --arg pcd "${dig[prometheus]}" --arg pt "${ttag[prometheus]}" --arg ptd "${tdig[prometheus]}" \
      --arg ac "${ref[alertmanager]}" --arg acd "${dig[alertmanager]}" --arg at2 "${ttag[alertmanager]}" --arg atd "${tdig[alertmanager]}" \
      --arg fails "${FAILS[*]:-}" '{
        planned_at: $at, control: $ctrl, fails: ($fails | split(" reason=") | if . == [""] then [] else . end),
        prometheus: {current_ref: $pc, current_digest: $pcd, target_tag: $pt, target_digest: $ptd},
        alertmanager: {current_ref: $ac, current_digest: $acd, target_tag: $at2, target_digest: $atd}}' >"$out_file" \
      || { log "ERROR: cannot write $out_file"; return 1; }
    log "plan written to $(basename "$out_file")"
  fi
  if [ "${#FAILS[@]}" -gt 0 ]; then
    log "RESULT: BLOCKED - ${FAILS[*]} (control $ctrl) -> exit 4"; return 4
  fi
  log "RESULT: READY - upgrade ${up[*]}: prometheus ${tag[prometheus]} -> ${ttag[prometheus]}, alertmanager ${tag[alertmanager]} -> ${ttag[alertmanager]} (control $ctrl); image store changed -> pft-integrity accept"
  return 0
}

# --- apply / rollback ---------------------------------------------------------------------------------------------

read -r -a CURL <<< "${CURL:-curl}"
read -r -a SS <<< "${SS:-ss}"
PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"
AM_URL="${AM_URL:-http://127.0.0.1:9093}"
BRIDGE_CONTAINER="${BRIDGE_CONTAINER:-pft-alert-bridge}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-monupgrade}"
PFT_MAINT_BIN="${PFT_MAINT_BIN:-/usr/local/bin/pft-maint}"
PLAN_MAX_AGE="${PLAN_MAX_AGE:-86400}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
SETTLE_TIMEOUT="${SETTLE_TIMEOUT:-180}"
DELIVERY_TIMEOUT="${DELIVERY_TIMEOUT:-150}"
POLL="${POLL:-3}"
WATCHDOG="${WATCHDOG:-PFTAlertPipelineWatchdog}"
TEST_ALERT="${TEST_ALERT:-PFTMonupgradeTest}"

api() { "${CURL[@]}" -fsS --max-time 10 "$@"; }
# json URL -> body on stdout, rc 1 when unreachable / empty / not JSON (fail closed)
json() { local j; j="$(api "$1" 2>/dev/null)" && [ -n "$j" ] && jq -e 'type' >/dev/null 2>&1 <<<"$j" && printf '%s\n' "$j"; }
now() { date -u +%s; }

# signature NAME -> everything a re-create must keep, except the image (one JSON line)
signature() {
  "${DOCKER[@]}" inspect "$1" 2>/dev/null | jq -c '.[0] | {
    args: .Args, entrypoint: .Config.Entrypoint, user: .Config.User,
    mounts: ([.Mounts[] | {Type, Name: (if .Type == "volume" then .Name else null end), Source: (if .Type == "bind" then .Source else null end), Destination, RW}] | sort_by(.Destination)),
    restart: .HostConfig.RestartPolicy.Name, network: .HostConfig.NetworkMode, security: .HostConfig.SecurityOpt,
    capdrop: .HostConfig.CapDrop, capadd: .HostConfig.CapAdd, readonly: .HostConfig.ReadonlyRootfs,
    tmpfs: .HostConfig.Tmpfs, log: .HostConfig.LogConfig, memory: .HostConfig.Memory, nanocpus: .HostConfig.NanoCpus,
    privileged: .HostConfig.Privileged, ports: .HostConfig.PortBindings}'
}

# run_args NAME -> NUL-separated `docker run` options rebuilt from the container's own configuration
run_args() {
  "${DOCKER[@]}" inspect "$1" | jq -j '.[0] | (
    ["-d", "--name", (.Name | ltrimstr("/")), "--restart", .HostConfig.RestartPolicy.Name,
     "--network", .HostConfig.NetworkMode]
    + ([.HostConfig.SecurityOpt // [] | .[] | ["--security-opt", .]] | add // [])
    + ([.HostConfig.CapDrop // [] | .[] | ["--cap-drop", .]] | add // [])
    + ([.HostConfig.CapAdd // [] | .[] | ["--cap-add", .]] | add // [])
    + (if .HostConfig.ReadonlyRootfs then ["--read-only"] else [] end)
    + (if (.Config.User // "") != "" then ["--user", .Config.User] else [] end)
    + (if .HostConfig.LogConfig.Type != "json-file" or (.HostConfig.LogConfig.Config // {}) != {} then
        ["--log-driver", .HostConfig.LogConfig.Type] + ([.HostConfig.LogConfig.Config // {} | to_entries[] | ["--log-opt", "\(.key)=\(.value)"]] | add // [])
       else [] end)
    + ([.Mounts[] | ["-v", ((if .Type == "volume" then .Name else .Source end) + ":" + .Destination + (if .RW then "" else ":ro" end))]] | add // [])
  ) | map(. + "\u0000") | join("")'
}

# recreate NAME IMAGE -> stop + rename the old container (kept, restart=no) and `docker run` IMAGE with the same
# configuration and arguments; rc 0 when the new container is running
recreate() {
  local name="$1" img="$2" opts=() cmd=()
  mapfile -d '' -t opts < <(run_args "$name") || return 1
  mapfile -t cmd < <("${DOCKER[@]}" inspect "$name" | jq -r '.[0].Args[]') || return 1
  [ "${#opts[@]}" -gt 6 ] || { log "ERROR: cannot read the configuration of $name"; return 1; }
  "${DOCKER[@]}" inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$name" >"$STATE_DIR/restart.$name" || return 1
  signature "$name" >"$STATE_DIR/sig.$name" || return 1
  "${DOCKER[@]}" stop -t 30 "$name" >/dev/null || return 1
  "${DOCKER[@]}" rename "$name" "$name-premonupgrade" || return 1
  "${DOCKER[@]}" update --restart=no "$name-premonupgrade" >/dev/null || return 1
  log "  recreate $name on $img"
  if ! "${DOCKER[@]}" run "${opts[@]}" "$img" "${cmd[@]}" >/dev/null; then
    log "  docker run failed for $name: restoring the previous container"
    restore_old "$name"; return 1
  fi
}

# restore_old NAME -> remove the new container, put the kept previous one back (rename, restart policy, start)
restore_old() {
  local name="$1" pol
  "${DOCKER[@]}" inspect "$name-premonupgrade" >/dev/null 2>&1 || return 1
  pol="$(cat "$STATE_DIR/restart.$name" 2>/dev/null)"
  "${DOCKER[@]}" rm -f "$name" >/dev/null 2>&1 || true
  "${DOCKER[@]}" rename "$name-premonupgrade" "$name" && "${DOCKER[@]}" update --restart="${pol:-unless-stopped}" "$name" >/dev/null \
    && "${DOCKER[@]}" start "$name" >/dev/null
}

wait_ready() {
  local t0; t0="$(now)"
  while :; do
    api "$PROM_URL/-/ready" >/dev/null 2>&1 && api "$AM_URL/-/ready" >/dev/null 2>&1 && return 0
    [ $(($(now) - t0)) -ge "$READY_TIMEOUT" ] && return 1
    sleep "$POLL"
  done
}

# snapshot -> one JSON object: versions, rule set + health, targets, receivers, active silence ids, watchdog status.
# The API bodies go to jq as files: a real /api/v1/rules body is larger than one argv string (MAX_ARG_STRLEN 128 KiB).
snapshot() {
  local d rc=1
  d="$(mktemp -d)" || return 1
  if json "$PROM_URL/api/v1/status/buildinfo" >"$d/bi" && json "$AM_URL/api/v2/status" >"$d/st" \
    && json "$PROM_URL/api/v1/rules" >"$d/r" && json "$PROM_URL/api/v1/targets" >"$d/tg" \
    && json "$AM_URL/api/v2/receivers" >"$d/rc" && json "$AM_URL/api/v2/silences" >"$d/sil" \
    && json "$AM_URL/api/v2/alerts?filter=alertname%3D%22$WATCHDOG%22" >"$d/wd"; then
    jq -nc --slurpfile bi "$d/bi" --slurpfile st "$d/st" --slurpfile r "$d/r" --slurpfile tg "$d/tg" \
      --slurpfile rc "$d/rc" --slurpfile sil "$d/sil" --slurpfile wd "$d/wd" '
      $bi[0] as $bi | $st[0] as $st | $r[0] as $r | $tg[0] as $tg | $rc[0] as $rc | $sil[0] as $sil | $wd[0] as $wd | {
      prom_version: $bi.data.version, am_version: $st.versionInfo.version,
      rules: ([$r.data.groups[] | .name as $g | .rules[] | "\($g)/\(.name)"] | sort),
      rules_not_ok: ([$r.data.groups[] | .rules[] | select(.health != "ok") | .name] | sort),
      targets: ([$tg.data.activeTargets[] | "\(.labels.job) \(.scrapeUrl)"] | sort),
      targets_up: ([$tg.data.activeTargets[] | select(.health == "up") | "\(.labels.job) \(.scrapeUrl)"] | sort),
      receivers: ([$rc[].name] | sort),
      silences: ([$sil[] | select(.status.state == "active") | .id] | sort),
      watchdog: ([$wd[] | {state: .status.state, silenced: (.status.silencedBy | length)}])}'
    rc=$?
  fi
  rm -rf "$d"
  return "$rc"
}

# isolation -> rc 0 when the bridge delivers to NTFY_TEST_URL only (mounted env file = test URL, bridge started after
# the file was written); prints the reason otherwise
isolation() {
  local src started mt url
  [ -n "${NTFY_TEST_URL:-}" ] || { echo "NTFY_TEST_URL is not set"; return 1; }
  src="$("${DOCKER[@]}" inspect "$BRIDGE_CONTAINER" 2>/dev/null \
    | jq -r '.[0].Mounts[] | select(.Destination == "/run/secrets/ntfy.env") | .Source')"
  [ -n "$src" ] && [ -r "$src" ] || { echo "bridge ntfy env not mounted/readable"; return 1; }
  url="$(sed -n 's/^NTFY_URL=//p' "$src" | head -n1)"
  [ "$url" = "$NTFY_TEST_URL" ] || { echo "bridge env does not point at NTFY_TEST_URL"; return 1; }
  started="$("${DOCKER[@]}" inspect -f '{{.State.StartedAt}}' "$BRIDGE_CONTAINER" | sed 's/\.[0-9]*Z$/Z/')"
  mt="$(stat -c %Y "$src")"
  [ "$(date -u -d "$started" +%s)" -ge "$mt" ] || { echo "bridge started before its env file changed (still the old URL)"; return 1; }
}

# watchdog_clear SNAPSHOT -> rc 0 when the watchdog is active in Alertmanager and no silence covers it
watchdog_clear() { jq -e '(.watchdog | length) > 0 and all(.watchdog[]; .state == "active" and .silenced == 0)' >/dev/null <<<"$1"; }

# test_alert RUNID -> post a synthetic alert to Alertmanager and wait for it on the NTFY_TEST_URL topic
test_alert() {
  local rid="$1" t0 body got="" st
  t0="$(now)"
  body="$(jq -nc --arg n "$TEST_ALERT" --arg id "$rid" --arg e "$(date -u -d "+10 min" +%FT%TZ)" \
    '[{labels: {alertname: $n, severity: "info", run: $id}, annotations: {summary: "pft-monupgrade test \($id)"}, endsAt: $e}]')"
  api -X POST -H 'Content-Type: application/json' --data "$body" "$AM_URL/api/v2/alerts" >/dev/null \
    || { echo "post to Alertmanager failed"; return 1; }
  st="$(json "$AM_URL/api/v2/alerts?filter=alertname%3D%22$TEST_ALERT%22")" \
    && jq -e 'any(.[]; .status.silencedBy == [] and .status.inhibitedBy == [])' >/dev/null <<<"$st" \
    || { echo "test alert silenced/inhibited or not in Alertmanager"; return 1; }
  while [ $(($(now) - t0)) -lt "$DELIVERY_TIMEOUT" ]; do
    got="$(api "$NTFY_TEST_URL/json?poll=1&since=$t0" 2>/dev/null | jq -r --arg id "$rid" --arg n "$TEST_ALERT" \
      'select(.event == "message" and ((.title // "") | contains($n)) and ((.message // "") | contains($id))) | .title' 2>/dev/null | head -n1)"
    [ -n "$got" ] && { printf 'delivered "%s" after %ss\n' "$got" "$(($(now) - t0))"; return 0; }
    sleep "$POLL"
  done
  echo "not delivered to NTFY_TEST_URL within ${DELIVERY_TIMEOUT}s"; return 1
}

# resolve_test_alert RUNID -> end the synthetic alert and wait until its [RESOLVED] reaches NTFY_TEST_URL too:
# Alertmanager sends it at the next group flush (group_interval), so returning earlier lets a caller that moves the
# bridge back to the real topic deliver it there (dry run 5: one [RESOLVED] PFTMonupgradeTest reached the operator)
resolve_test_alert() {
  local rid="$1" t0 body got=""
  t0="$(now)"
  body="$(jq -nc --arg n "$TEST_ALERT" --arg id "$rid" --arg e "$(date -u +%FT%TZ)" \
    '[{labels: {alertname: $n, severity: "info", run: $id}, annotations: {summary: "pft-monupgrade test \($id)"}, endsAt: $e}]')"
  api -X POST -H 'Content-Type: application/json' --data "$body" "$AM_URL/api/v2/alerts" >/dev/null \
    || { echo "resolve post to Alertmanager failed"; return 1; }
  while [ $(($(now) - t0)) -lt "$DELIVERY_TIMEOUT" ]; do
    got="$(api "$NTFY_TEST_URL/json?poll=1&since=$t0" 2>/dev/null | jq -r --arg id "$rid" --arg n "[RESOLVED] $TEST_ALERT" \
      'select(.event == "message" and ((.title // "") | startswith($n)) and ((.message // "") | contains($id))) | .title' 2>/dev/null | head -n1)"
    [ -n "$got" ] && { printf 'delivered "%s" after %ss\n' "$got" "$(($(now) - t0))"; return 0; }
    sleep "$POLL"
  done
  echo "[RESOLVED] not delivered to NTFY_TEST_URL within ${DELIVERY_TIMEOUT}s"; return 1
}

# loopback_only -> rc 0 when 9090/9093 listen on loopback only
loopback_only() {
  local l
  l="$("${SS[@]}" -Htln 2>/dev/null | awk '{print $4}' | grep -E ':(9090|9093)$' || true)"
  [ -n "$l" ] && ! grep -qvE '^(127\.0\.0\.1|\[::1\]):' <<<"$l"
}

# gate PRE_SNAPSHOT PROM_REF AM_REF RUNID -> rc 0 PASS; prints one CHECK line per check
GATE_FAILS=()
gate() {
  local pre="$1" pref="$2" aref="$3" rid="$4" post="" t0 n c msg
  GATE_FAILS=()
  check() { if [ "$2" = ok ]; then printf '  CHECK %-22s ok %s\n' "$1" "${3:-}"; else printf '  CHECK %-22s FAIL %s\n' "$1" "${3:-}"; GATE_FAILS+=("$1"); fi; }
  for n in prometheus alertmanager; do
    c="$PROM_CONTAINER"; [ "$n" = alertmanager ] && c="$AM_CONTAINER"
    local want="$pref"; [ "$n" = alertmanager ] && want="$aref"
    local ref running
    ref="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)"
    running="$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)"
    [ "$ref" = "$want" ] && [ "$running" = true ] && check "$n-image" ok "$ref" || check "$n-image" fail "ref=$ref running=$running want=$want"
  done
  wait_ready && check ready ok || check ready fail "not ready within ${READY_TIMEOUT}s"
  # rules need one evaluation and the scrape target one scrape before they are comparable
  t0="$(now)"
  while :; do
    post="$(snapshot)" || post=""
    if [ -n "$post" ] && jq -e --argjson pre "$pre" '.rules_not_ok == $pre.rules_not_ok and .targets_up == $pre.targets_up
      and (.watchdog | length) > 0' >/dev/null 2>&1 <<<"$post"; then break; fi
    [ $(($(now) - t0)) -ge "$SETTLE_TIMEOUT" ] && break
    sleep "$POLL"
  done
  [ -n "$post" ] || { check snapshot fail "Prometheus/Alertmanager API unreadable"; return 1; }
  local pv av
  pv="$(jq -r .prom_version <<<"$post")"; av="$(jq -r .am_version <<<"$post")"
  [ "v$pv" = "$(tag_of "$pref")" ] && check prometheus-version ok "$pv" || check prometheus-version fail "$pv"
  [ "v$av" = "$(tag_of "$aref")" ] && check alertmanager-version ok "$av" || check alertmanager-version fail "$av"
  for c in rules targets targets_up receivers; do
    if jq -e --argjson pre "$pre" --arg k "$c" '.[$k] == $pre[$k]' >/dev/null <<<"$post"; then
      check "$c-parity" ok "$(jq -r --arg k "$c" '.[$k] | length' <<<"$post") items"
    else
      check "$c-parity" fail "$(jq -rc --argjson pre "$pre" --arg k "$c" '{missing: ($pre[$k] - .[$k]), new: (.[$k] - $pre[$k])}' <<<"$post")"
    fi
  done
  jq -e --argjson pre "$pre" '(.rules_not_ok - $pre.rules_not_ok) == []' >/dev/null <<<"$post" \
    && check rules-health ok "not ok: $(jq -c .rules_not_ok <<<"$post") (before: $(jq -c .rules_not_ok <<<"$pre"))" \
    || check rules-health fail "$(jq -c .rules_not_ok <<<"$post")"
  jq -e --argjson pre "$pre" '($pre.silences - .silences) == []' >/dev/null <<<"$post" \
    && check silences-kept ok "$(jq -r '.silences | length' <<<"$post") active" \
    || check silences-kept fail "lost $(jq -c --argjson pre "$pre" '$pre.silences - .silences' <<<"$post")"
  watchdog_clear "$post" && check watchdog-unsilenced ok || check watchdog-unsilenced fail "$(jq -c .watchdog <<<"$post")"
  loopback_only && check loopback-only ok || check loopback-only fail
  msg="$(test_alert "$rid")" && check test-alert ok "$msg" || check test-alert fail "$msg"
  msg="$(resolve_test_alert "$rid")" && check test-alert-resolved ok "$msg" || check test-alert-resolved fail "$msg"
  [ "${#GATE_FAILS[@]}" -eq 0 ]
}

refuse() { log "REFUSED: $*"; exit 4; }

# daemon_log_defaults SIG_OLD SIG_NEW -> rc 0 when the only difference is that the old container had no log options
# and the new one has exactly the daemon's default "log-opts" (dockerd adds them to every container created after
# daemon.json set them; `docker run` cannot ask for "none"). Any other log difference stays a signature failure.
DOCKER_DAEMON_JSON="${DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
daemon_log_defaults() {
  local d
  d="$(jq -c '."log-opts" // {}' "$DOCKER_DAEMON_JSON" 2>/dev/null)" || return 1
  jq -n -e --argjson o "$1" --argjson n "$2" --argjson d "$d" \
    '$d != {} and $o.log.Config == {} and $n.log.Type == $o.log.Type and ($o | .log.Config = $d) == $n' >/dev/null 2>&1
}

# switch_to PROM_REF AM_REF PRE RUNID LABEL -> recreate what differs, gate; rc 0 PASS
switch_to() {
  local pref="$1" aref="$2" pre="$3" id="$4" label="$5" did=()
  if [ "$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$AM_CONTAINER")" != "$aref" ]; then
    recreate "$AM_CONTAINER" "$aref" || return 1; did+=("$AM_CONTAINER")
  fi
  if [ "$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$PROM_CONTAINER")" != "$pref" ]; then
    recreate "$PROM_CONTAINER" "$pref" || return 1; did+=("$PROM_CONTAINER")
  fi
  local c sig_old sig_new bad=0
  for c in "${did[@]}"; do
    sig_old="$(cat "$STATE_DIR/sig.$c")"; sig_new="$(signature "$c")"
    if [ -n "$sig_old" ] && [ "$sig_old" = "$sig_new" ]; then printf '  CHECK %-22s ok\n' "$c-signature"
    elif [ -n "$sig_old" ] && daemon_log_defaults "$sig_old" "$sig_new"; then
      printf '  CHECK %-22s ok (log options = daemon.json log-opts defaults, applied by dockerd to the new container)\n' "$c-signature"
    else printf '  CHECK %-22s FAIL %s\n' "$c-signature" "$(diff <(jq . <<<"$sig_old") <(jq . <<<"$sig_new") | tr '\n' ' ')"; bad=1; fi
  done
  log "$label gate"
  gate "$pre" "$pref" "$aref" "$id" && [ "$bad" -eq 0 ]
}

# drop_old -> remove the kept previous containers after a PASS (volumes are referenced by name and kept)
drop_old() {
  local c
  for c in "$PROM_CONTAINER" "$AM_CONTAINER"; do
    "${DOCKER[@]}" rm -f "$c-premonupgrade" >/dev/null 2>&1 && log "  removed $c-premonupgrade" || true
  done
}

# back_out -> put every kept previous container back (automatic rollback of a failed switch)
back_out() {
  local c
  for c in "$AM_CONTAINER" "$PROM_CONTAINER"; do
    if "${DOCKER[@]}" inspect "$c-premonupgrade" >/dev/null 2>&1; then
      restore_old "$c" && log "  restored previous $c" || log "  ERROR: could not restore previous $c"
    fi
  done
}

guards() { # guards YES -> exit 4 on any refusal
  [ "$1" = 1 ] || refuse "--yes missing"
  [ "$(id -u)" = 0 ] || [ "${PFT_MU_ALLOW_NONROOT:-0}" = 1 ] || refuse "run as root"
  [ -x "$PFT_MAINT_BIN" ] && "$PFT_MAINT_BIN" active >/dev/null 2>&1 || refuse "no active pft-maint window"
  local why
  why="$(isolation)" || refuse "alert routing not isolated: $why"
  "${DOCKER[@]}" inspect "$PROM_CONTAINER-premonupgrade" >/dev/null 2>&1 && refuse "$PROM_CONTAINER-premonupgrade exists (earlier run not finished)"
  "${DOCKER[@]}" inspect "$AM_CONTAINER-premonupgrade" >/dev/null 2>&1 && refuse "$AM_CONTAINER-premonupgrade exists (earlier run not finished)"
  api "$PROM_URL/-/ready" >/dev/null 2>&1 && api "$AM_URL/-/ready" >/dev/null 2>&1 || refuse "Prometheus/Alertmanager not ready"
  return 0
}

trap_int() { INTERRUPTED=1; }

do_switch() { # do_switch MODE PROM_REF AM_REF -> exit code
  local mode="$1" pref="$2" aref="$3" pre id rc
  id="$(date -u +%Y%m%dT%H%M%SZ)-$mode"
  pre="$(snapshot)" || refuse "Prometheus/Alertmanager API unreadable"
  watchdog_clear "$pre" || refuse "watchdog $WATCHDOG not active or silenced: $(jq -c .watchdog <<<"$pre")"
  install -d -m 700 "$STATE_DIR/backup/$id" || { log "ERROR: cannot create $STATE_DIR/backup/$id"; return 64; }
  "${DOCKER[@]}" inspect "$PROM_CONTAINER" "$AM_CONTAINER" >"$STATE_DIR/backup/$id/inspect.json"
  cp "$ALERTS_DIR/prometheus.yml" "$ALERTS_DIR/alertmanager.yml" "$STATE_DIR/backup/$id/"
  json "$AM_URL/api/v2/silences" >"$STATE_DIR/backup/$id/silences.json"
  printf '%s\n' "$pre" >"$STATE_DIR/backup/$id/snapshot.json"
  (cd "$STATE_DIR/backup/$id" && sha256sum inspect.json prometheus.yml alertmanager.yml silences.json snapshot.json >SHA256SUMS)
  log "backup $id: inspect, prometheus.yml, alertmanager.yml, silences ($(jq -r '.silences | length' <<<"$pre") active), snapshot (rules $(jq -r '.rules | length' <<<"$pre"), targets $(jq -r '.targets | length' <<<"$pre"))"
  local prev_p prev_a
  prev_p="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$PROM_CONTAINER")"
  prev_a="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$AM_CONTAINER")"
  INTERRUPTED=0; trap trap_int INT TERM
  if switch_to "$pref" "$aref" "$pre" "$id" "$mode" && [ "$INTERRUPTED" = 0 ]; then
    trap - INT TERM
    drop_old
    jq -n --arg at "$(date -u +%FT%TZ)" --arg m "$mode" --arg pp "$prev_p" --arg pa "$prev_a" --arg cp "$pref" --arg ca "$aref" \
      --arg id "$id" '{at: $at, mode: $m, run: $id, previous: {prometheus: $pp, alertmanager: $pa}, current: {prometheus: $cp, alertmanager: $ca}}' \
      >"$STATE_DIR/state.json"
    log "RESULT: PASS - $mode: prometheus $prev_p -> $pref, alertmanager $prev_a -> $aref"
    return 0
  fi
  rc=1
  log "$mode FAILED (${GATE_FAILS[*]:-recreate/signature}$([ "$INTERRUPTED" = 1 ] && echo ", interrupted")): automatic rollback to the previous containers"
  back_out
  if wait_ready; then log "  previous containers ready"; else log "  ERROR: previous containers not ready"; rc=2; fi
  trap - INT TERM
  log "RESULT: FAIL - $mode rolled back (exit $rc)"
  return "$rc"
}

apply() {
  local plan_file="" yes=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --plan) plan_file="${2:?--plan FILE}"; shift 2 ;;
      --yes) yes=1; shift ;;
      *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
  done
  [ -n "$plan_file" ] || { echo "apply needs --plan FILE" >&2; exit 2; }
  log "pft-monupgrade apply"
  local p pref aref cp ca rp ra age
  p="$(jq -e -c . "$plan_file" 2>/dev/null)" || refuse "plan $plan_file unreadable"
  jq -e '.fails == [] and (.prometheus.target_digest | test("^sha256:[0-9a-f]{64}$")) and (.alertmanager.target_digest | test("^sha256:[0-9a-f]{64}$"))' \
    >/dev/null <<<"$p" || refuse "plan has failures or no pinned targets"
  pref="$PROM_REPO:$(jq -r .prometheus.target_tag <<<"$p")@$(jq -r .prometheus.target_digest <<<"$p")"
  aref="$AM_REPO:$(jq -r .alertmanager.target_tag <<<"$p")@$(jq -r .alertmanager.target_digest <<<"$p")"
  rp="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$PROM_CONTAINER" 2>/dev/null)" || refuse "$PROM_CONTAINER missing"
  ra="$("${DOCKER[@]}" inspect -f '{{.Config.Image}}' "$AM_CONTAINER" 2>/dev/null)" || refuse "$AM_CONTAINER missing"
  if [ "$rp" = "$pref" ] && [ "$ra" = "$aref" ]; then
    log "RESULT: NOTHING TO DO - both containers already run the plan targets ($pref, $aref)"; return 0
  fi
  [ "$yes" = 1 ] || refuse "--yes missing"
  age=$(( $(now) - $(date -u -d "$(jq -r .planned_at <<<"$p")" +%s) ))
  [ "$age" -le "$PLAN_MAX_AGE" ] || refuse "plan is ${age}s old (> PLAN_MAX_AGE $PLAN_MAX_AGE): run plan again"
  cp="$(current "$PROM_CONTAINER" "$PROM_REPO" | cut -f3)"; ca="$(current "$AM_CONTAINER" "$AM_REPO" | cut -f3)"
  [ "$rp" = "$pref" ] || [ "$cp" = "$(jq -r .prometheus.current_digest <<<"$p")" ] || refuse "prometheus changed since the plan (running $cp)"
  [ "$ra" = "$aref" ] || [ "$ca" = "$(jq -r .alertmanager.current_digest <<<"$p")" ] || refuse "alertmanager changed since the plan (running $ca)"
  local r
  for r in "$pref" "$aref"; do
    "${DOCKER[@]}" image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "${r%%:*}@${r#*@}" 2>/dev/null | grep -qxF "${r%%:*}@${r#*@}" \
      || refuse "target $r not in the image store with its digest (run plan)"
  done
  guards "$yes"
  do_switch apply "$pref" "$aref"
}

rollback() {
  local yes=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --yes) yes=1; shift ;;
      *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
  done
  log "pft-monupgrade rollback"
  local st pref aref
  st="$(jq -e -c . "$STATE_DIR/state.json" 2>/dev/null)" || refuse "no earlier apply recorded in STATE_DIR"
  [ "$(jq -r .mode <<<"$st")" = apply ] || { log "RESULT: NOTHING TO DO - the last change was already a rollback"; return 0; }
  pref="$(jq -r .previous.prometheus <<<"$st")"; aref="$(jq -r .previous.alertmanager <<<"$st")"
  guards "$yes"
  local r d
  for r in "$pref" "$aref"; do
    case "$r" in *@sha256:*) d="${r%%:*}@${r#*@}" ;; *) d="$r" ;; esac
    "${DOCKER[@]}" image inspect "$d" >/dev/null 2>&1 || refuse "previous image $r no longer in the image store"
  done
  do_switch rollback "$pref" "$aref"
}

case "${1:-}" in
  plan) shift; plan "$@"; exit $? ;;
  apply) shift; apply "$@"; exit $? ;;
  rollback) shift; rollback "$@"; exit $? ;;
  *) sed -n '3,36p' "$0"; exit 2 ;;
esac
