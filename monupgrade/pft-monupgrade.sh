#!/usr/bin/env bash
# pft-monupgrade: reversible upgrades of the pinned Prometheus + Alertmanager images of the loopback monitoring
# stack (../alerts/run-stack.sh: containers pft-prometheus, pft-alertmanager; `docker run`, no compose file).
#
# Usage: pft-monupgrade plan [--out FILE] [--no-pull]
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
#         RepoDigests must contain it.
#         Exit: 0 an upgrade is available and every target check passed; 3 nothing to upgrade (both current);
#         4 a target check failed (reasons listed); 1 error (reasons listed); 2 usage.
#         Every failure prints `FAIL <image> reason=<name>`, names: container-missing, current-unpinned,
#         hub-unreachable, no-target, pull-failed, digest-mismatch, promtool-check-config, promtool-check-rules,
#         promtool-test-rules, amtool-check-config (a CONTROL failure prints `CONTROL-FAIL` with the same names).
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
  declare -A ref id dig tag ttag tdig tpushed
  local names=(prometheus alertmanager) cont=("$PROM_CONTAINER" "$AM_CONTAINER") repos=("$PROM_REPO" "$AM_REPO")
  local overrides=("${TARGET_PROM:-}" "${TARGET_AM:-}") n line
  for i in 0 1; do
    n="${names[$i]}"
    if ! line="$(current "${cont[$i]}" "${repos[$i]}")"; then
      fail "$n" container-missing "${cont[$i]}"; continue
    fi
    IFS=$'\t' read -r a b c <<<"$line"
    ref[$n]="$a"; id[$n]="$b"; dig[$n]="$c"
    tag[$n]="$(tag_of "${ref[$n]}")"
    printf 'CURRENT %-12s container=%s ref=%s id=%s digest=%s\n' "$n" "${cont[$i]}" "${ref[$n]}" "${id[$n]}" "${dig[$n]}"
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

case "${1:-}" in
  plan) shift; plan "$@"; exit $? ;;
  *) sed -n '2,30p' "$0"; exit 2 ;;
esac
