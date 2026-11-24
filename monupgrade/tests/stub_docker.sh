#!/usr/bin/env bash
# Stub `docker` for pft-monupgrade tests. Every call is appended to $STUB_DIR/calls (one line, args joined by spaces).
# Knobs (env): STUB_MISSING=<container>   inspect of that container fails
#              STUB_REF_PROM / STUB_REF_AM  Config.Image of pft-prometheus / pft-alertmanager
#              STUB_FAIL_PULL=1             every pull fails
#              STUB_MISMATCH=1              image inspect of a pulled ref reports another digest
#              STUB_FAIL_RUN="<regex>"      `run` calls whose joined args match the regex exit 1 with an error line
set -u
printf '%s\n' "$*" >>"$STUB_DIR/calls"
P_DIG=sha256:1111111111111111111111111111111111111111111111111111111111111111
A_DIG=sha256:2222222222222222222222222222222222222222222222222222222222222222
case "$1" in
  inspect)
    name="${*: -1}"
    [ "$name" = "${STUB_MISSING:-}" ] && { echo "Error: No such object: $name" >&2; exit 1; }
    case "$name:$3" in
      pft-prometheus:'{{.Config.Image}}') echo "${STUB_REF_PROM:-prom/prometheus:v3.5.0}" ;;
      pft-prometheus:'{{.Image}}') echo "$P_DIG" ;;
      pft-alertmanager:'{{.Config.Image}}') echo "${STUB_REF_AM:-prom/alertmanager:v0.28.1}" ;;
      pft-alertmanager:'{{.Image}}') echo "$A_DIG" ;;
      *) exit 1 ;;
    esac ;;
  image)
    ref="${*: -1}"
    case "$ref" in
      "$P_DIG") echo "prom/prometheus@$P_DIG" ;;
      "$A_DIG") echo "prom/alertmanager@$A_DIG" ;;
      *@sha256:*)
        grep -q "@${ref#*@}\$" "$STUB_DIR/pulled" 2>/dev/null || { echo "Error: No such image: $ref" >&2; exit 1; }
        if [ "${STUB_MISMATCH:-0}" = 1 ]; then echo "${ref%%@*}@sha256:$(printf '9%.0s' {1..64})"; else echo "$ref"; fi ;;
      *) exit 1 ;;
    esac ;;
  pull)
    [ "${STUB_FAIL_PULL:-0}" = 1 ] && { echo "Error response from daemon: manifest unknown" >&2; exit 1; }
    printf '%s\n' "$*" >>"$STUB_DIR/pulled"; echo "${*: -1}" ;;
  run)
    if [ -n "${STUB_FAIL_RUN:-}" ] && [[ "$*" =~ $STUB_FAIL_RUN ]]; then echo "FAILED: error: stub failure"; exit 1; fi
    case "$*" in
      *"test rules"*) echo "  SUCCESS" ;;
      *) echo "  SUCCESS: checked" ;;
    esac ;;
  *) echo "stub: unexpected docker $*" >&2; exit 99 ;;
esac
