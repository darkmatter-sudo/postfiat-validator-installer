#!/usr/bin/env bash
# Publish the live text/JSON/Prometheus reports of both hosts (task_62b5fc29b42bbe4e484a03a450c97616): copy each
# host's last observation file (/var/lib/pft-upstreamwatch/last-obs.json, written by the hourly timer run) into
# upstreamwatch/reports/<host>/obs.json and render the three formats from it with the repo's helper, offline
# (`pft-upstreamwatch report --obs`, no network, no docker, no host config). drill/fresh-clone.sh re-renders them
# from a public clone and compares with cmp. Fails closed (writes nothing for a host) if the observation names this
# host, the admin user, a home path or an IPv4 address.
#   bash upstreamwatch/drill/reports.sh 2>&1 | tee LOG    (repo root, agent user with sudo + ssh relay)
set -uo pipefail
REPO="$(git rev-parse --show-toplevel)"; cd "$REPO" || exit 3
export TZ=UTC
ME="$(id -un)"; HN="$(hostname)"
R() { ssh -o LogLevel=ERROR -o BatchMode=yes relay "$@"; }
RHN="$(R hostname 2>/dev/null)"; RHN="${RHN:-$HN}"
OUT=upstreamwatch/reports
FAILS=0
echo "upstreamwatch reports - $(date -u +%FT%TZ) - repo HEAD $(git rev-parse HEAD)"
for h in validator sentry; do
  d="$OUT/$h"; tmp="$(mktemp -p "$HOME/.cache")"
  if [ "$h" = validator ]; then sudo -n cat /var/lib/pft-upstreamwatch/last-obs.json | cat > "$tmp"
  else R 'sudo -n cat /var/lib/pft-upstreamwatch/last-obs.json' > "$tmp"; fi
  if ! jq -e --arg h "$h" '.config.host == $h' "$tmp" >/dev/null; then
    echo "$h: observation missing or for another host"; FAILS=$((FAILS + 1)); rm -f "$tmp"; continue
  fi
  if grep -qE "$HN|$RHN|\\b$ME\\b|/home/|\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b" "$tmp"; then
    echo "$h: observation contains a host name, user, home path or IPv4 address; not published"
    FAILS=$((FAILS + 1)); rm -f "$tmp"; continue
  fi
  mkdir -p "$d"; mv -f "$tmp" "$d/obs.json"; chmod 644 "$d/obs.json"
  echo "$h: collected $(date -u -d "@$(jq -r .collected_epoch "$d/obs.json")" +%FT%TZ), sha256 $(sha256sum "$d/obs.json" | cut -c1-64)"
  for f in text json prom; do
    ext=$f; [ "$f" = text ] && ext=txt
    PFT_UW_CONF=/dev/null PFT_UW_LIB="$REPO/upstreamwatch/upstreamwatch_lib.py" \
      bash upstreamwatch/pft-upstreamwatch.sh report --obs "$d/obs.json" --format "$f" > "$d/report.$ext" \
      || { echo "$h: render $f failed"; FAILS=$((FAILS + 1)); }
  done
  sed 's/^/  /' "$d/report.txt"
done
echo "reports done $(date -u +%FT%TZ): $FAILS failure(s) -> $([ "$FAILS" = 0 ] && echo PASS || echo FAIL)"
[ "$FAILS" = 0 ]
