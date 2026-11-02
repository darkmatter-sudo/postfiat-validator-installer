#!/usr/bin/env bash
# recreate: re-create a `docker run` postfiatd container (the sentry) with exactly its current configuration, to prove
# that its node identity survives container re-creation. The run arguments come from its inspect JSON with
# ../../confine/pft-confine.sh's recreate_args program (name, restart and log policy, user, network, ports, volumes,
# env, image, cmd) plus the runtime profile read back from HostConfig (cap_drop/cap_add, read-only root, tmpfs,
# pids/memory limits, security_opt), so a confined container stays confined.
#   sudo bash recreate.sh [--dry-run] NAME
# Steps: inspect -> args; stop; rename to NAME-prerecreate-<ts> with restart=no (kept for rollback); docker run;
# compare a summary of the new container's config with the old one (must be identical apart from Id/Created);
# on any failure the new container is removed and the old one renamed back and started (exit 1; 5 if that fails).
# The old container is removed only after the summary matched and the new one is running (the caller then waits
# for server_state and checks pubkey_node).
# Exit codes: 0 re-created, 1 failed + restored, 2 error before any change, 3 usage, 5 restore failed.
# "A && B || C" is intended: C only reports and exits.
# shellcheck disable=SC2015
set -uo pipefail
DOCKER="${DOCKER:-docker}"
DRY=0; [ "${1:-}" = --dry-run ] && { DRY=1; shift; }
C="${1:-}"; [ -n "$C" ] || { echo "usage: sudo bash recreate.sh [--dry-run] NAME" >&2; exit 3; }
ts() { date -u +%FT%TZ; }
I="$("$DOCKER" inspect "$C" 2>/dev/null | jq '.[0]')" || { echo "$(ts) recreate: no container $C"; exit 2; }
[ -n "$I" ] && [ "$I" != null ] || { echo "$(ts) recreate: no container $C"; exit 2; }
jq -e '.Config.Labels["com.docker.compose.project"] == null' >/dev/null <<<"$I" \
  || { echo "$(ts) recreate: $C is a compose container (use docker compose up -d --force-recreate)"; exit 2; }
IMG="$(jq -r .Image <<<"$I")"
IENV="$("$DOCKER" image inspect "$IMG" 2>/dev/null | jq -c '.[0].Config.Env // []')" || IENV='[]'
TAG="$(jq -r .Config.Image <<<"$I")"
# docker run resolves the TAG: refuse if it now names a different image than the one running (that would be an
# upgrade, not a re-creation)
[ "$("$DOCKER" image inspect -f '{{.Id}}' "$TAG" 2>/dev/null)" = "$IMG" ] \
  || { echo "$(ts) recreate: tag $TAG no longer points at the running image ${IMG:7:12} - refusing"; exit 2; }

summary() { # INSPECT_JSON(.[0]) -> the config that must not change
  jq -S -c '{Name, Image, Cmd: .Config.Cmd, Entrypoint: .Config.Entrypoint, User: .Config.User, Env: .Config.Env,
    Mounts: [.Mounts[] | {Type, Name, Source, Destination, RW}] | sort_by(.Destination),
    Ports: .HostConfig.PortBindings, Restart: .HostConfig.RestartPolicy, Log: .HostConfig.LogConfig,
    Network: .HostConfig.NetworkMode, CapAdd: .HostConfig.CapAdd, CapDrop: .HostConfig.CapDrop,
    ReadonlyRootfs: .HostConfig.ReadonlyRootfs, Tmpfs: .HostConfig.Tmpfs, PidsLimit: .HostConfig.PidsLimit,
    Memory: .HostConfig.Memory, MemorySwap: .HostConfig.MemorySwap, SecurityOpt: .HostConfig.SecurityOpt}' <<<"$1"
}
# shellcheck disable=SC2016 # jq program
args() { # INSPECT_JSON IMAGE_ENV_JSON -> one docker-run arg per line; profile flags first, image + cmd last
  jq -r '
    (.HostConfig.CapDrop // [])[] | "--cap-drop=\(.)"' <<<"$1"
  jq -r '(.HostConfig.CapAdd // [])[] | "--cap-add=\(.)"' <<<"$1"
  jq -r 'if .HostConfig.ReadonlyRootfs then "--read-only" else empty end' <<<"$1"
  jq -r '(.HostConfig.Tmpfs // {}) | to_entries[] | "--tmpfs=\(.key)\(if .value != "" then ":" + .value else "" end)"' <<<"$1"
  jq -r 'if (.HostConfig.PidsLimit // 0) > 0 then "--pids-limit=\(.HostConfig.PidsLimit)" else empty end' <<<"$1"
  jq -r 'if (.HostConfig.Memory // 0) > 0 then "--memory=\(.HostConfig.Memory)" else empty end' <<<"$1"
  jq -r 'if (.HostConfig.MemorySwap // 0) != 0 then "--memory-swap=\(.HostConfig.MemorySwap)" else empty end' <<<"$1"
  jq -r '(.HostConfig.SecurityOpt // [])[] | "--security-opt=\(.)"' <<<"$1"
  # the rest is pft-confine's recreate_args program (confine/pft-confine.sh), unchanged
  jq -r --argjson ienv "$2" '
    "--name=\(.Name[1:])",
    "--restart=\(.HostConfig.RestartPolicy.Name)\(if .HostConfig.RestartPolicy.Name == "on-failure" then ":\(.HostConfig.RestartPolicy.MaximumRetryCount)" else "" end)",
    (if (.Config.User // "") != "" then "--user=\(.Config.User)" else empty end),
    "--log-driver=\(.HostConfig.LogConfig.Type)",
    ((.HostConfig.LogConfig.Config // {}) | to_entries[] | "--log-opt=\(.key)=\(.value)"),
    (if .HostConfig.NetworkMode != "default" then "--network=\(.HostConfig.NetworkMode)" else empty end),
    ((.HostConfig.PortBindings // {}) | to_entries[] | .key as $k | .value[]
      | "--publish=\(if .HostIp != "" then .HostIp + ":" else "" end)\(.HostPort):\($k | sub("/tcp$"; ""))"),
    (.Mounts[] | if .Type == "volume" then "--volume=\(.Name):\(.Destination)\(if .RW then "" else ":ro" end)"
                 elif .Type == "bind" then "--volume=\(.Source):\(.Destination)\(if .RW then "" else ":ro" end)"
                 else empty end),
    (.Config.Env // [] | map(select(. as $e | $ienv | index($e) | not)) | .[] | "--env=\(.)"),
    .Config.Image, (.Config.Cmd // [])[]' <<<"$1"
}
mapfile -t ARGS < <(args "$I" "$IENV")
red() { sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/<redacted-ip>/g; s#--volume=[0-9a-f]{64}:#--volume=<anonymous volume>:#'; }
echo "$(ts) recreate: $C image ${IMG:7:12}, ${#ARGS[@]} run args:"
printf '  %s\n' "${ARGS[@]}" | red
BEFORE="$(summary "$I")"
[ "$DRY" = 1 ] && { echo "$(ts) recreate: dry run, nothing changed"; exit 0; }

OLD="$C-prerecreate-$(date -u +%Y%m%dT%H%M%SZ)"
restore_old() {
  "$DOCKER" rm -f "$C" >/dev/null 2>&1
  "$DOCKER" rename "$OLD" "$C" && "$DOCKER" update --restart "$(jq -r .HostConfig.RestartPolicy.Name <<<"$I")" "$C" >/dev/null \
    && "$DOCKER" start "$C" >/dev/null && { echo "$(ts) recreate: FAILED, old container restored and started"; exit 1; }
  echo "$(ts) recreate: FAILED and the restore failed too"; exit 5
}
"$DOCKER" stop -t 60 "$C" >/dev/null || { echo "$(ts) recreate: stop failed"; exit 2; }
"$DOCKER" update --restart no "$C" >/dev/null && "$DOCKER" rename "$C" "$OLD" || { "$DOCKER" start "$C" >/dev/null; echo "$(ts) recreate: rename failed, old started again"; exit 1; }
echo "$(ts) recreate: stopped, kept as $OLD (restart=no)"
NEWID="$("$DOCKER" run -d "${ARGS[@]}")" || { echo "$(ts) recreate: docker run failed"; restore_old; }
echo "$(ts) recreate: new container ${NEWID:0:12} started (old ${OLD##*-})"
AFTER="$("$DOCKER" inspect "$C" | jq '.[0]')"
if [ "$(summary "$AFTER")" != "$BEFORE" ]; then
  echo "$(ts) recreate: config summary differs:"; diff <(jq -S . <<<"$BEFORE") <(summary "$AFTER" | jq -S .) | red | sed 's/^/  /'
  restore_old
fi
echo "$(ts) recreate: config summary identical (image, cmd, user, env, mounts, ports, restart/log policy, network, caps, read-only, tmpfs, pids/memory limits, security_opt)"
[ "$(jq -r .Id <<<"$AFTER")" != "$(jq -r .Id <<<"$I")" ] && echo "$(ts) recreate: container Id changed ${I:0:0}$(jq -r '.Id[0:12]' <<<"$I") -> $(jq -r '.Id[0:12]' <<<"$AFTER") (a new container, not a restart)"
"$DOCKER" rm "$OLD" >/dev/null && echo "$(ts) recreate: old container $OLD removed (volumes kept)"
exit 0
