#!/usr/bin/env bash
# Stub commands for run-tests.sh. Sourced; mk_env DIR builds a fake host in DIR:
#   DIR/root      PFT_DOCKERD_ROOT (files that exist on the fake host)
#   DIR/s         stub state (info.json, loaded.json, containers, rules, enabled, perms, ss, ipt, group, calls)
#   DIR/bin       one executable per stubbed command
# The fake dockerd "loads" root/etc/docker/daemon.json into s/loaded.json on restart (all keys) and on reload
# (live-restore only, like the real daemon). A restart with live-restore off in loaded.json restarts every
# container (new StartedAt), which is what the health gate must catch.
# shellcheck disable=SC2016

mk_env() {
  local d="$1" b
  mkdir -p "$d/root/etc/docker" "$d/root/usr/bin" "$d/root/run/containerd" "$d/root/lib/systemd/system" \
    "$d/root/etc/audit/rules.d" "$d/s" "$d/bin"
  for b in dockerd containerd containerd-shim-runc-v2 runc; do : > "$d/root/usr/bin/$b"; done
  : > "$d/root/run/containerd/containerd.sock"; : > "$d/root/lib/systemd/system/docker.service"
  : > "$d/root/lib/systemd/system/docker.socket"; : > "$d/root/run/docker.sock"
  cat > "$d/s/info.json" <<'J'
{"LiveRestoreEnabled":false,"ExperimentalBuild":false,"SecurityOptions":["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"],
 "Swarm":{"LocalNodeState":"inactive"},"RegistryConfig":{"InsecureRegistryCIDRs":["::1/128","127.0.0.0/8"],"IndexConfigs":{"docker.io":{"Name":"docker.io","Secure":true}}}}
J
  echo '{}' > "$d/s/loaded.json"
  printf 'c1 /postfiatd 2026-10-28T11:33:11.2Z\nc2 /pft-prometheus 2026-10-26T07:37:48.8Z\n' > "$d/s/containers"
  printf -- '-w /usr/bin/dockerd -p wa -k pft-docker\n-w /etc/docker -p wa -k pft-docker\n-w /usr/bin/containerd -p wa -k pft-docker\n' > "$d/s/rules"
  echo 1 > "$d/s/enabled"
  cat > "$d/s/perms" <<'P'
/lib/systemd/system/docker.service 644 root:root
/lib/systemd/system/docker.socket 644 root:root
/etc/docker 755 root:root
/run/docker.sock 660 root:docker
/etc/docker/daemon.json 644 root:root
/run/containerd/containerd.sock 660 root:root
P
  echo 'LISTEN 0 4096 0.0.0.0:2559 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))' > "$d/s/ss"
  printf -- '-N DOCKER-USER\n-A DOCKER-USER -p tcp --dport 2559 -j PFT-RL\n' > "$d/s/ipt"
  echo 'docker:x:999:' > "$d/s/group"
  echo full > "$d/s/state"
  : > "$d/s/calls"

  cat > "$d/bin/docker" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "docker $*" >> "$S/calls"
case "$1" in
  info) [ -f "$S/down" ] && exit 1
        jq -c --slurpfile l "$S/loaded.json" '.LiveRestoreEnabled = ($l[0]["live-restore"] // false)' "$S/info.json" ;;
  ps) awk '{print $1}' "$S/containers" ;;
  inspect) [ "$2" = -f ] && awk -v id="$4" '$1==id{print $2, $3}' "$S/containers" || grep -q " /$2 " "$S/containers" ;;
  *) exit 0 ;;
esac
B
  cat > "$d/bin/dockerd" <<'B'
#!/usr/bin/env bash
# dockerd --validate --config-file F: unknown keys fail like the real daemon
[ "$1" = --validate ] || exit 2
bad="$(jq -r 'keys[] | select(IN("live-restore","no-new-privileges","log-driver","log-opts","icc","userland-proxy","userns-remap","hosts","iptables","debug","insecure-registries")|not)' "$3")" || { echo "invalid JSON"; exit 1; }
[ -z "$bad" ] && { echo "configuration OK"; exit 0; }
echo "unable to configure the Docker daemon with file $3: the following directives don't match any configuration option: $bad"; exit 1
B
  cat > "$d/bin/systemctl" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; R="$PFT_DOCKERD_ROOT"; echo "systemctl $*" >> "$S/calls"
cur() { if [ -f "$R/etc/docker/daemon.json" ]; then cat "$R/etc/docker/daemon.json"; else echo '{}'; fi; }
case "$1" in
  reload) jq --argjson n "$(cur)" '. + {"live-restore": ($n["live-restore"] // false)}' "$S/loaded.json" > "$S/l.tmp" && mv "$S/l.tmp" "$S/loaded.json" ;;
  restart)
    [ -f "$S/restart_fails" ] && { touch "$S/down"; exit 1; }
    rm -f "$S/down"
    if [ "$(jq -r '."live-restore" // false' "$S/loaded.json")" != true ] || [ -f "$S/kill_on_restart" ]; then
      awk '{print $1, $2, "2099-01-01T00:00:00Z"}' "$S/containers" > "$S/c.tmp" && mv "$S/c.tmp" "$S/containers"
      rm -f "$S/kill_on_restart"
    fi
    cur > "$S/loaded.json" ;;
esac
B
  cat > "$d/bin/auditctl" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; case "$1" in -l) cat "$S/rules" ;; -s) echo "enabled $(cat "$S/enabled")" ;; esac
B
  cat > "$d/bin/augenrules" <<'B'
#!/usr/bin/env bash
S="$STUB_S"; echo "augenrules $*" >> "$S/calls"
[ "$(cat "$S/enabled")" = 2 ] && exit 1
grep '^-w' "$PFT_DOCKERD_ROOT/etc/audit/rules.d/pft-dockerd.rules" >> "$S/rules"
B
  cat > "$d/bin/ss" <<'B'
#!/usr/bin/env bash
cat "$STUB_S/ss"
B
  cat > "$d/bin/iptables" <<'B'
#!/usr/bin/env bash
cat "$STUB_S/ipt"
B
  cat > "$d/bin/stat" <<'B'
#!/usr/bin/env bash
# stat -L -c FMT PATH: answer from s/perms for paths that exist under the fake root
p="${4#"$PFT_DOCKERD_ROOT"}"; [ -e "$4" ] || exit 1
l="$(awk -v p="$p" '$1==p{print $2, $3}' "$STUB_S/perms")"; [ -n "$l" ] && echo "$l" || echo "644 root:root"
B
  cat > "$d/bin/getent" <<'B'
#!/usr/bin/env bash
cat "$STUB_S/group"
B
  cat > "$d/bin/pgrep" <<'B'
#!/usr/bin/env bash
echo "123 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock $(cat "$STUB_S/extra_args" 2>/dev/null)"
B
  cat > "$d/bin/rpc" <<'B'
#!/usr/bin/env bash
cat "$STUB_S/state"
B
  chmod +x "$d/bin/"*
}

use_env() { # DIR -> exports for the tool
  local d="$1"
  export STUB_S="$d/s" PFT_DOCKERD_ROOT="$d/root" PFT_DOCKERD_DOCKER="$d/bin/docker" PFT_DOCKERD_DOCKERD="$d/bin/dockerd" \
    PFT_DOCKERD_SYSTEMCTL="$d/bin/systemctl" PFT_DOCKERD_AUDITCTL="$d/bin/auditctl" PFT_DOCKERD_AUGENRULES="$d/bin/augenrules" \
    PFT_DOCKERD_SS="$d/bin/ss" PFT_DOCKERD_IPT="$d/bin/iptables" PFT_DOCKERD_STAT="$d/bin/stat" PFT_DOCKERD_GETENT="$d/bin/getent" \
    PFT_DOCKERD_PGREP="$d/bin/pgrep" PFT_DOCKERD_RPC="$d/bin/rpc" RELOAD_WAIT=0 POLL_SEC=0.3 HEALTH_BUDGET=1 CONTAINER=postfiatd \
    AUDIT_RULES="$d/root/etc/audit/rules.d/pft-dockerd.rules" BACKUP_DIR="$d/root/var/lib/pft-dockerd"
}
