#!/usr/bin/env bash
# Two-host fake for `pft-patch run` (sourced by run-tests.sh after stubs.sh). mk_run DIR builds:
#   DIR/sentry, DIR/validator   one mk_env host each (root, s, bin); DIR/<host>/s also holds node/gate state:
#                 info (server_info JSON), started (container StartedAt), down_polls (N polls answer "connected"),
#                 integrity_warn, audit_fail, egress_fail, restart_fail, ssh_down, ssh_down_after_reboot
#   DIR/rbin      ssh sudo docker pft-integrity pft-audittrail pft-egress pft-maint systemctl systemd-run curl pft-patch
#   DIR/calls     every stub call as "<host>: <command line>", in order
#   DIR/hosts.conf  sentry over ssh (first), validator local
# The ssh stub runs the remote command with the sentry's environment; local commands use the validator's.
# A `systemd-run ... systemctl reboot` stub "reboots" at once: new boot id, reboot flag cleared, container restarted.
# shellcheck disable=SC2016,SC2034

host_env() { # DIR HOST -> export that host's tool/stub environment
  export STUB_HOST="$2" STUB_S="$1/$2/s" PFT_PATCH_ROOT="$1/$2/root"
  export PFT_PATCH_APT_GET="$1/$2/bin/apt-get" PFT_PATCH_APT_CONFIG="$1/$2/bin/apt-config" PFT_PATCH_APT_MARK="$1/$2/bin/apt-mark"
  export PFT_PATCH_DPKG_QUERY="$1/$2/bin/dpkg-query" PFT_PATCH_NEEDRESTART="$1/$2/bin/needrestart"
}

mk_run() {
  local d="$1" h b
  mk_env "$d/sentry"; mk_env "$d/validator"; mkdir -p "$d/rbin" "$d/state"; : > "$d/calls"; echo 1793235000 > "$d/now"
  for h in sentry validator; do
    echo '{"server_state":"full","peers":12,"validated_ledger":{"age":2,"seq":7570500}}' > "$d/$h/s/info"
    echo "2026-10-28T10:00:00.000000000Z" > "$d/$h/s/started"
  done
  printf 'host sentry    ssh   relay  postfiatd-sentry  5\nhost validator local -      postfiatd         5\npost sentry pft-egress reapply --container postfiatd-sentry\n' > "$d/hosts.conf"
  rec='echo "$STUB_HOST: $(basename "$0") $*" >> "$RUN_D/calls"; S="$RUN_D/$STUB_HOST/s"'
  b="$d/rbin"
  cat > "$b/ssh" <<B
#!/usr/bin/env bash
while [ "\$1" = -o ]; do shift 2; done
t="\$1"; shift
[ "\$t" = relay ] || { echo "ssh: unknown host \$t" >&2; exit 255; }
[ -e "\$RUN_D/sentry/s/ssh_down" ] && { echo "ssh: connect to host relay port 22: Connection refused" >&2; exit 255; }
$(declare -f host_env)
host_env "\$RUN_D" sentry
exec bash -c "\$*"
B
  printf '#!/usr/bin/env bash\n[ "$1" = -n ] && shift\nexec "$@"\n' > "$b/sudo"
  cat > "$b/docker" <<B
#!/usr/bin/env bash
$rec
case "\$1" in
  exec)
    [ -f "\$S/info" ] || exit 1
    n="\$(cat "\$S/down_polls" 2>/dev/null || echo 0)"
    if [ "\$n" -gt 0 ]; then echo \$((n - 1)) > "\$S/down_polls"; echo '{"result":{"info":{"server_state":"connected","peers":3}}}'; exit 0; fi
    jq -c '{result:{info:.}}' "\$S/info" ;;
  inspect) cat "\$S/started" ;;
esac
B
  cat > "$b/pft-integrity" <<B
#!/usr/bin/env bash
$rec
if [ -e "\$S/integrity_warn" ]; then echo "  [WARN] sshd:effective changed: sha256"; echo "RESULT: WARN - 49 unchanged, 1 warn, 0 fail -> exit 1"; exit 1; fi
echo "RESULT: PASS - 50 unchanged, 0 warn, 0 fail -> exit 0"
B
  printf '#!/usr/bin/env bash\n%s\n[ ! -e "$S/audit_fail" ]\n' "$rec" > "$b/pft-audittrail"
  printf '#!/usr/bin/env bash\n%s\n[ "$1" = check ] && [ -e "$S/egress_fail" ] && exit 1\nexit 0\n' "$rec" > "$b/pft-egress"
  cat > "$b/pft-maint" <<B
#!/usr/bin/env bash
$rec
case "\$1" in
  lock) [ -e "\$S/lock" ] && { echo "acct 2026-10-30T00:38:00Z snapshot"; exit 0; }; echo "no data-collection locks" ;;
  start) [ -e "\$S/maint_fail" ] && { echo "refused"; exit 4; }; echo "window started" ;;
  end) echo "window ended" ;;
esac
B
  printf '#!/usr/bin/env bash\n%s\n[ "$1" = restart ] && [ -e "$S/restart_fail" ] && exit 1\nexit 0\n' "$rec" > "$b/systemctl"
  cat > "$b/systemd-run" <<B
#!/usr/bin/env bash
$rec
case "\$*" in *"systemctl reboot"*)
  echo "boot-\$RANDOM\$RANDOM" > "\$PFT_PATCH_ROOT/proc/sys/kernel/random/boot_id"
  rm -f "\$PFT_PATCH_ROOT/var/run/reboot-required" "\$PFT_PATCH_ROOT/var/run/reboot-required.pkgs"
  sed -i 's/KSTA: [23]/KSTA: 1/' "\$S/nr"
  echo "2026-10-29T02:00:00.000000000Z" > "\$S/started"
  [ -e "\$S/ssh_down_after_reboot" ] && touch "\$S/ssh_down"
  [ -e "\$S/down_after_reboot" ] && echo 2 > "\$S/down_polls" ;;
esac
exit 0
B
  cat > "$b/curl" <<'B'
#!/usr/bin/env bash
m=GET; u=""; for a; do [ "$p" = -X ] && m="$a"; case "$a" in http*) u="$a" ;; esac; p="$a"; done
echo "$STUB_HOST: curl $m $u $(printf '%s ' "$@" | grep -o '"id":"[^"]*"')" >> "$RUN_D/calls"
[ -e "$RUN_D/am_fail" ] && exit 7
[ "$m" = POST ] && echo '{"silenceID":"sil0123456789"}'
exit 0
B
  printf '#!/usr/bin/env bash\n%s\nexec bash "$PATCH_TOOL" "$@"\n' "$rec" > "$b/pft-patch"
  chmod +x "$b/"*
}

use_run() { # DIR TOOL -> orchestrator environment (runs as the validator)
  export RUN_D="$1" PATCH_TOOL="$2" CONF="$1/hosts.conf" STATE_DIR="$1/state" PFT_PATCH_NOW_FILE="$1/now"
  export PFT_PATCH_SSH="$1/rbin/ssh" PATCH_CMD=pft-patch AM="http://am.test:9093" PFT_PATCH_NOROOT=1
  export PATH="$1/rbin:$ORIG_PATH" POLL_SEC=10 GATE_TIMEOUT=120 REBOOT_TIMEOUT=60 SILENCE_TAIL=900
  unset PFT_PATCH_INJECT MAINT_HOST BOOT_ID_FILE
  host_env "$1" validator
}
