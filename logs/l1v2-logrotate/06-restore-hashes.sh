#!/usr/bin/env bash
# Evidence helper for postfiatorg/postfiatl1v2 PR #260: run the PR's install.sh in a
# private user + mount namespace (unshare -rm, scratch /etc/logrotate.d, /var/log, ...)
# and print sha256sum of every rule file before install.sh and after it refuses, plus the
# exact `^error: .*postfiat` lines its full-config dry run matched.
#   06-restore-hashes.sh TREE   (TREE = checkout of the PR head)
# Cases:
#   generic+fleet  example as /etc/logrotate.d/postfiat + the fleet event rules (pre-check refusal)
#   generic        example only (install.sh writes 3 rules, post-check fails, restore = remove)
#   logonly+fleet  a rule owning only */*.log + the fleet event rules: pre-check passes,
#                  install.sh writes postfiat-service-output and edits both fleet rules,
#                  post-check fails, restore must put both fleet rules back byte for byte
set -euo pipefail

if [ "${1:-}" = __ns ]; then
  TREE=$2 S=$3
  umask 022
  for p in etc/logrotate.d etc/logrotate.conf etc/systemd etc/passwd etc/group var/log var/lib/logrotate; do
    mount --bind "$S/$p" "/$p"
  done
  systemctl() { echo "systemctl $*" >>"$S/calls"; [ "$1" != is-active ] || echo active; }
  journalctl() { echo "journalctl $*" >>"$S/calls"; }
  export -f systemctl journalctl
  export S
  fail=0
  hashes() { # every file in /etc/logrotate.d, plus the three validator-host rule paths
    local r
    (cd /etc/logrotate.d && find . -type f -print0 | sort -z | xargs -0r sha256sum | sed 's# \./# /etc/logrotate.d/#')
    for r in postfiat-service-output postfiat-rpc-events postfiat-validator-events; do
      [ -e "/etc/logrotate.d/$r" ] || echo "(absent)  /etc/logrotate.d/$r"
    done
  }
  # install.sh's dry runs call logrotate: record the rule-file hashes at each call, so the
  # post-write state that the restore undoes is shown too.
  logrotate() { echo "--- at logrotate call $(($(cat "$S/ncalls" 2>/dev/null || echo 0) + 1))" >>"$S/mid"; hashes >>"$S/mid"; echo $(($(cat "$S/ncalls" 2>/dev/null || echo 0) + 1)) >"$S/ncalls"; command logrotate "$@"; }
  export -f hashes logrotate
  fleet_rule() { # fleet rule as deployed 2026-09-29/30, still with delaycompress
    sed 's/^    copytruncate$/    delaycompress\n    copytruncate/' "$TREE/ops/validator-host/logrotate/$1" >"/etc/logrotate.d/$1"
  }
  setup() {
    find /etc/logrotate.d -mindepth 1 -delete
    rm -rf /var/log/postfiat /etc/systemd/journald.conf.d "$S/calls" "$S/mid" "$S/ncalls"
    mkdir -p /var/log/postfiat/validator-0
    for f in stdout.log stderr.log rpc-stdout.log rpc-stderr.log rpc-events.ndjson transport-validator-events.ndjson; do
      echo x >"/var/log/postfiat/validator-0/$f"
    done
    case $1 in
      generic+fleet)
        cp "$TREE/systemd/postfiat-logrotate.example" /etc/logrotate.d/postfiat
        fleet_rule postfiat-rpc-events; fleet_rule postfiat-validator-events ;;
      generic) cp "$TREE/systemd/postfiat-logrotate.example" /etc/logrotate.d/postfiat ;;
      logonly+fleet)
        printf '/var/log/postfiat/*/*.log {\n    daily\n    rotate 14\n    missingok\n    copytruncate\n}\n' >/etc/logrotate.d/postfiat-local
        fleet_rule postfiat-rpc-events; fleet_rule postfiat-validator-events ;;
    esac
  }
  check() { local d=$1; shift; if "$@"; then echo "  ok: $d"; else echo "  FAIL: $d"; fail=1; fi; }
  is() { [ "$1" = "$2" ]; }
  for c in generic+fleet generic logonly+fleet; do
    echo "=== case $c"
    setup "$c"
    before=$(hashes)
    echo "  sha256 before install.sh:"; printf '%s\n' "$before" | sed 's/^/    /'
    rc=0; bash "$TREE/ops/validator-host/logrotate/install.sh" 0 >"$S/out" 2>"$S/err" || rc=$?
    echo "  install.sh rc=$rc; stderr:"; sed 's/^/    | /' "$S/err"
    echo "  matched '^error: .*postfiat' lines (install.sh prints exactly its grep hits):"
    grep -E '^error: .*postfiat' "$S/err" | sed 's/^/    > /' || echo "    > (none)"
    echo "  sha256 inside install.sh, at each logrotate dry-run call:"; sed 's/^/    /' "$S/mid"
    after=$(hashes)
    echo "  sha256 after install.sh:"; printf '%s\n' "$after" | sed 's/^/    /'
    check "rc=1" is "$rc" 1
    check "sha256 of every rule file identical before/after" is "$before" "$after"
    case $c in
      generic+fleet) check "pre-check refusal (nothing written)" grep -q '^refusing: the installed logrotate configuration already has postfiat errors' "$S/err" ;;
      *) check "post-check 'refusing: ... restored' path taken" grep -q '^refusing: another rule already rotates these files (above); restored ' "$S/err" ;;
    esac
    if [ "$c" = logonly+fleet ]; then
      check "fleet rules restored WITH delaycompress (install.sh had removed it)" \
        grep -qx '    delaycompress' /etc/logrotate.d/postfiat-rpc-events
      check "at call 2 (after install.sh wrote) no fleet-rule hash equals its before value" \
        is "$(awk '/^--- at logrotate call 2$/{on=1; next} on' "$S/mid" | grep -cF -f <(printf '%s\n' "$before" | grep 'events$') || true)" 0
    fi
  done
  exit "$fail"
fi

TREE="$(cd "${1:?usage: 06-restore-hashes.sh TREE}" && pwd)"
S="$(mktemp -d -p "$HOME/.cache")"
trap 'rm -rf "$S"' EXIT
umask 022
mkdir -p "$S/etc/logrotate.d" "$S/etc/systemd" "$S/var/log" "$S/var/lib/logrotate"
printf 'weekly\nrotate 4\ninclude /etc/logrotate.d\n' >"$S/etc/logrotate.conf"
cp /etc/passwd "$S/etc/passwd"; cp /etc/group "$S/etc/group"
getent passwd postfiat >/dev/null || echo 'postfiat:x:0:0::/nonexistent:/usr/sbin/nologin' >>"$S/etc/passwd"
getent group postfiat >/dev/null || echo 'postfiat:x:0:' >>"$S/etc/group"
echo "tree: $(git -C "$TREE" rev-parse HEAD) install.sh sha256 $(sha256sum <"$TREE/ops/validator-host/logrotate/install.sh" | cut -d' ' -f1)"
logrotate --version 2>&1 | head -1
rc=0; unshare -rm "$BASH" "${BASH_SOURCE[0]}" __ns "$TREE" "$S" || rc=$?
if [ "$rc" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$rc"
