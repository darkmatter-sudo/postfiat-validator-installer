#!/usr/bin/env bash
# Stub commands for run-tests.sh. Sourced; mk_env DIR builds a fake host in DIR:
#   DIR/root   PFT_CLUSTER_ROOT: the config volume (var/lib/docker/volumes/postfiatd_postfiatd-config/_data),
#              var/lib/pft-cluster, var/lib/pft-exporter/textfile, etc/pft-cluster.env
#   DIR/s      fake node + host state (see fake_node.py), calls (every stubbed command line), integrity.out
#   DIR/bin    one executable per stubbed command
# Stub bodies are literal scripts, single-quoted on purpose.
# shellcheck disable=SC2016,SC2034 # SC2034: PEER_* are used by run-tests.sh

STUBS_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOL=/var/lib/docker/volumes/postfiatd_postfiatd-config/_data
WALLET_PUB=n9MASi45ub7Qe4ZE36UT5G6cU4ud8Fhhe4deS4F3cw9KTAb8dLcu  # fixture keys: random valid base58, 52 chars
PEER_OLD=n9kC7edhDQ7cn5d4gEYkbUrMWeWQLGsCmrG6dLaYyNoVKf58ZTBq  # the sentry before its own apply
PEER_NEW=n9NAYT3j5qcdsyuMNmPfYetW5v6JXmj54omLidkuVKnRyjP2WPBg  # the sentry pinned

mk_env() {
  local d="$1"
  mkdir -p "$d/root$VOL" "$d/root/var/lib/pft-exporter/textfile" "$d/root/etc" "$d/s" "$d/bin"
  # a stock config tail: the real file has ~1580 lines; sections and comments are what the parser sees
  cat > "$d/root$VOL/postfiatd.cfg" <<'CFG'
# postfiatd.cfg (fixture)
# [node_seed]
# sXXXXXXXXXXXXXXXXXXXXXXXXXXXX   <- the stock file documents the section in comments
[server]
port_rpc_admin_local
port_peer

[port_peer]
port = 2559
ip = 0.0.0.0
protocol = peer

[ips_fixed]
192.0.2.10 2559

[peer_private]
0

[node_db]
type=NuDB
path=/var/lib/postfiatd/db/nudb
online_delete=512

CFG
  chmod 644 "$d/root$VOL/postfiatd.cfg"
  echo "$d/root$VOL/postfiatd.cfg" > "$d/s/cfg"
  cp "$d/root$VOL/postfiatd.cfg" "$d/s/loaded.cfg"
  echo "$WALLET_PUB" > "$d/s/wallet_pub"
  echo 2026-11-02T00:00:00.000000001Z > "$d/s/started"
  echo full > "$d/s/state"
  echo "$PEER_OLD" > "$d/s/peer_pub"
  touch "$d/s/peer_connected"
  printf 'pft-exporter.service\npft-senders-tx.service\n' > "$d/s/daemons"
  : > "$d/s/calls"; : > "$d/s/inactive"; : > "$d/s/log"; : > "$d/s/ps"; : > "$d/s/inspect_extra"
  printf 'pft-integrity verify - fixture\n  [WARN] cfgvol:postfiatd.cfg                             changed  sha256 mode mtime\nRESULT: WARN\n' > "$d/s/integrity.out"
  printf 'HOST_LABEL=validator\nPEER_LABEL=sentry\n' > "$d/root/etc/pft-cluster.env"
  touch "$d/s/maint"

  cat > "$d/bin/rpc" <<'STUB'
#!/usr/bin/env bash
echo "rpc $*" >> "$STUB_S/calls"
exec python3 "$STUB_HERE/fake_node.py" "$STUB_S" rpc "$2"
STUB
  cat > "$d/bin/docker" <<'STUB'
#!/usr/bin/env bash
S="$STUB_S"; echo "docker $*" >> "$S/calls"
case "$1" in
  inspect)
    if [ "$2" = -f ]; then
      [ "$4" = postfiatd ] || exit 1
      case "$3" in
        *State.StartedAt*) cat "$S/started" ;;
        *Mounts*) [ -f "$S/nocfgmount" ] || echo "${STUB_VOL}" ;;
      esac
    else
      [ "$2" = postfiatd ] || exit 1
      printf '[{"Name":"/postfiatd","Config":{"Env":["PATH=/usr/bin"%s],"Cmd":["--conf","/etc/postfiatd/postfiatd.cfg"]}}]\n' "$(cat "$S/inspect_extra")"
    fi ;;
  restart) exec python3 "$STUB_HERE/fake_node.py" "$S" restart ;;
  logs) cat "$S/log" ;;
  *) exit 0 ;;
esac
STUB
  cat > "$d/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_S/calls"
case "$1" in
  list-units) sed 's/$/ loaded active running x/' "$STUB_S/daemons" ;;
  # gate faults (inactive daemon, ssh, peer port) hit only while the loaded config is seeded: a fault apply caused
  is-active) grep -q '^\[node_seed\]' "$STUB_S/loaded.cfg" && grep -qx "$2" "$STUB_S/inactive" && echo inactive || echo active ;;
esac
exit 0
STUB
  cat > "$d/bin/ss" <<'STUB'
#!/usr/bin/env bash
[ -f "$STUB_S/no22" ] || echo "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
{ [ -f "$STUB_S/nopeerport" ] && grep -q '^\[node_seed\]' "$STUB_S/loaded.cfg"; } || echo "LISTEN 0 4096 0.0.0.0:2559 0.0.0.0:*"
STUB
  cat > "$d/bin/sshd" <<'STUB'
#!/usr/bin/env bash
[ -f "$STUB_S/sshd_bad" ] && grep -q '^\[node_seed\]' "$STUB_S/loaded.cfg" && exit 255; exit 0
STUB
  cat > "$d/bin/ssh-keyscan" <<'STUB'
#!/usr/bin/env bash
echo "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTURE"
STUB
  cat > "$d/bin/ps" <<'STUB'
#!/usr/bin/env bash
echo "COMMAND"; echo "/usr/local/bin/postfiatd --conf /etc/postfiatd/postfiatd.cfg"; cat "$STUB_S/ps"
STUB
  cat > "$d/bin/pft-maint" <<'STUB'
#!/usr/bin/env bash
echo "pft-maint $*" >> "$STUB_S/calls"
[ "$1" = active ] && [ -f "$STUB_S/maint" ]
STUB
  cat > "$d/bin/pft-integrity" <<'STUB'
#!/usr/bin/env bash
echo "pft-integrity $*" >> "$STUB_S/calls"
case "$1" in
  verify) cat "$STUB_S/integrity.out"; exit 1 ;;
  accept) echo "accepted" > "$STUB_S/accepted"; exit 0 ;;
esac
STUB
  cat > "$d/bin/fakessh" <<'STUB'
#!/usr/bin/env bash
# PULL_SSH stub: "fakessh cat -- FILE" serves STUB_S/peer.prom
echo "fakessh $*" >> "$STUB_S/calls"
[ -f "$STUB_S/ssh_fail" ] && exit 255
cat "$STUB_S/peer.prom"
STUB
  chmod +x "$d/bin/"*
}

use_env() { # DIR: point the tool at the fake host
  local d="$1"
  export STUB_S="$d/s" STUB_HERE="$STUBS_HERE" STUB_VOL="$VOL"
  export PFT_CLUSTER_ROOT="$d/root" PFT_CLUSTER_DOCKER="$d/bin/docker" PFT_CLUSTER_RPC="$d/bin/rpc"
  export PFT_CLUSTER_SYSTEMCTL="$d/bin/systemctl" PFT_CLUSTER_SS="$d/bin/ss" PFT_CLUSTER_SSHD="$d/bin/sshd"
  export PFT_CLUSTER_KEYSCAN="$d/bin/ssh-keyscan" PFT_CLUSTER_PS="$d/bin/ps" PFT_CLUSTER_MAINT="$d/bin/pft-maint"
  export PFT_CLUSTER_INTEGRITY="$d/bin/pft-integrity"
  SEED_UID="$(id -u)"; export SEED_UID HEALTH_BUDGET=3 POLL_SEC=1
  unset PFT_CLUSTER_INJECT CONTAINER STATE_DIR TEXTFILE_DIR PFT_CLUSTER_CONF
}
