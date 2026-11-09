#!/usr/bin/env bash
# pft-kmod: kernel-module attack-surface audit and dependency-guarded hardening for a Post Fiat validator or sentry
# host (Ubuntu 22.04, postfiatd 1.0.9 in Docker). CIS Ubuntu 22.04 1.1.1.x (unused filesystems, usb-storage) and
# 3.4.x (uncommon network protocols) style: every module on the deny list gets `install M /bin/false` + `blacklist M`
# in one managed modprobe.d file, so neither an explicit `modprobe M` nor a kernel autoload request (socket(AF_X...),
# mount -t X) can load it. Builds on ../sysctl (sysctl profile) and ../audittrail (module-load audit rules).
#
# Usage: pft-kmod audit [--json] [--textfile]    read-only; --textfile also writes TEXTFILE_DIR/pft_kmod_HOST.prom
#        pft-kmod list                           the deny list (module, class, rationale)
#        sudo pft-kmod apply --yes [--dry-run]   (inside a pft-maint window)
#        sudo pft-kmod rollback --yes            undo the last apply (inside a pft-maint window)
#        sudo pft-kmod pull                      validator: copy the peer's textfile (PULL_SSH in the env file)
#        pft-kmod validate FILE HOST             the check pull applies to a fetched textfile
#        pft-kmod version
#
#  audit   one line per check, PASS / WARN / FAIL / INFO; exit 0 PASS, 1 any WARN/FAIL, 2 error.
#            deny:M      PASS  `modprobe -c` has `install M /bin/false` (or /bin/true) and M is not loaded
#                        FAIL  M is loaded (/proc/modules), or M is in this kernel's module tree with no install rule
#                        WARN  M is absent from the module tree and has no rule (a later linux-modules-extra
#                              install would make it loadable)
#                        INFO  M is built into the kernel (modules.builtin): modprobe.d cannot deny it
#            autoload    kernel.modprobe is a modprobe binary, so autoload requests go through the install rules
#                        (FAIL if it points elsewhere; INFO if modules_disabled=1: nothing can load at all)
#            required:M  every module in REQUIRED (Docker bridge/NAT/overlayfs, netfilter, ...) and every module
#                        loaded now resolves (`modprobe --show-depends`) to insmod/builtin lines only (FAIL if an
#                        install rule blocks it or one of its dependencies)
#            managed     CONF_FILE matches what apply would write now (WARN: missing or drifted)
#  apply   refuses (exit 4, nothing written) without --yes, without an active pft-maint window with at least
#          MAINT_MIN s left and no data-collection lock, when the node is not full, when kernel.modprobe is not a
#          modprobe binary, when a deny-list module is loaded, built in, REQUIRED or a dependency of a REQUIRED or
#          loaded module (the required closure), or when the last apply is still in place. Then it backs up an
#          existing CONF_FILE (bytes + mode), writes the new one and verifies: every deny module resolves to
#          `install /bin/false`, every required module still resolves to insmod/builtin, the node is still full
#          with peers >= MIN_PEERS and the container still running. Any failure -> CONF_FILE restored
#          byte-identical, exit 1. Nothing is unloaded or loaded: a module already loaded refuses the apply.
#  rollback  restores the backed-up CONF_FILE byte-identical (or removes it if there was none), checks its sha256
#          against the one recorded at apply and re-runs the required check. Exit 5 if the restore does not match.
#  pull    runs "$PULL_SSH cat -- REMOTE_DIR/pft_kmod_PEER.prom", validates it (only pft_kmod_ samples whose first
#          label is host="PEER", <= MAX_BYTES, an up and a last_run sample) and renames it into TEXTFILE_DIR.
#          Exit 1 fetch failed, 2 validation failed (the old copy stays, so a dead peer goes stale).
#
# Exit codes: 0 ok, 1 findings (audit) / verify failed and restored (apply), 2 error, 3 usage, 4 refused, 5 rollback
#             restore mismatch.
# Config: /etc/pft-kmod.env (KEY=VALUE, read, never sourced; PFT_KM_CONF overrides the path): HOST_LABEL (validator),
#   PEER_LABEL (sentry), PULL_SSH, PULL_TIMEOUT (30), EXTRA_REQUIRED (more module names for the required set),
#   EXTRA_DENY (more module names to deny), KEEP (deny-list modules this host needs; never written).
# Env: CONF_FILE (/etc/modprobe.d/60-pft-kmod.conf)  STATE_DIR (/var/lib/pft-kmod)  TEXTFILE_DIR
#      (/var/lib/pft-exporter/textfile)  REMOTE_DIR (same)  CONTAINER (auto: postfiatd or postfiatd-sentry)
#      MAINT_MIN (600)  MIN_PEERS (1)  NODE_CFG (/etc/postfiatd/postfiatd.cfg, in the container)  VERIFY_INJECT=required (the post-apply verify fails: restore drill)
#   Test hooks: PFT_KM_ROOT (prefix for /proc, /sys, /lib/modules)  PFT_KM_MODPROBE  PFT_KM_DOCKER  PFT_KM_MAINT
#      PFT_KM_UNAME_R  PFT_KM_NOW (epoch)
# shellcheck disable=SC2016
set -uo pipefail
umask 022
VERSION=1.0.0

R="${PFT_KM_ROOT:-}"
MODPROBE="${PFT_KM_MODPROBE:-modprobe}"
DOCKER="${PFT_KM_DOCKER:-docker}"
MAINT="${PFT_KM_MAINT:-pft-maint}"
KREL="${PFT_KM_UNAME_R:-$(uname -r)}"
CONF_FILE="${CONF_FILE:-/etc/modprobe.d/60-pft-kmod.conf}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-kmod}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
REMOTE_DIR="${REMOTE_DIR:-/var/lib/pft-exporter/textfile}"
MAINT_MIN="${MAINT_MIN:-600}"
MIN_PEERS="${MIN_PEERS:-1}"
NODE_CFG="${NODE_CFG:-/etc/postfiatd/postfiatd.cfg}" # inside the container; without --conf postfiatd looks in /etc/opt
INJECT="${VERIFY_INJECT:-}"
MAX_BYTES=16384
HOST_LABEL=validator; PEER_LABEL=sentry; PULL_SSH=""; PULL_TIMEOUT=30; EXTRA_REQUIRED=""; EXTRA_DENY=""; KEEP=""
CONF="${PFT_KM_CONF:-/etc/pft-kmod.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|PEER_LABEL|PULL_SSH|PULL_TIMEOUT|EXTRA_REQUIRED|EXTRA_DENY|KEEP)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi

# module  class  rationale. No module here is used by postfiatd, Docker, LXD, snapd, AppArmor, auditd or chrony.
# squashfs is deliberately NOT listed (snapd/LXD mount their snaps with it; built in on Ubuntu kernels anyway).
DENY='cramfs fs CIS 1.1.1.1: legacy compressed ROM filesystem, no use on a node host
freevxfs fs CIS 1.1.1.2: Veritas VxFS reader
jffs2 fs CIS 1.1.1.3: flash filesystem
hfs fs CIS 1.1.1.4: legacy Apple filesystem parser
hfsplus fs CIS 1.1.1.5: Apple HFS+ parser
udf fs CIS 1.1.1.7: optical-media filesystem parser
usb-storage dev CIS 1.1.1.8 / 1.1.10: USB mass storage (a cloud VM has no USB media)
dccp net CIS 3.4.1: DCCP, repeated local privilege escalations (e.g. CVE-2017-6074)
sctp net CIS 3.4.2: SCTP, autoloaded by an unprivileged socket() call
rds net CIS 3.4.3: RDS, autoloaded by socket(AF_RDS) (e.g. CVE-2010-3904)
tipc net CIS 3.4.4: TIPC, autoloaded by socket(AF_TIPC) (e.g. CVE-2021-43267)
atm net uncommon protocol (Ubuntu blacklist-rare-network: blacklist only, still loadable by modprobe)
can net CAN bus protocol family
ieee802154 net IEEE 802.15.4 low-rate wireless stack
appletalk net AppleTalk
x25 net X.25
ax25 net AX.25 amateur radio
netrom net NET/ROM amateur radio
rose net ROSE amateur radio
n_hdlc tty HDLC line discipline (CVE-2017-2636), loadable through TIOCSETD'

# Modules the node stack needs: Docker bridge networking + NAT + overlay2, netfilter/ufw, IPsec-free XFRM netlink,
# kTLS. Everything loaded at run time is added to this set, and so are the dependencies of both.
REQUIRED='overlay bridge br_netfilter veth llc stp nf_conntrack nf_nat nf_tables nft_compat nft_chain_nat nft_masq x_tables ip_tables ip6_tables iptable_filter iptable_nat ip6table_filter ip6table_nat xt_conntrack xt_MASQUERADE xt_addrtype xt_nat xt_tcpudp xt_multiport xt_limit xt_recent xt_comment xt_LOG nf_reject_ipv4 nf_reject_ipv6 ipt_REJECT ip6t_REJECT tls xfrm_user'

die() { printf 'pft-kmod: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_KM_NOW:-$(date -u +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }
sha() { if [ -f "$1" ]; then sha256sum <"$1" | cut -c1-64; else echo absent; fi; }
norm() { tr '-' '_' <<<"$1"; }   # modprobe treats - and _ alike; /proc/modules uses _

deny_lines() {
  local m keep
  while read -r m c r; do
    for keep in $KEEP; do [ "$(norm "$keep")" = "$(norm "$m")" ] && continue 2; done
    printf '%s %s %s\n' "$m" "$c" "$r"
  done <<<"$DENY"
  for m in $EXTRA_DENY; do printf '%s extra listed in EXTRA_DENY (%s)\n' "$m" "$CONF"; done
}
deny_mods() { deny_lines | awk '{print $1}'; }

loaded() { awk '{print $1}' "$R/proc/modules" 2>/dev/null; }
is_loaded() { loaded | grep -qx "$(norm "$1")"; }
is_builtin() { grep -qE "/$(norm "$1" | sed 's/_/[-_]/g')\.ko$" "$R/lib/modules/$KREL/modules.builtin" 2>/dev/null; }
# show_deps M -> modprobe --show-depends lines (rc 1 if M is not found in the tree and has no install rule)
show_deps() { "$MODPROBE" --show-depends "$1" 2>/dev/null; }
# denied M -> rc 0 if the effective config has `install M /bin/false|/bin/true` (the last install line wins)
# `modprobe -c` (reads every modprobe.d file, ~0.1 s on the live hosts) is loaded once into CFG by cfg_load: at the
# start of an audit and again right after apply/rollback writes CONF_FILE.
CFG=""
cfg_load() { CFG="$("$MODPROBE" -c 2>/dev/null | grep -E '^(install|blacklist) ')"; }
cfg() { printf '%s\n' "$CFG"; }
denied() {
  local n; n="$(norm "$1")"
  cfg | awk -v m="$n" '$1 == "install" { k = $2; gsub(/-/, "_", k); if (k == m) { v = $3 } }
    END { exit !(v == "/bin/false" || v == "/bin/true" || v == "/usr/bin/false" || v == "/usr/bin/true") }'
}
blacklisted() {
  local n; n="$(norm "$1")"
  cfg | awk -v m="$n" '$1 == "blacklist" { k = $2; gsub(/-/, "_", k); if (k == m) f = 1 } END { exit !f }'
}
in_tree() { show_deps "$1" | grep -qE '^insmod ' || is_builtin "$1"; }

# required set = REQUIRED + EXTRA_REQUIRED + loaded; closure = that set plus every module its insmod lines name
required_set() { { for m in $REQUIRED $EXTRA_REQUIRED; do norm "$m"; done; loaded; } | sort -u; }
# deps_load resolves the required set once (DEPS[m] = show-depends output, DEPRC[m] = its rc) in the calling shell;
# closure/required_blocked read it. Called after every cfg_load: install rules change the resolution.
declare -A DEPS=() DEPRC=()
deps_load() {
  local m
  DEPS=(); DEPRC=()
  while read -r m; do DEPS[$m]="$(show_deps "$m")"; DEPRC[$m]=$?; done < <(required_set)
}
closure() {
  local m
  for m in "${!DEPS[@]}"; do
    echo "$m"
    awk '$1 == "insmod" { n = $2; sub(/.*\//, "", n); sub(/\.ko(\.[a-z]+)?$/, "", n); gsub(/-/, "_", n); print n }' <<<"${DEPS[$m]}"
  done | sort -u
}
# required_blocked -> one "M: reason" line per required module whose resolution hits an install rule
required_blocked() {
  local m out
  for m in "${!DEPS[@]}"; do
    out="${DEPS[$m]}"
    if [ "${DEPRC[$m]}" != 0 ]; then is_loaded "$m" && echo "$m: loaded but modprobe cannot resolve it"; continue; fi
    [ "$INJECT" = required ] && [ "$m" = overlay ] && out="install /bin/false"
    if grep -qE '^install ' <<<"$out"; then echo "$m: resolves to '$(grep -m1 -E '^install ' <<<"$out" | sed 's/ *$//')'"; fi
  done | sort
}

autoload_path() { tr -d '\n' <"$R/proc/sys/kernel/modprobe" 2>/dev/null; }
autoload_ok() { case "$(autoload_path)" in /sbin/modprobe|/usr/sbin/modprobe|/bin/kmod|/usr/bin/kmod) return 0 ;; esac; return 1; }

render_conf() {
  printf '# Managed by pft-kmod (postfiat-validator-installer/kmod). Rollback: sudo pft-kmod rollback --yes\n'
  printf '# install M /bin/false blocks explicit modprobe and kernel autoload; blacklist M also drops alias matches.\n'
  deny_lines | while read -r m c r; do printf '# %s (%s)\ninstall %s /bin/false\nblacklist %s\n' "$m" "$c: $r" "$m" "$m"; done
}

# ---------- node health (docker exec <container> postfiatd --conf NODE_CFG server_info) ----------
container() {
  if [ -n "${CONTAINER:-}" ]; then echo "$CONTAINER"; return; fi
  local c
  for c in postfiatd postfiatd-sentry; do
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && { echo "$c"; return; }
  done
  echo postfiatd
}
node_state() { # -> "running state peers"
  local c run info
  c="$(container)"
  run="$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)"; [ "$run" = true ] || run=false
  info="$("$DOCKER" exec "$c" postfiatd --conf "$NODE_CFG" server_info 2>/dev/null)"
  printf '%s %s %s\n' "$run" "$(jq -r '.result.info.server_state // "down"' <<<"$info" 2>/dev/null || echo down)" \
    "$(jq -r '.result.info.peers // 0' <<<"$info" 2>/dev/null || echo 0)"
}
node_ok() { # "running state peers" -> rc 0 if running, full/proposing, peers >= MIN_PEERS
  local run st p; read -r run st p <<<"$1"
  [ "$run" = true ] && case "$st" in full|proposing|validating) true ;; *) false ;; esac && [ "${p:-0}" -ge "$MIN_PEERS" ]
}

# ---------- audit ----------
ROWS=()
row() { ROWS+=("$(printf '%s\t%s\t%s' "$1" "$2" "$3")"); }
N_DENY=0 N_ENF=0 N_LOADED=0 N_LOADABLE=0 N_ABSENT=0 N_BUILTIN=0 N_REQBLK=0 AUTO=1 MANAGED=0

run_audit() {
  local m c r b
  cfg_load; deps_load
  while read -r m c r; do
    N_DENY=$((N_DENY + 1)); b=""; blacklisted "$m" || b=" (no blacklist line)"
    if is_loaded "$m"; then N_LOADED=$((N_LOADED + 1)); row FAIL "deny:$m" "loaded now ($c) - unload it in a maintenance window, then apply"
    elif is_builtin "$m"; then N_BUILTIN=$((N_BUILTIN + 1)); row INFO "deny:$m" "built into this kernel: modprobe.d cannot deny it"
    elif denied "$m"; then N_ENF=$((N_ENF + 1)); row PASS "deny:$m" "install rule blocks load and autoload$b"
    elif in_tree "$m"; then N_LOADABLE=$((N_LOADABLE + 1)); row FAIL "deny:$m" "loadable: in the module tree, no install rule ($c)"
    else N_ABSENT=$((N_ABSENT + 1)); row WARN "deny:$m" "not in this kernel's module tree and no install rule (a linux-modules-extra install would make it loadable)"
    fi
  done < <(deny_lines)
  if [ "$(cat "$R/proc/sys/kernel/modules_disabled" 2>/dev/null)" = 1 ]; then
    row INFO autoload "kernel.modules_disabled=1: no module can be loaded until reboot"
  elif autoload_ok; then row PASS autoload "kernel.modprobe=$(autoload_path): autoload requests go through the install rules"
  else AUTO=0; row FAIL autoload "kernel.modprobe=$(autoload_path) is not modprobe: autoload bypasses modprobe.d"; fi
  local blk; blk="$(required_blocked)"
  N_REQBLK="$(grep -c . <<<"$blk")"
  if [ "$N_REQBLK" = 0 ]; then row PASS required "$(required_set | grep -c .) required/loaded modules resolve to insmod/builtin only"
  else while IFS= read -r m; do row FAIL "required:${m%%:*}" "${m#*: }"; done <<<"$blk"; fi
  if [ ! -f "$CONF_FILE" ]; then row WARN managed "$CONF_FILE missing (not applied)"
  elif cmp -s "$CONF_FILE" <(render_conf); then MANAGED=1; row PASS managed "$CONF_FILE matches the deny list (sha256 $(sha "$CONF_FILE" | cut -c1-12))"
  else row WARN managed "$CONF_FILE differs from what apply would write now (edited, or the deny list changed)"; fi
}

worst() { local r w=0; for r in "${ROWS[@]}"; do case "${r%%$'\t'*}" in WARN|FAIL) w=1 ;; esac; done; echo "$w"; }

metrics() { # UP RUN_TS
  local L="host=\"$HOST_LABEL\""
  cat <<EOF
# HELP pft_kmod_up 1 if the last audit completed.
# TYPE pft_kmod_up gauge
pft_kmod_up{$L} $1
# HELP pft_kmod_last_run_timestamp_seconds When the last audit ran.
# TYPE pft_kmod_last_run_timestamp_seconds gauge
pft_kmod_last_run_timestamp_seconds{$L} $2
EOF
  [ "$1" = 1 ] || return 0
  cat <<EOF
# HELP pft_kmod_deny_modules Deny-list modules by state (enforced = install rule; loaded/loadable = FAIL; absent = WARN; builtin = cannot be denied).
# TYPE pft_kmod_deny_modules gauge
pft_kmod_deny_modules{$L,state="enforced"} $N_ENF
pft_kmod_deny_modules{$L,state="loaded"} $N_LOADED
pft_kmod_deny_modules{$L,state="loadable"} $N_LOADABLE
pft_kmod_deny_modules{$L,state="absent"} $N_ABSENT
pft_kmod_deny_modules{$L,state="builtin"} $N_BUILTIN
# HELP pft_kmod_required_blocked Required or loaded modules whose modprobe resolution hits an install rule.
# TYPE pft_kmod_required_blocked gauge
pft_kmod_required_blocked{$L} $N_REQBLK
# HELP pft_kmod_autoload_ok 1 if kernel.modprobe is a modprobe binary (autoload honours modprobe.d).
# TYPE pft_kmod_autoload_ok gauge
pft_kmod_autoload_ok{$L} $AUTO
# HELP pft_kmod_managed 1 if the managed modprobe.d file matches the deny list.
# TYPE pft_kmod_managed gauge
pft_kmod_managed{$L} $MANAGED
EOF
}

write_textfile() { # CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_kmod_$HOST_LABEL.XXXXXX" 2>/dev/null)" || { echo "pft-kmod: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { printf '%s\n' "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_kmod_$HOST_LABEL.prom"; }; then
    rm -f "$t"; echo "pft-kmod: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

audit() {
  local json=0 tf=0 t0 rc r st k n
  while [ $# -gt 0 ]; do
    case "$1" in --json) json=1 ;; --textfile) tf=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift
  done
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL" 3
  t0="$(now)"
  if ! command -v "$MODPROBE" >/dev/null || [ ! -r "$R/proc/modules" ]; then
    [ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"
    die "modprobe or /proc/modules unavailable" 2
  fi
  run_audit
  rc="$(worst)"
  [ "$tf" = 1 ] && write_textfile "$(metrics 1 "$t0")"
  if [ "$json" = 1 ]; then
    printf '%s\n' "${ROWS[@]}" | jq -R -s -c --arg host "$HOST_LABEL" --arg ts "$(ts)" --arg kernel "$KREL" --argjson exit "$rc" '
      [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], check: .[1], note: .[2]}] as $r |
      {host: $host, time: $ts, kernel: $kernel, result: (if $exit == 0 then "PASS" else "FINDINGS" end), exit: $exit, checks: $r}'
  else
    printf 'pft-kmod audit %s - %s  host=%s  kernel %s  OS: %s\n' "$VERSION" "$(ts)" "$HOST_LABEL" "$KREL" \
      "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')"
    for r in "${ROWS[@]}"; do IFS=$'\t' read -r st k n <<<"$r"; printf '%-5s %-22s %s\n' "$st" "$k" "$n"; done
    printf 'RESULT: %s - deny %d: %d enforced, %d loaded, %d loadable, %d absent, %d builtin; required blocked %d; autoload %s -> exit %d\n' \
      "$([ "$rc" = 0 ] && echo PASS || echo FINDINGS)" "$N_DENY" "$N_ENF" "$N_LOADED" "$N_LOADABLE" "$N_ABSENT" "$N_BUILTIN" \
      "$N_REQBLK" "$([ "$AUTO" = 1 ] && echo ok || echo BYPASSED)" "$rc"
  fi
  return "$rc"
}

# ---------- apply / rollback ----------
refuse() { echo "$(ts) REFUSED - $1; nothing written"; exit 4; }
maint_gate() { # rc 0, or the reason on stdout
  local j w rem nl
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "pft-maint status failed (is pft-maint installed?)"; return 1; }
  w="$(jq -r '.window // "none"' <<<"$j")"; rem="$(jq -r '.remaining_sec // 0' <<<"$j")"; nl="$(jq -r '.locks | length' <<<"$j")"
  if [ "$w" != active ]; then echo "no active pft-maint window (window=$w); run: sudo pft-maint start --ttl 30m --reason ..."; return 1; fi
  if [ "${rem%.*}" -lt "$MAINT_MIN" ]; then echo "pft-maint window has ${rem%.*} s left (< MAINT_MIN $MAINT_MIN)"; return 1; fi
  if [ "$nl" -gt 0 ]; then echo "$nl pft-maint data-collection lock(s) held"; return 1; fi
}

guards() { # rc 0, or the first refusal reason on stdout. Used by apply (and --dry-run, which skips --yes/maint).
  local m cl why
  autoload_ok || { echo "kernel.modprobe=$(autoload_path) is not modprobe: install rules would not govern autoload"; return 1; }
  cl="$(closure)"
  while read -r m _; do
    if is_loaded "$m"; then echo "deny-list module $m is loaded (unload it first, or add it to KEEP)"; return 1; fi
    if is_builtin "$m"; then echo "deny-list module $m is built into this kernel (remove it from the list)"; return 1; fi
    if grep -qx "$(norm "$m")" <<<"$cl"; then
      why="$(for r in $REQUIRED $EXTRA_REQUIRED; do [ "$(norm "$r")" = "$(norm "$m")" ] && echo REQUIRED; done)"
      echo "deny-list module $m is ${why:-a dependency of a required or loaded module} (add it to KEEP)"; return 1
    fi
  done < <(deny_lines)
}

apply() {
  local yes=0 dry=0 why ns0 ns1 id new bk pre post rc=0 m fails=""
  while [ $# -gt 0 ]; do case "$1" in --yes) yes=1 ;; --dry-run) dry=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift; done
  [ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || [ -n "${PFT_KM_TEST:-}" ] || die "apply needs root" 3
  if [ "$dry" = 0 ]; then
    [ "$yes" = 1 ] || refuse "apply writes $CONF_FILE: add --yes"
    why="$(maint_gate)" || refuse "$why"
    [ -f "$STATE_DIR/apply.json" ] && refuse "the last apply ($(jq -r .id "$STATE_DIR/apply.json" 2>/dev/null)) is still in place: rollback first"
  fi
  ns0="$(node_state)"
  [ "$dry" = 1 ] || node_ok "$ns0" || refuse "node not healthy before apply (running/state/peers: $ns0; need full and peers >= $MIN_PEERS)"
  deps_load
  why="$(guards)" || refuse "$why"
  new="$(mktemp)"; render_conf >"$new"
  echo "$(ts) apply on $HOST_LABEL: node (running/state/peers) $ns0; $(deny_mods | grep -c .) deny rules; CONF_FILE sha256 before $(sha "$CONF_FILE")"
  diff -u --label "$CONF_FILE (current)" --label "$CONF_FILE (new)" "$([ -f "$CONF_FILE" ] && echo "$CONF_FILE" || echo /dev/null)" "$new" | sed 's/^/  /'
  if [ "$dry" = 1 ]; then rm -f "$new"; echo "$(ts) dry-run: guards pass, nothing written"; return 0; fi
  if [ -f "$CONF_FILE" ] && cmp -s "$CONF_FILE" "$new"; then rm -f "$new"; echo "$(ts) already applied: $CONF_FILE identical, nothing written"; return 0; fi
  id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"; bk="$STATE_DIR/backup-$id"
  install -d -m 700 "$STATE_DIR" || die "cannot create $STATE_DIR"
  pre="$(sha "$CONF_FILE")"
  if [ -f "$CONF_FILE" ]; then cp -p "$CONF_FILE" "$bk.conf" || die "backup failed"; fi
  install -m 644 "$new" "$CONF_FILE" || { rm -f "$new"; die "cannot write $CONF_FILE"; }
  rm -f "$new"; post="$(sha "$CONF_FILE")"
  jq -n --arg id "$id" --arg host "$HOST_LABEL" --arg pre "$pre" --arg post "$post" --arg conf "$CONF_FILE" \
    --arg bk "$([ -f "$bk.conf" ] && echo "$bk.conf" || echo -)" \
    '{id: $id, host: $host, conf: $conf, sha_before: $pre, sha_after: $post, backup: $bk}' >"$STATE_DIR/apply.json"
  echo "$(ts) wrote $CONF_FILE (sha256 $post); backup: $([ -f "$bk.conf" ] && echo "$bk.conf" || echo "none (file did not exist)")"
  # verify
  cfg_load; deps_load
  for m in $(deny_mods); do denied "$m" || fails="$fails deny:$m"; done
  local blk; blk="$(required_blocked)"; [ -z "$blk" ] || fails="$fails required:[$(tr '\n' ';' <<<"$blk")]"
  ns1="$(node_state)"; node_ok "$ns1" || fails="$fails node:[$ns1]"
  if [ -n "$fails" ]; then
    echo "$(ts) VERIFY FAILED:$fails -> restoring"
    restore_conf "$pre" || rc=5
    rm -f "$STATE_DIR/apply.json"
    echo "$(ts) restored $CONF_FILE (sha256 $(sha "$CONF_FILE"), before-apply $pre)"
    return "$([ "$rc" = 5 ] && echo 5 || echo 1)"
  fi
  echo "$(ts) verify ok: $(deny_mods | grep -c .) deny modules resolve to install /bin/false; required closure unblocked; node $ns1"
}

restore_conf() { # PRE_SHA: restore from the apply's backup, or remove if there was none; rc 1 on sha mismatch
  local bk
  bk="$(jq -r '.backup // "-"' "$STATE_DIR/apply.json" 2>/dev/null)"; [ -n "$bk" ] || bk=-
  if [ "$bk" != - ] && [ -f "$bk" ]; then cp -p "$bk" "$CONF_FILE"; else rm -f "$CONF_FILE"; fi
  [ "$(sha "$CONF_FILE")" = "$1" ]
}

rollback() {
  local yes=0 why pre ns
  while [ $# -gt 0 ]; do case "$1" in --yes) yes=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift; done
  [ "$(id -u)" = 0 ] || [ -n "${PFT_KM_TEST:-}" ] || die "rollback needs root" 3
  [ "$yes" = 1 ] || refuse "rollback writes $CONF_FILE: add --yes"
  why="$(maint_gate)" || refuse "$why"
  [ -f "$STATE_DIR/apply.json" ] || refuse "no apply on record in $STATE_DIR"
  pre="$(jq -r .sha_before "$STATE_DIR/apply.json")"
  [ "$(sha "$CONF_FILE")" = "$(jq -r .sha_after "$STATE_DIR/apply.json")" ] ||
    echo "$(ts) note: $CONF_FILE changed since the apply (sha256 $(sha "$CONF_FILE")); restoring the pre-apply copy anyway"
  if ! restore_conf "$pre"; then echo "$(ts) ROLLBACK MISMATCH: $CONF_FILE sha256 $(sha "$CONF_FILE") != pre-apply $pre"; exit 5; fi
  mv -f "$STATE_DIR/apply.json" "$STATE_DIR/rolled-back-$(jq -r .id "$STATE_DIR/apply.json").json"
  ns="$(node_state)"; cfg_load; deps_load
  echo "$(ts) rollback on $HOST_LABEL: $CONF_FILE restored byte-identical (sha256 $pre); required blocked: $(required_blocked | grep -c .); node $ns"
}

# ---------- pull / validate ----------
validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"; [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_kmod_[a-z_]+ / || /^$/ { next }
    {
      if (match($0, /^pft_kmod_[a-z_]+\{/) == 0) { printf "line %d: not a pft_kmod_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_kmod_up\{/) up = 1
      if ($0 ~ /^pft_kmod_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_kmod_up sample"; exit 1 }
      if (!ts) { print "no pft_kmod_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL" 3
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)" 3
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT" 3
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-kmod-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_kmod_$PEER_LABEL.prom" >"$tmp" 2>/dev/null; then
    rm -f "$tmp"; die "fetch of pft_kmod_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_kmod_$PEER_LABEL.prom"; }; then rm -f "$tmp"; die "rename failed" 1; fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  audit) audit "$@" ;;
  list) deny_lines | while read -r m c r; do printf '%-12s %-4s %s\n' "$m" "$c" "$r"; done ;;
  apply) apply "$@" ;;
  rollback) rollback "$@" ;;
  pull) [ $# -eq 0 ] || die "pull takes no arguments" 3; pull ;;
  validate) [ $# -eq 2 ] || die "usage: pft-kmod validate FILE HOST" 3; valid_label "$2" || die "bad host label" 3
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-kmod $VERSION" ;;
  *) die "usage: pft-kmod audit|list|apply|rollback|pull|validate|version (see the header of this script)" 3 ;;
esac
