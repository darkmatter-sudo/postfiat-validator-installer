#!/usr/bin/env bash
# pft-aptrust: supply-chain trust audit for a Post Fiat validator or sentry host (Ubuntu 22.04, postfiatd 1.0.9 in
# Docker). It answers "who can put code on this host through the package and image channels?": APT sources, the
# keys they trust, APT options that weaken signature checks, pinning, the provenance of running container images,
# and code that was installed outside any package manager. It does not look for CVEs (../vulnscan), file hashes
# (../integrity) or deployments (../rollout).
#
# Usage: pft-aptrust audit [--json] [--textfile]   read-only; --textfile also writes TEXTFILE_DIR/pft_aptrust_HOST.prom
#        sudo pft-aptrust apply --dry-run|--yes   safe-only fixes (see "apply / rollback" below)
#        sudo pft-aptrust rollback [--yes]        undo the last apply from its backup
#        sudo pft-aptrust pull                    validator: copy the peer's textfile (PULL_SSH in the env file)
#        pft-aptrust validate FILE HOST           the check pull applies to a fetched textfile
#        pft-aptrust version
#
#  audit   one line per check, PASS / WARN / FAIL / INFO; exit 0 PASS (INFO allowed), 1 any WARN/FAIL, 2 error.
#            src:FILE:N     a deb line / deb822 stanza. FAIL trusted=yes, allow-insecure/allow-weak/
#                           allow-downgrade-to-insecure=yes, signed-by naming a missing keyring, or a third-party
#                           source over http with no signed-by; WARN third-party with no signed-by (it trusts every
#                           global key) or over http; INFO Ubuntu archive over http (InRelease is signature-checked)
#            perm:PATH      APT config/keyring paths: FAIL not root-owned or group/world-writable (a non-root writer
#                           can add a source, a key or an option)
#            legacy         FAIL /etc/apt/trusted.gpg holds keys (deprecated global keyring)
#            global:FILE    trusted.gpg.d: INFO stock file of a package (dpkg -V clean); WARN anything else (a global
#                           key is trusted for every source without signed-by)
#            key:FILE       every keyring a source or the global set uses: FAIL weak (RSA < 2048, DSA) or no usable
#                           key left (all expired/revoked); WARN a usable key expires within EXPIRY_WARN_DAYS;
#                           INFO expired/revoked keys kept next to a usable one
#            aptconf:KEY    `apt-config dump`: FAIL AllowInsecureRepositories / AllowDowngradeToInsecureRepositories /
#                           AllowWeakRepositories / AllowUnauthenticated true, https Verify-Peer / Verify-Host false;
#                           WARN Check-Valid-Until / Check-Date false
#            pin:FILE:N     preferences: WARN Pin-Priority >= 1000 (allows downgrades) or a third-party pin above
#                           500 for every package; INFO stock package files
#            image:NAME     running container: PASS the image ID has a registry RepoDigest; INFO official rolling
#                           tag (OFFICIAL_IMAGES, per Post Fiat's validator guide) or a known local build
#                           (LOCAL_IMAGES); WARN `latest`/untagged third-party image, or no RepoDigest (unknown
#                           local build)
#            compose:FILE:N `image:` lines of the container's compose files: PASS tag@sha256; INFO official
#                           rolling tag or a version tag; WARN `latest`/untagged
#            offpkg:PATH    /usr/local/{bin,sbin} file not owned by a package: PASS-counted if in the add-on
#                           allowlist (ALLOW_MANIFEST INSTALL_PATH column + OFFPKG_ALLOW); WARN otherwise; FAIL
#                           group/world-writable or not root-owned
#            pip:/npm:/dpkg-local:NAME   WARN package installed outside APT (global pip/npm, dpkg -i with no archive)
#
# Exit codes: 0 ok, 1 findings, 2 error, 3 usage.
# Config: /etc/pft-aptrust.env (KEY=VALUE, read, never sourced; PFT_AT_CONF overrides the path): HOST_LABEL
#   (validator), OFFICIAL_IMAGES (agtipft/postfiatd), LOCAL_IMAGES (pft-exporter), OFFPKG_ALLOW (allowed
#   /usr/local paths beyond the manifest; default pft-agent + the installer's postfiat-health / postfiat-docker-user.sh), UBUNTU_HOSTS (archive/security/ports/esm .ubuntu.com and *.archive.ubuntu.com mirrors),
#   EXPIRY_WARN_DAYS (30); for pull: PEER_LABEL (sentry), PULL_SSH (command line that runs `cat` on the peer, e.g.
#   runuser -u OPERATOR -- ssh -o BatchMode=yes relay sudo -n), PULL_TIMEOUT (30), REMOTE_DIR (the peer's TEXTFILE_DIR).
#  pull    runs "$PULL_SSH cat -- REMOTE_DIR/pft_aptrust_PEER.prom" (timeout PULL_TIMEOUT), validates it (only
#          pft_aptrust_ samples whose first label is host="PEER", up + last_run present, <= MAX_BYTES 65536) and
#          renames it into TEXTFILE_DIR; a failed fetch or validation leaves the old copy (PFTAptrustStale then fires).
# Env: TEXTFILE_DIR (/var/lib/pft-exporter/textfile)  ALLOW_MANIFEST (/usr/local/lib/pft-aptrust/manifest.tsv)
#   Test hooks: PFT_AT_ROOT (prefix for /etc/apt, /usr/local, /var/lib/dpkg paths)  PFT_AT_DOCKER  PFT_AT_GPG
#      PFT_AT_DPKG  PFT_AT_APTCONFIG  PFT_AT_APT  PFT_AT_NOW (epoch)
set -uo pipefail
umask 022
VERSION=0.1.0

R="${PFT_AT_ROOT:-}"
DOCKER="${PFT_AT_DOCKER:-docker}"
GPG="${PFT_AT_GPG:-gpg}"
DPKG="${PFT_AT_DPKG:-dpkg}"
APTCONFIG="${PFT_AT_APTCONFIG:-apt-config}"
APT="${PFT_AT_APT:-apt}"
APTGET="${PFT_AT_APTGET:-apt-get}"
GPGV="${PFT_AT_GPGV:-gpgv}"
MAINT="${PFT_AT_MAINT:-pft-maint}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-aptrust}"
MAINT_MIN="${MAINT_MIN:-600}"
INJECT="${VERIFY_INJECT:-}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
ALLOW_MANIFEST="${ALLOW_MANIFEST:-/usr/local/lib/pft-aptrust/manifest.tsv}"
HOST_LABEL=validator; OFFICIAL_IMAGES="agtipft/postfiatd"; LOCAL_IMAGES="pft-exporter"; # default allowlist beyond the manifest: the operator's agent CLI and the two files the repo's top-level install.sh
# writes from quoted heredocs (constant bytes, no repo file of their own for pft-fleet to track)
OFFPKG_ALLOW="/usr/local/bin/pft-agent /usr/local/bin/postfiat-health /usr/local/sbin/postfiat-docker-user.sh"
UBUNTU_HOSTS="archive.ubuntu.com security.ubuntu.com ports.ubuntu.com esm.ubuntu.com"; EXPIRY_WARN_DAYS=30
PEER_LABEL=sentry; PULL_SSH=""; PULL_TIMEOUT=30; REMOTE_DIR=/var/lib/pft-exporter/textfile; MAX_BYTES=65536
CONF="${PFT_AT_CONF:-/etc/pft-aptrust.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|OFFICIAL_IMAGES|LOCAL_IMAGES|OFFPKG_ALLOW|UBUNTU_HOSTS|EXPIRY_WARN_DAYS|PEER_LABEL|PULL_SSH|PULL_TIMEOUT|REMOTE_DIR)
        v="${v%\"}"; v="${v#\"}"; printf -v "$k" '%s' "$v" ;;
    esac
  done < <(grep -E '^[A-Z_]+=' "$CONF")
fi

die() { printf 'pft-aptrust: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_AT_NOW:-$(date -u +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
valid_label() { [[ "$1" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; }

ROWS=()
row() { ROWS+=("$(printf '%s\t%s\t%s' "$1" "$2" "$3")"); }
declare -A KEYRINGS=()   # keyring path (without R) -> "global" or "signed-by"
UNSIGNED=()   # third-party sources with no signed-by: FILE<TAB>LINE<TAB>URI<TAB>SUITE<TAB>FORMAT (list|deb822)
PERMFIX=()    # APT paths apply can fix: PATH<TAB>own|mode<TAB>MODE
N_SRC=0 N_KEYS=0 N_IMG=0 N_OFFPKG_OK=0

# ubuntu_host URI -> rc 0 if the URI's host is an Ubuntu archive (UBUNTU_HOSTS or an *.archive.ubuntu.com mirror)
ubuntu_host() {
  local h="${1#*://}" u; h="${h%%/*}"; h="${h%%:*}"; h="${h,,}"
  for u in $UBUNTU_HOSTS; do [ "$h" = "$u" ] && return 0; done
  [[ "$h" == *.archive.ubuntu.com ]]
}

# grade_source WHERE TYPE URI OPTS SUITE FORMAT   OPTS: space-separated lower-case key=value (deb822 keys are mapped)
grade_source() {
  local where="$1" uri="$3" opts=" $4 " suite="${5:-}" fmt="${6:-list}" o k v sb="" bad="" scheme="${3%%://*}"
  N_SRC=$((N_SRC + 1))
  for o in $opts; do
    k="${o%%=*}"; v="${o#*=}"; v="${v,,}"
    case "$k" in
      trusted) [ "$v" = yes ] && bad+="trusted=yes (signature check off); " ;;
      allow-insecure|allow-weak|allow-downgrade-to-insecure) [ "$v" = yes ] && bad+="$k=yes; " ;;
      signed-by) sb="${o#*=}" ;;
    esac
  done
  if [ -n "$sb" ] && [[ "$sb" == /* ]]; then
    local krs; IFS=',' read -r -a krs <<<"$sb"
    for k in "${krs[@]}"; do
      if [ -f "$R$k" ]; then KEYRINGS["$k"]=signed-by; else bad+="signed-by keyring $k missing; "; fi
    done
  fi
  if [ -n "$bad" ]; then row FAIL "src:$where" "${bad%; } ($uri)"; return; fi
  if ubuntu_host "$uri"; then
    if [ "$scheme" = http ]; then row INFO "src:$where" "Ubuntu archive over http: InRelease is signature-checked (${sb:+signed-by }${sb:-stock global keys})"
    else row PASS "src:$where" "Ubuntu archive over $scheme (${sb:+signed-by }${sb:-stock global keys})"; fi
    return
  fi
  [ -z "$sb" ] && UNSIGNED+=("$(printf '%s\t%s\t%s\t%s\t%s' "${where%:*}" "${where##*:}" "$uri" "$suite" "$fmt")")
  if [ -z "$sb" ] && [ "$scheme" != https ]; then row FAIL "src:$where" "third-party source over $scheme with no signed-by: any global key can sign it and the transport is plain ($uri)"
  elif [ -z "$sb" ]; then row WARN "src:$where" "third-party source with no signed-by: every global key in trusted.gpg.d can sign it ($uri)"
  elif [ "$scheme" != https ]; then row WARN "src:$where" "third-party source over $scheme (signed-by $sb): metadata is signed but readable and replayable until Valid-Until ($uri)"
  else row PASS "src:$where" "https + signed-by $sb ($uri)"; fi
}

# one-line format: deb [opt=v opt2=v] URI suite comps...
scan_list() {
  local f="$1" n=0 line rest opts uri suite
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1)); line="${line%%#*}"; read -r -a w <<<"$line"
    [ "${#w[@]}" -gt 0 ] || continue
    case "${w[0]}" in deb|deb-src) ;; *) continue ;; esac
    rest="${line#*"${w[0]}"}"; opts=""
    if [[ "$rest" =~ ^[[:space:]]*\[([^]]*)\][[:space:]]*(.*)$ ]]; then opts="${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"; fi
    read -r uri suite _ <<<"$rest"
    grade_source "${f#"$R"}:$n" "${w[0]}" "$uri" "$opts" "$suite" list
  done <"$f"
}

# deb822 format: stanzas separated by blank lines; Enabled: no skips the stanza; multi-value URIs graded each
scan_sources() {
  local f="$1"
  awk '
    function flush() { if (have && en != "no") printf "%d\t%s\t%s\t%s\n", start, types, uris, opts; have = 0; types = uris = opts = ""; en = "" }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { flush(); next }
    /^[[:space:]]/ { next }   # continuation lines (inline Signed-By key blocks)
    {
      if (!have) { have = 1; start = NR }
      k = tolower($1); sub(/:$/, "", k); v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/[[:space:]]+$/, "", v)
      if (k == "types") types = v
      else if (k == "uris") uris = v
      else if (k == "enabled") en = tolower(v)
      else if (k == "trusted" || k == "allow-insecure" || k == "allow-weak" || k == "allow-downgrade-to-insecure") opts = opts " " k "=" v
      else if (k == "signed-by") opts = opts " signed-by=" (v == "" ? "inline" : v)
    }
    END { flush() }' "$f" | while IFS=$'\t' read -r n types uris opts; do
      for u in $uris; do printf '%s\t%s\t%s\t%s\n' "$n" "${types%% *}" "$u" "$opts"; done
    done >"$TMP/sources.tsv"
  local n t u o
  while IFS=$'\t' read -r n t u o; do grade_source "${f#"$R"}:$n" "$t" "$u" "$o" "" deb822; done <"$TMP/sources.tsv"
}

# perm PATH -> FAIL if not root-owned or group/world-writable (symlinks: the target)
perm_check() {
  local p="$1" st
  [ -e "$R$p" ] || return 0
  st="$(stat -L -c '%u %a' "$R$p" 2>/dev/null)" || return 0
  local uid="${st%% *}" mode="${st##* }"
  if [ -n "${PFT_AT_ROOT:-}" ] && [ -n "${PFT_AT_UID_ROOT:-}" ]; then [ "$uid" = "$PFT_AT_UID_ROOT" ] && uid=0; fi
  if [ "$uid" != 0 ]; then
    row FAIL "perm:$p" "owned by uid $uid, not root: that user can change what APT trusts"
    PERMFIX+=("$(printf '%s\town\t%o' "$p" $((8#$mode & ~8#022)))"); return 1
  fi
  if (( 8#$mode & 8#022 )); then
    row FAIL "perm:$p" "mode $mode is group/world-writable: a non-root writer can change what APT trusts"
    PERMFIX+=("$(printf '%s\tmode\t%o' "$p" $((8#$mode & ~8#022)))"); return 1
  fi
  return 0
}

pkg_stock() { # FILE -> package name if the file belongs to a package and dpkg -V reports it unchanged
  local p
  p="$("$DPKG" -S "$1" 2>/dev/null | head -n 1)" || return 1
  p="${p%%:*}"; [ -n "$p" ] || return 1
  "$DPKG" -V "$p" 2>/dev/null | awk -v f="$1" '$NF == f { bad = 1 } END { exit bad }' || return 1
  echo "$p"
}

# key_check FILE (path without R): parse with gpg --show-keys (binary or armored keyrings)
key_check() {
  local f="$1" out t warn=$((EXPIRY_WARN_DAYS * 86400)) usable=0 dead=0 weak="" soon="" kid algo len exp val
  t="$(now)"
  out="$("$GPG" --batch --no-options --homedir "$TMP/gnupg" --show-keys --with-colons "$R$f" 2>/dev/null)"
  if ! grep -q '^pub:' <<<"$out"; then row FAIL "key:$f" "no OpenPGP public key could be read (empty or corrupt keyring)"; return; fi
  while IFS=: read -r _ val len algo kid _ exp _; do
    N_KEYS=$((N_KEYS + 1))
    case "$algo" in
      1|2|3) [ "$len" -lt 2048 ] && weak+="${kid: -8} RSA-$len; " ;;
      17) weak+="${kid: -8} DSA-$len; " ;;
    esac
    if [ "$val" = e ] || [ "$val" = r ] || { [ -n "$exp" ] && [ "$exp" -le "$t" ]; }; then dead=$((dead + 1))
    else
      usable=$((usable + 1))
      [ -n "$exp" ] && [ $((exp - t)) -lt "$warn" ] && soon+="${kid: -8} expires $(date -u -d "@$exp" +%F); "
    fi
  done < <(grep '^pub:' <<<"$out")
  if [ -n "$weak" ]; then row FAIL "key:$f" "weak key(s): ${weak%; } (apt warns; use RSA >= 2048 / Ed25519)"
  elif [ "$usable" = 0 ]; then row FAIL "key:$f" "no usable key: $dead expired/revoked (sources signed by it fail apt-get update)"
  elif [ -n "$soon" ]; then row WARN "key:$f" "${soon%; } (within ${EXPIRY_WARN_DAYS}d)"
  elif [ "$dead" -gt 0 ]; then row INFO "key:$f" "$usable usable key(s), $dead expired/revoked key(s) kept alongside (vendor keyring; harmless)"
  else row PASS "key:$f" "$usable usable key(s), none weak, none expiring within ${EXPIRY_WARN_DAYS}d"; fi
}

scan_aptconf() {
  local dump k v
  dump="$("$APTCONFIG" dump 2>/dev/null)" || { row WARN aptconf "apt-config dump failed"; return; }
  local hits=0
  while IFS= read -r line; do
    k="${line%% *}"; v="${line#* }"; v="${v%;}"; v="${v//\"/}"; v="${v,,}"
    case "${k,,}" in
      acquire::allowinsecurerepositories|acquire::allowdowngradetoinsecurerepositories|acquire::allowweakrepositories|apt::get::allowunauthenticated)
        case "$v" in true|yes|1|on) row FAIL "aptconf:$k" "$v: APT accepts unsigned or weakly signed repositories"; hits=$((hits + 1)) ;; esac ;;
      acquire::https::verify-peer|acquire::https::verify-host|acquire::https::*::verify-peer|acquire::https::*::verify-host)
        case "$v" in false|no|0|off) row FAIL "aptconf:$k" "$v: TLS certificate checks off"; hits=$((hits + 1)) ;; esac ;;
      acquire::check-valid-until|acquire::check-date)
        case "$v" in false|no|0|off) row WARN "aptconf:$k" "$v: replayed (frozen) repository metadata is accepted"; hits=$((hits + 1)) ;; esac ;;
    esac
  done <<<"$dump"
  [ "$hits" = 0 ] && row PASS aptconf "no option weakens signature, TLS or freshness checks"
}

scan_prefs() {
  local f="$1" stock="$2"
  awk '
    function flush() { if (have) printf "%d\t%s\t%s\t%s\n", start, pkg, pin, prio; have = 0; pkg = pin = prio = "" }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { flush(); next }
    { if (!have) { have = 1; start = NR }
      k = tolower($1); sub(/:$/, "", k); v = $0; sub(/^[^:]*:[[:space:]]*/, "", v)
      if (k == "package") pkg = v; else if (k == "pin") pin = v; else if (k == "pin-priority") prio = v }
    END { flush() }' "$R$f" >"$TMP/prefs.tsv"
  local n pkg pin prio
  while IFS=$'\t' read -r n pkg pin prio; do
    [[ "$prio" =~ ^-?[0-9]+$ ]] || { row WARN "pin:$f:$n" "unparseable Pin-Priority '$prio'"; continue; }
    if [ -n "$stock" ]; then row INFO "pin:$f:$n" "stock file of $stock: $pin -> $prio"
    elif [ "$prio" -ge 1000 ]; then row WARN "pin:$f:$n" "Pin-Priority $prio >= 1000 lets '$pin' downgrade installed packages ($pkg)"
    elif [ "$prio" -gt 500 ] && [ "$pkg" = "*" ] && ! [[ "$pin" =~ (o=Ubuntu|origin[[:space:]]+\"?[a-z.]*ubuntu\.com) ]]; then
      row WARN "pin:$f:$n" "every package from '$pin' outranks the Ubuntu archive (priority $prio)"
    else row PASS "pin:$f:$n" "$pin -> $prio ($pkg)"; fi
  done <"$TMP/prefs.tsv"
}

# unvar REF -> compose interpolation ${VAR:-default} / ${VAR-default} replaced by the default, ${VAR} by "VAR"
unvar() { sed -E 's/\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}/\1/g; s/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/\1/g' <<<"$1"; }
in_words() { local x; for x in $2; do [ "$x" = "$1" ] && return 0; done; return 1; }
img_repo() { local r="${1%%@*}"; [[ "${r##*/}" == *:* ]] && r="${r%:*}"; r="${r#docker.io/}"; r="${r#library/}"; echo "$r"; }
img_tag() { local r="${1%%@*}"; if [[ "${r##*/}" == *:* ]]; then echo "${r##*:}"; else echo ""; fi; }

scan_images() {
  local names name ref id rd repo tag files f n line
  names="$("$DOCKER" ps --format '{{.Names}}' 2>/dev/null)" || { row WARN image "docker ps failed: image provenance not checked"; return; }
  declare -A seen=()
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    N_IMG=$((N_IMG + 1))
    read -r ref id < <("$DOCKER" inspect -f '{{.Config.Image}} {{.Image}}' "$name" 2>/dev/null)
    rd="$("$DOCKER" image inspect -f '{{join .RepoDigests " "}}' "$id" 2>/dev/null)"
    repo="$(img_repo "$ref")"; tag="$(img_tag "$ref")"
    if [[ "$ref" == *@sha256:* ]] && [ -n "$rd" ]; then row PASS "image:$name" "$ref: pinned by digest, image has RepoDigest"
    elif [ -z "$rd" ]; then
      if in_words "$repo" "$LOCAL_IMAGES"; then row INFO "image:$name" "$ref: known local build (LOCAL_IMAGES), no registry digest"
      else row WARN "image:$name" "$ref: no RepoDigest, so the image did not come from a registry pull (unknown local build)"; fi
    elif in_words "$repo" "$OFFICIAL_IMAGES"; then row INFO "image:$name" "$ref: official rolling tag (Post Fiat validator guide); running ${rd%% *}"
    elif [ -z "$tag" ] || [ "$tag" = latest ]; then row WARN "image:$name" "$ref: '${tag:-untagged}' third-party image: what runs after the next pull is unknown; pin a version tag (and digest)"
    else row PASS "image:$name" "$ref: version tag, registry digest ${rd%% *}"; fi
    files="$("$DOCKER" inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$name" 2>/dev/null)"
    IFS=',' read -r -a fl <<<"$files"
    for f in "${fl[@]}"; do
      if [ -z "$f" ] || [ -n "${seen[$f]:-}" ]; then continue; fi
      seen[$f]=1
      [ -r "$R$f" ] || { row WARN "compose:$f" "listed by container $name but not readable"; continue; }
      n=0
      while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        [[ "$line" =~ ^[[:space:]]*image:[[:space:]]*[\"\']?([^\"\'[:space:]#]+) ]] || continue
        ref="$(unvar "${BASH_REMATCH[1]}")"; repo="$(img_repo "$ref")"; tag="$(img_tag "$ref")"
        if [[ "$ref" == *@sha256:* ]]; then row PASS "compose:$f:$n" "$ref pinned by digest"
        elif in_words "$repo" "$OFFICIAL_IMAGES"; then row INFO "compose:$f:$n" "$ref: official rolling tag (Post Fiat validator guide)"
        elif [ -z "$tag" ] || [ "$tag" = latest ]; then row WARN "compose:$f:$n" "$ref: '${tag:-untagged}': pin a version tag (and digest)"
        else row INFO "compose:$f:$n" "$ref: version tag without digest (tags can be re-pushed)"; fi
      done <"$R$f"
    done
  done <<<"$names"
}

scan_offpkg() {
  local allow="" p d
  [ -r "$R$ALLOW_MANIFEST" ] && allow="$(awk '!/^#/ && NF >= 3 { print $3 }' "$R$ALLOW_MANIFEST")"
  for d in /usr/local/bin /usr/local/sbin; do
    [ -d "$R$d" ] || continue
    perm_check "$d" || true
    for p in "$R$d"/*; do
      [ -f "$p" ] || continue; p="${p#"$R"}"
      perm_check "$p" || continue
      "$DPKG" -S "$p" >/dev/null 2>&1 && continue
      if grep -qxF "$p" <<<"$allow" || in_words "$p" "$OFFPKG_ALLOW"; then N_OFFPKG_OK=$((N_OFFPKG_OK + 1)); continue; fi
      row WARN "offpkg:$p" "not from a package and not a known add-on file (ALLOW_MANIFEST / OFFPKG_ALLOW): unknown provenance"
    done
  done
  [ -r "$R$ALLOW_MANIFEST" ] || row WARN offpkg "allowlist $ALLOW_MANIFEST missing: add-on files cannot be told apart"
  row INFO offpkg "$N_OFFPKG_OK add-on file(s) in /usr/local/{bin,sbin} match the allowlist"
  local m
  for m in "$R"/usr/local/lib/python3*/dist-packages/*.dist-info "$R"/usr/local/lib/python3*/dist-packages/*.egg-info \
           "$R"/usr/local/lib/python3*/site-packages/*.dist-info; do
    [ -e "$m" ] && row WARN "pip:$(basename "$m")" "global pip package outside APT (${m#"$R"})"
  done
  for m in "$R"/usr/local/lib/node_modules/*; do
    [ -e "$m" ] && row WARN "npm:$(basename "$m")" "global npm package outside APT (${m#"$R"})"
  done
  while IFS= read -r m; do
    [ -n "$m" ] && row WARN "dpkg-local:${m%%/*}" "installed with no APT archive offering it (dpkg -i or a removed source): $m"
  done < <("$APT" list --installed 2>/dev/null | grep -F '[installed,local]')
}

run_audit() {
  local f p b
  TMP="$(mktemp -d)"; mkdir -m 700 "$TMP/gnupg"
  for p in /etc/apt /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/apt.conf.d /etc/apt/preferences \
           /etc/apt/preferences.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d /etc/apt/keyrings; do perm_check "$p" || true; done
  for f in "$R"/etc/apt/sources.list.d/* "$R"/etc/apt/apt.conf.d/* "$R"/etc/apt/preferences.d/*; do
    [ -f "$f" ] && { perm_check "${f#"$R"}" || true; }
  done
  [ -f "$R/etc/apt/sources.list" ] && scan_list "$R/etc/apt/sources.list"
  for f in "$R"/etc/apt/sources.list.d/*.list; do [ -f "$f" ] && scan_list "$f"; done
  for f in "$R"/etc/apt/sources.list.d/*.sources; do [ -f "$f" ] && scan_sources "$f"; done
  [ "$N_SRC" -gt 0 ] || row FAIL src "no enabled APT source found"
  if [ -s "$R/etc/apt/trusted.gpg" ]; then row FAIL legacy "/etc/apt/trusted.gpg holds keys: deprecated global keyring, trusted for every source"; KEYRINGS[/etc/apt/trusted.gpg]=global
  else row PASS legacy "no /etc/apt/trusted.gpg keyring"; fi
  for f in "$R"/etc/apt/trusted.gpg.d/*; do
    [ -f "$f" ] || continue; f="${f#"$R"}"; KEYRINGS["$f"]=global
    if p="$(pkg_stock "$f")"; then row INFO "global:$f" "stock file of package $p (dpkg -V clean); global trust for sources without signed-by"
    else row WARN "global:$f" "not a stock package file: this key is trusted for EVERY source without signed-by; move it to /etc/apt/keyrings + signed-by"; fi
  done
  for f in "$R"/etc/apt/keyrings/*; do [ -f "$f" ] && { f="${f#"$R"}"; perm_check "$f" || true; [ -n "${KEYRINGS[$f]:-}" ] || KEYRINGS["$f"]=unused; }; done
  for f in $(printf '%s\n' "${!KEYRINGS[@]}" | sort); do
    perm_check "$f" || true
    key_check "$f"
  done
  scan_aptconf
  [ -f "$R/etc/apt/preferences" ] && scan_prefs /etc/apt/preferences ""
  for f in "$R"/etc/apt/preferences.d/*; do
    [ -f "$f" ] || continue; f="${f#"$R"}"
    b="${f##*/}"   # APT reads preferences.d files with no extension or .pref, named [A-Za-z0-9_.-]
    [[ "$b" =~ ^[A-Za-z0-9_.-]+$ ]] || continue
    [[ "$b" == *.* && "$b" != *.pref ]] && continue
    scan_prefs "$f" "$(pkg_stock "$f" || true)"
  done
  scan_images
  scan_offpkg
  [ "${1:-}" = keep ] || rm -rf "$TMP"
}

count() { local r n=0; for r in "${ROWS[@]}"; do [ "${r%%$'\t'*}" = "$1" ] && n=$((n + 1)); done; echo "$n"; }

metrics() { # UP RUN_TS
  local L="host=\"$HOST_LABEL\""
  cat <<EOF
# HELP pft_aptrust_up 1 if the last audit completed.
# TYPE pft_aptrust_up gauge
pft_aptrust_up{$L} $1
# HELP pft_aptrust_last_run_timestamp_seconds When the last audit ran.
# TYPE pft_aptrust_last_run_timestamp_seconds gauge
pft_aptrust_last_run_timestamp_seconds{$L} $2
EOF
  [ "$1" = 1 ] || return 0
  cat <<EOF
# HELP pft_aptrust_checks Audit checks by result.
# TYPE pft_aptrust_checks gauge
pft_aptrust_checks{$L,result="pass"} $(count PASS)
pft_aptrust_checks{$L,result="info"} $(count INFO)
pft_aptrust_checks{$L,result="warn"} $(count WARN)
pft_aptrust_checks{$L,result="fail"} $(count FAIL)
# HELP pft_aptrust_sources Enabled APT source entries graded.
# TYPE pft_aptrust_sources gauge
pft_aptrust_sources{$L} $N_SRC
# HELP pft_aptrust_keys OpenPGP primary keys read from the keyrings APT uses.
# TYPE pft_aptrust_keys gauge
pft_aptrust_keys{$L} $N_KEYS
EOF
}

write_textfile() { # CONTENT
  local t
  t="$(mktemp "$TEXTFILE_DIR/.pft_aptrust_$HOST_LABEL.XXXXXX" 2>/dev/null)" || { echo "pft-aptrust: cannot write $TEXTFILE_DIR" >&2; return 1; }
  if ! { printf '%s\n' "$1" >"$t" && chmod 644 "$t" && mv -f "$t" "$TEXTFILE_DIR/pft_aptrust_$HOST_LABEL.prom"; }; then
    rm -f "$t"; echo "pft-aptrust: cannot write $TEXTFILE_DIR" >&2; return 1
  fi
}

audit() {
  local json=0 tf=0 t0 rc r st k n
  while [ $# -gt 0 ]; do
    case "$1" in --json) json=1 ;; --textfile) tf=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift
  done
  valid_label "$HOST_LABEL" || die "bad HOST_LABEL" 3
  [[ "$EXPIRY_WARN_DAYS" =~ ^[0-9]+$ ]] || die "bad EXPIRY_WARN_DAYS" 3
  t0="$(now)"
  if [ ! -d "$R/etc/apt" ] || ! command -v "$GPG" >/dev/null; then
    [ "$tf" = 1 ] && write_textfile "$(metrics 0 "$t0")"
    die "/etc/apt or gpg unavailable" 2
  fi
  run_audit
  rc=0; [ "$(count WARN)" -gt 0 ] || [ "$(count FAIL)" -gt 0 ] && rc=1
  [ "$tf" = 1 ] && write_textfile "$(metrics 1 "$t0")"
  if [ "$json" = 1 ]; then
    printf '%s\n' "${ROWS[@]}" | jq -R -s -c --arg host "$HOST_LABEL" --arg ts "$(ts)" --argjson exit "$rc" '
      [split("\n")[] | select(length > 0) | split("\t") | {status: .[0], check: .[1], note: .[2]}] as $r |
      {host: $host, time: $ts, result: (if $exit == 0 then "PASS" else "FINDINGS" end), exit: $exit, checks: $r}'
  else
    printf 'pft-aptrust audit %s - %s  host=%s  OS: %s\n' "$VERSION" "$(ts)" "$HOST_LABEL" \
      "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')"
    for r in "${ROWS[@]}"; do IFS=$'\t' read -r st k n <<<"$r"; printf '%-5s %-44s %s\n' "$st" "$k" "$n"; done
    printf 'RESULT: %s - %d sources, %d keys, %d containers; %d pass, %d info, %d warn, %d fail -> exit %d\n' \
      "$([ "$rc" = 0 ] && echo PASS || echo FINDINGS)" "$N_SRC" "$N_KEYS" "$N_IMG" "$(count PASS)" "$(count INFO)" \
      "$(count WARN)" "$(count FAIL)" "$rc"
  fi
  return "$rc"
}

# ---------- apply / rollback (safe-only) ----------
# A plan line is one of
#   perm  PATH  own|mode  MODE          chown root:root (own) and/or chmod MODE (group/world write bits removed)
#   sign  FILE  LINE  URI  KEYRING  FPR  add signed-by=KEYRING to a one-line source; KEYRING gets the key that signs
#                                        the source's cached InRelease (exported from the global keyring that has it)
#   drop  GLOBALFILE                     a non-stock global keyring (/etc/apt/trusted.gpg or trusted.gpg.d) whose every
#                                        key was moved to a signed-by keyring: removed (backed up)
# Nothing else is ever changed: options, pins, packages and images are report-only.
refuse() { echo "$(ts) REFUSED - $1; nothing written"; exit 4; }
sha() { if [ -f "$1" ]; then sha256sum <"$1" | cut -c1-64; else echo absent; fi; }

maint_gate() { # rc 0, or the reason on stdout
  local j w rem nl
  j="$("$MAINT" status --json 2>/dev/null)" || { echo "pft-maint status failed (is pft-maint installed?)"; return 1; }
  w="$(jq -r '.window // "none"' <<<"$j")"; rem="$(jq -r '.remaining_sec // 0' <<<"$j")"; nl="$(jq -r '.locks | length' <<<"$j")"
  if [ "$w" != active ]; then echo "no active pft-maint window (window=$w); run: sudo pft-maint start --ttl 30m --reason ..."; return 1; fi
  if [ "${rem%.*}" -lt "$MAINT_MIN" ]; then echo "pft-maint window has ${rem%.*} s left (< MAINT_MIN $MAINT_MIN)"; return 1; fi
  if [ "$nl" -gt 0 ]; then echo "$nl pft-maint data-collection lock(s) held"; return 1; fi
}

# list_name URI SUITE -> the InRelease file APT caches for it (apt's URItoFileName: scheme and user dropped, / -> _)
list_name() {
  local u="${1#*://}"; u="${u#*@}"; u="${u%/}"
  printf '%s/var/lib/apt/lists/%s_dists_%s_InRelease\n' "$R" "${u//\//_}" "${2//\//_}"
}
global_keyrings() { # non-stock global keyring files (paths without R), one per line
  local f
  [ -s "$R/etc/apt/trusted.gpg" ] && echo /etc/apt/trusted.gpg
  for f in "$R"/etc/apt/trusted.gpg.d/*; do
    [ -f "$f" ] || continue; f="${f#"$R"}"
    pkg_stock "$f" >/dev/null || echo "$f"
  done
}
fprs() { # KEYRING -> primary fingerprints, one per line
  "$GPG" --batch --no-options --homedir "$TMP/gnupg" --show-keys --with-colons "$R$1" 2>/dev/null |
    awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }'
}
signer() { # INRELEASE -> primary fingerprint of the key that made a valid signature (from the global keyrings), rc 1 if none
  local a=() g
  while IFS= read -r g; do a+=(--keyring "$R$g"); done < <(global_keyrings; for g in "$R"/etc/apt/trusted.gpg.d/*; do [ -f "$g" ] && echo "${g#"$R"}"; done)
  [ "${#a[@]}" -gt 0 ] || return 1
  "$GPGV" --homedir "$TMP/gnupg" --status-fd 1 "${a[@]}" "$1" 2>/dev/null | awk '$2 == "VALIDSIG" { print $NF; f = 1 } END { exit !f }'
}

# make_plan -> $TMP/plan (tab-separated) and $TMP/manual (findings apply will not touch). Needs run_audit's arrays.
make_plan() {
  local e p k m f n u s fmt fp g kr host
  : >"$TMP/plan"; : >"$TMP/manual"
  for e in "${PERMFIX[@]}"; do IFS=$'\t' read -r p k m <<<"$e"; printf 'perm\t%s\t%s\t%s\n' "$p" "$k" "$m" >>"$TMP/plan"; done
  declare -A moved=()
  for e in "${UNSIGNED[@]}"; do
    IFS=$'\t' read -r f n u s fmt <<<"$e"
    if [ "$fmt" != list ]; then echo "$f:$n deb822 stanza without Signed-By: add Signed-By by hand" >>"$TMP/manual"; continue; fi
    if [ ! -f "$(list_name "$u" "$s")" ]; then echo "$f:$n no cached InRelease for $u $s (run apt-get update first; flat or Release.gpg-only repos are manual)" >>"$TMP/manual"; continue; fi
    if ! fp="$(signer "$(list_name "$u" "$s")")"; then echo "$f:$n the cached InRelease of $u verifies with no global key" >>"$TMP/manual"; continue; fi
    host="${u#*://}"; host="${host#*@}"; host="${host%%/*}"; host="${host%%:*}"
    kr="/etc/apt/keyrings/pft-aptrust-${host//[^A-Za-z0-9.-]/_}.gpg"
    printf 'sign\t%s\t%s\t%s\t%s\t%s\n' "$f" "$n" "$u" "$kr" "$fp" >>"$TMP/plan"
    moved[$fp]=1
  done
  # a non-stock global keyring is dropped only if every one of its keys now has a signed-by home and no source
  # left without signed-by (that apply cannot sign) might still need it
  [ -s "$TMP/manual" ] && grep -q 'without Signed-By\|no cached\|verifies with no' "$TMP/manual" && return 0
  while IFS= read -r g; do
    local all=1 any=0
    while IFS= read -r fp; do any=1; [ -n "${moved[$fp]:-}" ] || all=0; done < <(fprs "$g")
    if [ "$any" = 1 ] && [ "$all" = 1 ]; then printf 'drop\t%s\n' "$g" >>"$TMP/plan"
    else echo "$g keeps key(s) no source here is signed by: left in place (remove by hand if unused)" >>"$TMP/manual"; fi
  done < <(global_keyrings)
}

# update_gate LOG -> rc 0 if `apt-get update` exited 0 with no signature/fetch error; the index lines go to LOG
update_gate() {
  local out rc
  out="$("$APTGET" update 2>&1)"; rc=$?
  printf '%s\n' "$out" >"$1"
  [ "$rc" = 0 ] || { echo "apt-get update exit $rc"; return 1; }
  if grep -qE '^(Err:|E:)|NO_PUBKEY|is not signed|signatures (were invalid|couldn.t be verified)|EXPKEYSIG|BADSIG' "$1"; then
    echo "apt-get update reported: $(grep -m1 -E '^(Err:|E:)|NO_PUBKEY|is not signed|signatures|EXPKEYSIG|BADSIG' "$1")"; return 1
  fi
}
indexes() { awk '$1 ~ /^(Hit|Get):[0-9]+$/ { print $2, $3 }' "$1" | sort -u; }

plan_paths() { # paths the plan writes or removes (without R)
  awk -F'\t' '$1 == "perm" || $1 == "drop" { print $2 } $1 == "sign" { print $2; print $5 }' "$TMP/plan" | sort -u
}

apply() {
  local yes=0 dry=0 why id bk p rc=0 kind a b c d e fails="" migrated=0
  while [ $# -gt 0 ]; do case "$1" in --yes) yes=1 ;; --dry-run) dry=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift; done
  [ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || [ -n "${PFT_AT_TEST:-}" ] || die "apply needs root" 3
  if [ "$dry" = 0 ]; then
    [ "$yes" = 1 ] || refuse "apply changes APT trust files: add --yes"
    why="$(maint_gate)" || refuse "$why"
    [ -f "$STATE_DIR/apply.json" ] && refuse "the last apply ($(jq -r .id "$STATE_DIR/apply.json" 2>/dev/null)) is still in place: rollback first"
  fi
  run_audit keep
  make_plan
  echo "$(ts) apply on $HOST_LABEL: $(grep -c . "$TMP/plan") planned change(s), $(grep -c . "$TMP/manual") manual item(s)"
  sed 's/^/  plan    /' "$TMP/plan"; sed 's/^/  manual  /' "$TMP/manual"
  if [ ! -s "$TMP/plan" ]; then rm -rf "$TMP"; echo "$(ts) nothing to apply"; return 0; fi
  if [ "$dry" = 1 ]; then rm -rf "$TMP"; echo "$(ts) dry-run: nothing written"; return 0; fi
  while IFS= read -r p; do
    [ -e "$R$p" ] && { rm -rf "$TMP"; refuse "$p already exists (not written by this apply)"; }
  done < <(awk -F'\t' '$1 == "sign" { print $5 }' "$TMP/plan" | sort -u)
  why="$(update_gate "$TMP/pre.log")" || { rm -rf "$TMP"; refuse "pre-apply gate: $why"; }
  id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"; bk="$STATE_DIR/backup-$id"
  install -d -m 700 "$STATE_DIR" "$bk" || die "cannot create $STATE_DIR"
  cp "$TMP/plan" "$bk/plan"; indexes "$TMP/pre.log" >"$bk/pre-indexes"
  # backup: every path the plan touches, bytes + mode + owner (tar -p, numeric owner); new files are listed
  : >"$bk/created"
  while IFS= read -r p; do
    if [ -e "$R$p" ]; then printf '%s\t%s\n' "$p" "$(sha "$R$p")" >>"$bk/sha-before"; else echo "$p" >>"$bk/created"; fi
  done < <(plan_paths)
  touch "$bk/sha-before"
  if [ -s "$bk/sha-before" ]; then
    cut -f1 "$bk/sha-before" | sed 's#^/##' >"$bk/files.list"
    tar -C "${R:-/}" --numeric-owner -cpf "$bk/files.tar" -T "$bk/files.list" || die "backup failed"
  fi
  jq -n --arg id "$id" --arg host "$HOST_LABEL" --arg bk "$bk" '{id: $id, host: $host, backup: $bk}' >"$STATE_DIR/apply.json"
  echo "$(ts) backup $bk: $(grep -c . "$bk/sha-before") file(s) saved, $(grep -c . "$bk/created") to be created"
  while IFS=$'\t' read -r kind a b c d e; do
    case "$kind" in
      perm)
        [ "$b" = own ] && { chown 0:0 "$R$a" || fails+=" chown:$a"; }
        chmod "$c" "$R$a" || fails+=" chmod:$a"
        echo "$(ts) perm $a -> root-owned mode $c" ;;
      sign)
        if [ ! -e "$R$d" ]; then
          local g ex=""
          while IFS= read -r g; do
            ex="$("$GPG" --batch --no-options --homedir "$TMP/gnupg" --no-default-keyring --keyring "$R$g" --export "$e" 2>/dev/null | base64 -w0)"
            [ -n "$ex" ] && break
          done < <(global_keyrings; for g in "$R"/etc/apt/trusted.gpg.d/*; do [ -f "$g" ] && echo "${g#"$R"}"; done)
          if [ -z "$ex" ]; then fails+=" export:$e"; continue; fi
          if ! { install -d -m 755 "$R/etc/apt/keyrings" && base64 -d <<<"$ex" >"$R$d" && chmod 644 "$R$d"; }; then
            fails+=" write:$d"; continue
          fi
        fi
        awk -v n="$b" -v kr="$d" 'NR == n {
            if (match($0, /^[[:space:]]*deb(-src)?[[:space:]]+\[/)) { $0 = substr($0, 1, RLENGTH) "signed-by=" kr " " substr($0, RLENGTH + 1) }
            else { sub(/^[[:space:]]*deb(-src)?/, "& [signed-by=" kr "]") } }
          { print }' "$R$a" >"$TMP/src.new" && cat "$TMP/src.new" >"$R$a" || fails+=" edit:$a:$b"
        migrated=$((migrated + 1))
        echo "$(ts) sign $a:$b ($c) -> signed-by=$d (key ${e: -16})" ;;
      drop) rm -f "$R$a" || fails+=" drop:$a"; echo "$(ts) drop global keyring $a (all its keys now in signed-by keyrings)" ;;
    esac
  done <"$TMP/plan"
  # verify: the post gate must see every index the pre gate saw, with no signature error; then re-audit
  if [ -z "$fails" ]; then
    why="$(update_gate "$TMP/post.log")" || fails+=" post-gate:[$why]"
    indexes "$TMP/post.log" >"$TMP/post-indexes"; cp "$TMP/post.log" "$bk/post.log"
    local lost; lost="$(comm -23 "$bk/pre-indexes" "$TMP/post-indexes")"
    [ -z "$lost" ] || fails+=" lost-index:[$(tr '\n' ';' <<<"$lost")]"
    [ -n "$INJECT" ] && fails+=" injected:$INJECT"
  fi
  if [ -n "$fails" ]; then
    echo "$(ts) VERIFY FAILED:$fails -> restoring"
    restore "$bk" || rc=5
    rm -f "$STATE_DIR/apply.json"
    why="$(update_gate "$TMP/restore.log")" && echo "$(ts) restored; apt-get update after restore ok" || echo "$(ts) restored; apt-get update after restore: $why"
    rm -rf "$TMP"
    return "$([ "$rc" = 5 ] && echo 5 || echo 1)"
  fi
  while IFS= read -r p; do printf '%s\t%s\n' "$p" "$(sha "$R$p")"; done < <(plan_paths) >"$bk/sha-after"
  echo "$(ts) verify ok: apt-get update exit 0, no signature error, $(grep -c . "$bk/pre-indexes") index(es) before = $(grep -c . "$TMP/post-indexes") after; $migrated source(s) moved to signed-by"
  rm -rf "$TMP"
}

restore() { # BACKUP_DIR: remove created files, untar the saved ones, check every sha256; rc 1 on mismatch
  local bk="$1" p want ok=0
  while IFS= read -r p; do [ -n "$p" ] && rm -f "$R$p"; done <"$bk/created"
  [ -f "$bk/files.tar" ] && tar -C "${R:-/}" --numeric-owner -xpf "$bk/files.tar"
  while IFS=$'\t' read -r p want; do
    [ "$(sha "$R$p")" = "$want" ] || { echo "$(ts) RESTORE MISMATCH $p: $(sha "$R$p") != $want"; ok=1; }
  done <"$bk/sha-before"
  while IFS= read -r p; do [ -z "$p" ] || [ ! -e "$R$p" ] || { echo "$(ts) RESTORE: $p still present"; ok=1; }; done <"$bk/created"
  return "$ok"
}

rollback() {
  local yes=0 why bk id p want
  while [ $# -gt 0 ]; do case "$1" in --yes) yes=1 ;; *) die "unknown argument: $1" 3 ;; esac; shift; done
  [ "$(id -u)" = 0 ] || [ -n "${PFT_AT_TEST:-}" ] || die "rollback needs root" 3
  [ "$yes" = 1 ] || refuse "rollback changes APT trust files: add --yes"
  why="$(maint_gate)" || refuse "$why"
  [ -f "$STATE_DIR/apply.json" ] || refuse "no apply on record in $STATE_DIR"
  bk="$(jq -r .backup "$STATE_DIR/apply.json")"; id="$(jq -r .id "$STATE_DIR/apply.json")"
  [ -d "$bk" ] || die "backup $bk missing" 5
  while IFS=$'\t' read -r p want; do
    [ "$(sha "$R$p")" = "$want" ] || echo "$(ts) note: $p changed since the apply; restoring the pre-apply copy anyway"
  done <"$bk/sha-after"
  if ! restore "$bk"; then echo "$(ts) ROLLBACK MISMATCH (see above)"; exit 5; fi
  mv -f "$STATE_DIR/apply.json" "$STATE_DIR/rolled-back-$id.json"
  TMP="$(mktemp -d)"
  if why="$(update_gate "$TMP/rb.log")"; then echo "$(ts) rollback on $HOST_LABEL: $(grep -c . "$bk/sha-before") file(s) restored byte-identical, $(grep -c . "$bk/created") removed; apt-get update ok"
  else echo "$(ts) rollback on $HOST_LABEL: files restored byte-identical; apt-get update after rollback: $why"; rm -rf "$TMP"; exit 1; fi
  rm -rf "$TMP"
}

# ---------- pull / validate ----------
validate() { # FILE HOST -> rc 0, or rc 1 with the first reason on stdout
  local f="$1" h="$2" size
  [ -f "$f" ] || { echo "not a file"; return 1; }
  size="$(stat -c %s "$f")"; [ "$size" -le "$MAX_BYTES" ] || { echo "too big ($size bytes)"; return 1; }
  awk -v h="$h" '
    BEGIN { pre = "host=\"" h "\"" }
    /^# (HELP|TYPE) pft_aptrust_[a-z_]+ / || /^$/ { next }
    {
      if (match($0, /^pft_aptrust_[a-z_]+\{/) == 0) { printf "line %d: not a pft_aptrust_ sample\n", NR; bad = 1; exit }
      rest = substr($0, RLENGTH + 1)
      if (index(rest, pre) != 1) { printf "line %d: first label is not %s\n", NR, pre; bad = 1; exit }
      if (rest !~ /^[^{}]*\} -?[0-9]+(\.[0-9]+)?$/) { printf "line %d: malformed sample\n", NR; bad = 1; exit }
      if ($0 ~ /^pft_aptrust_up\{/) up = 1
      if ($0 ~ /^pft_aptrust_last_run_timestamp_seconds\{/) ts = 1
    }
    END {
      if (bad) exit 1
      if (!up) { print "no pft_aptrust_up sample"; exit 1 }
      if (!ts) { print "no pft_aptrust_last_run_timestamp_seconds sample"; exit 1 }
    }' "$f"
}

pull() {
  local tmp why
  valid_label "$PEER_LABEL" || die "bad PEER_LABEL" 3
  [ "$PEER_LABEL" != "$HOST_LABEL" ] || die "refusing to pull over this host's own textfile ($PEER_LABEL)" 3
  [ -n "$PULL_SSH" ] || die "PULL_SSH not set (see $CONF)" 3
  [[ "$PULL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "bad PULL_TIMEOUT" 3
  tmp="$(mktemp "$TEXTFILE_DIR/.pull-aptrust-$PEER_LABEL.XXXXXX")" || die "cannot create a temp file in $TEXTFILE_DIR" 1
  # shellcheck disable=SC2086 # PULL_SSH is a command line from the root-owned env file
  if ! timeout "$PULL_TIMEOUT" $PULL_SSH cat -- "$REMOTE_DIR/pft_aptrust_$PEER_LABEL.prom" >"$tmp" 2>/dev/null </dev/null; then
    rm -f "$tmp"; die "fetch of pft_aptrust_$PEER_LABEL.prom failed" 1
  fi
  if ! why="$(validate "$tmp" "$PEER_LABEL")"; then rm -f "$tmp"; die "validation failed: $why" 2; fi
  if ! { chmod 644 "$tmp" && mv -f "$tmp" "$TEXTFILE_DIR/pft_aptrust_$PEER_LABEL.prom"; }; then rm -f "$tmp"; die "rename failed" 1; fi
}

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  audit) audit "$@" ;;
  apply) apply "$@" ;;
  rollback) rollback "$@" ;;
  pull) [ $# -eq 0 ] || die "pull takes no arguments" 3; pull ;;
  validate) [ $# -eq 2 ] || die "usage: pft-aptrust validate FILE HOST" 3; valid_label "$2" || die "bad host label" 3
            why="$(validate "$1" "$2")" && exit 0; echo "$why"; exit 2 ;;
  version) echo "pft-aptrust $VERSION" ;;
  *) die "usage: pft-aptrust audit|apply|rollback|pull|validate|version (see the header of this script)" 3 ;;
esac
