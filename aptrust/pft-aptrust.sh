#!/usr/bin/env bash
# pft-aptrust: supply-chain trust audit for a Post Fiat validator or sentry host (Ubuntu 22.04, postfiatd 1.0.9 in
# Docker). It answers "who can put code on this host through the package and image channels?": APT sources, the
# keys they trust, APT options that weaken signature checks, pinning, the provenance of running container images,
# and code that was installed outside any package manager. It does not look for CVEs (../vulnscan), file hashes
# (../integrity) or deployments (../rollout).
#
# Usage: pft-aptrust audit [--json] [--textfile]   read-only; --textfile also writes TEXTFILE_DIR/pft_aptrust_HOST.prom
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
#   (validator), OFFICIAL_IMAGES (agtipft/postfiatd), LOCAL_IMAGES (pft-exporter), OFFPKG_ALLOW (more allowed
#   /usr/local paths), UBUNTU_HOSTS (archive/security/ports/esm .ubuntu.com and *.archive.ubuntu.com mirrors),
#   EXPIRY_WARN_DAYS (30).
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
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/pft-exporter/textfile}"
ALLOW_MANIFEST="${ALLOW_MANIFEST:-/usr/local/lib/pft-aptrust/manifest.tsv}"
HOST_LABEL=validator; OFFICIAL_IMAGES="agtipft/postfiatd"; LOCAL_IMAGES="pft-exporter"; OFFPKG_ALLOW="/usr/local/bin/pft-agent"
UBUNTU_HOSTS="archive.ubuntu.com security.ubuntu.com ports.ubuntu.com esm.ubuntu.com"; EXPIRY_WARN_DAYS=30
CONF="${PFT_AT_CONF:-/etc/pft-aptrust.env}"
if [ -f "$CONF" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      HOST_LABEL|OFFICIAL_IMAGES|LOCAL_IMAGES|OFFPKG_ALLOW|UBUNTU_HOSTS|EXPIRY_WARN_DAYS)
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
N_SRC=0 N_KEYS=0 N_IMG=0 N_OFFPKG_OK=0

# ubuntu_host URI -> rc 0 if the URI's host is an Ubuntu archive (UBUNTU_HOSTS or an *.archive.ubuntu.com mirror)
ubuntu_host() {
  local h="${1#*://}" u; h="${h%%/*}"; h="${h%%:*}"; h="${h,,}"
  for u in $UBUNTU_HOSTS; do [ "$h" = "$u" ] && return 0; done
  [[ "$h" == *.archive.ubuntu.com ]]
}

# grade_source WHERE TYPE URI OPTS   OPTS: space-separated lower-case key=value (deb822 keys are mapped to these)
grade_source() {
  local where="$1" uri="$3" opts=" $4 " o k v sb="" bad="" scheme="${3%%://*}"
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
  if [ -z "$sb" ] && [ "$scheme" != https ]; then row FAIL "src:$where" "third-party source over $scheme with no signed-by: any global key can sign it and the transport is plain ($uri)"
  elif [ -z "$sb" ]; then row WARN "src:$where" "third-party source with no signed-by: every global key in trusted.gpg.d can sign it ($uri)"
  elif [ "$scheme" != https ]; then row WARN "src:$where" "third-party source over $scheme (signed-by $sb): metadata is signed but readable and replayable until Valid-Until ($uri)"
  else row PASS "src:$where" "https + signed-by $sb ($uri)"; fi
}

# one-line format: deb [opt=v opt2=v] URI suite comps...
scan_list() {
  local f="$1" n=0 line rest opts uri
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1)); line="${line%%#*}"; read -r -a w <<<"$line"
    [ "${#w[@]}" -gt 0 ] || continue
    case "${w[0]}" in deb|deb-src) ;; *) continue ;; esac
    rest="${line#*"${w[0]}"}"; opts=""
    if [[ "$rest" =~ ^[[:space:]]*\[([^]]*)\][[:space:]]*(.*)$ ]]; then opts="${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"; fi
    read -r uri _ <<<"$rest"
    grade_source "${f#"$R"}:$n" "${w[0]}" "$uri" "$opts"
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
  while IFS=$'\t' read -r n t u o; do grade_source "${f#"$R"}:$n" "$t" "$u" "$o"; done <"$TMP/sources.tsv"
}

# perm PATH -> FAIL if not root-owned or group/world-writable (symlinks: the target)
perm_check() {
  local p="$1" st
  [ -e "$R$p" ] || return 0
  st="$(stat -L -c '%u %a' "$R$p" 2>/dev/null)" || return 0
  local uid="${st%% *}" mode="${st##* }"
  if [ -n "${PFT_AT_ROOT:-}" ] && [ -n "${PFT_AT_UID_ROOT:-}" ]; then [ "$uid" = "$PFT_AT_UID_ROOT" ] && uid=0; fi
  if [ "$uid" != 0 ]; then row FAIL "perm:$p" "owned by uid $uid, not root: that user can change what APT trusts"; return 1; fi
  if (( 8#$mode & 8#022 )); then row FAIL "perm:$p" "mode $mode is group/world-writable: a non-root writer can change what APT trusts"; return 1; fi
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
  rm -rf "$TMP"
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

cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in
  audit) audit "$@" ;;
  version) echo "pft-aptrust $VERSION" ;;
  *) die "usage: pft-aptrust audit|version (see the header of this script)" 3 ;;
esac
