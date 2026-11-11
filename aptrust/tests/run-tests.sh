#!/usr/bin/env bash
# Offline tests for pft-aptrust.sh: a fixture root (PFT_AT_ROOT) shaped like the live hosts, stub gpg (colon lines
# from the fixture keyring), stub dpkg / apt / apt-config / docker, fake clock. No root; nothing on the host changes.
# The clean fixture must PASS; every negative control changes ONE thing and must produce its own finding.
#   bash aptrust/tests/run-tests.sh [SCRIPT]   (default ../pft-aptrust.sh)
# Prints one PASS/FAIL line per assertion and "RESULT: N/M passed"; exit 0 only if all passed.
# shellcheck disable=SC2016,SC2034  # check() eval()s its single-quoted condition; OUT/RC are read there
set -uo pipefail
umask 022   # fixture files must be 0644 like the hosts' (the tool flags group-writable APT files)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
S="${1:-$HERE/../pft-aptrust.sh}"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "${T:?}"' EXIT
chmod 755 "$T"
pass=0; total=0
ok()  { total=$((total + 1)); pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
bad() { total=$((total + 1)); printf 'FAIL %s\n' "$1"; [ -z "${APTRUST_FAILFAST:-}" ] || exit 1; }
check() { if (eval "$2"); then ok "$1"; else bad "$1"; fi; }
NOW=4070908800   # 2099-01-01
PFT_AT_UID_ROOT="$(id -u)"
export PFT_AT_ROOT="$T/root" PFT_AT_NOW=$NOW PFT_AT_UID_ROOT PFT_AT_CONF="$T/pft-aptrust.env"
export PFT_AT_GPG="$T/bin/gpg" PFT_AT_DPKG="$T/bin/dpkg" PFT_AT_APT="$T/bin/apt" PFT_AT_APTCONFIG="$T/bin/apt-config"
export PFT_AT_DOCKER="$T/bin/docker" TEXTFILE_DIR="$T/tf" ALLOW_MANIFEST=/usr/local/lib/pft-aptrust/manifest.tsv
mkdir -p "$T/bin" "$T/tf"

# stub gpg: print the pub: colon lines stored in the keyring fixture (last argument)
printf '#!/bin/sh\nfor a; do f="$a"; done\ngrep "^pub:" "$f"\nexit 0\n' > "$T/bin/gpg"
# stub dpkg: -S PATH -> "pkg: PATH" from $T/owned; -V PKG -> $T/dpkgV (modified files of every package)
cat > "$T/bin/dpkg" <<STUB
#!/bin/sh
case "\$1" in
  -S) grep -F ": \$2" "$T/owned" | grep -E ": \$2\\\$" || { echo "dpkg-query: no path found matching pattern \$2" >&2; exit 1; } ;;
  -V) cat "$T/dpkgV" ;;
  *) exit 9 ;;
esac
STUB
printf '#!/bin/sh\n[ "$1 $2" = "list --installed" ] || exit 9\ncat %s/aptlist\n' "$T" > "$T/bin/apt"
printf '#!/bin/sh\n[ "$1" = dump ] || exit 9\ncat %s/aptdump\n' "$T" > "$T/bin/apt-config"
# stub docker: ps -> names in $T/docker/ps (or exit 1 if $T/docker/psfail); inspect -f FMT NAME -> the line for
# FMT kind from $T/docker/NAME.{ref,label,wd}; image inspect -f FMT ID -> $T/docker/ID.rd
cat > "$T/bin/docker" <<STUB
#!/bin/bash
D="$T/docker"
case "\$1" in
  ps) [ -e "\$D/psfail" ] && exit 1; cat "\$D/ps" ;;
  inspect) case "\$3" in *working_dir*) cat "\$D/\$4.wd" 2>/dev/null; echo ;; *Labels*) cat "\$D/\$4.label" 2>/dev/null; echo ;;
             *) cat "\$D/\$4.ref" ;; esac ;;
  image) cat "\$D/\$5.rd" 2>/dev/null; echo ;;
  *) exit 9 ;;
esac
STUB
chmod +x "$T/bin/"*

RA="$T/root/etc/apt"
pub() { # VALIDITY LEN ALGO KEYID EXPIRES -> one gpg colon line
  printf 'pub:%s:%s:%s:%s:1600000000:%s::-:::scESC::::::23::0:\n' "$1" "$2" "$3" "$4" "$5"
}
reset() { # the clean fixture: Ubuntu archive + one https/signed-by vendor source, stock keys, pinned images
  rm -rf "$T/root" "$T/docker" "$T/tf"; mkdir -p "$T/tf" "$T/docker"
  mkdir -p "$RA/sources.list.d" "$RA/apt.conf.d" "$RA/preferences.d" "$RA/trusted.gpg.d" "$RA/keyrings" \
           "$T/root/usr/local/bin" "$T/root/usr/local/sbin" "$T/root/usr/local/lib/pft-aptrust" "$T/root/opt/postfiatd"
  printf '# comment\ndeb http://archive.ubuntu.com/ubuntu jammy main restricted\n\ndeb http://security.ubuntu.com/ubuntu jammy-security main  # tail\n' > "$RA/sources.list"
  printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/vendor.gpg] https://pkg.vendor.example/apt stable main\n' > "$RA/sources.list.d/vendor.list"
  printf 'Types: deb\nURIs: https://pkg2.vendor.example/apt\nSuites: stable\nComponents: main\nSigned-By: /etc/apt/keyrings/vendor.gpg\n\n# disabled\nTypes: deb\nURIs: http://old.vendor.example/apt\nSuites: stable\nTrusted: yes\nEnabled: no\n' > "$RA/sources.list.d/vendor2.sources"
  pub - 4096 1 AAAA111122223333 "" > "$RA/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg"
  pub - 4096 22 BBBB111122223333 "" > "$RA/keyrings/vendor.gpg"
  printf 'Package: *\nPin: release o=UbuntuESMApps\nPin-Priority: 510\n' > "$RA/preferences.d/ubuntu-pro-esm-apps"
  printf 'APT::Install-Recommends "1";\nAcquire::Check-Valid-Until "true";\nAcquire::https::Verify-Peer "true";\n' > "$T/aptdump"
  printf 'Listing...\nbash/jammy-updates,now 5.1-6ubuntu1.1 amd64 [installed]\n' > "$T/aptlist"
  printf 'ubuntu-keyring: /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg\nubuntu-pro-client: /etc/apt/preferences.d/ubuntu-pro-esm-apps\nfoo: /usr/local/bin/foo-packaged\n' > "$T/owned"
  : > "$T/dpkgV"
  for f in pft-kmod pft-agent foo-packaged; do printf '#!/bin/sh\n' > "$T/root/usr/local/bin/$f"; done
  printf '# ADDON REPO_PATH INSTALL_PATH MODE ROLES\nkmod kmod/pft-kmod.sh /usr/local/bin/pft-kmod 0755 both\n' > "$T/root/usr/local/lib/pft-aptrust/manifest.tsv"
  printf 'services:\n  postfiatd:\n    image: agtipft/postfiatd:${NETWORK:-devnet}-light-latest\n  prom:\n    image: "prom/prometheus:v3.5.0@sha256:%064d"\n' 0 > "$T/root/opt/postfiatd/docker-compose.yml"
  printf 'postfiatd\npft-prometheus\n' > "$T/docker/ps"
  echo "agtipft/postfiatd:testnet-light-latest sha256:aaa" > "$T/docker/postfiatd.ref"
  echo "agtipft/postfiatd@sha256:$(printf '%064d' 1)" > "$T/docker/sha256:aaa.rd"
  echo "/opt/postfiatd/docker-compose.yml" > "$T/docker/postfiatd.label"
  echo "/opt/postfiatd" > "$T/docker/postfiatd.wd"
  printf '# compose .env\nNETWORK="testnet"\n' > "$T/root/opt/postfiatd/.env"
  echo "prom/prometheus:v3.5.0 sha256:bbb" > "$T/docker/pft-prometheus.ref"
  echo "prom/prometheus@sha256:$(printf '%064d' 2)" > "$T/docker/sha256:bbb.rd"
  : > "$T/pft-aptrust.env"
  find "$T/root" -type d -exec chmod 755 {} +; find "$T/root" -type f -exec chmod 644 {} +
  chmod 755 "$T/root/usr/local/bin/"*
}
run() { OUT="$(bash "$S" "$@" 2>&1)"; RC=$?; }
# output columns are padded: compare with runs of spaces squeezed to one, in the output and the pattern
sq() { tr '\t' ' ' | sed -E 's/ {2,}/ /g'; }   # plan lines are tab-separated
has() { grep -qE "$(sq <<<"$1")" < <(sq <<<"$OUT"); }
cnt() { grep -cE "$(sq <<<"$1")" < <(sq <<<"$OUT"); }

# ---------- clean fixture ----------
reset; run audit
check "clean: exit 0" '[ "$RC" = 0 ]'
check "clean: no WARN/FAIL lines" '[ "$(cnt "^(WARN|FAIL) ")" = 0 ]'
check "clean: 4 sources graded (2 ubuntu, 1 list, 1 deb822; disabled stanza skipped)" 'has "RESULT: PASS - 4 sources, 2 keys, 2 containers"'
check "clean: ubuntu http is INFO" '[ "$(cnt "^INFO  src:/etc/apt/sources.list:[24] .*Ubuntu archive over http")" = 2 ]'
check "clean: comment tail stripped (line 4 graded)" 'has "^INFO  src:/etc/apt/sources.list:4 "'
check "clean: vendor https+signed-by PASS" 'has "^PASS  src:/etc/apt/sources.list.d/vendor.list:1 .*https \+ signed-by /etc/apt/keyrings/vendor.gpg"'
check "clean: deb822 stanza PASS at its first line" 'has "^PASS  src:/etc/apt/sources.list.d/vendor2.sources:1 "'
check "clean: disabled Trusted: yes stanza not graded" '! has "old.vendor.example"'
check "clean: stock global key INFO" 'has "^INFO  global:/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg stock file of package ubuntu-keyring"'
check "clean: vendor key PASS" 'has "^PASS  key:/etc/apt/keyrings/vendor.gpg 1 usable"'
check "clean: aptconf PASS" 'has "^PASS  aptconf "'
check "clean: stock pin INFO" 'has "^INFO  pin:/etc/apt/preferences.d/ubuntu-pro-esm-apps:1 stock file of ubuntu-pro-client"'
check "clean: official rolling image INFO" 'has "^INFO  image:postfiatd .*official rolling tag"'
check "clean: version-tag image with RepoDigest PASS" 'has "^PASS  image:pft-prometheus "'
check "clean: compose \${NETWORK:-devnet} resolved from the project .env (testnet), official INFO" 'has "^INFO  compose:/opt/postfiatd/docker-compose.yml:3 agtipft/postfiatd:testnet-light-latest: official"'
check "clean: compose digest pin PASS (quoted)" 'has "^PASS  compose:/opt/postfiatd/docker-compose.yml:5 prom/prometheus:v3.5.0@sha256:0+ pinned"'
check "clean: 2 allowlisted add-on files (manifest + default pft-agent), packaged file skipped" 'has "^INFO  offpkg +2 add-on file"'
run audit --json
check "clean: json exit 0, result PASS" '[ "$(jq -r ".exit, .result" <<<"$OUT" | tr "\n" " ")" = "0 PASS " ]'
run audit --textfile
F="$T/tf/pft_aptrust_validator.prom"
check "clean: textfile up 1, fail 0, warn 0, 4 sources" 'grep -q "^pft_aptrust_up{host=\"validator\"} 1$" "$F" && grep -q "result=\"fail\"} 0$" "$F" && grep -q "result=\"warn\"} 0$" "$F" && grep -q "^pft_aptrust_sources{host=\"validator\"} 4$" "$F"'
check "clean: textfile is 0644, no temp left" '[ "$(stat -c %a "$F")" = 644 ] && [ -z "$(ls -A "$T/tf" | grep "^\.")" ]'

# ---------- negative controls: each changes one thing ----------
neg() { # NAME EXPECTED_REGEX  (runs audit on the current fixture; requires exit 1 and the finding line)
  local re="$2"   # check() evals in its own frame, where $2 is the condition (lesson 94)
  run audit
  check "neg $1: exit 1 + finding" '[ "$RC" = 1 ] && has "$re"'
}
reset; sed -i 's#^deb \[arch#deb [trusted=yes arch#' "$RA/sources.list.d/vendor.list"; neg "trusted=yes" "^FAIL  src:/etc/apt/sources.list.d/vendor.list:1 trusted=yes"
reset; sed -i 's#^deb \[arch#deb [allow-insecure=yes arch#' "$RA/sources.list.d/vendor.list"; neg "allow-insecure" "^FAIL  src:.*vendor.list:1 allow-insecure=yes"
reset; sed -i 's#^deb \[arch#deb [allow-weak=YES arch#' "$RA/sources.list.d/vendor.list"; neg "allow-weak (upper case)" "^FAIL  src:.*vendor.list:1 allow-weak=yes"
reset; sed -i 's#^Signed-By: .*#&\nTrusted: yes#' "$RA/sources.list.d/vendor2.sources"; neg "deb822 Trusted: yes" "^FAIL  src:.*vendor2.sources:1 trusted=yes"
reset; sed -i 's#vendor.gpg\]#missing.gpg]#' "$RA/sources.list.d/vendor.list"; neg "signed-by missing keyring" "^FAIL  src:.*vendor.list:1 signed-by keyring /etc/apt/keyrings/missing.gpg missing"
reset; echo 'deb http://pkg.thirdparty.example/apt stable main' > "$RA/sources.list.d/tp.list"; neg "third-party http, no signed-by" "^FAIL  src:.*tp.list:1 third-party source over http with no signed-by"
reset; echo 'deb https://pkg.thirdparty.example/apt stable main' > "$RA/sources.list.d/tp.list"; neg "third-party https, no signed-by" "^WARN  src:.*tp.list:1 third-party source with no signed-by"
reset; echo 'deb [signed-by=/etc/apt/keyrings/vendor.gpg] http://pkg.thirdparty.example/apt stable main' > "$RA/sources.list.d/tp.list"; neg "third-party http with signed-by" "^WARN  src:.*tp.list:1 third-party source over http \(signed-by"
reset; echo 'deb http://evil.example/archive.ubuntu.com/ubuntu jammy main' > "$RA/sources.list.d/tp.list"; neg "ubuntu name in the path is not an ubuntu host" "^FAIL  src:.*tp.list:1 third-party"
reset; echo 'deb http://archive.ubuntu.com.evil.example/ubuntu jammy main' > "$RA/sources.list.d/tp.list"; neg "ubuntu host as a prefix of another domain" "^FAIL  src:.*tp.list:1 third-party"
reset; echo 'deb http://de.archive.ubuntu.com/ubuntu jammy main' > "$RA/sources.list.d/mirror.list"; run audit
check "country mirror *.archive.ubuntu.com is Ubuntu (INFO, exit 0)" '[ "$RC" = 0 ] && has "^INFO  src:.*mirror.list:1 Ubuntu archive"'
reset; rm "$RA/sources.list" "$RA/sources.list.d/"*; neg "no enabled source" "^FAIL  src +no enabled APT source"
reset; pub - 4096 1 CCCC111122223333 "" > "$RA/trusted.gpg"; neg "legacy trusted.gpg with keys" "^FAIL  legacy .*deprecated global keyring"
reset; pub - 4096 1 DDDD111122223333 "" > "$RA/trusted.gpg.d/vendor-global.gpg"; neg "non-stock global key" "^WARN  global:/etc/apt/trusted.gpg.d/vendor-global.gpg not a stock package file"
reset; echo "??5??????   /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg" > "$T/dpkgV"; neg "stock global key modified (dpkg -V)" "^WARN  global:/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg not a stock"
reset; chmod 666 "$RA/keyrings/vendor.gpg"; neg "world-writable keyring" "^FAIL  perm:/etc/apt/keyrings/vendor.gpg mode 666"
reset; chmod 775 "$RA/sources.list.d"; neg "group-writable sources.list.d" "^FAIL  perm:/etc/apt/sources.list.d mode 775"
reset; touch "$RA/apt.conf.d/99x"; chmod 646 "$RA/apt.conf.d/99x"; neg "world-writable apt.conf.d file" "^FAIL  perm:/etc/apt/apt.conf.d/99x mode 646"
reset; OUT="$(PFT_AT_UID_ROOT=999999 bash "$S" audit 2>&1)"; RC=$?
check "neg not-root-owned: exit 1 + owner finding" '[ "$RC" = 1 ] && has "^FAIL  perm:/etc/apt/sources.list owned by uid [0-9]+, not root"'
reset; pub - 1024 1 EEEE111122223333 "" > "$RA/keyrings/vendor.gpg"; neg "RSA-1024 key" "^FAIL  key:/etc/apt/keyrings/vendor.gpg weak key\(s\): 22223333 RSA-1024"
reset; pub - 2048 1 EEEE111122223333 "" > "$RA/keyrings/vendor.gpg"; run audit
check "RSA-2048 is not weak (boundary)" '[ "$RC" = 0 ] && has "^PASS  key:/etc/apt/keyrings/vendor.gpg"'
reset; pub - 3072 17 FFFF111122223333 "" > "$RA/keyrings/vendor.gpg"; neg "DSA key" "^FAIL  key:.*vendor.gpg weak key\(s\): 22223333 DSA-3072"
reset; pub e 4096 1 AAAA000000000001 $((NOW - 86400)) > "$RA/keyrings/vendor.gpg"; neg "only key expired (validity e)" "^FAIL  key:.*vendor.gpg no usable key: 1 expired/revoked"
reset; pub - 4096 1 AAAA000000000001 $((NOW - 1)) > "$RA/keyrings/vendor.gpg"; neg "only key expired (by date, validity not set)" "^FAIL  key:.*vendor.gpg no usable key"
reset; pub r 4096 1 AAAA000000000001 "" > "$RA/keyrings/vendor.gpg"; neg "only key revoked" "^FAIL  key:.*vendor.gpg no usable key: 1 expired/revoked"
reset; pub - 4096 1 AAAA000000000002 $((NOW + 10 * 86400)) > "$RA/keyrings/vendor.gpg"; neg "key expires in 10 days" "^WARN  key:.*vendor.gpg 00000002 expires 2099-01-11"
reset; pub - 4096 1 AAAA000000000002 $((NOW + 31 * 86400)) > "$RA/keyrings/vendor.gpg"; run audit
check "key expiring in 31 days is not WARN (boundary)" '[ "$RC" = 0 ]'
reset; { pub e 4096 1 AAAA000000000001 $((NOW - 86400)); pub - 4096 1 AAAA000000000002 ""; } > "$RA/keyrings/vendor.gpg"; run audit
check "expired key next to a usable one is INFO (exit 0)" '[ "$RC" = 0 ] && has "^INFO  key:.*vendor.gpg 1 usable key\(s\), 1 expired"'
reset; : > "$RA/keyrings/vendor.gpg"; neg "empty keyring" "^FAIL  key:/etc/apt/keyrings/vendor.gpg no OpenPGP public key"
reset; pub - 4096 1 AAAA000000000003 "" > "$RA/keyrings/unused.gpg"; chmod 666 "$RA/keyrings/unused.gpg"; neg "unused keyring in /etc/apt/keyrings is still checked" "^FAIL  perm:/etc/apt/keyrings/unused.gpg mode 666"
for kv in 'Acquire::AllowInsecureRepositories "true";' 'Acquire::AllowDowngradeToInsecureRepositories "1";' \
          'Acquire::AllowWeakRepositories "yes";' 'APT::Get::AllowUnauthenticated "true";' 'Acquire::https::Verify-Peer "false";' \
          'Acquire::https::pkg.vendor.example::Verify-Host "false";'; do
  reset; echo "$kv" >> "$T/aptdump"; neg "aptconf ${kv%% *}" "^FAIL  aptconf:${kv%% *} "
done
reset; echo 'Acquire::Check-Valid-Until "false";' >> "$T/aptdump"; neg "aptconf Check-Valid-Until false" "^WARN  aptconf:Acquire::Check-Valid-Until false"
reset; echo 'Acquire::AllowInsecureRepositories "false";' >> "$T/aptdump"; run audit
check "aptconf AllowInsecureRepositories false is fine" '[ "$RC" = 0 ]'
reset; rm "$T/bin/apt-config"; printf '#!/bin/sh\nexit 100\n' > "$T/bin/apt-config"; chmod +x "$T/bin/apt-config"; neg "apt-config dump fails" "^WARN  aptconf +apt-config dump failed"
printf '#!/bin/sh\n[ "$1" = dump ] || exit 9\ncat %s/aptdump\n' "$T" > "$T/bin/apt-config"
reset; printf 'Package: *\nPin: origin pkg.vendor.example\nPin-Priority: 1001\n' > "$RA/preferences.d/vendor"; neg "pin >= 1000" "^WARN  pin:/etc/apt/preferences.d/vendor:1 Pin-Priority 1001 >= 1000"
reset; printf 'Package: *\nPin: origin pkg.vendor.example\nPin-Priority: 600\n' > "$RA/preferences.d/vendor"; neg "third-party pin > 500 for every package" "^WARN  pin:/etc/apt/preferences.d/vendor:1 every package"
reset; printf 'Package: gh\nPin: origin pkg.vendor.example\nPin-Priority: 600\n' > "$RA/preferences.d/vendor"; run audit
check "single-package pin 600 is fine" '[ "$RC" = 0 ] && has "^PASS  pin:/etc/apt/preferences.d/vendor:1"'
reset; printf 'Package: *\nPin: origin pkg.vendor.example\nPin-Priority: 1001\n' > "$RA/preferences.d/vendor.dpkg-old"; run audit
check "preferences.d file with a dot-extension other than .pref is ignored (as APT does)" '[ "$RC" = 0 ] && ! has "vendor.dpkg-old"'
reset; echo nginx >> "$T/docker/ps"; echo "nginx sha256:ccc" > "$T/docker/nginx.ref"; echo "nginx@sha256:$(printf '%064d' 3)" > "$T/docker/sha256:ccc.rd"
neg "untagged third-party image" "^WARN  image:nginx nginx: 'untagged'"
reset; echo web >> "$T/docker/ps"; echo "docker.io/library/nginx:latest sha256:ccc" > "$T/docker/web.ref"; echo "nginx@sha256:$(printf '%064d' 3)" > "$T/docker/sha256:ccc.rd"
neg ":latest third-party image" "^WARN  image:web docker.io/library/nginx:latest: 'latest'"
reset; echo mystery >> "$T/docker/ps"; echo "mystery:1.0 sha256:ddd" > "$T/docker/mystery.ref"; neg "image without RepoDigest" "^WARN  image:mystery mystery:1.0: no RepoDigest"
reset; echo exp >> "$T/docker/ps"; echo "pft-exporter:latest sha256:eee" > "$T/docker/exp.ref"; run audit
check "known local build (LOCAL_IMAGES) is INFO" '[ "$RC" = 0 ] && has "^INFO  image:exp pft-exporter:latest: known local build"'
reset; echo "registry.example:5000/team/app:2.1 sha256:fff" > "$T/docker/pft-prometheus.ref"; echo "registry.example:5000/team/app@sha256:$(printf '%064d' 4)" > "$T/docker/sha256:fff.rd"; run audit
check "registry with a port: tag parsed as 2.1 (PASS)" '[ "$RC" = 0 ] && has "^PASS  image:pft-prometheus registry.example:5000/team/app:2.1: version tag"'
reset; echo "registry.example:5000/team/app sha256:fff" > "$T/docker/pft-prometheus.ref"; echo "registry.example:5000/team/app@sha256:$(printf '%064d' 4)" > "$T/docker/sha256:fff.rd"
neg "registry port is not a tag (untagged)" "^WARN  image:pft-prometheus .*'untagged'"
reset; touch "$T/docker/psfail"; neg "docker ps fails" "^WARN  image +docker ps failed"
reset; printf '  x:\n    image: redis:latest\n' >> "$T/root/opt/postfiatd/docker-compose.yml"; neg "compose :latest" "^WARN  compose:/opt/postfiatd/docker-compose.yml:7 redis:latest"
reset; printf '  x:\n    image: redis:7.2\n' >> "$T/root/opt/postfiatd/docker-compose.yml"; run audit
check "compose version tag is INFO" '[ "$RC" = 0 ] && has "^INFO  compose:.*:7 redis:7.2: version tag without digest"'
reset; echo "/opt/postfiatd/missing.yml" > "$T/docker/postfiatd.label"; neg "compose file listed but missing" "^WARN  compose:/opt/postfiatd/missing.yml listed by container postfiatd"
# compose interpolation from the project .env (working_dir label), never sourced
reset; rm "$T/root/opt/postfiatd/.env"; run audit
check "compose: no project .env -> \${NETWORK:-devnet} takes its default" '[ "$RC" = 0 ] && has "^INFO  compose:.*:3 agtipft/postfiatd:devnet-light-latest: official"'
reset; rm "$T/docker/postfiatd.wd"; run audit
check "compose: no working_dir label -> no .env read, default used" '[ "$RC" = 0 ] && has "^INFO  compose:.*:3 agtipft/postfiatd:devnet-light-latest: official"'
reset; printf 'NETWORK=\n' > "$T/root/opt/postfiatd/.env"; run audit
check "compose: empty NETWORK= with :- -> default" '[ "$RC" = 0 ] && has "^INFO  compose:.*:3 agtipft/postfiatd:devnet-light-latest: official"'
reset; printf "NETWORK='mainnet'\nTAG=latest\nEMPTY=\n" > "$T/root/opt/postfiatd/.env"
printf '  x:\n    image: redis:${TAG:-7.2}\n  y:\n    image: busybox:1.36${EMPTY-x}\n  z:\n    image: ${REG}/tool:1\n' >> "$T/root/opt/postfiatd/docker-compose.yml"
run audit
check "compose: single-quoted .env value used (mainnet)" 'has "^INFO  compose:.*:3 agtipft/postfiatd:mainnet-light-latest: official"'
check "compose: .env TAG=latest turns a pinned-looking default into a WARN" '[ "$RC" = 1 ] && has "^WARN  compose:.*:7 redis:latest"'
check "compose: \${EMPTY-x} with EMPTY set but empty -> empty (version tag INFO)" 'has "^INFO  compose:.*:9 busybox:1.36: version tag"'
check "compose: unset \${REG} without default -> its name" 'has "^INFO  compose:.*:11 REG/tool:1: version tag"'
reset; printf 'NETWORK=$(touch %s/pwned)\n' "$T" > "$T/root/opt/postfiatd/.env"; run audit
check "compose: .env value is text, never executed" '[ ! -e "$T/pwned" ] && has "compose:.*:3 agtipft/postfiatd:\\\$\\(touch"'
reset; printf '#!/bin/sh\n' > "$T/root/usr/local/bin/evil"; chmod 755 "$T/root/usr/local/bin/evil"; neg "unknown /usr/local/bin file" "^WARN  offpkg:/usr/local/bin/evil not from a package"
reset; printf '#!/bin/sh\n' > "$T/root/usr/local/sbin/evil"; chmod 755 "$T/root/usr/local/sbin/evil"; neg "unknown /usr/local/sbin file" "^WARN  offpkg:/usr/local/sbin/evil "
reset; printf '#!/bin/sh\n' > "$T/root/usr/local/bin/extra"; echo 'OFFPKG_ALLOW="/usr/local/bin/extra /usr/local/bin/pft-agent"' > "$T/pft-aptrust.env"; run audit
check "OFFPKG_ALLOW from the env file allows a path" '[ "$RC" = 0 ] && has "^INFO  offpkg +3 add-on"'
reset; printf '#!/bin/sh\n' > "$T/root/usr/local/bin/postfiat-health"; printf '#!/bin/sh\n' > "$T/root/usr/local/sbin/postfiat-docker-user.sh"; run audit
check "default allowlist: the installer's postfiat-health + postfiat-docker-user.sh are known (no WARN)" '[ "$RC" = 0 ] && ! has "offpkg:/usr/local/(s?bin)/postfiat-"'
reset; printf '#!/bin/sh\n' > "$T/root/usr/local/bin/postfiat-healthx"; run audit
check "default allowlist matches whole paths: postfiat-healthx -> WARN" '[ "$RC" = 1 ] && has "^WARN  offpkg:/usr/local/bin/postfiat-healthx "'
reset; chmod 775 "$T/root/usr/local/bin/pft-kmod"; neg "group-writable add-on file" "^FAIL  perm:/usr/local/bin/pft-kmod mode 775"
reset; chmod 777 "$T/root/usr/local/bin"; neg "world-writable /usr/local/bin" "^FAIL  perm:/usr/local/bin mode 777"
reset; rm "$T/root/usr/local/lib/pft-aptrust/manifest.tsv"; neg "allowlist missing" "^WARN  offpkg +allowlist .* missing"
reset; mkdir -p "$T/root/usr/local/lib/python3.10/dist-packages/requests-2.31.0.dist-info"; neg "global pip package" "^WARN  pip:requests-2.31.0.dist-info global pip package"
reset; mkdir -p "$T/root/usr/local/lib/node_modules/left-pad"; neg "global npm package" "^WARN  npm:left-pad global npm package"
reset; echo 'mytool/now 1.0 amd64 [installed,local]' >> "$T/aptlist"; neg "dpkg -i package (installed,local)" "^WARN  dpkg-local:mytool installed with no APT archive"
reset; pub - 1024 1 EEEE111122223333 "" > "$RA/keyrings/vendor.gpg"; echo 'mytool/now 1.0 amd64 [installed,local]' >> "$T/aptlist"; run audit --textfile
F="$T/tf/pft_aptrust_validator.prom"
check "textfile counts 1 fail + 1 warn" 'grep -q "result=\"fail\"} 1$" "$F" && grep -q "result=\"warn\"} 1$" "$F"'
run audit --json
check "json exit 1, FINDINGS, one FAIL check" '[ "$(jq -r ".exit, .result, ([.checks[]|select(.status==\"FAIL\")]|length)" <<<"$OUT" | tr "\n" " ")" = "1 FINDINGS 1 " ]'

# ---------- errors / usage ----------
reset; rm -rf "$RA"; run audit --textfile
check "no /etc/apt: exit 2, textfile up 0" '[ "$RC" = 2 ] && grep -q "^pft_aptrust_up{host=\"validator\"} 0$" "$T/tf/pft_aptrust_validator.prom"'
reset; run audit --bogus; check "unknown argument: exit 3" '[ "$RC" = 3 ]'
reset; echo 'HOST_LABEL=Bad Label' > "$T/pft-aptrust.env"; run audit; check "bad HOST_LABEL: exit 3" '[ "$RC" = 3 ]'
reset; echo 'EXPIRY_WARN_DAYS=x' > "$T/pft-aptrust.env"; run audit; check "bad EXPIRY_WARN_DAYS: exit 3" '[ "$RC" = 3 ]'
reset; echo 'HOST_LABEL=sentry' > "$T/pft-aptrust.env"; run audit --textfile; check "HOST_LABEL from env names the textfile" '[ -s "$T/tf/pft_aptrust_sentry.prom" ]'
run nonsense; check "unknown command: exit 3" '[ "$RC" = 3 ]'

# ---------- apply / rollback ----------
export PFT_AT_TEST=1 PFT_AT_APTGET="$T/bin/apt-get" PFT_AT_GPGV="$T/bin/gpgv" PFT_AT_MAINT="$T/bin/pft-maint" STATE_DIR="$T/state"
# stub gpg, extended: --export FPR prints the pub+fpr lines of FPR from the --keyring file; otherwise pub/fpr lines
cat > "$T/bin/gpg" <<STUB
#!/bin/bash
kr=""; ex=""; last=""
while [ \$# -gt 0 ]; do case "\$1" in --keyring) kr="\$2"; shift ;; --export) ex="\$2"; shift ;; esac; last="\$1"; shift; done
if [ -n "\$ex" ]; then awk -v f="\$ex" '/^pub:/ { p = \$0; next } /^fpr:/ && index(\$0, f) { print p; print }' "\$kr"; exit 0; fi
grep -E "^(pub|fpr):" "\$last"; exit 0
STUB
# stub gpgv: VALIDSIG <signfpr> if one of the --keyring files holds it (and the signed file exists)
cat > "$T/bin/gpgv" <<STUB
#!/bin/bash
f=\$(cat "$T/signfpr"); hit=0; last=""
while [ \$# -gt 0 ]; do case "\$1" in --keyring) grep -q "fpr:::::::::\$f:" "\$2" && hit=1; shift ;; esac; last="\$1"; shift; done
[ -f "\$last" ] && [ "\$hit" = 1 ] || exit 2
echo "[GNUPG:] VALIDSIG \$f 2026-01-01 0 0 4 0 1 10 01 \$f"
STUB
# stub apt-get update: $T/aptget.out (rc in $T/aptget.rc); once a source line carries signed-by and $T/break_after
# exists, prints a NO_PUBKEY error (a migration that broke verification); $T/drop_after drops one index line
cat > "$T/bin/apt-get" <<STUB
#!/bin/bash
[ "\$1" = update ] || exit 9
if [ -e "$T/break_after" ] && grep -qs 'signed-by=/etc/apt/keyrings/pft-aptrust' "$RA"/sources.list.d/*.list; then
  echo "W: GPG error: https://pkg.tp.example/apt stable InRelease: NO_PUBKEY 1111222233334444"; echo "E: The repository is not signed."; exit 100
fi
if [ -e "$T/drop_after" ] && grep -qs 'signed-by=/etc/apt/keyrings/pft-aptrust' "$RA"/sources.list.d/*.list; then grep -v pkg.tp.example "$T/aptget.out"; exit 0; fi
cat "$T/aptget.out"; exit "\$(cat "$T/aptget.rc")"
STUB
printf '#!/bin/sh\n[ "$1 $2" = "status --json" ] || exit 9\ncat %s/maint.json\n' "$T" > "$T/bin/pft-maint"
chmod +x "$T/bin/"*
VF=1111222233334444555566667777888899990000
areset() { # clean fixture + a legacy third-party source: key in /etc/apt/trusted.gpg, no signed-by
  reset; rm -rf "$T/state" "$T/break_after" "$T/drop_after"
  printf 'pub:-:4096:1:9999000011112222:1600000000:::-:::scESC::::::23::0:\nfpr:::::::::%s:\n' "$VF" > "$RA/trusted.gpg"
  echo 'deb https://pkg.tp.example/apt stable main' > "$RA/sources.list.d/tp.list"
  mkdir -p "$T/root/var/lib/apt/lists"; echo signed > "$T/root/var/lib/apt/lists/pkg.tp.example_apt_dists_stable_InRelease"
  echo "$VF" > "$T/signfpr"
  printf 'Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\nHit:2 https://pkg.tp.example/apt stable InRelease\nReading package lists...\n' > "$T/aptget.out"
  echo 0 > "$T/aptget.rc"
  printf '{"window":"active","remaining_sec":1500,"locks":[]}\n' > "$T/maint.json"
  chmod 644 "$RA/trusted.gpg" "$RA/sources.list.d/tp.list"
}
tree() { (cd "$T/root" && find . -printf '%P %m %s\n' | sort && find . -type f -exec sha256sum {} + | sort -k2); }
KR=/etc/apt/keyrings/pft-aptrust-pkg.tp.example.gpg
areset; run audit
check "apply fixture: audit sees legacy keyring FAIL + unsigned source WARN" '[ "$RC" = 1 ] && has "^FAIL  legacy " && has "^WARN  src:/etc/apt/sources.list.d/tp.list:1 third-party source with no signed-by"'
B="$(tree)"
run apply; check "apply without --yes: exit 4, nothing written" '[ "$RC" = 4 ] && has "REFUSED - apply changes APT trust files: add --yes" && [ "$(tree)" = "$B" ]'
echo '{"window":"none","remaining_sec":0,"locks":[]}' > "$T/maint.json"; run apply --yes
check "apply without a maint window: exit 4" '[ "$RC" = 4 ] && has "REFUSED - no active pft-maint window" && [ "$(tree)" = "$B" ]'
echo '{"window":"active","remaining_sec":300,"locks":[]}' > "$T/maint.json"; run apply --yes
check "apply with < MAINT_MIN left: exit 4" '[ "$RC" = 4 ] && has "REFUSED - pft-maint window has 300 s left" && [ "$(tree)" = "$B" ]'
echo '{"window":"active","remaining_sec":1500,"locks":[{"name":"x"}]}' > "$T/maint.json"; run apply --yes
check "apply with a data-collection lock: exit 4" '[ "$RC" = 4 ] && has "REFUSED - 1 pft-maint data-collection lock" && [ "$(tree)" = "$B" ]'
printf '{"window":"active","remaining_sec":1500,"locks":[]}\n' > "$T/maint.json"
run apply --dry-run
check "dry-run: plan sign + drop, nothing written" '[ "$RC" = 0 ] && has "plan sign /etc/apt/sources.list.d/tp.list 1 https://pkg.tp.example/apt $KR $VF" && has "plan drop /etc/apt/trusted.gpg" && has "dry-run: nothing written" && [ "$(tree)" = "$B" ] && [ ! -e "$T/state" ]'
echo 100 > "$T/aptget.rc"; run apply --yes
check "pre-gate apt-get update fails: refused, nothing written" '[ "$RC" = 4 ] && has "REFUSED - pre-apply gate: apt-get update exit 100" && [ "$(tree)" = "$B" ]'
echo 0 > "$T/aptget.rc"; echo "W: GPG error: x InRelease: NO_PUBKEY 1234" >> "$T/aptget.out"; run apply --yes
check "pre-gate signature error: refused, nothing written" '[ "$RC" = 4 ] && has "REFUSED - pre-apply gate: apt-get update reported: W: GPG error" && [ "$(tree)" = "$B" ]'
areset; B="$(tree)"; run apply --yes
check "apply: exit 0, verify ok" '[ "$RC" = 0 ] && has "verify ok: apt-get update exit 0, no signature error, 2 index\(es\) before = 2 after; 1 source"'
check "apply: source line now has signed-by" 'grep -qx "deb \[signed-by=$KR\] https://pkg.tp.example/apt stable main" "$RA/sources.list.d/tp.list"'
check "apply: new keyring holds exactly the signer key, 0644" 'grep -q "fpr:::::::::$VF:" "$T/root$KR" && [ "$(grep -c "^pub:" "$T/root$KR")" = 1 ] && [ "$(stat -c %a "$T/root$KR")" = 644 ]'
check "apply: legacy trusted.gpg dropped" '[ ! -e "$RA/trusted.gpg" ]'
run audit; check "after apply: audit exit 0 (legacy + unsigned findings gone)" '[ "$RC" = 0 ] && has "^PASS  src:/etc/apt/sources.list.d/tp.list:1 https \+ signed-by $KR"'
run apply --yes; check "second apply while the first is in place: exit 4" '[ "$RC" = 4 ] && has "REFUSED - the last apply .* is still in place"'
run rollback; check "rollback without --yes: exit 4" '[ "$RC" = 4 ]'
run rollback --yes
check "rollback: exit 0, tree byte-identical to before apply (bytes, modes, removed keyring)" '[ "$RC" = 0 ] && has "rollback on validator: 2 file\(s\) restored byte-identical, 1 removed; apt-get update ok" && [ "$(tree | grep -v "^var/lib/apt/lists\|^$")" = "$(grep -v "^var/lib/apt/lists\|^$" <<<"$B")" ]'
check "rollback: apply record archived" '[ ! -e "$T/state/apply.json" ] && ls "$T/state"/rolled-back-*.json >/dev/null'
run rollback --yes; check "rollback with no apply on record: exit 4" '[ "$RC" = 4 ] && has "REFUSED - no apply on record"'
areset; sed -i 's#^deb #deb [arch=amd64] #' "$RA/sources.list.d/tp.list"; run apply --yes
check "apply into an existing [options] block" '[ "$RC" = 0 ] && grep -qx "deb \[signed-by=$KR arch=amd64\] https://pkg.tp.example/apt stable main" "$RA/sources.list.d/tp.list"'
areset; B="$(tree)"; touch "$T/break_after"; run apply --yes
check "post-gate NO_PUBKEY: exit 1, auto-restored byte-identical, no apply record" '[ "$RC" = 1 ] && has "VERIFY FAILED: post-gate:\[apt-get update exit 100\]" && has "restored; apt-get update after restore ok" && [ "$(tree)" = "$B" ] && [ ! -e "$T/state/apply.json" ]'
areset; B="$(tree)"; touch "$T/drop_after"; run apply --yes
check "post-gate lost an index: exit 1, restored" '[ "$RC" = 1 ] && has "VERIFY FAILED: lost-index:\[https://pkg.tp.example/apt stable;\]" && [ "$(tree)" = "$B" ]'
areset; B="$(tree)"; OUT="$(VERIFY_INJECT=drill bash "$S" apply --yes 2>&1)"; RC=$?
check "VERIFY_INJECT: exit 1, restored byte-identical" '[ "$RC" = 1 ] && has "VERIFY FAILED: injected:drill" && [ "$(tree)" = "$B" ]'
areset; mkdir -p "$T/root/etc/apt/keyrings"; echo other > "$T/root$KR"; chmod 644 "$T/root$KR"; B="$(tree)"; run apply --yes
check "target keyring already exists: refused, nothing written" '[ "$RC" = 4 ] && has "REFUSED - $KR already exists" && [ "$(tree)" = "$B" ]'
areset; printf 'pub:-:4096:1:AAAA000011112222:1600000000:::-:::scESC::::::23::0:\nfpr:::::::::%s:\n' AAAA0000111122223333444455556666777788ZZ >> "$RA/trusted.gpg"; run apply --yes
check "global keyring with an unused extra key: source signed, keyring kept (manual)" '[ "$RC" = 0 ] && [ -e "$RA/trusted.gpg" ] && has "manual /etc/apt/trusted.gpg keeps key\(s\) no source here is signed by" && grep -q "signed-by=$KR" "$RA/sources.list.d/tp.list"'
areset; rm "$T/root/var/lib/apt/lists/"*; run apply --yes
check "no cached InRelease: manual, keyring kept, nothing to apply" '[ "$RC" = 0 ] && has "manual /etc/apt/sources.list.d/tp.list:1 no cached InRelease" && has "nothing to apply" && [ -e "$RA/trusted.gpg" ]'
areset; echo 0000000000000000000000000000000000000000 > "$T/signfpr"; run apply --yes
check "InRelease verifies with no global key: manual, nothing written" '[ "$RC" = 0 ] && has "verifies with no global key" && has "nothing to apply"'
areset; rm "$RA/sources.list.d/tp.list"; printf 'Types: deb\nURIs: https://pkg.tp.example/apt\nSuites: stable\nComponents: main\n' > "$RA/sources.list.d/tp.sources"; chmod 644 "$RA/sources.list.d/tp.sources"; run apply --yes
check "deb822 without Signed-By: manual, legacy keyring NOT dropped" '[ "$RC" = 0 ] && has "manual /etc/apt/sources.list.d/tp.sources:1 deb822 stanza without Signed-By" && [ -e "$RA/trusted.gpg" ] && ! has "plan +drop"'
# the legacy key signs a list source apply CAN move AND a deb822 source it cannot: the list source is signed, but the
# keyring must stay, or the deb822 source loses its only key (every key "moved" is not enough; mutant P12)
areset; printf 'Types: deb\nURIs: https://pkg3.tp.example/apt\nSuites: stable\nComponents: main\n' > "$RA/sources.list.d/tp3.sources"; chmod 644 "$RA/sources.list.d/tp3.sources"; run apply --yes
check "signable list + unsignable deb822 on one legacy key: list signed, legacy keyring kept" '[ "$RC" = 0 ] && grep -q "signed-by=$KR" "$RA/sources.list.d/tp.list" && has "manual /etc/apt/sources.list.d/tp3.sources:1 deb822 stanza without Signed-By" && [ -e "$RA/trusted.gpg" ] && ! has "plan +drop"'
check "control: the plain one-source apply does plan the drop (the absence check above can match)" 'areset; run apply --dry-run; has "plan +drop.+/etc/apt/trusted.gpg"'
areset; chmod 666 "$RA/keyrings/vendor.gpg"; chmod 775 "$RA/sources.list.d"; B="$(tree)"; run apply --yes
check "perm fixes: keyring 0644, sources.list.d 0755" '[ "$RC" = 0 ] && [ "$(stat -c %a "$RA/keyrings/vendor.gpg")" = 644 ] && [ "$(stat -c %a "$RA/sources.list.d")" = 755 ]'
run rollback --yes
check "rollback restores the old modes (666 / 775) byte-identical" '[ "$RC" = 0 ] && [ "$(stat -c %a "$RA/keyrings/vendor.gpg")" = 666 ] && [ "$(stat -c %a "$RA/sources.list.d")" = 775 ]'
areset; run apply --yes; bk="$(jq -r .backup "$T/state/apply.json")"
( cd "$T" && mkdir -p evil/etc/apt/sources.list.d && echo tampered > evil/etc/apt/sources.list.d/tp.list && tar -C evil -cf "$bk/files.tar" etc/apt/sources.list.d/tp.list ); run rollback --yes
check "rollback whose backup restores wrong bytes: exit 5 RESTORE MISMATCH" '[ "$RC" = 5 ] && has "RESTORE MISMATCH /etc/apt/sources.list.d/tp.list"'

# ---------- validate / pull (the validator copies the sentry's textfile) ----------
RD="$T/remote"; P="$T/tf/pft_aptrust_sentry.prom"
printf '#!/bin/sh\nexec "$@"\n' > "$T/bin/rssh"; printf '#!/bin/sh\nexit 255\n' > "$T/bin/rssh-fail"
printf '#!/bin/sh\nsleep 5\nexec "$@"\n' > "$T/bin/rssh-hang"; chmod +x "$T/bin/rssh"*
preset() { # a sentry textfile in the "remote" dir, the validator's env pointing PULL_SSH at a stub
  reset; rm -rf "$RD"; mkdir -p "$RD"
  echo 'HOST_LABEL=sentry' > "$T/pft-aptrust.env"; TEXTFILE_DIR="$RD" bash "$S" audit --textfile >/dev/null 2>&1
  printf 'HOST_LABEL=validator\nPULL_SSH=%s\nREMOTE_DIR=%s\nPULL_TIMEOUT=%s\n' "$T/bin/${1:-rssh}" "$RD" "${2:-30}" > "$T/pft-aptrust.env"
}
preset; run validate "$RD/pft_aptrust_sentry.prom" sentry
check "validate: a real sentry textfile is accepted for host sentry" '[ "$RC" = 0 ]'
run validate "$RD/pft_aptrust_sentry.prom" validator
check "validate: the same file for host validator -> exit 2, first label is not host=validator" '[ "$RC" = 2 ] && has "first label is not host=\"validator\""'
cp "$RD/pft_aptrust_sentry.prom" "$T/v.prom"; echo 'node_exporter_build_info{host="sentry"} 1' >> "$T/v.prom"; run validate "$T/v.prom" sentry
check "validate: a foreign metric -> exit 2, not a pft_aptrust_ sample" '[ "$RC" = 2 ] && has "not a pft_aptrust_ sample"'
grep -v '^pft_aptrust_up{' "$RD/pft_aptrust_sentry.prom" > "$T/v.prom"; run validate "$T/v.prom" sentry
check "validate: no up sample -> exit 2" '[ "$RC" = 2 ] && has "no pft_aptrust_up sample"'
grep -v '^pft_aptrust_last_run_timestamp_seconds{' "$RD/pft_aptrust_sentry.prom" > "$T/v.prom"; run validate "$T/v.prom" sentry
check "validate: no last_run sample -> exit 2" '[ "$RC" = 2 ] && has "no pft_aptrust_last_run_timestamp_seconds sample"'
sed 's/^\(pft_aptrust_up{host="sentry"}\) 1$/\1 1 x/' "$RD/pft_aptrust_sentry.prom" > "$T/v.prom"; run validate "$T/v.prom" sentry
check "validate: trailing junk on a sample -> exit 2, malformed" '[ "$RC" = 2 ] && has "malformed sample"'
{ cat "$RD/pft_aptrust_sentry.prom"; head -c 70000 /dev/zero | tr '\0' '#'; echo; } > "$T/v.prom"; run validate "$T/v.prom" sentry
check "validate: over 65536 bytes -> exit 2, too big" '[ "$RC" = 2 ] && has "too big"'
preset; run pull
check "pull: copies the peer file byte-identical, 0644, no temp left" '[ "$RC" = 0 ] && cmp -s "$P" "$RD/pft_aptrust_sentry.prom" && [ "$(stat -c %a "$P")" = 644 ] && [ -z "$(ls -A "$T/tf" | grep "^\.")" ]'
echo old > "$P"; preset rssh-fail; echo old > "$P"; run pull
check "pull: failed fetch -> exit 1, old copy kept, no temp left" '[ "$RC" = 1 ] && has "fetch of pft_aptrust_sentry.prom failed" && [ "$(cat "$P")" = old ] && [ -z "$(ls -A "$T/tf" | grep "^\.")" ]'
preset rssh-hang 1; echo old > "$P"; t0=$(date +%s); run pull; t1=$(date +%s)
check "pull: hanging fetch is cut at PULL_TIMEOUT 1 s -> exit 1 in < 4 s, old copy kept" '[ "$RC" = 1 ] && [ $((t1 - t0)) -lt 4 ] && [ "$(cat "$P")" = old ]'
preset; echo 'pft_aptrust_up{host="validator"} 1' >> "$RD/pft_aptrust_sentry.prom"; echo old > "$P"; run pull
check "pull: a fetched file that fails validation -> exit 2, old copy kept, no temp left" '[ "$RC" = 2 ] && has "validation failed: line" && [ "$(cat "$P")" = old ] && [ -z "$(ls -A "$T/tf" | grep "^\.")" ]'
preset; printf 'HOST_LABEL=sentry\nPEER_LABEL=sentry\nPULL_SSH=%s\nREMOTE_DIR=%s\n' "$T/bin/rssh" "$RD" > "$T/pft-aptrust.env"; rm -f "$P"; run pull
check "pull: PEER_LABEL = HOST_LABEL -> exit 3, nothing written" '[ "$RC" = 3 ] && has "refusing to pull over this host" && [ ! -e "$P" ]'
preset; printf 'HOST_LABEL=validator\n' > "$T/pft-aptrust.env"; run pull
check "pull: no PULL_SSH -> exit 3" '[ "$RC" = 3 ] && has "PULL_SSH not set"'
preset; printf 'PULL_SSH=%s\nREMOTE_DIR=%s\nPULL_TIMEOUT=0\n' "$T/bin/rssh" "$RD" > "$T/pft-aptrust.env"; run pull
check "pull: PULL_TIMEOUT 0 -> exit 3" '[ "$RC" = 3 ] && has "bad PULL_TIMEOUT"'
run pull extra; check "pull takes no arguments: exit 3" '[ "$RC" = 3 ]'

# ---------- real gpg: the colon parser against a real keyring ----------
if command -v gpg >/dev/null; then
  G="$T/gnupg"; mkdir -m 700 "$G"
  gpg --batch --homedir "$G" --pinentry-mode loopback --passphrase '' --faked-system-time 20200101T000000 --quick-gen-key 'aptrust test <t@example.invalid>' rsa2048 sign 1y >/dev/null 2>&1
  gpg --batch --homedir "$G" --pinentry-mode loopback --passphrase '' --quick-gen-key 'aptrust ok <ok@example.invalid>' ed25519 sign never >/dev/null 2>&1
  # the stock global keyring must be a real key too, or real gpg reads the stub colon fixture as a corrupt keyring
  reset; gpg --batch --homedir "$G" --export 'aptrust ok' > "$RA/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg"
  gpg --batch --homedir "$G" --export > "$RA/keyrings/vendor.gpg"
  OUT="$(PFT_AT_GPG=gpg PFT_AT_NOW="$(date -u +%s)" bash "$S" audit 2>&1)"; RC=$?
  check "real gpg: expired RSA-2048 + usable Ed25519 -> INFO 1 usable, 1 expired, exit 0" '[ "$RC" = 0 ] && has "^INFO  key:/etc/apt/keyrings/vendor.gpg 1 usable key\(s\), 1 expired"'
  gpg --batch --homedir "$G" --export 'aptrust test' > "$RA/keyrings/vendor.gpg"
  OUT="$(PFT_AT_GPG=gpg PFT_AT_NOW="$(date -u +%s)" bash "$S" audit 2>&1)"; RC=$?
  check "real gpg: only the expired key -> FAIL no usable key (the only FAIL)" '[ "$RC" = 1 ] && has "^FAIL  key:/etc/apt/keyrings/vendor.gpg no usable key" && [ "$(cnt "^(WARN|FAIL) ")" = 1 ]'
  gpg --batch --homedir "$G" --armor --export 'aptrust ok' > "$RA/keyrings/vendor.gpg"
  OUT="$(PFT_AT_GPG=gpg PFT_AT_NOW="$(date -u +%s)" bash "$S" audit 2>&1)"; RC=$?
  check "real gpg: armored Ed25519 keyring -> PASS" '[ "$RC" = 0 ] && has "^PASS  key:/etc/apt/keyrings/vendor.gpg 1 usable"'
  gpgconf --homedir "$G" --kill all >/dev/null 2>&1 || true
else
  bad "real gpg tests: gpg not installed"
fi

echo "RESULT: $pass/$total passed"
[ "$pass" = "$total" ]
