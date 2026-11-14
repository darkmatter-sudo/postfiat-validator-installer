#!/usr/bin/env bash
# test-fw.sh: unit tests for pft-integrity's collect_fw (fw:ufw / fw:docker-user items) on stubbed ufw/iptables.
# No root, no real firewall: the function is extracted from the script and run with stubs first on PATH.
# The IPv6-half case is run against the fixed script AND the pre-fix version (CONTROL_REV, git) to show the
# control: the old collector does not see a v6-only change, the new one does.
#   bash integrity/tests/test-fw.sh [path/to/pft-integrity.sh]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${1:-$HERE/../pft-integrity.sh}"
CONTROL_REV="${CONTROL_REV:-46ce9bbf53dd8c1375e3bd8b05b858f8a0b29a6f}"
T="$(mktemp -d -p "${TEST_TMPDIR:-$HOME/.cache}")"; trap 'rm -rf "$T"' EXIT
PASS=0 FAIL=0
ok() { if [ "$2" = 0 ]; then echo "ok   $1"; PASS=$((PASS + 1)); else echo "FAIL $1"; FAIL=$((FAIL + 1)); fi; }

extract() { # extract SCRIPT_FILE OUT: emit() + collect_fw() only
  { grep -E '^emit\(\) ' "$1"; sed -n '/^collect_fw() {/,/^}/p' "$1"; } >"$2"
  grep -q '^collect_fw() {' "$2"
}
extract "$SCRIPT" "$T/new.sh"; ok "collect_fw extracted from $(basename "$SCRIPT")" $?
git -C "$HERE" show "$CONTROL_REV:integrity/pft-integrity.sh" >"$T/old-full.sh" 2>/dev/null &&
  extract "$T/old-full.sh" "$T/old.sh"; ok "pre-fix collect_fw extracted from $CONTROL_REV" $?

# stubs read fixtures from $FX (one dir per scenario)
mkdir -p "$T/bin"
cat >"$T/bin/ufw" <<'EOS'
#!/usr/bin/env bash
case "$*" in
  "show added") cat "$FX/added" ;;
  "status verbose") cat "$FX/status" ;;
  *) exit 2 ;;
esac
EOS
cat >"$T/bin/iptables" <<'EOS'
#!/usr/bin/env bash
[ "$*" = "-S DOCKER-USER" ] && cat "$FX/du4"
EOS
cat >"$T/bin/ip6tables" <<'EOS'
#!/usr/bin/env bash
[ "$*" = "-S DOCKER-USER" ] && cat "$FX/du6"
EOS
chmod 755 "$T/bin/"*

fixture() { # fixture NAME: dual-family baseline (format captured from a live host, peer IP redacted)
  local d="$T/fx/$1"; mkdir -p "$d"
  cat >"$d/added" <<'EOF'
Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp comment 'SSH'
ufw limit 2559/tcp comment 'Post Fiat peer protocol (rate-limited)'
EOF
  cat >"$d/status" <<'EOF'
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                   # SSH
2559/tcp                   LIMIT IN    Anywhere                   # Post Fiat peer protocol (rate-limited)
22/tcp (v6)                ALLOW IN    Anywhere (v6)              # SSH
2559/tcp (v6)              LIMIT IN    Anywhere (v6)              # Post Fiat peer protocol (rate-limited)

EOF
  printf '%s\n' '-N DOCKER-USER' '-A DOCKER-USER -j RETURN' >"$d/du4"
  printf '%s\n' '-N DOCKER-USER' '-A DOCKER-USER -j RETURN' >"$d/du6"
  echo "$d"
}
run() { # run FUNCFILE FIXTUREDIR [nopath-ufw] -> item lines
  local p="$T/bin:$PATH"
  if [ "${3:-}" = no-ufw ]; then mkdir -p "$T/bin-noufw"; cp -p "$T/bin/iptables" "$T/bin/ip6tables" "$T/bin-noufw/"
    p="$T/bin-noufw:/usr/bin:/bin"; fi
  FX="$2" PATH="$p" bash -c ". '$1'; collect_fw"
}
val() { awk -F'\t' -v i="$1" -v f="$2" '$1==i && $2==f {print $3}' <<<"$3"; }

base="$(fixture base)"
B_NEW="$(run "$T/new.sh" "$base")"
ok "baseline: fw:ufw rules 2, v6_rules 2" "$([ "$(val fw:ufw rules "$B_NEW")" = 2 ] && [ "$(val fw:ufw v6_rules "$B_NEW")" = 2 ] && echo 0 || echo 1)"
ok "baseline: deterministic (same input -> same sha256)" "$([ "$(run "$T/new.sh" "$base")" = "$B_NEW" ] && echo 0 || echo 1)"

# 1. the gap: delete only the IPv6 half of 2559 (ufw delete on the v6 rule); `show added` is unchanged
v6="$(fixture v6half)"; sed -i '/^2559\/tcp (v6)/d' "$v6/status"
V_NEW="$(run "$T/new.sh" "$v6")"
ok "v6-only deletion: new collector changes fw:ufw sha256" "$([ "$(val fw:ufw sha256 "$V_NEW")" != "$(val fw:ufw sha256 "$B_NEW")" ] && echo 0 || echo 1)"
ok "v6-only deletion: new collector v6_rules 2 -> 1" "$([ "$(val fw:ufw v6_rules "$V_NEW")" = 1 ] && echo 0 || echo 1)"
B_OLD="$(run "$T/old.sh" "$base")"; V_OLD="$(run "$T/old.sh" "$v6")"
ok "CONTROL: pre-fix collector misses the v6-only deletion (identical items)" "$([ -n "$B_OLD" ] && [ "$B_OLD" = "$V_OLD" ] && echo 0 || echo 1)"

# 2. v6-only addition (a rule present only in user6.rules)
a6="$(fixture v6add)"; printf '%s\n' '8080/tcp (v6)               ALLOW IN    Anywhere (v6)' >>"$a6/status"
A_NEW="$(run "$T/new.sh" "$a6")"
ok "v6-only addition: sha256 changes, v6_rules 2 -> 3" "$([ "$(val fw:ufw sha256 "$A_NEW")" != "$(val fw:ufw sha256 "$B_NEW")" ] && [ "$(val fw:ufw v6_rules "$A_NEW")" = 3 ] && echo 0 || echo 1)"
ok "CONTROL: pre-fix collector misses the v6-only addition" "$([ "$(run "$T/old.sh" "$a6")" = "$B_OLD" ] && echo 0 || echo 1)"

# 3. v4-side change still detected (both versions)
v4="$(fixture v4)"; sed -i "/^ufw limit 2559/d" "$v4/added"; sed -i '/^2559\/tcp  /d' "$v4/status"
F_NEW="$(run "$T/new.sh" "$v4")"
ok "v4 rule removal: rules 2 -> 1 and sha256 changes" "$([ "$(val fw:ufw rules "$F_NEW")" = 1 ] && [ "$(val fw:ufw sha256 "$F_NEW")" != "$(val fw:ufw sha256 "$B_NEW")" ] && echo 0 || echo 1)"

# 4. default policy change
dp="$(fixture policy)"; sed -i 's/^Default: deny (incoming)/Default: allow (incoming)/' "$dp/status"
ok "default policy change: sha256 changes" "$([ "$(val fw:ufw sha256 "$(run "$T/new.sh" "$dp")")" != "$(val fw:ufw sha256 "$B_NEW")" ] && echo 0 || echo 1)"

# 5. noise that must NOT move the hash: Logging/New profiles lines, trailing blank lines
nz="$(fixture noise)"; sed -i 's/^Logging: on (low)/Logging: on (medium)/; s/^New profiles: skip/New profiles: add/' "$nz/status"; echo >>"$nz/status"
ok "logging level / new-profiles / blank lines do not change any item" "$([ "$(run "$T/new.sh" "$nz")" = "$B_NEW" ] && echo 0 || echo 1)"

# 6. DOCKER-USER v6 change detected (unchanged behaviour)
d6="$(fixture du6)"; sed -i '1a -A DOCKER-USER -p tcp --dport 2559 -j DROP' "$d6/du6"
ok "ip6tables DOCKER-USER change: docker-user sha256 + rules change" "$(X="$(run "$T/new.sh" "$d6")"; [ "$(val fw:docker-user rules "$X")" = 3 ] && [ "$(val fw:docker-user sha256 "$X")" != "$(val fw:docker-user sha256 "$B_NEW")" ] && echo 0 || echo 1)"

# 7. no ufw installed: no fw:ufw items, docker-user still emitted
N="$(run "$T/new.sh" "$base" no-ufw)"
ok "no ufw on PATH: no fw:ufw items, fw:docker-user present" "$(! grep -q '^fw:ufw' <<<"$N" && grep -q '^fw:docker-user' <<<"$N" && echo 0 || echo 1)"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
