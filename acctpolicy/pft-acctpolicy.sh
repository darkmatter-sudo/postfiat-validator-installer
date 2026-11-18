#!/usr/bin/env bash
# pft-acctpolicy: local account and authentication-policy audit for a Post Fiat validator or sentry host (Ubuntu 22.04,
# postfiatd 1.0.9 in Docker), plus a guarded fix mode for the safe subset. Covers what ../privesc (sudoers, setuid),
# ../sshcrypto (sshd crypto) and ../authwatch (login events) do not: the account database (passwd/shadow/group), the
# PAM stacks, login.defs / useradd defaults, and the same account checks inside the node container's root filesystem.
#
# Usage: pft-acctpolicy audit [--json]          read-only; one line per check: ID STATUS detail
#        pft-acctpolicy plan                    the fixes apply would make now, as unified diffs (read-only)
#        sudo pft-acctpolicy apply --yes        back up, write the planned fixes, self-test; any failure -> restore
#        sudo pft-acctpolicy rollback --yes     restore the files of the last apply byte-identical
#        sudo pft-acctpolicy selftest           the access self-test apply runs (SSH key login, sudo, su, node)
#        pft-acctpolicy checks                  the check table (ID, fix, what it checks)
#        pft-acctpolicy version
#
# Never changes a password, a password hash, an SSH key, an account's shell, home or group membership, and never
# touches sshd_config or sudoers: every fix edits one of four policy files (FIXABLE below). Hash values never leave
# this script: output names only the scheme (yescrypt, sha512, ...) and counts, never a hash or a hash prefix.
#
# Exit codes: 0 PASS (audit) / ok, 1 findings (audit) / self-test failed and restored (apply), 2 error, 3 usage,
#             4 refused (nothing written), 5 rollback restore mismatch.
# Env: STATE_DIR (/var/lib/pft-acctpolicy: backup/, apply.json)  CONTAINER (auto: postfiatd or postfiatd-sentry)
#      NODE_CFG (/etc/postfiatd/postfiatd.cfg, in the container)  MIN_PEERS (1)  SU_GROUP (sudo)
#      PASS_MAX (365)  PASS_MIN (1)  INACTIVE_DAYS (30)  SELFTEST_USER (the invoking sudo user; self-test key:
#      STATE_DIR/selftest_ed25519)
#      VERIFY_INJECT=selftest (the post-apply self-test fails: automatic-restore drill)
#   Test hooks: PFT_AP_ROOT (prefix for /etc, /home, /proc)  PFT_AP_SSHD (sshd binary)  PFT_AP_SSH  PFT_AP_DOCKER
#      PFT_AP_SUDO  PFT_AP_SELFTEST (replace the SSH self-test command)  PFT_AP_NOW (epoch)
#      PFT_AP_OWNER / PFT_AP_GROUP (expected owner/group of the account files, default root)
# shellcheck disable=SC2016  # hash-scheme prefixes like $y$ are literal
set -uo pipefail
umask 022
VERSION=1.0.0

R="${PFT_AP_ROOT:-}"
SSHD="${PFT_AP_SSHD:-/usr/sbin/sshd}"
SSH="${PFT_AP_SSH:-ssh}"
DOCKER="${PFT_AP_DOCKER:-docker}"
SUDO="${PFT_AP_SUDO:-sudo}"
STATE_DIR="${STATE_DIR:-/var/lib/pft-acctpolicy}"
NODE_CFG="${NODE_CFG:-/etc/postfiatd/postfiatd.cfg}"
MIN_PEERS="${MIN_PEERS:-1}"
SU_GROUP="${SU_GROUP:-sudo}"
PASS_MAX="${PASS_MAX:-365}"
PASS_MIN="${PASS_MIN:-1}"
INACTIVE_DAYS="${INACTIVE_DAYS:-30}"
SELFTEST_USER="${SELFTEST_USER:-${SUDO_USER:-}}"
INJECT="${VERIFY_INJECT:-}"
OWN="${PFT_AP_OWNER:-root}"; GRP="${PFT_AP_GROUP:-root}"

E="$R/etc"
PASSWD="$E/passwd"; SHADOW="$E/shadow"; GROUP="$E/group"; GSHADOW="$E/gshadow"
COMMON_AUTH="$E/pam.d/common-auth"; COMMON_PASSWORD="$E/pam.d/common-password"; PAM_SU="$E/pam.d/su"
LOGIN_DEFS="$E/login.defs"; USERADD="$E/default/useradd"

die() { printf 'pft-acctpolicy: %s\n' "$1" >&2; exit "${2:-2}"; }
now() { echo "${PFT_AP_NOW:-$(date -u +%s)}"; }
ts() { date -u -d "@$(now)" +%FT%TZ; }
sha() { if [ -f "$1" ]; then sha256sum <"$1" | cut -c1-64; else echo absent; fi; }

# id  fix  what
CHECKS='acct.uid0 - only root has UID 0 (passwd)
acct.dup-uid - no two accounts share a UID
acct.dup-name - no duplicate user or group names
acct.shadowed - every passwd entry has password field x and a shadow entry
acct.empty-password - no shadow entry has an empty password field
acct.hash-scheme - every usable password hash is yescrypt or sha512 (scheme only is reported)
acct.root-password - a usable root password is only acceptable when sshd refuses password and keyboard-interactive login
acct.system-shell - system accounts (UID 1-999) with a login shell are locked and reachable only by restrict,command= keys
acct.file-modes - passwd/group (and backups) 0644 or stricter root-owned; shadow/gshadow 0640 root:shadow or stricter
acct.home-modes - human homes (UID >= 1000) are not group-writable or world-accessible
pam.nullok nullok pam_unix in common-auth has no nullok (an empty password would log in)
pam.permit - pam_permit.so is never sufficient or a jump target in any auth stack
pam.faillock - pam_faillock is configured, or no network or non-root password path exists (sshd password/kbd off, only root has a usable password)
pam.su-wheel su-wheel su requires membership of SU_GROUP (pam_wheel use_uid)
login.encrypt encrypt login.defs ENCRYPT_METHOD equals the pam_unix password hash (yescrypt or sha512)
login.pass-max passage login.defs PASS_MAX_DAYS <= PASS_MAX and PASS_MIN_DAYS >= PASS_MIN (new accounts only)
login.umask - login.defs UMASK is 022 or stricter
useradd.inactive inactive useradd INACTIVE is 1..INACTIVE_DAYS (new accounts lock that many days after password expiry)
ctr.uid0 - container root filesystem: only root has UID 0
ctr.empty-password - container: no shadow entry with an empty password field, no hash in passwd
ctr.runtime - container is not privileged, has no-new-privileges and drops ALL capabilities'

# ---------- readers ----------
# hash_kind FIELD -> empty | locked | yescrypt | sha512 | sha256 | md5 | bcrypt | des   (never prints the field)
hash_kind() {
  case "$1" in
    "") echo empty ;; '!'*|'*'*) echo locked ;; '$y$'*) echo yescrypt ;; '$6$'*) echo sha512 ;;
    '$5$'*) echo sha256 ;; '$1$'*) echo md5 ;; '$2'*) echo bcrypt ;; *) echo des ;;
  esac
}
sshd_opt() { # NAME -> value from `sshd -T` (lower case)
  [ -n "${SSHD_T+x}" ] || SSHD_T="$("$SSHD" -T 2>/dev/null)"
  awk -v k="$1" '$1 == k { print tolower($2); exit }' <<<"$SSHD_T"
}
defs() { awk -v k="$1" '$1 == k { v = $2 } END { print v }' "$LOGIN_DEFS" 2>/dev/null; }
useradd_opt() { sed -n "s/^$1=//p" "$USERADD" 2>/dev/null | tail -1; }
pam_lines() { grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }
unix_pw_hash() { # the hash option on pam_unix in common-password
  pam_lines "$COMMON_PASSWORD" | awk '$1 == "password" && $0 ~ /pam_unix\.so/ {
    for (i = 4; i <= NF; i++) if ($i ~ /^(yescrypt|sha512|sha256|md5|bigcrypt|blowfish)$/) h = $i } END { print h }'
}
mode_ok() { # FILE MAXOCTAL OWNER GROUPS(re) -> rc 0 if no bits outside MAX, owner and group match
  local m o g; read -r m o g < <(stat -c '%a %U %G' "$1" 2>/dev/null) || return 1
  [ $(( 8#$m & ~8#$2 )) = 0 ] && [ "$o" = "$3" ] && [[ "$g" =~ ^($4)$ ]]
}

# ---------- audit ----------
RES=()
add() { RES+=("$1"$'\t'"$2"$'\t'"$3"); }

audit_accounts() { # PREFIX ROOTDIR
  local p="$1" r="$2" n
  n="$(awk -F: '$3 == "0" { print $1 }' "$r/etc/passwd" | grep -cvx root)"
  if [ "$p" = acct ]; then
    if [ "$n" = 0 ]; then add acct.uid0 PASS "root is the only UID 0 account"; else add acct.uid0 FAIL "$n account(s) other than root have UID 0"; fi
    n="$(cut -d: -f3 "$r/etc/passwd" | sort | uniq -d | wc -l)"
    if [ "$n" = 0 ]; then add acct.dup-uid PASS "all UIDs unique"; else add acct.dup-uid FAIL "$n UID(s) shared by several accounts"; fi
    n="$( { cut -d: -f1 "$r/etc/passwd" | sort | uniq -d; cut -d: -f1 "$r/etc/group" | sort | uniq -d | sed 's/^/g:/'; } | wc -l)"
    if [ "$n" = 0 ]; then add acct.dup-name PASS "user and group names unique"; else add acct.dup-name FAIL "$n duplicate user/group name(s)"; fi
  else
    if [ "$n" = 0 ]; then add ctr.uid0 PASS "root is the only UID 0 account"; else add ctr.uid0 FAIL "$n account(s) other than root have UID 0"; fi
  fi
}

audit_host() {
  audit_accounts acct "$R"
  local u pw nos=0 nox=0 empty=0 weak="" k ok=0 rootk="" sys_bad=0 sys_ok=0 shell home uid
  declare -A SH=()
  while IFS=: read -r u pw _; do SH[$u]="$pw"; done < "$SHADOW"
  while IFS=: read -r u pw uid _ _ home shell; do
    [ "$pw" = x ] || nox=$((nox + 1))
    [ -n "${SH[$u]+x}" ] || nos=$((nos + 1))
  done < "$PASSWD"
  if [ $((nos + nox)) = 0 ]; then add acct.shadowed PASS "every account has x in passwd and a shadow entry"
  else add acct.shadowed FAIL "$nox passwd entr(ies) without x, $nos without a shadow entry"; fi
  for u in "${!SH[@]}"; do
    k="$(hash_kind "${SH[$u]}")"
    case "$k" in
      empty) empty=$((empty + 1)) ;; locked) ;;
      yescrypt|sha512) ok=$((ok + 1)) ;;
      *) weak="$weak $k" ;;
    esac
    [ "$u" = root ] && rootk="$k"
  done
  if [ "$empty" = 0 ]; then add acct.empty-password PASS "no empty password field"
  else add acct.empty-password FAIL "$empty account(s) with an empty password field"; fi
  if [ -z "$weak" ]; then add acct.hash-scheme PASS "$ok usable hash(es), all yescrypt/sha512"
  else add acct.hash-scheme WARN "weak scheme(s):$(tr ' ' '\n' <<<"$weak" | sort | uniq -c | awk '{printf " %s x%s", $2, $1}') (re-set those passwords; not changed by this tool)"; fi
  local pa kbd prl
  pa="$(sshd_opt passwordauthentication)"; kbd="$(sshd_opt kbdinteractiveauthentication)"; prl="$(sshd_opt permitrootlogin)"
  case "$rootk" in
    locked|"") add acct.root-password PASS "root password locked" ;;
    empty) add acct.root-password FAIL "root has an empty password" ;;
    *) if [ "$pa" = no ] && [ "$kbd" = no ] && [ "$prl" != yes ]; then
         add acct.root-password PASS "root has a usable password (console recovery); sshd: password no, kbd-interactive no, permitrootlogin ${prl:-?}"
       else add acct.root-password FAIL "root has a usable password and sshd allows password=${pa:-?} kbd=${kbd:-?} permitrootlogin=${prl:-?}"; fi ;;
  esac
  local names="" keys line
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -ge 1 ] && [ "$uid" -lt 1000 ]; } 2>/dev/null || continue
    case "$shell" in */nologin|*/false|/bin/sync|/sbin/shutdown|/sbin/halt|"") continue ;; esac
    k="$(hash_kind "${SH[$u]-}")"
    keys="$R$home/.ssh/authorized_keys"
    local good=1
    [ "$k" = locked ] || good=0
    if [ -f "$keys" ]; then
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ (^|,)restrict(,|[[:space:]]) ]] && [[ "$line" =~ (^|,)command=\" ]] || good=0
      done < "$keys"
    fi
    if [ "$good" = 1 ]; then sys_ok=$((sys_ok + 1)); else sys_bad=$((sys_bad + 1)); names="$names uid$uid"; fi
  done < "$PASSWD"
  if [ "$sys_bad" = 0 ]; then add acct.system-shell PASS "$sys_ok system account(s) with a shell, all locked + forced-command keys only"
  else add acct.system-shell WARN "$sys_bad system account(s) with a login shell not locked or with unrestricted keys:$names"; fi
  local bad=""
  for f in "$PASSWD" "$GROUP" "$PASSWD-" "$GROUP-"; do
    [ -e "$f" ] || continue; mode_ok "$f" 644 "$OWN" "$GRP" || bad="$bad ${f#"$R"}"
  done
  for f in "$SHADOW" "$GSHADOW" "$SHADOW-" "$GSHADOW-"; do
    [ -e "$f" ] || continue; mode_ok "$f" 640 "$OWN" "$GRP|shadow" || bad="$bad ${f#"$R"}"
  done
  if [ -z "$bad" ]; then add acct.file-modes PASS "account files 0644/0640 or stricter, root-owned"
  else add acct.file-modes FAIL "mode/owner too open:$bad"; fi
  local hb=0 hn=0
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ]; } 2>/dev/null || continue
    [ -d "$R$home" ] || continue
    hn=$((hn + 1))
    m="$(stat -c '%a' "$R$home")"
    [ $(( 8#$m & 8#027 )) = 0 ] || hb=$((hb + 1))
  done < "$PASSWD"
  if [ "$hb" = 0 ]; then add acct.home-modes PASS "$hn human home(s), none group-writable or world-accessible"
  else add acct.home-modes WARN "$hb of $hn human home(s) group-writable or world-accessible"; fi

  # PAM
  if pam_lines "$COMMON_AUTH" | grep -E 'pam_unix\.so' | grep -qwE 'nullok|nullok_secure'; then
    add pam.nullok WARN "common-auth pam_unix has nullok"
  else add pam.nullok PASS "common-auth pam_unix without nullok"; fi
  local pp; pp="$(for f in "$E"/pam.d/*; do [ -f "$f" ] || continue
      pam_lines "$f" | awk -v f="${f##*/}" '$1 == "auth" && $0 ~ /pam_permit\.so/ && ($2 == "sufficient" || $2 ~ /success=(done|[1-9])/) { print f }'
    done | sort -u | tr '\n' ' ')"
  if [ -z "$pp" ]; then add pam.permit PASS "pam_permit.so is never sufficient in an auth stack"
  else add pam.permit FAIL "pam_permit.so sufficient/jump in: $pp"; fi
  if pam_lines "$COMMON_AUTH" | grep -q 'pam_faillock\.so'; then add pam.faillock PASS "pam_faillock configured in common-auth"
  else
    local others; others="$(for u in "${!SH[@]}"; do [ "$u" = root ] && continue; k="$(hash_kind "${SH[$u]}")"; [ "$k" = locked ] || echo x; done | wc -l)"
    if [ "$pa" = no ] && [ "$kbd" = no ] && [ "$others" = 0 ]; then
      add pam.faillock PASS "not configured; no password path to lock out: sshd password/kbd-interactive no, 0 non-root accounts with a usable password"
    else add pam.faillock WARN "not configured while password=${pa:-?} kbd=${kbd:-?} and $others non-root account(s) have a usable password"; fi
  fi
  if pam_lines "$PAM_SU" | awk '$1 == "auth" && $0 ~ /pam_wheel\.so/ && $0 !~ /deny/ && $0 ~ /use_uid/' | grep -q .; then
    add pam.su-wheel PASS "su restricted by pam_wheel ($(pam_lines "$PAM_SU" | grep -o 'group=[^ ]*' | head -1))"
  else add pam.su-wheel WARN "su is open to every account that knows the target password (no active pam_wheel use_uid)"; fi

  # login.defs / useradd
  local em ph; em="$(defs ENCRYPT_METHOD)"; ph="$(unix_pw_hash)"
  if [ -n "$ph" ] && [ "$(tr '[:upper:]' '[:lower:]' <<<"$em")" = "$ph" ] && [[ "$ph" =~ ^(yescrypt|sha512)$ ]]; then
    add login.encrypt PASS "ENCRYPT_METHOD $em = pam_unix $ph"
  else add login.encrypt WARN "ENCRYPT_METHOD ${em:-unset} vs pam_unix ${ph:-unset} (chpasswd/newusers would hash differently from passwd)"; fi
  local mx mn; mx="$(defs PASS_MAX_DAYS)"; mn="$(defs PASS_MIN_DAYS)"
  if [ "${mx:-99999}" -le "$PASS_MAX" ] 2>/dev/null && [ "${mn:-0}" -ge "$PASS_MIN" ] 2>/dev/null; then
    add login.pass-max PASS "PASS_MAX_DAYS $mx, PASS_MIN_DAYS $mn"
  else add login.pass-max WARN "PASS_MAX_DAYS ${mx:-unset} (> $PASS_MAX) or PASS_MIN_DAYS ${mn:-unset} (< $PASS_MIN)"; fi
  local um; um="$(defs UMASK)"
  if [[ "$um" =~ ^0?[0-7]{3}$ ]] && [ $(( 8#$um & 8#022 )) = $(( 8#022 )) ]; then add login.umask PASS "UMASK $um"
  else add login.umask WARN "UMASK ${um:-unset} lets new files be group/world-writable"; fi
  local ia; ia="$(useradd_opt INACTIVE)"
  if [ "${ia:--1}" -ge 1 ] 2>/dev/null && [ "$ia" -le "$INACTIVE_DAYS" ]; then add useradd.inactive PASS "INACTIVE=$ia"
  else add useradd.inactive WARN "INACTIVE=${ia:--1 (default)} (accounts never lock after password expiry)"; fi
}

container() {
  if [ -n "${CONTAINER:-}" ]; then echo "$CONTAINER"; return; fi
  local c
  for c in postfiatd postfiatd-sentry; do
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = true ] && { echo "$c"; return; }
  done
}

audit_container() {
  local c pid root nx empty
  c="$(container)"
  if [ -z "$c" ]; then
    add ctr.uid0 FAIL "no running node container"; add ctr.empty-password FAIL "no running node container"
    add ctr.runtime FAIL "no running node container"; return
  fi
  pid="$("$DOCKER" inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)"
  root="$R/proc/$pid/root"   # read from the host: nothing runs inside the container (its AppArmor profile denies it)
  if [ ! -r "$root/etc/passwd" ]; then
    add ctr.uid0 FAIL "cannot read $c /etc/passwd via /proc/PID/root"; add ctr.empty-password FAIL "unreadable"
  else
    audit_accounts ctr "$root"
    nx="$(awk -F: '$2 != "x" && $2 !~ /^[!*]/' "$root/etc/passwd" | wc -l)"
    empty=0
    if [ -r "$root/etc/shadow" ]; then empty="$(awk -F: '$2 == ""' "$root/etc/shadow" | wc -l)"; fi
    if [ $((nx + empty)) = 0 ]; then add ctr.empty-password PASS "$c: no empty password field, no hash in passwd"
    else add ctr.empty-password FAIL "$c: $empty empty shadow field(s), $nx passwd entr(ies) with a hash or empty field"; fi
  fi
  local priv sec cd
  priv="$("$DOCKER" inspect -f '{{.HostConfig.Privileged}}' "$c" 2>/dev/null)"
  sec="$("$DOCKER" inspect -f '{{json .HostConfig.SecurityOpt}}' "$c" 2>/dev/null)"
  cd="$("$DOCKER" inspect -f '{{json .HostConfig.CapDrop}}' "$c" 2>/dev/null)"
  if [ "$priv" = false ] && grep -q '"no-new-privileges' <<<"$sec" && grep -qE '"(CAP_)?ALL"' <<<"$cd"; then
    add ctr.runtime PASS "$c: not privileged, no-new-privileges, cap-drop ALL"
  else add ctr.runtime FAIL "$c: privileged=${priv:-?} no-new-privileges=$(grep -q no-new-privileges <<<"$sec" && echo yes || echo no) capdrop=${cd:-?}"; fi
}

run_audit() { RES=(); audit_host; audit_container; }

print_text() {
  local l id st d f=0 w=0 p=0
  echo "pft-acctpolicy $VERSION audit - $(ts)"
  for l in "${RES[@]}"; do
    IFS=$'\t' read -r id st d <<<"$l"
    printf '%-20s %-4s %s\n' "$id" "$st" "$d"
    case "$st" in FAIL) f=$((f + 1)) ;; WARN) w=$((w + 1)) ;; *) p=$((p + 1)) ;; esac
  done
  if [ $((f + w)) = 0 ]; then echo "RESULT: PASS - $p checks"; else echo "RESULT: FINDINGS - $f FAIL, $w WARN, $p PASS"; fi
}
print_json() {
  printf '%s\n' "${RES[@]}" | jq -R -s --arg t "$(ts)" --arg v "$VERSION" '
    [split("\n")[] | select(length > 0) | split("\t") | {id: .[0], status: .[1], detail: .[2]}] as $c
    | {tool: "pft-acctpolicy", version: $v, time: $t, checks: $c,
       fail: ([$c[] | select(.status == "FAIL")] | length), warn: ([$c[] | select(.status == "WARN")] | length)}'
}
rc_of() { printf '%s\n' "${RES[@]}" | cut -f2 | grep -qE 'FAIL|WARN' && return 1; return 0; }

# ---------- fixes: each prints the new content of its file on stdout (current content on stdin) ----------
fix_nullok() { awk 'BEGIN { OFS = "\t" } /^[[:space:]]*#/ || $0 !~ /pam_unix\.so/ { print; next }
  { line = $0; gsub(/[ \t]+nullok(_secure)?([ \t]|$)/, " ", line); sub(/[ \t]+$/, "", line); print line }'; }
fix_su_wheel() { # insert after the pam_rootok line (root keeps su without a password), else at the top
  awk -v g="$SU_GROUP" 'BEGIN { l = "# pft-acctpolicy su-wheel (PAM has no trailing comments)\nauth       required   pam_wheel.so use_uid group=" g }
    { print } !done && $0 !~ /^[[:space:]]*#/ && /pam_rootok\.so/ { print l; done = 1 }
    END { if (!done) exit 7 }'; }
set_key() { # KEY VALUE SEP: replace the last active KEY line, or append
  awk -v k="$1" -v v="$2" -v s="$3" '{ L[NR] = $0 } $0 ~ "^" k "([ \t=]|$)" { last = NR }
    END { for (i = 1; i <= NR; i++) { if (i == last) print k s v; else print L[i] } if (!last) print k s v }'; }
fix_encrypt() { set_key ENCRYPT_METHOD "$(unix_pw_hash | tr '[:lower:]' '[:upper:]')" $'\t'; }
fix_passage() { set_key PASS_MAX_DAYS "$PASS_MAX" $'\t' | set_key PASS_MIN_DAYS "$PASS_MIN" $'\t'; }
fix_inactive() { set_key INACTIVE "$INACTIVE_DAYS" '='; }

# plan -> lines "FIXID FILE" for every fixable check that is WARN now and whose precondition holds
plan_ids() {
  local l id st d
  for l in "${RES[@]}"; do
    IFS=$'\t' read -r id st _ <<<"$l"
    [ "$st" = WARN ] || continue
    case "$id" in
      pam.nullok)       st_of acct.empty-password PASS && echo "nullok $COMMON_AUTH" ;;
      pam.su-wheel)     getent_group "$SU_GROUP" && pam_lines "$PAM_SU" | grep -q pam_rootok && echo "su-wheel $PAM_SU" ;;
      login.encrypt)    [[ "$(unix_pw_hash)" =~ ^(yescrypt|sha512)$ ]] && echo "encrypt $LOGIN_DEFS" ;;
      login.pass-max)   echo "passage $LOGIN_DEFS" ;;
      useradd.inactive) [ -f "$USERADD" ] && echo "inactive $USERADD" ;;
    esac
  done
}
st_of() { printf '%s\n' "${RES[@]}" | awk -F'\t' -v i="$1" -v s="$2" '$1 == i && $2 == s { f = 1 } END { exit !f }'; }
getent_group() { awk -F: -v g="$1" '$1 == g { f = 1 } END { exit !f }' "$GROUP"; }

# build NEWDIR: one candidate file per target, all fixes for a file applied in order
build() {
  local nd="$1" fid f t
  while read -r fid f; do
    t="$nd/$(sha256sum <<<"$f" | cut -c1-16)"
    [ -f "$t" ] || cp -p "$f" "$t"
    case "$fid" in
      nullok) fix_nullok <"$t" >"$t.n" ;; su-wheel) fix_su_wheel <"$t" >"$t.n" ;;
      encrypt) fix_encrypt <"$t" >"$t.n" ;; passage) fix_passage <"$t" >"$t.n" ;; inactive) fix_inactive <"$t" >"$t.n" ;;
    esac || { rm -f "$t.n"; return 1; }
    cat "$t.n" >"$t"; rm -f "$t.n"
    printf '%s\t%s\t%s\n' "$fid" "$f" "$t" >>"$nd/index"
  done < <(plan_ids)
  return 0
}

do_plan() {
  run_audit
  local nd; nd="$(mktemp -d)"; trap 'rm -rf "${nd:?}"' RETURN
  build "$nd" || die "a fix could not be built (unexpected file shape)"
  if [ ! -s "$nd/index" ]; then echo "plan: nothing to fix"; return 0; fi
  echo "plan: $(cut -f1 "$nd/index" | tr '\n' ' ')"
  cut -f2,3 "$nd/index" | sort -u | while IFS=$'\t' read -r f t; do diff -u --label "${f#"$R"}" --label "${f#"$R"} (planned)" "$f" "$t"; done
  return 0
}

# ---------- self-test: everything an operator needs to get back in ----------
node_full() {
  local c out st pe; c="$(container)"; [ -n "$c" ] || { echo "no node container"; return 1; }
  out="$("$DOCKER" exec "$c" postfiatd --conf "$NODE_CFG" server_info 2>/dev/null)"
  st="$(jq -r '.result.info.server_state // empty' <<<"$out" 2>/dev/null)"
  pe="$(jq -r '.result.info.peers // 0' <<<"$out" 2>/dev/null)"
  echo "server_state=${st:-?} peers=${pe:-?}"
  [ "$st" = full ] && [ "${pe:-0}" -ge "$MIN_PEERS" ]
}
ssh_selftest() { # a throwaway sshd on 127.0.0.1:PORT with a minimal private config (UsePAM yes, so /etc/pam.d/sshd
  # and the common-* stacks run account + session for SELFTEST_USER), the self-test key in a private AuthorizedKeysFile,
  # its log in a private file (-E: no "Accepted" line reaches the journal/authwatch), then `sudo -n true` inside the
  # session. No authorized_keys file, sshd_config or the real sshd is touched. The key (KEY_FILE, created once, root
  # 0600) is accepted by nothing but this throwaway sshd; install.sh allowlists its fingerprint in authwatch as well.
  if [ -n "${PFT_AP_SELFTEST:-}" ]; then "$PFT_AP_SELFTEST"; return; fi
  [ -n "$SELFTEST_USER" ] || { echo "no SELFTEST_USER"; return 1; }
  local k="$STATE_DIR/selftest_ed25519" d port rc pid
  if [ ! -f "$k" ]; then
    if ! { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR" && ssh-keygen -q -t ed25519 -N '' -C pft-acctpolicy-selftest -f "$k"; }; then
      echo "cannot create $k"; return 1
    fi
  fi
  d="$(mktemp -d /run/pft-acctpolicy.XXXXXX)" || return 1
  port=$(( 30000 + RANDOM % 20000 ))
  ssh-keygen -q -t ed25519 -N '' -f "$d/hk" || { rm -rf "$d"; return 1; }
  cp "$k.pub" "$d/ak"; cp "$k" "$d/k"; chown "$SELFTEST_USER" "$d/k"; chmod 600 "$d/k"; chmod 644 "$d/ak"; chmod 755 "$d"
  cat >"$d/cfg" <<EOC
Port $port
ListenAddress 127.0.0.1
HostKey $d/hk
PidFile $d/pid
UsePAM yes
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile $d/ak
AllowUsers $SELFTEST_USER
StrictModes no
MaxSessions 1
EOC
  "$SSHD" -f "$d/cfg" -E "$d/sshd.log" 2>"$d/sshd.err" || { echo "selftest sshd did not start: $(head -c 300 "$d/sshd.err")"; rm -rf "$d"; return 1; }
  sleep 0.5
  "$SUDO" -u "$SELFTEST_USER" "$SSH" -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=10 -i "$d/k" -p "$port" "$SELFTEST_USER@127.0.0.1" 'sudo -n true && echo selftest-ssh-sudo-ok' \
    >"$d/out" 2>&1 </dev/null
  rc=$?
  pid="$(cat "$d/pid" 2>/dev/null)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null
  echo "ssh key login + sudo -n via throwaway sshd 127.0.0.1: rc=$rc $(tr '\n' ' ' <"$d/out" | head -c 200)"
  grep -q selftest-ssh-sudo-ok "$d/out"; rc=$?
  rm -rf "$d"
  return $rc
}
selftest() { # [post]: VERIFY_INJECT only fails the self-test that runs after the change
  local f=0 o
  if o="$("$SSHD" -t 2>&1)"; then echo "selftest sshd -t: ok"; else echo "selftest sshd -t: FAIL $o"; f=1; fi
  if o="$(ssh_selftest)"; then echo "selftest $o"; else echo "selftest FAIL $o"; f=1; fi
  o="$("$SUDO" -n su -s /bin/sh -c 'echo su-ok' nobody 2>&1)"
  if [ "$o" = su-ok ]; then echo "selftest root su to a system account: ok"; else echo "selftest root su: FAIL $o"; f=1; fi
  if o="$(node_full)"; then echo "selftest node: $o"; else echo "selftest node: FAIL $o"; f=1; fi
  if [ "${1:-}" = post ] && [ "$INJECT" = selftest ]; then echo "selftest: VERIFY_INJECT=selftest -> forced FAIL (restore drill)"; f=1; fi
  return $f
}

# ---------- apply / rollback ----------
restore_from() { # BACKUPDIR -> restore every file byte-identical (bytes, mode, owner); rc 1 on any sha mismatch
  local b="$1" f s m o g bad=0
  while IFS=$'\t' read -r f s m o g; do
    cat "$b/$(sha256sum <<<"$f" | cut -c1-16)" >"$f.pft-acctpolicy.tmp" && chown "$o:$g" "$f.pft-acctpolicy.tmp" 2>/dev/null
    chmod "$m" "$f.pft-acctpolicy.tmp" && mv -f "$f.pft-acctpolicy.tmp" "$f"
    if [ "$(sha "$f")" = "$s" ]; then echo "restored ${f#"$R"} sha256 $s"; else echo "RESTORE MISMATCH ${f#"$R"}"; bad=1; fi
  done < "$b/manifest"
  return $bad
}

do_apply() {
  [ "${1:-}" = --yes ] || die "apply needs --yes (see: pft-acctpolicy plan)" 4
  [ -n "${PFT_AP_ROOT:-}" ] || [ "$(id -u)" = 0 ] || die "apply needs root" 4
  [ ! -f "$STATE_DIR/apply.json" ] || die "the last apply is still in place (rollback first): $STATE_DIR/apply.json" 4
  run_audit
  local o; o="$(node_full)" || die "node not healthy before apply ($o)" 4
  local nd; nd="$(mktemp -d)"
  build "$nd" || { rm -rf "$nd"; die "a fix could not be built (unexpected file shape); nothing written" 4; }
  [ -s "$nd/index" ] || { rm -rf "$nd"; echo "apply: nothing to fix"; return 0; }
  o="$(selftest)" || { rm -rf "$nd"; printf '%s\n' "$o"; die "self-test fails BEFORE any change; nothing written" 4; }
  local id; id="$(date -u -d "@$(now)" +%Y%m%dT%H%M%SZ)"
  local b="$STATE_DIR/backup/$id" f t
  { mkdir -p "$b" && chmod 700 "$STATE_DIR" "$STATE_DIR/backup" "$b"; } || die "cannot create $b"
  cut -f2 "$nd/index" | sort -u | while read -r f; do
    cp -p "$f" "$b/$(sha256sum <<<"$f" | cut -c1-16)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$(sha "$f")" "$(stat -c '%a' "$f")" "$(stat -c '%U' "$f")" "$(stat -c '%G' "$f")"
  done > "$b/manifest"
  echo "apply $id: $(cut -f1 "$nd/index" | tr '\n' ' ')"
  cut -f2,3 "$nd/index" | sort -u | while IFS=$'\t' read -r f t; do
    diff -u --label "${f#"$R"}" --label "${f#"$R"} (new)" "$f" "$t"
    cat "$t" >"$f.pft-acctpolicy.tmp" && chown --reference="$f" "$f.pft-acctpolicy.tmp" 2>/dev/null
    chmod --reference="$f" "$f.pft-acctpolicy.tmp" && mv -f "$f.pft-acctpolicy.tmp" "$f"
  done
  rm -rf "$nd"
  if o="$(selftest post)"; then
    printf '%s\n' "$o"
    jq -n --arg id "$id" --arg t "$(ts)" --arg b "$b" --rawfile m "$b/manifest" \
      '{id: $id, time: $t, backup: $b, files: [$m | split("\n")[] | select(length > 0) | split("\t") | {path: .[0], sha256_before: .[1]}]}' \
      > "$STATE_DIR/apply.json"
    echo "apply $id: self-test PASS; rollback with: pft-acctpolicy rollback --yes"
    return 0
  fi
  printf '%s\n' "$o"
  echo "apply $id: self-test FAILED -> restoring"
  restore_from "$b" || { echo "apply $id: RESTORE MISMATCH"; return 5; }
  echo "apply $id: restored byte-identical"
  return 1
}

do_rollback() {
  [ "${1:-}" = --yes ] || die "rollback needs --yes" 4
  [ -f "$STATE_DIR/apply.json" ] || die "no apply to roll back ($STATE_DIR/apply.json missing)" 4
  local b o; b="$(jq -r '.backup' "$STATE_DIR/apply.json")"
  [ -f "$b/manifest" ] || die "backup manifest missing: $b" 2
  echo "rollback $(jq -r '.id' "$STATE_DIR/apply.json")"
  restore_from "$b" || return 5
  rm -f "$STATE_DIR/apply.json"
  o="$(selftest)"; printf '%s\n' "$o"
  echo "rollback: restored byte-identical"
  return 0
}

case "${1:-}" in
  audit) run_audit; if [ "${2:-}" = --json ]; then print_json; else print_text; fi; rc_of; exit $? ;;
  plan) do_plan; exit $? ;;
  apply) shift; do_apply "$@"; exit $? ;;
  rollback) shift; do_rollback "$@"; exit $? ;;
  checks) printf '%s\n' "$CHECKS" | awk '{ id = $1; fx = $2; $1 = $2 = ""; sub(/^  /, ""); printf "%-20s %-9s %s\n", id, fx, $0 }'; exit 0 ;;
  selftest) selftest; exit $? ;;
  version) echo "pft-acctpolicy $VERSION"; exit 0 ;;
  *) sed -n '8,15p' "$0" >&2; exit 3 ;;
esac
