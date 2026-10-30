#!/usr/bin/env bash
# Stubbed two-host tests for pft-fleet.sh + fleet_lib.py. No root, no network, no real host is touched.
# A temp git repo holds two fake add-ons with a five-commit history; two fake hosts (sentry over a stub ssh,
# validator local) are directory trees under a temp dir (PFT_FLEET_ROOT_<label>); systemctl, docker, pft-maint,
# pft-integrity, sudo and ssh are stubs in PATH. One PASS/FAIL line per check; exit 1 if any check failed.
# Usage: tests/run-tests.sh [PFT_FLEET_SH] [FLEET_LIB_PY]
# shellcheck disable=SC2016
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(readlink -f "${1:-$HERE/../pft-fleet.sh}")"
LIBPY="$(readlink -f "${2:-$HERE/../fleet_lib.py}")"
T="$(mktemp -d)"; trap 'rm -rf "${T:?}"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }

# ---------- fake repo ----------
R="$T/repo"; mkdir -p "$R/demo" "$R/other"
g() { git -C "$R" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@" >/dev/null; }
g init -q -b main
printf '#!/usr/bin/env bash\necho demo v1\n' > "$R/demo/pft-demo.sh"
printf '[Unit]\nDescription=demo\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/pft-demo\n' > "$R/demo/pft-demo.service"
printf 'print("helper v1")\n' > "$R/demo/demo_helper.py"
printf '#!/usr/bin/env bash\necho other v1\n' > "$R/other/pft-other.sh"
g add -A; g commit -qm v1; V1="$(git -C "$R" rev-parse HEAD)"
printf '#!/usr/bin/env bash\necho demo v2\n' > "$R/demo/pft-demo.sh"; g commit -qam v2; V2="$(git -C "$R" rev-parse HEAD)"
printf '#!/usr/bin/env bash\necho demo v3 (\n' > "$R/demo/pft-demo.sh"; g commit -qam v3-broken; V3="$(git -C "$R" rev-parse HEAD)"
printf '#!/usr/bin/env bash\necho demo v4\n' > "$R/demo/pft-demo.sh"
printf 'print("helper v4")\n' > "$R/demo/demo_helper.py"; g commit -qam v4; V4="$(git -C "$R" rev-parse HEAD)"
printf '[Unit]\nDescription=demo v5\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/pft-demo\n' > "$R/demo/pft-demo.service"
g commit -qam v5; V5="$(git -C "$R" rev-parse HEAD)"
g checkout -q -b side; printf '#!/usr/bin/env bash\necho unreviewed\n' > "$R/demo/pft-demo.sh"; g commit -qam side
SIDE="$(git -C "$R" rev-parse HEAD)"; g checkout -q main

cat > "$T/manifest.tsv" <<'M'
# test manifest
demo   demo/pft-demo.sh       /usr/local/bin/pft-demo                   0755 both
demo   demo/pft-demo.service  /etc/systemd/system/pft-demo.service      0644 both
demo   demo/demo_helper.py    /usr/local/lib/pft-demo/demo_helper.py    0644 validator
other  other/pft-other.sh     /usr/local/sbin/pft-other                 0755 sentry
M
cat > "$T/hosts.conf" <<'H'
host sentry    ssh   relaystub  postfiatd-sentry  sentry
host validator local -          postfiatd         validator
H
cat > "$T/fleet.conf" <<C
REPO=$R
REF=main
HOSTS_CONF=$T/hosts.conf
TEXTFILE_DIR=$T/textfile
STATE_DIR=$T/state
C

# ---------- stubs ----------
B="$T/bin"; S="$T/s"; mkdir -p "$B" "$S"
cat > "$B/ssh" <<'X'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; -*) shift ;; *) break ;; esac; done
tgt="$1"; shift
echo "ssh $tgt" >> "$STUB_S/calls"
[ -e "$STUB_S/ssh_down" ] && { echo "ssh: connect: timeout" >&2; exit 255; }
STUB_HOST=sentry exec bash -c "$*"
X
cat > "$B/sudo" <<'X'
#!/usr/bin/env bash
[ "$1" = -n ] && shift
exec "$@"
X
cat > "$B/systemctl" <<'X'
#!/usr/bin/env bash
h="${STUB_HOST:-validator}"
echo "systemctl $h $*" >> "$STUB_S/calls"
case "$1" in
  daemon-reload) [ -e "$STUB_S/reload_breaks_node_$h" ] && echo connected > "$STUB_S/node_$h"; exit 0 ;;
  show) [ -e "$STUB_S/loadfail_$h" ] && { echo not-found; exit 0; }; echo loaded ;;
  is-enabled) echo enabled ;;
  is-active) if [ -e "$STUB_S/failed_${h}_$2" ]; then echo failed; exit 3; fi; echo active ;;
  list-units) exit 0 ;;
esac
X
cat > "$B/docker" <<'X'
#!/usr/bin/env bash
h="${STUB_HOST:-validator}"
st=full; [ -e "$STUB_S/node_$h" ] && st="$(cat "$STUB_S/node_$h")"
printf '{"result":{"info":{"server_state":"%s"}}}\n' "$st"
X
cat > "$B/pft-maint" <<'X'
#!/usr/bin/env bash
h="${STUB_HOST:-validator}"
[ "$1" = active ] && { [ -e "$STUB_S/maint_$h" ] && exit 0; exit 1; }
X
cat > "$B/pft-integrity" <<'X'
#!/usr/bin/env bash
h="${STUB_HOST:-validator}"
case "$1" in
  verify) if [ -e "$STUB_S/integ_$h" ]; then cat "$STUB_S/integ_$h"
          else echo '{"status":"PASS","exit":0,"findings":[]}'; fi ;;
  accept) shift; echo "$h $*" >> "$STUB_S/accepts" ;;
esac
X
cat > "$B/mv" <<'X'
#!/usr/bin/env bash
# mv_corrupt: the new file lands with extra bytes (bad write); mv_norestore: a rollback restore cannot be moved
src="${*: -2:1}"; dst="${*: -1}"
case "$src" in
  *.pft-fleet.rb) [ -e "$STUB_S/mv_norestore" ] && { echo "mv: cannot move: Read-only file system" >&2; exit 1; } ;;
esac
/bin/mv "$@" || exit
case "$src" in *.pft-fleet.new) [ -e "$STUB_S/mv_corrupt" ] && echo "# corrupted" >> "$dst" ;; esac
exit 0
X
chmod +x "$B"/*
export PATH="$B:$PATH" STUB_S="$S" PFT_FLEET_CONF="$T/fleet.conf" PFT_FLEET_MANIFEST="$T/manifest.tsv"
export PFT_FLEET_LIB="$LIBPY" PFT_FLEET_NOROOT=1 PFT_FLEET_ROOT_sentry="$T/h/sentry" PFT_FLEET_ROOT_validator="$T/h/validator"
unset SUDO_USER

blob() { git -C "$R" show "$1:$2"; }
sha() { sha256sum < "$1" | cut -c1-64; }
put() { # HOST PATH COMMIT REPO_PATH
  mkdir -p "$(dirname "$T/h/$1$2")"; blob "$3" "$4" > "$T/h/$1$2"
}
reset_hosts() { # every expected file at $1 (default V5)
  local c="${1:-$V5}"
  rm -rf "$T/h" "$T/state" "$T/textfile"; rm -f "$S"/*
  for h in sentry validator; do
    put $h /usr/local/bin/pft-demo "$c" demo/pft-demo.sh
    put $h /etc/systemd/system/pft-demo.service "$c" demo/pft-demo.service
  done
  put validator /usr/local/lib/pft-demo/demo_helper.py "$c" demo/demo_helper.py
  put sentry /usr/local/sbin/pft-other "$c" other/pft-other.sh
  : > "$S/calls"
}
run() { OUT="$("$@" 2>&1)"; RC=$?; }
fl() { run bash "$TOOL" "$@"; }
has() { grep -qE -- "$1" <<<"$OUT"; }
line() { grep -E -- "$1" <<<"$OUT" | head -1; }

# ---------- skew classification ----------
reset_hosts
fl skew
check "all current: exit 0" [ "$RC" = 0 ]
check "all current: SUMMARY CURRENT=3 none else" has 'SUMMARY CURRENT=3 BEHIND=0 MODIFIED=0 MISSING=0 UNEXPECTED=0 DIVERGED=0'

reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
fl skew
check "sentry at v2: exit 1" [ "$RC" = 1 ]
check "sentry at v2: sentry demo BEHIND" has '^sentry +demo +BEHIND'
check "sentry at v2: BEHIND names v2 and 2 newer commits" has "BEHIND @${V2:0:12} \(-2\)"
check "sentry at v2: validator demo CURRENT" has '^validator +demo +CURRENT'
check "sentry at v2: DIVERGED demo pft-demo path" has '^\* +demo +DIVERGED +/usr/local/bin/pft-demo$'
fl skew --json
check "json: sentry/demo BEHIND, exit_code 1" python3 -c '
import json,sys; d=json.loads(sys.argv[1]); a={(x["host"],x["addon"]):x["state"] for x in d["addons"]}
sys.exit(0 if a[("sentry","demo")]=="BEHIND" and d["exit_code"]==1 and d["diverged"][0]["addon"]=="demo" else 1)' "$OUT"

reset_hosts; put sentry /usr/local/bin/pft-demo "$V1" demo/pft-demo.sh; put validator /usr/local/bin/pft-demo "$V1" demo/pft-demo.sh
fl skew
check "both at v1 (same bytes): BEHIND both, exit 1" [ "$RC" = 1 ]
check "both at v1: no DIVERGED" has 'DIVERGED=0'
check "both at v1: newest matching commit is v1, 3 newer commits touch the file (-3)" has "BEHIND @${V1:0:12} \(-3\)"

reset_hosts; put sentry /usr/local/bin/pft-demo "$V1" demo/pft-demo.sh; put validator /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
fl skew
check "v1 vs v2: DIVERGED although both BEHIND" has '^\* +demo +DIVERGED'

reset_hosts; echo '# hand edit' >> "$T/h/sentry/usr/local/bin/pft-demo"
fl skew
check "hand edit: exit 2" [ "$RC" = 2 ]
check "hand edit: sentry demo MODIFIED" has '^sentry +demo +MODIFIED'

reset_hosts; rm "$T/h/validator/etc/systemd/system/pft-demo.service"
fl skew
check "missing unit: exit 2" [ "$RC" = 2 ]
check "missing unit: validator demo MISSING" has '^validator +demo +MISSING +/etc/systemd/system/pft-demo.service MISSING'

reset_hosts; put validator /usr/local/sbin/pft-other "$V5" other/pft-other.sh
fl skew
check "sentry-only add-on on validator: exit 1" [ "$RC" = 1 ]
check "sentry-only add-on on validator: UNEXPECTED" has '^validator +other +UNEXPECTED'

reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh; rm "$T/h/sentry/etc/systemd/system/pft-demo.service"
fl skew
check "BEHIND + MISSING on one host: worst (MISSING) wins" has '^sentry +demo +MISSING'

reset_hosts; touch "$S/ssh_down"
fl skew --metrics
check "sentry unreachable: exit 2" [ "$RC" = 2 ]
check "sentry unreachable: host line error" has '^host sentry +role sentry +error'
check "sentry unreachable: pft_fleet_up 0" grep -qx 'pft_fleet_up 0' "$T/textfile/pft_fleet.prom"
check "sentry unreachable: host_up sentry 0" grep -qx 'pft_fleet_host_up{host="sentry"} 0' "$T/textfile/pft_fleet.prom"

# ---------- metrics + drift clock ----------
reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
PFT_FLEET_NOW=1000 fl skew --metrics
P="$T/textfile/pft_fleet.prom"
check "metrics: state series BEHIND" grep -qx 'pft_fleet_addon_state{host="sentry",addon="demo",state="BEHIND"} 1' "$P"
check "metrics: exit code 1" grep -qx 'pft_fleet_exit_code 1' "$P"
check "metrics: diverged 1" grep -qx 'pft_fleet_addon_diverged{addon="demo"} 1' "$P"
check "metrics: drift since 1000" grep -qx 'pft_fleet_drift_since_timestamp_seconds{host="sentry",addon="demo"} 1000' "$P"
PFT_FLEET_NOW=5000 fl skew --metrics
check "metrics: drift clock kept on the next run (1000, not 5000)" grep -qx 'pft_fleet_drift_since_timestamp_seconds{host="sentry",addon="demo"} 1000' "$P"
check "metrics: last run 5000" grep -qx 'pft_fleet_last_run_timestamp_seconds 5000' "$P"
touch "$S/ssh_down"; PFT_FLEET_NOW=6000 fl skew --metrics; rm "$S/ssh_down"
check "metrics: drift clock survives a run where the host was unreadable" grep -qx 'pft_fleet_drift_since_timestamp_seconds{host="sentry",addon="demo"} 1000' "$P"
put sentry /usr/local/bin/pft-demo "$V5" demo/pft-demo.sh
PFT_FLEET_NOW=9000 fl skew --metrics
check "metrics: back to CURRENT clears the drift clock" bash -c "! grep -q 'drift_since_timestamp_seconds{host=\"sentry\"' '$P'"
check "metrics: exit code 0 after fix" grep -qx 'pft_fleet_exit_code 0' "$P"

# ---------- inventory ----------
reset_hosts
fl inventory
check "inventory: exit 0" [ "$RC" = 0 ]
check "inventory: sha256 of sentry pft-demo" has "^sentry +demo +/usr/local/bin/pft-demo +$(sha "$T/h/sentry/usr/local/bin/pft-demo" | cut -c1-12) "
check "inventory: unit row" has '^validator +pft-demo.service +enabled +active'

# ---------- sync: dry run and refusals ----------
reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
before="$(sha "$T/h/sentry/usr/local/bin/pft-demo")"
fl sync --addon demo --to "$V5"
check "dry run: exit 0" [ "$RC" = 0 ]
check "dry run: plan writes sentry pft-demo" has '^PLAN sentry sentry /usr/local/bin/pft-demo 0755 BEHIND .* write$'
check "dry run: file untouched" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$before" ]
fl sync --addon demo --to "$SIDE" --apply
check "unreviewed commit (not in main): exit 3" [ "$RC" = 3 ]
fl sync --addon nosuch --to "$V5"
check "unknown add-on: exit 3" [ "$RC" = 3 ]
fl sync --addon demo --to "$V5" --apply
check "no maintenance window: exit 4" [ "$RC" = 4 ]
check "no maintenance window: file untouched" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$before" ]
touch "$S/maint_sentry" "$S/maint_validator"; echo syncing > "$S/node_sentry"
fl sync --addon demo --to "$V5" --apply
check "node not full: exit 4" [ "$RC" = 4 ]
rm "$S/node_sentry"
echo '{"status":"FAIL","exit":2,"findings":[{"status":"FAIL","item":"bin:pft-unrelated","change":"changed","detail":"sha256"}]}' > "$S/integ_sentry"
fl sync --addon demo --to "$V5" --apply
check "unrelated integrity finding: exit 4" [ "$RC" = 4 ]
check "unrelated integrity finding: named" has 'unrelated findings: bin:pft-unrelated'
check "unrelated integrity finding: file untouched" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$before" ]

# ---------- sync: success ----------
echo '{"status":"FAIL","exit":2,"findings":[{"status":"FAIL","item":"bin:pft-demo","change":"changed","detail":"sha256"}]}' > "$S/integ_sentry"
fl sync --addon demo --to "$V5" --apply --reason "test"
check "sync BEHIND -> CURRENT: exit 0" [ "$RC" = 0 ]
check "sync: integrity finding on the rewritten file is allowed" has '^PRE sentry pft-integrity FAIL \(1 findings'
check "sync: sentry file now v5 bytes" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$(blob "$V5" demo/pft-demo.sh | sha256sum | cut -c1-64)" ]
check "sync: mode 0755" [ "$(stat -c %a "$T/h/sentry/usr/local/bin/pft-demo")" = 755 ]
check "sync: backup kept" bash -c "ls '$T'/h/sentry'$T'/state/backup/*-demo-sentry/_usr_local_bin_pft-demo >/dev/null"
check "sync: gate lines PASS" has '^GATE sentry sha256 /usr/local/bin/pft-demo = target .* PASS'
check "sync: integrity accept with reason on sentry" grep -q "^sentry --reason pft-fleet sync demo@${V5:0:12} on sentry: pft-demo (test)" "$S/accepts"
check "sync: validator had nothing to do" has 'validator: every demo file already at'
check "sync: no accept on validator" bash -c "! grep -q '^validator' '$S/accepts'"
rm -f "$S/integ_sentry"
fl skew
check "after sync: all CURRENT" [ "$RC" = 0 ]

reset_hosts "$V4"; touch "$S/maint_sentry" "$S/maint_validator"
fl sync --addon demo --to "$V5" --apply
check "both hosts behind: exit 0" [ "$RC" = 0 ]
check "both hosts: sentry written before validator" bash -c "grep -n '^WRITE' <<<'$OUT' | head -1 | grep -q 'WRITE sentry'"
check "both hosts: daemon-reload on each" [ "$(grep -c '^RELOAD' <<<"$OUT")" = 2 ]
check "both hosts: accept on both" [ "$(wc -l < "$S/accepts")" = 2 ]

# ---------- sync: rollback ----------
reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh; put validator /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
touch -d '2026-01-02 03:04:05' "$T/h/sentry/usr/local/bin/pft-demo"; chmod 750 "$T/h/sentry/usr/local/bin/pft-demo"
orig="$(sha "$T/h/sentry/usr/local/bin/pft-demo")"; orig_v="$(sha "$T/h/validator/usr/local/bin/pft-demo")"
touch "$S/maint_sentry" "$S/maint_validator"
PFT_FLEET_INJECT_GATE_FAIL=sentry fl sync --addon demo --to "$V5" --apply
check "injected gate failure: exit 5" [ "$RC" = 5 ]
check "injected gate failure: GATE line" has '^GATE sentry injected failure .* FAIL'
check "rollback: sentry sha256 restored" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$orig" ]
check "rollback: ROLLBACK PASS line" has "^ROLLBACK sentry /usr/local/bin/pft-demo sha256 ${orig:0:12} = original PASS"
check "rollback: mtime restored" [ "$(stat -c %Y "$T/h/sentry/usr/local/bin/pft-demo")" = "$(date -d '2026-01-02 03:04:05' +%s)" ]
check "rollback: mode restored" [ "$(stat -c %a "$T/h/sentry/usr/local/bin/pft-demo")" = 750 ]
check "rollback: validator untouched (stops before next host)" [ "$(sha "$T/h/validator/usr/local/bin/pft-demo")" = "$orig_v" ]
check "rollback: no WRITE on validator" bash -c "! grep -q '^WRITE validator' <<<'$OUT'"
check "rollback: no integrity accept" [ ! -e "$S/accepts" ]

reset_hosts; put sentry /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh; put validator /usr/local/bin/pft-demo "$V2" demo/pft-demo.sh
touch "$S/maint_sentry" "$S/maint_validator"
PFT_FLEET_INJECT_GATE_FAIL=validator fl sync --addon demo --to "$V5" --apply
check "validator gate fails after sentry synced: exit 5" [ "$RC" = 5 ]
check "validator rolled back to v2" [ "$(sha "$T/h/validator/usr/local/bin/pft-demo")" = "$(blob "$V2" demo/pft-demo.sh | sha256sum | cut -c1-64)" ]
check "sentry keeps its passed sync (v5)" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$(blob "$V5" demo/pft-demo.sh | sha256sum | cut -c1-64)" ]

reset_hosts "$V2"; touch "$S/maint_sentry"
fl sync --addon demo --to "$V3" --hosts sentry --apply
check "broken script (bash -n) at v3: exit 5" [ "$RC" = 5 ]
check "broken script: syntax GATE FAIL" has '^GATE sentry syntax /usr/local/bin/pft-demo bash -n FAIL'
check "broken script: rolled back to v2" [ "$(sha "$T/h/sentry/usr/local/bin/pft-demo")" = "$(blob "$V2" demo/pft-demo.sh | sha256sum | cut -c1-64)" ]

reset_hosts "$V4"; touch "$S/maint_sentry" "$S/loadfail_sentry"
fl sync --addon demo --to "$V5" --hosts sentry --apply
check "unit not loaded after write: exit 5" [ "$RC" = 5 ]
check "unit not loaded: GATE FAIL" has '^GATE sentry unit pft-demo.service LoadState=not-found FAIL'
check "unit not loaded: unit restored" [ "$(sha "$T/h/sentry/etc/systemd/system/pft-demo.service")" = "$(blob "$V4" demo/pft-demo.service | sha256sum | cut -c1-64)" ]

reset_hosts "$V4"; touch "$S/maint_validator" "$S/failed_validator_pft-demo.service"
fl sync --addon demo --to "$V5" --hosts validator --apply
check "failed unit after write: exit 5" [ "$RC" = 5 ]
check "failed unit: GATE FAIL names it" has '^GATE validator addon units failed=pft-demo.service FAIL'

reset_hosts; rm "$T/h/validator/usr/local/lib/pft-demo/demo_helper.py"; touch "$S/maint_validator"
PFT_FLEET_INJECT_GATE_FAIL=validator fl sync --addon demo --to "$V5" --hosts validator --apply
check "file absent before sync: rollback removes it (exit 5)" [ "$RC" = 5 ]
check "file absent before sync: gone after rollback" [ ! -e "$T/h/validator/usr/local/lib/pft-demo/demo_helper.py" ]
check "file absent before sync: ROLLBACK PASS (-)" has '^ROLLBACK validator /usr/local/lib/pft-demo/demo_helper.py sha256 .* = original PASS'

reset_hosts "$V4"; touch "$S/maint_sentry" "$S/mv_corrupt"
fl sync --addon demo --to "$V5" --hosts sentry --apply
check "bytes on disk differ from the commit after write: exit 5" [ "$RC" = 5 ]
check "bad write: sha256 GATE FAIL" has '^GATE sentry sha256 /etc/systemd/system/pft-demo.service = .* want .* FAIL'
check "bad write: unit restored to v4" [ "$(sha "$T/h/sentry/etc/systemd/system/pft-demo.service")" = "$(blob "$V4" demo/pft-demo.service | sha256sum | cut -c1-64)" ]

reset_hosts "$V4"; touch "$S/maint_sentry" "$S/reload_breaks_node_sentry"
fl sync --addon demo --to "$V5" --hosts sentry --apply
check "node leaves full after the write: exit 5" [ "$RC" = 5 ]
check "node leaves full: GATE node FAIL" has '^GATE sentry node server_state=connected FAIL'

reset_hosts "$V4"; touch "$S/maint_sentry" "$S/mv_norestore"
PFT_FLEET_INJECT_GATE_FAIL=sentry fl sync --addon demo --to "$V5" --hosts sentry --apply
check "restore impossible: exit 6 (rollback mismatch)" [ "$RC" = 6 ]
check "restore impossible: ROLLBACK FAIL line" has '^ROLLBACK sentry /etc/systemd/system/pft-demo.service sha256 .* want .* FAIL'
check "restore impossible: names the backup dir" has 'ROLLBACK MISMATCH on sentry - fix by hand from .*/backup/'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
