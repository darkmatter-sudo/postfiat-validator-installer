#!/usr/bin/env bash
# Offline tests for pft-migrate.sh: two fake hosts (source "src", target "tgt") with stubbed docker / RPC / TCP probe
# and REAL age keys. Covers arguments, plan, export (encryption, sidecar, manifest, no plaintext left), fencing
# (guard, refusals), import negatives (sidecar tamper, truncation, wrong key, path escape, symlink, manifest mismatch,
# extra file, running copy), start-target refusals, verify (identity match/mismatch, timeout, downtime), rollback
# (refusals, byte-identical .env, restart policy) and secret exposure. No root, no docker, no network.
# Usage: tests/run-tests.sh [path/to/pft-migrate.sh]
# "A && ok || ko" is intended: ok/ko always return 0. Stub bodies are literal scripts, single-quoted on purpose.
# shellcheck disable=SC2016,SC2015,SC2001
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(cd "$(dirname "${1:-$HERE/../pft-migrate.sh}")" && pwd)/$(basename "${1:-pft-migrate.sh}")"
# /tmp is noexec on a host hardened by ../mounts, and the stubs must execute: default to the user cache dir
TBASE="${TEST_TMPDIR:-${XDG_CACHE_HOME:-$HOME/.cache}}"; mkdir -p "$TBASE"
T="$(mktemp -d "$TBASE/pft-migrate-tests.XXXXXX")"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
ko() { FAIL=$((FAIL + 1)); echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     | /' <<<"$2" | head -25; }
SEED=snoPBrXtMeMyMHUVTgbuqAfg1SUTb   # fixture seed (format only), must never be printed
PUB_A=n9MASi45ub7Qe4ZE36UT5G6cU4ud8Fhhe4deS4F3cw9KTAb8dLcu   # identity that SEED gives
PUB_B=n9kC7edhDQ7cn5d4gEYkbUrMWeWQLGsCmrG6dLaYyNoVKf58ZTBq   # any other identity
VOL=/var/lib/docker/volumes/postfiatd_postfiatd-config/_data
export PFT_MIGRATE_TEST=1 POLL_SEC=1 STOP_TIMEOUT=1 TSTATE="$T"

mkdir -p "$T/bin" "$T/hosts" "$T/shm"
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
S="$H/s"; echo "docker $*" >> "$S/calls"
case "$1" in
  inspect)
    shift; fmt=""; [ "$1" = -f ] && { fmt="$2"; shift 2; }; n="$1"; d="$S/c/$n"; [ -d "$d" ] || exit 1
    case "$fmt" in
      "") echo '[{}]' ;;
      *'"com.docker.compose.project.working_dir"'*) echo /opt/postfiatd ;;
      *'"com.docker.compose.project"'*) echo postfiatd ;;
      *'"com.docker.compose.service"'*) echo postfiatd ;;
      *'.Source'*) echo /var/lib/docker/volumes/postfiatd_postfiatd-config/_data ;;
      *RestartPolicy*) cat "$d/restart" ;;
      *'.Name}}'*) echo postfiatd_postfiatd-config ;;
      *Config.Image*) echo agtipft/postfiatd:testnet-light-latest ;;
      *State.Status*) cat "$d/status" ;;
      *State.Running*) [ "$(cat "$d/status")" = running ] && echo true || echo false ;;
      *) echo "stub: unknown format $fmt" >&2; exit 9 ;;
    esac ;;
  update) n="${!#}"; [ -d "$S/c/$n" ] || exit 1; echo "${2#--restart=}" > "$S/c/$n/restart" ;;
  stop) n="${!#}"; [ -d "$S/c/$n" ] || exit 1; echo exited > "$S/c/$n/status" ;;
  compose)
    [ "$2 $3" = "up -d" ] || exit 9
    [ "$PWD" = "$R/opt/postfiatd" ] || { echo "stub: compose up in $PWD" >&2; exit 9; }
    d="$S/c/postfiatd"; cf="$(sed -n 's/^COMPOSE_FILE=//p' .env 2>/dev/null | tail -1)"
    for f in $(tr ':' ' ' <<<"${cf:-docker-compose.yml}"); do [ -f "$f" ] || { echo "stub compose: $f missing" >&2; exit 14; }; done
    if [[ ":$cf:" == *":docker-compose.migrate-fence.yml:"* ]]; then
      mkdir -p "$d"; echo exited > "$d/status"; echo no > "$d/restart"; touch "$d/guarded"
      echo 'Error response from daemon: exec: "/pft-migrate-FENCED": no such file or directory' >&2; exit 1
    fi
    if [ ! -d "$d" ] || [ -f "$d/guarded" ]; then mkdir -p "$d"; rm -f "$d/guarded"; echo unless-stopped > "$d/restart"; fi
    echo running > "$d/status" ;;
  volume)
    case "$2" in
      inspect) n="${!#}"; [ -d "$R/var/lib/docker/volumes/$n/_data" ] || exit 1; [ "$3" = -f ] && echo "/var/lib/docker/volumes/$n/_data" || echo '[{}]' ;;
      create) n="${!#}"; mkdir -p "$R/var/lib/docker/volumes/$n/_data"; echo "$n" ;;
      *) exit 9 ;;
    esac ;;
  *) echo "stub: docker $*" >&2; exit 9 ;;
esac
STUB
cat > "$T/bin/rpc" <<'STUB'
#!/usr/bin/env bash
[ "$(cat "$H/s/c/postfiatd/status" 2>/dev/null)" = running ] || exit 0
cfg="$R/var/lib/docker/volumes/postfiatd_postfiatd-config/_data/postfiatd.cfg"
seed="$(awk '/^\[/{s=($0=="[node_seed]");next} s&&NF{print;exit}' "$cfg")"
[ "$seed" = "$FIX_SEED" ] && pub="$FIX_PUB_A" || pub="$FIX_PUB_B"
printf '{"result":{"info":{"server_state":"%s","pubkey_node":"%s"}}}\n' "$(cat "$H/s/state" 2>/dev/null || echo full)" "$pub"
STUB
cat > "$T/bin/probe" <<'STUB'
#!/usr/bin/env bash
echo "probe $*" >> "$H/s/calls"
if [ "$1" = 127.0.0.1 ]; then h="$H"; else h="$TSTATE/hosts/$1"; fi
[ "$(cat "$h/s/c/postfiatd/status" 2>/dev/null)" = running ]
STUB
cat > "$T/bin/pft-maint" <<'STUB'
#!/usr/bin/env bash
echo "maint $*" >> "$H/s/calls"
STUB
chmod +x "$T/bin"/*
export FIX_SEED="$SEED" FIX_PUB_A="$PUB_A" FIX_PUB_B="$PUB_B"

mk_host() { # NAME [bare]: a fake host; "bare" = fresh target with nothing installed
  local h="$T/hosts/$1" r="$T/hosts/$1/root"
  mkdir -p "$h/s/c" "$r/var/lib" "$h/state" "$h/out"; : > "$h/s/calls"
  [ "${2:-}" = bare ] && return
  mkdir -p "$r$VOL" "$r/opt/postfiatd" "$r/etc/pft-seccomp" "$r/etc/apparmor.d" "$r/var/lib/pft-cluster" "$h/s/c/postfiatd"
  printf '[server]\nport_peer\n\n[node_seed]\n%s\n\n[ips_fixed]\n192.0.2.10 2559\n' "$SEED" > "$r$VOL/postfiatd.cfg"
  printf '[validator_list_sites]\nhttps://postfiat.org\n' > "$r$VOL/validators.txt"
  chmod 640 "$r$VOL/postfiatd.cfg"
  printf 'services:\n  postfiatd:\n    container_name: postfiatd\n    restart: unless-stopped\n' > "$r/opt/postfiatd/docker-compose.yml"
  printf 'services:\n  postfiatd:\n    security_opt:\n      - "no-new-privileges:true"\n' > "$r/opt/postfiatd/docker-compose.override.yml"
  printf 'services:\n  postfiatd:\n    security_opt:\n      - "seccomp=/etc/pft-seccomp/pft-postfiatd.json"\n' > "$r/opt/postfiatd/docker-compose.seccomp.yml"
  printf 'services:\n  postfiatd:\n    security_opt:\n      - "apparmor=pft-postfiatd"\n' > "$r/opt/postfiatd/docker-compose.apparmor.yml"
  printf 'NETWORK=testnet\nCOMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:docker-compose.seccomp.yml:docker-compose.apparmor.yml\n' > "$r/opt/postfiatd/.env"
  echo '{"defaultAction":"SCMP_ACT_ERRNO"}' > "$r/etc/pft-seccomp/pft-postfiatd.json"
  echo 'profile pft-postfiatd flags=(attach_disconnected) {}' > "$r/etc/apparmor.d/pft-postfiatd"
  echo "$SEED" > "$r/var/lib/pft-cluster/node_seed"; echo "$PUB_A" > "$r/var/lib/pft-cluster/node_pub"
  chmod 700 "$r/var/lib/pft-cluster"; chmod 600 "$r/var/lib/pft-cluster/node_seed"
  echo running > "$h/s/c/postfiatd/status"; echo unless-stopped > "$h/s/c/postfiatd/restart"
}
on() { # HOST: run the tool as that host
  export H="$T/hosts/$1" R="$T/hosts/$1/root" PFT_MIGRATE_ROOT="$T/hosts/$1/root" STATE_DIR="$T/hosts/$1/state"
  export STAGE_BASE="$T/shm" DOCKER="$T/bin/docker" PFT_MIGRATE_RPC="$T/bin/rpc" PFT_MIGRATE_PROBE="$T/bin/probe" MAINT="$T/bin/pft-maint"
}
run() { OUT="$(timeout 60 bash "$TOOL" "$@" 2>&1)"; RC=$?; ALL="$ALL$OUT"$'\n'; }
st() { cat "$T/hosts/$1/s/c/postfiatd/status" 2>/dev/null || echo none; }
rp() { cat "$T/hosts/$1/s/c/postfiatd/restart" 2>/dev/null || echo none; }
rc_is() { [ "$RC" = "$2" ] && ok "$1 (exit $2)" || ko "$1: exit $RC, want $2" "$OUT"; }
ALL=""

age-keygen -o "$T/tgt.key" 2>/dev/null; TGT_PUB="$(age-keygen -y "$T/tgt.key")"
age-keygen -o "$T/other.key" 2>/dev/null
mk_host src; on src
"$DOCKER" inspect postfiatd >/dev/null && grep -q '^docker inspect postfiatd' "$H/s/calls" && ok "self-check: the docker stub answered" || ko "self-check: stub not used"

# --- arguments -------------------------------------------------------------------------------------------------
run; rc_is "no command" 3
run bogus; rc_is "unknown command" 3
run export --out "$H/out"; rc_is "export without --to" 3
run export --to "$T/tgt.key" --out "$H/out"; rc_is "export --to an IDENTITY file refused" 3
grep -q 'never an identity' <<<"$OUT" && ok "identity refusal says why" || ko "identity refusal text" "$OUT"
{ echo "$TGT_PUB"; grep '^AGE-SECRET-KEY' "$T/tgt.key"; } > "$T/mixed.txt"   # a recipient line next to a secret key
run export --to "$T/mixed.txt" --out "$H/out"; rc_is "export --to a file holding a recipient AND a secret key refused" 3
run export --to age1notakey --out "$H/out"; rc_is "export --to malformed recipient" 3
run fence-source --bundle-id nope; rc_is "fence bad bundle id" 3
run verify --expect-pubkey xyz; rc_is "verify bad pubkey" 3
run start-target --fence-proof /dev/null --source 'h:99999x'; rc_is "start-target bad address" 3
run import --bundle /nonexistent --identity "$T/tgt.key"; rc_is "import missing bundle" 3
run plan --role bogus; rc_is "plan bad role" 3

# --- plan ------------------------------------------------------------------------------------------------------
run plan
rc_is "plan ok" 0
for f in cfgvol/postfiatd.cfg cfgvol/validators.txt compose/docker-compose.yml compose/docker-compose.override.yml \
  compose/docker-compose.seccomp.yml compose/docker-compose.apparmor.yml compose/.env cluster/node_seed \
  host/etc/pft-seccomp/pft-postfiatd.json host/etc/apparmor.d/pft-postfiatd; do
  grep -q " $f " <<<"$OUT" || { ko "plan lists $f" "$OUT"; continue; }; ok "plan lists $f"
done
grep -q "pubkey_node $PUB_A" <<<"$OUT" && grep -q 'pinned by pft-cluster' <<<"$OUT" && ok "plan: live identity + pinned" || ko "plan identity" "$OUT"
run plan --json
[ "$RC" = 0 ] && [ "$(jq -r '.files|length' <<<"$OUT")" = 11 ] && [ "$(jq -r .ok <<<"$OUT")" = true ] && ok "plan --json: 11 files, ok" || ko "plan json" "$OUT"
mv "$R/opt/postfiatd/docker-compose.seccomp.yml" "$T/sc.yml"
run plan; rc_is "plan: COMPOSE_FILE member missing" 1
grep -q 'docker-compose.seccomp.yml.*missing' <<<"$OUT" && ok "plan names the missing member" || ko "plan missing member text" "$OUT"
mv "$T/sc.yml" "$R/opt/postfiatd/docker-compose.seccomp.yml"
mv "$R/etc/pft-seccomp/pft-postfiatd.json" "$T/sc.json"
run plan; rc_is "plan: overlay host file missing" 1
mv "$T/sc.json" "$R/etc/pft-seccomp/pft-postfiatd.json"
[ -z "$(ls -A "$T/shm")" ] && ok "plan: stage removed" || ko "plan left stage" "$(ls -A "$T/shm")"

# --- export ----------------------------------------------------------------------------------------------------
cp -p "$R/opt/postfiatd/.env" "$T/env.orig"
run export --to "$TGT_PUB" --out "$H/out"
rc_is "export ok" 0
ID="$(tail -1 <<<"$OUT")"; B="$H/out/pft-migrate-$ID.age"
[[ "$ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] && ok "export prints bundle id" || ko "bundle id '$ID'" "$OUT"
[ -f "$B" ] && [ "$(stat -c %a "$B")" = 600 ] && head -c 21 "$B" | grep -q 'age-encryption.org/v1' && ok "bundle is age, 0600" || ko "bundle file" "$(ls -l "$H/out")"
(cd "$H/out" && sha256sum -c --quiet "$(basename "$B").sha256") && ok "sidecar sha256 matches" || ko "sidecar"
! grep -qaF "$SEED" "$B" && ! grep -qaF 'node_seed' "$B" && ok "bundle holds no plaintext" || ko "PLAINTEXT IN BUNDLE"
[ -z "$(ls -A "$T/shm")" ] && ok "export: RAM stage removed" || ko "export left stage" "$(ls -A "$T/shm")"
[ -f "$STATE_DIR/exports/$ID.meta" ] && ! grep -qF "$SEED" "$STATE_DIR/exports/$ID.meta" && grep -qx "pubkey=$PUB_A" "$STATE_DIR/exports/$ID.meta" \
  && ok "export record: pubkey, no seed" || ko "export record" "$(cat "$STATE_DIR/exports/$ID.meta" 2>&1)"
age -d -i "$T/tgt.key" "$B" | tar -tf - | LC_ALL=C sort > "$T/list"
grep -qx './MANIFEST.sha256' "$T/list" && grep -qx './META' "$T/list" && [ "$(grep -vc '/$' "$T/list")" = 13 ] && ok "bundle: META + MANIFEST + 11 files" || ko "bundle list" "$(cat "$T/list")"
mkdir "$T/peek" && age -d -i "$T/tgt.key" "$B" | tar -xf - -C "$T/peek" && (cd "$T/peek" && sha256sum --quiet -c MANIFEST.sha256) \
  && [ "$(wc -l < "$T/peek/MANIFEST.sha256")" = 12 ] && ok "inner manifest: 12 files verify" || ko "inner manifest"
grep -qx "source_pubkey=$PUB_A" "$T/peek/META" && grep -qx 'restart_policy=unless-stopped' "$T/peek/META" && ok "META: pubkey + restart policy" || ko "META" "$(cat "$T/peek/META")"
cp -a "$T/peek" "$T/good"; rm -rf "$T/peek"
[ "$(st src)" = running ] && ok "export does not stop the node" || ko "export stopped node"

# --- fence-source ----------------------------------------------------------------------------------------------
run fence-source --bundle-id 20990101T000000Z-deadbeef; rc_is "fence: unknown bundle" 4
run start-target --fence-proof /dev/null --source tgt; rc_is "start-target on the source (nothing imported)" 4
export PFT_MIGRATE_NOW=1900000000
run fence-source --bundle-id "$ID" --proof-out "$T/src.proof"
rc_is "fence ok" 0
[ "$(st src)" = exited ] && [ "$(rp src)" = no ] && ok "fence: container exited, restart=no" || ko "fence state $(st src)/$(rp src)"
for k in kind=pft-migrate-fence "bundle_id=$ID" "pubkey=$PUB_A" container_state=exited restart_policy=no compose_guard=on \
  peer_port_local=closed rpc=down fenced_at=1900000000; do
  grep -qx "$k" "$T/src.proof" || { ko "proof has $k" "$(cat "$T/src.proof")"; continue; }; ok "proof: $k"
done
grep -q 'maint lock add pft-migrate --until 1900007200' "$H/s/calls" && ok "fence: pft-maint lock until +LOCK_TTL" || ko "maint lock" "$(cat "$H/s/calls")"
grep -q 'docker-compose.migrate-fence.yml$' "$R/opt/postfiatd/.env" && ok "fence: guard in COMPOSE_FILE" || ko "guard env" "$(cat "$R/opt/postfiatd/.env")"
if (cd "$R/opt/postfiatd" && "$DOCKER" compose up -d >/dev/null 2>&1); then ko "compose guard: up succeeded"
elif [ "$(st src)" = exited ]; then ok "fenced source: plain 'docker compose up -d' does not run the node"; else ko "compose guard: $(st src)"; fi
run fence-source --bundle-id "$ID"; rc_is "fence again (same bundle) idempotent" 0
grep -qx 'fenced_at=1900000000' "$STATE_DIR/FENCED" && ok "re-fence keeps the first fenced_at" || ko "re-fence fenced_at"
mkdir -p "$STATE_DIR/exports"; cp "$STATE_DIR/exports/$ID.meta" "$STATE_DIR/exports/20990101T000000Z-0badc0de.meta"
run fence-source --bundle-id 20990101T000000Z-0badc0de; rc_is "fence for another bundle while fenced" 4
rm -f "$STATE_DIR/exports/20990101T000000Z-0badc0de.meta"

# --- import negatives (target) ---------------------------------------------------------------------------------
mk_host tgt bare; on tgt
cp "$B" "$B.sha256" "$H/out/"; TB="$H/out/$(basename "$B")"
mkbundle() { # DIR NAME: tar DIR, age to the target, sidecar -> prints path
  tar -C "$1" -cf - . | age -r "$TGT_PUB" -o "$H/out/$2.age"; (cd "$H/out" && sha256sum "$2.age" > "$2.age.sha256"); echo "$H/out/$2.age"
}
run import --bundle "$TB" --identity "$T/other.key"; rc_is "import: wrong identity" 2
grep -q 'age decryption failed' <<<"$OUT" && ok "wrong identity: says decryption failed" || ko "wrong key text" "$OUT"
cp "$TB" "$H/out/flip.age"; cp "$TB.sha256" "$H/out/flip.age.sha256"; sed -i "s/$(basename "$TB")/flip.age/" "$H/out/flip.age.sha256"
printf '\xff' | dd of="$H/out/flip.age" bs=1 seek=300 conv=notrunc 2>/dev/null
run import --bundle "$H/out/flip.age" --identity "$T/tgt.key"; rc_is "import: one flipped byte (sidecar)" 2
cp "$H/out/flip.age" "$H/out/flip2.age"; (cd "$H/out" && sha256sum flip2.age > flip2.age.sha256)
run import --bundle "$H/out/flip2.age" --identity "$T/tgt.key"; rc_is "import: flipped byte with re-made sidecar (age MAC)" 2
head -c 400 "$TB" > "$H/out/trunc.age"; (cd "$H/out" && sha256sum trunc.age > trunc.age.sha256)
run import --bundle "$H/out/trunc.age" --identity "$T/tgt.key"; rc_is "import: truncated bundle" 2
cp "$TB" "$H/out/nosc.age"; run import --bundle "$H/out/nosc.age" --identity "$T/tgt.key"; rc_is "import: no sidecar" 2
GB="$(mkbundle "$T/good" sconly)"; cut -c1-64 "$TB.sha256" | sed 's/$/  sconly.age/' > "$GB.sha256"   # valid bundle, foreign sidecar
run import --bundle "$GB" --identity "$T/tgt.key"; rc_is "import: valid bundle, sidecar of another bundle" 2
grep -q 'does not match its sidecar' <<<"$OUT" && ok "sidecar mismatch is what refused it" || ko "sidecar text" "$OUT"
cp -a "$T/good" "$T/ev1"; echo x > "$T/ev1/cfgvol/postfiatd.cfg"
run import --bundle "$(mkbundle "$T/ev1" ev1)" --identity "$T/tgt.key"; rc_is "import: file changed, manifest not" 2
cp -a "$T/good" "$T/ev2"; echo x > "$T/ev2/cfgvol/extra.txt"
run import --bundle "$(mkbundle "$T/ev2" ev2)" --identity "$T/tgt.key"; rc_is "import: extra file not in manifest" 2
cp -a "$T/good" "$T/ev3"; mkdir -p "$T/ev3/etc/cron.d"; echo '* * * * * root id' > "$T/ev3/etc/cron.d/x"
run import --bundle "$(mkbundle "$T/ev3" ev3)" --identity "$T/tgt.key"; rc_is "import: path outside the layout" 2
(cd "$T/ev3" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > ../ev3.m && mv ../ev3.m MANIFEST.sha256)
run import --bundle "$(mkbundle "$T/ev3" ev3m)" --identity "$T/tgt.key"; rc_is "import: path outside the layout, listed in the manifest" 2
grep -q 'unexpected path' <<<"$OUT" && ok "layout check is what refused it" || ko "layout text" "$OUT"
cp -a "$T/good" "$T/ev4"; ln -s /etc/shadow "$T/ev4/cfgvol/link"
run import --bundle "$(mkbundle "$T/ev4" ev4)" --identity "$T/tgt.key"; rc_is "import: symlink" 2
(cd "$T/good" && tar -cf - --transform 's|^\./cfgvol/validators.txt|../../escape.txt|' . | age -r "$TGT_PUB" -o "$H/out/ev5.age"); (cd "$H/out" && sha256sum ev5.age > ev5.age.sha256)
run import --bundle "$H/out/ev5.age" --identity "$T/tgt.key"; rc_is "import: ../ path escape" 2
[ ! -e "$T/hosts/escape.txt" ] && [ ! -e "$T/escape.txt" ] && ok "path escape wrote nothing" || ko "ESCAPE WRITTEN"
cp -a "$T/good" "$T/ev6"; sed -i 's|^compose_dir=.*|compose_dir=/opt/../etc|' "$T/ev6/META"; (cd "$T/ev6" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > ../ev6.m && mv ../ev6.m MANIFEST.sha256)
run import --bundle "$(mkbundle "$T/ev6" ev6)" --identity "$T/tgt.key"; rc_is "import: META compose_dir with .." 2
[ "$(find "$R" -type f | wc -l)" = 0 ] && [ ! -f "$STATE_DIR/IMPORTED" ] && ok "import negatives installed nothing" || ko "negatives left files" "$(find "$R" | head)"
[ -z "$(ls -A "$T/shm")" ] && ok "import negatives: RAM stage removed" || ko "stage left" "$(ls -A "$T/shm")"
mkdir -p "$H/s/c/postfiatd"; echo running > "$H/s/c/postfiatd/status"; echo unless-stopped > "$H/s/c/postfiatd/restart"
run import --bundle "$TB" --identity "$T/tgt.key"; rc_is "import: a copy is RUNNING here" 4
rm -rf "$H/s/c/postfiatd"
run import --bundle "$TB" --identity "$T/tgt.key" --skip-overlay docker-compose.yml; rc_is "import: cannot skip the base file" 3

# --- import ok -------------------------------------------------------------------------------------------------
run import --bundle "$TB" --identity "$T/tgt.key"
rc_is "import ok" 0
cmp -s "$R$VOL/postfiatd.cfg" "$T/hosts/src/root$VOL/postfiatd.cfg" && [ "$(stat -c %a "$R$VOL/postfiatd.cfg")" = 640 ] && ok "import: cfg byte-identical, mode kept" || ko "cfg"
[ "$(stat -c %a "$R/var/lib/pft-cluster/node_seed")" = 600 ] && [ "$(stat -c %a "$R/var/lib/pft-cluster")" = 700 ] && ok "import: node_seed 0600 in 0700" || ko "seed mode"
[ -f "$R/etc/pft-seccomp/pft-postfiatd.json" ] && [ -f "$R/etc/apparmor.d/pft-postfiatd" ] && ok "import: overlay host files" || ko "host files"
cmp -s "$STATE_DIR/env.imported" "$T/env.orig" && grep -q 'migrate-fence.yml$' "$R/opt/postfiatd/.env" && ok "import: env kept, guard on" || ko "import env"
[ "$(st tgt)" = none ] && ! grep -q 'compose up' "$H/s/calls" && ok "import never starts the node" || ko "import started node"
grep -q 'docker volume create --label com.docker.compose.project=postfiatd --label com.docker.compose.volume=postfiatd-config postfiatd_postfiatd-config' "$H/s/calls" \
  && ok "import: volume created with compose labels" || ko "volume create" "$(grep volume "$H/s/calls")"
(cd "$R/opt/postfiatd" && "$DOCKER" compose up -d >/dev/null 2>&1); [ "$(st tgt)" != running ] && ok "imported target: plain compose up refused by guard" || ko "target guard"
rm -rf "$H/s/c/postfiatd"

# --- start-target ----------------------------------------------------------------------------------------------
sed 's/^container_state=.*/container_state=running/' "$T/src.proof" > "$T/p.run"
sed "s/^bundle_id=.*/bundle_id=20990101T000000Z-deadbeef/" "$T/src.proof" > "$T/p.id"
sed "s/^pubkey=.*/pubkey=$PUB_B/" "$T/src.proof" > "$T/p.pub"
grep -v '^compose_guard=' "$T/src.proof" > "$T/p.guard"
run start-target --fence-proof "$T/p.run" --source src; rc_is "start-target: proof says running" 4
run start-target --fence-proof "$T/p.id" --source src; rc_is "start-target: proof for another bundle" 4
run start-target --fence-proof "$T/p.pub" --source src; rc_is "start-target: proof for another pubkey" 4
run start-target --fence-proof "$T/p.guard" --source src; rc_is "start-target: proof without guard" 4
echo running > "$T/hosts/src/s/c/postfiatd/status"
run start-target --fence-proof "$T/src.proof" --source src:2559; rc_is "start-target: source still answers" 4
grep -q 'still answers' <<<"$OUT" && grep -q 'probe src 2559' "$H/s/calls" && ok "source probe was made" || ko "probe" "$OUT"
echo exited > "$T/hosts/src/s/c/postfiatd/status"
[ "$(st tgt)" = none ] && ok "refusals started nothing" || ko "refusal started target"
export PFT_MIGRATE_NOW=1900000042
run start-target --fence-proof "$T/src.proof" --source src
rc_is "start-target ok" 0
[ "$(st tgt)" = running ] && [ "$(rp tgt)" = unless-stopped ] && ok "target running, restart unless-stopped" || ko "target state $(st tgt)/$(rp tgt)"
cmp -s "$R/opt/postfiatd/.env" "$T/env.orig" && [ ! -f "$R/opt/postfiatd/docker-compose.migrate-fence.yml" ] && ok "target guard removed, .env = source's" || ko "target env"

# --- verify ----------------------------------------------------------------------------------------------------
export PFT_MIGRATE_NOW=1900000100
run verify --expect-pubkey "$PUB_A" --since-proof "$T/src.proof"
rc_is "verify target ok" 0
grep -qx 'downtime_s=100' <<<"$OUT" && grep -q 'matches' <<<"$OUT" && ok "verify: identity matches, downtime_s=100" || ko "verify out" "$OUT"
run verify --expect-pubkey "$PUB_B"; rc_is "verify: wrong identity" 2
echo syncing > "$H/s/state"
run verify --expect-pubkey "$PUB_A" --timeout 3; rc_is "verify: not full -> timeout" 1
rm -f "$H/s/state"

# --- rollback --------------------------------------------------------------------------------------------------
on src
run rollback --bundle-id "$ID" --fence-proof "$T/src.proof" --target tgt; rc_is "rollback: target running" 4
[ "$(st src)" = exited ] && ok "refused rollback left source fenced" || ko "source started"
on tgt
export PFT_MIGRATE_NOW=1900000200
run fence --bundle-id "$ID" --proof-out "$T/tgt.proof"
rc_is "fence the target (alias)" 0
[ "$(st tgt)" = exited ] && grep -qx 'fenced_at=1900000200' "$T/tgt.proof" && ok "target fenced, proof written" || ko "target fence" "$OUT"
run start-target --fence-proof "$T/src.proof" --source src; rc_is "start-target on a fenced target" 4
on src
cp "$T/tgt.proof" "$T/p.old"; sed -i 's/^fenced_at=.*/fenced_at=1899999999/' "$T/p.old"
run rollback --bundle-id "$ID" --fence-proof "$T/p.old" --target tgt; rc_is "rollback: target proof older than the source fence" 4
run rollback --bundle-id 20990101T000000Z-deadbeef --fence-proof "$T/tgt.proof" --target tgt; rc_is "rollback: wrong bundle id" 4
on tgt; run rollback --bundle-id "$ID" --fence-proof "$T/src.proof" --target src; rc_is "rollback on the target (not the source)" 4
on src
rm -f "$H/s/c/postfiatd/guarded"   # nobody ran compose up while fenced: compose starts the SAME container, policy as left
export PFT_MIGRATE_NOW=1900000210
run rollback --bundle-id "$ID" --fence-proof "$T/tgt.proof" --target tgt
rc_is "rollback ok" 0
cmp -s "$R/opt/postfiatd/.env" "$T/env.orig" && ok "rollback: .env byte-identical to before the fence" || ko "rollback env" "$(diff "$T/env.orig" "$R/opt/postfiatd/.env")"
[ "$(st src)" = running ] && [ "$(rp src)" = unless-stopped ] && ok "rollback: source running, restart unless-stopped" || ko "rollback state $(st src)/$(rp src)"
[ ! -f "$STATE_DIR/FENCED" ] && [ -f "$STATE_DIR/rolled-back-$ID" ] && grep -q 'maint lock rm pft-migrate' "$H/s/calls" && ok "rollback: FENCED archived, lock removed" || ko "rollback records"
export PFT_MIGRATE_NOW=1900000260
run verify --expect-pubkey "$PUB_A" --since-proof "$T/tgt.proof"
rc_is "verify source after rollback" 0
grep -qx 'downtime_s=60' <<<"$OUT" && ok "rollback downtime_s=60" || ko "rollback downtime" "$OUT"
run rollback --bundle-id "$ID" --fence-proof "$T/tgt.proof" --target tgt; rc_is "second rollback: not fenced" 4

# --- secrets ---------------------------------------------------------------------------------------------------
grep -qF "$SEED" <<<"$ALL" && ko "SEED PRINTED in tool output" || ok "seed never printed by any command"
grep -q 'AGE-SECRET-KEY' <<<"$ALL" && ko "AGE IDENTITY PRINTED" || ok "age identity never printed"

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
