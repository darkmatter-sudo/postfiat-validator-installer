#!/usr/bin/env bash
# pft-valkeys: validator master-key / token lifecycle for a Post Fiat validator, plus a read-only check of the
# running node's manifest sequence, ephemeral key and key/config permissions.
#
# Usage: pft-valkeys keys create   --dir DIR                       new master key in DIR/validator-keys.json
#        pft-valkeys token rotate  --dir DIR [--out FILE]          next [validator_token] (sequence + 1) into FILE
#        pft-valkeys revoke        --dir DIR --confirm-key nH...   [--confirm-phrase "REVOKE nH..."]
#        pft-valkeys check [--container NAME] [--conf PATH] [--keydir DIR] [--state FILE] [--textfile-dir DIR]
#                          [--host LABEL]
#        pft-valkeys version
#
#  keys/token/revoke run the `validator-keys` binary from the postfiatd image in a throwaway container:
#  --network none, --read-only, --cap-drop ALL, no-new-privileges, as the calling uid:gid, with only DIR mounted.
#  Run them on an offline/admin machine, not on the validator. DIR must be a real directory (not a symlink) owned
#  by the caller with mode 0700 (created 0700 if missing). Every file written is 0600. Secrets never reach stdout:
#  validator-keys' own output is captured in a 0600 temp file inside DIR, the token/revocation block is copied to
#  its output file, and only the public key, sequence and file paths are printed. Existing files are never
#  overwritten (exit 2). revoke needs the master public key twice: --confirm-key and the phrase
#  "REVOKE <public key>" (typed on a terminal, or --confirm-phrase when stdin is not a terminal).
#
#  check is read-only. It reads the node container with `docker exec` (stat, grep -c of section headers, find -name,
#  and the admin RPC commands server_info / validator_info / manifest via the postfiatd CLI) and never prints a file's
#  contents. Writes happen only to --state FILE (highest sequence seen per master key) and --textfile-dir.
#  Output: one "OK|INFO|WARN|FAIL <id> <message>" line per check, then RESULT. Exit 0 OK, 1 WARN, 2 FAIL,
#  3 usage error.
#
# Env: PFT_VK_IMAGE (agtipft/postfiatd:testnet-light-latest), PFT_VK_DOCKER (docker), PFT_VK_NOW (epoch, tests).
set -uo pipefail
umask 077
VERSION=1.0.0
IMAGE="${PFT_VK_IMAGE:-agtipft/postfiatd:testnet-light-latest}"
DOCKER="${PFT_VK_DOCKER:-docker}"
KEYFILE=validator-keys.json
REVOKED_SEQ=4294967295

die() { printf 'pft-valkeys: %s\n' "$1" >&2; exit "${2:-2}"; }
usage() { sed -n '4,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 3; }

# seq_compare CUR MAX -> first | same | advanced | regression   (MAX empty = never seen)
seq_compare() {
  local cur="$1" max="$2"
  [[ "$cur" =~ ^[0-9]+$ ]] || { echo invalid; return; }
  if [ -z "$max" ]; then echo first
  elif ! [[ "$max" =~ ^[0-9]+$ ]]; then echo invalid
  elif [ "$cur" -lt "$max" ]; then echo regression
  elif [ "$cur" -eq "$max" ]; then echo same
  else echo advanced; fi
}

# perm_grade MODE SECRET(0|1) -> ok | warn | fail   (MODE octal like 600 / 644)
perm_grade() {
  local m=$((8#$1))
  if [ "$2" != 1 ]; then echo ok; return; fi
  if (( m & 8#007 )); then echo fail; elif (( m & 8#070 )); then echo warn; else echo ok; fi
}

# ---- offline key operations -------------------------------------------------------------------------------
# secure_dir DIR CREATE(0|1): refuse symlinks, other owners and any group/other bits
secure_dir() {
  local d="$1"
  [ -L "$d" ] && die "refusing: $d is a symlink"
  if [ ! -e "$d" ]; then
    [ "$2" = 1 ] || die "refusing: $d does not exist"
    mkdir -m 700 -- "$d" || die "cannot create $d"
  fi
  [ -d "$d" ] || die "refusing: $d is not a directory"
  [ "$(stat -c %u -- "$d")" = "$(id -u)" ] || die "refusing: $d is not owned by uid $(id -u)"
  [ "$(stat -c %a -- "$d")" = 700 ] || die "refusing: $d has mode $(stat -c %a -- "$d"), need 700"
}

vk() { # vk DIR CMD... : validator-keys in a network-isolated throwaway container, output -> stdout of caller
  local d; d="$(cd -- "$1" && pwd -P)"; shift
  "$DOCKER" run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" -e HOME=/k -v "$d:/k" --entrypoint validator-keys "$IMAGE" \
    --keyfile "/k/$KEYFILE" "$@"
}

keyfield() { jq -r --arg f "$2" '.[$f] // empty' "$1/$KEYFILE"; }

check_keyfile() {
  local f="$1/$KEYFILE"
  if [ ! -f "$f" ] || [ -L "$f" ]; then die "refusing: no key file $f"; fi
  [ "$(stat -c %a -- "$f")" = 600 ] || die "refusing: $f has mode $(stat -c %a -- "$f"), need 600"
  jq -e '.public_key and .secret_key' "$f" >/dev/null 2>&1 || die "refusing: $f is not a validator-keys file"
}

new_out() { # new_out PATH : must not exist; parent must not be group/other writable
  local p="$1" par
  [ -e "$p" ] || [ -L "$p" ] && die "refusing to overwrite $p"
  par="$(dirname -- "$p")"
  [ -d "$par" ] || die "refusing: $par is not a directory"
  (( 8#$(stat -c %a -- "$par") & 8#022 )) && die "refusing: $par is group/other writable"
  return 0
}

capture() { # capture DIR CMD... : run vk, keep its output in a 0600 temp file inside DIR, echo the temp path
  local d="$1" tmp; shift
  tmp="$(mktemp "$d/.vk-out.XXXXXX")" || die "mktemp failed"
  if ! vk "$d" "$@" > "$tmp" 2>&1; then
    echo "pft-valkeys: validator-keys $1 failed: $(grep -v -E '^[A-Za-z0-9+/=]{20,}$' "$tmp" | head -3 | tr '\n' ' ')" >&2
    rm -f -- "$tmp"; exit 2
  fi
  echo "$tmp"
}

block() { awk -v h="$2" '$0 == h {f=1} f && NF' "$1"; } # block FILE HEADER : header + following non-empty lines

cmd_keys_create() {
  local dir=""
  while [ $# -gt 0 ]; do case "$1" in --dir) dir="${2:-}"; shift 2 ;; *) usage ;; esac; done
  [ -n "$dir" ] || usage
  secure_dir "$dir" 1
  [ -e "$dir/$KEYFILE" ] || [ -L "$dir/$KEYFILE" ] && die "refusing to overwrite $dir/$KEYFILE"
  local tmp; tmp="$(capture "$dir" create_keys)"; rm -f -- "$tmp"
  [ -f "$dir/$KEYFILE" ] || die "validator-keys did not create $dir/$KEYFILE"
  chmod 600 -- "$dir/$KEYFILE"
  echo "created   $dir/$KEYFILE (mode $(stat -c %a -- "$dir/$KEYFILE"))"
  echo "public_key $(keyfield "$dir" public_key) ($(keyfield "$dir" key_type))"
  echo "next: pft-valkeys token rotate --dir $dir ; keep this directory offline and backed up"
}

cmd_token_rotate() {
  local dir="" out=""
  while [ $# -gt 0 ]; do case "$1" in --dir) dir="${2:-}"; shift 2 ;; --out) out="${2:-}"; shift 2 ;; *) usage ;; esac; done
  [ -n "$dir" ] || usage
  secure_dir "$dir" 0; check_keyfile "$dir"
  [ "$(keyfield "$dir" revoked)" = true ] && die "refusing: key $(keyfield "$dir" public_key) is revoked"
  local old new; old="$(keyfield "$dir" token_sequence)"; old="${old:-0}"
  [ -n "$out" ] || out="$dir/token-seq$((old + 1)).cfg"
  new_out "$out"
  local tmp; tmp="$(capture "$dir" create_token)"
  new="$(keyfield "$dir" token_sequence)"
  if [ "$new" != "$((old + 1))" ]; then rm -f -- "$tmp"; die "token_sequence went $old -> $new, expected $((old + 1))"; fi
  block "$tmp" '[validator_token]' > "$out"; rm -f -- "$tmp"; chmod 600 -- "$out"
  if [ "$(head -1 "$out")" != '[validator_token]' ] || [ "$(wc -l < "$out")" -lt 2 ]; then
    die "no [validator_token] block in validator-keys output"
  fi
  echo "rotated   $(keyfield "$dir" public_key) token sequence $old -> $new"
  echo "token     $out (mode $(stat -c %a -- "$out"), $(($(wc -l < "$out") - 1)) lines; not printed)"
  echo "next: replace the [validator_token] section of postfiatd.cfg with this file, restart postfiatd, then"
  echo "      pft-valkeys check --state FILE should report sequence $new; shred the file once installed"
}

cmd_revoke() {
  local dir="" key="" phrase="" have_phrase=0
  while [ $# -gt 0 ]; do case "$1" in
    --dir) dir="${2:-}"; shift 2 ;; --confirm-key) key="${2:-}"; shift 2 ;;
    --confirm-phrase) phrase="${2:-}"; have_phrase=1; shift 2 ;; *) usage ;; esac; done
  [ -n "$dir" ] || usage
  secure_dir "$dir" 0; check_keyfile "$dir"
  local pub; pub="$(keyfield "$dir" public_key)"
  [ "$(keyfield "$dir" revoked)" = true ] && die "refusing: key $pub is already revoked"
  [ "$key" = "$pub" ] || die "refusing: --confirm-key must equal the master public key in $dir/$KEYFILE"
  if [ "$have_phrase" = 0 ]; then
    [ -t 0 ] || die "refusing: stdin is not a terminal; pass --confirm-phrase \"REVOKE $pub\""
    echo "WARNING: revoking $pub is permanent. Every node will stop trusting this master key."
    printf 'Type REVOKE %s to continue: ' "$pub"; IFS= read -r phrase
  fi
  [ "$phrase" = "REVOKE $pub" ] || die "refusing: confirmation phrase does not match"
  local out="$dir/revocation.cfg"; new_out "$out"
  local tmp; tmp="$(capture "$dir" revoke_keys)"
  block "$tmp" '[validator_key_revocation]' > "$out"; rm -f -- "$tmp"; chmod 600 -- "$out"
  if [ "$(keyfield "$dir" revoked)" != true ] || [ "$(head -1 "$out")" != '[validator_key_revocation]' ]; then
    die "revocation did not complete (check $dir)"
  fi
  echo "revoked   $pub"
  echo "revocation $out (mode $(stat -c %a -- "$out"); not printed)"
  echo "next: put this section in postfiatd.cfg in place of [validator_token], restart, and create a new master key"
}

# ---- read-only node check ---------------------------------------------------------------------------------
NW=0; NF=0
say() { # say GRADE ID MESSAGE
  case "$1" in WARN) NW=$((NW + 1)) ;; FAIL) NF=$((NF + 1)) ;; esac
  printf '%-4s %-18s %s\n' "$1" "$2" "$3"
}
dx() { "$DOCKER" exec "$CONTAINER" "$@"; }
rpc() { dx postfiatd --conf "$CONF" "$@" 2>/dev/null; }

cmd_check() {
  CONTAINER=postfiatd; CONF=/etc/postfiatd/postfiatd.cfg
  local keydir="" state="" tdir="" host=validator
  while [ $# -gt 0 ]; do case "$1" in
    --container) CONTAINER="${2:-}"; shift 2 ;; --conf) CONF="${2:-}"; shift 2 ;;
    --keydir) keydir="${2:-}"; shift 2 ;; --state) state="${2:-}"; shift 2 ;;
    --textfile-dir) tdir="${2:-}"; shift 2 ;; --host) host="${2:-}"; shift 2 ;; *) usage ;; esac; done
  if [ -z "$CONTAINER" ] || [ -z "$CONF" ]; then usage; fi
  [[ "$host" =~ ^[A-Za-z0-9_.-]+$ ]] || die "bad --host label" 3
  local up=1 configured=0 seq="" maxseq="" regression=0 cmp="" now="${PFT_VK_NOW:-$(date +%s)}"

  # config file: mode/owner and which key sections it has (header counts only, never the values)
  local st n_tok n_seed n_rev secret=0
  if ! st="$(dx stat -c '%a %u' "$CONF" 2>/dev/null)"; then
    say FAIL conf.read "cannot stat $CONF in container $CONTAINER (not running?)"; up=0
  else
    n_tok="$(dx grep -c '^\[validator_token\]' "$CONF" 2>/dev/null)"; n_tok="${n_tok:-0}"
    n_seed="$(dx grep -c '^\[validation_seed\]' "$CONF" 2>/dev/null)"; n_seed="${n_seed:-0}"
    n_rev="$(dx grep -c '^\[validator_key_revocation\]' "$CONF" 2>/dev/null)"; n_rev="${n_rev:-0}"
    [ "$n_tok" -gt 0 ] || [ "$n_seed" -gt 0 ] && secret=1
    case "$(perm_grade "${st% *}" "$secret")" in
      fail) say FAIL conf.perms "$CONF mode ${st% *} is world-readable and holds a validator secret (chmod 600)" ;;
      warn) say WARN conf.perms "$CONF mode ${st% *} is group-readable and holds a validator secret (chmod 600)" ;;
      *) if [ "$secret" = 1 ]; then say OK conf.perms "$CONF mode ${st% *} owner uid ${st#* }"
         else say INFO conf.perms "$CONF mode ${st% *}; holds no validator secret"; fi ;;
    esac
    [ "$n_tok" -gt 1 ] && say FAIL conf.token "$CONF has $n_tok [validator_token] sections"
    [ "$n_seed" -gt 0 ] && say WARN conf.seed "$CONF uses [validation_seed]: the master secret is online; switch to validator-keys tokens"
    [ "$n_rev" -gt 0 ] && say WARN conf.revocation "$CONF has [validator_key_revocation]: this node announces a revoked key and does not validate"
    [ "$n_tok" -gt 0 ] && [ "$n_rev" -gt 0 ] && say FAIL conf.token "$CONF has both [validator_token] and [validator_key_revocation]"
    local mk
    mk="$(dx sh -c 'find /etc/postfiatd /var/lib/postfiatd -maxdepth 2 -type f -name "*.json" -size -8k -exec grep -l "\"secret_key\"" {} + 2>/dev/null | wc -l')"
    if [ "${mk:-0}" -gt 0 ]; then say WARN keys.online "$mk master key file(s) (secret_key) inside the node container; keep master keys offline"
    else say OK keys.online "no master key file under /etc/postfiatd or /var/lib/postfiatd"; fi
  fi

  # offline key directory, if this host holds one
  if [ -n "$keydir" ]; then
    if [ ! -d "$keydir" ]; then say FAIL keys.perms "--keydir $keydir is not a directory"
    else
      local dm bad=0 f
      dm="$(stat -c %a -- "$keydir")"
      [ "$dm" = 700 ] || { say FAIL keys.perms "$keydir mode $dm, need 700"; bad=1; }
      for f in "$keydir"/* "$keydir"/.vk-out.*; do
        [ -e "$f" ] || continue
        [ "$(stat -c %a -- "$f")" = 600 ] || { say FAIL keys.perms "$(basename -- "$f") mode $(stat -c %a -- "$f"), need 600"; bad=1; }
        [ "$(stat -c %u -- "$f")" = "$(stat -c %u -- "$keydir")" ] || { say FAIL keys.perms "$(basename -- "$f") owner differs from $keydir"; bad=1; }
      done
      [ "$bad" = 0 ] && say OK keys.perms "$keydir 700, every file 600"
    fi
  fi

  # running node: is a validator key loaded, which manifest sequence, which ephemeral key
  local si vi master="" eph="" state_s pubv
  if [ "$up" = 1 ]; then
    si="$(rpc server_info)"
    pubv="$(jq -r '.result.info.pubkey_validator // empty' <<<"$si" 2>/dev/null)"
    state_s="$(jq -r '.result.info.server_state // empty' <<<"$si" 2>/dev/null)"
    if [ -z "$state_s" ]; then say FAIL rpc "server_info failed in $CONTAINER"; up=0
    else say INFO rpc "server_state $state_s"; fi
  fi
  if [ "$up" = 1 ]; then
    vi="$(rpc validator_info)"
    if [ "$(jq -r '.result.status // empty' <<<"$vi" 2>/dev/null)" = success ]; then
      configured=1
      master="$(jq -r '.result.master_key // empty' <<<"$vi")"; eph="$(jq -r '.result.ephemeral_key // empty' <<<"$vi")"
      seq="$(jq -r '.result.seq // empty' <<<"$vi")"
      say OK validator "master key ${master:0:12}... loaded (server_info pubkey_validator ${pubv:0:12}...)"
      [ "$pubv" = "$master" ] || say FAIL validator "server_info pubkey_validator differs from validator_info master_key"
      if [[ "$eph" =~ ^n[1-9A-HJ-NP-Za-km-z]{40,60}$ ]] && [ "$eph" != "$master" ]; then
        say OK ephemeral "ephemeral key ${eph:0:12}... (signing key from the token)"
      else say FAIL ephemeral "no valid ephemeral key in validator_info (token missing or not loaded)"; fi
      if ! [[ "$seq" =~ ^[0-9]+$ ]]; then say FAIL seq "validator_info has no manifest seq"; seq=""
      elif [ "$seq" = "$REVOKED_SEQ" ]; then say FAIL seq "manifest seq $seq: this key is revoked"
      else
        # the manifest this node has cached for its own master key (peers may have relayed a newer one)
        local ms; ms="$(rpc manifest "$master" | jq -r '.result.details.seq // empty' 2>/dev/null)"
        if [[ "$ms" =~ ^[0-9]+$ ]] && [ "$(seq_compare "$seq" "$ms")" = regression ]; then
          say FAIL seq.network "running token seq $seq is older than the manifest seq $ms known to the node (old token reinstalled?)"
          regression=1
        fi
        if [ -n "$state" ]; then
          if [ -f "$state" ] && ! jq -e 'type == "object"' "$state" >/dev/null 2>&1; then cmp=invalid
          else
            maxseq="$( [ -f "$state" ] && jq -r --arg m "$master" '.[$m] // empty' "$state")"
            cmp="$(seq_compare "$seq" "$maxseq")"
          fi
          case "$cmp" in
            regression) say FAIL seq "manifest seq $seq is LOWER than the highest seen ($maxseq): old token in use"; regression=1 ;;
            same) say OK seq "manifest seq $seq (highest seen $maxseq)" ;;
            advanced) say OK seq "manifest seq $seq advanced from $maxseq (rotation recorded)" ;;
            first) say OK seq "manifest seq $seq (first record for this key)" ;;
            *) say FAIL seq "state file $state is not a JSON object (left untouched)"; maxseq="" ;;
          esac
          if [ "$cmp" = advanced ] || [ "$cmp" = first ]; then
            local tmpst; tmpst="$(mktemp "$(dirname -- "$state")/.valkeys-state.XXXXXX")" &&
              { if [ -f "$state" ]; then jq --arg m "$master" --argjson s "$seq" '.[$m] = $s' "$state"; else jq -n --arg m "$master" --argjson s "$seq" '{($m): $s}'; fi } > "$tmpst" &&
              mv -f -- "$tmpst" "$state" && maxseq="$seq"
          fi
        else say OK seq "manifest seq $seq (no --state: regression vs. history not checked)"; fi
      fi
    else
      [ -n "$pubv" ] && [ "$pubv" != none ] && say FAIL validator "pubkey_validator $pubv but validator_info failed"
      if [ "${n_tok:-0}" -gt 0 ]; then say FAIL validator "[validator_token] configured but no validator key loaded"
      else say INFO validator "not configured as a validator (no [validator_token]); sequence checks skipped"; fi
    fi
  fi

  if [ -n "$tdir" ]; then
    local tf="$tdir/pft_valkeys_$host.prom" tmp
    tmp="$(mktemp "$tdir/.pft_valkeys.XXXXXX")" || die "cannot write in $tdir"
    {
      echo "# HELP pft_valkeys_up 1 if the node could be read"; echo "# TYPE pft_valkeys_up gauge"
      echo "pft_valkeys_up{host=\"$host\"} $up"
      echo "# HELP pft_valkeys_validator_configured 1 if validator_info reports a loaded validator key"
      echo "# TYPE pft_valkeys_validator_configured gauge"
      echo "pft_valkeys_validator_configured{host=\"$host\"} $configured"
      if [ -n "$seq" ]; then
        echo "# HELP pft_valkeys_manifest_sequence manifest sequence of the running validator token"
        echo "# TYPE pft_valkeys_manifest_sequence gauge"
        echo "pft_valkeys_manifest_sequence{host=\"$host\",master=\"${master:0:12}\"} $seq"
      fi
      if [ -n "$maxseq" ]; then
        echo "# HELP pft_valkeys_manifest_sequence_max highest manifest sequence recorded in the state file"
        echo "# TYPE pft_valkeys_manifest_sequence_max gauge"
        echo "pft_valkeys_manifest_sequence_max{host=\"$host\",master=\"${master:0:12}\"} $maxseq"
      fi
      echo "# HELP pft_valkeys_sequence_regression 1 if the running token is older than one already seen"
      echo "# TYPE pft_valkeys_sequence_regression gauge"
      echo "pft_valkeys_sequence_regression{host=\"$host\"} $regression"
      echo "# HELP pft_valkeys_findings check lines by grade"; echo "# TYPE pft_valkeys_findings gauge"
      echo "pft_valkeys_findings{host=\"$host\",grade=\"warn\"} $NW"
      echo "pft_valkeys_findings{host=\"$host\",grade=\"fail\"} $NF"
      echo "# HELP pft_valkeys_last_run_timestamp_seconds end of the last check"
      echo "# TYPE pft_valkeys_last_run_timestamp_seconds gauge"
      echo "pft_valkeys_last_run_timestamp_seconds{host=\"$host\"} $now"
    } > "$tmp" && chmod 644 -- "$tmp" && mv -f -- "$tmp" "$tf"
  fi

  if [ "$NF" -gt 0 ]; then echo "RESULT: FAIL - $NF fail, $NW warn"; exit 2
  elif [ "$NW" -gt 0 ]; then echo "RESULT: WARN - $NW warn"; exit 1
  else echo "RESULT: OK"; exit 0; fi
}

[ -n "${PFT_VK_LIB:-}" ] && return 0 2>/dev/null   # sourced by tests for seq_compare / perm_grade
command -v jq >/dev/null || die "jq is required" 3
case "${1:-}" in
  keys) [ "${2:-}" = create ] || usage; shift 2; cmd_keys_create "$@" ;;
  token) [ "${2:-}" = rotate ] || usage; shift 2; cmd_token_rotate "$@" ;;
  revoke) shift; cmd_revoke "$@" ;;
  check) shift; cmd_check "$@" ;;
  version) echo "pft-valkeys $VERSION" ;;
  *) usage ;;
esac
