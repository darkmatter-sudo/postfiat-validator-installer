#!/usr/bin/env bash
# Stand-in for `docker` in tests/run-tests.sh. Fixture files live in $STUB:
#   run  ... validator-keys ... CMD : fake create_keys / create_token / revoke_keys on <dir>:/k (STUB_INC = sequence
#                                     step for create_token, default 1; $STUB/vk-fail makes it exit 1)
#   exec CONTAINER CMD...           : $STUB/down -> exit 1; stat -> $STUB/stat; grep -c PATTERN -> count in $STUB/cfg;
#                                     sh (master key scan) -> $STUB/mk or 0; postfiatd ... server_info|validator_info|
#                                     manifest -> $STUB/<cmd>.json ({} if absent)
# Every call is appended to $STUB/calls.
set -uo pipefail
echo "$*" >> "$STUB/calls"
case "${1:-}" in
  run)
    d=""; for a in "$@"; do case "$a" in *:/k) d="${a%:/k}" ;; esac; done
    cmd="${*: -1}"; kf="$d/validator-keys.json"
    [ -f "$STUB/vk-fail" ] && { echo "stub validator-keys failure"; exit 1; }
    case "$cmd" in
      create_keys)
        [ -e "$kf" ] && { echo "Refusing to overwrite existing key file"; exit 1; }
        printf '{"key_type":"ed25519","public_key":"nHStubPublicKey","revoked":false,"secret_key":"STUBSECRETKEYVALUE","token_sequence":0}\n' > "$kf"
        chmod 644 "$kf"; echo "Validator keys stored in /k/validator-keys.json" ;;
      create_token)
        jq --argjson i "${STUB_INC:-1}" '.token_sequence += $i' "$kf" > "$kf.n" && mv "$kf.n" "$kf"
        printf 'Update rippled.cfg file with these values and restart rippled:\n\n# validator public key: nHStubPublicKey\n\n[validator_token]\nSTUBTOKENLINEONE\nSTUBTOKENLINETWO\n\n' ;;
      revoke_keys)
        jq '.revoked = true' "$kf" > "$kf.n" && mv "$kf.n" "$kf"
        printf 'WARNING: This will revoke your validator keys!\n\n[validator_key_revocation]\nSTUBREVOKELINE\n\n' ;;
    esac ;;
  exec)
    shift 2
    [ -f "$STUB/down" ] && exit 1
    case "$1" in
      stat) cat "$STUB/stat" ;;
      grep) grep -c -- "$3" "$STUB/cfg" ;;
      sh) cat "$STUB/mk" 2>/dev/null || echo 0 ;;
      postfiatd) f="$STUB/$4.json"; if [ -f "$f" ]; then cat "$f"; else echo '{}'; fi ;;
    esac ;;
esac
