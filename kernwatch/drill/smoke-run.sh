#!/usr/bin/env bash
# Read-only smoke of pft-kernwatch on both hosts, from the repo root: check-catalogue, a redacted report of every boot
# in the journal, then collect --stdout (seed, then incremental) and collect --from-boot-start in throwaway state dirs
# (removed afterwards). Writes no textfile and installs nothing. Usage: bash kernwatch/drill/smoke-run.sh
set -uo pipefail
x() { echo "\$ $*"; eval "$*"; local rc=$?; echo "(exit $rc)"; return "$rc"; }
F="kernwatch/pft-kernwatch.sh kernwatch/kernwatch_parse.py kernwatch/catalogue.tsv"
echo "== pft-kernwatch smoke $(date -u +%FT%TZ)"
echo "OS: $(. /etc/os-release; echo "$PRETTY_NAME") | commit $(git rev-parse HEAD)"
x "sha256sum $F"
echo "== validator-host (local)"
S=/var/tmp/kw-smoke-v
E="sudo -n env PFT_KW_CONF=/nonexistent PFT_KW_HELPER=kernwatch/kernwatch_parse.py CATALOGUE=kernwatch/catalogue.tsv HOST_LABEL=validator"
x "sudo -n rm -rf $S $S-full"
x "$E bash kernwatch/pft-kernwatch.sh check-catalogue"
x "$E bash kernwatch/pft-kernwatch.sh report --boot all --format tsv"
x "$E STATE_DIR=$S bash kernwatch/pft-kernwatch.sh collect --stdout | grep -vE '^# (HELP|TYPE)' | grep -E 'up|records|seeded|backlog|matches_total.*(oom_global|martian)\b'"
x "sudo -n python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sorted(d), d[\"records_total\"])' $S/state.json"
x "$E STATE_DIR=$S bash kernwatch/pft-kernwatch.sh collect --stdout | grep -E '^pft_kernwatch_(up|records_total|run_records|malformed_total)\{'"
x "$E STATE_DIR=$S-full bash kernwatch/pft-kernwatch.sh collect --stdout --from-boot-start | grep -E '^pft_kernwatch_(up|records_total|malformed_total|backlog)\{|matches_total.* [1-9][0-9]*$'"
x "sudo -n stat -c '%a %U %n' $S $S/state.json"
x "sudo -n rm -rf $S $S-full"
echo "== sentry-host (ssh relay)"
R=/var/tmp/kw-smoke-src
x "ssh relay 'rm -rf $R /var/tmp/kw-smoke-s /var/tmp/kw-smoke-s-full && mkdir -p $R/kernwatch'"
x "scp -q $F relay:$R/kernwatch/"
x "ssh relay '. /etc/os-release; echo OS: \$PRETTY_NAME; cd $R && sha256sum $F'"
RE="cd $R && env PFT_KW_CONF=/nonexistent PFT_KW_HELPER=kernwatch/kernwatch_parse.py CATALOGUE=kernwatch/catalogue.tsv HOST_LABEL=sentry"
x "ssh relay '$RE bash kernwatch/pft-kernwatch.sh report --boot all --format tsv'"
x "ssh relay '$RE STATE_DIR=/var/tmp/kw-smoke-s bash kernwatch/pft-kernwatch.sh collect --stdout' | grep -E '^pft_kernwatch_(up|records_total|seeded_timestamp_seconds|backlog)\{'"
x "ssh relay '$RE STATE_DIR=/var/tmp/kw-smoke-s bash kernwatch/pft-kernwatch.sh collect --stdout' | grep -E '^pft_kernwatch_(up|records_total|run_records|malformed_total)\{'"
x "ssh relay '$RE STATE_DIR=/var/tmp/kw-smoke-s-full bash kernwatch/pft-kernwatch.sh collect --stdout --from-boot-start' | grep -E '^pft_kernwatch_(up|records_total|malformed_total|backlog)\{|matches_total.* [1-9][0-9]*$'"
x "ssh relay 'rm -rf $R /var/tmp/kw-smoke-s /var/tmp/kw-smoke-s-full; ls -d /var/tmp/kw-smoke* 2>/dev/null | wc -l'"
echo "end $(date -u +%FT%TZ)"
