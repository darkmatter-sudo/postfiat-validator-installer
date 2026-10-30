#!/usr/bin/env bash
# Stubbed tests for pft-rulecheck.sh + rulecheck_lib.py. No root, no real Prometheus, no host is touched.
# A stub Prometheus API (stub_prom.py, 127.0.0.1 random port) serves fixtures/prom-*.json; textfile dirs are temp
# dirs whose mtimes are set with touch -d; the clock is PFT_RC_NOW. One PASS/FAIL line per check; exit 1 if any
# check failed.   Usage: tests/run-tests.sh [PFT_RULECHECK_SH] [RULECHECK_LIB_PY]
# shellcheck disable=SC2016,SC2034,SC1003  # check conditions are single-quoted and eval'd by check(); RC/e are read there
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$(readlink -f "${1:-$HERE/../pft-rulecheck.sh}")"
LIBPY="$(readlink -f "${2:-$HERE/../rulecheck_lib.py}")"
T="$(mktemp -d)"
STUB_PID=""
cleanup() { [ -z "$STUB_PID" ] || kill "$STUB_PID" 2>/dev/null; rm -rf "${T:?}"; }
trap cleanup EXIT
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
# check NAME 'CONDITION' : condition runs in a subshell, so an exit inside it cannot end the suite
check() { if (eval "$2") >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

NOW=1800000000
export PFT_RC_LIB="$LIBPY" PFT_RC_NOW="$NOW" PFT_RC_ENV="$T/rc.env"
FIX="$T/fixture.json"; QLOG="$T/queries.log"; : > "$QLOG"
cp "$HERE/fixtures/prom-mixed.json" "$FIX"
python3 -I "$HERE/stub_prom.py" "$FIX" "$T/port" "$QLOG" & STUB_PID=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
[ -s "$T/port" ] || { echo "stub Prometheus did not start"; exit 2; }
PORT="$(cat "$T/port")"
fixture() { # NAME [MODE]
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["mode"]=sys.argv[3]; json.dump(d, open(sys.argv[2],"w"))' \
    "$HERE/fixtures/prom-$1.json" "$FIX" "${2:-ok}"
}
TF="$T/textfile"; mkdir -p "$TF"
ago() { date -u -d "@$((NOW - $1))" +%Y-%m-%dT%H:%M:%SZ; }   # mtime N seconds before NOW
mkprom() { # FILE AGE_MTIME [TS_METRIC TS_AGE]
  local f="$TF/$1"
  { echo "# HELP x test"; echo "x_up 1"; [ -z "${3:-}" ] || echo "$3{host=\"a\"} $((NOW - $4))"; } > "$f"
  touch -d "$(ago "$2")" "$f"
}
cat > "$T/rc.conf" <<'C'
# test config
textfile pft_one_*.prom     5m   pft_one_ts
textfile pft_pulled_*.prom  5m   pft_pulled_ts
textfile pft_mtime.prom     10m  -
textfile pft_rulecheck_*.prom 3h pft_rulecheck_last_run_timestamp_seconds
textfile pft_*.prom         1h   pft_generic_ts
require pft_one_local.prom
require pft_needed.prom
ignore-rule g-bad/Ignored  optional metric, only on some hosts
ignore-metric pft_only_on_error_total  counter appears with the first error
leftover-age 10m
C
cat > "$T/rc.env" <<E
HOST_LABEL=validator
PROM_URL=http://127.0.0.1:$PORT
CONF=$T/rc.conf
TEXTFILE_DIR=$TF
LOOKBACK=10m
E
OUT=""; RC=0
rc() { OUT="$("$TOOL" "$@" 2>&1)"; RC=$?; }
has() { grep -qE -- "$1" <<<"$OUT"; }
row() { grep -qE -- "^$1 +$2( |$)" <<<"$OUT"; }       # STATE NAME (table row)

reset_tf() {
  rm -rf "$TF"; mkdir -p "$TF"
  mkprom pft_one_local.prom 30 pft_one_ts 30            # FRESH
  mkprom pft_one_old.prom 400 pft_one_ts 400            # STALE by mtime (and content)
  mkprom pft_pulled_peer.prom 20 pft_pulled_ts 900      # pulled copy fresh, content 15 min old -> STALE (content)
  mkprom pft_pulled_nots.prom 20                        # ts metric missing -> STALE
  mkprom pft_mtime.prom 590                             # mtime-only, 590 < 600 -> FRESH
  mkprom pft_generic.prom 3000 pft_generic_ts 3000      # catch-all 1h -> FRESH
  mkprom other_collector.prom 10                        # no line matches -> UNCONFIGURED
  echo partial > "$TF/.pull-peer.Ab12Cd"; touch -d "$(ago 900)" "$TF/.pull-peer.Ab12Cd"     # LEFTOVER
  echo partial > "$TF/.pull-peer.Young1"; touch -d "$(ago 60)" "$TF/.pull-peer.Young1"      # in flight: ignored
  echo x > "$TF/notes.txt"; touch -d "$(ago 700)" "$TF/notes.txt"                           # LEFTOVER (non-.prom)
}

# ---------- selector extraction ----------
sel() { "$TOOL" selectors "$1" 2>&1 | paste -sd'|' -; }
check "selectors: aggregation by() labels are not metrics" '[ "$(sel "sum by (instance, job) (rate(foo_total[5m]))")" = "foo_total" ]'
check "selectors: trailing by() after the call" '[ "$(sel "sum(rate(foo[5m])) by (job)")" = "foo" ]'
check "selectors: on()/group_left() labels skipped, both sides kept" '[ "$(sel "a > on (job, instance) group_left (x) b")" = "a|b" ]'
check "selectors: ignoring()/without() labels skipped" '[ "$(sel "max without (state) (a) / ignoring (z) b")" = "a|b" ]'
check "selectors: absent() argument marked" '[ "$(sel "x == 0 or absent(x{job=\"p\"})")" = "x|absent:x{job=\"p\"}" ]'
check "selectors: absent_over_time() marked" '[ "$(sel "absent_over_time(y[10m])")" = "absent:y" ]'
check "selectors: constants have no selector" '[ -z "$(sel "vector(1) * 2 + time()")" ]'
check "selectors: Inf/NaN are numbers" '[ -z "$(sel "NaN > Inf")" ]'
check "selectors: strings in label_replace ignored" '[ "$(sel "label_replace(up, \"d\", \"\$1\", \"s\", \"(.*)\")")" = "up" ]'
check "selectors: offset and @ end() stripped" '[ "$(sel "rate(m[5m] offset 1h) and n @ end()")" = "m|n" ]'
check "selectors: subquery range skipped" '[ "$(sel "max_over_time(rate(c[5m])[1h:1m])")" = "c" ]'
check "selectors: recording-rule names with colons" '[ "$(sel "pft:a:ratio > on () group_left () (1 - pft:b:ratio)")" = "pft:a:ratio|pft:b:ratio" ]'
check "selectors: bare {__name__=~} matcher" '[ "$(sel "{__name__=~\"a|b\", job!=\"z\"}")" = "{__name__=~\"a|b\",job!=\"z\"}" ]'
check "selectors: quoted metric name (Prometheus 3)" '[ "$(sel "{\"my.metric\", a=\"b\"}")" = "{\"my.metric\",a=\"b\"}" ]'
check "selectors: single-quoted value with escaped quote" '[ "$(sel "up{a='"'"'x\\'"'"'y'"'"'}")" = "up{a=\"x'"'"'y\"}" ]'
check "selectors: braces inside a label value" '[ "$(sel "m{a=\"}{\"} > 0")" = "m{a=\"}{\"}" ]'
check "selectors: keywords and/or/unless/bool are not metrics" '[ "$(sel "a and b or c unless d == bool 1")" = "a|b|c|d" ]'
check "selectors: count_values string + ALERTS" '[ "$(sel "count_values(\"v\", ALERTS)")" = "ALERTS" ]'
check "selectors: topk param + metric" '[ "$(sel "topk(3, q)")" = "q" ]'
check "selectors: comment ignored" '[ "$(sel "a # b c")" = "a" ]'
check "selectors: unbalanced paren -> exit 2" '! "$TOOL" selectors "sum(a" && [ "$("$TOOL" selectors "sum(a" >/dev/null 2>&1; echo $?)" = 2 ]'
check "selectors: unclosed brace -> exit 2" '[ "$("$TOOL" selectors "a{b=\"c\"" >/dev/null 2>&1; echo $?)" = 2 ]'

# ---------- rules: every class ----------
reset_tf
fixture mixed; : > "$QLOG"
rc check
check "mixed: exit 1 (findings)" '[ "$RC" = 1 ]'
check "LIVE: plain selector" 'row LIVE "g-live/LiveOne"'
check "LIVE: constant rule (no selector)" 'row LIVE "g-live/Const" && has "g-live/Const +0/0 +no selector"'
check "LIVE: absent()-only rule is not dead" 'row LIVE "g-live/AbsentOnly"'
check "LIVE: ALERTS-only rule is not dead" 'row LIVE "g-live/AlertsOnly"'
check "LIVE: recording rule" 'row LIVE "g-live/job:pft_x:rate5m"'
check "LIVE: escaped quote + regex matcher queried verbatim" 'row LIVE "g-live/Matchers" && has "g-live/Matchers +2/2"'
check "LIVE: same selector twice counted once" 'has "g-live/SameTwice +1/1"'
check "DEAD: renamed metric" 'row DEAD "g-bad/DeadOne" && has "g-bad/DeadOne +0/1 +pft_renamed_metric"'
check "PARTIAL: one side empty, names the dead selector" 'row PARTIAL "g-bad/PartialOne" && has "g-bad/PartialOne +1/2 +pft_b$"'
check "ERROR: Prometheus health err with lastError" 'row ERROR "g-bad/ErrHealth" && has "many-to-many matching not allowed"'
check "ERROR: unparsable expression" 'row ERROR "g-bad/ParseFail" && has "cannot parse"'
check "IGNORED: ignore-rule with reason" 'row IGNORED "g-bad/Ignored" && has "optional metric, only on some hosts"'
check "ignore-metric: rule with only that selector is LIVE 0/0" 'row LIVE "g-bad/IgnMetric" && has "g-bad/IgnMetric +0/0"'
check "same rule name in two groups listed twice" '[ "$(grep -cE "/LiveOne " <<<"$OUT")" = 2 ]'
check "query cache: each distinct selector queried once" '[ "$(sort "$QLOG" | uniq -d | wc -l)" = 0 ] && [ "$(wc -l < "$QLOG")" = 6 ]'
check "queries use count(last_over_time(SEL[10m]))" 'grep -qx "count(last_over_time(pft_renamed_metric\[10m\]))" "$QLOG"'
check "absent()/ALERTS/ignored selectors never queried" '! grep -qE "pft_missing_metric|ALERTS|pft_only_on_error_total|pft_optional_metric" "$QLOG"'
check "RESULT line counts" 'has "^RESULT FINDINGS - rules: LIVE 9 PARTIAL 1 DEAD 1 ERROR 2 IGNORED 1 \|"'
rc check --lookback 2h
check "--lookback passed to the query" '[ "$RC" = 1 ] && grep -q "\[2h\]))$" "$QLOG"'
rc check --lookback 2x
check "bad --lookback -> exit 2" '[ "$RC" = 2 ]'
rc check --lookback 0m
check "--lookback 0m refused by the wrapper (empty range) -> exit 2" '[ "$RC" = 2 ] && has "bad --lookback"'

# ---------- textfiles: every class ----------
rc check --no-prom
check "no-prom: rules skipped" 'has "rules: skipped"'
check "FRESH: local file, content ts 30s" 'row FRESH pft_one_local.prom'
check "STALE: mtime 400s > 5m" 'row STALE pft_one_old.prom'
check "STALE: pulled copy fresh but content 15m old (source = ts metric)" 'row STALE pft_pulled_peer.prom && has "pft_pulled_peer.prom +15m.* pft_pulled_ts"'
check "STALE: ts metric missing from the file" 'row STALE pft_pulled_nots.prom && has "timestamp metric missing"'
check "FRESH: mtime-only line, 590s < 10m" 'row FRESH pft_mtime.prom'
check "first matching line wins (catch-all 1h only for the rest)" 'row FRESH pft_generic.prom'
check "UNCONFIGURED: no line matches" 'row UNCONFIGURED other_collector.prom'
check "LEFTOVER: interrupted pull temp file 15m old" 'row LEFTOVER .pull-peer.Ab12Cd'
check "LEFTOVER: old non-.prom file" 'row LEFTOVER notes.txt'
check "young temp file (in-flight pull) not reported" '! has "Young1"'
check "MISSING: required file absent" 'row MISSING pft_needed.prom'
check "required file present is not MISSING" '! row MISSING pft_one_local.prom'
check "no-prom textfile findings -> exit 1" '[ "$RC" = 1 ]'
check "textfile RESULT counts" 'has "textfiles: FRESH 3 STALE 3 MISSING 1 LEFTOVER 2 UNCONFIGURED 1 -> exit 1"'
check "symlinked .prom is skipped" 'ln -s "$TF/pft_one_local.prom" "$TF/pft_one_link.prom"; o="$("$TOOL" check --no-prom)"; rm -f "$TF/pft_one_link.prom"; ! grep -q pft_one_link <<<"$o"'

# ---------- exit 0 ----------
rm -rf "$TF"; mkdir -p "$TF"; mkprom pft_one_local.prom 30 pft_one_ts 30; mkprom pft_needed.prom 30 pft_generic_ts 30
fixture all-live
rc check
check "all LIVE + all FRESH -> exit 0" '[ "$RC" = 0 ] && has "^RESULT OK"'

# ---------- exit 2 ----------
fixture all-live http500; rc check
check "Prometheus HTTP 500 -> exit 2" '[ "$RC" = 2 ] && has "^ERROR /api/v1/rules"'
fixture all-live garbage; rc check
check "Prometheus answers non-JSON -> exit 2" '[ "$RC" = 2 ]'
fixture all-live rules_error; rc check
check "rules API error status -> exit 2 with its message" '[ "$RC" = 2 ] && has "rule manager not ready"'
fixture all-live query_error; rc check
check "query API error -> exit 2 (not DEAD)" '[ "$RC" = 2 ] && ! has "^DEAD"'
fixture all-live bad_sample; rc check
check "malformed sample -> exit 2" '[ "$RC" = 2 ] && has "malformed sample"'
fixture all-live
sed -i "s#^PROM_URL=.*#PROM_URL=http://127.0.0.1:1#" "$T/rc.env"; rc check
check "Prometheus unreachable -> exit 2" '[ "$RC" = 2 ]'
sed -i "s#^PROM_URL=.*#PROM_URL=http://127.0.0.1:$PORT#" "$T/rc.env"
cp "$T/rc.conf" "$T/rc.conf.good"; echo "textfile pft_x.prom soon" >> "$T/rc.conf"; rc check
check "bad duration in config -> exit 2 naming the line" '[ "$RC" = 2 ] && has "rc.conf:[0-9]+:"'
cp "$T/rc.conf.good" "$T/rc.conf"; echo "frobnicate yes" >> "$T/rc.conf"; rc check
check "unknown config directive -> exit 2" '[ "$RC" = 2 ]'
cp "$T/rc.conf.good" "$T/rc.conf"
sed -i "s#^TEXTFILE_DIR=.*#TEXTFILE_DIR=$T/nope#" "$T/rc.env"; rc check --no-prom
check "missing textfile dir -> exit 2" '[ "$RC" = 2 ] && has "textfile dir"'
sed -i "s#^TEXTFILE_DIR=.*#TEXTFILE_DIR=$TF#" "$T/rc.env"
echo 'EVIL=$(touch /tmp/x)' >> "$T/rc.env"; rc check
check "unknown env key -> exit 2, nothing evaluated" '[ "$RC" = 2 ] && has "unknown key EVIL"'
sed -i '/^EVIL=/d' "$T/rc.env"
echo 'HOST_LABEL=a b' >> "$T/rc.env"; rc check
check "bad HOST_LABEL -> exit 2" '[ "$RC" = 2 ]'
sed -i '$d' "$T/rc.env"
echo 'PROM_URL=file:///etc/passwd' >> "$T/rc.env"; rc check
check "non-http PROM_URL refused" '[ "$RC" = 2 ] && has "bad PROM_URL"'
sed -i '$d' "$T/rc.env"
rc check --frob
check "unknown check argument -> exit 2" '[ "$RC" = 2 ]'

# ---------- JSON ----------
reset_tf; fixture mixed
rc check --json
check "json: valid, exit 1, summary counts" '[ "$RC" = 1 ] && jq -e ".exit == 1 and .summary.rules.DEAD == 1 and .summary.rules.PARTIAL == 1 and .summary.textfiles.STALE == 3" <<<"$OUT"'
check "json: dead selector listed on the rule" 'jq -e "[.rules[] | select(.rule == \"PartialOne\")][0].dead == [\"pft_b\"]" <<<"$OUT"'
check "json: textfile row has age/max_age/source" 'jq -e "[.textfiles[] | select(.file == \"pft_pulled_peer.prom\")][0] | .state == \"STALE\" and .age == 900 and .max_age == 300 and .source == \"pft_pulled_ts\"" <<<"$OUT"'
fixture mixed http500; rc check --json
check "json: error run still one object with exit 2" '[ "$RC" = 2 ] && jq -e ".exit == 2 and (.error | test(\"HTTP 500\"))" <<<"$OUT"'

# ---------- run (metrics) ----------
fixture mixed; rc run
P="$TF/pft_rulecheck_validator.prom"
check "run: exit 1 with findings, metrics written" '[ "$RC" = 1 ] && [ -s "$P" ]'
check "metrics: up 1" 'grep -qx "pft_rulecheck_up{host=\"validator\"} 1" "$P"'
check "metrics: last run = PFT_RC_NOW" 'grep -qx "pft_rulecheck_last_run_timestamp_seconds{host=\"validator\"} $NOW" "$P"'
check "metrics: DEAD rule = 1 with state label" 'grep -qx "pft_rulecheck_rule_dead{host=\"validator\",group=\"g-bad\",rule=\"DeadOne\",idx=\"0\",state=\"DEAD\"} 1" "$P"'
check "metrics: PARTIAL and ERROR rules = 1" 'grep -q "rule=\"PartialOne\",idx=\"1\",state=\"PARTIAL\"} 1" "$P" && grep -q "rule=\"ParseFail\",idx=\"3\",state=\"ERROR\"} 1" "$P"'
check "metrics: LIVE and IGNORED rules = 0" 'grep -q "rule=\"LiveOne\",idx=\"0\",state=\"LIVE\"} 0" "$P" && grep -q "rule=\"Ignored\",idx=\"4\",state=\"IGNORED\"} 0" "$P"'
check "metrics: duplicate rule names keep distinct series (group/idx)" '[ "$(grep -c "rule=\"LiveOne\"" "$P")" = 2 ]'
check "metrics: escaped label value" 'grep -q "group=\"g-live\",rule=\"job:pft_x:rate5m\"" "$P"'
check "metrics: STALE textfile = 1" 'grep -qx "pft_rulecheck_textfile_stale{host=\"validator\",file=\"pft_pulled_peer.prom\",state=\"STALE\"} 1" "$P"'
check "metrics: FRESH textfile = 0" 'grep -qx "pft_rulecheck_textfile_stale{host=\"validator\",file=\"pft_one_local.prom\",state=\"FRESH\"} 0" "$P"'
check "metrics: LEFTOVER + MISSING = 1" 'grep -q "file=\".pull-peer.Ab12Cd\",state=\"LEFTOVER\"} 1" "$P" && grep -q "file=\"pft_needed.prom\",state=\"MISSING\"} 1" "$P"'
check "metrics: age series (content age for the pulled copy)" 'grep -qx "pft_rulecheck_textfile_age_seconds{host=\"validator\",file=\"pft_pulled_peer.prom\"} 900" "$P"'
check "metrics: rule state counts" 'grep -qx "pft_rulecheck_rules{host=\"validator\",state=\"DEAD\"} 1" "$P" && grep -qx "pft_rulecheck_rules{host=\"validator\",state=\"LIVE\"} 9" "$P"'
check "metrics: own file checked on the next run, no temp file left" 'rc run; grep -qE "^pft_rulecheck_textfile_stale\{host=\"validator\",file=\"pft_rulecheck_validator.prom\",state=\"[A-Z]+\"\} [01]$" "$P" && [ -z "$(find "$TF" -name ".rulecheck.*")" ]'
check "metrics: file mode 0644" '[ "$(stat -c %a "$P")" = 644 ]'
fixture mixed http500; rc run
check "run: Prometheus down -> exit 2, up 0, no rule/textfile series (not 'all fine')" '[ "$RC" = 2 ] && grep -qx "pft_rulecheck_up{host=\"validator\"} 0" "$P" && ! grep -q "^pft_rulecheck_rule_dead" "$P" && ! grep -q "^pft_rulecheck_textfile_stale" "$P"'
fixture mixed
sed -i "s#^TEXTFILE_DIR=.*#TEXTFILE_DIR=$T/nope#" "$T/rc.env"; rc run
check "run: textfile dir missing -> exit 2, nothing written" '[ "$RC" = 2 ] && [ ! -e "$T/nope" ]'
sed -i "s#^TEXTFILE_DIR=.*#TEXTFILE_DIR=$TF#" "$T/rc.env"
chmod 300 "$TF"; rc run; chmod 755 "$TF"
check "run: Prometheus fine but textfile dir unreadable -> exit 2, up 0, no rule series either" '[ "$RC" = 2 ] && grep -qx "pft_rulecheck_up{host=\"validator\"} 0" "$P" && ! grep -q "^pft_rulecheck_rule_dead" "$P"'
check "metrics: promtool-style parse (every sample line well formed)" 'rc run; ! grep -vE "^(# (HELP|TYPE) .*|pft_rulecheck_[a-z_]+\{host=\"validator\"[^}]*\} -?[0-9.]+)$" "$P"'

# ---------- validate + pull ----------
cp "$P" "$T/v.prom"
rc validate "$T/v.prom" validator
check "validate: own run output accepted" '[ "$RC" = 0 ]'
rc validate "$T/v.prom" sentry
check "validate: wrong host refused" '[ "$RC" = 2 ] && has "host is not sentry"'
printf 'pft_rulecheck_up{host="sentry"} 1\nnode_evil{host="sentry"} 1\npft_rulecheck_last_run_timestamp_seconds{host="sentry"} 1\n' > "$T/e.prom"; rc validate "$T/e.prom" sentry
check "validate: foreign metric refused" '[ "$RC" = 2 ] && has "line 2"'
printf 'pft_rulecheck_up{host="sentry"} 1\n' > "$T/n.prom"; rc validate "$T/n.prom" sentry
check "validate: missing last_run refused" '[ "$RC" = 2 ] && has "no pft_rulecheck_last_run"'
: > "$T/z.prom"; rc validate "$T/z.prom" sentry
check "validate: empty refused" '[ "$RC" = 2 ] && has empty'
head -c 300000 /dev/zero | tr '\0' '#' > "$T/big.prom"; rc validate "$T/big.prom" sentry
check "validate: > 256 KiB refused" '[ "$RC" = 2 ] && has "too large"'
# pull through a stub "ssh" (a script that cats from a fake remote dir)
RD="$T/remote"; mkdir -p "$RD"
sed "s/host=\"validator\"/host=\"sentry\"/" "$P" > "$RD/pft_rulecheck_sentry.prom"
printf '#!/usr/bin/env bash\n[ -e "%s/down" ] && exit 255\n[ -e "%s/hang" ] && sleep 30\nshift; exec "$@"\n' "$T" "$T" > "$T/fakessh"; chmod +x "$T/fakessh"
{ echo "PEER_LABEL=sentry"; echo "REMOTE_DIR=$RD"; echo "PULL_SSH=\"$T/fakessh relay\""; echo "PULL_TIMEOUT=3"; } >> "$T/rc.env"
rm -f "$TF/pft_rulecheck_sentry.prom"; rc pull
check "pull: ok -> exit 0, copy identical, mode 0644" '[ "$RC" = 0 ] && cmp -s "$RD/pft_rulecheck_sentry.prom" "$TF/pft_rulecheck_sentry.prom" && [ "$(stat -c %a "$TF/pft_rulecheck_sentry.prom")" = 644 ]'
cp "$TF/pft_rulecheck_sentry.prom" "$T/good-copy"
touch "$T/down"; rc pull; rm -f "$T/down"
check "pull: ssh fails -> exit 1, old copy kept, no temp left" '[ "$RC" = 1 ] && cmp -s "$T/good-copy" "$TF/pft_rulecheck_sentry.prom" && [ -z "$(find "$TF" -name ".pull-rulecheck-*")" ]'
cp "$RD/pft_rulecheck_sentry.prom" "$T/remote-good"; echo 'node_evil{host="sentry"} 1' >> "$RD/pft_rulecheck_sentry.prom"; rc pull
check "pull: invalid remote file -> exit 2, old copy kept, no temp left" '[ "$RC" = 2 ] && cmp -s "$T/good-copy" "$TF/pft_rulecheck_sentry.prom" && [ -z "$(find "$TF" -name ".pull-rulecheck-*")" ]'
cp "$T/remote-good" "$RD/pft_rulecheck_sentry.prom"
touch "$T/hang"; s=$(date +%s); rc pull; e=$(( $(date +%s) - s )); rm -f "$T/hang"
check "pull: hanging ssh stopped by PULL_TIMEOUT (exit 1 within 10s)" '[ "$RC" = 1 ] && [ "$e" -lt 10 ]'
rc pull extra
check "pull: arguments refused" '[ "$RC" = 2 ]'
sed -i '/^PULL_SSH=/d' "$T/rc.env"; rc pull
check "pull: PULL_SSH unset -> exit 2" '[ "$RC" = 2 ] && has "PULL_SSH not set"'

# ---------- misc ----------
rc version
check "version" '[ "$RC" = 0 ] && has "^pft-rulecheck [0-9]+\.[0-9]+\.[0-9]+$"'
rc frob
check "unknown command -> exit 2" '[ "$RC" = 2 ]'

echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
