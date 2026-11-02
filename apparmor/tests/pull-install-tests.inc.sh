# Sourced by run-tests.sh (uses its fresh/run/ok/ko, $E, $T, $TOOL). validate + pull (validator copy of the sentry's
# textfile) and install.sh against a fake root: stub systemctl runs the INSTALLED tool for `start <unit>`, the way
# the real oneshot units do (audit exit 1 = findings is a success, SuccessExitStatus=1).
# shellcheck shell=bash disable=SC2016,SC2015
# PFT_AA_INSTALL: mutate.py points it at a mutated copy; install.sh always installs $TOOL (PFT_AA_SRC)
INST="${PFT_AA_INSTALL:-$HERE/../install.sh}"

# ---- validate --------------------------------------------------------------------------------------------
fresh; printf 'HOST_LABEL=sentry\n' > "$E/root/etc/pft-apparmor.env"
run audit --textfile; TF="$E/root/textfile/pft_apparmor_sentry.prom"
[ "$RC" = 0 ] && [ -f "$TF" ] && grep -q '^pft_apparmor_check{host="sentry",check="confine:cap_drop",status="PASS"} 1$' "$TF" \
  && ok "textfile: pft_apparmor_<HOST_LABEL>.prom, label from the env file" || ko "textfile sentry: rc=$RC" "$OUT"
run validate "$TF" sentry; [ "$RC" = 0 ] && ok "validate: own sentry textfile accepted (check labels with ':')" || ko "validate own: rc=$RC" "$OUT"
run validate "$TF" validator
[ "$RC" = 2 ] && grep -q 'unexpected lines' <<<"$OUT" && ok "validate: wrong host label rejected" || ko "validate host: rc=$RC" "$OUT"
cp "$TF" "$T/bad.prom"; echo 'node_load1 9' >> "$T/bad.prom"; run validate "$T/bad.prom" sentry
[ "$RC" = 2 ] && grep -q '^1 unexpected lines$' <<<"$OUT" && ok "validate: foreign metric rejected" || ko "validate foreign: rc=$RC" "$OUT"
cp "$TF" "$T/bad.prom"; echo 'pft_apparmor_findings{host="sentry"} 0 # x' >> "$T/bad.prom"; run validate "$T/bad.prom" sentry
[ "$RC" = 2 ] && grep -q 'unexpected lines' <<<"$OUT" && ok "validate: trailing junk on an own metric rejected" || ko "validate junk: rc=$RC" "$OUT"
grep -v last_run "$TF" > "$T/bad.prom"; run validate "$T/bad.prom" sentry
[ "$RC" = 2 ] && grep -q 'no last_run' <<<"$OUT" && ok "validate: missing last_run rejected" || ko "validate last_run: rc=$RC" "$OUT"
{ cat "$TF"; for _ in $(seq 1 1200); do echo '# HELP pft_apparmor_pad padding padding padding padding'; done; } > "$T/bad.prom"
run validate "$T/bad.prom" sentry
[ "$RC" = 2 ] && grep -q 'larger than 65536' <<<"$OUT" && ok "validate: file over 64 KiB rejected" || ko "validate size: rc=$RC" "$OUT"
run validate "$T/nope.prom" sentry; [ "$RC" = 2 ] && grep -q '^missing$' <<<"$OUT" && ok "validate: missing file rejected" || ko "validate missing: rc=$RC" "$OUT"
run validate "$TF" 'Bad!'; [ "$RC" = 3 ] && ok "validate: bad host label is a usage error" || ko "validate label: rc=$RC" "$OUT"
run validate "$TF"; [ "$RC" = 3 ] && ok "validate: one argument is a usage error" || ko "validate 1 arg: rc=$RC" "$OUT"
run validate "$TF" sentry extra; [ "$RC" = 3 ] && grep -q 'too many arguments' <<<"$OUT" && ok "cli: a third positional argument is refused" || ko "3 args: rc=$RC" "$OUT"
ARG=/etc/passwd ARG2=x run check; [ "$RC" = 3 ] && ok "cli: ARG/ARG2 from the environment are ignored" || ko "env ARG: rc=$RC" "$OUT"

# ---- pull ------------------------------------------------------------------------------------------------
# fake ssh: records its arguments, then prints $E/s/peer.prom (or fails / hangs, from $E/state/ssh_mode)
pull_env() {
  cp "$TF" "$E/s/peer.prom"
  cat > "$E/s/fakessh" <<STUB
#!/usr/bin/env bash
echo "\$*" > "$E/state/ssh_args"
case "\$(cat "$E/state/ssh_mode" 2>/dev/null)" in
  fail) exit 255 ;;
  hang) sleep 30 ;;
esac
cat "$E/s/peer.prom"
STUB
  chmod +x "$E/s/fakessh"
  printf 'HOST_LABEL=validator\nPULL_SSH="%s -o BatchMode=yes peer"\n' "$E/s/fakessh" > "$E/root/etc/pft-apparmor.env"
}
pull_env; PD="$E/root/textfile"; rm -f "$PD/pft_apparmor_sentry.prom"
run pull
[ "$RC" = 0 ] && cmp -s "$E/s/peer.prom" "$PD/pft_apparmor_sentry.prom" && [ "$(stat -c %a "$PD/pft_apparmor_sentry.prom")" = 644 ] \
  && ok "pull: peer textfile copied (0644)" || ko "pull: rc=$RC" "$OUT"
[ "$(cat "$E/state/ssh_args")" = "-o BatchMode=yes peer cat -- /var/lib/pft-exporter/textfile/pft_apparmor_sentry.prom" ] \
  && ok "pull: PULL_SSH word-split, peer path for PEER_LABEL sentry" || ko "pull args" "$(cat "$E/state/ssh_args")"
cp "$PD/pft_apparmor_sentry.prom" "$T/good.prom"; echo 'evil 1' >> "$E/s/peer.prom"; run pull
[ "$RC" = 2 ] && grep -q 'pulled file rejected: 1 unexpected lines' <<<"$OUT" && cmp -s "$T/good.prom" "$PD/pft_apparmor_sentry.prom" \
  && [ -z "$(find "$PD" -name '.*pull')" ] && ok "pull: tampered file rejected, last good copy kept, no temp left" || ko "pull tampered: rc=$RC" "$OUT"
sed -i 's/host="sentry"/host="validator"/' "$E/s/peer.prom"; sed -i '/^evil/d' "$E/s/peer.prom"; run pull
[ "$RC" = 2 ] && cmp -s "$T/good.prom" "$PD/pft_apparmor_sentry.prom" && ok "pull: a file labelled for another host is rejected" || ko "pull label: rc=$RC" "$OUT"
echo fail > "$E/state/ssh_mode"; run pull
[ "$RC" = 1 ] && grep -q 'pull from sentry failed' <<<"$OUT" && cmp -s "$T/good.prom" "$PD/pft_apparmor_sentry.prom" \
  && [ -z "$(find "$PD" -name '.*pull')" ] && ok "pull: ssh failure exit 1, last good copy kept, no temp left" || ko "pull fail: rc=$RC" "$OUT"
echo hang > "$E/state/ssh_mode"; t0=$(date +%s); PULL_TIMEOUT=2 run pull; el=$(( $(date +%s) - t0 ))
[ "$RC" = 1 ] && [ "$el" -lt 10 ] && cmp -s "$T/good.prom" "$PD/pft_apparmor_sentry.prom" \
  && ok "pull: a hanging ssh is cut at PULL_TIMEOUT (${el}s), last good copy kept" || ko "pull hang: rc=$RC el=${el}s" "$OUT"
printf 'HOST_LABEL=validator\n' > "$E/root/etc/pft-apparmor.env"; run pull
[ "$RC" = 2 ] && grep -q 'PULL_SSH not set' <<<"$OUT" && ok "pull: refuses without PULL_SSH" || ko "pull no ssh: rc=$RC" "$OUT"
printf 'PEER_LABEL=Bad!\nPULL_SSH=x\n' > "$E/root/etc/pft-apparmor.env"; run pull
[ "$RC" = 2 ] && grep -q 'bad PEER_LABEL' <<<"$OUT" && ok "pull: refuses a bad PEER_LABEL" || ko "pull label: rc=$RC" "$OUT"
if [ "$(id -u)" != 0 ]; then
  OUT="$(env -u PFT_AA_ROOT bash "$TOOL" pull 2>&1)"; RC=$?
  [ "$RC" = 4 ] && grep -q 'pull needs root' <<<"$OUT" && ok "pull: needs root on a real host" || ko "pull root: rc=$RC" "$OUT"
fi

# ---- install.sh ------------------------------------------------------------------------------------------
# fake root P=$E/root; stub systemctl: `start X.service` runs the installed tool like the unit; is-failed reads state
inst_env() {
  fresh
  export PFT_AA_SRC="$TOOL" PFT_AA_UNITSRC="$HERE/../systemd" TEXTFILE_DIR="$E/root/var/lib/pft-exporter/textfile" STATE_DIR="$E/root/var/lib/pft-apparmor" PFT_AA_JOURNALCTL=true
  mkdir -p "$E/root/etc" "$STATE_DIR"
  cat > "$E/s/isystemctl" <<STUB
#!/usr/bin/env bash
echo "systemctl \$*" >> "$E/state/calls"
B="$E/root/usr/local/bin/pft-apparmor"
case "\$1" in
  start)
    rm -f "$E/state/failed_\$2"
    case "\$2" in
      pft-apparmor.service) [ -f "$E/state/audit_fail" ] && rc=2 || { bash "\$B" audit --textfile >/dev/null 2>&1; rc=\$?; }
        [ -f "$E/state/garbage" ] && echo 'evil 1' >> "$TEXTFILE_DIR/pft_apparmor_\$(sed -n 's/^HOST_LABEL=//p' "$E/root/etc/pft-apparmor.env").prom"
        [ "\$rc" -le 1 ] || { touch "$E/state/failed_\$2"; exit 1; } ;;
      pft-apparmor-pull.service) bash "\$B" pull >/dev/null 2>&1 || { touch "$E/state/failed_\$2"; exit 1; } ;;
    esac ;;
  is-failed) [ -f "$E/state/failed_\$3" ] ;;
  is-enabled) [ "\$2" = apparmor.service ] && { echo enabled; exit 0; }; exit 1 ;;
  *) exit 0 ;;
esac
STUB
  chmod +x "$E/s/isystemctl"
  export PFT_AA_SYSTEMCTL="$E/s/isystemctl"
}
irun() { OUT="$(bash "$INST" "$@" 2>&1)"; RC=$?; }
calls() { grep -c -- "$1" "$E/state/calls" 2>/dev/null || true; }

inst_env; printf '# rulecheck\n' > "$E/root/etc/pft-rulecheck.conf"; irun
[ "$RC" = 0 ] && cmp -s "$TOOL" "$E/root/usr/local/bin/pft-apparmor" && [ "$(stat -c %a "$E/root/usr/local/bin/pft-apparmor")" = 755 ] \
  && ok "install: exit 0, tool installed 0755" || ko "install: rc=$RC" "$OUT"
grep -qx 'HOST_LABEL=validator' "$E/root/etc/pft-apparmor.env" && [ "$(stat -c %a "$E/root/etc/pft-apparmor.env")" = 600 ] \
  && ok "install: env file HOST_LABEL=validator, 0600" || ko "install env" "$(cat "$E/root/etc/pft-apparmor.env")"
[ -f "$E/root/etc/systemd/system/pft-apparmor.service" ] && [ -f "$E/root/etc/systemd/system/pft-apparmor.timer" ] \
  && ok "install: units installed" || ko "install units" "$(ls -R "$E/root/etc/systemd" 2>&1)"
[ "$(calls 'start pft-apparmor.service')" = 1 ] && [ "$(calls 'enable --now pft-apparmor.timer')" = 1 ] && grep -q '^pft_apparmor_findings{host="validator"} 0$' <<<"$OUT" \
  && ok "install: first audit through the unit, textfile valid, timer enabled" || ko "install calls" "$OUT
$(cat "$E/state/calls")"
[ "$(grep -c 'pft_apparmor_' "$E/root/etc/pft-rulecheck.conf")" = 1 ] && ok "install: rulecheck textfile line added" || ko "rulecheck line" "$(cat "$E/root/etc/pft-rulecheck.conf")"
irun; [ "$RC" = 0 ] && [ "$(grep -c 'pft_apparmor_' "$E/root/etc/pft-rulecheck.conf")" = 1 ] && [ "$(grep -c '^HOST_LABEL=' "$E/root/etc/pft-apparmor.env")" = 1 ] \
  && ok "install: idempotent (one rulecheck line, one HOST_LABEL)" || ko "install twice: rc=$RC" "$OUT"

inst_env; irun --host sentry
[ "$RC" = 0 ] && grep -qx 'HOST_LABEL=sentry' "$E/root/etc/pft-apparmor.env" && [ -f "$TEXTFILE_DIR/pft_apparmor_sentry.prom" ] \
  && [ ! -e "$E/root/etc/pft-rulecheck.conf" ] && ok "install --host sentry: label + sentry textfile; no rulecheck conf created" || ko "install sentry: rc=$RC" "$OUT"
inst_env; irun --host 'Bad!'; [ "$RC" = 3 ] && [ ! -e "$E/root/usr/local/bin/pft-apparmor" ] && ok "install: bad label refused before any change" || ko "install bad label: rc=$RC" "$OUT"
inst_env; irun --bogus; [ "$RC" = 3 ] && ok "install: unknown argument refused" || ko "install bogus: rc=$RC" "$OUT"
inst_env; touch "$E/state/audit_fail"; irun
[ "$RC" = 1 ] && grep -q 'first audit failed' <<<"$OUT" && [ "$(calls 'enable --now')" = 0 ] \
  && ok "install: failed first audit -> exit 1, timer NOT enabled" || ko "install audit fail: rc=$RC" "$OUT"
inst_env; touch "$E/state/garbage"; irun
[ "$RC" = 1 ] && grep -q 'textfile rejected' <<<"$OUT" && [ "$(calls 'enable --now')" = 0 ] \
  && ok "install: textfile that fails validate -> exit 1, timer NOT enabled" || ko "install garbage: rc=$RC" "$OUT"

# --pull
inst_env; irun --pull
[ "$RC" = 3 ] && grep -q 'without PULL_SSH' <<<"$OUT" && [ ! -e "$E/root/usr/local/bin/pft-apparmor" ] \
  && ok "install --pull: refuses without an env file, nothing installed" || ko "install pull no env: rc=$RC" "$OUT"
inst_env; printf 'HOST_LABEL=validator\n' > "$E/root/etc/pft-apparmor.env"; irun --pull
[ "$RC" = 3 ] && grep -q 'without PULL_SSH' <<<"$OUT" && [ ! -e "$E/root/usr/local/bin/pft-apparmor" ] \
  && ok "install --pull: refuses an env file without PULL_SSH, nothing installed" || ko "install pull no ssh: rc=$RC" "$OUT"
inst_env; printf 'HOST_LABEL=sentry\n' > "$E/root/etc/pft-apparmor.env"; bash "$TOOL" audit --prom "$T/peer-src.prom" >/dev/null 2>&1
TF="$T/peer-src.prom"; pull_env; chmod 644 "$E/root/etc/pft-apparmor.env"; irun --pull
[ "$RC" = 0 ] && cmp -s "$E/s/peer.prom" "$TEXTFILE_DIR/pft_apparmor_sentry.prom" && [ "$(calls 'enable --now pft-apparmor-pull.timer')" = 1 ] \
  && [ "$(stat -c %a "$E/root/etc/pft-apparmor.env")" = 600 ] && [ -f "$E/root/etc/systemd/system/pft-apparmor-pull.timer" ] \
  && ok "install --pull: first pull copied the peer file, env 0600, pull timer enabled" || ko "install pull: rc=$RC" "$OUT"
echo fail > "$E/state/ssh_mode"; rm -f "$E/state/calls"; irun --pull
[ "$RC" = 1 ] && grep -q 'first pull failed' <<<"$OUT" && [ "$(calls 'enable --now')" = 0 ] \
  && ok "install --pull: failed first pull -> exit 1, timer NOT enabled" || ko "install pull fail: rc=$RC" "$OUT"
irun --pull --uninstall
[ "$RC" = 0 ] && [ ! -e "$TEXTFILE_DIR/pft_apparmor_sentry.prom" ] && [ "$(calls 'disable --now pft-apparmor-pull.timer')" = 1 ] \
  && ok "install --pull --uninstall: pull timer disabled, pulled file removed" || ko "pull uninstall: rc=$RC" "$OUT"

# --uninstall refuses while an apply is in place
inst_env; irun; echo '{"id":"a1","container":"postfiatd"}' > "$STATE_DIR/apply-postfiatd.json"; irun --uninstall
[ "$RC" = 3 ] && grep -q 'apply is in place' <<<"$OUT" && [ -f "$TEXTFILE_DIR/pft_apparmor_validator.prom" ] && [ "$(calls 'disable --now')" = 0 ] \
  && ok "uninstall: refused while an apply is in place, nothing removed" || ko "uninstall applied: rc=$RC" "$OUT"
echo '{"id":"a1","container":"postfiatd","rolled_back":true}' > "$STATE_DIR/apply-postfiatd.json"; irun --uninstall
[ "$RC" = 0 ] && [ ! -e "$TEXTFILE_DIR/pft_apparmor_validator.prom" ] && [ "$(calls 'disable --now pft-apparmor.timer')" = 1 ] \
  && ok "uninstall: after rollback, timer disabled and textfile removed" || ko "uninstall: rc=$RC" "$OUT"
unset STATE_DIR PFT_AA_JOURNALCTL PFT_AA_SRC PFT_AA_UNITSRC
