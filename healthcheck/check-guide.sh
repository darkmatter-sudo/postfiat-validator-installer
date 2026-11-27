#!/usr/bin/env bash
# check-guide: static checks of the continuous health check subsection in a postfiatorg.github.io checkout.
#   sudo bash check-guide.sh GUIDE_REPO BASE_SHA HEAD_SHA OUTDIR
# 1 the diff BASE..HEAD touches exactly the three guide copies
# 2 every part extracted from each copy at HEAD is byte-identical in all 3 copies (cmp + sha256)
# 3 shellcheck: install, visibility and uninstall blocks (bash) and postfiat-healthcheck (sh)
# 4 systemd-analyze verify of the extracted service + timer, inside a private mount namespace where the extracted
#   script is bind-mounted over /usr/local/bin (verify checks that ExecStart exists; nothing on the host changes)
# Exit 0 = every step PASS. OUTDIR must be on an exec-capable filesystem (not a noexec /tmp).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ $# = 4 ] || { echo "usage: sudo bash $0 GUIDE_REPO BASE_SHA HEAD_SHA OUTDIR" >&2; exit 2; }
G="$1"; BASE="$2"; HEADSHA="$3"; OUT="$4"
FILES=(content/validator-setup.md static/agents/validator-setup.md static/agents/validator-setup.txt)
PARTS=(section.txt install.sh postfiat-healthcheck postfiat-healthcheck.service postfiat-healthcheck.timer
  visibility.sh alert.conf uninstall.sh)
FAILS=0
step() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"

echo "== 1 changed files $BASE..$HEADSHA"
changed="$(git -C "$G" diff --name-status "$BASE" "$HEADSHA")"; echo "$changed"
want="$(printf 'M\t%s\n' "${FILES[@]}" | sort)"
[ "$(sort <<<"$changed")" = "$want" ]; step "diff touches exactly the 3 guide copies" $?
git -C "$G" diff --stat "$BASE" "$HEADSHA"

echo "== 2 extracted subsection at $HEADSHA"
i=0
for f in "${FILES[@]}"; do
  i=$((i + 1)); d="$OUT/copy$i"; mkdir -p "$d"
  git -C "$G" show "$HEADSHA:$f" > "$d/guide"
  echo "-- $f"; python3 -I "$HERE/extract_healthcheck.py" "$d/guide" "$d"; rc=$?
  step "extract $f" "$rc"
  for p in "${PARTS[@]}"; do
    [ -f "$d/$p" ] && echo "sha256 $(sha256sum "$d/$p" | cut -c1-64) copy$i/$p"
  done
done
for p in "${PARTS[@]}"; do
  cmp "$OUT/copy1/$p" "$OUT/copy2/$p" && cmp "$OUT/copy1/$p" "$OUT/copy3/$p"; step "$p identical in all 3 copies" $?
done
echo "-- diff of the subsection between copies (empty = identical)"
diff "$OUT/copy1/section.txt" "$OUT/copy2/section.txt"; diff "$OUT/copy1/section.txt" "$OUT/copy3/section.txt"

echo "== 3 shellcheck ($(shellcheck --version | sed -n 's/^version: //p'))"
X="$OUT/copy1"
shellcheck -s bash "$X/install.sh"; step "shellcheck -s bash install block" $?
shellcheck -s sh "$X/postfiat-healthcheck"; step "shellcheck -s sh postfiat-healthcheck" $?
shellcheck -s bash "$X/visibility.sh"; step "shellcheck -s bash visibility block" $?
shellcheck -s bash "$X/uninstall.sh"; step "shellcheck -s bash uninstall block" $?

echo "== 4 systemd-analyze verify ($(systemd-analyze --version | head -1))"
U="$OUT/unit"; B="$OUT/bin"; mkdir -p "$U" "$B"
cp "$X/postfiat-healthcheck.service" "$X/postfiat-healthcheck.timer" "$U/"
install -m 0755 "$X/postfiat-healthcheck" "$B/postfiat-healthcheck"
# shellcheck disable=SC2016  # $1/$2 expand in the inner sh
va="$(unshare -m --propagation private sh -c 'mount --bind "$1" /usr/local/bin && systemd-analyze verify "$2/postfiat-healthcheck.timer" "$2/postfiat-healthcheck.service"' sh "$B" "$U" 2>&1)"; rc=$?
echo "systemd-analyze verify rc=$rc"
if [ -n "$va" ]; then while IFS= read -r l; do echo "  output: $l"; done <<<"$va"; fi
# verify also loads unrelated host units; only lines naming the two new units count
own="$(grep -c 'postfiat-healthcheck' <<<"$va")"
echo "lines naming postfiat-healthcheck: $own (other lines are about unrelated host units)"
[ "$rc" = 0 ] && [ "$own" = 0 ]; step "systemd-analyze verify: rc 0, no finding for the service or the timer" $?
! [ -e /usr/local/bin/postfiat-healthcheck ]; step "host /usr/local/bin unchanged (no postfiat-healthcheck outside the namespace)" $?

# hand OUTDIR back to the invoking user so the unprivileged tests can use it
if [ -n "${SUDO_USER:-}" ]; then chown -R "$SUDO_USER:" "$OUT"; fi
echo "RESULT: $FAILS failed"
[ "$FAILS" = 0 ]
