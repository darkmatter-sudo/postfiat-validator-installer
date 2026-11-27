#!/usr/bin/env bash
# check-guide: static checks of the DOCKER-USER persistence change in a postfiatorg.github.io checkout.
#   bash check-guide.sh GUIDE_REPO BASE_SHA HEAD_SHA OUTDIR
# 1 the diff BASE..HEAD touches exactly the three guide copies
# 2 the section extracted from each copy at HEAD is byte-identical (cmp + sha256)
# 3 shellcheck: install block (bash), postfiat-docker-user.sh (sh), check block (bash) and its body (sh)
# 4 systemd-analyze verify of the extracted unit (run with sudo on the target host)
# Exit 0 = every step PASS.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ $# = 4 ] || { echo "usage: bash $0 GUIDE_REPO BASE_SHA HEAD_SHA OUTDIR" >&2; exit 2; }
G="$1"; BASE="$2"; HEADSHA="$3"; OUT="$4"
FILES=(content/validator-setup.md static/agents/validator-setup.md static/agents/validator-setup.txt)
FAILS=0
step() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi; }
mkdir -p "$OUT"

echo "== 1 changed files $BASE..$HEADSHA"
changed="$(git -C "$G" diff --name-status "$BASE" "$HEADSHA")"; echo "$changed"
want="$(printf 'M\t%s\n' "${FILES[@]}" | sort)"
[ "$(sort <<<"$changed")" = "$want" ]; step "diff touches exactly the 3 guide copies" $?
git -C "$G" diff --stat "$BASE" "$HEADSHA"

echo "== 2 extracted sections at $HEADSHA"
i=0
for f in "${FILES[@]}"; do
  i=$((i + 1)); d="$OUT/copy$i"; mkdir -p "$d"
  git -C "$G" show "$HEADSHA:$f" > "$d/guide"
  echo "-- $f"; python3 -I "$HERE/extract_dockeruser.py" "$d/guide" "$d"; rc=$?
  step "extract $f" "$rc"
  for p in section.txt install.sh postfiat-docker-user.sh postfiat-docker-user.service check.sh; do
    [ -f "$d/$p" ] && echo "sha256 $(sha256sum "$d/$p" | cut -c1-64) copy$i/$p"
  done
done
for p in section.txt install.sh postfiat-docker-user.sh postfiat-docker-user.service check.sh; do
  cmp "$OUT/copy1/$p" "$OUT/copy2/$p" && cmp "$OUT/copy1/$p" "$OUT/copy3/$p"; step "$p identical in all 3 copies" $?
done

echo "== 3 shellcheck ($(shellcheck --version | sed -n 's/^version: //p'))"
X="$OUT/copy1"
sed -e '1d' -e '$d' "$X/check.sh" > "$X/check-body.sh"
shellcheck -s bash "$X/install.sh"; step "shellcheck -s bash install block" $?
shellcheck -s sh "$X/postfiat-docker-user.sh"; step "shellcheck -s sh postfiat-docker-user.sh" $?
shellcheck -s bash "$X/check.sh"; step "shellcheck -s bash check block" $?
shellcheck -s sh "$X/check-body.sh"; step "shellcheck -s sh check body" $?

echo "== 4 systemd-analyze verify ($(systemd-analyze --version | head -1))"
U="$OUT/unit"; mkdir -p "$U"; cp "$X/postfiat-docker-user.service" "$U/"
va="$(systemd-analyze verify "$U/postfiat-docker-user.service" 2>&1)"; rc=$?
echo "systemd-analyze verify rc=$rc"
if [ -n "$va" ]; then while IFS= read -r l; do echo "  output: $l"; done <<<"$va"; fi
# verify also loads the host's other units (docker.service deps); only lines naming this unit count
own="$(grep -c 'postfiat-docker-user' <<<"$va")"
echo "lines naming postfiat-docker-user: $own (other lines are about unrelated host units)"
[ "$rc" = 0 ] && [ "$own" = 0 ]; step "systemd-analyze verify: rc 0, no finding for postfiat-docker-user.service" $?

echo "RESULT: $FAILS failed"
[ "$FAILS" = 0 ]
