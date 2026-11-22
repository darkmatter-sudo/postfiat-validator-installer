#!/usr/bin/env bash
# Public report bundle of one host (task_76248c8a4b04f05417f1bd7088735a54), written as a tar stream on stdout.
# Runs a read-only `pft-imagescan scan --no-fetch` with a scratch textfile dir and bundle (live metrics, cache and
# feeds are not touched; inventories come from the per-image-ID cache), then keeps only what may be published:
#   inv/*.json        every inventory except images whose ref matches WITHHOLD_REF (unremediated upstream image)
#   containers.json, now, feeds/feeds.json, feeds/<file>.xz (xz copies of the pinned feed files, sha256 in feeds.json)
#   withheld.json     counts + findings_sha256 of the withheld images (imagescan_lib.py withhold), no findings
#   before.json       optional: BEFORE_SCAN reduced to the refs in BEFORE_REFS (found -> fixed -> verified input)
# Never the accept file: it names the withheld findings. The full report stays on the host (stderr gets a summary).
#   bash public-bundle.sh > bundle.tar          (as the agent user, sudo -n for the scan)
#   ssh host 'bash -s' < public-bundle.sh > bundle.tar
set -euo pipefail
WITHHOLD_REF="${WITHHOLD_REF:-^agtipft/postfiatd:}"
BEFORE_SCAN="${BEFORE_SCAN:-}"; BEFORE_REFS="${BEFORE_REFS:-pft-exporter:latest}"
LIB=/usr/local/lib/pft-imagescan/imagescan_lib.py
CACHE=/var/cache/pft-imagescan
w="$(mktemp -d -p "$HOME/.cache")"
trap 'sudo -n rm -rf "$w"' EXIT
chmod 700 "$w"
rc=0
# shellcheck disable=SC2024  # the scratch report and scan copy belong to the agent user on purpose
sudo -n pft-imagescan scan --no-fetch --textfile-dir "$w/tf" --bundle "$w/b" > "$w/report.txt" 2>&1 || rc=$?
[ "$rc" -le 1 ] || { echo "scan failed (exit $rc): $(tail -3 "$w/report.txt")" >&2; exit 2; }
grep -E '^(pft-imagescan scan|IMAGE |  findings_sha256 |RESULT)' "$w/report.txt" | cut -c1-160 >&2 || true
sudo -n chown -R "$(id -u):$(id -g)" "$w/b"
# shellcheck disable=SC2024
sudo -n cat "$CACHE/last-scan.json" > "$w/scan.json"
p="$w/pub"; mkdir -p "$p/inv" "$p/feeds"
python3 -I "$LIB" withhold --scan "$w/scan.json" --ref "$WITHHOLD_REF" > "$p/withheld.json"
kept=0; held=0
for f in "$w"/b/inv/*.json; do
  if python3 -I -c 'import json, re, sys; sys.exit(0 if re.search(sys.argv[2], json.load(open(sys.argv[1]))["ref"]) else 1)' \
    "$f" "$WITHHOLD_REF"; then held=$((held + 1)); else cp "$f" "$p/inv/"; kept=$((kept + 1)); fi
done
cp "$w/b/containers.json" "$w/b/now" "$p/"
cp "$w/b/feeds/feeds.json" "$p/feeds/"
for file in $(python3 -I -c 'import json, sys; [print(v["file"]) for v in json.load(open(sys.argv[1])).values()]' \
  "$p/feeds/feeds.json"); do
  sudo -n cat "$CACHE/feeds/$file" | xz -T1 -6 -c > "$p/feeds/$file.xz"
done
if [ -n "$BEFORE_SCAN" ]; then
  python3 -I -c 'import json, sys
s = json.load(open(sys.argv[1])); refs = set(sys.argv[2].split(","))
s["images"] = [i for i in s["images"] if i["ref"] in refs]
json.dump(s, sys.stdout, sort_keys=True, indent=1); print()' "$BEFORE_SCAN" "$BEFORE_REFS" > "$p/before.json"
fi
xzs=("$p"/feeds/*.xz)
echo "public bundle: $kept inventories kept, $held withheld ($WITHHOLD_REF), ${#xzs[@]} feed copies, before=$([ -n "$BEFORE_SCAN" ] && echo yes || echo no)" >&2
tar -C "$p" --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -cf - .
