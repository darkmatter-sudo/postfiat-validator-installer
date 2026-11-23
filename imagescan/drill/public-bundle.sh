#!/usr/bin/env bash
# Public report bundle of one host (task_76248c8a4b04f05417f1bd7088735a54), written as a tar stream on stdout.
# Runs a read-only `pft-imagescan scan --no-fetch` with a scratch textfile dir and bundle (live metrics, cache and
# feeds are not touched; inventories come from the per-image-ID cache), then keeps only what may be published:
#   inv/*.json        every inventory except images whose ref matches WITHHOLD_REF (in-use upstream images with open
#                     fixable advisories this task does not remediate: postfiatd, Prometheus, Alertmanager),
#                     provenance.created in UTC
#   containers.json, now, feeds/feeds.json, feeds/<file>.xz (xz copies of the pinned feed files, sha256 in feeds.json)
#   withheld.json     counts + findings_sha256 of the withheld images (imagescan_lib.py withhold), no findings
#   before.json       optional: BEFORE_SCAN reduced to the refs in BEFORE_REFS and to the findings gone from this
#                     scan (found -> fixed -> verified input; still-open advisories are never published)
# Never the accept file: it names the withheld findings. The full report stays on the host (stderr gets a summary).
#   bash public-bundle.sh > bundle.tar          (as the agent user, sudo -n for the scan)
#   ssh host 'bash -s' < public-bundle.sh > bundle.tar
set -euo pipefail
WITHHOLD_REF="${WITHHOLD_REF:-^(agtipft/postfiatd|prom/prometheus|prom/alertmanager):}"
BEFORE_SCAN="${BEFORE_SCAN:-}"; BEFORE_REFS="${BEFORE_REFS:-pft-exporter:latest}"
LIB=/usr/local/lib/pft-imagescan/imagescan_lib.py
CACHE=/var/cache/pft-imagescan
w="$(mktemp -d -p "$HOME/.cache")"
trap 'sudo -n rm -rf "$w"' EXIT
chmod 700 "$w"; mkdir "$w/tf"
rc=0
# shellcheck disable=SC2024  # the scratch report and scan copy belong to the agent user on purpose
sudo -n pft-imagescan scan --no-fetch --textfile-dir "$w/tf" --bundle "$w/b" > "$w/report.txt" 2>&1 || rc=$?
[ "$rc" -le 1 ] || { echo "scan failed (exit $rc): $(tail -3 "$w/report.txt")" >&2; exit 2; }
grep -E '^(pft-imagescan scan|IMAGE |  findings_sha256 |RESULT)' "$w/report.txt" | cut -c1-160 >&2 || true
sudo -n chown -R "$(id -u):$(id -g)" "$w/b"
# shellcheck disable=SC2024
sudo -n cat "$CACHE/last-scan.json" > "$w/scan.json"
p="$w/pub"; mkdir -p "$p/inv" "$p/feeds"
# git keeps no empty directory: a bundle whose every image is withheld still needs inv/ after a clone
: > "$p/inv/.keep"
python3 -I "$LIB" withhold --scan "$w/scan.json" --ref "$WITHHOLD_REF" > "$p/withheld.json"
utc_created() { # the inventory with provenance.created as the same instant in UTC (locally built images carry the
  # builder's local offset; scan and render never read the field)
  python3 -I -c 'import json, re, sys
from datetime import datetime, timezone
d = json.load(open(sys.argv[1])); c = (d.get("provenance") or {}).get("created", "")
m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d:\d\d)", c or "")
if m:
    t = datetime.fromisoformat(m.group(1) + m.group(3)).astimezone(timezone.utc)
    d["provenance"]["created"] = t.strftime("%Y-%m-%dT%H:%M:%S") + (m.group(2) or "") + "Z"
json.dump(d, sys.stdout, sort_keys=True, separators=(",", ":")); print()' "$1"
}
kept=0; held=0
for f in "$w"/b/inv/*.json; do
  if python3 -I -c 'import json, re, sys; sys.exit(0 if re.search(sys.argv[2], json.load(open(sys.argv[1]))["ref"]) else 1)' \
    "$f" "$WITHHOLD_REF"; then held=$((held + 1)); else utc_created "$f" > "$p/inv/${f##*/}"; kept=$((kept + 1)); fi
done
cp "$w/b/containers.json" "$w/b/now" "$p/"
cp "$w/b/feeds/feeds.json" "$p/feeds/"
files="$(python3 -I -c 'import json, sys; [print(v["file"]) for v in json.load(open(sys.argv[1]))["feeds"].values()]' \
  "$p/feeds/feeds.json")" || { echo "feeds.json unreadable" >&2; exit 2; }
[ -n "$files" ] || { echo "feeds.json lists no feed" >&2; exit 2; }
for file in $files; do
  sudo -n cat "$CACHE/feeds/$file" | xz -T1 -6 -c > "$p/feeds/$file.xz"
done
if [ -n "$BEFORE_SCAN" ]; then
  # only the findings the remediation removed (gone from the current scan): still-open advisories are not published,
  # and neither is a fixed ID that is still open in a withheld image (CVE ids are shared across distributions, so
  # listing it would hint at the withheld image's open findings; the count goes to stderr). provenance.created in UTC.
  python3 -I -c 'import json, re, sys
from datetime import datetime, timezone
s = json.load(open(sys.argv[1])); refs = set(sys.argv[2].split(",")); cur = json.load(open(sys.argv[3]))
now = {i["ref"]: {(f["source"], f["id"]) for f in i["findings"]} for i in cur["images"]}
held = {x for i in cur["images"] if re.search(sys.argv[4], i["ref"]) for f in i["findings"] for x in [f["id"], *f.get("cves", [])]}
s["images"] = [dict(i, findings=[f for f in i["findings"] if (f["source"], f["id"]) not in now.get(i["ref"], set())])
               for i in s["images"] if i["ref"] in refs and i["ref"] in now]
for i in s["images"]:
    keep = [f for f in i["findings"] if not ({f["id"], *f.get("cves", [])} & held)]
    n = len(i["findings"])
    print("before.json %s: %d fixed, %d not listed (still open in a withheld image)" % (i["ref"], n, n - len(keep)), file=sys.stderr)
    i["findings"] = keep
for i in s["images"]:
    m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d:\d\d)", (i.get("provenance") or {}).get("created") or "")
    if m:
        t = datetime.fromisoformat(m.group(1) + m.group(3)).astimezone(timezone.utc)
        i["provenance"]["created"] = t.strftime("%Y-%m-%dT%H:%M:%S") + (m.group(2) or "") + "Z"
json.dump(s, sys.stdout, sort_keys=True, indent=1); print()' "$BEFORE_SCAN" "$BEFORE_REFS" "$w/scan.json" "$WITHHOLD_REF" > "$p/before.json"
fi
shopt -s nullglob; xzs=("$p"/feeds/*.xz); shopt -u nullglob
[ "${#xzs[@]}" = "$(wc -w <<<"$files")" ] || { echo "feed copies: ${#xzs[@]} of $(wc -w <<<"$files")" >&2; exit 2; }
echo "public bundle: $kept inventories kept, $held withheld ($WITHHOLD_REF), ${#xzs[@]} feed copies, before=$([ -n "$BEFORE_SCAN" ] && echo yes || echo no)" >&2
tar -C "$p" --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -cf - .
