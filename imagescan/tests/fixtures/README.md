# test fixtures

- `amtool.buildinfo`: the real Go build-info record (magic, header, version string, modinfo; 7677 bytes) cut out of
  `/bin/amtool` in `prom/alertmanager:v0.28.1` (image `sha256:27c475db5fb1…`, go1.23.7). The tests embed it in a
  synthetic ELF file inside a synthetic image layer, so the parser runs on real build-info bytes.
- Feeds are built by `test_imagescan.py` in Canonical OCI OVAL / Debian tracker / OSV structure with made-up
  `USN-0000-*` / `CVE-0000-*` / `GO-0000-*` IDs, so the fixtures never describe a real open weakness.
