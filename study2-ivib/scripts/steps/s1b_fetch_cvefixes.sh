#!/usr/bin/env bash
# Step 1b: CVEfixes v1.0.8 (Bhandari et al. 2021; Zenodo 13118970), 12.7 GB zip with one SQLite DB.
# curl -C - resumes a partial download after a reboot. Unzipped once, then the zip is kept for checksums.
set -eu
H="$(cd "$(dirname "$0")/.." && pwd)"
D="$IVIB_DATA/cvefixes"; mkdir -p "$D"; cd "$D"
exec 8> "$D/.lock"; flock 8   # a manual run and the queue's run never download at the same time
# Same file as Zenodo 13118970 (md5 checked below); the Hugging Face mirror is ~40x faster from here.
URL=https://huggingface.co/datasets/starsofchance/CVEfixes_v1.0.8/resolve/main/CVEfixes_v1.0.8.zip
if [ ! -f zip.ok ]; then
  curl -fL --retry 10 --retry-delay 30 -C - -o CVEfixes_v1.0.8.zip "$URL"
  want=$(curl -fsS https://zenodo.org/api/records/13118970 | python3 -c "import json,sys;print([f['checksum'] for f in json.load(sys.stdin)['files']][0].split(':')[1])")
  got=$(md5sum CVEfixes_v1.0.8.zip | cut -d' ' -f1)
  if [ "$want" != "$got" ]; then echo "checksum mismatch ($got != $want), restarting download"; rm -f CVEfixes_v1.0.8.zip; exit 1; fi
  touch zip.ok
fi
if [ ! -f db.ok ]; then
  [ -f unzip.ok ] || { python3 -I -c "import zipfile; zipfile.ZipFile('CVEfixes_v1.0.8.zip').extractall('.')"; touch unzip.ok; }
  # The zip holds a gzipped SQL dump, not a .db: load it into SQLite (a few hours, CPU + disk).
  [ -f CVEfixes.db ] || python3 -I "$H/cvefixes_to_sqlite.py" CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz CVEfixes.db
  echo CVEfixes.db > db.path
  touch db.ok
fi
echo "CVEfixes DB: $(cat db.path)"
