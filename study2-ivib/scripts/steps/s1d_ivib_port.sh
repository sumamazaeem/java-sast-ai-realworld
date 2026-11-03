#!/usr/bin/env bash
# Step 1d: unpack the IVIB code (RAR5 archives) and build its Java slicer on Linux / JDK 21.
set -eu
D="$IVIB_DATA/ivib"; mkdir -p "$D/src"
[ -d "$D/src/IVIB" ] || git clone -q --depth 1 https://github.com/KLSEHB/IVIB.git "$D/src/IVIB"
X=$(command -v unrar || command -v 7z || command -v 7zz || true)
if [ -z "$X" ]; then
  echo "needs unrar: run 'sudo apt-get install -y unrar'" > "$IVIB_STATE/$STEP.blocked"; exit 75
fi
mkdir -p "$D/x"
if [ ! -f "$D/x/.ok" ]; then
  for a in slice-project experiment; do
    case "$X" in *unrar) "$X" x -idq -o+ "$D/src/IVIB/$a.rar" "$D/x/" ;; *) "$X" x -y -o"$D/x" "$D/src/IVIB/$a.rar" >/dev/null ;; esac
  done
  touch "$D/x/.ok"
fi
# The build and Linux port are written by scripts/ivib/port_ivib.sh once the code has been read.
P="$(dirname "$0")/../port_ivib.sh"
if [ ! -f "$P" ]; then
  echo "IVIB unpacked; Linux port script not written yet" > "$IVIB_STATE/$STEP.blocked"; exit 75
fi
bash "$P"
