#!/usr/bin/env bash
# Step 1c: one method-level labelled dataset per source, 5 CWEs (see scripts/ivib/build_units.py).
set -eu
python3 -I "$(dirname "$0")/../build_units.py"
