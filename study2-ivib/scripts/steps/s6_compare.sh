#!/usr/bin/env bash
# Step 6: score every method on every set (precision, recall, F1, pairs) and test significance.
set -eu
H="$(dirname "$0")/.."
python3 -I "$H/score_units.py" score
"$HOME/thesis/.venv/bin/python" -I "$H/compare_report.py"
