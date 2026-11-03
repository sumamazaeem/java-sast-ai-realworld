#!/usr/bin/env bash
# Step 1e: CodeQL and Semgrep on every real-world version (CPU only, 4 threads, resumable), then
# per-unit predictions for both tools on all four test sets.
set -eu
H="$(dirname "$0")/.."
for t in semgrep codeql; do "$HOME/thesis/.venv/bin/python" -I "$H/scan_baselines.py" --tool $t; done
python3 -I "$H/score_units.py" sarif --tool codeql
python3 -I "$H/score_units.py" sarif --tool semgrep
python3 -I "$H/score_units.py" score
