#!/usr/bin/env bash
# Step 7: tables and figures for the synopsis/thesis (results/ivib/RESULTS.md, fig_*.png).
set -eu
"$HOME/thesis/.venv/bin/python" -I "$(dirname "$0")/../compare_report.py"
