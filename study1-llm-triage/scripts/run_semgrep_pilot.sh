#!/usr/bin/env bash
# Pilot: Semgrep over OWASP BenchmarkJava. Skips steps whose outputs already exist.
set -euo pipefail
T=~/thesis
OUT=$T/results/pilot
mkdir -p "$OUT" "$T/datasets"
[ -d "$T/datasets/BenchmarkJava" ] || git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava "$T/datasets/BenchmarkJava"
if [ ! -s "$OUT/semgrep.sarif" ]; then
  "$T/.venv/bin/semgrep" scan --metrics=off --config p/java --config p/owasp-top-ten \
    --sarif --output "$OUT/semgrep.sarif.tmp" --jobs 8 --timeout 30 \
    "$T/datasets/BenchmarkJava/src/main/java" 2> "$OUT/semgrep.log"
  mv "$OUT/semgrep.sarif.tmp" "$OUT/semgrep.sarif"
fi
"$T/.venv/bin/python" -I "$T/scripts/score_owasp.py" \
  --sarif "$OUT/semgrep.sarif" \
  --expected "$(ls "$T"/datasets/BenchmarkJava/expectedresults-*.csv | head -1)" \
  --out "$OUT/semgrep_score.csv"
