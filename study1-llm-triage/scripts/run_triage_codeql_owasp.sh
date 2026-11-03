#!/usr/bin/env bash
# Qwen2.5-Coder 7B triage of CodeQL's OWASP BenchmarkJava findings (GPU job, run alone).
# Waits for PID $1 (if given) to exit first. Every finding is fsynced; results are committed and
# pushed every 200 findings, so a power cut loses little. Resumable: rerun to continue.
set -u
cd "$(dirname "$0")/.."
[ -n "${1:-}" ] && while kill -0 "$1" 2>/dev/null; do sleep 30; done
OUT=results/triage_codeql/qwen2.5-coder_7b/raw.jsonl
TOTAL=2160
PY=.venv/bin/python
push() {
  git add results/triage_codeql >/dev/null 2>&1
  git commit -qm "checkpoint: 7B triage of CodeQL OWASP findings ($(wc -l < $OUT 2>/dev/null || echo 0)/$TOTAL)" >/dev/null 2>&1
  git push -q origin main >/dev/null 2>&1 || true
}
while [ "$(wc -l < $OUT 2>/dev/null || echo 0)" -lt "$TOTAL" ]; do
  before=$(wc -l < $OUT 2>/dev/null || echo 0)
  $PY -I scripts/triage_llm.py --model qwen2.5-coder:7b --sarif results/codeql/codeql.sarif \
    --per-test results/codeql/codeql_score_per_test.csv --src-root datasets/BenchmarkJava --out $OUT --limit 200
  push
  [ "$(wc -l < $OUT)" -gt "$before" ] || { echo "no progress, stopping"; exit 1; }
done
$PY -I scripts/eval_triage.py --raw $OUT --per-test results/codeql/codeql_score_per_test.csv
$PY -I scripts/summarize_results.py > /dev/null
git add results/README.md; push
echo TRIAGE-DONE
