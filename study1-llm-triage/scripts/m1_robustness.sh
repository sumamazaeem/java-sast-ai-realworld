#!/usr/bin/env bash
# Method 1 robustness runs (the two gaps left open in Chapter 4): does the guardrail result hold
# (a) with few-shot examples in the prompt and (b) with sampled, non-deterministic decoding?
# Same real-world items (90 real + 597 other findings), same prompt/schema, frozen guardrails v2.
#   R-fs   Qwen2.5-Coder 7B, few-shot (config/fewshot_java.json), temperature 0, seed 42
#   R-t1..3 Qwen2.5-Coder 7B, zero-shot, temperature 0.7, seeds 1, 2, 3
# ~687 findings x ~2.6 s = ~30 min per run on the RTX 2070 (150 W cap), ~2 h total. Resumable.
# Run it only when the GPU is free (after the IVIB queue). Then: python3 -I scripts/m1_robustness_report.py
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
ITEMS=results/items/realworld.jsonl
OUT=results/robustness_realworld
run() {  # name, extra args...
  local name=$1; shift
  local raw=$OUT/$name/raw.jsonl
  mkdir -p "$OUT/$name"
  while [ "$(wc -l < "$raw" 2>/dev/null || echo 0)" -lt "$(wc -l < $ITEMS)" ]; do
    local before; before=$(wc -l < "$raw" 2>/dev/null || echo 0)
    $PY -I scripts/triage_snippets.py --items $ITEMS --out "$raw" --limit 200 "$@"
    [ "$(wc -l < "$raw")" -gt "$before" ] || { echo "no progress in $raw" >&2; exit 1; }
  done
  $PY -I scripts/eval_snippets.py --raw "$raw"
}
run qwen7b_fewshot --fewshot config/fewshot_java.json --temperature 0 --seed 42
for s in 1 2 3; do run "qwen7b_t07_s$s" --temperature 0.7 --seed "$s"; done
$PY -I scripts/m1_robustness_report.py
