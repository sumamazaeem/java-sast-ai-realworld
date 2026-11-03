#!/usr/bin/env bash
# Step 3: show the gap. Train IVIB-R on all synthetic slices (OWASP + Juliet, our 5 CWEs) and predict
# real projects it has never seen (CWE-Bench-Java, Java CVE Benchmark, CVEfixes); unsliced units = not
# reported. Also the same with the method's parameters as sources (ivib5p), to separate "no source
# found" from "model does not transfer".
set -eu
H="$(dirname "$0")/.."
PY="$HOME/thesis/.venv/bin/python"
"$IVIB_ML" -c "import torch,torchcrf,transformers,sklearn" 2>/dev/null || { echo "ML environment not ready" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
for sp in ivib5 ivib5p; do
  [ -s "$IVIB_DATA/slices/$sp/cvefixes.jsonl" ] || $PY -I "$H/build_slices.py" --spec $sp
  "$IVIB_ML" -I "$H/train_ivib.py" fit --spec $sp --name synth-$sp --train owasp juliet --test cwebench javacve cvefixes
done
python3 -I "$H/score_units.py" score
