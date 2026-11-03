#!/usr/bin/env bash
# Step 5 (Enhancements 1 + 2 together and apart). IVIB-R slices with the LLM-inferred specs (llm),
# then the IVIB model trained (a) on synthetic data only and (b) on synthetic + real CVE fix pairs
# from CVEfixes (projects held out 80/20; test projects of CWE-Bench-Java / Java CVE removed).
# (b) with spec ivib5p isolates Enhancement 2 without Enhancement 1.
set -eu
H="$(dirname "$0")/.."
python3 -I "$H/check_split.py" || { echo "train/test leakage check failed" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
PY="$HOME/thesis/.venv/bin/python"
"$IVIB_ML" -c "import torch,torchcrf,transformers,sklearn" 2>/dev/null || { echo "ML environment not ready" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
[ -s "$IVIB_DATA/slices/llm/cvefixes.jsonl" ] || $PY -I "$H/build_slices.py" --spec llm
"$IVIB_ML" -I "$H/train_ivib.py" fit --spec llm --name synth-llm --train owasp juliet --test cwebench javacve cvefixes
"$IVIB_ML" -I "$H/train_ivib.py" fit --spec ivib5p --name real-ivib5p --train owasp juliet cvefixes --test cwebench javacve cvefixes
"$IVIB_ML" -I "$H/train_ivib.py" fit --spec llm --name real-llm --train owasp juliet cvefixes --test cwebench javacve cvefixes
python3 -I "$H/score_units.py" score
