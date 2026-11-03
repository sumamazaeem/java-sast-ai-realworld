#!/usr/bin/env bash
# Step 2: repeat the base paper. IVIB-R slices of OWASP + Juliet with IVIB's own source/sink lists,
# IVIB's BERT-BiLSTM-CRF, 5-fold CV (80/20), paper hyper-parameters. Target: F1 96.93%.
set -eu
H="$(dirname "$0")/.."
"$IVIB_ML" -c "import torch,torchcrf,transformers,sklearn" 2>/dev/null || { echo "ML environment not ready" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
[ -s "$IVIB_DATA/slices/ivib/juliet.jsonl" ] || "$HOME/thesis/.venv/bin/python" -I "$H/build_slices.py" --spec ivib --datasets owasp juliet
"$IVIB_ML" -I "$H/train_ivib.py" cv --spec ivib --train owasp juliet
