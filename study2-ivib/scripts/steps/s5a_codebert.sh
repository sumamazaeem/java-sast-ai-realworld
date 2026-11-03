#!/usr/bin/env bash
# Step 5a (Enhancement 2, learned baseline without slicing): CodeBERT trained on synthetic code only
# (as IVIB was) vs synthetic + real CVE fix pairs (CVEfixes), both tested on every set. GPU, resumable.
set -eu
H="$(dirname "$0")/.."
[ -x "$IVIB_ML" ] && "$IVIB_ML" -c "import torch,transformers" 2>/dev/null || { echo "ML environment not ready" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
"$IVIB_ML" -I "$H/train_codebert.py" --name synth --train owasp juliet
"$IVIB_ML" -I "$H/train_codebert.py" --name real --train owasp juliet cvefixes
python3 -I "$H/score_units.py" score
