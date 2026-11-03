#!/usr/bin/env bash
# Step 4 (Enhancement 1): Qwen2.5-Coder 7B infers sources/sinks/sanitisers per project version (GPU).
# The queue holds ~/thesis/state/gpu.lock for the whole step. Resumable per batch.
set -eu
curl -fsS http://127.0.0.1:11434/api/version >/dev/null || { echo "ollama not reachable" > "$IVIB_STATE/$STEP.blocked"; exit 75; }
python3 -I "$(dirname "$0")/../llm_specs.py" --model qwen2.5-coder:7b
