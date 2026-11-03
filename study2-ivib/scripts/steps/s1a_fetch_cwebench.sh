#!/usr/bin/env bash
# Step 1a: CWE-Bench-Java sources (buggy + fixed) for the 5 CWEs. Network only, resumable.
# The lock lets a manual run and the queue's run share the work safely.
set -eu
mkdir -p "$IVIB_DATA/cwe-bench-java"
flock "$IVIB_DATA/cwe-bench-java/.lock" python3 -I "$(dirname "$0")/../fetch_cwebench.py"
