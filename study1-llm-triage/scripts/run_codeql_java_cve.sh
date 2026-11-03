#!/usr/bin/env bash
# CodeQL over the vulnerable versions of the Java CVE Benchmark, 10 versions per chunk,
# committing and pushing after each chunk (power-loss safe). CPU only, 4 threads; GPU must be idle.
set -u
cd "$(dirname "$0")/.."
while true; do
  out=$(.venv/bin/python -I scripts/scan_java_cve.py --tool codeql --vul-only --limit 10 2>&1)
  echo "$out"
  git add results/java_cve/codeql >/dev/null 2>&1
  git commit -qm "checkpoint: CodeQL Java CVE scans" >/dev/null 2>&1 \
    && git push -q origin main >/dev/null 2>&1
  echo "$out" | grep -q '^0 versions to scan' && break
done
.venv/bin/python -I scripts/label_java_cve.py --all --tool codeql
