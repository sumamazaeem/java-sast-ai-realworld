#!/usr/bin/env bash
# Scan Juliet Java 1.3 with Semgrep, SpotBugs+FindSecBugs (after a javac compile) and CodeQL.
# CPU only, up to 8 threads, low priority; run alone (no GPU job at the same time).
# Each step is skipped if its SARIF already exists, so the script can be re-run after an interruption.
set -u
T=~/thesis
J=$T/datasets/juliet-java/src/Java
OUT=$T/results/juliet
mkdir -p "$OUT"/{semgrep,spotbugs,codeql}
step() { echo "[$(date -u +%H:%M:%S)] $*"; }

if [ ! -s "$OUT/semgrep/semgrep.sarif.gz" ]; then
  step "semgrep"
  (cd "$J" && nice -n 10 "$T/.venv/bin/semgrep" scan --metrics=off --config p/java --config p/owasp-top-ten \
     --sarif --output "$OUT/semgrep/semgrep.sarif" --jobs 8 --timeout 30 --no-git-ignore src/testcases \
     > "$OUT/semgrep/scan.log" 2>&1) && gzip -f "$OUT/semgrep/semgrep.sarif" || step "semgrep FAILED (see scan.log)"
fi

CLS=$T/datasets/juliet-java/build/classes
if [ ! -f "$CLS/.complete" ]; then
  step "javac compile"
  mkdir -p "$CLS"
  # skip the per-CWE ant build copies and the Main/ServletMain templates (placeholders, not test cases)
  find "$J/src" -name '*.java' -not -path '*/antbuild/*' -not -name 'Main.java' -not -name 'ServletMain.java' \
    > "$T/datasets/juliet-java/build/sources.txt"
  nice -n 10 javac -J-Xmx8g -nowarn -encoding UTF-8 -source 8 -target 8 -cp "$J/lib/*" -d "$CLS" \
    @"$T/datasets/juliet-java/build/sources.txt" > "$OUT/spotbugs/javac.log" 2>&1 && touch "$CLS/.complete" \
    || step "javac FAILED (see spotbugs/javac.log)"
fi

if [ -f "$CLS/.complete" ] && [ ! -s "$OUT/spotbugs/spotbugs.sarif.gz" ]; then
  step "spotbugs + findsecbugs"
  SB=$(ls -d "$T"/tools/spotbugs-*/ | tail -1); FSB=$(ls "$T"/tools/findsecbugs-plugin-*.jar | tail -1)
  JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=8 -Xmx12g" nice -n 10 "$SB/bin/spotbugs" -textui -effort:max -low \
    -pluginList "$FSB" -auxclasspath "$(ls "$J"/lib/*.jar | tr '\n' ':')" -onlyAnalyze 'testcases.-' \
    -sarif="$OUT/spotbugs/spotbugs.sarif" "$CLS" > "$OUT/spotbugs/scan.log" 2>&1 \
    && gzip -f "$OUT/spotbugs/spotbugs.sarif" || step "spotbugs FAILED (see spotbugs/scan.log)"
fi

if [ ! -s "$OUT/codeql/codeql.sarif.gz" ]; then
  step "codeql"
  CQ=$T/tools/codeql/codeql; DB=$T/datasets/juliet-java/build/codeql-db
  [ -d "$DB" ] || nice -n 10 "$CQ" database create "$DB" --language=java --build-mode=none --source-root "$J" \
    --threads=8 > "$OUT/codeql/create.log" 2>&1
  nice -n 10 "$CQ" database analyze "$DB" codeql/java-queries:codeql-suites/java-security-extended.qls \
    --format=sarif-latest --output="$OUT/codeql/codeql.sarif" --threads=8 --ram=16000 > "$OUT/codeql/analyze.log" 2>&1 \
    && gzip -f "$OUT/codeql/codeql.sarif" || step "codeql FAILED (see codeql/*.log)"
fi
step "JULIET-SCANS-DONE"
