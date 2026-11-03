#!/usr/bin/env bash
# SpotBugs+FindSecBugs and CodeQL scans of BenchmarkJava, CPU limited to 4 threads.
# Run only while no LLM inference is running (power budget). Skips scans whose SARIF exists.
set -euo pipefail
T=~/thesis
B=$T/datasets/BenchmarkJava
mkdir -p "$T/results/spotbugs" "$T/results/codeql"

SB=$(ls -d "$T"/tools/spotbugs-*/ | grep -v '\.tgz' | tail -1)
FSB=$(ls "$T"/tools/findsecbugs-plugin-*.jar | tail -1)
if [ ! -s "$T/results/spotbugs/spotbugs.sarif" ]; then
  # Only the Benchmark test cases; dependency jars on the aux classpath for type resolution.
  CP=$(find ~/.m2/repository -name '*.jar' | tr '\n' ':')
  JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=4" "$SB/bin/spotbugs" -textui -effort:max -low \
    -pluginList "$FSB" -auxclasspath "$CP" \
    -onlyAnalyze 'org.owasp.benchmark.testcode.-' \
    -sarif="$T/results/spotbugs/spotbugs.sarif.tmp" "$B/target/classes" \
    > "$T/results/spotbugs/scan.log" 2>&1
  mv "$T/results/spotbugs/spotbugs.sarif.tmp" "$T/results/spotbugs/spotbugs.sarif"
fi

CQ=$T/tools/codeql/codeql
if [ ! -s "$T/results/codeql/codeql.sarif" ]; then
  [ -d "$T/results/codeql/db" ] || "$CQ" database create "$T/results/codeql/db" --language=java \
    --build-mode=none --source-root "$B" --threads=4 > "$T/results/codeql/create.log" 2>&1
  "$CQ" database analyze "$T/results/codeql/db" codeql/java-queries:codeql-suites/java-security-extended.qls \
    --format=sarif-latest --output="$T/results/codeql/codeql.sarif.tmp" --threads=4 \
    > "$T/results/codeql/analyze.log" 2>&1
  mv "$T/results/codeql/codeql.sarif.tmp" "$T/results/codeql/codeql.sarif"
fi
echo SCANS-OK
