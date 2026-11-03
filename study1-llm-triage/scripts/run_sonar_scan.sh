#!/usr/bin/env bash
# SonarQube scan of OWASP BenchmarkJava. Reads SONAR_HOST_URL/SONAR_TOKEN from ~/.config/thesis/sonar.env
# (the scanner picks SONAR_TOKEN up from the environment, so it never appears in argv or logs).
set -euo pipefail
T=~/thesis
set -a; . ~/.config/thesis/sonar.env; set +a
# Upload to the local port, not through Cloudflare (a 16 MB report timed out via the tunnel).
SCAN_URL=${SONAR_SCAN_URL:-http://127.0.0.1:9000}
cd "$T/datasets/BenchmarkJava"
"$T"/tools/sonar-scanner-*/bin/sonar-scanner \
  -Dsonar.host.url="$SCAN_URL" \
  -Dsonar.projectKey=owasp-benchmarkjava \
  -Dsonar.projectName="OWASP BenchmarkJava 1.2" \
  -Dsonar.sources=src/main/java \
  -Dsonar.java.binaries=target/classes \
  -Dsonar.java.libraries="$HOME/.m2/repository/**/*.jar" \
  -Dsonar.java.source=1.8 \
  -Dsonar.scm.disabled=true \
  -Dsonar.cpd.exclusions="**/*" \
  -Dsonar.scanner.responseTimeout=600 \
  -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=3600
