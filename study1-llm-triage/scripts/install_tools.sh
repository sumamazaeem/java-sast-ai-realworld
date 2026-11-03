#!/usr/bin/env bash
# Installs SpotBugs + FindSecBugs plugin and the CodeQL CLI bundle into ~/thesis/tools (no sudo).
# Run this yourself (Claude is not permitted to download and execute external tools).
# Latest versions are resolved at runtime, with pinned fallbacks if a lookup fails.
# Idempotent: tools that are already installed are skipped.
set -euo pipefail
T=~/thesis/tools
mkdir -p "$T" && cd "$T"

STEP="start"
trap 'echo "FAILED at step: $STEP" >&2' ERR
step() { STEP="$1"; echo "[step] $1"; }

SPOTBUGS_FALLBACK=4.10.5
FINDSECBUGS_FALLBACK=1.14.0

latest_github() {  # owner/repo -> latest release tag (without leading v)
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1
}
latest_maven() {  # group/path artifact -> latest release version
  curl -fsSL "https://repo1.maven.org/maven2/$1/$2/maven-metadata.xml" | sed -n 's:.*<release>\(.*\)</release>.*:\1:p'
}

step "resolve SpotBugs version"
SB=$(latest_github spotbugs/spotbugs || true); SB=${SB:-$SPOTBUGS_FALLBACK}
if [ ! -x "spotbugs-$SB/bin/spotbugs" ]; then
  step "download SpotBugs $SB (GitHub release)"
  curl -fL -o "spotbugs-$SB.tgz" "https://github.com/spotbugs/spotbugs/releases/download/$SB/spotbugs-$SB.tgz"
  step "unpack SpotBugs $SB"
  tar xzf "spotbugs-$SB.tgz"
  chmod +x "spotbugs-$SB/bin/spotbugs"
fi

step "resolve FindSecBugs version"
FSB=$(latest_maven com/h3xstream/findsecbugs findsecbugs-plugin || true); FSB=${FSB:-$FINDSECBUGS_FALLBACK}
if [ ! -f "findsecbugs-plugin-$FSB.jar" ]; then
  step "download FindSecBugs plugin $FSB (Maven Central)"
  curl -fL -o "findsecbugs-plugin-$FSB.jar" \
    "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/$FSB/findsecbugs-plugin-$FSB.jar"
fi

if [ ! -x codeql/codeql ]; then
  step "download CodeQL bundle (latest codeql-action release, ~600 MB unpacked)"
  curl -fL -o codeql-bundle-linux64.tar.gz \
    https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
  step "unpack CodeQL bundle"
  tar xzf codeql-bundle-linux64.tar.gz
fi

step "verify"
echo "spotbugs=$SB findsecbugs=$FSB"
"$T/spotbugs-$SB/bin/spotbugs" -version
"$T/codeql/codeql" version | head -1
echo INSTALL-OK
