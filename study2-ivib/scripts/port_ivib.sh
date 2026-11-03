#!/usr/bin/env bash
# Called by step 1d after unpacking. Records what the released IVIB code contains (audit), and checks
# that the parts reused by IVIB-R (Constants.java lists, the BERT-BiLSTM-CRF model, TAG2IDX) are there.
set -eu
X="$IVIB_DATA/ivib/x"
J="$X/slice-project/src/main/java/com/example/javaslicer"
M="$X/experiment/mycode"
for f in "$J/constant/Constants.java" "$J/isl/impl/TranslateServiceImpl.java" "$M/a_超参数训练/model.py" "$M/config/properties.py"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done
OUT="$(dirname "$0")/../../results/ivib/ivib_release_audit.md"
{
  echo "# What the released IVIB code contains (github.com/KLSEHB/IVIB, checked $(date -u +%F))"
  echo
  echo "| Part | Status in the release | Evidence |"
  echo "|---|---|---|"
  echo "| Source/sink lists | present, method names only, no sanitisers | Constants.java: $(grep -c '"' "$J/constant/Constants.java") quoted names |"
  echo "| Slicing traversals | stubs returning empty sets | TranslateServiceImpl.java lines $(grep -n 'return  *new HashSet' "$J/isl/impl/TranslateServiceImpl.java" | cut -d: -f1 | tr '\n' ' ')|"
  echo "| prune() / translate() calls | commented out | SlicingServiceImpl.java: $(grep -c '^//.*translateService' "$J/service/impl/SlicingServiceImpl.java") commented calls |"
  echo "| ISL writer | writes an empty string | ParseFileServiceImpl.writeTranslateResult has an empty body |"
  echo "| Vulnerability classes | sqlvul, xssvul, cmdvul, xpathvul (no path traversal, no code injection) | config/properties.py TAG2IDX |"
  echo "| BERT-BiLSTM-CRF model + training code | complete | mycode/a_超参数训练/model.py, train.py |"
  echo "| Data, slices, trained model | not included | experiment/resource/{data,model} are empty |"
  echo "| Paths | hard-coded Windows (D:\\\\...) and /home/dixu | application.properties, experiment.properties |"
} > "$OUT"
cat "$OUT"
