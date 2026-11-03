#!/usr/bin/env python3
"""Score a SARIF file against OWASP Benchmark expected results.

A test case counts as "flagged" if at least one SARIF result is located in
BenchmarkTestNNNNN.java and carries a CWE that maps to that test's category.
Default mapping follows the Benchmark scorecard idea (exact CWE) plus a few
documented aliases (e.g. 338 -> weakrand); use --strict for exact CWE only.

Outputs:
  --out           per-category + overall metrics CSV
  <out>_per_test  per-test verdicts (input for later LLM triage)
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

TEST_RE = re.compile(r"(BenchmarkTest\d{5})")
CWE_RE = re.compile(r"CWE-(\d+)", re.I)

# Extra CWEs that tools commonly report for each Benchmark category.
ALIASES = {
    "cmdi": {78, 77},
    "crypto": {327, 326},
    "hash": {328, 327, 916},
    "ldapi": {90},
    "pathtraver": {22, 23, 36, 73},
    "securecookie": {614},
    "sqli": {89, 564},
    "trustbound": {501},
    "weakrand": {330, 338},
    "xpathi": {643},
    "xss": {79, 80},
    "codeinj": {94, 95},
    "deserialization": {502},
    "redirect": {601},
    "xxe": {611, 776},
}


def load_expected(path):
    tests = {}
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, cat, real, cwe = (c.strip() for c in row[:4])
            tests[name] = {"category": cat, "real": real.lower() == "true", "cwe": int(cwe)}
    return tests


def rule_cwes(rule):
    text = json.dumps(rule.get("properties", {})) + " " + json.dumps(rule.get("shortDescription", {}))
    cwes = {int(m) for m in CWE_RE.findall(text)}
    # SpotBugs: CWE given as a relationship to the CWE taxonomy (target.id = "89")
    for rel in rule.get("relationships", []):
        tgt = rel.get("target", {})
        if tgt.get("toolComponent", {}).get("name", "").upper() == "CWE" and str(tgt.get("id", "")).isdigit():
            cwes.add(int(tgt["id"]))
    return cwes


def load_findings(path):
    """Return {test_name: {cwe: [rule_ids]}}."""
    sarif = json.loads(Path(path).read_text())
    found = defaultdict(lambda: defaultdict(list))
    for run in sarif.get("runs", []):
        rules = {r["id"]: rule_cwes(r) for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            cwes = rules.get(rid, set()) | {int(m) for m in CWE_RE.findall(json.dumps(res.get("properties", {})))}
            for loc in res.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                m = TEST_RE.search(uri)
                if not m:
                    continue
                for c in cwes or {-1}:
                    found[m.group(1)][c].append(rid)
    return found


def metrics(tp, fp, fn, tn):
    prec = tp / (tp + fp) if tp + fp else 0.0
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return prec, tpr, fpr, tpr - fpr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--strict", action="store_true", help="exact CWE match only")
    args = ap.parse_args()

    tests = load_expected(args.expected)
    found = load_findings(args.sarif)

    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    per_test = []
    for name, t in sorted(tests.items()):
        accept = {t["cwe"]} if args.strict else ALIASES.get(t["category"], set()) | {t["cwe"]}
        hits = sorted({r for c, rs in found.get(name, {}).items() if c in accept for r in rs})
        flagged = bool(hits)
        key = ("tp" if t["real"] else "fp") if flagged else ("fn" if t["real"] else "tn")
        counts[t["category"]][key] += 1
        per_test.append([name, t["category"], t["cwe"], t["real"], flagged, key.upper(), ";".join(hits)])

    rows = []
    total = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    scores = []
    for cat in sorted(counts):
        c = counts[cat]
        for k in total:
            total[k] += c[k]
        p, r, f, s = metrics(c["tp"], c["fp"], c["fn"], c["tn"])
        scores.append(s)
        cwe = next(t["cwe"] for t in tests.values() if t["category"] == cat)
        rows.append([cat, cwe, c["tp"], c["fp"], c["fn"], c["tn"], p, r, f, s])
    p, r, f, s = metrics(total["tp"], total["fp"], total["fn"], total["tn"])
    rows.append(["OVERALL (pooled)", "", total["tp"], total["fp"], total["fn"], total["tn"], p, r, f, s])
    rows.append(["OVERALL (avg of categories, Benchmark style)", "", "", "", "", "",
                 sum(x[6] for x in rows[:-1]) / len(scores), sum(x[7] for x in rows[:-1]) / len(scores),
                 sum(x[8] for x in rows[:-1]) / len(scores), sum(scores) / len(scores)])

    header = ["category", "cwe", "TP", "FP", "FN", "TN", "precision", "recall_TPR", "FPR", "score_TPR_minus_FPR"]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow([f"{v:.4f}" if isinstance(v, float) else v for v in row])
    with open(out.with_name(out.stem + "_per_test.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["test", "category", "cwe", "real_vuln", "flagged", "outcome", "matching_rules"])
        w.writerows(per_test)

    fmt = "{:<46}{:>5}{:>5}{:>5}{:>5}{:>5}{:>7}{:>7}{:>7}{:>8}"
    print(fmt.format(*["category", "cwe", "TP", "FP", "FN", "TN", "prec", "TPR", "FPR", "score"]))
    for row in rows:
        print(fmt.format(*[f"{v:.3f}" if isinstance(v, float) else v for v in row]))
    print(f"\nwrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
