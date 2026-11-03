#!/usr/bin/env python3
"""Compare tools on the Java CVE Benchmark from their labelled per-CVE results (label_java_cve.py)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = sys.argv[1:] or ["semgrep", "codeql"]


def load(tool):
    p = ROOT / "results/java_cve" / tool / "per_cve.jsonl"
    return {json.loads(l)["cve"]: json.loads(l) for l in open(p)} if p.exists() else None


def strict(recs):
    unknown = sum(r["detected_strict"] is None for r in recs)
    return f"{sum(bool(r['detected_strict']) for r in recs)}" + (f" (+{unknown} not checked)" if unknown else "")


def row(name, recs):
    n502 = [r for r in recs if r["cwe"] != "CWE-502"]
    return (f"| {name} | {len(recs)} | {sum(r['detected'] for r in recs)} | {strict(recs)} | "
            f"{sum(r['detected'] for r in n502)}/{len(n502)} | {sum(r['findings'] for r in recs)} | "
            f"{sum(r['tp_findings'] for r in recs)} |")


data = {t: load(t) for t in TOOLS if load(t)}
lines = ["| Tool | CVEs scanned | Detected | Detected (strict: gone after fix) | Detected excl. CWE-502 | Findings | Findings in vulnerable methods |",
         "|---|---|---|---|---|---|---|"]
for t, d in data.items():
    lines.append(row(t, list(d.values())))
if len(data) > 1:
    common = set.intersection(*(set(d) for d in data.values()))
    union = [{"cve": c, "cwe": next(iter(data.values()))[c]["cwe"],
              "detected": any(d[c]["detected"] for d in data.values()),
              "detected_strict": any(bool(d[c]["detected_strict"]) for d in data.values()),
              "findings": sum(d[c]["findings"] for d in data.values()),
              "tp_findings": sum(d[c]["tp_findings"] for d in data.values())} for c in sorted(common)]
    lines.append(row(" + ".join(data), union))
    lines.append("")
    for t, d in data.items():
        hits = sorted(c for c in common if d[c]["detected"])
        lines.append(f"- {t} detects: {', '.join(hits) if hits else 'none'}")
out = ROOT / "results/java_cve/comparison.md"
out.write_text("# Java CVE Benchmark: tool comparison\n\n" + "\n".join(lines) + "\n")
print(out.read_text())
