#!/usr/bin/env python3
"""Score a SARIF file against the Juliet Java 1.3 ground truth (data/juliet-java/manifest.jsonl.gz).

Each test case contributes one positive and one negative:
  TP if a CWE-matching finding lies in a bad method/class (else FN),
  FP if a CWE-matching finding lies in a good method/class (else TN).
CWE matching: same CWE, or same weakness family (FAMILIES below, mirroring score_owasp's aliases).
Files are matched by name (Juliet file names are unique), so tools that report paths relative to
different roots (Semgrep/CodeQL: src/testcases/..., SpotBugs: testcases/...) all work.

Writes <out> (per CWE + overall) and <out>_owasp.csv (the 9,218 cases overlapping OWASP Benchmark
categories, per category), and prints both.
"""
import argparse
import csv
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from score_owasp import metrics, rule_cwes  # noqa: E402

FAMILIES = [{22, 23, 36, 73}, {79, 80, 81, 82, 83}, {89, 564}, {77, 78}, {90}, {643}, {326, 327, 329},
            {328, 759, 760, 916}, {330, 338}, {614, 315, 311}, {501}, {601}, {113, 93}, {190, 680}, {191}]
OWASP = {"sqli": {89}, "cmdi": {78}, "xss": {79, 80, 81, 82, 83}, "ldapi": {90}, "xpathi": {643},
         "pathtraver": {22, 23, 36}, "crypto": {327}, "hash": {328, 759, 760, 916}, "weakrand": {330, 338},
         "securecookie": {614}, "trustbound": {501}}


def family(c):
    for f in FAMILIES:
        if c in f:
            return f
    return {c}


def load_sarif(path):
    p = Path(path)
    data = json.loads(gzip.open(p).read() if p.suffix == ".gz" else p.read_text())
    by_file = defaultdict(list)  # file name -> [(line, cwes)]
    for run in data.get("runs", []):
        rules = {r["id"]: rule_cwes(r) for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            cwes = rules.get(res.get("ruleId"), set())
            if not cwes:
                continue
            for loc in res.get("locations", [])[:1]:
                pl = loc.get("physicalLocation", {})
                name = pl.get("artifactLocation", {}).get("uri", "").rsplit("/", 1)[-1]
                by_file[name].append((pl.get("region", {}).get("startLine", 0), cwes))
    return by_file


def hit(ranges, by_file, case_cwe):
    fam = family(case_cwe)
    for r in ranges:
        for line, cwes in by_file.get(r["file"].rsplit("/", 1)[-1], []):
            if r["start"] <= line <= r["end"] and cwes & fam:
                return True
    return False


def write(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["group", "cases", "TP", "FP", "FN", "TN", "precision", "TPR", "FPR", "score"])
        for name, c in rows:
            p, r, f, s = metrics(c["tp"], c["fp"], c["fn"], c["tn"])
            w.writerow([name, c["n"], c["tp"], c["fp"], c["fn"], c["tn"], f"{p:.4f}", f"{r:.4f}", f"{f:.4f}", f"{s:.4f}"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", default=str(ROOT / "data/juliet-java/manifest.jsonl.gz"))
    args = ap.parse_args()

    by_file = load_sarif(args.sarif)
    per_cwe = defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
    per_owasp = defaultdict(lambda: {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})
    per_case = []
    with gzip.open(args.manifest, "rt") as fh:
        for line in fh:
            c = json.loads(line)
            b, g = hit(c["bad"], by_file, c["cwe"]), hit(c["good"], by_file, c["cwe"])
            per_case.append((c["case"], c["cwe"], b, g))
            groups = [per_cwe[c["cwe"]]] + [per_owasp[k] for k, v in OWASP.items() if c["cwe"] in v]
            for grp in groups:
                grp["n"] += 1
                grp["tp" if b else "fn"] += 1
                grp["fp" if g else "tn"] += 1

    def total(d):
        t = {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for c in d.values():
            for k in t:
                t[k] += c[k]
        return t

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    cwe_rows = [(f"CWE-{k}", v) for k, v in sorted(per_cwe.items())]
    detected = {k: v for k, v in per_cwe.items() if v["tp"] or v["fp"]}
    cwe_rows += [("OVERALL (all cases)", total(per_cwe)), ("OVERALL (CWEs the tool reports at all)", total(detected))]
    write(out, cwe_rows)
    ow_rows = sorted(per_owasp.items()) + [("OVERALL (OWASP-overlap cases)", total(per_owasp))]
    write(out.with_name(out.stem + "_owasp.csv"), ow_rows)
    with open(out.with_name(out.stem + "_per_case.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case", "cwe", "bad_flagged", "good_flagged"])
        w.writerows(per_case)

    for title, rows in (("OWASP-overlap categories", ow_rows), ("overall", cwe_rows[-2:])):
        print(f"== {title}")
        for name, c in rows:
            p, r, f, s = metrics(c["tp"], c["fp"], c["fn"], c["tn"])
            print(f"{name:42}{c['n']:>7}  TPR {r:.3f}  FPR {f:.3f}  score {s:.3f}")
    print(f"tool reports CWEs matching {len(detected)} of {len(per_cwe)} Juliet CWEs")


if __name__ == "__main__":
    main()
