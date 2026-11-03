#!/usr/bin/env python3
"""Combine per-test results of several tools (from score_owasp.py *_per_test.csv files).

For each test case: union = flagged by any tool, intersection = flagged by all tools.
Prints and writes per-category metrics for every single tool, the union and the intersection.

usage: combine_scores.py --out results/combined/scores.csv name1=per_test1.csv name2=per_test2.csv ...
"""
import argparse
import csv
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score_owasp import metrics  # noqa: E402


def load(path):
    return {r["test"]: r for r in csv.DictReader(open(path))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pairs", action="store_true", help="also score the union of every pair of tools")
    ap.add_argument("tools", nargs="+", help="name=path/to/*_per_test.csv")
    args = ap.parse_args()

    tools = dict(t.split("=", 1) for t in args.tools)
    data = {name: load(p) for name, p in tools.items()}
    base = next(iter(data.values()))
    variants = {name: (lambda t, n=name: data[n][t]["flagged"] == "True") for name in data}
    variants["union"] = lambda t: any(data[n][t]["flagged"] == "True" for n in data)
    variants["intersection"] = lambda t: all(data[n][t]["flagged"] == "True" for n in data)
    if args.pairs and len(data) > 2:
        for a, b in combinations(data, 2):
            variants[f"{a}+{b}"] = lambda t, a=a, b=b: data[a][t]["flagged"] == "True" or data[b][t]["flagged"] == "True"

    rows = []
    for vname, flagged in variants.items():
        counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for t, r in base.items():
            real = r["real_vuln"] == "True"
            f = flagged(t)
            counts[r["category"]][("tp" if real else "fp") if f else ("fn" if real else "tn")] += 1
        tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        scores = []
        for cat in sorted(counts):
            c = counts[cat]
            for k in tot:
                tot[k] += c[k]
            p, r_, fpr, s = metrics(c["tp"], c["fp"], c["fn"], c["tn"])
            scores.append(s)
            rows.append({"variant": vname, "category": cat, **{k.upper(): v for k, v in c.items()},
                         "precision": round(p, 4), "TPR": round(r_, 4), "FPR": round(fpr, 4), "score": round(s, 4)})
        p, r_, fpr, s = metrics(tot["tp"], tot["fp"], tot["fn"], tot["tn"])
        rows.append({"variant": vname, "category": "OVERALL (pooled)", **{k.upper(): v for k, v in tot.items()},
                     "precision": round(p, 4), "TPR": round(r_, 4), "FPR": round(fpr, 4), "score": round(s, 4)})
        rows.append({"variant": vname, "category": "OVERALL (avg of categories)", "TP": "", "FP": "", "FN": "", "TN": "",
                     "precision": "", "TPR": "", "FPR": "", "score": round(sum(scores) / len(scores), 4)})

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    get = {(r["variant"], r["category"]): r for r in rows}
    print(f"{'variant':28}{'TPR':>7}{'FPR':>7}{'pooled':>8}{'bm-avg':>8}")
    for v in variants:
        p = get[(v, "OVERALL (pooled)")]
        print(f"{v:28}{p['TPR']:>7.3f}{p['FPR']:>7.3f}{p['score']:>8.3f}{get[(v, 'OVERALL (avg of categories)')]['score']:>8.3f}")


if __name__ == "__main__":
    main()
