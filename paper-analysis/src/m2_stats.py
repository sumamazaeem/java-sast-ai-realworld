#!/usr/bin/env python3
"""Method 2 (IVIB enhancement) statistics for the paper.

Reads results/ivib/units_labels.csv and results/ivib/preds/*.csv (from the experiment branch) and writes:
  tables/m2_metrics_ci.csv   precision/recall/F1/MCC/pair-accuracy with project-clustered bootstrap 95% CIs
  tables/m2_mcnemar.csv      paired McNemar tests between methods (unit = method), Holm-adjusted
Every method is scored on the same units: for CVEfixes only the held-out 20% of projects (heldout=1),
so models trained on real fixes and models trained on synthetic code see identical test units.

usage: python3 -I m2_stats.py <results/ivib dir> <out dir>
"""
import csv
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

from scipy.stats import binomtest, chi2

B, SEED = 2000, 42
RES, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

labels = {}
for r in csv.DictReader(open(RES / "units_labels.csv")):
    labels[r["id"]] = r


def in_test(u):
    if u["dataset"] == "cvefixes":
        return u["heldout"] == "1"
    return u["dataset"] in ("cwebench", "javacve")


preds = defaultdict(dict)  # (method, dataset) -> id -> pred
for p in sorted((RES / "preds").glob("*.csv")):
    method, ds = p.stem.rsplit("_", 1)
    if ds not in ("cwebench", "javacve", "cvefixes"):
        continue
    for r in csv.DictReader(open(p)):
        u = labels.get(r["id"])
        if u and in_test(u):
            preds[(method, ds)][r["id"]] = int(r["pred"])


def metrics(ids, pr):
    tp = fp = fn = tn = 0
    pairs = defaultdict(dict)
    for i in ids:
        y, p = int(labels[i]["label"]), pr[i]
        tp += y and p
        fp += (not y) and p
        fn += y and not p
        tn += (not y) and not p
        if labels[i]["pair_id"]:
            pairs[labels[i]["pair_id"]][y] = p
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / den if den else 0.0
    full = [v for v in pairs.values() if 0 in v and 1 in v]
    pa = sum(1 for v in full if v[1] == 1 and v[0] == 0) / len(full) if full else float("nan")
    return dict(n=len(ids), tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, mcc=mcc,
                pairs=len(full), pair_acc=pa)


def clustered(ids):
    by = defaultdict(list)
    for i in ids:
        by[labels[i]["project"]].append(i)
    return list(by.values())


rows = []
for (method, ds), pr in sorted(preds.items()):
    ids = sorted(pr)
    est = metrics(ids, pr)
    groups = clustered(ids)
    rng = random.Random(SEED)
    samples = defaultdict(list)
    for _ in range(B):
        bs = [i for g in (rng.choice(groups) for _ in groups) for i in g]
        m = metrics(bs, pr)
        for k in ("precision", "recall", "f1", "mcc", "pair_acc"):
            if not math.isnan(m[k]):
                samples[k].append(m[k])
    row = dict(method=method, dataset=ds, projects=len(groups), **est)
    for k, v in samples.items():
        v.sort()
        row[k + "_lo"] = v[int(0.025 * len(v))]
        row[k + "_hi"] = v[min(len(v) - 1, int(0.975 * len(v)))]
    rows.append(row)

keys = list(rows[0].keys())
for r in rows:
    for k in r:
        if k not in keys:
            keys.append(k)
with open(OUT / "m2_metrics_ci.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=keys)
    w.writeheader()
    for r in rows:
        w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})

# Paired McNemar on per-unit correctness, planned comparisons only.
PLAN = [("codebert-real", "codebert-synth"), ("codebert-real", "ivib-synth-ivib5p"),
        ("ivib-synth-ivib5p", "ivib-synth-ivib5"), ("ivib-synth-llm", "ivib-synth-ivib5p"),
        ("ivib-real-ivib5p", "ivib-synth-ivib5p"), ("ivib-real-llm", "ivib-real-ivib5p"),
        ("codeql", "codebert-real"), ("codeql", "ivib-synth-ivib5p")]
tests = []
for a, b in PLAN:
    for ds in ("cwebench", "cvefixes", "javacve"):
        pa, pb = preds.get((a, ds)), preds.get((b, ds))
        if not pa or not pb:
            continue
        ids = sorted(set(pa) & set(pb))
        only_a = sum(1 for i in ids if (pa[i] == int(labels[i]["label"])) and pb[i] != int(labels[i]["label"]))
        only_b = sum(1 for i in ids if (pb[i] == int(labels[i]["label"])) and pa[i] != int(labels[i]["label"]))
        nd = only_a + only_b
        if nd == 0:
            p, test = 1.0, "none"
        elif nd < 25:
            p, test = binomtest(only_a, nd, 0.5).pvalue, "exact binomial"
        else:
            stat = (abs(only_a - only_b) - 1) ** 2 / nd
            p, test = chi2.sf(stat, 1), "chi-square (cc)"
        tests.append(dict(a=a, b=b, dataset=ds, units=len(ids), only_a=only_a, only_b=only_b, test=test, p=p))
# Holm over all planned tests
order = sorted(range(len(tests)), key=lambda i: tests[i]["p"])
m, run = len(tests), 0.0
for rank, i in enumerate(order):
    run = max(run, min(1.0, (m - rank) * tests[i]["p"]))
    tests[i]["p_holm"] = run
with open(OUT / "m2_mcnemar.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(tests[0].keys()))
    w.writeheader()
    for t in tests:
        w.writerow({k: (f"{v:.3g}" if isinstance(v, float) else v) for k, v in t.items()})
print(open(OUT / "m2_metrics_ci.csv").read())
print(open(OUT / "m2_mcnemar.csv").read())
