#!/usr/bin/env python3
"""Summarise the method 1 robustness runs (scripts/m1_robustness.sh) against the reference run.

For each run and policy (unguarded, guarded = frozen v2): real findings lost (of 90), other findings
removed (of 597), and precision of kept findings; for the temperature runs also mean and range over
seeds, the share of findings whose unguarded verdict flips between seeds, and an exact McNemar test of
v2 vs unguarded per run. Writes results/robustness_realworld/summary.md and summary.csv.
"""
import csv
import statistics
from pathlib import Path

from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "results/robustness_realworld"
RUNS = [("reference (zero-shot, T=0)", ROOT / "results/triage_realworld/qwen2.5-coder_7b/per_test.csv"),
        ("few-shot, T=0", BASE / "qwen7b_fewshot/per_test.csv")] + \
       [(f"zero-shot, T=0.7, seed {s}", BASE / f"qwen7b_t07_s{s}/per_test.csv") for s in (1, 2, 3)]


def load(p):
    out = {}
    for r in csv.DictReader(open(p)):
        if r["policy"] in ("unguarded", "guarded"):
            out[(r["policy"], r["test"])] = (int(r["flagged"]), r["real"])
    return out


def stats(d, pol):
    rs = [(f, real) for (p, _), (f, real) in d.items() if p == pol]
    lost = sum(1 for f, real in rs if real == "1" and not f)
    removed = sum(1 for f, real in rs if real != "1" and not f)
    kept_real = sum(1 for f, real in rs if real == "1" and f)
    kept = sum(1 for f, _ in rs if f)
    return lost, removed, kept_real / kept if kept else 0.0


rows, data = [], {}
for name, p in RUNS:
    if not p.exists():
        rows.append(dict(run=name, policy="-", real_lost="PENDING", other_removed="", precision_kept="", mcnemar_p=""))
        continue
    d = data[name] = load(p)
    reals = [t for (pol, t), (_, real) in d.items() if pol == "unguarded" and real == "1"]
    a = sum(1 for t in reals if d[("guarded", t)][0] and not d[("unguarded", t)][0])  # only v2 keeps it
    b = sum(1 for t in reals if not d[("guarded", t)][0] and d[("unguarded", t)][0])
    pval = binomtest(a, a + b, 0.5).pvalue if a + b else 1.0
    for pol in ("unguarded", "guarded"):
        lost, removed, prec = stats(d, pol)
        rows.append(dict(run=name, policy="v2" if pol == "guarded" else "none", real_lost=lost,
                         other_removed=removed, precision_kept=round(prec, 3),
                         mcnemar_p=f"{pval:.3g}" if pol == "guarded" else ""))

temp = [n for n in data if "T=0.7" in n]
lines = ["# Method 1 robustness on the real-world set (90 real, 597 other findings)", "",
         "| Run | Guardrails | Real lost (of 90) | Other removed (of 597) | Precision kept | McNemar p (v2 vs none, real findings) |",
         "|---|---|---|---|---|---|"]
lines += [f"| {r['run']} | {r['policy']} | {r['real_lost']} | {r['other_removed']} | {r['precision_kept']} | {r['mcnemar_p']} |" for r in rows]
if len(temp) >= 2:
    lines.append("")
    for pol, lab in (("unguarded", "no guardrails"), ("guarded", "guardrails v2")):
        v = [stats(data[n], pol)[0] for n in temp]
        lines.append(f"- T=0.7, {lab}: real lost mean {statistics.mean(v):.1f}, range {min(v)}-{max(v)} over {len(v)} seeds")
    ids = [t for (pol, t) in data[temp[0]] if pol == "unguarded"]
    flips = sum(1 for t in ids if len({data[n][("unguarded", t)][0] for n in temp}) > 1)
    lines.append(f"- Unguarded keep/dismiss decision differs between seeds for {flips} of {len(ids)} findings ({flips / len(ids):.1%})")
BASE.mkdir(parents=True, exist_ok=True)
(BASE / "summary.md").write_text("\n".join(lines) + "\n")
with open(BASE / "summary.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print("\n".join(lines))
