#!/usr/bin/env python3
"""Figures for the paper (vector PDF + PNG). Numbers come from results files; see comments.

usage: python3 -I make_figures.py <tables dir with m2_metrics_ci.csv> <results/ivib dir> <out dir>
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

TAB, RES, OUT = map(Path, sys.argv[1:4])
OUT.mkdir(parents=True, exist_ok=True)
S1, S2, S3, S4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"  # categorical slots 1-4 (validated order)
INK, INK2, GRID = "#0b0b0b", "#52514e", "#d9d8d4"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
                     "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42})


def save(fig, name):
    fig.tight_layout(pad=0.3)
    fig.savefig(OUT / f"{name}.pdf")
    fig.savefig(OUT / f"{name}.png", dpi=300)
    plt.close(fig)


# Fig. 1: method 1, real-world Java CVEs, real findings lost vs other findings removed
# (results/FINAL_COMPARISON.md, Java CVE Benchmark, pooled 'all' rows; 90 real, 597 other)
rows = [("Random Forest", 83, 499, 14, 361), ("Qwen2.5-Coder 7B", 33, 365, 9, 313),
        ("Llama 3.1 8B", 20, 339, 5, 286)]
fig, ax = plt.subplots(figsize=(3.4, 2.3))
for (name, lu, ru, lg, rg), c in zip(rows, (S1, S2, S3)):
    ax.annotate("", xy=(rg / 597 * 100, lg / 90 * 100), xytext=(ru / 597 * 100, lu / 90 * 100),
                arrowprops=dict(arrowstyle="->", color=c, lw=1.2))
    ax.plot(ru / 597 * 100, lu / 90 * 100, "o", ms=6, mfc="white", mec=c, mew=1.5)
    ax.plot(rg / 597 * 100, lg / 90 * 100, "o", ms=6, color=c, mec="white", mew=1)
    ax.text(ru / 597 * 100 + 1.5, lu / 90 * 100 + 2, name, color=INK, fontsize=7)
ax.plot([], [], "o", mfc="white", mec=INK2, label="no guardrails")
ax.plot([], [], "o", color=INK2, label="guardrails v2")
ax.set_xlabel("Other findings removed (% of 597)")
ax.set_ylabel("Real findings lost (% of 90)")
ax.set_xlim(40, 95)
ax.set_ylim(0, 100)
ax.legend(loc="upper left", fontsize=7)
save(fig, "fig1-m1-realworld-tradeoff")

# Fig. 2: method 2, CWE-Bench-Java, F1 vs MCC vs pair accuracy (tables/m2_metrics_ci.csv)
m = {(r["method"], r["dataset"]): r for r in csv.DictReader(open(TAB / "m2_metrics_ci.csv"))}
order = [("codebert-synth", "CodeBERT\n(synthetic)"), ("ivib-synth-ivib5", "IVIB-R\n(IVIB lists)"),
         ("ivib-synth-ivib5p", "IVIB-R\n(+params)"), ("codebert-real", "CodeBERT\n(+real fixes)")]
fig, ax = plt.subplots(figsize=(3.4, 2.3))
w = 0.26
for j, (key, lab, c) in enumerate([("f1", "F1", S1), ("mcc", "MCC", S2), ("pair_acc", "Pair accuracy", S3)]):
    xs, ys, lo, hi = [], [], [], []
    for i, (meth, _) in enumerate(order):
        r = m[(meth, "cwebench")]
        y = float(r[key])
        xs.append(i + (j - 1) * w)
        ys.append(y)
        lo.append(y - float(r[key + "_lo"]))
        hi.append(float(r[key + "_hi"]) - y)
    ax.bar(xs, ys, w * 0.9, color=c, label=lab, yerr=[lo, hi], error_kw=dict(lw=0.7, capsize=1.5, ecolor=INK2))
ax.axhline(0, color=INK2, lw=0.6)
ax.set_xticks(range(len(order)))
ax.set_xticklabels([o[1] for o in order], fontsize=7)
ax.set_ylim(-0.2, 0.75)
ax.set_ylabel("Score on CWE-Bench-Java")
ax.legend(ncol=3, fontsize=7, loc="upper right")
save(fig, "fig2-m2-metrics-cwebench")

# Fig. 3: method 2, slice coverage of vulnerable units (results/ivib/slices_*.csv)
def cov(f):
    agg = defaultdict(lambda: [0, 0])
    for r in csv.DictReader(open(RES / f)):
        if r["label"] == "1":
            agg[r["dataset"]][0] += int(r["units"])
            agg[r["dataset"]][1] += int(r["sliced"])
    return {k: v[1] / v[0] * 100 for k, v in agg.items()}


specs = [("slices_ivib5.csv", "IVIB lists", S1), ("slices_ivib5p.csv", "+ method parameters", S2),
         ("slices_llm.csv", "LLM-inferred lists", S3)]
dsets = [("owasp", "OWASP"), ("juliet", "Juliet"), ("cvefixes", "CVEfixes"), ("cwebench", "CWE-\nBench"),
         ("javacve", "Java CVE\nBench.")]
fig, ax = plt.subplots(figsize=(3.4, 2.2))
for j, (f, lab, c) in enumerate(specs):
    cv = cov(f)
    ax.bar([i + (j - 1) * w for i in range(len(dsets))], [cv[d] for d, _ in dsets], w * 0.9, color=c, label=lab)
ax.set_xticks(range(len(dsets)))
ax.set_xticklabels([d[1] for d in dsets], fontsize=7)
ax.set_ylabel("Vulnerable units with a\nsource-to-sink slice (%)")
ax.set_ylim(0, 100)
ax.legend(fontsize=7, loc="upper right")
save(fig, "fig3-m2-slice-coverage")
print("ok")
