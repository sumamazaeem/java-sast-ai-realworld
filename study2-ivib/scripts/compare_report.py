#!/usr/bin/env python3
"""Steps 6-7: one comparison of every method on every test set, significance tests, figures, and a
plain-English results page.

Inputs (all under results/ivib/): metrics.csv (score_units.py), preds/*.csv, replication_ivib.csv,
slices_*.csv, specs_summary.csv, ivib_release_audit.md.
Outputs: results/ivib/comparison.csv, significance.csv, fig_f1.png, fig_coverage.png, RESULTS.md
McNemar's test (scripts/mcnemar.py) compares our best model with each baseline on the same units.
"""
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcnemar import mcnemar  # noqa: E402

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
R = Path(__file__).resolve().parents[2] / "results/ivib"
TEST_SETS = ["cwebench", "javacve", "cvefixes"]
NAMES = {
    "codeql": "CodeQL", "semgrep": "Semgrep",
    "ivib-synth-ivib5": "IVIB-R (synthetic training, IVIB specs)",
    "ivib-synth-ivib5p": "IVIB-R (synthetic, + parameters as sources)",
    "ivib-synth-llm": "IVIB-R + LLM specs (Enh. 1)",
    "ivib-real-ivib5p": "IVIB-R + real fix training (Enh. 2)",
    "ivib-real-llm": "IVIB-R + LLM specs + real fixes (Enh. 1+2)",
    "codebert-synth": "CodeBERT (synthetic training)",
    "codebert-real": "CodeBERT (+ real fix training)",
}
OURS = "ivib-real-llm"


def rows(p):
    return list(csv.DictReader(open(p))) if p.exists() else []


def preds(method, ds):
    p = R / "preds" / f"{method}_{ds}.csv"
    return {r["id"]: int(r["pred"]) for r in rows(p)}


def labels(ds):
    p = DATA / "units" / f"{ds}.jsonl"
    return {u["id"]: u["label"] for u in (json.loads(l) for l in open(p))} if p.exists() else {}


def main():
    m = [r for r in rows(R / "metrics.csv") if r["group"] == "all"]
    comp = R / "comparison.csv"
    with open(comp, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "method", "n", "coverage", "precision", "recall", "f1", "mcc", "pair_correct"])
        for ds in ["owasp", "juliet"] + TEST_SETS:
            for r in sorted((r for r in m if r["dataset"] == ds), key=lambda r: -float(r["f1"])):
                w.writerow([ds, NAMES.get(r["method"], r["method"]), r["n"], r["coverage"], r["precision"],
                            r["recall"], r["f1"], r["mcc"], r["pair_correct"]])
    sig = []
    for ds in TEST_SETS:
        lab = labels(ds)
        ours = preds(OURS, ds)
        for other in NAMES:
            if other == OURS:
                continue
            th = preds(other, ds)
            common = set(ours) & set(th) & set(lab)
            if not common:
                continue
            b = sum(1 for i in common if (ours[i] == lab[i]) and (th[i] != lab[i]))
            c = sum(1 for i in common if (ours[i] != lab[i]) and (th[i] == lab[i]))
            t = mcnemar(b, c)
            sig.append([ds, NAMES[OURS], NAMES[other], len(common), b, c, t["method"], round(t["p"], 6)])
    with open(R / "significance.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "ours", "other", "units", "ours_right_other_wrong", "ours_wrong_other_right",
                    "test", "p"])
        w.writerows(sig)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    methods = [k for k in NAMES if any(r["method"] == k for r in m)]
    fig, ax = plt.subplots(figsize=(10, 4.5))
    width = 0.8 / max(len(methods), 1)
    for i, k in enumerate(methods):
        ys = [next((float(r["f1"]) for r in m if r["method"] == k and r["dataset"] == ds), 0) for ds in TEST_SETS]
        ax.bar([x + i * width for x in range(len(TEST_SETS))], ys, width, label=NAMES[k])
    ax.set_xticks([x + width * (len(methods) - 1) / 2 for x in range(len(TEST_SETS))])
    ax.set_xticklabels(["CWE-Bench-Java", "Java CVE Benchmark", "CVEfixes (held-out projects)"])
    ax.set_ylabel("F1 (method level)")
    ax.set_ylim(0, 1)
    ax.legend(fontsize=7, ncol=2)
    ax.set_title("Real-world projects not seen in training, 5 injection CWEs")
    fig.tight_layout()
    fig.savefig(R / "fig_f1.png", dpi=150)

    cov = defaultdict(dict)
    for sp in ("ivib", "ivib5", "ivib5p", "llm"):
        agg = defaultdict(lambda: [0, 0])
        for r in rows(R / f"slices_{sp}.csv"):
            agg[r["dataset"]][0] += int(r["units"])
            agg[r["dataset"]][1] += int(r["sliced"])
        for ds, (n, s) in agg.items():
            cov[ds][sp] = s / n if n else 0
    fig, ax = plt.subplots(figsize=(9, 4))
    dss = [d for d in ["owasp", "juliet"] + TEST_SETS if d in cov]
    sps = ["ivib", "ivib5", "ivib5p", "llm"]
    for i, sp in enumerate(sps):
        ax.bar([x + i * 0.2 for x in range(len(dss))], [cov[d].get(sp, 0) for d in dss], 0.2, label=sp)
    ax.set_xticks([x + 0.3 for x in range(len(dss))])
    ax.set_xticklabels(dss)
    ax.set_ylabel("share of methods with a source-to-sink slice")
    ax.legend()
    fig.tight_layout()
    fig.savefig(R / "fig_coverage.png", dpi=150)

    rep = rows(R / "replication_ivib.csv")
    lines = ["# IVIB enhancement experiments: results", "",
             "Generated by scripts/ivib/compare_report.py. Plain-English notes in brackets.", "",
             "## Step 2: repeating the base paper (OWASP + Juliet, 5-fold cross-validation)", ""]
    if rep:
        keys = ["accuracy", "weighted_f1", "macro_f1", "binary_f1"]
        mean = {k: sum(float(r[k]) for r in rep) / len(rep) for k in keys}
        lines += [f"Folds done: {len(rep)}. Mean accuracy {mean['accuracy']:.4f}, weighted F1 "
                  f"{mean['weighted_f1']:.4f}, macro F1 {mean['macro_f1']:.4f}, vulnerable-or-not F1 "
                  f"{mean['binary_f1']:.4f}. The paper reports F1 0.9693.", ""]
    lines += ["## Steps 3-6: real projects (method level)", "",
              "| Test set | Method | Coverage | Precision | Recall | F1 | MCC | Pair-correct |", "|---|---|---|---|---|---|---|---|"]
    for r in rows(comp):
        if r["dataset"] in TEST_SETS:
            lines.append(f"| {r['dataset']} | {r['method']} | {r['coverage']} | {r['precision']} | {r['recall']} | "
                         f"{r['f1']} | {r['mcc']} | {r['pair_correct']} |")
    lines += ["", "(F1 is misleading on these sets, which are balanced bug/fix pairs: a tool that says vulnerable for everything gets F1 0.63. MCC = Matthews correlation, 0 means chance, 1 perfect. Coverage = share of methods the tool gave an answer for. Pair-correct = share of real "
              "bug/fix pairs where the tool flags the buggy version and not the fixed one.)", "",
              "Significance: results/ivib/significance.csv (McNemar's test, our full model vs each other method).",
              "Figures: fig_f1.png, fig_coverage.png. Release audit: ivib_release_audit.md."]
    (R / "RESULTS.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
