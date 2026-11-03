#!/usr/bin/env python3
"""Bootstrap 95% confidence intervals for the main triage comparison (Chapter 4, Table 4.10).

Units are resampled with replacement, B = 2000 replicates, seed 42, percentile intervals:
  OWASP Benchmark  test cases, stratified by category (category sizes fixed, as the Benchmark score
                   averages over categories). Metrics: precision, recall (TPR), FPR, F1, Benchmark score.
  Juliet           findings, clustered by test case (all findings of a resampled case come along).
                   Metrics on findings: precision of kept, recall (share of real findings kept), F1.
  Real-world CVEs  findings, clustered by CVE. Metrics: precision of kept (a lower bound: findings outside
                   the vulnerable method are unlabelled), recall, F1, share of other findings removed.
The difference "guardrails v2 minus raw SAST" and "guardrails v2 minus no guardrails" is bootstrapped on the
same replicates (paired). Read-only over results/; writes results/bootstrap/ci.csv.

Run: python3 -I scripts/bootstrap_ci.py
"""
import csv
import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
B, SEED = 2000, 42

# (dataset, tool, method label, per_test.csv, policies) -- the runs reported in Table 4.5
OWASP = [("owasp_java", "semgrep", "Random Forest", "triage/ml_rf/per_test.csv", ["baseline", "unguarded", "guarded"]),
         ("owasp_java", "semgrep", "Qwen2.5-Coder 7B", "triage/qwen2.5-coder_7b/per_test.csv", ["unguarded", "guarded"]),
         ("owasp_java", "semgrep", "Qwen2.5-Coder 14B", "triage/qwen2.5-coder_14b/per_test.csv", ["unguarded", "guarded"]),
         ("owasp_java", "codeql", "Qwen2.5-Coder 7B", "triage_codeql/qwen2.5-coder_7b/per_test.csv",
          ["baseline", "unguarded", "guarded"])]
SNIPPETS = [("juliet", "Qwen2.5-Coder 7B", "triage_juliet/qwen2.5-coder_7b/per_test_agree.csv",
             ["baseline", "unguarded", "guarded", "guarded+agree"]),
            ("juliet", "Llama 3.1 8B", "triage_juliet/llama3.1_8b/per_test.csv", ["unguarded", "guarded"]),
            ("juliet", "Random Forest (trained on OWASP)", "triage_juliet/rf_owasp/per_test.csv", ["unguarded", "guarded"]),
            ("java_cve", "Qwen2.5-Coder 7B", "triage_realworld/qwen2.5-coder_7b/per_test_agree.csv",
             ["baseline", "unguarded", "guarded", "guarded+agree"]),
            ("java_cve", "Llama 3.1 8B", "triage_realworld/llama3.1_8b/per_test.csv", ["unguarded", "guarded"]),
            ("java_cve", "Random Forest (trained on OWASP + Juliet)", "triage_realworld/rf_owasp_juliet/per_test.csv",
             ["unguarded", "guarded"])]


def per_test(rel):
    """{policy: {unit: (flagged, real or None, tool)}}"""
    out = defaultdict(dict)
    for r in csv.DictReader(open(R / rel)):
        out[r["policy"]][r["test"]] = (r["flagged"] == "1", None if r["real"] == "" else r["real"] == "1",
                                       r.get("tool", ""))
    return out


def safe(a, b):
    return a / b if b else float("nan")


def f1(p, r):
    return safe(2 * p * r, p + r)


def owasp_metrics(units, cats, dec):
    """units: list of test ids (with repeats); dec: {test: (flagged, real)}"""
    tp = fp = fn = tn = 0
    per = defaultdict(lambda: [0, 0, 0, 0])
    for u in units:
        fl, re = dec[u][0], dec[u][1]
        k = (0 if fl else 2) if re else (1 if fl else 3)
        per[cats[u]][k] += 1
        if re:
            tp, fn = tp + fl, fn + (not fl)
        else:
            fp, tn = fp + fl, tn + (not fl)
    p, r, fpr = safe(tp, tp + fp), safe(tp, tp + fn), safe(fp, fp + tn)
    score = sum(safe(c[0], c[0] + c[2]) - safe(c[1], c[1] + c[3]) for c in per.values()) / len(per)
    return {"precision": p, "recall": r, "fpr": fpr, "f1": f1(p, r), "score": score}


def snippet_metrics(units, dec):
    real = kept_real = other = removed_other = 0
    for u in units:
        fl, re = dec[u][0], dec[u][1]
        if re:
            real, kept_real = real + 1, kept_real + fl
        else:
            other, removed_other = other + 1, removed_other + (not fl)
    kept = kept_real + other - removed_other
    p, r = safe(kept_real, kept), safe(kept_real, real)
    return {"precision": p, "recall": r, "f1": f1(p, r), "other_removed": safe(removed_other, other),
            "real_lost": real - kept_real}


def pct(xs, q):
    xs = sorted(x for x in xs if x == x)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float("nan")


def summarise(rows, ds, tool, method, policy, point, reps):
    for m, v in point.items():
        vals = [rep[m] for rep in reps]
        rows.append({"dataset": ds, "tool": tool, "method": method, "policy": policy, "metric": m,
                     "estimate": round(v, 6), "ci_low": round(pct(vals, 0.025), 6),
                     "ci_high": round(pct(vals, 0.975), 6)})


def run_owasp(rows, rng):
    cats = {}
    for rel in ("pilot/semgrep_score_per_test.csv", "codeql/codeql_score_per_test.csv"):
        for r in csv.DictReader(open(R / rel)):
            cats[r["test"]] = r["category"]
    by_cat = defaultdict(list)
    for t, c in sorted(cats.items()):
        by_cat[c].append(t)
    samples = [[t for c in sorted(by_cat) for t in rng.choices(by_cat[c], k=len(by_cat[c]))] for _ in range(B)]
    allu = [t for c in sorted(by_cat) for t in by_cat[c]]
    for ds, tool, method, rel, pols in OWASP:
        if not (R / rel).exists():
            continue
        pt = per_test(rel)
        for pol in pols:
            dec = pt[pol]
            summarise(rows, ds, tool, "-" if pol == "baseline" else method, pol, owasp_metrics(allu, cats, dec),
                      [owasp_metrics(s, cats, dec) for s in samples])
        if "guarded" in pt:  # paired differences in the Benchmark score
            g = pt["guarded"]
            for other, lab in (("baseline", "score diff v2 - raw"), ("unguarded", "score diff v2 - unguarded")):
                o = pt[other]
                d = lambda us: owasp_metrics(us, cats, g)["score"] - owasp_metrics(us, cats, o)["score"]
                summarise(rows, ds, tool, method, "guarded", {lab: d(allu)}, [{lab: d(s)} for s in samples])


def run_snippets(rows, rng):
    cluster_key = {"juliet": "case", "java_cve": "cve"}
    items = {}
    for ds, f in (("juliet", "items/juliet.jsonl"), ("java_cve", "items/realworld.jsonl")):
        items[ds] = {json.loads(l)["id"]: json.loads(l) for l in open(R / f)}
    samples = {}
    for ds in items:
        clusters = defaultdict(list)
        for i in items[ds].values():
            clusters[i[cluster_key[ds]]].append(i["id"])
        keys = sorted(clusters)
        samples[ds] = (clusters, [[u for k in rng.choices(keys, k=len(keys)) for u in clusters[k]] for _ in range(B)])
    for ds, method, rel, pols in SNIPPETS:
        if not (R / rel).exists() or not (R / rel).stat().st_size:
            continue
        pt = per_test(rel)
        clusters, reps = samples[ds]
        allu = [u for k in sorted(clusters) for u in clusters[k]]
        for tool in ("all", "semgrep", "codeql"):
            keep = (lambda u: True) if tool == "all" else (lambda u, t=tool: items[ds][u]["tool"] == t)
            for pol in pols:
                dec = pt[pol]
                summarise(rows, ds, tool, "-" if pol == "baseline" else method, pol,
                          snippet_metrics([u for u in allu if keep(u)], dec),
                          [snippet_metrics([u for u in s if keep(u)], dec) for s in reps])


def main():
    rng = random.Random(SEED)
    rows = []
    run_owasp(rows, rng)
    run_snippets(rows, rng)
    out = R / "bootstrap"
    out.mkdir(exist_ok=True)
    with open(out / "ci.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {(out / 'ci.csv').relative_to(ROOT)} (B={B}, seed={SEED})")


if __name__ == "__main__":
    main()
