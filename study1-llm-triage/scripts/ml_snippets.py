#!/usr/bin/env python3
"""Random Forest triage of an items file (realworld / juliet).

Same features as ml_triage.py (TF-IDF of code tokens + rule id), applied to the code window each item
shows the LLM (triage_snippets.window). Training data (--train):
  owasp         all Semgrep findings of OWASP BenchmarkJava (labels from expectedresults)
  owasp+juliet  the above plus all Semgrep/CodeQL findings in Juliet bad (real) / good (fake) methods
                of every CWE family, with the same masked windows the LLM sees
Design: train on OWASP + Juliet, test on the real-world CVE findings;
OWASP -> Juliet is kept as a secondary transfer result. Training and test sets are different
datasets, so no test unit can leak into training. Writes verdicts in triage_snippets.py's raw format
(so eval_snippets.py scores RF and LLM alike) and the training setup to meta.jsonl.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from juliet_rf_transfer import features  # noqa: E402
from ml_triage import code_text  # noqa: E402
from score_owasp import load_expected  # noqa: E402
from triage_llm import relevant_findings  # noqa: E402
from triage_snippets import window  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--items", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--train", choices=["owasp", "owasp+juliet"], default="owasp")
    args = ap.parse_args()

    tests = load_expected(next((ROOT / "datasets/BenchmarkJava").glob("expectedresults-*.csv")))
    train = list(relevant_findings(ROOT / "results/pilot/semgrep.sarif", ROOT / "results/pilot/semgrep_score_per_test.csv"))
    texts = [code_text(f) for f in train]
    rules = [f["rule_id"] for f in train]
    labels = [int(tests[f["test"]]["real"]) for f in train]
    n_juliet = 0
    if args.train == "owasp+juliet":
        import build_items
        pool = build_items.juliet_pool(["semgrep", "codeql"], owasp_only=False)
        for it in pool:
            texts.append(window(it, 60, 60)[0])
            rules.append(it["rule_id"])
            labels.append(1 if it["label"] == "real" else 0)
        n_juliet = len(pool)
    y = np.array(labels, dtype=int)
    X, tfidf, onehot = features(True, texts, np.array([[r] for r in rules]))
    rf = RandomForestClassifier(n_estimators=300, n_jobs=args.jobs, random_state=42, class_weight="balanced").fit(X, y)

    items = [json.loads(l) for l in open(args.items)]
    wins = [window(it, 60, 60) for it in items]
    Xi, *_ = features(False, [w[0] for w in wins], np.array([[it["rule_id"]] for it in items]), tfidf, onehot)
    p = rf.predict_proba(Xi)[:, list(rf.classes_).index(1)]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for it, (_, lo, hi), pr in zip(items, wins, p):
            raw = {"reasoning": f"Random Forest (trained on {args.train}) P(real)={pr:.3f}",
                   "verdict": "true_positive" if pr >= 0.5 else "false_positive",
                   "confidence": round(float(max(pr, 1 - pr)), 4), "evidence_lines": [it["start_line"]]}
            fh.write(json.dumps(dict(it, model=f"random-forest-{args.train}", raw=json.dumps(raw), error=None,
                                     window=[lo, hi], p_real=round(float(pr), 4))) + "\n")
    with open(out.with_name("meta.jsonl"), "a") as mf:
        mf.write(json.dumps({"model": "random-forest", "train": args.train, "train_owasp_findings": len(train),
                             "train_juliet_findings": n_juliet, "train_real": int(y.sum()), "train_fake": int((1 - y).sum()),
                             "features": "TF-IDF code tokens (1-2 grams, min_df 2, 20k) + rule id one-hot; window 60/60",
                             "rf": "300 trees, class_weight balanced, seed 42", "test_items": args.items}) + "\n")
    print(f"{len(items)} items scored by RF (train={args.train}, {len(train)} OWASP + {n_juliet} Juliet) -> {out}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
