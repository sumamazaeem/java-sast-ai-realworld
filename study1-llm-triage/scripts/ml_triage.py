#!/usr/bin/env python3
"""Classical ML triage baseline: Random Forest over warning + code features, cross-validated.

Same findings as triage_llm.py (Semgrep findings that count toward the Benchmark score).
Features: rule id (one-hot) + TF-IDF of code tokens of the comment-stripped file.
Label: whether the finding's test case is a real vulnerability (expected results).
Cross-validation: 5-fold StratifiedGroupKFold grouped by test case, so findings of one test
never sit in both train and test; or leave-one-category-out (train on the other vulnerability
categories), which shows how much the model relies on Benchmark's per-category templates.
Every finding is predicted by a model that did not see it.

Writes records in the triage_llm.py raw.jsonl format (raw = JSON verdict), so eval_triage.py
applies the same decision policies and scoring.
"""
import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import LeaveOneGroupOut, StratifiedGroupKFold
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from score_owasp import load_expected  # noqa: E402
from triage_llm import relevant_findings, strip_comments  # noqa: E402

TOKEN = r"[A-Za-z_][A-Za-z0-9_]*|[(){}\[\];=+?:.,<>!]"


def code_text(f):
    src = strip_comments((ROOT / f["uri"]).read_text(), f["uri"])
    return re.sub(r"BenchmarkTest\d{5}", "TESTNAME", src)  # test ids carry no signal


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", default=str(ROOT / "results/pilot/semgrep.sarif"))
    ap.add_argument("--per-test", default=str(ROOT / "results/pilot/semgrep_score_per_test.csv"))
    ap.add_argument("--expected", default=str(next((ROOT / "datasets/BenchmarkJava").glob("expectedresults-*.csv"))))
    ap.add_argument("--out", default=str(ROOT / "results/triage/ml_rf/raw.jsonl"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--cv", choices=["group-kfold", "leave-one-category-out"], default="group-kfold",
                    help="leave-one-category-out trains on the other vulnerability categories only")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    tests = load_expected(args.expected)
    findings = list(relevant_findings(args.sarif, args.per_test))
    y = np.array([tests[f["test"]]["real"] for f in findings], dtype=int)
    groups = np.array([f["test"] for f in findings])
    texts = [code_text(f) for f in findings]
    rules = np.array([[f["rule_id"]] for f in findings])

    proba = np.zeros(len(findings))
    if args.cv == "group-kfold":
        splits = StratifiedGroupKFold(n_splits=args.folds, shuffle=True, random_state=args.seed).split(texts, y, groups)
    else:
        cats = np.array([tests[f["test"]]["category"] for f in findings])
        splits = LeaveOneGroupOut().split(texts, y, cats)
    for fold, (tr, te) in enumerate(splits):
        tfidf = TfidfVectorizer(token_pattern=TOKEN, lowercase=False, ngram_range=(1, 2), min_df=2, max_features=20000)
        onehot = OneHotEncoder(handle_unknown="ignore")
        Xtr = hstack([tfidf.fit_transform([texts[i] for i in tr]), onehot.fit_transform(rules[tr])]).tocsr()
        Xte = hstack([tfidf.transform([texts[i] for i in te]), onehot.transform(rules[te])]).tocsr()
        rf = RandomForestClassifier(n_estimators=300, n_jobs=args.jobs, random_state=args.seed, class_weight="balanced")
        rf.fit(Xtr, y[tr])
        p = rf.predict_proba(Xte)
        proba[te] = p[:, list(rf.classes_).index(1)] if 1 in rf.classes_ else 0.0
        acc = ((proba[te] >= 0.5) == y[te]).mean()
        print(f"fold {fold}: train={len(tr)} test={len(te)} accuracy={acc:.3f}", file=sys.stderr)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for f, p in zip(findings, proba):
            verdict = "true_positive" if p >= 0.5 else "false_positive"
            raw = {"reasoning": f"Random Forest P(real)={p:.3f}", "verdict": verdict,
                   "confidence": round(float(max(p, 1 - p)), 4), "evidence_lines": [f["start_line"]]}
            fh.write(json.dumps(dict(f, model="random-forest", raw=json.dumps(raw), error=None,
                                     p_real=round(float(p), 4))) + "\n")
    print(f"overall accuracy={((proba >= 0.5) == y).mean():.3f} on {len(findings)} findings", file=sys.stderr)


if __name__ == "__main__":
    main()
