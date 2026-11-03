#!/usr/bin/env python3
"""Does the Random Forest triage model learned on OWASP Benchmark transfer to Juliet?

Train: Semgrep findings on OWASP BenchmarkJava (same features/labels as ml_triage.py).
Test:  Semgrep findings on Juliet Java 1.3 that lie in a bad (label real) or good (label not real)
       method of a test case whose CWE family matches the finding (OWASP-overlap and other CWEs).
Reports accuracy, how many real/fake findings the model would dismiss, and the Juliet score of
Semgrep alone vs Semgrep + RF triage (a case stays flagged if any matching finding is kept).
For reference it also runs a grouped 5-fold CV inside Juliet (by test case).
"""
import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from ml_triage import TOKEN, code_text  # noqa: E402
from score_juliet import OWASP, family  # noqa: E402
from score_owasp import load_expected, metrics, rule_cwes  # noqa: E402
from triage_llm import relevant_findings, strip_comments  # noqa: E402

J = ROOT / "datasets/juliet-java/src/Java"


def juliet_findings(sarif_path, manifest_path):
    data = json.loads(gzip.open(sarif_path).read())
    by_file = defaultdict(list)
    for run in data["runs"]:
        rules = {r["id"]: rule_cwes(r) for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            loc = res["locations"][0]["physicalLocation"]
            name = loc["artifactLocation"]["uri"].rsplit("/", 1)[-1]
            by_file[name].append((res["ruleId"], loc["region"]["startLine"], rules.get(res["ruleId"], set())))
    out = []
    with gzip.open(manifest_path, "rt") as fh:
        for line in fh:
            c = json.loads(line)
            fam = family(c["cwe"])
            owasp = next((k for k, v in OWASP.items() if c["cwe"] in v), None)
            for kind, label in (("bad", 1), ("good", 0)):
                for r in c[kind]:
                    for rule, ln, cwes in by_file.get(r["file"].rsplit("/", 1)[-1], []):
                        if r["start"] <= ln <= r["end"] and cwes & fam:
                            out.append({"case": c["case"], "cwe": c["cwe"], "owasp": owasp, "rule_id": rule,
                                        "file": r["file"], "kind": kind, "y": label})
    return out


def features(fit, texts, rules, tfidf=None, onehot=None):
    if fit:
        tfidf = TfidfVectorizer(token_pattern=TOKEN, lowercase=False, ngram_range=(1, 2), min_df=2, max_features=20000)
        onehot = OneHotEncoder(handle_unknown="ignore")
        X = hstack([tfidf.fit_transform(texts), onehot.fit_transform(rules)]).tocsr()
    else:
        X = hstack([tfidf.transform(texts), onehot.transform(rules)]).tocsr()
    return X, tfidf, onehot


def juliet_score(items, keep):
    """Juliet score over the cases that have at least one finding (bad/good flagged if any kept finding)."""
    bad, good = defaultdict(bool), defaultdict(bool)
    cases = {it["case"] for it in items}
    for it, k in zip(items, keep):
        if k:
            (bad if it["kind"] == "bad" else good)[it["case"]] = True
    tp = sum(bad[c] for c in cases)
    fp = sum(good[c] for c in cases)
    return metrics(tp, fp, len(cases) - tp, len(cases) - fp), len(cases)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juliet-sarif", default=str(ROOT / "results/juliet/semgrep/semgrep.sarif.gz"))
    ap.add_argument("--manifest", default=str(ROOT / "data/juliet-java/manifest.jsonl.gz"))
    ap.add_argument("--out", default=str(ROOT / "results/juliet/rf_transfer.json"))
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    tests = load_expected(next((ROOT / "datasets/BenchmarkJava").glob("expectedresults-*.csv")))
    owasp_f = list(relevant_findings(ROOT / "results/pilot/semgrep.sarif", ROOT / "results/pilot/semgrep_score_per_test.csv"))
    y_tr = np.array([tests[f["test"]]["real"] for f in owasp_f], dtype=int)
    X_tr, tfidf, onehot = features(True, [code_text(f) for f in owasp_f], np.array([[f["rule_id"]] for f in owasp_f]))
    rf = RandomForestClassifier(n_estimators=300, n_jobs=args.jobs, random_state=42, class_weight="balanced").fit(X_tr, y_tr)

    items = juliet_findings(args.juliet_sarif, args.manifest)
    texts_cache = {}

    def jtext(path):
        if path not in texts_cache:
            texts_cache[path] = strip_comments((J / path).read_text(errors="replace"))
        return texts_cache[path]

    texts = [jtext(it["file"]) for it in items]
    rules = np.array([[it["rule_id"]] for it in items])
    y = np.array([it["y"] for it in items])
    X_te, *_ = features(False, texts, rules, tfidf, onehot)
    p = rf.predict_proba(X_te)[:, list(rf.classes_).index(1)]
    keep = p >= 0.5

    result = {"train_findings_owasp": len(owasp_f), "juliet_findings": len(items),
              "juliet_findings_real": int(y.sum()), "juliet_findings_fake": int((1 - y).sum()),
              "transfer_accuracy": round(float((keep == y).mean()), 4),
              "dismissed_real": int(((~keep) & (y == 1)).sum()), "dismissed_fake": int(((~keep) & (y == 0)).sum())}
    for name, sel in (("all", [True] * len(items)), ("owasp_overlap", [it["owasp"] is not None for it in items])):
        sub = [i for i, s in enumerate(sel) if s]
        its = [items[i] for i in sub]
        (pb, rb, fb, sb), n = juliet_score(its, [True] * len(its))
        (pr, rr, fr, sr), _ = juliet_score(its, [bool(keep[i]) for i in sub])
        result[name] = {"cases_with_findings": n, "semgrep_alone": {"TPR": round(rb, 4), "FPR": round(fb, 4), "score": round(sb, 4)},
                        "semgrep_plus_rf": {"TPR": round(rr, 4), "FPR": round(fr, 4), "score": round(sr, 4)}}

    # reference: grouped 5-fold CV inside Juliet
    groups = np.array([it["case"] for it in items])
    pin = np.zeros(len(items))
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(texts, y, groups):
        Xa, tf2, oh2 = features(True, [texts[i] for i in tr], rules[tr])
        Xb, *_ = features(False, [texts[i] for i in te], rules[te], tf2, oh2)
        m = RandomForestClassifier(n_estimators=300, n_jobs=args.jobs, random_state=42, class_weight="balanced").fit(Xa, y[tr])
        pin[te] = m.predict_proba(Xb)[:, list(m.classes_).index(1)] if 1 in m.classes_ else 0.0
    result["juliet_internal_cv_accuracy"] = round(float(((pin >= 0.5) == y).mean()), 4)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
