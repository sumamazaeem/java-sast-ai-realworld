#!/usr/bin/env python3
"""Apply the triage policies (eval_triage.py) to triage_snippets.py / ml_snippets.py output.

Unit = finding. For each dataset/tool and policy it reports how many real findings were kept or
wrongly dismissed and how many fake (Juliet good-method) or unlabelled (real-world, mostly false
alarms) findings were dismissed, plus precision of the kept findings where labels allow it.
Writes <dir>/scores.csv and <dir>/per_test.csv (unit = finding id; flagged = kept; real = 1/0, blank
when unlabelled; per_test_agree.csv when --agree-raw is given) next to the raw file, and per tool a scores.csv in eval_triage.py's column
format under results/triage_<tool>_<dataset>/<method>/ (method = the raw file's folder name):
findings_dismissed, dismissed_on_real_vuln_tests (inside a vulnerable/bad method),
dismissed_on_fake_vuln_tests (unlabelled for real-world, good-method for Juliet). For Juliet,
TP/FP/FN/TN, precision, TPR and FPR are counted per finding; for real-world they are left blank.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from eval_triage import decide, decide_agree, load_verdicts, policy_set  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--agree-raw", default=None, help="second model's raw.jsonl for the guarded+agree policy")
    args = ap.parse_args()
    other = load_verdicts(args.agree_raw) if args.agree_raw else None
    recs = [json.loads(l) for l in open(args.raw)]
    policies = policy_set(None, agree=other is not None, baseline=False)

    rows, per_test_rows = [], []
    groups = defaultdict(list)
    for r in recs:
        groups[(r["dataset"], r["tool"])].append(r)
        groups[(r["dataset"], "all")].append(r)
    for (ds, tool), rs in sorted(groups.items()):
        for name, (guards, min_conf) in [("baseline", (None, None))] + list(policies.items()):
            c = defaultdict(int)
            for r in rs:
                lo, hi = r.get("window") or [1, 10**9]
                lines = {r["uri"]: set(range(lo, hi + 1))}
                if guards is None:
                    dismiss = False
                elif name == "guarded+agree":
                    dismiss = decide_agree(r, guards, min_conf, lines, other)[0]
                else:
                    dismiss = decide(r, guards, min_conf, lines)[0]
                c[f"{r['label']}_{'dismissed' if dismiss else 'kept'}"] += 1
                if tool != "all":
                    per_test_rows.append({"test": r["id"], "policy": name, "flagged": int(not dismiss),
                                          "real": {"real": 1, "fake": 0}.get(r["label"], ""),
                                          "dataset": ds, "tool": tool})
            real = c["real_kept"] + c["real_dismissed"]
            neg = sum(v for k, v in c.items() if not k.startswith("real"))
            neg_kept = sum(v for k, v in c.items() if k.endswith("_kept") and not k.startswith("real"))
            rows.append({
                "dataset": ds, "tool": tool, "policy": name, "findings": len(rs),
                "real": real, "real_kept": c["real_kept"], "real_dismissed": c["real_dismissed"],
                "other": neg, "other_dismissed": neg - neg_kept,
                "real_retention": round(c["real_kept"] / real, 4) if real else "",
                "other_removed": round((neg - neg_kept) / neg, 4) if neg else "",
                "precision_kept": round(c["real_kept"] / (c["real_kept"] + neg_kept), 4) if c["real_kept"] + neg_kept else "",
            })
    method = Path(args.raw).parent.name + (f"+agree-{Path(args.agree_raw).parent.name}" if other is not None else "")
    for (ds, tool) in sorted({(r["dataset"], r["tool"]) for r in rows if r["tool"] != "all"}):
        conv = []
        for r in rows:
            if (r["dataset"], r["tool"]) != (ds, tool):
                continue
            tp, fn = r["real_kept"], r["real_dismissed"]
            fp, tn = r["other"] - r["other_dismissed"], r["other_dismissed"]
            juliet = ds == "juliet"
            prec = tp / (tp + fp) if juliet and tp + fp else ""
            tpr = tp / (tp + fn) if juliet and tp + fn else ""
            fpr = fp / (fp + tn) if juliet and fp + tn else ""
            conv.append({"policy": r["policy"], "findings_triaged": r["findings"], "tests_covered": "",
                         "findings_dismissed": r["real_dismissed"] + r["other_dismissed"],
                         "dismissed_on_fake_vuln_tests": r["other_dismissed"], "dismissed_on_real_vuln_tests": fn,
                         "findings_on_real_vuln_tests": r["real"],
                         "TP": tp if juliet else "", "FP": fp if juliet else "", "FN": fn if juliet else "",
                         "TN": tn if juliet else "",
                         "precision": round(prec, 4) if prec != "" else "", "TPR": round(tpr, 4) if tpr != "" else "",
                         "FPR": round(fpr, 4) if fpr != "" else "",
                         "score_pooled": round(tpr - fpr, 4) if tpr != "" and fpr != "" else "",
                         "score_benchmark_avg": "", "decision_reasons": ""})
        d = ROOT / "results" / f"triage_{tool}_{ds}" / method
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "scores.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(conv[0]))
            w.writeheader()
            w.writerows(conv)

    with open(Path(args.raw).with_name("per_test.csv" if other is None else "per_test_agree.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["test", "policy", "flagged", "real", "dataset", "tool"])
        w.writeheader()
        w.writerows(per_test_rows)

    out = Path(args.raw).with_name("scores.csv")
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{'dataset':10}{'tool':9}{'policy':24}{'real kept':>10}{'real lost':>10}{'other removed':>15}{'precision':>10}")
    for r in rows:
        print(f"{r['dataset']:10}{r['tool']:9}{r['policy']:24}{r['real_kept']:>10}{r['real_dismissed']:>10}"
              f"{r['other_dismissed']:>8}/{r['other']:<6}{r['precision_kept']!s:>10}")


if __name__ == "__main__":
    main()
