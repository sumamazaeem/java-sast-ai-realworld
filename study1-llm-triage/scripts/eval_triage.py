#!/usr/bin/env python3
"""Apply triage decision policies to raw LLM verdicts and score them on OWASP Benchmark.

Policies (a finding is either KEPT or DISMISSED; a test case stays flagged if any
of its relevant findings is kept):
  baseline        scanner alone, nothing dismissed
  unguarded       dismiss whenever the model says false_positive (unparseable -> keep)
  guarded-v1      schema + evidence + confidence >= 0.8 + severity (first version)
  guarded         guardrails v2: schema + evidence + weakcrypto + severity
                  (+ confidence only if --min-conf is given)
  guarded-no-<g>  guarded (v2) with one guardrail switched off (ablation)
  guarded+agree   v2, and additionally a second model (--agree-raw, its saved verdicts on the same
                  findings) must also say false_positive; otherwise the finding is kept. Findings the
                  second model did not see, or answered invalidly, are kept.

Guardrails:
  schema      output must parse and match the schema, otherwise keep (fail closed)
  evidence    evidence_lines must be non-empty and point at real code lines, otherwise keep
  unsure      verdict 'unsure' keeps the finding (always true here, listed for clarity)
  confidence  dismiss only if confidence >= min_conf. Off by default in v2: Qwen2.5-Coder 7B
              reported confidence >= 0.8 on every finding, so the gate never fired and only
              adds a false sense of control.
  weakcrypto  findings about weak algorithms or randomness (CWE 326/327/328/330/338/916) are never
              dismissed: they concern which API/algorithm is used, not data flow, so "the input is
              not attacker-controlled" is no reason to drop them
  severity    findings from 'error'-level rules are never auto-dismissed (sent to human review)

Writes <dir>/scores.csv, <dir>/per_category.csv, <dir>/per_test.csv (test, policy, flagged, real: for
paired tests such as McNemar's) and <dir>/decisions.jsonl (guarded policy, one line per finding).
"""
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from score_owasp import load_expected, metrics  # noqa: E402

GUARDS_V1 = ["schema", "evidence", "confidence", "severity"]
GUARDS_V2 = ["schema", "evidence", "weakcrypto", "severity"]
V1_MIN_CONF = 0.8
WEAK_CRYPTO_CWES = {326, 327, 328, 330, 338, 916}
VERDICTS = {"true_positive", "false_positive", "unsure"}
CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def finding_cwes(rec):
    return {int(m) for c in rec.get("cwe", []) for m in CWE_RE.findall(c)}


def parse(raw):
    """Return (verdict dict, problem) with strict schema validation."""
    try:
        v = json.loads(raw)
    except Exception:
        return None, "invalid_json"
    if not isinstance(v, dict):
        return None, "not_object"
    if v.get("verdict") not in VERDICTS:
        return None, "bad_verdict"
    if not isinstance(v.get("confidence"), (int, float)) or not 0 <= v["confidence"] <= 1:
        return None, "bad_confidence"
    if not isinstance(v.get("evidence_lines"), list) or not all(isinstance(x, int) for x in v["evidence_lines"]):
        return None, "bad_evidence_type"
    if not isinstance(v.get("reasoning"), str) or not v["reasoning"].strip():
        return None, "no_reasoning"
    return v, None


def lenient(raw):
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def decide(rec, guards, min_conf, code_lines):
    """Return (dismiss: bool, reason)."""
    if "schema" in guards:
        v, problem = parse(rec["raw"])
        if problem:
            return False, f"keep:schema:{problem}"
    else:
        v = lenient(rec["raw"])
    verdict = v.get("verdict")
    if verdict == "unsure" and "dismiss-unsure" in guards:  # ablation of "unsure keeps the finding"
        verdict = "false_positive"
    if verdict != "false_positive":
        return False, f"keep:verdict:{verdict}"
    if "evidence" in guards:
        ev = v.get("evidence_lines") or []
        valid = code_lines.get(rec["uri"], set())
        if not ev or not all(x in valid for x in ev):
            return False, "keep:evidence:missing_or_invalid"
    if "confidence" in guards and not (isinstance(v.get("confidence"), (int, float)) and v["confidence"] >= min_conf):
        return False, "keep:confidence:below_threshold"
    if "weakcrypto" in guards and finding_cwes(rec) & WEAK_CRYPTO_CWES:
        return False, "keep:weakcrypto:algorithm_choice_not_dismissable"
    if "severity" in guards and rec["level"] == "error":
        return False, "keep:severity:high_needs_human"
    return True, "dismiss"


ABLATION_GUARDS = ["schema", "evidence", "weakcrypto", "severity"]


def policy_set(min_conf=None, agree=False, baseline=True):
    """name -> (guards, min_conf) for all policies, including the guardrail ablations:
    guarded-no-<g>  v2 minus one guardrail (leave-one-out); guarded-no-unsure = v2 but 'unsure' is
                    treated like false_positive; guarded-no-confidence only if a gate is configured
    only-<g>        unguarded plus that single guardrail; only-confidence uses the v1 threshold (0.8)
    guarded+agree   v2 plus second-model agreement (only if agree)."""
    v2 = set(GUARDS_V2) | ({"confidence"} if min_conf is not None else set())
    pol = {"baseline": (None, None)} if baseline else {}
    pol.update({"unguarded": (set(), None), "guarded-v1": (set(GUARDS_V1), V1_MIN_CONF), "guarded": (v2, min_conf)})
    for g in sorted(v2, key=(GUARDS_V2 + ["confidence"]).index):
        pol[f"guarded-no-{g}"] = (v2 - {g}, min_conf)
    pol["guarded-no-unsure"] = (v2 | {"dismiss-unsure"}, min_conf)
    for g in ABLATION_GUARDS:
        pol[f"only-{g}"] = ({g}, None)
    pol["only-confidence"] = ({"confidence"}, V1_MIN_CONF)
    if agree:
        pol["guarded+agree"] = (v2, min_conf)
    return pol


def load_verdicts(path):
    """finding id -> schema-valid verdict of another run (None if invalid)."""
    out = {}
    for line in open(path):
        r = json.loads(line)
        v, problem = parse(r["raw"])
        out[r["id"]] = None if problem else v["verdict"]
    return out


def decide_agree(rec, guards, min_conf, code_lines, other):
    """v2 decision, but a dismissal also needs the second model's false_positive verdict."""
    dismiss, why = decide(rec, guards, min_conf, code_lines)
    if dismiss and other.get(rec["id"]) != "false_positive":
        return False, "keep:agree:second_model_not_fp"
    return dismiss, why


def non_blank_lines(uri):
    from triage_llm import strip_comments
    src = strip_comments((ROOT / uri).read_text(), uri)
    return {i for i, line in enumerate(src.splitlines(), 1) if line.strip()}


def test_flags(tests, findings_by_test, dismissed, flagged_base):
    """test -> still flagged after triage (tests whose findings were not triaged keep their baseline flag)."""
    flags = {}
    for name in tests:
        ids = findings_by_test.get(name)
        flags[name] = name in flagged_base and (not ids or any(i not in dismissed for i in ids))
    return flags


def score(tests, findings_by_test, dismissed, flagged_base):
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for name, flagged in test_flags(tests, findings_by_test, dismissed, flagged_base).items():
        t = tests[name]
        key = ("tp" if t["real"] else "fp") if flagged else ("fn" if t["real"] else "tn")
        counts[t["category"]][key] += 1
    return counts


def summarize(counts):
    tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    cat_scores = []
    for c in counts.values():
        for k in tot:
            tot[k] += c[k]
        cat_scores.append(metrics(c["tp"], c["fp"], c["fn"], c["tn"]))
    p, r, f, s = metrics(tot["tp"], tot["fp"], tot["fn"], tot["tn"])
    avg = [sum(x[i] for x in cat_scores) / len(cat_scores) for i in range(4)]
    return tot, (p, r, f, s), avg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--expected", default=str(next((ROOT / "datasets/BenchmarkJava").glob("expectedresults-*.csv"))))
    ap.add_argument("--per-test", default=str(ROOT / "results/pilot/semgrep_score_per_test.csv"))
    ap.add_argument("--agree-raw", default=None, help="raw.jsonl of a second model for the guarded+agree policy")
    ap.add_argument("--min-conf", type=float, default=None,
                    help="add a confidence gate to the v2 policy (off by default, see module docstring)")
    args = ap.parse_args()

    raw_path = Path(args.raw)
    outdir = raw_path.parent
    tests = load_expected(args.expected)
    flagged_base = {r["test"] for r in csv.DictReader(open(args.per_test)) if r["flagged"] == "True"}
    recs = [json.loads(line) for line in raw_path.read_text().splitlines()]
    by_test = defaultdict(list)
    for r in recs:
        by_test[r["test"]].append(r["id"])
    code_lines = {u: non_blank_lines(u) for u in {r["uri"] for r in recs}}
    coverage = len({r["test"] for r in recs})

    other = load_verdicts(args.agree_raw) if args.agree_raw else None
    policies = policy_set(args.min_conf, agree=other is not None)

    rows, cat_rows, per_test_rows = [], [], []
    for name, (guards, min_conf) in policies.items():
        dismissed, reasons = set(), defaultdict(int)
        if guards is not None:
            for r in recs:
                d, why = (decide_agree(r, guards, min_conf, code_lines, other) if name == "guarded+agree"
                          else decide(r, guards, min_conf, code_lines))
                reasons[why.split(":")[0] + ":" + why.split(":")[1] if ":" in why else why] += 1
                if d:
                    dismissed.add(r["id"])
            if name == "guarded":
                with open(outdir / "decisions.jsonl", "w") as fh:
                    for r in recs:
                        d, why = decide(r, guards, min_conf, code_lines)
                        v = lenient(r["raw"])
                        fh.write(json.dumps({"id": r["id"], "test": r["test"], "rule_id": r["rule_id"],
                                             "level": r["level"], "line": r["start_line"],
                                             "verdict": v.get("verdict"), "confidence": v.get("confidence"),
                                             "evidence_lines": v.get("evidence_lines"),
                                             "reasoning": v.get("reasoning"), "decision": "dismiss" if d else "keep",
                                             "rule": why, "model": r["model"]}) + "\n")
        counts = score(tests, by_test, dismissed, flagged_base)
        for t, fl in test_flags(tests, by_test, dismissed, flagged_base).items():
            per_test_rows.append({"test": t, "policy": name, "flagged": int(fl), "real": int(tests[t]["real"])})
        tot, pooled, avg = summarize(counts)
        real_flagged = sum(1 for r in recs if tests[r["test"]]["real"])
        dismissed_real = sum(1 for r in recs if r["id"] in dismissed and tests[r["test"]]["real"])
        dismissed_fake = sum(1 for r in recs if r["id"] in dismissed and not tests[r["test"]]["real"])
        rows.append({
            "policy": name, "findings_triaged": len(recs), "tests_covered": coverage,
            "findings_dismissed": len(dismissed),
            "dismissed_on_fake_vuln_tests": dismissed_fake, "dismissed_on_real_vuln_tests": dismissed_real,
            "findings_on_real_vuln_tests": real_flagged,
            **{k.upper(): v for k, v in tot.items()},
            "precision": round(pooled[0], 4), "TPR": round(pooled[1], 4), "FPR": round(pooled[2], 4),
            "score_pooled": round(pooled[3], 4), "score_benchmark_avg": round(avg[3], 4),
            "decision_reasons": ";".join(f"{k}={v}" for k, v in sorted(reasons.items())),
        })
        for cat, c in sorted(counts.items()):
            p, r_, f, s = metrics(c["tp"], c["fp"], c["fn"], c["tn"])
            cat_rows.append({"policy": name, "category": cat, **{k.upper(): v for k, v in c.items()},
                             "precision": round(p, 4), "TPR": round(r_, 4), "FPR": round(f, 4), "score": round(s, 4)})

    for path, data in ((outdir / "scores.csv", rows), (outdir / "per_category.csv", cat_rows),
                       (outdir / "per_test.csv", per_test_rows)):
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0]))
            w.writeheader()
            w.writerows(data)

    fmt = "{:<24}{:>6}{:>6}{:>6}{:>6}{:>7}{:>7}{:>7}{:>8}{:>8}"
    print(f"triaged {len(recs)} findings covering {coverage} test cases")
    print(fmt.format("policy", "TP", "FP", "FN", "TN", "prec", "TPR", "FPR", "score", "bm-avg"))
    for r in rows:
        print(fmt.format(r["policy"], r["TP"], r["FP"], r["FN"], r["TN"], f'{r["precision"]:.3f}',
                         f'{r["TPR"]:.3f}', f'{r["FPR"]:.3f}', f'{r["score_pooled"]:.3f}', f'{r["score_benchmark_avg"]:.3f}'))


if __name__ == "__main__":
    main()
