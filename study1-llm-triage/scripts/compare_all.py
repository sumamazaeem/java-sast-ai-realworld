#!/usr/bin/env python3
"""Final comparison tables across datasets: raw scanner vs RF vs LLM (unguarded / v1 / v2 / v2+agree).

Reads the scores.csv files written by eval_triage.py (OWASP Benchmark) and eval_snippets.py
(real-world CVE set, Juliet sample) and writes results/FINAL_COMPARISON.md. Then, if
scripts/build_chapter4.py exists on main, pulls (fast-forward only) and runs it.
"""
import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
POLICIES = ["baseline", "unguarded", "guarded-v1", "guarded", "guarded+agree"]
NAMES = {"baseline": "scanner alone", "unguarded": "unguarded", "guarded-v1": "guardrails v1",
         "guarded": "guardrails v2", "guarded+agree": "v2 + agreement"}


def read(p):
    p = R / p
    return list(csv.DictReader(open(p))) if p.exists() else []


def f3(x):
    try:
        return f"{float(x):.3f}"
    except (TypeError, ValueError):
        return ""


def owasp_table(title, runs):
    out = [f"### {title}", "", "| Method | Policy | Real vulns lost | False alarms removed | Precision | TPR | FPR | Score (Benchmark avg) |",
           "|---|---|---|---|---|---|---|---|"]
    shown_base = False
    for name, path in runs:
        rows = {r["policy"]: r for r in read(path)}
        for pol in POLICIES:
            r = rows.get(pol)
            if not r or (pol == "baseline" and shown_base):
                continue
            shown_base |= pol == "baseline"
            out.append(f"| {'—' if pol == 'baseline' else name} | {NAMES[pol]} | {r['dismissed_on_real_vuln_tests']} | "
                       f"{r['dismissed_on_fake_vuln_tests']} | {f3(r['precision'])} | {f3(r['TPR'])} | {f3(r['FPR'])} | "
                       f"{f3(r['score_benchmark_avg'])} |")
        if "guarded" in rows and "guarded+agree" in rows:
            g, a = rows["guarded"], rows["guarded+agree"]
            blocked = int(g["findings_dismissed"]) - int(a["findings_dismissed"])
            saved = int(g["dismissed_on_real_vuln_tests"]) - int(a["dismissed_on_real_vuln_tests"])
            out.append(f"| {name} | *agreement effect* | {saved} real vulns saved | {blocked} dismissals blocked | | | | |")
    return out + [""]


def snippet_table(title, ds, runs):
    out = [f"### {title}", "", "| Method | Tool | Policy | Real kept | Real lost | Other removed | Precision of kept |",
           "|---|---|---|---|---|---|---|"]
    for name, path in runs:
        for r in read(path):
            if r["policy"] not in POLICIES or r["dataset"] != ds:
                continue
            out.append(f"| {name} | {r['tool']} | {NAMES[r['policy']]} | {r['real_kept']} | {r['real_dismissed']} | "
                       f"{r['other_dismissed']}/{r['other']} | {f3(r['precision_kept'])} |")
    return out + [""]


ABLATION = ["unguarded", "only-schema", "only-evidence", "only-weakcrypto", "only-severity", "only-confidence",
            "guarded", "guarded-no-schema", "guarded-no-evidence", "guarded-no-weakcrypto", "guarded-no-severity",
            "guarded-no-unsure"]


def ablation_rows(name, rows, score_key):
    """Rows of the ablation table for one run. 'Blocked' = dismissals the guardrail prevents:
    for only-<g>: unguarded minus only-<g>; for guarded-no-<g>: guarded-no-<g> minus guarded."""
    by = {r["policy"]: r for r in rows}
    if "guarded" not in by or "unguarded" not in by:
        return []
    out = []
    for pol in ABLATION:
        r = by.get(pol)
        if not r:
            continue
        if pol.startswith("only-"):
            blocked = int(by["unguarded"]["findings_dismissed"]) - int(r["findings_dismissed"])
        elif pol.startswith("guarded-no-"):
            blocked = int(r["findings_dismissed"]) - int(by["guarded"]["findings_dismissed"])
        else:
            blocked = ""
        out.append(f"| {name} | {pol} | {f3(r.get(score_key, ''))} | {r['dismissed_on_fake_vuln_tests']} | "
                   f"{r['dismissed_on_real_vuln_tests']} | {r['findings_dismissed']} | {blocked} |")
    return out


def ablation_section():
    md = ["## Guardrail ablation", "",
          "*only-X* = unguarded plus guardrail X alone; *guarded-no-X* = v2 without X (leave-one-out;",
          "*guarded-no-unsure* treats 'unsure' like false positive). *Blocked* = dismissals that guardrail prevents",
          "(only-X: vs unguarded; guarded-no-X: vs v2). Score = Benchmark avg (OWASP) or precision of kept findings",
          "(real-world/Juliet, per tool).", "",
          "| Run | Variant | Score | False alarms removed | Real vulns dropped | Dismissed | Blocked by guardrail |",
          "|---|---|---|---|---|---|---|"]
    for name, path in [("Semgrep OWASP, Qwen 7B", "triage/qwen2.5-coder_7b/scores.csv"),
                       ("Semgrep OWASP, Qwen 14B", "triage/qwen2.5-coder_14b/scores.csv"),
                       ("Semgrep OWASP, RF (CV)", "triage/ml_rf/scores.csv"),
                       ("CodeQL OWASP, Qwen 7B", "triage_codeql/qwen2.5-coder_7b/scores.csv")]:
        md += ablation_rows(name, read(path), "score_benchmark_avg")
    for ds in ("realworld", "juliet"):
        for tool in ("semgrep", "codeql"):
            for method in ("qwen2.5-coder_7b", "llama3.1_8b", "rf_owasp_juliet", "rf_owasp"):
                md += ablation_rows(f"{tool} {ds}, {method}", read(f"triage_{tool}_{ds}/{method}/scores.csv"), "precision")
    return md + [""]


def severity_section():
    """Severity level of the triaged findings per tool: explains when the severity guardrail blocks everything."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from collections import Counter
    from triage_llm import relevant_findings
    md = ["## Severity of triaged findings (SARIF level)", "",
          "The severity guardrail never auto-dismisses 'error'-level findings, so its effect depends on how a tool",
          "rates severity: CodeQL's security-extended suite marks most taint-tracking findings 'error' (the share of",
          "findings v2 can dismiss at all is the warning/note share below).", "",
          "| Tool | Dataset | Findings | error | warning | note |", "|---|---|---|---|---|---|"]
    for tool, sarif, per_test, src in [("Semgrep", "pilot/semgrep.sarif", "pilot/semgrep_score_per_test.csv", ""),
                                       ("CodeQL", "codeql/codeql.sarif", "codeql/codeql_score_per_test.csv", "datasets/BenchmarkJava"),
                                       ("SpotBugs", "spotbugs/spotbugs.sarif", "spotbugs/spotbugs_score_per_test.csv", ""),
                                       ("SonarQube", "sonarqube/sonarqube_all.sarif", "sonarqube/sonarqube_score_per_test.csv", "")]:
        if not (R / sarif).exists() or not (R / per_test).exists():
            continue
        c = Counter(f["level"] for f in relevant_findings(R / sarif, R / per_test, src))
        n = sum(c.values())
        md.append(f"| {tool} | OWASP Java (findings that count toward the score) | {n} | {c['error']} | {c['warning']} | {c['note']} |")
    import json
    for ds in ("realworld", "juliet"):
        p = R / "items" / f"{ds}.jsonl"
        if p.exists():
            items = [json.loads(l) for l in open(p)]
            for tool in sorted({i["tool"] for i in items}):
                c = Counter(i["level"] for i in items if i["tool"] == tool)
                md.append(f"| {tool} | {ds} triage sample | {sum(c.values())} | {c['error']} | {c['warning']} | {c['note']} |")
    return md + [""]


def main():
    md = ["# Final comparison", "",
          "Generated by `scripts/compare_all.py`. Guardrails v2 frozen at git tag `guardrails-v2-frozen` before the",
          "held-out runs (real-world CVE set, Juliet). *v2 + agreement*: v2, and a second model must also say",
          "false positive (Llama 3.1 8B; Qwen2.5-Coder 14B for the Semgrep OWASP findings).", "",
          "## OWASP Benchmark Java (test-level scoring)", ""]
    md += owasp_table("Semgrep findings", [
        ("Qwen2.5-Coder 7B", "triage/qwen2.5-coder_7b/scores.csv"),
        ("Qwen2.5-Coder 7B (14B sample)", "triage/qwen2.5-coder_7b_sample14b/scores.csv"),
        ("Qwen2.5-Coder 14B", "triage/qwen2.5-coder_14b/scores.csv"),
        ("Random Forest (grouped CV)", "triage/ml_rf/scores.csv"),
        ("Random Forest (leave-one-category-out)", "triage/ml_rf_loco/scores.csv")])
    md += owasp_table("CodeQL findings", [
        ("Qwen2.5-Coder 7B", "triage_codeql/qwen2.5-coder_7b/scores.csv"),
        ("Llama 3.1 8B (only findings Qwen called FP)", "triage_codeql/llama3.1_8b/scores.csv")])
    md += ["## Java CVE Benchmark (real-world; finding-level; 'other' = findings outside vulnerable methods)", ""]
    md += snippet_table("Sample of Semgrep and CodeQL findings", "realworld", [
        ("Random Forest (trained on OWASP + Juliet)", "triage_realworld/rf_owasp_juliet/scores.csv"),
        ("Qwen2.5-Coder 7B", "triage_realworld/qwen2.5-coder_7b/scores.csv"),
        ("Llama 3.1 8B", "triage_realworld/llama3.1_8b/scores.csv")])
    md += ["## Juliet Java 1.3 (OWASP-overlap sample; finding-level; 'other' = findings in good methods)", ""]
    md += snippet_table("Stratified, balanced sample", "juliet", [
        ("Random Forest (trained on OWASP)", "triage_juliet/rf_owasp/scores.csv"),
        ("Qwen2.5-Coder 7B", "triage_juliet/qwen2.5-coder_7b/scores.csv"),
        ("Llama 3.1 8B", "triage_juliet/llama3.1_8b/scores.csv")])
    md += ablation_section()
    md += severity_section()
    md += ["## Paired significance (McNemar; unit = test case for OWASP, finding for real-world/Juliet)", "",
           "| Run | Comparison | Units | Only A correct | Only B correct | Test | p |", "|---|---|---|---|---|---|---|"]
    sys.path.insert(0, str(ROOT / "scripts"))
    from mcnemar import compare
    for name, path in [("Semgrep OWASP, Qwen 7B", "triage/qwen2.5-coder_7b/per_test.csv"),
                       ("Semgrep OWASP, Qwen 7B (14B sample)", "triage/qwen2.5-coder_7b_sample14b/per_test.csv"),
                       ("CodeQL OWASP, Qwen 7B", "triage_codeql/qwen2.5-coder_7b/per_test.csv"),
                       ("Juliet, Qwen 7B", "triage_juliet/qwen2.5-coder_7b/per_test_agree.csv"),
                       ("Juliet, Qwen 7B", "triage_juliet/qwen2.5-coder_7b/per_test.csv"),
                       ("Real-world, Qwen 7B (labelled findings only)", "triage_realworld/qwen2.5-coder_7b/per_test_agree.csv")]:
        p = R / path
        if not p.exists():
            continue
        pols = {row["policy"] for row in csv.DictReader(open(p))}
        for a, b in (("guarded", "unguarded"), ("guarded+agree", "guarded"), ("guarded", "baseline")):
            if a in pols and b in pols:
                r = compare(p, a, b)
                md.append(f"| {name} | {NAMES[a]} vs {NAMES[b]} | {r['units']} | {r['b']} | {r['c']} | {r['method']} | {r['p']:.3g} |")
    md.append("")
    cve = R / "java_cve/comparison.md"
    if cve.exists():
        md += ["## Detection on the Java CVE Benchmark", ""] + cve.read_text().splitlines()[2:] + [""]
    (R / "FINAL_COMPARISON.md").write_text("\n".join(md))
    print("\n".join(md))

    subprocess.run(["git", "-C", str(ROOT), "pull", "-q", "--ff-only", "origin", "main"], capture_output=True)
    ch4 = ROOT / "scripts/build_chapter4.py"
    if ch4.exists():
        r = subprocess.run([str(ROOT / ".venv/bin/python"), "-I", str(ch4)], cwd=ROOT)
        print(f"build_chapter4.py exit code {r.returncode}", file=sys.stderr)
        # stage the chapter so the queue's final push commits it together with results/
        subprocess.run(["git", "-C", str(ROOT), "add", "thesis/chapter4"], capture_output=True)


if __name__ == "__main__":
    main()
