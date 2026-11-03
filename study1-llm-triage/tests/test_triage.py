"""Unit tests for the guardrail policy, prompt building and SARIF scoring helpers."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import eval_triage as ev  # noqa: E402
import score_owasp as so  # noqa: E402
import triage_llm as tl  # noqa: E402

URI = "src/T.java"
LINES = {URI: {10, 11, 12}}


def rec(verdict="false_positive", conf=0.9, ev_lines=(10,), level="warning", cwe=("CWE-89: SQLi",), raw=None):
    v = {"reasoning": "r", "verdict": verdict, "confidence": conf, "evidence_lines": list(ev_lines)}
    return {"raw": raw if raw is not None else json.dumps(v), "uri": URI, "level": level, "cwe": list(cwe)}


def decide(r, guards, min_conf=None):
    return ev.decide(r, set(guards), min_conf, LINES)


# --- schema ---------------------------------------------------------------
def test_invalid_json_kept_when_schema_on_and_ignored_when_off():
    r = rec(raw='{"verdict": "false_positive"')  # truncated output
    assert decide(r, ["schema"]) == (False, "keep:schema:invalid_json")
    assert decide(r, [])[0] is False  # unparseable is never dismissed


def test_schema_rejects_out_of_range_confidence():
    assert decide(rec(conf=1.5), ["schema"]) == (False, "keep:schema:bad_confidence")


# --- verdicts -------------------------------------------------------------
def test_only_false_positive_is_dismissed():
    assert decide(rec(verdict="true_positive"), ev.GUARDS_V2)[0] is False
    assert decide(rec(verdict="unsure"), ev.GUARDS_V2)[0] is False
    assert decide(rec(), ev.GUARDS_V2) == (True, "dismiss")


# --- evidence -------------------------------------------------------------
def test_evidence_must_point_at_real_lines():
    assert decide(rec(ev_lines=()), ["evidence"])[1] == "keep:evidence:missing_or_invalid"
    assert decide(rec(ev_lines=(10, 99)), ["evidence"])[1] == "keep:evidence:missing_or_invalid"
    assert decide(rec(ev_lines=(11, 12)), ["evidence"]) == (True, "dismiss")


# --- confidence -----------------------------------------------------------
def test_confidence_gate_only_when_enabled():
    low = rec(conf=0.5)
    assert decide(low, ["confidence"], min_conf=0.8)[1] == "keep:confidence:below_threshold"
    assert decide(low, ev.GUARDS_V2) == (True, "dismiss")  # v2 default: no confidence gate


# --- weak crypto ----------------------------------------------------------
def test_weak_crypto_never_dismissed():
    for cwe in ("CWE-327: Broken crypto", "CWE-328: Weak hash", "CWE-330: Weak random", "CWE-338"):
        assert decide(rec(cwe=(cwe,)), ["weakcrypto"])[1] == "keep:weakcrypto:algorithm_choice_not_dismissable"
    assert decide(rec(cwe=("CWE-89",)), ["weakcrypto"]) == (True, "dismiss")


# --- severity -------------------------------------------------------------
def test_error_level_needs_human():
    assert decide(rec(level="error"), ["severity"])[1] == "keep:severity:high_needs_human"
    assert decide(rec(level="warning"), ["severity"]) == (True, "dismiss")


# --- prompt building ------------------------------------------------------
def test_strip_comments_keeps_line_numbers_and_strings():
    src = 'a = "http://x"; // c\n/* one\ntwo */ b = 1;\n'
    out = tl.strip_comments(src)
    assert out.count("\n") == src.count("\n")
    assert '"http://x"' in out and "// c" not in out and "one" not in out and "b = 1" in out


def test_python_docstring_and_comments_removed():
    src = "'''licence\ntext'''\nimport os\n# hint: safe\nx = 1  # trailing kept\n"
    out = tl.strip_comments(src, "a.py").splitlines()
    assert out[0] == "" and out[1] == "" and out[2] == "import os" and out[3] == ""
    assert len(out) == len(src.splitlines())


def test_prompt_unchanged_without_fewshot():
    f = {"rule_id": "r", "cwe": ["CWE-89: x"], "message": "m", "start_line": 1, "end_line": 1, "uri": "T.java"}
    plain = tl.build_prompt(f, "int a;\n")
    assert tl.build_prompt(f, "int a;\n", None) == plain
    shots = {"89": [{"code": "q()", "verdict": "false_positive", "why": "bound"}]}
    with_shots = tl.build_prompt(f, "int a;\n", shots)
    assert with_shots.endswith(plain) and "Examples for this weakness" in with_shots
    assert tl.build_prompt(f, "int a;\n", {"79": shots["89"]}) == plain  # no matching CWE


def test_fewshot_file_is_valid():
    data = json.loads((ROOT / "config/fewshot_java.json").read_text())
    for k, v in data.items():
        if k.startswith("_"):
            continue
        assert k.isdigit()
        assert all(e["verdict"] in ev.VERDICTS and e["code"] and e["why"] for e in v)


# --- SARIF CWE extraction -------------------------------------------------
def test_rule_cwes_from_tags_and_relationships():
    assert so.rule_cwes({"properties": {"tags": ["CWE-89: SQL Injection"]}}) == {89}
    assert so.rule_cwes({"properties": {"tags": ["external/cwe/cwe-079"]}}) == {79}
    spotbugs = {"relationships": [{"target": {"id": "22", "toolComponent": {"name": "CWE"}}}]}
    assert so.rule_cwes(spotbugs) == {22}


def test_metrics():
    assert so.metrics(5, 5, 5, 5) == (0.5, 0.5, 0.5, 0.0)
    assert so.metrics(0, 0, 0, 0) == (0.0, 0.0, 0.0, 0.0)


# --- Java CVE Benchmark labelling ----------------------------------------
def test_label_java_cve_marks_findings_inside_vulnerable_methods(tmp_path):
    import label_java_cve as lj

    def sarif(results):
        return {"runs": [{"results": [{"ruleId": r, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": u}, "region": {"startLine": ln}}}]} for r, u, ln in results]}]}

    entry = {"vul_methods": [{"file": "src/main/java/A.java", "start": 10, "end": 20, "method": "A.run"}],
             "fix_methods": [{"file": "src/main/java/A.java", "start": 10, "end": 22, "method": "A.run"}]}
    v = tmp_path / "v.sarif"
    v.write_text(json.dumps(sarif([("r1", "src/main/java/A.java", 15), ("r2", "src/main/java/A.java", 30),
                                   ("r1", "src/main/java/B.java", 15)])))
    f = tmp_path / "f.sarif"
    f.write_text(json.dumps(sarif([("r1", "src/main/java/A.java", 12)])))
    labs = lj.label(entry, v, f)
    assert [x["label"] for x in labs] == ["TP", "unlabelled", "unlabelled"]
    assert labs[0]["still_reported_after_fix"] is True  # same rule still fires in the fixed method


# --- Juliet scoring -------------------------------------------------------
def test_juliet_hit_uses_family_and_method_range():
    import score_juliet as sj
    by_file = {"CWE23_Relative_Path__x_01.java": [(15, {22}), (40, {89})]}
    bad = [{"file": "src/testcases/CWE23/CWE23_Relative_Path__x_01.java", "start": 10, "end": 20}]
    good = [{"file": "src/testcases/CWE23/CWE23_Relative_Path__x_01.java", "start": 30, "end": 50}]
    assert sj.hit(bad, by_file, 23) is True       # CWE-22 finding counts for a CWE-23 case
    assert sj.hit(good, by_file, 23) is False     # only an unrelated CWE-89 finding in the good method
    assert sj.hit(good, by_file, 89) is True


# --- model-agreement policy ----------------------------------------------
def test_agree_policy_needs_second_model_fp():
    r = dict(rec(), id="f1")
    assert ev.decide_agree(r, set(ev.GUARDS_V2), None, LINES, {"f1": "false_positive"}) == (True, "dismiss")
    for other in ({"f1": "true_positive"}, {"f1": "unsure"}, {"f1": None}, {}):
        assert ev.decide_agree(r, set(ev.GUARDS_V2), None, LINES, other) == (False, "keep:agree:second_model_not_fp")


def test_agree_policy_never_dismisses_what_v2_keeps():
    r = dict(rec(level="error"), id="f2")  # v2 keeps (severity)
    d, why = ev.decide_agree(r, set(ev.GUARDS_V2), None, LINES, {"f2": "false_positive"})
    assert d is False and why == "keep:severity:high_needs_human"


def test_load_verdicts_marks_invalid_output(tmp_path):
    p = tmp_path / "raw.jsonl"
    good = json.dumps({"reasoning": "r", "verdict": "false_positive", "confidence": 0.9, "evidence_lines": [1]})
    p.write_text(json.dumps({"id": "a", "raw": good}) + "\n" + json.dumps({"id": "b", "raw": "{bad"}) + "\n")
    assert ev.load_verdicts(p) == {"a": "false_positive", "b": None}


# --- McNemar ---------------------------------------------------------------
def test_mcnemar_exact_and_chi2(tmp_path):
    import mcnemar as mc
    assert mc.mcnemar(0, 0)["p"] == 1.0
    exact = mc.mcnemar(1, 9)                    # n = 10 < 25: exact binomial, p = 2*(1+10)/1024
    assert exact["method"] == "exact binomial" and abs(exact["p"] - 22 / 1024) < 1e-12
    big = mc.mcnemar(10, 30)                    # chi2 = (20-1)^2/40 = 9.025
    assert big["chi2"] == 9.025 and abs(big["p"] - 0.002663) < 1e-5
    p = tmp_path / "per_test.csv"
    rows = ["test,policy,flagged,real", "t1,A,1,1", "t1,B,0,1", "t2,A,0,0", "t2,B,0,0", "t3,A,1,0", "t3,B,0,0",
            "t4,A,1,,", "t4,B,0,"]
    p.write_text("\n".join(rows) + "\n")
    r = mc.compare(p, "A", "B")
    assert (r["units"], r["b"], r["c"]) == (3, 1, 1)   # t4 has no ground truth


# --- guardrail ablation wiring --------------------------------------------
def test_policy_set_leave_one_out_and_single_guard():
    pol = ev.policy_set()
    v2 = set(ev.GUARDS_V2)
    assert pol["guarded"] == (v2, None) and pol["unguarded"] == (set(), None)
    for g in ev.GUARDS_V2:
        assert pol[f"guarded-no-{g}"][0] == v2 - {g}
        assert pol[f"only-{g}"][0] == {g}
    assert pol["guarded-no-unsure"][0] == v2 | {"dismiss-unsure"}
    assert pol["only-confidence"] == ({"confidence"}, ev.V1_MIN_CONF)
    assert "guarded-no-confidence" not in pol and "guarded+agree" not in pol
    with_gate = ev.policy_set(min_conf=0.9, agree=True)
    assert "confidence" in with_gate["guarded"][0] and with_gate["guarded-no-confidence"][0] == v2
    assert "guarded+agree" in with_gate and "baseline" not in ev.policy_set(baseline=False)


def test_unsure_ablation_only_changes_unsure_verdicts():
    unsure = rec(verdict="unsure")
    assert decide(unsure, ev.GUARDS_V2)[0] is False                         # v2: unsure keeps
    assert decide(unsure, set(ev.GUARDS_V2) | {"dismiss-unsure"}) == (True, "dismiss")
    assert decide(rec(verdict="true_positive"), {"dismiss-unsure"})[0] is False
    assert decide(rec(verdict="unsure"), [])[0] is False                    # unguarded unchanged
