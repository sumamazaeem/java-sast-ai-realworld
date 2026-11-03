"""Unit tests for the CI triage stage (SARIF normalising, outcomes, budget, timing)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import ci_triage as ci  # noqa: E402
import eval_triage as ev  # noqa: E402

JAVA = "class T {\n  void f(String s) {\n    run(s);\n  }\n}\n"


def write_sarif(path, uri, rules_in_extension=False, level=None):
    rule = {"id": "r1", "properties": {"tags": ["CWE-89: SQLi"]}, "defaultConfiguration": {"level": "warning"}}
    tool = {"driver": {"name": "CodeQL", "rules": []}, "extensions": [{"rules": [rule]}]} if rules_in_extension \
        else {"driver": {"name": "Semgrep", "rules": [rule]}}
    res = {"ruleId": "r1", "message": {"text": "m"},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}]}
    if level:
        res["level"] = level
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": tool, "results": [res]}]}))


def test_rules_found_in_codeql_extensions_and_absolute_paths_made_relative(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/T.java").write_text(JAVA)
    s = tmp_path / "s.sarif"
    write_sarif(s, f"file://{tmp_path}/src/T.java", rules_in_extension=True, level="error")
    [f] = ci.sarif_findings(s, tmp_path)
    assert f["uri"] == "src/T.java" and f["cwe"] == ["CWE-89: SQLi"] and f["level"] == "error"
    assert f["tool"] == "CodeQL"


def test_outcomes_map_guardrail_decisions():
    lines = {"T.java": {2, 3}}
    base = {"uri": "T.java", "level": "warning", "cwe": ["CWE-89"], "error": None}
    v = lambda verdict, ev_lines=(3,): json.dumps({"reasoning": "r", "verdict": verdict, "confidence": 0.9,
                                                    "evidence_lines": list(ev_lines)})
    g = set(ev.GUARDS_V2)
    assert ci.outcome(dict(base, raw=v("false_positive")), g, None, lines)[0] == "dismissed"
    assert ci.outcome(dict(base, raw=v("true_positive")), g, None, lines)[0] == "confirmed"
    assert ci.outcome(dict(base, raw=v("unsure")), g, None, lines)[0] == "human_review"
    assert ci.outcome(dict(base, raw=v("false_positive", (99,))), g, None, lines)[0] == "human_review"
    assert ci.outcome(dict(base, raw=v("false_positive"), level="error"), g, None, lines)[0] == "human_review"
    assert ci.outcome(dict(base, raw="", error="Timeout"), g, None, lines) == ("human_review", "keep:error:request_failed")
    assert ci.outcome(dict(base), g, None, lines) == ("not_triaged", "keep:budget:not_triaged")


def test_no_llm_run_keeps_everything_and_writes_reports(tmp_path, monkeypatch):
    (tmp_path / "T.java").write_text(JAVA)
    s = tmp_path / "s.sarif"
    write_sarif(s, "T.java")
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["ci_triage.py", "--sarif", str(s), "--workspace", str(tmp_path),
                                      "--out-dir", str(out), "--no-llm", "--max-kept", "0"])
    assert ci.main() == 1  # one kept finding > 0
    summary = json.loads((out / "triage_summary.json").read_text())
    assert summary["outcomes"] == {"not_triaged": 1} and summary["gate"] == "fail"
    sarif = json.loads((out / "triaged-s.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["properties"]["triage"]["outcome"] == "not_triaged"
