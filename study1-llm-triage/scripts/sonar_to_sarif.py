#!/usr/bin/env python3
"""Export SonarQube security issues and security hotspots for a project as SARIF.

Reads SONAR_HOST_URL and SONAR_TOKEN from the environment (source ~/.config/thesis/sonar.env);
the token is only sent in the Authorization header and never written anywhere.
CWE ids come from each rule's securityStandards (/api/rules/show) and are put into
rule properties.tags as "CWE-<n>" so score_owasp.py can read them.

Writes <out-prefix>_issues.sarif, <out-prefix>_hotspots.sarif and <out-prefix>_all.sarif.
"""
import argparse
import base64
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

HOST = os.environ["SONAR_HOST_URL"].rstrip("/")
CWE_LINK = re.compile(r"cwe\.mitre\.org/data/definitions/(\d+)")
# Primary CWE for rules whose description cites several (or a generic) CWE, following the
# rule -> CWE mapping OWASP Benchmark's own SonarQube results parser uses.
PRIMARY_CWE = {
    "java:S2077": "89", "java:S2092": "614", "java:S2245": "330", "java:S4790": "328",
    "java:S5542": "327", "java:S5547": "327", "java:S2755": "611",
}
AUTH = "Basic " + base64.b64encode((os.environ["SONAR_TOKEN"] + ":").encode()).decode()


def api(path, **params):
    url = f"{HOST}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def paged(path, key, **params):
    page = 1
    while True:
        data = api(path, p=page, ps=500, **params)
        items = data.get(key, [])
        yield from items
        total = data.get("paging", {}).get("total", data.get("total", 0))
        if not items or page * 500 >= min(total, 10000):
            break
        page += 1


def file_path(component):
    return component.split(":", 1)[1] if ":" in component else component


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default="owasp-benchmarkjava")
    ap.add_argument("--out-prefix", default=str(Path.home() / "thesis/results/sonarqube/sonarqube"))
    args = ap.parse_args()

    facet = api("/api/issues/search", componentKeys=args.project, impactSoftwareQualities="SECURITY",
                resolved="false", ps=1, facets="rules")
    counts = {v["val"]: v["count"] for f in facet["facets"] if f["property"] == "rules" for v in f["values"]}
    issues = []
    for rule_key, n in sorted(counts.items()):
        if n > 10000:
            print(f"warning: {rule_key} has {n} issues; the API returns at most 10000")
        issues += list(paged("/api/issues/search", "issues", componentKeys=args.project, rules=rule_key,
                             impactSoftwareQualities="SECURITY", resolved="false"))
    hotspots = list(paged("/api/hotspots/search", "hotspots", project=args.project))

    rule_keys = {i["rule"] for i in issues} | {h["ruleKey"] for h in hotspots}
    rules = {}
    for k in sorted(rule_keys):
        r = api("/api/rules/show", key=k)["rule"]
        cwes = {s.split(":", 1)[1] for s in r.get("securityStandards", []) if s.startswith("cwe:")}
        if not cwes:  # SonarQube 26.x: CWE ids only appear as links in the rule description
            text = " ".join(sec.get("content", "") for sec in r.get("descriptionSections", []))
            cwes = set(CWE_LINK.findall(text))
        cwes = [PRIMARY_CWE[k]] if k in PRIMARY_CWE else sorted(cwes, key=int)
        rules[k] = {"id": k, "name": r.get("name", k),
                    "shortDescription": {"text": r.get("name", k)},
                    "properties": {"tags": [f"CWE-{c}" for c in cwes], "type": r.get("type")}}

    def result(rule, component, line, msg, kind, extra):
        return {"ruleId": rule, "level": "warning" if kind == "hotspot" else "error",
                "message": {"text": msg},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": file_path(component)},
                    "region": {"startLine": line or 1}}}],
                "properties": {"kind": kind, **extra}}

    res_issues = [result(i["rule"], i["component"], i.get("line"), i.get("message", ""), "issue",
                         {"severity": i.get("severity"), "key": i["key"]}) for i in issues]
    res_hot = [result(h["ruleKey"], h["component"], h.get("line"), h.get("message", ""), "hotspot",
                      {"vulnerabilityProbability": h.get("vulnerabilityProbability"),
                       "securityCategory": h.get("securityCategory"), "key": h["key"]}) for h in hotspots]

    for name, results in (("issues", res_issues), ("hotspots", res_hot), ("all", res_issues + res_hot)):
        used = sorted({r["ruleId"] for r in results})
        sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                 "runs": [{"tool": {"driver": {"name": "SonarQube", "rules": [rules[u] for u in used]}},
                           "results": results}]}
        Path(f"{args.out_prefix}_{name}.sarif").write_text(json.dumps(sarif))
    no_cwe = sorted(k for k, v in rules.items() if not v["properties"]["tags"])
    print(f"issues={len(issues)} hotspots={len(hotspots)} rules={len(rules)} rules_without_cwe={len(no_cwe)}")


if __name__ == "__main__":
    main()
