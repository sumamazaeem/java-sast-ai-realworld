#!/usr/bin/env python3
"""Auto-label SAST findings on the Java CVE Benchmark against the ground-truth methods.

For a SARIF produced by scanning the vulnerable version of one CVE's project:
  a finding is TP  if it lies inside a labelled vulnerable method (file + line range);
  otherwise it is "unlabelled" (most are false alarms, but other, unknown bugs may exist).
A CVE counts as detected if at least one TP finding exists. Optionally, the SARIF of the fixed
version is checked: a TP-located finding that is still reported inside a fixed method suggests
the tool does not distinguish vulnerable from patched code (Li et al.'s stricter criterion).

usage: label_java_cve.py --cve CVE-2019-10086 --vul-sarif v.sarif [--fix-sarif f.sarif] [--out labels.jsonl]
       label_java_cve.py --all --tool semgrep   (per-version SARIF from scan_java_cve.py)
"""
import argparse
import gzip
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data/java-cve-benchmark/manifest.json"


def findings(sarif_path, src_root=None):
    p = Path(sarif_path)
    sarif = json.loads(gzip.open(p).read() if p.suffix == ".gz" else p.read_text())
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", [])[:1]:
                pl = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                if src_root and uri.startswith(src_root):
                    uri = uri[len(src_root):].lstrip("/")
                yield {"rule_id": res.get("ruleId"), "uri": uri, "line": pl.get("region", {}).get("startLine", 0),
                       "message": res.get("message", {}).get("text", "")}


def in_methods(f, methods):
    for m in methods:
        if (f["uri"] == m["file"] or f["uri"].endswith("/" + m["file"]) or m["file"].endswith("/" + f["uri"])) \
                and m["start"] <= f["line"] <= m["end"]:
            return m["method"]
    return None


def label(entry, vul_sarif, fix_sarif=None):
    vul = [dict(f, method=in_methods(f, entry["vul_methods"])) for f in findings(vul_sarif)]
    fix_hits = set()
    if fix_sarif and Path(fix_sarif).exists():
        fix_hits = {(f["rule_id"], m) for f in findings(fix_sarif) if (m := in_methods(f, entry.get("fix_methods", [])))}
    out = []
    for f in vul:
        f["label"] = "TP" if f["method"] else "unlabelled"
        f["still_reported_after_fix"] = bool(f["method"]) and (f["rule_id"], f["method"]) in fix_hits
        out.append(f)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--vul-sarif")
    ap.add_argument("--fix-sarif")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--tool")
    ap.add_argument("--out")
    args = ap.parse_args()
    manifest = {e["cve"]: e for e in json.loads(MANIFEST.read_text())}

    jobs = []
    if args.all:
        base = ROOT / "results/java_cve" / args.tool
        sources = json.loads((ROOT / "datasets/java-cve-benchmark/sources.json").read_text())

        def sarif_for(d):
            return base / "sarif" / (Path(d).parent.name + "__" + Path(d).name + ".sarif.gz") if d else None

        for c in sorted(sources):
            v, fx = sarif_for(sources[c]["vul"].get("dir")), sarif_for(sources[c].get("fix", {}).get("dir"))
            if v and v.exists() and not sources[c]["vul"].get("missing_files"):
                jobs.append((c, v, fx))
        out = Path(args.out or base / "labels.jsonl")
    else:
        jobs = [(args.cve, Path(args.vul_sarif), Path(args.fix_sarif) if args.fix_sarif else None)]
        out = Path(args.out) if args.out else None

    rows, per_cve = [], []
    for cve, v, fx in jobs:
        labs = label(manifest[cve], v, fx)
        tp = [x for x in labs if x["label"] == "TP"]
        has_fix = bool(fx) and Path(fx).exists()
        per_cve.append({"cve": cve, "cwe": manifest[cve]["cwe"], "findings": len(labs), "tp_findings": len(tp),
                        "detected": bool(tp),
                        # strict check needs a scan of the fixed version; None = not checked
                        "detected_strict": any(not x["still_reported_after_fix"] for x in tp) if has_fix else
                        (False if not tp else None)})
        rows += [dict(x, cve=cve) for x in labs]
    detected = sum(c["detected"] for c in per_cve)
    strict = sum(bool(c["detected_strict"]) for c in per_cve)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        out.with_name("per_cve.jsonl").write_text("".join(json.dumps(c) + "\n" for c in per_cve))
        no502 = [c for c in per_cve if c["cwe"] != "CWE-502"]
        print(f"excluding CWE-502: {sum(c['detected'] for c in no502)}/{len(no502)} detected, "
              f"{sum(bool(c['detected_strict']) for c in no502)} strict")
    print(f"{len(jobs)} CVEs scanned; detected (finding in a vulnerable method): {detected}; "
          f"detected and not reported again in the fixed method: {strict}; "
          f"findings: {len(rows)} ({sum(r['label'] == 'TP' for r in rows)} TP, "
          f"{sum(r['label'] != 'TP' for r in rows)} unlabelled)")


if __name__ == "__main__":
    main()
