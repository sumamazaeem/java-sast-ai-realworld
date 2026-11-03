#!/usr/bin/env python3
"""Build triage item files (input of triage_snippets.py / ml_snippets.py) for the non-OWASP datasets.

realworld: findings of each tool on the Java CVE Benchmark (results/java_cve/<tool>/labels.jsonl).
    All findings inside a labelled vulnerable method (label "real") plus a random sample of the
    other findings (label "unlabelled": mostly false alarms, possibly unknown bugs), per tool.
juliet: Semgrep/CodeQL findings on Juliet that lie in a bad (label "real") or good (label "fake")
    method of a test case in an OWASP-overlap CWE family; stratified sample, balanced bad/good per
    OWASP category, proportional to category size. Items carry mask=true (see triage_snippets.py).
"""
import argparse
import gzip
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from score_juliet import OWASP, family  # noqa: E402
from score_owasp import rule_cwes  # noqa: E402


def sarif_rules(paths):
    """rule id -> (["CWE-n", ...], level) over all given SARIF files."""
    rules = {}
    for p in paths:
        data = json.loads(gzip.open(p).read() if str(p).endswith(".gz") else Path(p).read_text())
        for run in data.get("runs", []):
            for r in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules.setdefault(r["id"], ([f"CWE-{n}" for n in sorted(rule_cwes(r))],
                                           r.get("defaultConfiguration", {}).get("level", "warning")))
    return rules


def ident(*parts):
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def realworld(args):
    sources = json.loads((ROOT / "datasets/java-cve-benchmark/sources.json").read_text())
    rng = random.Random(args.seed)
    items = []
    for tool in args.tools:
        base = ROOT / "results/java_cve" / tool
        if not (base / "labels.jsonl").exists():
            print(f"{tool}: no labels.jsonl, skipped", file=sys.stderr)
            continue
        rules = sarif_rules(sorted((base / "sarif").glob("*.sarif.gz")))
        rows = [json.loads(l) for l in open(base / "labels.jsonl")]
        real = [r for r in rows if r["label"] == "TP"]
        other = [r for r in rows if r["label"] != "TP"]
        chosen = real + rng.sample(other, min(args.n_unlabelled, len(other)))
        for r in chosen:
            cwe, level = rules.get(r["rule_id"], ([], "warning"))
            items.append({"id": ident(tool, r["cve"], r["rule_id"], r["uri"], r["line"]), "dataset": "realworld",
                          "tool": tool, "cve": r["cve"], "uri": f"{sources[r['cve']]['vul']['dir']}/{r['uri']}",
                          "start_line": r["line"], "end_line": r["line"], "rule_id": r["rule_id"], "cwe": cwe,
                          "message": r["message"], "level": level,
                          "label": "real" if r["label"] == "TP" else "unlabelled"})
        print(f"{tool}: {len(real)} real + {len(chosen) - len(real)} sampled of {len(other)} unlabelled", file=sys.stderr)
    return items


def juliet_pool(tools, owasp_only=True):
    """All Juliet findings of the given tools in bad/good methods (CWE-family matched), as items."""
    return [it for v in _juliet_pool(tools, owasp_only).values() for it in v]


def _juliet_pool(tools, owasp_only=True):
    jroot = "datasets/juliet-java/src/Java"
    pool = defaultdict(list)  # (category, label) -> items
    for tool in tools:
        sarif = ROOT / "results/juliet" / tool / f"{tool}.sarif.gz"
        if not sarif.exists():
            print(f"{tool}: no Juliet SARIF, skipped", file=sys.stderr)
            continue
        data = json.loads(gzip.open(sarif).read())
        by_file = defaultdict(list)
        for run in data["runs"]:
            rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
            for res in run["results"]:
                loc = res["locations"][0]["physicalLocation"]
                rule = rules.get(res["ruleId"], {})
                by_file[loc["artifactLocation"]["uri"].rsplit("/", 1)[-1]].append(
                    (res["ruleId"], loc["region"]["startLine"], loc["region"].get("endLine", loc["region"]["startLine"]),
                     rule_cwes(rule), rule.get("defaultConfiguration", {}).get("level", "warning"),
                     res.get("message", {}).get("text", "")))
        with gzip.open(ROOT / "data/juliet-java/manifest.jsonl.gz", "rt") as fh:
            for line in fh:
                c = json.loads(line)
                cat = next((k for k, v in OWASP.items() if c["cwe"] in v), None)
                if not cat:
                    if owasp_only:
                        continue
                    cat = f"CWE-{c['cwe']}"
                fam = family(c["cwe"])
                for kind, label in (("bad", "real"), ("good", "fake")):
                    for m in c[kind]:
                        for rule, s, e, cwes, level, msg in by_file.get(m["file"].rsplit("/", 1)[-1], []):
                            if m["start"] <= s <= m["end"] and cwes & fam:
                                pool[(cat, label)].append({
                                    "id": ident(tool, c["case"], rule, s), "dataset": "juliet", "tool": tool,
                                    "case": c["case"], "category": cat, "uri": f"{jroot}/{m['file']}",
                                    "start_line": s, "end_line": e, "rule_id": rule,
                                    "cwe": [f"CWE-{n}" for n in sorted(cwes)], "message": msg, "level": level,
                                    "label": label, "mask": True})
    return pool


def juliet(args):
    rng = random.Random(args.seed)
    pool = _juliet_pool(args.tools)
    total = sum(len(v) for v in pool.values())
    cats = sorted({c for c, _ in pool})
    items = []
    for cat in cats:
        share = sum(len(pool[(cat, l)]) for l in ("real", "fake")) / max(total, 1)
        k = max(1, round(args.n * share / 2))
        for label in ("real", "fake"):
            v = pool[(cat, label)]
            items += rng.sample(v, min(k, len(v)))
    print(f"juliet: {total} findings in bad/good methods of OWASP-overlap cases; sampled {len(items)} "
          f"(balanced real/fake per category, proportional to category size)", file=sys.stderr)
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=["realworld", "juliet"])
    ap.add_argument("--tools", nargs="+", default=["semgrep", "codeql"])
    ap.add_argument("--n-unlabelled", type=int, default=300, help="realworld: unlabelled findings sampled per tool")
    ap.add_argument("--n", type=int, default=600, help="juliet: target sample size")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    items = realworld(args) if args.dataset == "realworld" else juliet(args)
    seen, unique = set(), []
    for it in items:
        if it["id"] not in seen:
            seen.add(it["id"])
            unique.append(it)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("".join(json.dumps(it) + "\n" for it in unique))
    print(f"{len(unique)} items -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
