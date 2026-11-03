#!/usr/bin/env python3
"""Turn scanner SARIF into per-unit predictions, and score any prediction file against the units.

A unit (method) is flagged by a tool when the tool reports a finding whose CWE folds onto the unit's
CWE (same families as build_units.FOLD) and whose start line lies inside the unit's line range in the
same file. Pairs: a vulnerable/fixed pair counts as "pair-correct" only if the vulnerable version is
flagged and the fixed one is not (Ding et al. 2024, PrimeVul, pair-wise evaluation).

  score_units.py sarif --tool codeql      -> results/ivib/preds/codeql_<dataset>.csv
  score_units.py score                    -> results/ivib/metrics.csv (every preds file)
"""
import argparse
import csv
import gzip
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_units import fold  # noqa: E402

HOME = Path.home()
DATA = Path(os.environ.get("IVIB_DATA", HOME / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]
PREDS = REPO / "results/ivib/preds"
CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.I)
OLD = HOME / "thesis/results"
OLD_SARIF = {  # earlier full-suite runs on the synthetic sets
    ("codeql", "owasp"): [OLD / "codeql/codeql.sarif"],
    ("semgrep", "owasp"): [OLD / "pilot/semgrep.sarif"],
    ("codeql", "juliet"): [OLD / "juliet/codeql/codeql.sarif.gz"],
    ("semgrep", "juliet"): [OLD / "juliet/semgrep/semgrep.sarif.gz"],
}


def units(ds):
    with open(DATA / "units" / f"{ds}.jsonl") as fh:
        for line in fh:
            yield json.loads(line)


def load_sarif(p):
    op = gzip.open if str(p).endswith(".gz") else open
    with op(p, "rt") as fh:
        return json.load(fh)


def findings(sarif):
    """Yield (uri, line, folded_cwe) for each result."""
    for run in sarif.get("runs", []):
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            tags = " ".join(r.get("properties", {}).get("tags", []) or []) + " " + r.get("id", "")
            rules[r.get("id")] = {fold(int(c)) for c in CWE_RE.findall(tags)} - {None}
        for res in run.get("results", []):
            cw = set(rules.get(res.get("ruleId"), set()))
            cw |= {fold(int(c)) for c in CWE_RE.findall(json.dumps(res.get("properties", {})))} - {None}
            for loc in res.get("locations", [])[:1]:
                pl = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine")
                if uri and line:
                    for c in cw:
                        yield uri.replace("file://", ""), line, c


def flag_units(us, index):
    """index: uri -> [(line, cwe)]; match unit files by path suffix."""
    by_name = defaultdict(list)
    for uri, hits in index.items():
        by_name[Path(uri).name].append((uri, hits))
    out = {}
    for u in us:
        f = u["file"]
        hit = 0
        for uri, hs in by_name.get(Path(f).name, []):
            if not (f.endswith(uri.lstrip("/")) or uri.endswith(f)):
                continue
            if any(c == u["cwe"] and u["start"] <= ln <= u["end"] for ln, c in hs):
                hit = 1
                break
        out[u["id"]] = hit
    return out


def cmd_sarif(tool):
    PREDS.mkdir(parents=True, exist_ok=True)
    for ds in ("owasp", "juliet", "cwebench", "javacve"):
        us = list(units(ds))
        preds = {}
        if ds in ("owasp", "juliet"):
            index = defaultdict(list)
            for p in OLD_SARIF[(tool, ds)]:
                for uri, ln, c in findings(load_sarif(p)):
                    index[uri].append((ln, c))
            preds = flag_units(us, index)
        else:
            by_root = defaultdict(list)
            for u in us:
                by_root[u["root"]].append(u)
            missing = 0
            for root, group in by_root.items():
                p = DATA / "sarif" / tool / (Path(root).parent.name + "__" + Path(root).name + ".sarif.gz")
                if not p.exists():
                    missing += 1
                    continue  # scan failed: units get no prediction (reported as coverage)
                index = defaultdict(list)
                for uri, ln, c in findings(load_sarif(p)):
                    index[uri].append((ln, c))
                preds.update(flag_units(group, index))
            print(f"{tool}/{ds}: {missing} of {len(by_root)} versions have no SARIF", flush=True)
        write_preds(f"{tool}_{ds}", us, preds)


def write_preds(name, us, preds):
    PREDS.mkdir(parents=True, exist_ok=True)
    with open(PREDS / f"{name}.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "pred"])
        for u in us:
            if u["id"] in preds:
                w.writerow([u["id"], int(preds[u["id"]])])


def metrics(rows):
    tp = sum(1 for l, p in rows if l and p)
    fp = sum(1 for l, p in rows if not l and p)
    fn = sum(1 for l, p in rows if l and not p)
    tn = sum(1 for l, p in rows if not l and not p)
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    den = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = (tp * tn - fp * fn) / den if den else 0.0  # Matthews correlation: 0 = chance, honest on balanced pairs
    return dict(n=len(rows), tp=tp, fp=fp, fn=fn, tn=tn, precision=round(pr, 4), recall=round(rc, 4),
                f1=round(f1, 4), mcc=round(mcc, 4), accuracy=round((tp + tn) / len(rows), 4) if rows else 0.0)


def cmd_score():
    out = []
    cache = {}
    for pf in sorted(PREDS.glob("*.csv")):
        name = pf.stem
        method, ds = name.rsplit("_", 1)
        if ds not in cache:
            cache[ds] = {u["id"]: u for u in units(ds)}
        us = cache[ds]
        preds = {r["id"]: int(r["pred"]) for r in csv.DictReader(open(pf))}
        groups = defaultdict(list)
        pairs = defaultdict(dict)
        for i, p in preds.items():
            u = us.get(i)
            if not u:
                continue
            groups["all"].append((u["label"], p))
            groups[f"CWE-{u['cwe']}"].append((u["label"], p))
            if u.get("pair"):
                # a side is "flagged" if any of its units is flagged
                pairs[u["pair"]][u["label"]] = max(pairs[u["pair"]].get(u["label"], 0), p)
        full = [v for v in pairs.values() if 0 in v and 1 in v]
        pc = sum(1 for v in full if v[1] and not v[0])
        for g, rows in sorted(groups.items()):
            m = metrics(rows)
            m.update(method=method, dataset=ds, group=g, coverage=round(len(preds) / len(us), 4) if g == "all" else "",
                     pairs=len(full) if g == "all" else "",
                     pair_correct=round(pc / len(full), 4) if g == "all" and full else "")
            out.append(m)
    cols = ["method", "dataset", "group", "n", "coverage", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "mcc",
            "accuracy", "pairs", "pair_correct"]
    p = REPO / "results/ivib/metrics.csv"
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for m in out:
            w.writerow({k: m.get(k, "") for k in cols})
    print(f"{len(out)} rows -> {p}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sarif")
    s.add_argument("--tool", required=True, choices=["codeql", "semgrep"])
    sub.add_parser("score")
    a = ap.parse_args()
    cmd_sarif(a.tool) if a.cmd == "sarif" else cmd_score()


if __name__ == "__main__":
    main()
