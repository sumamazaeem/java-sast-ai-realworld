#!/usr/bin/env python3
"""Run the IVIB-R slicer over the units and write ISL token/state sequences.

  build_slices.py --spec ivib            IVIB's own source/sink lists (replication)
  build_slices.py --spec ivib5           + sinks for path traversal and code injection (our 5 CWEs)
  build_slices.py --spec ivib5p          + the unit method's parameters are sources (library entry points)
  build_slices.py --spec llm             + the LLM-inferred specs of each project version (Enhancement 1)

Context for interprocedural slicing: the unit's whole file; for Juliet all files of the test case
(flows 51-84 pass the tainted value to other classes). CVEfixes units only have the method.
Output: $IVIB_DATA/slices/<spec>/<dataset>.jsonl  {unit, dataset, cwe, label, tokens, states}
        results/ivib/slices_<spec>.csv  (coverage: units with a source-to-sink slice, per dataset/CWE/label)
Units are processed in parallel (4 processes, nice) and each dataset file is written once at the end.
"""
import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ivib_r as R  # noqa: E402

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]
DATASETS = ["owasp", "juliet", "cwebench", "javacve", "cvefixes"]
_SPEC = {}


def read(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def context(u):
    if not u.get("root"):
        return [u["code"]]
    f = Path(u["root"]) / u["file"]
    if u["dataset"] == "juliet":
        base = re.sub(r"_(a|b|c|d|e|bad|base|good\w*)\.java$", "", f.name).replace(".java", "")
        return [t for p in sorted(f.parent.glob(base + "*.java")) if (t := read(p))]
    t = read(f)
    return [t] if t else [u["code"]]


def specs_for(u, name):
    key = (name, u.get("root"))
    if key not in _SPEC:
        llm = None
        if name == "llm" and u.get("root"):
            p = DATA / "specs" / (Path(u["root"]).parent.name + "__" + Path(u["root"]).name + ".json")
            llm = json.loads(p.read_text()) if p.exists() else None
        _SPEC[key] = R.spec(name, llm)
    return _SPEC[key]


def one(args):
    u, name = args
    try:
        seq = R.slice_unit(u["code"], context(u), specs_for(u, name), R.final_state(u), u.get("method"))
    except Exception as e:  # noqa: BLE001 - a parser corner case must not stop the run
        return u["id"], None, str(e)[:120]
    return u["id"], seq, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, choices=["ivib", "ivib5", "ivib5p", "llm"])
    ap.add_argument("--datasets", nargs="+", default=DATASETS)
    a = ap.parse_args()
    out = DATA / "slices" / a.spec
    out.mkdir(parents=True, exist_ok=True)
    cov = Counter()
    for ds in a.datasets:
        p = DATA / "units" / f"{ds}.jsonl"
        if not p.exists():
            continue
        us = [json.loads(l) for l in open(p)]
        by = {u["id"]: u for u in us}
        errs = 0
        tmp = out / f"{ds}.jsonl.tmp"
        with ProcessPoolExecutor(4) as ex, open(tmp, "w") as fh:
            for uid, seq, err in ex.map(one, [(u, a.spec) for u in us], chunksize=64):
                u = by[uid]
                errs += err is not None
                cov[(ds, u["cwe"], u["label"], "units")] += 1
                if seq:
                    cov[(ds, u["cwe"], u["label"], "sliced")] += 1
                    fh.write(json.dumps({"unit": uid, "dataset": ds, "cwe": u["cwe"], "label": u["label"],
                                         "tokens": [t for t, _ in seq], "states": [s for _, s in seq]}) + "\n")
        tmp.rename(out / f"{ds}.jsonl")
        print(f"{a.spec}/{ds}: {sum(v for k, v in cov.items() if k[0] == ds and k[3] == 'sliced')}"
              f" of {len(us)} units sliced, {errs} parser errors", flush=True)
    rp = REPO / f"results/ivib/slices_{a.spec}.csv"
    with open(rp, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "cwe", "label", "units", "sliced", "coverage"])
        for (ds, c, l, k), n in sorted(cov.items()):
            if k == "units":
                s = cov.get((ds, c, l, "sliced"), 0)
                w.writerow([ds, c, l, n, s, round(s / n, 4)])
    print(f"coverage -> {rp}")


if __name__ == "__main__":
    os.nice(10)
    main()
