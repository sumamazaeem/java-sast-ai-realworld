#!/usr/bin/env python3
"""Stratified sample of triage findings (proportional per Benchmark category, fixed seed).

Writes finding ids, one per line. Ids listed in --include (e.g. findings already triaged) are always kept.
Also: --filter-raw IN OUT copies only the sampled records of another run (for like-for-like comparison).
"""
import argparse
import csv
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from triage_llm import relevant_findings  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--sarif", default=str(ROOT / "results/pilot/semgrep.sarif"))
    ap.add_argument("--per-test", default=str(ROOT / "results/pilot/semgrep_score_per_test.csv"))
    ap.add_argument("--include", default=None, help="raw.jsonl whose ids are always included")
    ap.add_argument("--out", required=True)
    ap.add_argument("--filter-raw", nargs=2, metavar=("IN", "OUT"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cat = {r["test"]: r["category"] for r in csv.DictReader(open(args.per_test))}
    by_cat = defaultdict(list)
    for f in relevant_findings(args.sarif, args.per_test):
        by_cat[cat[f["test"]]].append(f["id"])
    total = sum(len(v) for v in by_cat.values())
    rng = random.Random(args.seed)
    ids = set()
    if args.include and Path(args.include).exists():
        ids |= {json.loads(l)["id"] for l in open(args.include)}
    for c, v in sorted(by_cat.items()):
        k = max(1, round(args.n * len(v) / total))
        ids |= set(rng.sample(sorted(v), min(k, len(v))))
    Path(args.out).write_text("\n".join(sorted(ids)) + "\n")
    print(f"{len(ids)} ids sampled from {total} findings in {len(by_cat)} categories")
    if args.filter_raw:
        src, dst = args.filter_raw
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        rows = [l for l in open(src) if json.loads(l)["id"] in ids]
        Path(dst).write_text("".join(rows))
        print(f"{len(rows)} records of {src} written to {dst}")


if __name__ == "__main__":
    main()
