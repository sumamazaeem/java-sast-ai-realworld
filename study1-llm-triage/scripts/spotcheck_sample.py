#!/usr/bin/env python3
"""Draw the stratified sample for the manual check of unlabelled real-world findings (Chapter 4, Section 4.3.4).

Population: the 597 real-world triage findings outside a labelled vulnerable method ("unlabelled").
Strata: tool (Semgrep, CodeQL) x decision of Qwen2.5-Coder 7B with guardrails v2 (dismissed, kept).
15 findings per stratum (all of them if a stratum is smaller), seed 42. Writes the sampled ids, with the
model's verdict, to results/spotcheck/sample.jsonl. The manual labels are added in labels.csv.

Run: python3 -I scripts/spotcheck_sample.py
"""
import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
PER_STRATUM, SEED = 15, 42


def main():
    items = {json.loads(l)["id"]: json.loads(l) for l in open(R / "items" / "realworld.jsonl")}
    raw = {json.loads(l)["id"]: json.loads(l) for l in open(R / "triage_realworld" / "qwen2.5-coder_7b" / "raw.jsonl")}
    kept = {r["test"]: r["flagged"] == "1" for r in csv.DictReader(open(R / "triage_realworld" / "qwen2.5-coder_7b" / "per_test.csv"))
            if r["policy"] == "guarded"}
    strata = {}
    for i in sorted(items):
        it = items[i]
        if it["label"] == "real":
            continue
        strata.setdefault((it["tool"], "kept" if kept[i] else "dismissed"), []).append(i)
    rng = random.Random(SEED)
    out = []
    for key in sorted(strata):
        ids = strata[key]
        pick = sorted(rng.sample(ids, min(PER_STRATUM, len(ids))))
        for i in pick:
            try:
                v = json.loads(raw[i]["raw"])
            except Exception:
                v = {}
            out.append({**items[i], "stratum_tool": key[0], "stratum_v2": key[1], "stratum_size": len(ids),
                        "qwen_verdict": v.get("verdict"), "qwen_reasoning": v.get("reasoning")})
    (R / "spotcheck").mkdir(exist_ok=True)
    with open(R / "spotcheck" / "sample.jsonl", "w") as fh:
        for o in out:
            fh.write(json.dumps(o) + "\n")
    print({k: len(v) for k, v in strata.items()}, len(out), "sampled")


if __name__ == "__main__":
    main()
