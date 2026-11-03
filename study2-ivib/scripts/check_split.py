#!/usr/bin/env python3
"""Leakage check for steps 5-6: no project (and no CVE) may be in both training and test.

Training data (step 5): OWASP + Juliet (synthetic, no real projects) + the 80% of CVEfixes projects
whose md5(project) % 5 != 0. Test data: CWE-Bench-Java, Java CVE Benchmark, and the other 20% of
CVEfixes projects. Project = lower-case "owner/repo" (also compared by bare repo name, to catch forks
and renames). Writes results/ivib/split_report.md and exits 1 if anything overlaps.
"""
import hashlib
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]


def units(ds):
    return [json.loads(l) for l in open(DATA / "units" / f"{ds}.jsonl")]


def held_out(project):
    return int(hashlib.md5(project.encode()).hexdigest(), 16) % 5 == 0


def main():
    cw, jc, cf = units("cwebench"), units("javacve"), units("cvefixes")
    train_cf = [u for u in cf if not held_out(u["project"])]
    test_cf = [u for u in cf if held_out(u["project"])]
    train_proj = {u["project"] for u in train_cf}
    train_cve = {u["cve"] for u in train_cf}
    train_name = {p.rsplit("/", 1)[-1] for p in train_proj}
    tests = {"CWE-Bench-Java": cw, "Java CVE Benchmark": jc, "CVEfixes held-out 20%": test_cf}
    bad, lines = 0, []
    for name, rows in tests.items():
        projs = {u["project"] for u in rows}
        cves = {u["cve"] for u in rows}
        names = {p.rsplit("/", 1)[-1] for p in projs}
        a, b, c = projs & train_proj, cves & train_cve, names & train_name
        bad += len(a) + len(b)
        lines.append(f"| {name} | {len(projs)} | {len(rows)} | {len(a)} | {len(b)} | {len(c)} {sorted(c)[:5]} |")
    pc = defaultdict(set)
    for u in cf:
        pc[u["project"]].add(held_out(u["project"]))
    split_ok = all(len(v) == 1 for v in pc.values())
    out = ["# Train/test split check (steps 5-6)", "",
           f"Training: OWASP (all), Juliet (all), CVEfixes {len(train_proj)} projects / {len(train_cf)} methods.", "",
           "| Test set | Projects | Methods | Projects also in training | CVEs also in training | Same repo name in training (forks/renames) |",
           "|---|---|---|---|---|---|", *lines, "",
           f"Every CVEfixes project is wholly on one side: {split_ok}.",
           f"RESULT: {'PASS' if not bad and split_ok else 'FAIL'}"]
    (REPO / "results/ivib/split_report.md").write_text("\n".join(out) + "\n")
    print("\n".join(out))
    return 1 if bad or not split_ok else 0


if __name__ == "__main__":
    sys.exit(main())
