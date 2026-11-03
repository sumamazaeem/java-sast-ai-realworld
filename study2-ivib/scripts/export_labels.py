#!/usr/bin/env python3
"""results/ivib/units_labels.csv: id,dataset,cwe,label,project,pair_id,heldout (for paired tests and
project-clustered bootstrap). `heldout` = 1 for the CVEfixes projects kept out of training (md5 rule,
same as train_codebert.py / train_ivib.py), 0 for CVEfixes training projects, empty for other sets."""
import csv
import hashlib
import json
import os
from pathlib import Path

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
out = Path(__file__).resolve().parents[2] / "results/ivib/units_labels.csv"
n = 0
with open(out, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["id", "dataset", "cwe", "label", "project", "pair_id", "heldout"])
    for ds in ("cwebench", "javacve", "cvefixes", "owasp", "juliet"):
        for line in open(DATA / "units" / f"{ds}.jsonl"):
            u = json.loads(line)
            ho = int(int(hashlib.md5(u["project"].encode()).hexdigest(), 16) % 5 == 0) if ds == "cvefixes" else ""
            w.writerow([u["id"], ds, u["cwe"], u["label"], u["project"], u.get("pair") or "", ho])
            n += 1
print(n, "rows ->", out)
