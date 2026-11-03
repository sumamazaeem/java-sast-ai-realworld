#!/usr/bin/env python3
"""Fine-tune a ~125M code encoder (CodeBERT by default) as a method-level vulnerability classifier,
then predict every test set. This is the learned baseline that runs on raw methods (no slicing), and
the vehicle for Enhancement 2 (train on real CVE fix pairs as well as on synthetic code).

  train_codebert.py --name synth  --train owasp juliet
  train_codebert.py --name real   --train owasp juliet cvefixes

Labels are binary (vulnerable / not) with the CWE given to the model as a prefix token, like IVIB's
vulType instruction, so one model covers the 5 CWEs. Juliet is capped per CWE and label so its
near-duplicate templates do not swamp the rest (the IVIB paper notes the same redundancy).
Each test set listed in --test is predicted in full; a dataset also used for training is split 80/20
by project (by test case for Juliet, by file for OWASP) and only its held-out part is predicted.

Checkpoints after every epoch to $IVIB_DATA/models/<name>/ and resumes from there.
Predictions: results/ivib/preds/codebert-<name>_<dataset>.csv  (scored by score_units.py)
"""
import argparse
import csv
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path

import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]
PREDS = REPO / "results/ivib/preds"


def units(ds):
    with open(DATA / "units" / f"{ds}.jsonl") as fh:
        return [json.loads(l) for l in fh]


def group_key(u):
    return u["project"] if u["dataset"] not in ("juliet", "owasp") else (u.get("pair") or u["file"])


def held_out(u):  # deterministic 80/20 split by group
    return int(hashlib.md5(group_key(u).encode()).hexdigest(), 16) % 5 == 0


def text(u):
    return f"CWE-{u['cwe']} </s> {u['code']}"


def cap(rows, per, seed):
    rnd = random.Random(seed)
    by = {}
    for u in rows:
        by.setdefault((u["cwe"], u["label"]), []).append(u)
    out = []
    for k, v in by.items():
        rnd.shuffle(v)
        out += v[:per]
    return out


def batches(tok, rows, bs, max_len, shuffle, seed):
    def coll(b):
        enc = tok([text(u) for u in b], truncation=True, max_length=max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor([u["label"] for u in b])
        return enc
    g = torch.Generator().manual_seed(seed)
    return DataLoader(rows, batch_size=bs, shuffle=shuffle, collate_fn=coll, generator=g)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--train", nargs="+", required=True)
    ap.add_argument("--test", nargs="+", default=["owasp", "juliet", "cwebench", "javacve", "cvefixes"])
    ap.add_argument("--model", default="microsoft/codebert-base")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--juliet-cap", type=int, default=1500, help="max Juliet units per (CWE, label)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    random.seed(a.seed)
    torch.manual_seed(a.seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    mdir = DATA / "models" / a.name
    mdir.mkdir(parents=True, exist_ok=True)

    train = []
    for ds in a.train:
        rows = [u for u in units(ds) if not held_out(u)]
        if ds == "juliet":
            rows = cap(rows, a.juliet_cap, a.seed)
        train += rows
        print(f"train {ds}: {len(rows)}", flush=True)
    tok = AutoTokenizer.from_pretrained(a.model)
    state = mdir / "state.json"
    st = json.loads(state.read_text()) if state.exists() else {"epoch": 0}
    src = mdir / "ckpt" if (mdir / "ckpt").exists() else a.model
    model = AutoModelForSequenceClassification.from_pretrained(src, num_labels=2).to(dev)
    if st["epoch"] < a.epochs:
        # class weights: real-world data is not balanced
        pos = sum(u["label"] for u in train)
        w = torch.tensor([len(train) / (2 * (len(train) - pos)), len(train) / (2 * pos)], device=dev)
        opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
        steps = (len(train) // a.bs + 1) * a.epochs
        sch = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
        for _ in range(st["epoch"] * (len(train) // a.bs + 1)):
            sch.step()
        scaler = torch.amp.GradScaler(enabled=dev == "cuda")
        lossf = torch.nn.CrossEntropyLoss(weight=w)
        for ep in range(st["epoch"], a.epochs):
            model.train()
            t0, tot = time.time(), 0.0
            for i, b in enumerate(batches(tok, train, a.bs, a.max_len, True, a.seed + ep)):
                b = {k: v.to(dev) for k, v in b.items()}
                y = b.pop("labels")
                with torch.autocast(dev, dtype=torch.float16, enabled=dev == "cuda"):
                    loss = lossf(model(**b).logits.float(), y)
                opt.zero_grad()
                scaler.scale(loss).backward()
                scaler.unscale_(opt)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(opt)
                scaler.update()
                sch.step()
                tot += loss.item()
                if i % 200 == 0:
                    print(f"epoch {ep + 1} step {i} loss {tot / (i + 1):.4f} {time.time() - t0:.0f}s", flush=True)
            model.save_pretrained(mdir / "ckpt")
            st["epoch"] = ep + 1
            state.write_text(json.dumps(st))
            print(f"epoch {ep + 1} done, mean loss {tot / (i + 1):.4f}", flush=True)

    model.eval()
    PREDS.mkdir(parents=True, exist_ok=True)
    for ds in a.test:
        if not (DATA / "units" / f"{ds}.jsonl").exists():
            continue
        rows = units(ds)
        if ds in a.train:
            rows = [u for u in rows if held_out(u)]
        out = PREDS / f"codebert-{a.name}_{ds}.csv"
        with torch.no_grad(), open(out, "w", newline="") as fh:
            wr = csv.writer(fh)
            wr.writerow(["id", "pred", "score"])
            for b0 in range(0, len(rows), 64):
                part = rows[b0:b0 + 64]
                enc = tok([text(u) for u in part], truncation=True, max_length=a.max_len, padding=True,
                          return_tensors="pt").to(dev)
                with torch.autocast(dev, dtype=torch.float16, enabled=dev == "cuda"):
                    p = torch.softmax(model(**enc).logits.float(), -1)[:, 1].tolist()
                for u, s in zip(part, p):
                    wr.writerow([u["id"], int(s >= 0.5), round(s, 4)])
        print(f"predicted {ds}: {len(rows)} -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
