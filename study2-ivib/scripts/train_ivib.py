#!/usr/bin/env python3
"""Train and evaluate IVIB's BERT-BiLSTM-CRF on IVIB-R slices.

The model class is IVIB's own (experiment/mycode/a_超参数训练/model.py, BERT_BLSTM_CRF), ported to
current PyTorch/transformers with no change to the architecture: bert-base-cased, one BiLSTM layer
(768 per direction), linear emission layer, CRF over the state tags, tags as in IVIB's TAG2IDX plus
pathvul/codevul for our two extra CWEs. Training follows the paper's best setting (Adam, lr 1e-5,
dropout 0.1, 20 epochs) and IVIB's code (batch size 1, max length 200, every ISL token added to the
tokenizer as one token). A slice is predicted by the CRF state of its final vulType token.

  train_ivib.py cv    --spec ivib  --train owasp juliet         # Step 2: 5-fold CV (80/20), like the paper
  train_ivib.py fit   --spec ivib5 --train owasp juliet --name synth
                      --test cwebench javacve cvefixes          # Step 3 / 5: train once, predict test sets

Predictions are written per unit (results/ivib/preds/ivib-<name>_<dataset>.csv) so score_units.py
scores them like the scanners. A unit with no slice cannot be reported by IVIB: pred 0.
Checkpoints every epoch to $IVIB_DATA/models/ivib-<name>[-fold<k>]/ and resumes.
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
from torch import nn
from torchcrf import CRF
from transformers import BertModel, BertPreTrainedModel, BertTokenizer

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]
TAG2IDX = {"xpathvul": 0, "xssvul": 1, "sqlvul": 2, "cmdvul": 3, "novul": 4, "taint": 5, "san": 6, "val": 7,
           "conf": 8, "n-taint": 9, "chg": 10, "[CLS]": 11, "[SEP]": 12, "X": 13, "pathvul": 14, "codevul": 15}
VUL = {"xssvul", "sqlvul", "cmdvul", "xpathvul", "pathvul", "codevul"}
MAX_LEN = 200


class BERT_BLSTM_CRF(BertPreTrainedModel):  # IVIB's model, unchanged apart from device handling
    def __init__(self, config):
        super().__init__(config)
        self.num_labels = config.num_labels
        self.hidden_size = config.hidden_size
        self.rnn_layers = 1
        self.bert = BertModel(config)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.lstm = nn.LSTM(config.hidden_size, config.hidden_size, num_layers=1, bidirectional=True,
                            batch_first=True)
        self.classifier = nn.Linear(config.hidden_size * 2, self.num_labels)
        self.crf = CRF(self.num_labels, batch_first=True)
        self.post_init()

    def forward(self, input_ids, attn_masks, labels=None):
        seq = self.bert(input_ids, attn_masks)[0]
        h = (torch.randn(2, input_ids.size(0), self.hidden_size, device=seq.device),
             torch.randn(2, input_ids.size(0), self.hidden_size, device=seq.device))
        out, _ = self.lstm(seq, h)
        emission = self.classifier(self.dropout(out))
        mask = attn_masks.bool()
        if labels is not None:
            return -self.crf(torch.log_softmax(emission, 2), labels, mask=mask, reduction="mean")
        return self.crf.decode(emission, mask=mask)


def load(spec, ds):
    p = DATA / "slices" / spec / f"{ds}.jsonl"
    return [json.loads(l) for l in open(p)] if p.exists() else []


def all_tokens(*sets):
    toks = set()
    for s in sets:
        for r in s:
            toks.update(r["tokens"])
    return sorted(toks)


def build(tokens):
    tok = BertTokenizer.from_pretrained("bert-base-cased")
    tok.add_tokens(tokens)
    model = BERT_BLSTM_CRF.from_pretrained("bert-base-cased", num_labels=len(TAG2IDX), hidden_dropout_prob=0.1)
    model.resize_token_embeddings(len(tok))
    # transformers >= 5 leaves layers outside BERT uninitialised on load (they are not in the
    # checkpoint), which made the CRF loss explode (~1e32). Initialise them the PyTorch way.
    with torch.no_grad():
        model.lstm.reset_parameters()
        model.classifier.reset_parameters()
        model.crf.reset_parameters()
    return model, tok


def encode(tok, r):
    ids = tok.convert_tokens_to_ids(r["tokens"][-MAX_LEN:])
    tags = [TAG2IDX[s] for s in r["states"][-MAX_LEN:]]
    return torch.tensor([ids]), torch.ones(1, len(ids), dtype=torch.long), torch.tensor([tags])


def train(model, tok, rows, mdir, epochs, lr, seed, dev):
    mdir.mkdir(parents=True, exist_ok=True)
    st_p = mdir / "state.json"
    st = json.loads(st_p.read_text()) if st_p.exists() else {"epoch": 0}
    if st["epoch"]:
        model.load_state_dict(torch.load(mdir / "model.pt", map_location=dev))
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    if st["epoch"] and (mdir / "opt.pt").exists():
        opt.load_state_dict(torch.load(mdir / "opt.pt", map_location=dev))
    for ep in range(st["epoch"], epochs):
        model.train()
        order = rows[:]
        random.Random(seed + ep).shuffle(order)
        t0, tot = time.time(), 0.0
        for r in order:
            ids, m, y = (x.to(dev) for x in encode(tok, r))
            opt.zero_grad()
            loss = model(ids, m, y)
            loss.backward()
            opt.step()
            tot += loss.item()
        torch.save(model.state_dict(), mdir / "model.pt.tmp")
        torch.save(opt.state_dict(), mdir / "opt.pt.tmp")
        os.replace(mdir / "model.pt.tmp", mdir / "model.pt")
        os.replace(mdir / "opt.pt.tmp", mdir / "opt.pt")
        st["epoch"] = ep + 1
        st_p.write_text(json.dumps(st))
        print(f"  epoch {ep + 1}/{epochs} loss {tot / max(len(order), 1):.4f} {time.time() - t0:.0f}s", flush=True)


def predict(model, tok, rows, dev):
    model.eval()
    id2 = {v: k for k, v in TAG2IDX.items()}
    out = []
    with torch.no_grad():
        for r in rows:
            ids, m, _ = (x.to(dev) for x in encode(tok, r))
            out.append(id2[model(ids, m)[0][-1]])
    return out


def report(y, p):
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    res = {"n": len(y), "accuracy": accuracy_score(y, p)}
    for avg in ("macro", "weighted"):
        pr, rc, f1, _ = precision_recall_fscore_support(y, p, average=avg, zero_division=0)
        res.update({f"{avg}_precision": pr, f"{avg}_recall": rc, f"{avg}_f1": f1})
    yb, pb = [int(v in VUL) for v in y], [int(v in VUL) for v in p]
    pr, rc, f1, _ = precision_recall_fscore_support(yb, pb, average="binary", zero_division=0)
    res.update({"binary_precision": pr, "binary_recall": rc, "binary_f1": f1})
    return {k: round(v, 4) if isinstance(v, float) else v for k, v in res.items()}


def fold_of(r, k):
    return int(hashlib.md5(r["unit"].encode()).hexdigest(), 16) % k


def cmd_cv(a, dev):
    rows = sum((load(a.spec, ds) for ds in a.train), [])
    toks = all_tokens(rows)
    out_p = REPO / f"results/ivib/replication_{a.spec}.csv"
    done = {int(r["fold"]) for r in csv.DictReader(open(out_p))} if out_p.exists() else set()
    print(f"{len(rows)} slices, {len(toks)} distinct ISL tokens, {a.folds}-fold CV", flush=True)
    for k in range(a.folds):
        if k in done:
            continue
        tr = [r for r in rows if fold_of(r, a.folds) != k]
        te = [r for r in rows if fold_of(r, a.folds) == k]
        random.seed(a.seed); torch.manual_seed(a.seed)
        model, tok = build(toks)
        model.to(dev)
        print(f"fold {k}: train {len(tr)} test {len(te)}", flush=True)
        train(model, tok, tr, DATA / "models" / f"ivib-cv-{a.spec}-fold{k}", a.epochs, a.lr, a.seed, dev)
        rep = report([r["states"][-1] for r in te], predict(model, tok, te, dev))
        rep["fold"] = k
        new = not out_p.exists()
        with open(out_p, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rep))
            if new:
                w.writeheader()
            w.writerow(rep)
        print(f"fold {k}: {rep}", flush=True)
        del model
        torch.cuda.empty_cache()


def held_out(project):  # same 80/20 split by project as train_codebert.py
    return int(hashlib.md5(project.encode()).hexdigest(), 16) % 5 == 0


def unit_project(ds):
    return {u["id"]: u["project"] for u in (json.loads(l) for l in open(DATA / "units" / f"{ds}.jsonl"))}


def cmd_fit(a, dev):
    tr, tests = [], {}
    for ds in a.train:
        rows = load(a.spec, ds)
        if ds in a.test:  # a real-world set used for training is split by project; test only on held-out
            proj = unit_project(ds)
            rows = [r for r in rows if not held_out(proj[r["unit"]])]
        tr += rows
    for ds in a.test:
        rows = load(a.spec, ds)
        if ds in a.train:
            proj = unit_project(ds)
            rows = [r for r in rows if held_out(proj[r["unit"]])]
        tests[ds] = rows
    toks = all_tokens(tr, *tests.values())  # unseen test tokens get (untrained) embeddings, as in IVIB
    random.seed(a.seed); torch.manual_seed(a.seed)
    model, tok = build(toks)
    model.to(dev)
    print(f"fit {a.name}: {len(tr)} training slices", flush=True)
    train(model, tok, tr, DATA / "models" / f"ivib-{a.name}", a.epochs, a.lr, a.seed, dev)
    pdir = REPO / "results/ivib/preds"
    pdir.mkdir(parents=True, exist_ok=True)
    for ds, rows in tests.items():
        pred = dict(zip((r["unit"] for r in rows), predict(model, tok, rows, dev)))
        units = [json.loads(l) for l in open(DATA / "units" / f"{ds}.jsonl")]
        if ds in a.train:
            units = [u for u in units if held_out(u["project"])]
        with open(pdir / f"ivib-{a.name}_{ds}.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "pred", "state", "sliced"])
            for u in units:
                s = pred.get(u["id"])
                w.writerow([u["id"], int(s in VUL) if s else 0, s or "", int(s is not None)])
        print(f"predicted {ds}: {len(rows)} slices over {len(units)} units", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["cv", "fit"])
    ap.add_argument("--spec", required=True)
    ap.add_argument("--train", nargs="+", required=True)
    ap.add_argument("--test", nargs="*", default=[])
    ap.add_argument("--name", default="")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--lr", type=float, default=1e-5)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    (cmd_cv if a.cmd == "cv" else cmd_fit)(a, dev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
