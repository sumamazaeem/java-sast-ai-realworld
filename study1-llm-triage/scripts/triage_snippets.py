#!/usr/bin/env python3
"""LLM triage of arbitrary findings given as an items file (real-world CVE projects, Juliet, ...).

Each item (JSONL): id, uri (path relative to the repo root), start_line, end_line, rule_id, cwe (list
of "CWE-n" strings), message, level, label ("real" / "fake" / "unlabelled"), and optional mask (true
for Juliet: method names bad*/good* and the class name would give the answer away, so they are
renamed consistently before the code is shown).

The model sees a window of the comment-stripped file around the flagged lines (default 60 lines
before and after) with the same system prompt, JSON schema and options as triage_llm.py. Output
records follow the triage_llm.py raw.jsonl format plus "label" and "window" (the line range shown),
so eval_snippets.py can apply the same guardrail policies. Resumable; every record is fsynced.
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from triage_llm import SYSTEM, ask, fewshot_block, run_metadata, strip_comments  # noqa: E402

NAME_RE = re.compile(r"\b(?:bad|good)\w*|\bCWE\d+_\w+")


def mask(text):
    """Rename Juliet's revealing identifiers (bad*/good* methods, CWE class names) consistently."""
    names = {}

    def sub(m):
        names.setdefault(m.group(), f"m{len(names) + 1}" if not m.group().startswith("CWE") else f"Case{len(names) + 1}")
        return names[m.group()]
    return NAME_RE.sub(sub, text)


def window(item, before, after):
    src = strip_comments((ROOT / item["uri"]).read_text(errors="replace"), item["uri"])
    if item.get("mask"):
        src = mask(src)
    lines = src.splitlines()
    lo = max(1, item["start_line"] - before)
    hi = min(len(lines), item["end_line"] + after)
    out = []
    for no in range(lo, hi + 1):
        line = lines[no - 1]
        if line.strip():
            mark = ">>" if item["start_line"] <= no <= item["end_line"] else "  "
            out.append(f"{mark}{no:5d} | {line.rstrip()}")
    return "\n".join(out), lo, hi


def prompt(item, code, lo, hi):
    name = "Case.java" if item.get("mask") else Path(item["uri"]).name
    message = mask(item["message"]) if item.get("mask") else item["message"]
    return (f"Rule: {item['rule_id']}\n"
            f"CWE: {'; '.join(item['cwe'])}\n"
            f"Message: {message}\n"
            f"Flagged lines: {item['start_line']}-{item['end_line']} (marked >>)\n\n"
            f"File {name}, lines {lo}-{hi} (comments removed):\n{code}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--items", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--lang", default="Java")
    ap.add_argument("--before", type=int, default=60)
    ap.add_argument("--after", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--temperature", type=float, default=0.0, help="0 = the frozen deterministic setting")
    ap.add_argument("--fewshot", default=None, help="JSON file of per-CWE examples (config/fewshot_java.json)")
    args = ap.parse_args()
    fewshot = json.loads(Path(args.fewshot).read_text()) if args.fewshot else None

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out.with_name("meta.jsonl"), "a") as mf:
        mf.write(json.dumps(dict(run_metadata(args.host, args.model, args), items=args.items,
                                 window=[args.before, args.after])) + "\n")
    done = {json.loads(l)["id"] for l in out.read_text().splitlines()} if out.exists() else set()
    items = [json.loads(l) for l in open(args.items)]
    todo = [it for it in items if it["id"] not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"{len(done)} done, {len(todo)} to go", file=sys.stderr)
    system = SYSTEM.format(lang=args.lang)
    with open(out, "a") as fh:
        for i, it in enumerate(todo, 1):
            t0 = time.time()
            try:
                code, lo, hi = window(it, args.before, args.after)
                p = prompt(it, code, lo, hi)
                if fewshot:
                    p = fewshot_block({"cwe": it["cwe"]}, fewshot) + p
                resp = ask(args.host, args.model, system, p, args.num_ctx, args.seed, args.temperature)
                content, err = resp["message"]["content"], None
                stats = {k: resp.get(k) for k in ("prompt_eval_count", "eval_count", "total_duration")}
            except Exception as e:
                content, err, stats, lo, hi = "", f"{type(e).__name__}: {e}", {}, 0, 0
            rec = dict(it, model=args.model, raw=content, error=err, window=[lo, hi],
                       seconds=round(time.time() - t0, 2), **stats)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            if i % 25 == 0 or i == len(todo):
                print(f"{i}/{len(todo)} last={rec['seconds']}s", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
