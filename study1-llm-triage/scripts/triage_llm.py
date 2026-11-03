#!/usr/bin/env python3
"""LLM triage of Semgrep findings on OWASP Benchmark via a local Ollama model.

For every SARIF finding that counts toward the Benchmark score (located in a
BenchmarkTest file, with a CWE matching that test's category), ask the model
for a structured verdict. Raw responses are appended to
results/triage/<model>/raw.jsonl; reruns skip findings already in that file.
Decisions/policies are applied separately by eval_triage.py.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
TEST_RE = re.compile(r"(BenchmarkTest\d{5})")

SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "unsure"]},
        "confidence": {"type": "number"},
        "evidence_lines": {"type": "array", "items": {"type": "integer"}},
    },
    "required": ["reasoning", "verdict", "confidence", "evidence_lines"],
}

SYSTEM = """You are a senior application security engineer triaging findings from a static analysis (SAST) tool on {lang} code.
Decide whether the finding is a real, exploitable vulnerability (true_positive) or a false alarm (false_positive).

How to decide:
- Trace the data flow from untrusted sources (HTTP request parameters, headers, cookies, query string, request body) to the flagged sink line.
- It is a false_positive if the value reaching the sink is not attacker-controlled (e.g. it is overwritten by a constant, or only a branch assigning a constant can execute), if it is properly sanitized, escaped, encoded or parameterized for this specific sink, or if the flagged API is used safely (e.g. a strong algorithm).
- It is a true_positive if attacker-controlled data can reach the sink without adequate protection, or the flagged API usage is weak/insecure.
- Methods of helper classes that are not shown should be assumed to pass data through unchanged unless their name clearly says otherwise.
- If the code shown is insufficient to decide, answer unsure.

Respond only with JSON: reasoning (2-4 sentences), verdict, confidence (0.0-1.0), evidence_lines (the line numbers that support your verdict)."""


def strip_comments(src, path=""):
    """Blank out comments (Java, or Python for .py files), keeping line numbers intact."""
    if str(path).endswith(".py"):
        return strip_py_comments(src)
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_py_comments(src):
    """Blank a leading module docstring and full-line # comments."""
    lines = src.splitlines()
    stripped = src.lstrip()
    if stripped[:3] in ("'''", '"""'):
        q = stripped[:3]
        start = len(src) - len(stripped)
        end = src.find(q, start + 3)
        if end > 0:
            n = src.count("\n", 0, end + 3)
            lines[:n + 1] = [""] * (n + 1)
    return "\n".join("" if l.strip().startswith("#") else l for l in lines)


def numbered(src, flag_start, flag_end):
    lines = []
    for no, line in enumerate(src.splitlines(), 1):
        if not line.strip():
            continue
        mark = ">>" if flag_start <= no <= flag_end else "  "
        lines.append(f"{mark}{no:4d} | {line.rstrip()}")
    return "\n".join(lines)


def rule_cwe_tags(rule):
    """CWE tags as in the rule ("CWE-89: ..."), else derived from other encodings (CodeQL, SpotBugs)."""
    tags = [t for t in rule.get("properties", {}).get("tags", []) if t.startswith("CWE")]
    if tags:
        return tags
    from score_owasp import rule_cwes
    return [f"CWE-{n}" for n in sorted(rule_cwes(rule))]


def relevant_findings(sarif_path, per_test_path, src_root=""):
    """src_root: directory (relative to the repo root) the SARIF paths are relative to, if not the repo root."""
    per_test = {r["test"]: r for r in csv.DictReader(open(per_test_path))}
    sarif = json.loads(Path(sarif_path).read_text())
    for run in sarif["runs"]:
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            loc = res["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"]
            if src_root:
                uri = f"{src_root.rstrip('/')}/{uri}"
            m = TEST_RE.search(uri)
            if not m or m.group(1) not in per_test:
                continue
            if res["ruleId"] not in per_test[m.group(1)]["matching_rules"].split(";"):
                continue
            reg = loc["region"]
            rule = rules[res["ruleId"]]
            fid = hashlib.sha1(f'{res["ruleId"]}|{uri}|{reg["startLine"]}|{reg.get("startColumn")}'.encode()).hexdigest()[:16]
            yield {
                "id": fid,
                "test": m.group(1),
                "rule_id": res["ruleId"],
                "level": rule.get("defaultConfiguration", {}).get("level", "warning"),
                "cwe": rule_cwe_tags(rule),
                "message": res["message"]["text"],
                "uri": uri,
                "start_line": reg["startLine"],
                "end_line": reg.get("endLine", reg["startLine"]),
            }


def fewshot_block(f, fewshot):
    """Matching hand-written examples for the finding's CWE ids, or an empty string."""
    if not fewshot:
        return ""
    ids = {m for c in f["cwe"] for m in re.findall(r"CWE-(\d+)", c)}
    examples = [e for i in sorted(ids) for e in fewshot.get(i, [])]
    if not examples:
        return ""
    parts = [f"Example ({e['verdict']}): {e['why']}\n{e['code']}" for e in examples]
    return "Examples for this weakness (not from the file under review):\n" + "\n\n".join(parts) + "\n\n"


def build_prompt(f, src, fewshot=None):
    code = numbered(strip_comments(src, f["uri"]), f["start_line"], f["end_line"])
    return fewshot_block(f, fewshot) + (
        f"Rule: {f['rule_id']}\n"
        f"CWE: {'; '.join(f['cwe'])}\n"
        f"Message: {f['message']}\n"
        f"Flagged lines: {f['start_line']}-{f['end_line']} (marked >>)\n\n"
        f"File {Path(f['uri']).name} (comments removed):\n{code}"
    )


def ask(host, model, system, prompt, num_ctx, seed, temperature=0.0):
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "format": SCHEMA,
        "stream": False,
        "options": {"temperature": temperature, "seed": seed, "num_ctx": num_ctx, "num_predict": 768},
    }
    req = urllib.request.Request(f"{host}/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


def run_metadata(host, model, args):
    """Hardware/software context for this run (GPU power cap etc.), appended to meta.jsonl."""
    def sh(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception as e:
            return f"unavailable: {e}"
    def api(path, body=None):
        try:
            req = urllib.request.Request(f"{host}{path}", data=json.dumps(body).encode() if body else None)
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read())
        except Exception as e:
            return {"error": str(e)}
    show = api("/api/show", {"model": model})
    return {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "argv": sys.argv[1:],
        "model": model,
        "model_details": show.get("details"),
        "model_digest": next((m.get("digest") for m in api("/api/tags").get("models", []) if m.get("name") == model), None),
        "ollama_version": api("/api/version").get("version"),
        "gpu": sh(["nvidia-smi", "--query-gpu=name,driver_version,power.limit,power.default_limit,memory.total,clocks.max.sm",
                   "--format=csv,noheader"]),
        "options": {"temperature": getattr(args, "temperature", 0.0), "seed": args.seed, "num_ctx": args.num_ctx, "num_predict": 768},
        "system_prompt_sha1": hashlib.sha1(SYSTEM.format(lang=args.lang).encode()).hexdigest(),
        "guardrails_frozen_tag": "guardrails-v2-frozen",
        "guardrails_frozen_commit": sh(["git", "-C", str(ROOT), "rev-list", "-n1", "guardrails-v2-frozen"]),
        "code_commit": sh(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "fewshot": getattr(args, "fewshot", None),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--sarif", default=str(ROOT / "results/pilot/semgrep.sarif"))
    ap.add_argument("--per-test", default=str(ROOT / "results/pilot/semgrep_score_per_test.csv"))
    ap.add_argument("--src-root", default="", help="prefix for SARIF paths, e.g. datasets/BenchmarkJava for CodeQL")
    ap.add_argument("--out", default=None, help="default results/triage/<model>/raw.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="only triage the first N pending findings")
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--lang", default="Java servlet", help="code kind named in the system prompt")
    ap.add_argument("--ids", default=None, help="file with finding ids (one per line) to restrict the run to")
    ap.add_argument("--fewshot", default=None, help="JSON file of per-CWE examples (e.g. config/fewshot_java.json)")
    args = ap.parse_args()

    out = Path(args.out or ROOT / "results/triage" / args.model.replace(":", "_").replace("/", "_") / "raw.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out.with_name("meta.jsonl"), "a") as mf:
        mf.write(json.dumps(run_metadata(args.host, args.model, args)) + "\n")
    done = set()
    if out.exists():
        for line in out.read_text().splitlines():
            done.add(json.loads(line)["id"])

    fewshot = json.loads(Path(args.fewshot).read_text()) if args.fewshot else None
    findings = [f for f in relevant_findings(args.sarif, args.per_test, args.src_root) if f["id"] not in done]
    if args.ids:
        wanted = set(Path(args.ids).read_text().split())
        findings = [f for f in findings if f["id"] in wanted]
    if args.limit:
        findings = findings[: args.limit]
    print(f"{len(done)} already triaged, {len(findings)} to go", file=sys.stderr)

    with open(out, "a") as fh:
        for i, f in enumerate(findings, 1):
            src = (ROOT / f["uri"]).read_text()
            t0 = time.time()
            try:
                resp = ask(args.host, args.model, SYSTEM.format(lang=args.lang), build_prompt(f, src, fewshot), args.num_ctx, args.seed)
                content, err = resp["message"]["content"], None
                stats = {k: resp.get(k) for k in ("prompt_eval_count", "eval_count", "total_duration")}
            except Exception as e:  # recorded, so the guardrail layer sees the failure
                content, err, stats = "", f"{type(e).__name__}: {e}", {}
            rec = dict(f, model=args.model, raw=content, error=err, seconds=round(time.time() - t0, 2), **stats)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            os.fsync(fh.fileno())  # survive power loss
            if i % 25 == 0 or i == len(findings):
                print(f"{i}/{len(findings)} last={rec['seconds']}s", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
