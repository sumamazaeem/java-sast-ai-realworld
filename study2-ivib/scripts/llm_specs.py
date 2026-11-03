#!/usr/bin/env python3
"""Enhancement 1: a local LLM infers the taint specifications (sources, sinks, sanitisers) that IVIB
hard-codes in Constants.java.

For each project version we collect the candidate APIs the code actually calls (method name, the
class it is most likely called on from the imports, and a call-site example), then ask Qwen2.5-Coder
7B (Ollama, temperature 0, JSON schema output) to label each candidate as
  source            returns attacker-controlled data (e.g. HttpServletRequest.getParameter)
  sink:<cwe>        executes/uses data in a way that is dangerous for that CWE (e.g. Statement.executeQuery: 89)
  sanitizer:<cwe>   neutralises data for that CWE (e.g. ESAPI encodeForHTML: 79)
  none
Guardrails (same idea as the triage guardrails): the answer must use only candidate names that exist
in the project (no invented APIs), labels outside the schema are dropped, and every candidate is asked
twice in a different batch order; a label is kept only if both answers agree (self-consistency).

Output: $IVIB_DATA/specs/<version>.json  {"sources": [...], "sinks": {cwe: [...]}, "sanitizers": {cwe: [...]}}
        results/ivib/specs_summary.csv
Resumable per version and per batch (cache file per version).
"""
import argparse
import csv
import json
import os
import random
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))
REPO = Path(__file__).resolve().parents[2]
OUT = DATA / "specs"
CWES = [22, 78, 79, 89, 94]
LABELS = ["source", "none"] + [f"sink:{c}" for c in CWES] + [f"sanitizer:{c}" for c in CWES]
CALL_RE = re.compile(r"(?:(\b[A-Za-z_]\w*)\s*\.\s*)?\b([a-z]\w*)\s*\(")
IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.M)
JAVA_KW = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "super", "this", "assert",
           "throw", "else", "try", "do", "case"}
# Candidates whose class comes from one of these packages are the APIs that matter for taint specs.
API_PREFIXES = ("java.", "javax.", "jakarta.", "org.springframework.", "org.apache.", "com.fasterxml.",
                "org.hibernate.", "io.vertx.", "io.netty.", "org.owasp.", "org.jsoup.", "freemarker.",
                "org.thymeleaf.", "groovy.", "org.mvel2.", "ognl.", "org.eclipse.jetty.", "com.google.",
                "org.codehaus.", "org.yaml.", "spark.", "io.undertow.", "org.glassfish.", "com.mysql.")

SYSTEM = (
    "You are a Java application-security expert building taint-analysis specifications for injection "
    "vulnerabilities: SQL injection (CWE-89), OS command injection (CWE-78), cross-site scripting (CWE-79), "
    "path traversal (CWE-22) and code/expression injection (CWE-94). For each API method you are given, "
    "decide one label:\n"
    "- source: its return value can carry attacker-controlled input (HTTP parameters, headers, cookies, "
    "request bodies, uploaded file names, environment, sockets, files read from user-chosen paths).\n"
    "- sink:<cwe>: passing attacker data to it causes that injection (e.g. Statement.executeQuery -> sink:89, "
    "Runtime.exec -> sink:78, PrintWriter.print on an HTTP response -> sink:79, new File / Files.newInputStream "
    "-> sink:22, ScriptEngine.eval / SpelExpressionParser.parseExpression -> sink:94).\n"
    "- sanitizer:<cwe>: it neutralises data for that injection (escaping, encoding, canonical-path checks, "
    "prepared-statement parameter binding).\n"
    "- none: anything else (string utilities, collections, logging, getters of server configuration).\n"
    "Think about each method on its own: a method that returns any part of an HTTP request (parameter, "
    "header, cookie, query string, URI, body, part) is a source even if it looks harmless; a method that "
    "writes to an HTTP response body, runs a query, starts a process, opens a file path or evaluates an "
    "expression/script is a sink.\n"
    "Answer only with the JSON object asked for. Use the method keys exactly as given."
)


def candidates(root, limit):
    """Most-called (class, method) pairs in the project whose class resolves to a library import."""
    calls = Counter()
    example = {}
    for f in Path(root).rglob("*.java"):
        if "/test/" in str(f):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        imports = {i.rsplit(".", 1)[-1]: i for i in IMPORT_RE.findall(text)}
        # crude local type inference: "Type var" declarations in the file
        decl = {v: t for t, v in re.findall(r"\b([A-Z]\w*)(?:<[^>]*>)?\s+([a-z]\w*)\s*[=;,)]", text)}
        for line in text.split("\n"):
            for recv, name in CALL_RE.findall(line):
                if name in JAVA_KW:
                    continue
                cls = recv if recv[:1].isupper() else decl.get(recv, "")
                fq = imports.get(cls, "")
                if not fq.startswith(API_PREFIXES) and not cls in ("String", "Runtime", "ProcessBuilder", "File"):
                    continue
                key = f"{fq or cls}.{name}"
                calls[key] += 1
                example.setdefault(key, line.strip()[:160])
    top = [k for k, _ in calls.most_common(limit)]
    return [{"key": k, "example": example[k]} for k in top]


def ask(host, model, cands, seed):
    schema = {"type": "object", "properties": {c["key"]: {"type": "string", "enum": LABELS} for c in cands},
              "required": [c["key"] for c in cands]}
    prompt = "Label each API method. Call-site examples are from the project.\n\n" + "\n".join(
        f"- {c['key']}    e.g. `{c['example']}`" for c in cands)
    body = {"model": model, "stream": False, "format": schema, "keep_alive": 0,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            "options": {"temperature": 0, "seed": seed, "num_ctx": 8192, "num_predict": 2048}}
    req = urllib.request.Request(f"{host}/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=900) as r:
        msg = json.loads(r.read())["message"]["content"]
    try:
        ans = json.loads(msg)
    except json.JSONDecodeError:
        return {}
    keys = {c["key"] for c in cands}
    return {k: v for k, v in ans.items() if k in keys and v in LABELS}  # guardrail: no invented keys/labels


def infer(root, name, host, model, limit, batch):
    OUT.mkdir(parents=True, exist_ok=True)
    cache_p = OUT / f"{name}.cache.json"
    cache = json.loads(cache_p.read_text()) if cache_p.exists() else {"cands": None, "runs": [{}, {}]}
    if cache["cands"] is None:
        cache["cands"] = candidates(root, limit)
    cands = cache["cands"]
    for run, seed in ((0, 1), (1, 2)):
        order = cands[:] if run == 0 else random.Random(7).sample(cands, len(cands))
        todo = [c for c in order if c["key"] not in cache["runs"][run]]
        for i in range(0, len(todo), batch):
            part = todo[i:i + batch]
            got = ask(host, model, part, seed)
            for c in part:
                cache["runs"][run][c["key"]] = got.get(c["key"], "none")
            cache_p.write_text(json.dumps(cache))
    spec = {"sources": [], "sinks": defaultdict(list), "sanitizers": defaultdict(list), "disagreements": 0}
    for c in cands:
        a, b = cache["runs"][0].get(c["key"]), cache["runs"][1].get(c["key"])
        if a != b:
            spec["disagreements"] += 1
            continue
        if a == "source":
            spec["sources"].append(c["key"])
        elif a.startswith("sink:"):
            spec["sinks"][a[5:]].append(c["key"])
        elif a.startswith("sanitizer:"):
            spec["sanitizers"][a[10:]].append(c["key"])
    spec["candidates"] = len(cands)
    (OUT / f"{name}.json").write_text(json.dumps(spec, indent=1))
    return spec


def roots():
    """Every project version used in the real-world tests, plus OWASP and Juliet."""
    seen = {}
    for ds in ("owasp", "juliet", "cwebench", "javacve"):
        p = DATA / "units" / f"{ds}.jsonl"
        if p.exists():
            for line in open(p):
                r = json.loads(line)
                seen.setdefault(r["root"], ds)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--limit", type=int, default=300, help="candidate APIs per project version")
    ap.add_argument("--batch", type=int, default=40)
    a = ap.parse_args()
    rows = []
    rs = roots()
    for i, (root, ds) in enumerate(sorted(rs.items()), 1):
        name = Path(root).parent.name + "__" + Path(root).name
        t0 = time.time()
        spec = infer(root, name, a.host, a.model, a.limit, a.batch)
        rows.append([ds, name, spec["candidates"], len(spec["sources"]), sum(map(len, spec["sinks"].values())),
                     sum(map(len, spec["sanitizers"].values())), spec["disagreements"]])
        print(f"[{i}/{len(rs)}] {name}: {rows[-1][2:]} {time.time() - t0:.0f}s", flush=True)
    p = REPO / "results/ivib/specs_summary.csv"
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "version", "candidates", "sources", "sinks", "sanitizers", "disagreements"])
        w.writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
