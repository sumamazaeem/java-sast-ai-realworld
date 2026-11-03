#!/usr/bin/env python3
"""Build a ground-truth manifest for the Juliet Test Suite for Java 1.3 (NIST SARD).

Juliet encodes ground truth in names:
  - test case = files CWE<id>_<name>__<variant>_<flow>[ _a.._e ].java (multi-file cases share the
    base name and differ in the _a/_b/... suffix);
  - methods whose name starts with "bad" (bad, badSink, badSource, ...) contain the flaw;
  - methods whose name starts with "good" (good, goodG2B, goodB2G, good1, goodSink, ...) are the
    non-flawed variants of the same code; some flaw types use whole classes named *_bad / *_good*.
Method line ranges are found with a brace-matching scan (comments and strings skipped), which is
reliable for Juliet's generated, uniformly formatted code.

Writes data/juliet-java/manifest.jsonl.gz (one line per test case: cwe, files, bad/good method ranges)
and prints coverage statistics. No builds, no scans.
"""
import gzip
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "datasets/juliet-java/src/Java/src/testcases"
OUT = ROOT / "data/juliet-java/manifest.jsonl.gz"
FILE_RE = re.compile(r"^(?P<case>CWE(?P<cwe>\d+)_.+?)(?:_(?P<part>[a-e]|base|bad|good\w*))?\.java$")
METHOD_RE = re.compile(r"^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w.<>\[\]]+\s+"
                       r"(?P<name>(?:bad|good)\w*)\s*\(")


TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def strip(src):
    """Replace comments and string/char literals by spaces, keeping line structure."""
    return TOKENS.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), src)


def methods(path):
    """[(name, start_line, end_line)] for bad*/good* methods."""
    text = strip(path.read_text(errors="replace"))
    lines = text.split("\n")
    found, i = [], 0
    while i < len(lines):
        m = METHOD_RE.match(lines[i]) if ("bad" in lines[i] or "good" in lines[i]) else None
        if m and not lines[i].rstrip().endswith(";"):
            depth, started, j = 0, False, i
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                started = started or "{" in lines[j]
                if started and depth <= 0:
                    break
                j += 1
            found.append((m["name"], i + 1, j + 1))
            i = j + 1
        else:
            i += 1
    return found


def main():
    cases = {}
    for f in sorted(SRC.rglob("CWE*.java")):
        m = FILE_RE.match(f.name)
        if not m:
            continue
        case = cases.setdefault(m["case"], {"case": m["case"], "cwe": int(m["cwe"]), "files": [], "bad": [], "good": []})
        rel = str(f.relative_to(ROOT / "datasets/juliet-java/src/Java"))
        case["files"].append(rel)
        part = m["part"] or ""
        for name, s, e in methods(f):
            kind = "bad" if name.startswith("bad") else "good"
            case[kind].append({"file": rel, "method": name, "start": s, "end": e})
        if part == "bad" or part.startswith("good"):  # class-level flaw/fix files: whole file
            n = f.read_text(errors="replace").count("\n") + 1
            case["bad" if part == "bad" else "good"].append({"file": rel, "method": "<class>", "start": 1, "end": n})

    usable = [c for c in cases.values() if c["bad"] and c["good"]]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt") as fh:
        fh.writelines(json.dumps(c) + "\n" for c in usable)
    per_cwe = Counter(c["cwe"] for c in usable)
    print(f"{len(cases)} test cases, {len(usable)} with both bad and good code, {len(per_cwe)} CWEs; "
          f"{sum(len(c['files']) for c in usable)} files", file=sys.stderr)
    print("top CWEs:", per_cwe.most_common(15), file=sys.stderr)
    print("dropped (no bad or no good method found):", len(cases) - len(usable), file=sys.stderr)


if __name__ == "__main__":
    main()
