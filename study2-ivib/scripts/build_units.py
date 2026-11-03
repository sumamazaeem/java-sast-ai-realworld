#!/usr/bin/env python3
"""Build one method-level dataset ("units") for the 5 target CWEs from every source we use.

A unit is one Java method (or one OWASP test file) with a label:
  label 1 = vulnerable, label 0 = not vulnerable (safe test code, or the fixed version of a real method).

Output: $IVIB_DATA/units/<dataset>.jsonl  (one JSON per line)
  {id, dataset, project, cve, cwe, label, file, method, start, end, code, pair, root}
`root` is the source tree of that project version (file is relative to it); None for CVEfixes.
`pair` links the vulnerable and fixed versions of the same real-world method, so evaluation can be
done on pairs (the harder, more realistic setting) as well as on single methods.
Also writes results/ivib/units_summary.csv (counts per dataset, CWE and label).

Datasets
  owasp     OWASP Benchmark 1.2 (synthetic, the base paper's training data) -- whole test files
  juliet    Juliet Java 1.3 (synthetic, the base paper's training data) -- bad*/good* methods
  cwebench  CWE-Bench-Java (Li et al. 2025, IRIS), real CVEs -- methods changed by the fix, vul vs fix
  javacve   Java CVE Benchmark (Li et al. 2023), real CVEs not already in cwebench -- same
  cvefixes  CVEfixes 1.0.8 (Bhandari et al. 2021), real Java fix commits -- method before vs after,
            projects/CVEs that appear in cwebench or javacve are removed (no train/test leakage)
"""
import csv
import gzip
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

HOME = Path.home()
DATA = Path(os.environ.get("IVIB_DATA", HOME / "thesis-data"))
THESIS = HOME / "thesis"
OUT = DATA / "units"
REPO = Path(__file__).resolve().parents[2]
TARGET = {22, 78, 79, 89, 94}
# CWE families folded onto the 5 targets (children / close variants)
FOLD = {23: 22, 36: 22, 73: 22, 77: 78, 80: 79, 81: 79, 83: 79, 564: 89, 95: 94, 917: 94, 1336: 94}
OWASP_CAT = {"sqli": 89, "cmdi": 78, "xss": 79, "pathtraver": 22}


def fold(c):
    c = FOLD.get(c, c)
    return c if c in TARGET else None


def uid(*parts):
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def read(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def lines(text, start, end):
    ls = text.split("\n")
    return "\n".join(ls[max(start - 1, 0):end])


DECL = r"(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)*" \
       r"(?:<[^>]+>\s*)?[\w\[\]<>,.?\s]+?\s+{name}\s*\([^;{{]*?\)\s*(?:throws[\w\s,.]+)?\{{"


def method_by_name(text, name):
    """Return (start_line, end_line, code) for every declaration of method `name` (brace matched)."""
    out = []
    for m in re.finditer(DECL.format(name=re.escape(name)), text):
        i, depth, n = m.end() - 1, 0, len(text)
        in_s = in_c = in_l = in_b = False
        while i < n:
            ch = text[i]
            nx = text[i + 1] if i + 1 < n else ""
            if in_l:
                in_l = ch != "\n"
            elif in_b:
                if ch == "*" and nx == "/":
                    in_b = False; i += 1
            elif in_s or in_c:
                if ch == "\\":
                    i += 1
                elif (in_s and ch == '"') or (in_c and ch == "'"):
                    in_s = in_c = False
            elif ch == "/" and nx == "/":
                in_l = True
            elif ch == "/" and nx == "*":
                in_b = True
            elif ch == '"':
                in_s = True
            elif ch == "'":
                in_c = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    s = text.count("\n", 0, m.start()) + 1
                    e = text.count("\n", 0, i) + 1
                    out.append((s, e, text[m.start():i + 1]))
                    break
            i += 1
    return out


# ------------------------------------------------------------------ synthetic sets
def owasp():
    root = THESIS / "datasets/BenchmarkJava"
    tc = root / "src/main/java/org/owasp/benchmark/testcode"
    for row in csv.reader(open(root / "expectedresults-1.2.csv")):
        if row[0].startswith("#") or row[1] not in OWASP_CAT:
            continue
        f = tc / f"{row[0]}.java"
        code = read(f)
        if code is None:
            continue
        yield dict(id=uid("owasp", row[0]), dataset="owasp", project="owasp-benchmark", cve=None,
                   cwe=OWASP_CAT[row[1]], label=int(row[2] == "true"), file=str(f.relative_to(root)),
                   method="doPost", start=1, end=code.count("\n") + 1, code=code, pair=None, root=str(root))


def juliet():
    root = THESIS / "datasets/juliet-java/src/Java"
    with gzip.open(THESIS / "data/juliet-java/manifest.jsonl.gz", "rt") as fh:
        for line in fh:
            case = json.loads(line)
            c = fold(case["cwe"])
            if c is None:
                continue
            for lab, key in ((1, "bad"), (0, "good")):
                for m in case.get(key, []):
                    text = read(root / m["file"])
                    if text is None:
                        continue
                    yield dict(id=uid("juliet", case["case"], m["method"], m["start"]), dataset="juliet",
                               project="juliet", cve=None, cwe=c, label=lab, file=m["file"],
                               method=m["method"], start=m["start"], end=m["end"],
                               code=lines(text, m["start"], m["end"]), pair=case["case"], root=str(root))


# ------------------------------------------------------------------ real-world sets
def cwebench():
    d = DATA / "cwe-bench-java"
    index = json.loads((d / "index.json").read_text())
    for e in index:
        if not e.get("ok"):
            continue
        seen = set()
        for fm in e["fixed_methods"]:
            name = fm["method"]
            if not name or (fm["file"], name) in seen:
                continue
            seen.add((fm["file"], name))
            pair = uid(e["slug"], fm["file"], name)
            for lab, ver in ((1, "vul"), (0, "fix")):
                text = read(d / "src" / e["slug"] / ver / fm["file"])
                if text is None:
                    continue
                for s, en, code in method_by_name(text, name):
                    yield dict(id=uid("cwebench", e["slug"], ver, fm["file"], name, s), dataset="cwebench",
                               project=e["repo"].rstrip("/").split("github.com/")[-1].lower(), cve=e["cve"],
                               cwe=e["cwe"], label=lab, file=fm["file"], method=name, start=s, end=en,
                               code=code, pair=pair, root=str(d / "src" / e["slug"] / ver))


def javacve(skip_cves):
    root = THESIS / "datasets/java-cve-benchmark"
    man = json.loads((root / "manifest.json").read_text())
    src = json.loads((root / "sources.json").read_text())
    for e in man:
        cs = [fold(int(x)) for x in re.findall(r"CWE-(\d+)", e["cwe"])]
        c = next((x for x in cs if x), None)
        if c is None or e["cve"] in skip_cves or e["cve"] not in src:
            continue
        for lab, key, ver in ((1, "vul_methods", "vul"), (0, "fix_methods", "fix")):
            info = src[e["cve"]].get(ver) or {}
            if not info.get("dir"):
                continue
            seen = set()
            for m in e[key]:
                k = (m["file"], m["start"], m["end"])
                if k in seen:
                    continue
                seen.add(k)
                text = read(THESIS / info["dir"] / m["file"])
                if text is None:
                    continue
                yield dict(id=uid("javacve", e["cve"], ver, *k), dataset="javacve",
                           project=e["repo"].lower(), cve=e["cve"], cwe=c, label=lab, file=m["file"],
                           method=m["method"], start=m["start"], end=m["end"],
                           code=lines(text, m["start"], m["end"]), pair=uid(e["cve"], m["file"], m["method"]),
                           root=str(THESIS / info["dir"]))


def cvefixes(skip_cves, skip_projects):
    dbp = DATA / "cvefixes" / (DATA / "cvefixes/db.path").read_text().strip()
    con = sqlite3.connect(f"file:{dbp}?mode=ro", uri=True)
    q = """
      SELECT f.cve_id, cc.cwe_id, f.repo_url, fc.filename, mc.name, mc.signature, mc.before_change,
             mc.code, mc.start_line, mc.end_line, fc.file_change_id
      FROM method_change mc
      JOIN file_change fc ON fc.file_change_id = mc.file_change_id
      JOIN fixes f ON f.hash = fc.hash
      JOIN cwe_classification cc ON cc.cve_id = f.cve_id
      WHERE fc.programming_language = 'Java'
    """
    seen = set()
    for cve, cwe, repo, fn, name, sig, before, code, s, e, fcid in con.execute(q):
        m = re.match(r"CWE-(\d+)", str(cwe or ""))
        c = fold(int(m.group(1))) if m else None
        proj = re.sub(r"^https?://github.com/", "", str(repo)).lower().rstrip("/")
        if c is None or cve in skip_cves or proj in skip_projects or not code:
            continue
        lab = 1 if str(before).lower() in ("true", "1") else 0
        key = (cve, fcid, sig, lab)
        if key in seen:
            continue
        seen.add(key)
        yield dict(id=uid("cvefixes", *key), dataset="cvefixes", project=proj, cve=cve, cwe=c, label=lab,
                   file=fn, method=name, start=s, end=e, code=code, pair=uid(cve, fcid, sig), root=None)


def write(name, rows):
    OUT.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    with open(OUT / f"{name}.jsonl", "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"{name}: {len(rows)} units", flush=True)
    return rows


def main():
    counts = Counter()
    for name, fn in (("owasp", owasp), ("juliet", juliet)):
        for r in write(name, fn()):
            counts[(name, r["cwe"], r["label"])] += 1
    cw = write("cwebench", cwebench())
    for r in cw:
        counts[("cwebench", r["cwe"], r["label"])] += 1
    cw_cves = {r["cve"] for r in cw}
    jc = write("javacve", javacve(cw_cves))
    for r in jc:
        counts[("javacve", r["cwe"], r["label"])] += 1
    test_cves = cw_cves | {r["cve"] for r in jc}
    test_projects = {r["project"] for r in cw + jc}
    for r in write("cvefixes", cvefixes(test_cves, test_projects)):
        counts[("cvefixes", r["cwe"], r["label"])] += 1
    out = REPO / "results/ivib/units_summary.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "cwe", "label", "units"])
        for (d, c, l), n in sorted(counts.items()):
            w.writerow([d, c, l, n])
    print(f"summary -> {out}")


if __name__ == "__main__":
    sys.exit(main())
