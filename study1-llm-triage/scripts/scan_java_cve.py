#!/usr/bin/env python3
"""Scan every checked-out Java CVE Benchmark version with one SAST tool (no builds).

Each distinct (repo, tag) directory is scanned once; SARIF goes to
results/java_cve/<tool>/sarif/<repo-slug>__<tag>.sarif.gz with paths relative to the source root.
Resumable (existing SARIF is skipped); 4 threads, low priority. Run only while the GPU is idle.

tools: semgrep (p/java + p/owasp-top-ten, as on OWASP Benchmark), codeql (build-mode none,
java-security-extended).
"""
import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "datasets/java-cve-benchmark/sources.json"


def versions(sides=("vul", "fix")):
    seen = {}
    for cve, rec in json.loads(SOURCES.read_text()).items():
        for side in sides:
            d = rec.get(side, {}).get("dir")
            if d:
                seen[d] = True
    return sorted(seen)


def scan_semgrep(src, out_tmp):
    cmd = ["nice", "-n", "10", str(ROOT / ".venv/bin/semgrep"), "scan", "--metrics=off", "--config", "p/java",
           "--config", "p/owasp-top-ten", "--sarif", "--output", str(out_tmp), "--jobs", "4", "--timeout", "30",
           "--max-target-bytes", "2000000", "--no-git-ignore", "."]
    return subprocess.run(cmd, cwd=src, capture_output=True, text=True)


def scan_codeql(src, out_tmp):
    cq = str(ROOT / "tools/codeql/codeql")
    db = out_tmp.with_suffix(".db")
    shutil.rmtree(db, ignore_errors=True)
    r = subprocess.run(["nice", "-n", "10", cq, "database", "create", str(db), "--language=java", "--build-mode=none",
                        "--source-root", str(src), "--threads=4", "--overwrite"], capture_output=True, text=True)
    if r.returncode:
        return r
    r = subprocess.run(["nice", "-n", "10", cq, "database", "analyze", str(db),
                        "codeql/java-queries:codeql-suites/java-security-extended.qls", "--format=sarif-latest",
                        f"--output={out_tmp}", "--threads=4"], capture_output=True, text=True)
    shutil.rmtree(db, ignore_errors=True)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=["semgrep", "codeql"], required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--vul-only", action="store_true", help="scan only the vulnerable versions")
    ap.add_argument("--fix-for-detected", action="store_true",
                    help="scan only the fixed versions of CVEs this tool detected (per_cve.jsonl), for the strict check")
    args = ap.parse_args()
    outdir = ROOT / "results/java_cve" / args.tool / "sarif"
    outdir.mkdir(parents=True, exist_ok=True)
    log_path = ROOT / "results/java_cve" / args.tool / "scan_log.jsonl"
    failures = {}
    if log_path.exists():
        for line in log_path.read_text().splitlines():
            rec = json.loads(line)
            if not rec["ok"]:
                failures[rec["version"]] = failures.get(rec["version"], 0) + 1
    log = log_path.open("a")
    sides = ("vul",) if args.vul_only else ("vul", "fix")
    candidates = versions(sides)
    if args.fix_for_detected:
        src = json.loads(SOURCES.read_text())
        per_cve = ROOT / "results/java_cve" / args.tool / "per_cve.jsonl"
        hit = [json.loads(l)["cve"] for l in open(per_cve) if json.loads(l)["detected"]]
        candidates = sorted({src[c]["fix"]["dir"] for c in hit if src[c].get("fix", {}).get("dir")})
    todo = [d for d in candidates
            if not (outdir / (Path(d).parent.name + "__" + Path(d).name + ".sarif.gz")).exists()
            and failures.get(d, 0) < 2]  # give up on a version after two failed attempts
    if args.limit:
        todo = todo[: args.limit]
    print(f"{len(todo)} versions to scan with {args.tool}", file=sys.stderr)
    for i, d in enumerate(todo, 1):
        src = ROOT / d
        name = Path(d).parent.name + "__" + Path(d).name
        tmp = outdir / (name + ".sarif.tmp")
        t0 = time.time()
        r = (scan_semgrep if args.tool == "semgrep" else scan_codeql)(src, tmp)
        ok = r.returncode in (0, 1) and tmp.exists() and tmp.stat().st_size > 0
        if ok:
            with open(tmp, "rb") as fi, gzip.open(outdir / (name + ".sarif.gz"), "wb") as fo:
                shutil.copyfileobj(fi, fo)
            tmp.unlink()
        log.write(json.dumps({"version": d, "ok": ok, "seconds": round(time.time() - t0, 1), "returncode": r.returncode,
                              "stderr_tail": "" if ok else r.stderr[-500:]}) + "\n")
        log.flush()
        os.fsync(log.fileno())
        print(f"[{i}/{len(todo)}] {name} ok={ok} {time.time() - t0:.0f}s", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
