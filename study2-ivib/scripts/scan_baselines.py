#!/usr/bin/env python3
"""Run the rule-based baselines (CodeQL, Semgrep) on every real-world project version in the units.

Same settings as the earlier experiments (scripts/scan_java_cve.py): CodeQL build-mode none with
java-security-extended, Semgrep p/java + p/owasp-top-ten, 4 threads, nice. OWASP and Juliet are not
rescanned: their SARIF from the earlier runs is reused by score_units.py.

Resumable: a version is skipped when its SARIF exists; a version that failed twice is given up.
Output: $IVIB_DATA/sarif/<tool>/<name>.sarif.gz and $IVIB_DATA/sarif/<tool>/scan_log.jsonl
"""
import argparse
import gzip
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scan_java_cve import scan_codeql, scan_semgrep  # noqa: E402

DATA = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data"))


def sarif_name(root):
    p = Path(root)
    return p.parent.name + "__" + p.name


def roots():
    out = {}
    for ds in ("cwebench", "javacve"):
        f = DATA / "units" / f"{ds}.jsonl"
        for line in open(f):
            r = json.loads(line)
            out[r["root"]] = ds
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=["semgrep", "codeql"], required=True)
    args = ap.parse_args()
    outdir = DATA / "sarif" / args.tool
    outdir.mkdir(parents=True, exist_ok=True)
    log_path = outdir / "scan_log.jsonl"
    fails = {}
    if log_path.exists():
        for line in log_path.read_text().splitlines():
            rec = json.loads(line)
            if not rec["ok"]:
                fails[rec["root"]] = fails.get(rec["root"], 0) + 1
    todo = [r for r in roots() if not (outdir / (sarif_name(r) + ".sarif.gz")).exists() and fails.get(r, 0) < 2]
    print(f"{len(todo)} versions to scan with {args.tool}", flush=True)
    with open(log_path, "a") as log:
        for i, root in enumerate(todo, 1):
            name = sarif_name(root)
            tmp = outdir / (name + ".sarif.tmp")
            t0 = time.time()
            r = (scan_semgrep if args.tool == "semgrep" else scan_codeql)(Path(root), tmp)
            ok = r.returncode in (0, 1) and tmp.exists() and tmp.stat().st_size > 0
            if ok:
                with open(tmp, "rb") as fi, gzip.open(outdir / (name + ".sarif.gz"), "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                tmp.unlink()
            log.write(json.dumps({"root": root, "ok": ok, "seconds": round(time.time() - t0, 1),
                                  "returncode": r.returncode, "stderr_tail": "" if ok else r.stderr[-500:]}) + "\n")
            log.flush()
            os.fsync(log.fileno())
            print(f"[{i}/{len(todo)}] {name} ok={ok} {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
