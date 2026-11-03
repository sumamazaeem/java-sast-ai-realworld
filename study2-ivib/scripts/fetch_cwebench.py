#!/usr/bin/env python3
"""Fetch the Java sources of every CWE-Bench-Java project (iris-sast) in our 5 CWEs, at the buggy
commit and at the fix commit.

Only .java files are kept (the slicer and the scanners that work on source need nothing else), so
120 projects x 2 versions fit in a few GB. Resumable: a project is skipped once its `.ok` marker exists.

Output: $IVIB_DATA/cwe-bench-java/src/<slug>/{vul,fix}/...  and  .../index.json
"""
import csv
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

D = Path(os.environ.get("IVIB_DATA", Path.home() / "thesis-data")) / "cwe-bench-java"
META = D / "repo"
OUT = D / "src"
CWES = {"CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-094"}


def sh(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, check=True, capture_output=True, text=True, timeout=1800)


def fetch(url, commit, dest):
    tmp = dest.with_suffix(".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    sh("git", "init", "-q", cwd=tmp)
    sh("git", "fetch", "-q", "--depth", "1", "--filter=blob:none", url, commit, cwd=tmp)
    # sparse checkout of .java files only
    sh("git", "sparse-checkout", "set", "--no-cone", "*.java", cwd=tmp)
    sh("git", "checkout", "-q", "FETCH_HEAD", cwd=tmp)
    shutil.rmtree(tmp / ".git")
    shutil.rmtree(dest, ignore_errors=True)
    tmp.rename(dest)


def main():
    if not (META / "data/project_info.csv").exists():
        META.parent.mkdir(parents=True, exist_ok=True)
        sh("git", "clone", "-q", "--depth", "1", "https://github.com/iris-sast/cwe-bench-java.git", str(META))
    rows = [r for r in csv.DictReader(open(META / "data/project_info.csv")) if r["cwe_id"] in CWES]
    fixes = {}
    for r in csv.DictReader(open(META / "data/fix_info.csv")):
        fixes.setdefault(r["project_slug"], []).append(
            {k: r[k] for k in ("file", "class", "method", "method_start", "method_end", "signature", "commit")})
    def one(r):
        slug = r["project_slug"]
        base = OUT / slug
        url = r["github_url"].rstrip("/") + ".git"
        fix_commit = r["fix_commit_ids"].split(";")[-1].strip()
        entry = {"slug": slug, "cve": r["cve_id"], "cwe": int(r["cwe_id"].split("-")[1]),
                 "repo": r["github_url"], "vul_commit": r["buggy_commit_id"], "fix_commit": fix_commit,
                 "fixed_methods": fixes.get(slug, [])}
        if not (base / ".ok").exists():
            try:
                fetch(url, r["buggy_commit_id"], base / "vul")
                fetch(url, fix_commit, base / "fix")
                (base / ".ok").write_text("ok\n")
            except Exception as e:  # noqa: BLE001 - keep going, report at the end
                print(f"{slug}: FAILED {e}", flush=True)
                entry["error"] = str(e)[:300]
        entry["ok"] = (base / ".ok").exists()
        print(f"{slug}: {'ok' if entry['ok'] else 'missing'}", flush=True)
        return entry

    # network-bound: a few fetches in parallel
    with ThreadPoolExecutor(max_workers=6) as ex:
        index = list(ex.map(one, rows))
    (D / "index.json").write_text(json.dumps(index, indent=1))
    ok = sum(e["ok"] for e in index)
    print(f"{ok}/{len(index)} projects fetched")
    # a few projects may be gone from GitHub; 90% is enough to continue
    sys.exit(0 if ok >= 0.9 * len(index) else 1)


if __name__ == "__main__":
    main()
