#!/usr/bin/env python3
"""Check out the vulnerable and fixed source versions listed in the Java CVE Benchmark manifest.

Downloads GitHub's source tarball for each tag (codeload, snapshot only, no history) and
extracts it with tarfile's "data" filter into src/<owner>__<name>/<tag>/. Every labelled
vulnerable/fixed file is checked to exist at its tag; results go to sources.json. Resumable:
existing checkouts are skipped.
No builds are run.
"""
import json
import shutil
import sys
import tarfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "datasets/java-cve-benchmark"


def checkout(repo, tag):
    slug = repo.replace("/", "__")
    dest = D / "src" / slug / tag.replace("/", "_")
    if (dest / ".complete").exists():
        return dest, None
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    url = f"https://codeload.github.com/{repo}/tar.gz/refs/tags/{urllib.parse.quote(tag)}"
    tmp = dest.parent / (dest.name + ".tar.gz")
    try:
        with urllib.request.urlopen(url, timeout=600) as r, open(tmp, "wb") as fh:
            shutil.copyfileobj(r, fh)
        with tarfile.open(tmp) as tf:
            members = tf.getmembers()
            top = members[0].name.split("/")[0] if members else ""
            keep = []
            for m in members:  # drop the "<repo>-<tag>/" top folder
                if m.name.startswith(top + "/"):
                    m.name = m.name[len(top) + 1:]
                    keep.append(m)
            tf.extractall(dest, members=keep, filter="data")
    except Exception as e:
        return None, f"download/extract failed: {type(e).__name__}: {e}"[:200]
    finally:
        tmp.unlink(missing_ok=True)
    (dest / ".complete").write_text(tag)
    return dest, None


def main():
    manifest = json.loads((D / "manifest.json").read_text())
    # Download every distinct (repo, tag) first, 4 at a time: GitHub's tarball endpoint is slow per
    # connection, and this is network-bound, not CPU-bound.
    pairs = sorted({(e["repo"], e[k]) for e in manifest if e.get("vul_tag_ok") for k in ("vul_git_tag", "fix_git_tag")
                    if e.get(k)})
    with ThreadPoolExecutor(max_workers=4) as pool:
        for (repo, tag), (dest, err) in zip(pairs, pool.map(lambda p: checkout(*p), pairs)):
            print(f"{repo:40} {tag:30} {'ok' if dest else err}", file=sys.stderr, flush=True)
    status_path = D / "sources.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {}
    for e in manifest:
        if not e.get("vul_tag_ok") or e["cve"] in status:
            continue
        rec = {"repo": e["repo"]}
        for side, tag_key, methods_key in (("vul", "vul_git_tag", "vul_methods"), ("fix", "fix_git_tag", "fix_methods")):
            tag = e.get(tag_key)
            if not tag:
                rec[side] = {"error": "no tag"}
                continue
            dest, err = checkout(e["repo"], tag)
            files = sorted({m["file"] for m in e.get(methods_key, [])})
            missing = [f for f in files if dest is None or not (dest / f).exists()]
            rec[side] = {"tag": tag, "dir": str(dest.relative_to(ROOT)) if dest else None, "error": err,
                         "labelled_files": len(files), "missing_files": missing}
        status[e["cve"]] = rec
        status_path.write_text(json.dumps(status, indent=1))
        v = rec["vul"]
        print(f"{e['cve']:18} {e['repo']:40} {v.get('tag')!s:30} missing={len(v.get('missing_files', []))}"
              f"{' ERR ' + v['error'] if v.get('error') else ''}", file=sys.stderr, flush=True)
    ok = [c for c, r in status.items() if r["vul"].get("dir") and not r["vul"].get("missing_files")]
    print(f"{len(status)} CVEs processed; {len(ok)} with vulnerable source and all labelled files present")


if __name__ == "__main__":
    main()
