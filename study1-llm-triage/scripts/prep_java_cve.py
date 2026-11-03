#!/usr/bin/env python3
"""Build a manifest for the Java CVE Benchmark (Li et al., ESEC/FSE 2023).

Inputs (datasets/java-cve-benchmark/, from https://sites.google.com/view/java-sast-study):
  Real-world_benchmark.xlsx   CVE list with project, CWE and (sometimes) patch commit
  vul_info/vul_info/*.csv     vulnerable methods: "file:[start,end]:method" per CVE/version
  patch_info/patch_info/*.csv fixed methods in the patched version

Label file names are "<project>_<CVE>_<project>-<git tag>.csv". The GitHub repository of each
project is resolved with the GitHub search API and accepted only if the vulnerable tag exists
there (git ls-remote); results are cached in repos.json, which can also be edited by hand.

Writes manifest.json (one entry per CVE) and repos.json. Resumable via the repos.json cache.
"""
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "datasets/java-cve-benchmark"
NAME_RE = re.compile(r"^(?P<project>.*?)_(?P<cve>CVE-\d+-\d+)_(?P<version>.*)\.csv$")
PATH_RE = re.compile(r"^(?P<file>.*?):\[(?P<start>\d+),(?P<end>\d+)\]:(?P<method>.*)$")
csv.field_size_limit(sys.maxsize)


def read_methods(path):
    rows = list(csv.reader(open(path, encoding="utf-8-sig")))
    out = []
    for r in rows[1:]:
        m = PATH_RE.match(r[0]) if r else None
        if m:
            out.append({"file": m["file"], "start": int(m["start"]), "end": int(m["end"]), "method": m["method"]})
    return out


def label_files(sub):
    files = {}
    for p in sorted((D / sub / sub).glob("*.csv")):
        m = NAME_RE.match(p.name)
        if m:
            files[m["cve"]] = (m["project"], m["version"], p)
    return files


def tag_exists(repo, tag):
    try:
        out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git", f"refs/tags/{tag}"],
                             capture_output=True, text=True, timeout=60).stdout
        return bool(out.strip())
    except Exception:
        return False


_TAGS = {}


def repo_tags(repo):
    if repo not in _TAGS:
        try:
            out = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"],
                                 capture_output=True, text=True, timeout=120).stdout
            _TAGS[repo] = {l.split("refs/tags/", 1)[1].removesuffix("^{}") for l in out.splitlines() if "refs/tags/" in l}
        except Exception:
            _TAGS[repo] = set()
    return _TAGS[repo]


def resolve_tag(repo, tag):
    """The label's tag or a common variant of it that exists in the repo, else None."""
    if not repo:
        return None
    tags = repo_tags(repo)
    bare = re.sub(r"^[A-Za-z][\w.]*?(-[A-Za-z][\w.]*?)*-(?=\d)", "", tag)  # "resteasy-3.1.1.Final" -> "3.1.1.Final"
    name = repo.split("/")[1]
    for t in (tag, "v" + tag, tag.removeprefix("v"), tag.replace("_", "."), "rel/" + tag.removeprefix("rel-"),
              bare, "v" + bare, f"{name}-{bare}", f"{name.lower()}-{bare}"):
        if t in tags:
            return t
    return None


def candidates(project, patch_url):
    if patch_url:
        m = re.match(r"https://github.com/([^/]+/[^/]+)/commit/", patch_url)
        if m:
            yield m.group(1)
    out = subprocess.run(["gh", "api", "-X", "GET", "search/repositories", "-f", f"q={project} in:name language:Java",
                          "-f", "sort=stars", "-f", "per_page=5", "--jq", ".items[].full_name"],
                         capture_output=True, text=True, timeout=60).stdout.split()
    exact = [r for r in out if r.split("/")[1].lower() == project.lower()]
    yield from exact + [r for r in out if r not in exact]


def main():
    ws = openpyxl.load_workbook(D / "Real-world_benchmark.xlsx", read_only=True)["Overall"]
    sheet = {}
    for r in ws.iter_rows(values_only=True):
        r = tuple(r) + (None,) * 10
        if r[1] and re.match(r"CVE-\d+-\d+$", str(r[1])):
            sheet[r[1]] = {"project": r[0], "cwe": r[4], "cwe_name": r[5], "stars": r[7], "patch_commit": r[8]}

    vul, fix = label_files("vul_info"), label_files("patch_info")
    cache_path = D / "repos.json"
    repos = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    manifest = []
    for cve in sorted(vul):
        project, version, vpath = vul[cve]
        tag = version[len(project) + 1:] if version.startswith(project + "-") else version
        info = sheet.get(cve, {})
        entry = {"cve": cve, "project": project, "cwe": info.get("cwe"), "cwe_name": info.get("cwe_name"),
                 "vul_version": version, "vul_tag": tag, "vul_methods": read_methods(vpath)}
        if cve in fix:
            _, fversion, fpath = fix[cve]
            entry.update(fix_version=fversion,
                         fix_tag=fversion[len(project) + 1:] if fversion.startswith(project + "-") else fversion,
                         fix_methods=read_methods(fpath))
        key = project
        if key not in repos:
            repos[key] = None
            for cand in candidates(project, info.get("patch_commit")):
                if tag_exists(cand, tag):
                    repos[key] = cand
                    break
            cache_path.write_text(json.dumps(repos, indent=1, sort_keys=True))
            print(f"{project:32} -> {repos[key]}", file=sys.stderr, flush=True)
        entry["repo"] = repos[key]
        entry["vul_git_tag"] = resolve_tag(repos[key], tag)
        entry["fix_git_tag"] = resolve_tag(repos[key], entry["fix_tag"]) if entry.get("fix_tag") else None
        entry["vul_tag_ok"] = bool(entry["vul_git_tag"])
        manifest.append(entry)

    (D / "manifest.json").write_text(json.dumps(manifest, indent=1))
    ok = sum(e["vul_tag_ok"] for e in manifest)
    print(f"{len(manifest)} CVEs, {len({e['project'] for e in manifest})} projects, "
          f"{ok} with repo + vulnerable tag resolved; unresolved projects: "
          f"{sorted({e['project'] for e in manifest if not e['vul_tag_ok']})}")


if __name__ == "__main__":
    main()
