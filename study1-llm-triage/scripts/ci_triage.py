#!/usr/bin/env python3
"""CI stage: guarded LLM triage of SARIF findings, report and build gate.

Used by .github/workflows/sast-triage.yml (thesis Section 3.8, stages 3-7), but runs the same
from the command line. It reuses the batch experiments' prompt (triage_llm.py) and guardrails v2
(eval_triage.py), so pipeline results and batch results come from the same code.

Stages inside this script, each timed:
  normalise   read SARIF from any tool into common finding records; in incremental mode
              (--changed-files) keep only findings in files the change touched
  gpu_wait    wait for the shared GPU lock (the overnight experiment queue holds it per chunk);
              reported separately because it is queueing, not pipeline cost
  model_load  one tiny request so the model is resident before timing per-finding latency
  triage      one Ollama request per finding, in order, until --budget-seconds is spent; findings
              left over are KEPT and marked not_triaged (fail closed)
  guardrails  keep / dismiss / human review per finding (G1-G4, G6; G7 only with --min-conf)
  report      triaged SARIF (dismissed results carry a SARIF suppression), CSV, Markdown summary,
              timing.json with per-stage seconds and GPU energy

Outcomes per finding:
  dismissed     LLM said false_positive and every guardrail allowed it
  confirmed     LLM said true_positive
  human_review  LLM said unsure, or a guardrail blocked a dismissal, or the request failed
  not_triaged   time budget ran out first (kept)

Gate (exit code 1): the number of kept findings (confirmed + human_review + not_triaged) is above
--max-kept, or --fail-on-error and a kept finding comes from an error-level rule. --max-kept -1
disables the count rule (report-only mode).
"""
import argparse
import csv
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from eval_triage import GUARDS_V2, decide, lenient  # noqa: E402
from triage_llm import SYSTEM, ask, build_prompt, rule_cwe_tags, strip_comments  # noqa: E402

TEST_RE = re.compile(r"(BenchmarkTest\d{5})")


def sarif_findings(path, workspace):
    """Common finding records from one SARIF file (Semgrep, CodeQL, SpotBugs, SonarQube export)."""
    sarif = json.loads(Path(path).read_text())
    for run_no, run in enumerate(sarif["runs"]):
        driver = run["tool"]["driver"]
        tool = driver.get("name", "unknown")
        rules = {r["id"]: r for r in driver.get("rules", [])}
        for ext in run["tool"].get("extensions", []):  # CodeQL keeps its rules in query packs
            rules.update({r["id"]: r for r in ext.get("rules", [])})
        for res_no, res in enumerate(run.get("results", [])):
            if not res.get("locations"):
                continue
            loc = res["locations"][0]["physicalLocation"]
            uri = normalise_uri(loc["artifactLocation"]["uri"], workspace)
            reg = loc.get("region", {})
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id", "")
            rule = rules.get(rule_id, {})
            start = reg.get("startLine", 1)
            fid = hashlib.sha1(f'{rule_id}|{uri}|{start}|{reg.get("startColumn")}'.encode()).hexdigest()[:16]
            yield {
                "id": fid,
                "tool": tool,
                "rule_id": rule_id,
                "level": res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning"),
                "cwe": rule_cwe_tags(rule),
                "message": res.get("message", {}).get("text", ""),
                "uri": uri,
                "start_line": start,
                "end_line": reg.get("endLine", start),
                "sarif_ref": [str(path), run_no, res_no],
            }


def normalise_uri(uri, workspace):
    """Path relative to the workspace (Semgrep may write absolute paths, CodeQL relative ones)."""
    uri = uri.removeprefix("file://")
    p = Path(uri)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(Path(workspace).resolve()))
        except ValueError:
            return uri
    return uri.removeprefix("./")


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            out.append(f)
    return out


class PowerSampler(threading.Thread):
    """Samples GPU power once a second with nvidia-smi; energy is the sum of samples (Wh)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.samples, self.stop_evt = [], threading.Event()

    def run(self):
        while not self.stop_evt.is_set():
            try:
                out = subprocess.run(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"],
                                     capture_output=True, text=True, timeout=5).stdout
                self.samples.append((time.time(), sum(float(x) for x in out.split())))
            except Exception:
                return  # no GPU tools on this machine: energy is reported as null
            self.stop_evt.wait(1)

    def stop(self):
        self.stop_evt.set()
        self.join(timeout=10)
        if len(self.samples) < 2:
            return {"gpu_energy_wh": None, "gpu_mean_w": None, "gpu_peak_w": None, "power_samples": len(self.samples)}
        wh = sum((t2 - t1) * p1 for (t1, p1), (t2, _) in zip(self.samples, self.samples[1:])) / 3600
        watts = [p for _, p in self.samples]
        return {"gpu_energy_wh": round(wh, 3), "gpu_mean_w": round(sum(watts) / len(watts), 1),
                "gpu_peak_w": round(max(watts), 1), "power_samples": len(watts)}


def outcome(f, guards, min_conf, code_lines):
    if f.get("raw") is None:
        return "not_triaged", "keep:budget:not_triaged"
    if f.get("error"):
        return "human_review", "keep:error:request_failed"
    dismiss, why = decide(f, guards, min_conf, code_lines)
    if dismiss:
        return "dismissed", why
    verdict = lenient(f["raw"]).get("verdict")
    if why.startswith("keep:verdict:") and verdict == "true_positive":
        return "confirmed", why
    return "human_review", why


def load_expected(path):
    """OWASP Benchmark expected results (demo only): test name -> real vulnerability?"""
    out = {}
    for row in csv.reader(open(path)):
        if row and not row[0].startswith("#"):
            out[row[0].strip()] = row[2].strip().lower() == "true"
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sarif", nargs="+", required=True, help="SARIF file(s) from the scan stage")
    ap.add_argument("--workspace", default=".", help="checkout root; finding paths are relative to it")
    ap.add_argument("--changed-files", default=None, help="file listing changed paths (incremental mode)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST_URL", "http://127.0.0.1:11434"))
    ap.add_argument("--lang", default="Java servlet")
    ap.add_argument("--num-ctx", type=int, default=8192)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min-conf", type=float, default=None, help="enable the optional confidence gate (G7)")
    ap.add_argument("--budget-seconds", type=float, default=420,
                    help="time allowed for LLM triage; leaves room for checkout, scan and report in 10 min")
    ap.add_argument("--gpu-lock", default=None, help="lock file shared with other GPU jobs (flock)")
    ap.add_argument("--max-kept", type=int, default=-1, help="gate: fail if more findings are kept (-1 = off)")
    ap.add_argument("--fail-on-error", action="store_true", help="gate: fail if an error-level finding is kept")
    ap.add_argument("--expected", default=None, help="OWASP expected results CSV, adds ground truth (demo)")
    ap.add_argument("--no-llm", action="store_true", help="skip the model (measures the pipeline without triage)")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ws = Path(args.workspace)
    timing = {}

    # ---- normalise
    t = time.time()
    findings = dedupe([f for p in args.sarif for f in sarif_findings(p, ws)])
    total_scanned = len(findings)
    if args.changed_files:
        changed = {normalise_uri(l.strip(), ws) for l in Path(args.changed_files).read_text().splitlines() if l.strip()}
        findings = [f for f in findings if f["uri"] in changed]
    findings = [f for f in findings if (ws / f["uri"]).is_file()]
    timing["normalise"] = time.time() - t

    # ---- GPU lock, model load, triage
    lock_fh, power = None, {}
    timing["gpu_wait"] = timing["model_load"] = timing["triage"] = 0.0
    system = SYSTEM.format(lang=args.lang)
    if findings and not args.no_llm:
        if args.gpu_lock:
            t = time.time()
            lock_fh = open(args.gpu_lock, "a")
            print(f"waiting for GPU lock {args.gpu_lock}", file=sys.stderr, flush=True)
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            timing["gpu_wait"] = time.time() - t
        sampler = PowerSampler()
        sampler.start()
        t = time.time()
        try:
            ask(args.host, args.model, "Reply with JSON.", "ping", args.num_ctx, args.seed)
        except Exception as e:
            print(f"model load failed: {e}", file=sys.stderr)
        timing["model_load"] = time.time() - t
        t = deadline_start = time.time()
        for i, f in enumerate(findings, 1):
            if time.time() - deadline_start > args.budget_seconds:
                print(f"budget of {args.budget_seconds}s spent; {len(findings) - i + 1} findings kept untriaged",
                      file=sys.stderr)
                break
            t0 = time.time()
            try:
                src = (ws / f["uri"]).read_text(errors="replace")
                resp = ask(args.host, args.model, system, build_prompt(f, src), args.num_ctx, args.seed)
                f["raw"], f["error"] = resp["message"]["content"], None
                f.update({k: resp.get(k) for k in ("prompt_eval_count", "eval_count", "total_duration")})
            except Exception as e:  # fail closed: the guardrail layer keeps it
                f["raw"], f["error"] = "", f"{type(e).__name__}: {e}"
            f["seconds"] = round(time.time() - t0, 2)
            print(f"[{i}/{len(findings)}] {f['uri']}:{f['start_line']} {f['rule_id']} {f['seconds']}s",
                  file=sys.stderr, flush=True)
        timing["triage"] = time.time() - t
        power = sampler.stop()
        if lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
            lock_fh.close()

    # ---- guardrails
    t = time.time()
    guards = set(GUARDS_V2) | ({"confidence"} if args.min_conf is not None else set())
    code_lines = {}
    for u in {f["uri"] for f in findings}:
        src = strip_comments((ws / u).read_text(errors="replace"), u)
        code_lines[u] = {i for i, line in enumerate(src.splitlines(), 1) if line.strip()}
    for f in findings:
        f["outcome"], f["rule"] = outcome(f, guards, args.min_conf, code_lines)
        v = lenient(f.get("raw") or "")
        f["verdict"], f["reasoning"] = v.get("verdict"), v.get("reasoning")
    timing["guardrails"] = time.time() - t

    # ---- report
    t = time.time()
    expected = load_expected(args.expected) if args.expected else None
    for f in findings:
        m = TEST_RE.search(f["uri"])
        f["ground_truth"] = None if not expected or not m or m.group(1) not in expected else (
            "real" if expected[m.group(1)] else "fake")
    write_outputs(out, findings, args)
    counts = Counter(f["outcome"] for f in findings)
    kept = [f for f in findings if f["outcome"] != "dismissed"]
    gate_reasons = []
    if args.max_kept >= 0 and len(kept) > args.max_kept:
        gate_reasons.append(f"{len(kept)} kept findings > max {args.max_kept}")
    if args.fail_on_error and any(f["level"] == "error" for f in kept):
        gate_reasons.append("an error-level finding was kept")
    timing["report"] = time.time() - t

    per = [f["seconds"] for f in findings if "seconds" in f]
    summary = {
        "model": None if args.no_llm else args.model,
        "mode": "incremental" if args.changed_files else "full",
        "findings_scanned": total_scanned,
        "findings_in_scope": len(findings),
        "outcomes": dict(counts),
        "gate": "fail" if gate_reasons else "pass",
        "gate_reasons": gate_reasons,
        "budget_seconds": args.budget_seconds,
        "stage_seconds": {k: round(v, 2) for k, v in timing.items()},
        "per_finding_seconds": {"n": len(per), "mean": round(sum(per) / len(per), 2) if per else None,
                                "max": max(per) if per else None},
        **power,
        "guardrails": sorted(guards),
        "rules_fired": dict(Counter(f["rule"].rsplit(":", 1)[0] for f in findings)),
    }
    if expected:
        summary["ground_truth"] = {
            "dismissed_real": sum(1 for f in findings if f["outcome"] == "dismissed" and f["ground_truth"] == "real"),
            "dismissed_fake": sum(1 for f in findings if f["outcome"] == "dismissed" and f["ground_truth"] == "fake"),
            "kept_real": sum(1 for f in kept if f["ground_truth"] == "real"),
            "kept_fake": sum(1 for f in kept if f["ground_truth"] == "fake"),
        }
    (out / "triage_summary.json").write_text(json.dumps(summary, indent=1))
    (out / "report.md").write_text(markdown(findings, summary))
    print(json.dumps(summary, indent=1))
    return 1 if gate_reasons else 0


def write_outputs(out, findings, args):
    with open(out / "raw.jsonl", "w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")
    cols = ["outcome", "rule", "tool", "rule_id", "level", "uri", "start_line", "cwe", "verdict", "reasoning",
            "seconds", "ground_truth"]
    with open(out / "findings.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            w.writerow({**f, "cwe": ";".join(f["cwe"])})
    # triaged SARIF: every result gets properties.triage; dismissed ones get a suppression,
    # which SARIF viewers and code-scanning tools hide by default but keep for audit
    by_ref = {tuple(f["sarif_ref"]): f for f in findings}
    for path in args.sarif:
        sarif = json.loads(Path(path).read_text())
        for run_no, run in enumerate(sarif["runs"]):
            for res_no, res in enumerate(run.get("results", [])):
                f = by_ref.get((str(path), run_no, res_no))
                if not f:
                    continue
                res.setdefault("properties", {})["triage"] = {
                    k: f.get(k) for k in ("outcome", "rule", "verdict", "reasoning")} | {"model": args.model}
                if f["outcome"] == "dismissed":
                    res["suppressions"] = [{"kind": "external", "status": "accepted",
                                            "justification": f"LLM triage ({args.model}): {f.get('reasoning')}"}]
        (out / f"triaged-{Path(path).name}").write_text(json.dumps(sarif))


def markdown(findings, s):
    st = s["stage_seconds"]
    o = s["outcomes"]
    lines = [
        "## Guarded AI triage of SAST findings",
        "",
        f"**Gate: {s['gate'].upper()}**" + (f" ({'; '.join(s['gate_reasons'])})" if s["gate_reasons"] else ""),
        "",
        f"Model `{s['model']}`, {s['mode']} mode: {s['findings_in_scope']} findings triaged "
        f"(of {s['findings_scanned']} reported by the scanner).",
        "",
        "| Outcome | Findings |",
        "|---|---|",
        *[f"| {k} | {o.get(k, 0)} |" for k in ("dismissed", "confirmed", "human_review", "not_triaged")],
        "",
        "| Triage stage | Seconds |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in st.items()],
        "",
        f"Per finding: mean {s['per_finding_seconds']['mean']} s, max {s['per_finding_seconds']['max']} s. "
        f"GPU energy: {s.get('gpu_energy_wh')} Wh (mean {s.get('gpu_mean_w')} W).",
    ]
    if s.get("ground_truth"):
        g = s["ground_truth"]
        lines += ["", f"Ground truth (OWASP Benchmark labels, demo only): dismissed {g['dismissed_fake']} false alarms "
                      f"and {g['dismissed_real']} real vulnerabilities; kept {g['kept_real']} real and "
                      f"{g['kept_fake']} false alarms."]
    lines += ["", "| Outcome | Finding | Rule | Guardrail decision | Model reasoning |", "|---|---|---|---|---|"]
    order = {"human_review": 0, "confirmed": 1, "not_triaged": 2, "dismissed": 3}
    for f in sorted(findings, key=lambda f: (order[f["outcome"]], f["uri"], f["start_line"])):
        gt = f" ({f['ground_truth']})" if f.get("ground_truth") else ""
        why = (f.get("reasoning") or f.get("error") or "").replace("|", "/").replace("\n", " ")
        lines.append(f"| {f['outcome']}{gt} | `{Path(f['uri']).name}:{f['start_line']}` | `{f['rule_id'].split('.')[-1]}` "
                     f"({f['level']}) | {f['rule']} | {why[:300]} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
