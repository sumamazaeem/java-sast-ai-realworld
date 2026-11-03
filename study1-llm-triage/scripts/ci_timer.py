#!/usr/bin/env python3
"""Wall-clock timing of CI pipeline stages (thesis Section 3.8, stage 7; RQ3).

  ci_timer.py mark <stage>          record that <stage> starts now (the previous stage ends)
  ci_timer.py report --summary S    close the last stage, combine with the triage summary S and
                                    write pipeline_timing.json plus a Markdown table

Marks go to $CI_TIMING_FILE (default ./ci_timing.tsv). GPU lock waiting is subtracted from the
triage stage and shown on its own line, because it is time spent queueing behind the overnight
experiments, not time the triage itself adds. The verdict compares the pipeline time without
queueing against the 10-minute CI build budget (Rangnau et al., 2020).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

BUDGET_S = 600


def marks_file():
    return Path(os.environ.get("CI_TIMING_FILE", "ci_timing.tsv"))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mark")
    m.add_argument("stage")
    r = sub.add_parser("report")
    r.add_argument("--summary", default=None, help="triage_summary.json from ci_triage.py")
    r.add_argument("--out", default="pipeline_timing.json")
    r.add_argument("--markdown", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    r.add_argument("--meta", default="{}", help="JSON object of extra fields (scanner, commit, ...)")
    args = ap.parse_args()

    if args.cmd == "mark":
        with open(marks_file(), "a") as fh:
            fh.write(f"{args.stage}\t{time.time():.3f}\n")
        return 0

    marks = [(s, float(t)) for s, t in (l.split("\t") for l in marks_file().read_text().splitlines() if l)]
    marks.append(("end", time.time()))
    stages = {}
    for (s, t0), (_, t1) in zip(marks, marks[1:]):
        stages[s] = stages.get(s, 0) + (t1 - t0)
    tri = json.loads(Path(args.summary).read_text()) if args.summary and Path(args.summary).exists() else {}
    wait = tri.get("stage_seconds", {}).get("gpu_wait", 0.0)
    if "triage" in stages:
        stages["triage"] -= wait
    total = sum(stages.values())
    result = {
        **json.loads(args.meta),
        "stage_seconds": {k: round(v, 1) for k, v in stages.items()},
        "gpu_queue_wait_seconds": round(wait, 1),
        "pipeline_seconds_excl_queue": round(total, 1),
        "budget_seconds": BUDGET_S,
        "within_budget": total <= BUDGET_S,
        "triage_added_seconds": round(stages.get("triage", 0), 1),
        "triage_share_of_pipeline": round(stages.get("triage", 0) / total, 3) if total else None,
        "triage": tri,
    }
    Path(args.out).write_text(json.dumps(result, indent=1))
    md = ["## Pipeline timing (10-minute CI budget)", "", "| Stage | Seconds |", "|---|---|"]
    md += [f"| {k} | {v:.1f} |" for k, v in stages.items()]
    md += [f"| **total (excl. GPU queue)** | **{total:.1f}** |", f"| GPU queue wait (not counted) | {wait:.1f} |", "",
           f"{'Within' if total <= BUDGET_S else 'OVER'} the {BUDGET_S // 60}-minute budget; "
           f"triage added {stages.get('triage', 0):.0f} s ({100 * result['triage_share_of_pipeline'] if total else 0:.0f}% "
           f"of the pipeline)."
           + (f" GPU energy for triage: {tri['gpu_energy_wh']} Wh." if tri.get("gpu_energy_wh") else ""), ""]
    text = "\n".join(md) + "\n"
    if args.markdown:
        with open(args.markdown, "a") as fh:
            fh.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
