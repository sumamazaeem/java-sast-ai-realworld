# Strong on Benchmarks, Weak on CVEs: artifact

Code, results and analysis scripts for the paper *Strong on Benchmarks, Weak on CVEs: Testing Two AI Aids for Java Static Security Analysis on Real Vulnerabilities*.

Both studies run on one consumer GPU (RTX 2070, 8 GB) with open-weight models served by Ollama. No code is sent to an external service.

## Layout

| Folder | Contents |
|---|---|
| `study1-llm-triage/` | Study 1: LLM triage of Semgrep and CodeQL findings with fail-closed guardrails |
| `study2-ivib/` | Study 2: IVIB-R (a rebuild of the IVIB slicer), LLM-inferred taint specifications, CodeBERT baselines, real-fix training, CodeQL/Semgrep at method level |
| `paper-analysis/` | Scripts that produce the Study 2 statistics, the tables and the figures in the paper |

### Study 1 (`study1-llm-triage/`)

- `scripts/triage_llm.py`, `scripts/triage_snippets.py`: LLM triage (Qwen2.5-Coder 7B/14B, Llama 3.1 8B). Fixed JSON schema, comments stripped, temperature 0 and seed 42 unless set otherwise.
- `scripts/eval_triage.py`, `scripts/eval_snippets.py`: guardrail policies (v1, v2, v2 + agreement) and the leave-one-out and only-one ablations.
- `scripts/ml_triage.py`, `scripts/ml_snippets.py`: Random Forest baseline.
- `scripts/bootstrap_ci.py`, `scripts/mcnemar.py`: confidence intervals and paired tests.
- `scripts/m1_robustness.sh`, `scripts/m1_robustness_report.py`: few-shot and temperature 0.7 robustness runs.
- `scripts/ci_triage.py`, `.github/workflows/sast-triage.yml`: the CI stage (self-hosted runner with a GPU).
- `results/FINAL_COMPARISON.md`: all main tables.
- `results/triage*/`: every prompt result as `raw.jsonl` (model output), plus `per_test.csv` and `scores.csv`.
- `results/robustness_realworld/summary.md`: robustness runs.
- `results/spotcheck/labels.csv`: manual check of 60 unlabelled real-world findings, done by one reviewer (an AI assistant) against fixed criteria.
- `results/bootstrap/ci.csv`, `results/timing/`, `results/ci_runs/`: intervals, timing and CI runs.
- `demo/`: a small, deliberately vulnerable demo application used for the CI runs. Do not deploy it.

### Study 2 (`study2-ivib/`)

- `scripts/build_units.py`: method-level units from OWASP, Juliet, CWE-Bench-Java, the Java CVE Benchmark and CVEfixes.
- `scripts/check_split.py`: leakage check (no project, CVE or repository shared between training and test).
- `scripts/ivib_r.py`, `scripts/build_slices.py`: IVIB-R slicer.
- `scripts/llm_specs.py`: LLM-inferred sources, sinks and sanitisers.
- `scripts/train_ivib.py`, `scripts/train_codebert.py`: training.
- `scripts/scan_baselines.py`, `scripts/score_units.py`: CodeQL and Semgrep at method level, and scoring.
- `scripts/steps/`: the step order.
- `results/RESULTS.md`, `results/metrics.csv`: all results.
- `results/units_labels.csv`: unit ids, labels, projects and vulnerable/fixed pairs.
- `results/preds/`: per-unit predictions of every model and tool.
- `results/ivib_release_audit.md`: what the public IVIB release contains.

## Data and third-party material

This repository holds no third-party source code, datasets or model weights. Scripts download them from their original sources:

- [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava)
- [Juliet Test Suite for Java](https://samate.nist.gov/SARD/)
- the Java CVE Benchmark (Li et al., ESEC/FSE 2023)
- [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java)
- [CVEfixes](https://github.com/secureIT-project/CVEfixes)
- [IVIB](https://github.com/KLSEHB/IVIB)
- models through Ollama and Hugging Face

The results here contain only identifiers, file paths, line numbers, labels, scanner messages and model outputs. Model outputs can quote short fragments of the open-source code under analysis.

## Reproducing the paper's numbers

    pip install scipy matplotlib numpy scikit-learn
    python3 -I paper-analysis/src/m2_stats.py study2-ivib/results paper-analysis/tables
    python3 -I paper-analysis/src/make_figures.py paper-analysis/tables study2-ivib/results paper-analysis/figures
    python3 -I study1-llm-triage/scripts/compare_all.py      # Study 1 tables (run inside study1-llm-triage/)

Rerunning the LLM triage and training needs Ollama, a GPU and the datasets above. The scripts are resumable.

## Licence

Code: MIT (see `LICENSE`). Results, labels and figures: CC BY 4.0.
