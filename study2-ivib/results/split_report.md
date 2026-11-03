# Train/test split check (steps 5-6)

Training: OWASP (all), Juliet (all), CVEfixes 68 projects / 1495 methods.

| Test set | Projects | Methods | Projects also in training | CVEs also in training | Same repo name in training (forks/renames) |
|---|---|---|---|---|---|
| CWE-Bench-Java | 71 | 2118 | 0 | 0 | 0 [] |
| Java CVE Benchmark | 9 | 72 | 0 | 0 | 0 [] |
| CVEfixes held-out 20% | 22 | 426 | 0 | 0 | 0 [] |

Every CVEfixes project is wholly on one side: True.
RESULT: PASS
