# CI demo target

`app/` holds 14 test cases copied unchanged from OWASP BenchmarkJava v1.2
(https://github.com/OWASP-Benchmark/BenchmarkJava, GPL-2.0): one real vulnerability and one false
alarm per category for SQL injection, XSS, path traversal, command injection, LDAP injection and
trust boundary, plus one weak-crypto and one weak-hash case. `expected.csv` holds their official
labels, used only to show in the demo report whether triage was right.

Any push or pull request that changes files here runs `.github/workflows/sast-triage.yml` on the
home-lab runner in incremental mode (only changed files are scanned and triaged). Run it by hand
from the Actions tab (workflow_dispatch) for a full scan, another scanner, another model, or
`model: none` to time the pipeline without triage.
