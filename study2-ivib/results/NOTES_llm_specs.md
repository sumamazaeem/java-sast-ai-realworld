# Is the LLM spec used? (checked 2026-11-01)

Yes for CWE-Bench-Java and the Java CVE Benchmark, but it changes almost nothing.
- Spec files exist for all 230 project versions and `build_slices.py --spec llm` loads them (they add 4 sources and
  4 sinks on average over the parameters-as-sources baseline).
- On the 2,118 CWE-Bench-Java methods only 140 contain a call to a newly added source, 17 a newly added sink, and
  2 contain both. So a source-to-sink path inside one method is almost never created by the new names:
  slice coverage 179 -> 180 (CWE-Bench-Java), 6 -> 6 (Java CVE). The limit is method-level slicing, not the lists.
- CVEfixes units have no project checkout (root = None), so they get NO LLM spec at all: coverage 256/1921 is
  identical by construction. Enhancement 1 was therefore not applied to CVEfixes training or testing.
