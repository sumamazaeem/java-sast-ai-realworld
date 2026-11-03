#!/usr/bin/env python3
"""McNemar's test for two triage policies on the same units (per_test.csv from eval_triage/eval_snippets).

A unit is classified correctly when flagged == real (units without ground truth are skipped).
b = units policy A gets right and B wrong, c = the reverse. Exact two-sided binomial test when
b + c < 25, otherwise the chi-square statistic with continuity correction (1 degree of freedom).

usage: mcnemar.py per_test.csv POLICY_A POLICY_B
"""
import csv
import math
import sys
from collections import defaultdict


def mcnemar(b, c):
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "method": "none (no discordant units)", "p": 1.0}
    if n < 25:
        k = min(b, c)
        p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
        return {"b": b, "c": c, "method": "exact binomial", "p": p}
    chi2 = (abs(b - c) - 1) ** 2 / n
    return {"b": b, "c": c, "method": "chi-square (continuity corrected)", "chi2": round(chi2, 4),
            "p": math.erfc(math.sqrt(chi2 / 2))}


def compare(path, a, b_pol):
    correct = defaultdict(dict)
    for r in csv.DictReader(open(path)):
        if r["real"] in ("0", "1") and r["policy"] in (a, b_pol):
            correct[r["test"]][r["policy"]] = r["flagged"] == r["real"]
    b = sum(1 for v in correct.values() if len(v) == 2 and v[a] and not v[b_pol])
    c = sum(1 for v in correct.values() if len(v) == 2 and not v[a] and v[b_pol])
    n = sum(1 for v in correct.values() if len(v) == 2)
    return dict(mcnemar(b, c), units=n, a=a, b_policy=b_pol)


if __name__ == "__main__":
    res = compare(*sys.argv[1:4])
    print(f"{res['a']} vs {res['b_policy']} on {res['units']} units: {res['b']} only-{res['a']}-correct, "
          f"{res['c']} only-{res['b_policy']}-correct; {res['method']}, p = {res['p']:.4g}")
