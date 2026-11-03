# Method 1 robustness on the real-world set (90 real, 597 other findings)

| Run | Guardrails | Real lost (of 90) | Other removed (of 597) | Precision kept | McNemar p (v2 vs none, real findings) |
|---|---|---|---|---|---|
| reference (zero-shot, T=0) | none | 33 | 365 | 0.197 |  |
| reference (zero-shot, T=0) | v2 | 9 | 313 | 0.222 | 1.19e-07 |
| few-shot, T=0 | none | 25 | 370 | 0.223 |  |
| few-shot, T=0 | v2 | 8 | 317 | 0.227 | 1.53e-05 |
| zero-shot, T=0.7, seed 1 | none | 21 | 346 | 0.216 |  |
| zero-shot, T=0.7, seed 1 | v2 | 6 | 289 | 0.214 | 6.1e-05 |
| zero-shot, T=0.7, seed 2 | none | 24 | 350 | 0.211 |  |
| zero-shot, T=0.7, seed 2 | v2 | 7 | 295 | 0.216 | 1.53e-05 |
| zero-shot, T=0.7, seed 3 | none | 22 | 336 | 0.207 |  |
| zero-shot, T=0.7, seed 3 | v2 | 8 | 293 | 0.212 | 0.000122 |

- T=0.7, no guardrails: real lost mean 22.3, range 21-24 over 3 seeds
- T=0.7, guardrails v2: real lost mean 7.0, range 6-8 over 3 seeds
- Unguarded keep/dismiss decision differs between seeds for 249 of 687 findings (36.2%)
