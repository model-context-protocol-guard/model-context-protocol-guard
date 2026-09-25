# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio added p95 per `tools/call` | <= 5 ms | 0.013 ms | PASS |
| H2 description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.0367 ms | PASS |

AZT-Bench test: `{"block_rate": {"count": 499, "high": 0.9996468636054409, "low": 0.9887592932948533, "n": 500, "point": 0.998}, "false_positive_rate": {"count": 0, "high": 0.007624340461552241, "low": 0.0, "n": 500, "point": 0.0}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.003826758485555124, "low": 0.0, "n": 1000, "point": 0.0}, "wilson_n_is_distinct_traces": true}`.

TLC: `specs/tlc-output.txt` reports 254,178 states generated, 10,368 distinct states, depth 4, no violations.
