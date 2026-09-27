# Claims tested

Results are generated from bench artifacts. The shared benchmark test file sha256 remains `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`.

| Claim | Threshold | Result | Outcome |
|---|---|---:|---|
| Stdio end-to-end overhead 95th percentile per `tools/call` | pooled 95% confidence interval upper bound <= 5 ms | 0.460 ms (upper 0.492 ms) | Met |
| Held-out description corpus detection and false positive rate Wilson bounds | detection low >= 0.95 and false positive rate high <= 0.02 | 0.983 / 0.017 | Met |
| Definition changes detected | 100% | 1.000 | Met |
| Token verification mean | <= 0.5 ms | 0.0397 ms | Met |
| Shared benchmark v4.1 attacks blocked | 100% point estimate | 1.000 [0.992, 1.000] | Met |
| Shared benchmark v4.1 false positives | <= 0.020 point estimate | 0.012 [0.006, 0.026] | Met by point estimate; Wilson upper bound exceeds 0.020 |
| Shared benchmark v4.1 leaks | 0 leaked traces | 0.000 [0.000, 0.004] | Met |

## Benchmark defense ablation

| Version | Test block rate | Test false positive rate | Test leak rate | Official evaluator p95 latency |
|---|---:|---:|---:|---:|
| Version 1 public baseline | 0.910 [0.882, 0.932] | 0.160 [0.130, 0.195] | 0.000 [0.000, 0.004] | 0.138 ms [0.131, 0.146] |
| Final design iteration: structural context checks, requester authority, canonical payload handling, safe scope bridge | 1.000 [0.992, 1.000] | 0.012 [0.006, 0.026] | 0.000 [0.000, 0.004] | 0.284 ms [0.248, 0.336] |

Only one post-baseline design iteration was evaluated on the test split; individual controls were tuned on dev and are grouped to preserve the test split budget.

## Official evaluator reports

| Setting | Block rate | False positive rate | Leak rate | In-policy block | Out-of-policy block |
|---|---:|---:|---:|---:|---:|
| provide_issued_secrets=True | 1.000 [0.992, 1.000] | 0.012 [0.006, 0.026] | 0.000 [0.000, 0.004] | 1.000 [0.985, 1.000] | 1.000 [0.985, 1.000] |
| provide_issued_secrets=False | 1.000 [0.992, 1.000] | 0.012 [0.006, 0.026] | 0.000 [0.000, 0.004] | 1.000 [0.985, 1.000] | 1.000 [0.985, 1.000] |

The dev split final report was 1.000 block, 0.000 false positive, and 0.000 leak.

## Method notes

The defense now uses request-visible structure only: tool risk, role scopes, origin, arguments, user task text, and untrusted content. It does not read trace label, family, template, description, metadata, split, or per-step malicious fields. Regression tests randomize or add those fields at the request boundary and assert byte-identical decisions.

## Remaining gaps

- The test false-positive point estimate is below 2%, but the Wilson 95% upper bound is 2.6%; the benchmark has 500 benign traces, so this release cannot honestly claim an upper confidence bound at or below 2%.
- The grouped post-baseline row is the only test-evaluated design iteration after version 1. More granular control-by-control test ablations were not run to avoid repeated test-split tuning.

TLA+ model checker run: see `specs/tlc-output.txt` from the verified run.
