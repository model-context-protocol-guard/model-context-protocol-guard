# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio e2e overhead p95 per `tools/call` | pooled 95% CI upper bound <= 5 ms | 0.634 ms (upper 0.672 ms) | PASS |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.0741 ms | PASS |

## H1 method

The latency check runs 5 independent sessions with 200 warm `tools/call` samples per session. Each session starts fresh direct and guarded processes. The stdio check starts `tests/fixtures/stdio_server.py` directly, then starts `model-context-protocol-guard stdio -- <server>` around the same server. The HTTP check starts a direct Streamable HTTP server, then starts the proxy around the same upstream handler. Each session sends `initialize` and `tools/list` before sampling. Process and server startup are outside the timed window. Overhead is the paired guarded sample minus the paired direct sample.

H1 passes only when the pooled stdio `tools/call` overhead p95 95% bootstrap CI upper bound is at most 5 ms. This rule avoids claiming PASS from a single noisy session.

Background load note: Measured on a normal developer workstation with Windows Defender and other background services left enabled.

Between commits `3bb6a40` and `57f64f1`, `bench/run_benchmarks.py` changed imports and the CLI module name from the old package to `model_context_protocol_guard`, changed the benchmark dataset path from `../azt-bench/traces` to `../zero-trust-agent-benchmark/traces`, renamed the summary block to `zero_trust_agent_benchmark`, and expanded generated result text with v4 policy-slice metrics plus a carried v3 summary when present. The direct and guarded stdio sampling loops, warm-up requests, request frames, and timing windows did not change. The earlier H1 values were 20.194 ms, 0.439 ms, and 2.744 ms p95 across separate runs. This run measured 0.634 ms pooled p95 with a 0.672 ms upper CI bound.

## H1 sessions

| Transport | Session | Direct p50 | Direct p95 | Direct p99 | Guarded p50 | Guarded p95 | Guarded p99 | Overhead p50 | Overhead p95 | Overhead p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stdio | 1 | 0.051 ms | 0.152 ms | 1.261 ms | 0.327 ms | 0.761 ms | 5.862 ms | 0.272 ms | 0.712 ms | 5.808 ms |
| stdio | 2 | 0.055 ms | 0.135 ms | 0.251 ms | 0.293 ms | 0.631 ms | 0.928 ms | 0.233 ms | 0.544 ms | 0.828 ms |
| stdio | 3 | 0.055 ms | 0.134 ms | 0.193 ms | 0.418 ms | 0.699 ms | 1.405 ms | 0.359 ms | 0.634 ms | 1.348 ms |
| stdio | 4 | 0.072 ms | 0.158 ms | 0.234 ms | 0.289 ms | 0.583 ms | 0.717 ms | 0.215 ms | 0.460 ms | 0.651 ms |
| stdio | 5 | 0.070 ms | 0.189 ms | 0.560 ms | 0.474 ms | 0.792 ms | 1.935 ms | 0.386 ms | 0.673 ms | 1.854 ms |
| HTTP | 1 | 0.762 ms | 1.516 ms | 2.020 ms | 1.009 ms | 2.330 ms | 4.017 ms | 0.216 ms | 1.627 ms | 2.782 ms |
| HTTP | 2 | 0.806 ms | 1.491 ms | 1.818 ms | 0.875 ms | 1.632 ms | 2.091 ms | 0.058 ms | 0.755 ms | 1.309 ms |
| HTTP | 3 | 1.043 ms | 1.707 ms | 2.311 ms | 0.840 ms | 1.505 ms | 1.799 ms | -0.136 ms | 0.437 ms | 0.882 ms |
| HTTP | 4 | 0.950 ms | 1.663 ms | 2.147 ms | 0.962 ms | 1.725 ms | 2.665 ms | 0.022 ms | 0.891 ms | 1.961 ms |
| HTTP | 5 | 1.082 ms | 2.176 ms | 2.977 ms | 1.022 ms | 1.898 ms | 2.790 ms | -0.034 ms | 0.848 ms | 1.833 ms |


MCP corpus dev: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

MCP corpus held-out: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

Zero Trust Agent Benchmark test: `{"attack_policy_slices": {"in_policy": {"attack_traces": 250, "block_rate": {"count": 227, "high": 0.9379129848866933, "low": 0.8657382427250239, "n": 250, "point": 0.908}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}, "out_of_policy": {"attack_traces": 250, "block_rate": {"count": 250, "high": 1.0, "low": 0.9848667005045553, "n": 250, "point": 1.0}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}}, "block_rate": {"count": 477, "high": 0.9691548916291838, "low": 0.9319222072317267, "n": 500, "point": 0.954}, "false_positive_rate": {"count": 80, "high": 0.19470817916369146, "low": 0.13047637235016407, "n": 500, "point": 0.16}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.003826758485555124, "low": 0.0, "n": 1000, "point": 0.0}, "wilson_n_is_distinct_traces": true}`.

Zero Trust Agent Benchmark dataset: `{"dataset_version": "zero-trust-agent-benchmark-dataset-v4", "profile_version": "zero-trust-agent-benchmark-profile-v4", "test_jsonl_sha256": "4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7", "trace_file": "../zero-trust-agent-benchmark/traces/test.jsonl"}`.

Policy-slice note: FPR uses the shared benign test set; policy slices apply to attack traces..


TLC: see `specs/tlc-output.txt` from the verified run.
