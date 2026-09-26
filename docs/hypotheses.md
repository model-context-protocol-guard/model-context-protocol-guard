# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio e2e overhead p95 per `tools/call` | pooled 95% CI upper bound <= 5 ms | 0.460 ms (upper 0.492 ms) | PASS |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.0397 ms | PASS |

## H1 method

The latency check runs 5 independent sessions with 200 warm `tools/call` samples per session. Each session starts fresh direct and guarded processes. The stdio check starts `tests/fixtures/stdio_server.py` directly, then starts `model-context-protocol-guard stdio -- <server>` around the same server. The HTTP check starts a direct Streamable HTTP server, then starts the proxy around the same upstream handler. Each session sends `initialize` and `tools/list` before sampling. Process and server startup are outside the timed window. Overhead is the paired guarded sample minus the paired direct sample.

H1 passes only when the pooled stdio `tools/call` overhead p95 95% bootstrap CI upper bound is at most 5 ms. This rule avoids claiming PASS from a single noisy session.

Background load note: Measured on a normal developer workstation with Windows Defender and other background services left enabled.

Between commits `b1589d2` and `e80e377`, `bench/run_benchmarks.py` changed imports and the CLI module name from the old package to `model_context_protocol_guard`, changed the benchmark dataset path from `../azt-bench/traces` to `../zero-trust-agent-benchmark/traces`, renamed the summary block to `zero_trust_agent_benchmark`, and expanded generated result text with v4 policy-slice metrics plus a carried v3 summary when present. The direct and guarded stdio sampling loops, warm-up requests, request frames, and timing windows did not change. The earlier H1 values were 20.194 ms, 0.439 ms, and 2.744 ms p95 across separate runs. This run measured 0.460 ms pooled p95 with a 0.492 ms upper CI bound.

## H1 sessions

| Transport | Session | Direct p50 | Direct p95 | Direct p99 | Guarded p50 | Guarded p95 | Guarded p99 | Overhead p50 | Overhead p95 | Overhead p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stdio | 1 | 0.051 ms | 0.082 ms | 0.127 ms | 0.343 ms | 0.563 ms | 0.830 ms | 0.295 ms | 0.506 ms | 0.768 ms |
| stdio | 2 | 0.054 ms | 0.103 ms | 0.143 ms | 0.391 ms | 0.649 ms | 0.886 ms | 0.335 ms | 0.599 ms | 0.834 ms |
| stdio | 3 | 0.051 ms | 0.098 ms | 0.141 ms | 0.231 ms | 0.450 ms | 0.586 ms | 0.175 ms | 0.376 ms | 0.469 ms |
| stdio | 4 | 0.071 ms | 0.192 ms | 0.407 ms | 0.210 ms | 0.343 ms | 0.473 ms | 0.139 ms | 0.224 ms | 0.351 ms |
| stdio | 5 | 0.053 ms | 0.121 ms | 0.218 ms | 0.236 ms | 0.437 ms | 0.640 ms | 0.179 ms | 0.358 ms | 0.593 ms |
| HTTP | 1 | 0.725 ms | 1.216 ms | 1.627 ms | 0.800 ms | 1.031 ms | 1.363 ms | 0.066 ms | 0.284 ms | 0.410 ms |
| HTTP | 2 | 0.722 ms | 1.037 ms | 1.724 ms | 0.698 ms | 1.021 ms | 1.447 ms | -0.012 ms | 0.296 ms | 0.787 ms |
| HTTP | 3 | 0.713 ms | 0.923 ms | 1.761 ms | 0.671 ms | 1.015 ms | 1.484 ms | -0.029 ms | 0.263 ms | 0.565 ms |
| HTTP | 4 | 0.657 ms | 0.840 ms | 1.203 ms | 0.684 ms | 1.043 ms | 1.410 ms | 0.027 ms | 0.393 ms | 0.680 ms |
| HTTP | 5 | 0.721 ms | 1.019 ms | 1.332 ms | 0.908 ms | 1.373 ms | 1.963 ms | 0.117 ms | 0.619 ms | 1.371 ms |


MCP corpus dev: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

MCP corpus held-out: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

Zero Trust Agent Benchmark test: `{"attack_policy_slices": {"in_policy": {"attack_traces": 250, "block_rate": {"count": 205, "high": 0.8626665676985582, "low": 0.7676481206243572, "n": 250, "point": 0.82}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}, "out_of_policy": {"attack_traces": 250, "block_rate": {"count": 250, "high": 1.0, "low": 0.9848667005045553, "n": 250, "point": 1.0}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}}, "block_rate": {"count": 455, "high": 0.9320574521108607, "low": 0.8816905887106665, "n": 500, "point": 0.91}, "false_positive_rate": {"count": 80, "high": 0.19470817916369146, "low": 0.13047637235016407, "n": 500, "point": 0.16}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.003826758485555124, "low": 0.0, "n": 1000, "point": 0.0}, "wilson_n_is_distinct_traces": true}`.

Zero Trust Agent Benchmark dataset: `{"dataset_version": "zero-trust-agent-benchmark-dataset-v4", "profile_version": "zero-trust-agent-benchmark-profile-v4", "test_jsonl_sha256": "4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7", "trace_file": "../zero-trust-agent-benchmark/traces/test.jsonl"}`.

Policy-slice note: FPR uses the shared benign test set; policy slices apply to attack traces..


TLC: see `specs/tlc-output.txt` from the verified run.
