# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio e2e overhead p95 per `tools/call` | pooled 95% CI upper bound <= 5 ms | 0.443 ms (upper 0.472 ms) | PASS |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.0561 ms | PASS |

## H1 method

The latency check runs 5 independent sessions with 200 warm `tools/call` samples per session. Each session starts fresh direct and guarded processes. The stdio check starts `tests/fixtures/stdio_server.py` directly, then starts `model-context-protocol-guard stdio -- <server>` around the same server. The HTTP check starts a direct Streamable HTTP server, then starts the proxy around the same upstream handler. Each session sends `initialize` and `tools/list` before sampling. Process and server startup are outside the timed window. Overhead is the paired guarded sample minus the paired direct sample.

H1 passes only when the pooled stdio `tools/call` overhead p95 95% bootstrap CI upper bound is at most 5 ms. This rule avoids claiming PASS from a single noisy session.

Background load note: Measured on a normal developer workstation with Windows Defender and other background services left enabled.

Between commits `3bb6a40` and `57f64f1`, `bench/run_benchmarks.py` changed imports and the CLI module name from the old package to `model_context_protocol_guard`, changed the benchmark dataset path from `../azt-bench/traces` to `../zero-trust-agent-benchmark/traces`, renamed the summary block to `zero_trust_agent_benchmark`, and expanded generated result text with v4 policy-slice metrics plus a carried v3 summary when present. The direct and guarded stdio sampling loops, warm-up requests, request frames, and timing windows did not change. The earlier H1 values were 20.194 ms, 0.439 ms, and 2.744 ms p95 across separate runs. This run measured 0.443 ms pooled p95 with a 0.472 ms upper CI bound.

## H1 sessions

| Transport | Session | Direct p50 | Direct p95 | Direct p99 | Guarded p50 | Guarded p95 | Guarded p99 | Overhead p50 | Overhead p95 | Overhead p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| stdio | 1 | 0.082 ms | 0.161 ms | 0.203 ms | 0.316 ms | 0.535 ms | 0.913 ms | 0.226 ms | 0.422 ms | 0.838 ms |
| stdio | 2 | 0.063 ms | 0.145 ms | 0.290 ms | 0.316 ms | 0.546 ms | 0.896 ms | 0.240 ms | 0.488 ms | 0.791 ms |
| stdio | 3 | 0.084 ms | 0.220 ms | 0.448 ms | 0.276 ms | 0.520 ms | 0.830 ms | 0.181 ms | 0.436 ms | 0.683 ms |
| stdio | 4 | 0.083 ms | 0.179 ms | 0.316 ms | 0.266 ms | 0.461 ms | 0.930 ms | 0.178 ms | 0.378 ms | 0.678 ms |
| stdio | 5 | 0.105 ms | 0.214 ms | 0.445 ms | 0.407 ms | 0.561 ms | 0.829 ms | 0.295 ms | 0.470 ms | 0.692 ms |
| HTTP | 1 | 0.845 ms | 1.354 ms | 1.851 ms | 0.885 ms | 1.370 ms | 1.884 ms | 0.051 ms | 0.522 ms | 1.117 ms |
| HTTP | 2 | 0.884 ms | 1.492 ms | 2.161 ms | 0.911 ms | 1.357 ms | 2.048 ms | 0.004 ms | 0.533 ms | 1.131 ms |
| HTTP | 3 | 1.046 ms | 1.502 ms | 2.067 ms | 0.838 ms | 1.368 ms | 2.324 ms | -0.160 ms | 0.468 ms | 1.504 ms |
| HTTP | 4 | 1.135 ms | 1.618 ms | 1.933 ms | 1.053 ms | 1.392 ms | 1.934 ms | -0.083 ms | 0.444 ms | 1.227 ms |
| HTTP | 5 | 0.841 ms | 1.358 ms | 1.612 ms | 1.181 ms | 1.640 ms | 2.467 ms | 0.298 ms | 0.776 ms | 1.561 ms |


MCP corpus dev: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

MCP corpus held-out: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

Zero Trust Agent Benchmark test: `{"attack_policy_slices": {"in_policy": {"attack_traces": 250, "block_rate": {"count": 205, "high": 0.8626665676985582, "low": 0.7676481206243572, "n": 250, "point": 0.82}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}, "out_of_policy": {"attack_traces": 250, "block_rate": {"count": 250, "high": 1.0, "low": 0.9848667005045553, "n": 250, "point": 1.0}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}}, "block_rate": {"count": 455, "high": 0.9320574521108607, "low": 0.8816905887106665, "n": 500, "point": 0.91}, "false_positive_rate": {"count": 80, "high": 0.19470817916369146, "low": 0.13047637235016407, "n": 500, "point": 0.16}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.003826758485555124, "low": 0.0, "n": 1000, "point": 0.0}, "wilson_n_is_distinct_traces": true}`.

Zero Trust Agent Benchmark dataset: `{"dataset_version": "zero-trust-agent-benchmark-dataset-v4", "profile_version": "zero-trust-agent-benchmark-profile-v4", "test_jsonl_sha256": "4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7", "trace_file": "../zero-trust-agent-benchmark/traces/test.jsonl"}`.

Policy-slice note: FPR uses the shared benign test set; policy slices apply to attack traces..


TLC: see `specs/tlc-output.txt` from the verified run.
