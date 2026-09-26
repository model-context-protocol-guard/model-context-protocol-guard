# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio e2e overhead p95 per `tools/call` | <= 5 ms | 2.744 ms | PASS |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.4289 ms | PASS |

## H1 method

The stdio latency check starts `tests/fixtures/stdio_server.py` directly, then starts `model-context-protocol-guard stdio -- <server>` around the same server. Each process is started once. The benchmark sends `initialize` and `tools/list` before sampling. Each H1 sample times one `tools/call` request and response on the warm session. Process startup is outside the timed window. Overhead is the paired guarded sample minus the paired direct sample.

Between commits `3bb6a40` and `57f64f1`, `bench/run_benchmarks.py` changed imports and the CLI module name from the old package to `model_context_protocol_guard`, changed the benchmark dataset path from `../azt-bench/traces` to `../zero-trust-agent-benchmark/traces`, renamed the summary block to `zero_trust_agent_benchmark`, and expanded generated result text with v4 policy-slice metrics plus a carried v3 summary when present. The direct and guarded stdio sampling loops, warm-up requests, request frames, and timing windows did not change. The earlier H1 value was 20.194 ms p95. This run measured 2.744 ms p95 with the same end-to-end method.

MCP corpus dev: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

MCP corpus held-out: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

Zero Trust Agent Benchmark test: `{"attack_policy_slices": {"in_policy": {"attack_traces": 250, "block_rate": {"count": 227, "high": 0.9379129848866933, "low": 0.8657382427250239, "n": 250, "point": 0.908}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}, "out_of_policy": {"attack_traces": 250, "block_rate": {"count": 250, "high": 1.0, "low": 0.9848667005045553, "n": 250, "point": 1.0}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}}, "block_rate": {"count": 477, "high": 0.9691548916291838, "low": 0.9319222072317267, "n": 500, "point": 0.954}, "false_positive_rate": {"count": 80, "high": 0.19470817916369146, "low": 0.13047637235016407, "n": 500, "point": 0.16}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.003826758485555124, "low": 0.0, "n": 1000, "point": 0.0}, "wilson_n_is_distinct_traces": true}`.

Zero Trust Agent Benchmark dataset: `{"dataset_version": "zero-trust-agent-benchmark-dataset-v4", "profile_version": "zero-trust-agent-benchmark-profile-v4", "test_jsonl_sha256": "4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7", "trace_file": "../zero-trust-agent-benchmark/traces/test.jsonl"}`.

Policy-slice note: FPR uses the shared benign test set; policy slices apply to attack traces.

TLC: see `specs/tlc-output.txt` from the verified run.
