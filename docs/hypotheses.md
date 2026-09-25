# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio e2e overhead p95 per `tools/call` | <= 5 ms | 20.194 ms | FAIL |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | 0.983 / 0.017 | PASS |
| H3 definition changes detected | 100% | 1.000 | PASS |
| H4 token verify mean | <= 0.5 ms | 0.0478 ms | PASS |

MCP corpus dev: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

MCP corpus held-out: `{"attacks": 220, "benign": 220, "detection": {"count": 220, "high": 1.0, "low": 0.9828384838048643, "n": 220, "point": 1.0}, "false_positive": {"count": 0, "high": 0.01716151619513562, "low": 0.0, "n": 220, "point": 0.0}}`.

AZT-Bench test: `{"attack_policy_slices": {"in_policy": {"attack_traces": 250, "block_rate": {"count": 229, "high": 0.9444039612333553, "low": 0.8750051335864348, "n": 250, "point": 0.916}, "leak_count": 1, "leak_rate": {"count": 1, "high": 0.02230578556541592, "low": 0.0007064475340650972, "n": 250, "point": 0.004}}, "out_of_policy": {"attack_traces": 250, "block_rate": {"count": 249, "high": 0.9992935524659348, "low": 0.9776942144345839, "n": 250, "point": 0.996}, "leak_count": 0, "leak_rate": {"count": 0, "high": 0.015133299495444574, "low": 0.0, "n": 250, "point": 0.0}}}, "block_rate": {"count": 478, "high": 0.9707660443713928, "low": 0.9342805571276716, "n": 500, "point": 0.956}, "false_positive_rate": {"count": 14, "high": 0.04644640267494888, "low": 0.016750974720756446, "n": 500, "point": 0.028}, "leak_count": 1, "leak_rate": {"count": 1, "high": 0.0056425585979579355, "low": 0.00017654637062607817, "n": 1000, "point": 0.001}, "wilson_n_is_distinct_traces": true}`.

AZT-Bench dataset: `{"dataset_version": "azt-bench-dataset-v3", "profile_version": "azt-bench-profile-v3", "test_jsonl_sha256": "ce942cac25394fcf5e96bf41c58102f341b2983047e4082a4b7f6e71714cf341", "trace_file": "..\\azt-bench\\traces\\test.jsonl"}`.

TLC: see `specs/tlc-output.txt` from the verified run.
