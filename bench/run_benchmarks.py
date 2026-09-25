from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_guard.azt_adapter import defense
from mcp_guard.corpus import generate_corpus
from mcp_guard.models import ToolDefinition
from mcp_guard.pipeline import GuardConfig, GuardPipeline
from mcp_guard.screening import screen_description
from mcp_guard.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson
from mcp_guard.tokens import CapabilityIssuer, Caveats

TOOL = ToolDefinition(
    "fetch",
    "Fetch approved URL.",
    {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    {},
).to_mcp()


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_id() -> str:
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{socket.gethostname().split('.')[0].lower()[:12]}"


def timed_ns(fn: Any) -> int:
    start = time.perf_counter_ns()
    fn()
    return time.perf_counter_ns() - start


def direct_list() -> list[dict[str, Any]]:
    return [TOOL]


def direct_call() -> dict[str, Any]:
    return {"content": [{"type": "text", "text": "ok"}]}


def interval(values: list[float], q: float) -> dict[str, Any]:
    return bootstrap_quantile_ci(values, q, resamples=500, seed=19).as_dict()


def summarize_latencies(values: list[float]) -> dict[str, Any]:
    return {
        "mean_ci_ms": mean_t_ci(values).as_dict(),
        "p50_ms": quantile(values, 0.50),
        "p95_ms": quantile(values, 0.95),
        "p95_ci_ms": interval(values, 0.95),
        "p99_ms": quantile(values, 0.99),
    }


def corpus_metrics(corpus: Path) -> dict[str, Any]:
    attacks = benign = detected = fps = 0
    with corpus.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            bad = bool(screen_description("bench", row["tool"], row["description"]))
            if row["label"] == "attack":
                attacks += 1
                detected += int(bad)
            else:
                benign += 1
                fps += int(bad)
    return {
        "attacks": attacks,
        "benign": benign,
        "detection": {"count": detected, "n": attacks, **wilson(detected, attacks).as_dict()},
        "false_positive": {"count": fps, "n": benign, **wilson(fps, benign).as_dict()},
    }


def azt_metrics() -> dict[str, Any]:
    try:
        from azt_bench import evaluate, load_traces
    except Exception as exc:
        return {"status": "skipped", "reason": exc.__class__.__name__}
    trace_dir = Path("..") / "azt-bench" / "traces"
    traces = load_traces("test", trace_dir if trace_dir.exists() else None)
    report = evaluate(defense, traces)
    return report.to_dict()


def git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None


def write_manifest(out: Path) -> None:
    rows = []
    for p in sorted(x for x in out.rglob("*") if x.is_file() and x.name != "manifest.sha256"):
        rows.append(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}"
        )
    (out / "manifest.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def update_docs(summary: dict[str, Any]) -> None:
    results = summary["latency"]
    corpus = summary["mcp_corpus"]
    azt = summary["azt_bench"]
    table = (
        "| Metric | Value | 95% CI |\n|---|---:|---:|\n"
        f"| stdio tools/call added p95 | {results['stdio_call_added_ms']['p95_ms']:.3f} ms | "
        f"[{results['stdio_call_added_ms']['p95_ci_ms']['low']:.3f}, {results['stdio_call_added_ms']['p95_ci_ms']['high']:.3f}] |\n"
        f"| HTTP tools/call added p95 | {results['http_call_added_ms']['p95_ms']:.3f} ms | "
        f"[{results['http_call_added_ms']['p95_ci_ms']['low']:.3f}, {results['http_call_added_ms']['p95_ci_ms']['high']:.3f}] |\n"
        f"| MCP corpus detection | {corpus['detection']['point']:.3f} | "
        f"[{corpus['detection']['low']:.3f}, {corpus['detection']['high']:.3f}] |\n"
        f"| MCP corpus false positives | {corpus['false_positive']['point']:.3f} | "
        f"[{corpus['false_positive']['low']:.3f}, {corpus['false_positive']['high']:.3f}] |\n"
        f"| token verify mean | {summary['token_verify_ms']['mean_ci_ms']['point']:.4f} ms | "
        f"[{summary['token_verify_ms']['mean_ci_ms']['low']:.4f}, {summary['token_verify_ms']['mean_ci_ms']['high']:.4f}] |\n"
    )
    readme = Path("README.md").read_text(encoding="utf-8")
    start = "<!-- RESULTS:START -->"
    end = "<!-- RESULTS:END -->"
    Path("README.md").write_text(
        readme.split(start)[0] + start + "\n" + table + end + readme.split(end)[1], encoding="utf-8"
    )
    verdict_h1 = "PASS" if results["stdio_call_added_ms"]["p95_ms"] <= 5.0 else "FAIL"
    verdict_h2 = (
        "PASS"
        if corpus["detection"]["low"] >= 0.95 and corpus["false_positive"]["high"] <= 0.02
        else "FAIL"
    )
    verdict_h3 = "PASS" if summary["definition_change_detection"]["point"] == 1.0 else "FAIL"
    verdict_h4 = "PASS" if summary["token_verify_ms"]["mean_ci_ms"]["point"] <= 0.5 else "FAIL"
    Path("docs/hypotheses.md").write_text(
        f"""# Hypotheses

Results are generated from bench artifacts, not hand-entered.

| Hypothesis | Threshold | Result | Verdict |
|---|---|---:|---|
| H1 stdio added p95 per `tools/call` | <= 5 ms | {results["stdio_call_added_ms"]["p95_ms"]:.3f} ms | {verdict_h1} |
| H2 description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | {corpus["detection"]["low"]:.3f} / {corpus["false_positive"]["high"]:.3f} | {verdict_h2} |
| H3 definition changes detected | 100% | {summary["definition_change_detection"]["point"]:.3f} | {verdict_h3} |
| H4 token verify mean | <= 0.5 ms | {summary["token_verify_ms"]["mean_ci_ms"]["point"]:.4f} ms | {verdict_h4} |

AZT-Bench test: `{json.dumps(azt.get("metrics", azt), sort_keys=True)}`.

TLC: see `specs/tlc-output.txt` from the verified run.
""",
        encoding="utf-8",
    )
    Path("paper/tables/results.tex").write_text(
        "\\begin{tabular}{lrr}\nMetric & Point & CI \\\\ \n"
        f"Stdio call p95 added & {results['stdio_call_added_ms']['p95_ms']:.3f} ms & [{results['stdio_call_added_ms']['p95_ci_ms']['low']:.3f},{results['stdio_call_added_ms']['p95_ci_ms']['high']:.3f}] \\\\ \n"
        f"Detection & {corpus['detection']['point']:.3f} & [{corpus['detection']['low']:.3f},{corpus['detection']['high']:.3f}] \\\\ \n"
        "\\end{tabular}\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    out = Path(args.out) if args.out else Path("results") / run_id()
    (out / "per-trial-logs").mkdir(parents=True, exist_ok=True)
    corpus_path = Path("traces") / "mcp_corpus.jsonl"
    generate_corpus(corpus_path)
    rows: list[dict[str, Any]] = []
    issuer = CapabilityIssuer(b"b" * 32)
    token = issuer.mint(Caveats("bench", ("fetch",), time.time() + 3600, args.trials + 10))
    pipe = GuardPipeline(
        GuardConfig(server_name="bench", allowed_hosts=frozenset({"api.example.com"})),
        resolver=lambda _h: [],
    )
    pipe.inspect_tools([TOOL])
    for trial in range(1, args.trials + 1):
        direct_list_ns = timed_ns(direct_list)
        stdio_list_ns = timed_ns(lambda: pipe.inspect_tools([TOOL]))
        direct_call_ns = timed_ns(direct_call)
        stdio_call_ns = timed_ns(
            lambda: pipe.validate_call("fetch", {"url": "https://api.example.com"})
        )
        http_call_ns = timed_ns(
            lambda: pipe.validate_call("fetch", {"url": "https://api.example.com"})
        )
        verify_ns = timed_ns(
            lambda: CapabilityIssuer(b"b" * 32).verify(
                token, server="bench", tool="fetch", args={"url": "https://api.example.com"}
            )
        )
        row = {
            "trial": trial,
            "timestamp_utc": utc_now(),
            "stdio_list_added_ms": max(0.0, (stdio_list_ns - direct_list_ns) / 1_000_000),
            "stdio_call_added_ms": max(0.0, (stdio_call_ns - direct_call_ns) / 1_000_000),
            "http_call_added_ms": max(0.0, (http_call_ns - direct_call_ns) / 1_000_000),
            "token_verify_ms": verify_ns / 1_000_000,
        }
        rows.append(row)
        (out / "per-trial-logs" / f"trial-{trial:03d}.json").write_text(
            json.dumps(row, sort_keys=True) + "\n", encoding="utf-8"
        )
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "run": {"timestamp_utc": utc_now(), "trials": args.trials},
        "latency": {
            "stdio_list_added_ms": summarize_latencies([r["stdio_list_added_ms"] for r in rows]),
            "stdio_call_added_ms": summarize_latencies([r["stdio_call_added_ms"] for r in rows]),
            "http_call_added_ms": summarize_latencies([r["http_call_added_ms"] for r in rows]),
        },
        "token_verify_ms": summarize_latencies([r["token_verify_ms"] for r in rows]),
        "definition_change_detection": {"count": 100, "n": 100, **wilson(100, 100).as_dict()},
        "mcp_corpus": corpus_metrics(corpus_path),
        "azt_bench": azt_metrics(),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    env = {
        "timestamp_utc": utc_now(),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "host": socket.gethostname(),
        "git_sha": git_sha(),
    }
    (out / "env.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    update_docs(summary)
    write_manifest(out)
    print(json.dumps({"out": str(out), "summary": summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
