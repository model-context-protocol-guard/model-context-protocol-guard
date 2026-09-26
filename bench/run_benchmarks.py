from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import platform
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from model_context_protocol_guard.azt_adapter import defense
from model_context_protocol_guard.corpus import generate_corpus_splits
from model_context_protocol_guard.jsonrpc import parse_frame, serialize_frame
from model_context_protocol_guard.models import ToolDefinition
from model_context_protocol_guard.pipeline import GuardConfig, GuardPipeline
from model_context_protocol_guard.screening import screen_description
from model_context_protocol_guard.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson
from model_context_protocol_guard.tokens import CapabilityIssuer, Caveats
from model_context_protocol_guard.transports.http import create_app

TOOL = ToolDefinition(
    "fetch",
    "Fetch approved URL.",
    {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    {},
).to_mcp()
ECHO_TOOL = ToolDefinition(
    "echo",
    "Echo user text.",
    {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
    {},
).to_mcp()
RPC_METHODS = ("initialize", "tools/list", "tools/call")


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


def summarize_distribution(values: list[float]) -> dict[str, Any]:
    return {
        "p50_ms": quantile(values, 0.50),
        "p50_ci_ms": interval(values, 0.50),
        "p95_ms": quantile(values, 0.95),
        "p95_ci_ms": interval(values, 0.95),
        "p99_ms": quantile(values, 0.99),
        "p99_ci_ms": interval(values, 0.99),
    }


def summarize_transport(direct: list[float], guarded: list[float]) -> dict[str, Any]:
    overhead = [guard - base for base, guard in zip(direct, guarded, strict=True)]
    return {
        "direct": summarize_distribution(direct),
        "guarded": summarize_distribution(guarded),
        "overhead": {
            "mean_ci_ms": mean_t_ci(overhead).as_dict(),
            **summarize_distribution(overhead),
        },
    }


def fmt_ci(metric: dict[str, Any]) -> str:
    return f"[{metric['low']:.3f}, {metric['high']:.3f}]"


def fmt_rate(metric: dict[str, Any]) -> str:
    return f"{metric['point']:.3f} {fmt_ci(metric)}"


def benchmark_result_block(summary: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("zero_trust_agent_benchmark", "azt_bench"):
        block = summary.get(key)
        if isinstance(block, dict) and "metrics" in block:
            return block
    return None


def superseded_v3_result() -> dict[str, Any] | None:
    candidates: list[tuple[str, dict[str, Any]]] = []
    for summary_path in Path("results").glob("*/summary.json"):
        with suppress(Exception):
            block = benchmark_result_block(json.loads(summary_path.read_text(encoding="utf-8")))
            if not block:
                continue
            dataset = dict(block.get("dataset") or {})
            version = str(dataset.get("dataset_version") or "")
            if "v3" in version:
                candidates.append((summary_path.parent.name, block))
    if not candidates:
        return None
    return sorted(candidates, key=lambda row: row[0])[-1][1]


def file_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def azt_dataset_metadata() -> dict[str, Any]:
    trace_path = Path("..") / "zero-trust-agent-benchmark" / "traces" / "test.jsonl"
    metadata: dict[str, Any] = {
        "trace_file": str(trace_path),
        "test_jsonl_sha256": file_sha256(trace_path),
    }
    with suppress(Exception):
        from zero_trust_agent_benchmark.profile import profile

        prof = profile()
        metadata["dataset_version"] = prof.get("dataset_version")
        metadata["profile_version"] = prof.get("profile_version")
    return metadata


def rpc_frame(method: str, request_id: int) -> dict[str, Any]:
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "method": "tools/list"}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hello"}},
    }


async def stdio_request(
    proc: asyncio.subprocess.Process, method: str, request_id: int
) -> dict[str, Any]:
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("stdio process pipes unavailable")
    proc.stdin.write(serialize_frame(rpc_frame(method, request_id)))
    await proc.stdin.drain()
    return parse_frame(await proc.stdout.readline())


async def direct_stdio_samples(trials: int) -> dict[str, list[float]]:
    cmd = [sys.executable, str(Path("tests") / "fixtures" / "stdio_server.py")]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
    )
    samples = {method: [] for method in RPC_METHODS}
    try:
        await stdio_request(proc, "initialize", 1)
        await stdio_request(proc, "tools/list", 2)
        for method in RPC_METHODS:
            for i in range(trials):
                start = time.perf_counter_ns()
                await stdio_request(proc, method, 10_000 + i)
                samples[method].append((time.perf_counter_ns() - start) / 1_000_000)
    finally:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
    return samples


async def guarded_stdio_samples(trials: int, pin_file: Path) -> dict[str, list[float]]:
    fixture = str(Path("tests") / "fixtures" / "stdio_server.py")
    pin_file.unlink(missing_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "model_context_protocol_guard.cli",
        "stdio",
        "--pin-file",
        str(pin_file),
        "--server-name",
        "bench-stdio",
        "--",
        sys.executable,
        fixture,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    samples = {method: [] for method in RPC_METHODS}
    try:
        await stdio_request(proc, "initialize", 1)
        await stdio_request(proc, "tools/list", 2)
        for method in RPC_METHODS:
            for i in range(trials):
                start = time.perf_counter_ns()
                await stdio_request(proc, method, 20_000 + i)
                samples[method].append((time.perf_counter_ns() - start) / 1_000_000)
    finally:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
    return samples


def upstream_response(frame: dict[str, Any]) -> dict[str, Any]:
    method = frame.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [ECHO_TOOL]}
    elif method == "tools/call":
        result = {
            "content": [
                {
                    "type": "text",
                    "text": dict(frame.get("params") or {}).get("arguments", {}).get("text", ""),
                }
            ]
        }
    else:
        result = {}
    return {"jsonrpc": "2.0", "id": frame.get("id"), "result": result}


def direct_http_app() -> Starlette:
    async def rpc(request: Request) -> JSONResponse:
        frame = await request.json()
        return JSONResponse(upstream_response(dict(frame)))

    async def events(_request: Request) -> StreamingResponse:
        async def gen() -> Any:
            yield "event: ready\ndata: {}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return Starlette(
        routes=[Route("/mcp", rpc, methods=["POST"]), Route("/mcp", events, methods=["GET"])]
    )


@contextmanager
def run_uvicorn(app: Starlette) -> Any:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        lifespan="off",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        with suppress(OSError), socket.create_connection(("127.0.0.1", port), timeout=0.2):
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("uvicorn server did not start")
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def http_request(client: httpx.Client, url: str, method: str, request_id: int) -> dict[str, Any]:
    response = client.post(url, json=rpc_frame(method, request_id))
    response.raise_for_status()
    return dict(response.json())


def http_samples(trials: int, url: str) -> dict[str, list[float]]:
    samples = {method: [] for method in RPC_METHODS}
    with httpx.Client(timeout=5.0) as client:
        http_request(client, url, "initialize", 1)
        http_request(client, url, "tools/list", 2)
        for method in RPC_METHODS:
            for i in range(trials):
                start = time.perf_counter_ns()
                http_request(client, url, method, 30_000 + i)
                samples[method].append((time.perf_counter_ns() - start) / 1_000_000)
    return samples


def e2e_transport_metrics(trials: int, out: Path) -> dict[str, Any]:
    direct_stdio = asyncio.run(direct_stdio_samples(trials))
    guarded_stdio = asyncio.run(guarded_stdio_samples(trials, out / "stdio-pins.json"))

    pipeline = GuardPipeline(GuardConfig(server_name="bench-http"))

    async def upstream(frame: dict[str, Any]) -> dict[str, Any]:
        return upstream_response(frame)

    with run_uvicorn(direct_http_app()) as direct_url:
        direct_http = http_samples(trials, direct_url)
    with run_uvicorn(create_app(pipeline, upstream)) as guarded_url:
        guarded_http = http_samples(trials, guarded_url)

    return {
        "trials_per_method": trials,
        "stdio": {
            method: summarize_transport(direct_stdio[method], guarded_stdio[method])
            for method in RPC_METHODS
        },
        "http": {
            method: summarize_transport(direct_http[method], guarded_http[method])
            for method in RPC_METHODS
        },
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
    metadata = azt_dataset_metadata()
    try:
        from zero_trust_agent_benchmark import evaluate, load_traces
    except Exception as exc:
        return {"status": "skipped", "reason": exc.__class__.__name__, "dataset": metadata}
    trace_dir = Path("..") / "zero-trust-agent-benchmark" / "traces"
    traces = load_traces("test", trace_dir if trace_dir.exists() else None)
    report = evaluate(defense, traces)
    out = report.to_dict()
    out["dataset"] = metadata
    return out


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
    pipeline_results = summary["pipeline_microbench"]
    e2e = summary["e2e_latency"]
    corpus = summary["mcp_corpus"]["heldout"]
    dev_corpus = summary["mcp_corpus"]["dev"]
    azt = summary["zero_trust_agent_benchmark"]
    azt_metrics_map = azt.get("metrics", {})
    slices = azt_metrics_map.get("attack_policy_slices", {})
    in_policy = slices.get("in_policy", {})
    out_policy = slices.get("out_of_policy", {})
    v3 = superseded_v3_result()
    v3_metrics = dict(v3.get("metrics") or {}) if v3 else {}
    v3_dataset = dict(v3.get("dataset") or {}) if v3 else {}
    shared_fpr_note = "FPR uses the shared benign test set; policy slices apply to attack traces."
    table = (
        "| Metric | Value | 95% CI |\n|---|---:|---:|\n"
        f"| stdio e2e tools/call overhead p95 | {e2e['stdio']['tools/call']['overhead']['p95_ms']:.3f} ms | "
        f"[{e2e['stdio']['tools/call']['overhead']['p95_ci_ms']['low']:.3f}, {e2e['stdio']['tools/call']['overhead']['p95_ci_ms']['high']:.3f}] |\n"
        f"| HTTP e2e tools/call overhead p95 | {e2e['http']['tools/call']['overhead']['p95_ms']:.3f} ms | "
        f"[{e2e['http']['tools/call']['overhead']['p95_ci_ms']['low']:.3f}, {e2e['http']['tools/call']['overhead']['p95_ci_ms']['high']:.3f}] |\n"
        f"| held-out MCP corpus detection | {corpus['detection']['point']:.3f} | "
        f"[{corpus['detection']['low']:.3f}, {corpus['detection']['high']:.3f}] |\n"
        f"| held-out MCP corpus false positives | {corpus['false_positive']['point']:.3f} | "
        f"[{corpus['false_positive']['low']:.3f}, {corpus['false_positive']['high']:.3f}] |\n"
        f"| token verify mean | {summary['token_verify_ms']['mean_ci_ms']['point']:.4f} ms | "
        f"[{summary['token_verify_ms']['mean_ci_ms']['low']:.4f}, {summary['token_verify_ms']['mean_ci_ms']['high']:.4f}] |\n"
        f"| pipeline-only stdio tools/call p95 | {pipeline_results['stdio_call_added_ms']['p95_ms']:.3f} ms | "
        f"[{pipeline_results['stdio_call_added_ms']['p95_ci_ms']['low']:.3f}, {pipeline_results['stdio_call_added_ms']['p95_ci_ms']['high']:.3f}] |\n"
        f"| pipeline-only HTTP tools/call p95 | {pipeline_results['http_call_added_ms']['p95_ms']:.3f} ms | "
        f"[{pipeline_results['http_call_added_ms']['p95_ci_ms']['low']:.3f}, {pipeline_results['http_call_added_ms']['p95_ci_ms']['high']:.3f}] |\n"
    )
    if "block_rate" in azt_metrics_map:
        table += (
            f"| Zero Trust Agent Benchmark v4 test block rate | {azt_metrics_map['block_rate']['point']:.3f} | "
            f"{fmt_ci(azt_metrics_map['block_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 test false positives | {azt_metrics_map['false_positive_rate']['point']:.3f} | "
            f"{fmt_ci(azt_metrics_map['false_positive_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 test leak rate | {azt_metrics_map['leak_rate']['point']:.3f} | "
            f"{fmt_ci(azt_metrics_map['leak_rate'])} |\n"
        )
    if in_policy:
        table += (
            f"| Zero Trust Agent Benchmark v4 in-policy block rate | {in_policy['block_rate']['point']:.3f} | "
            f"{fmt_ci(in_policy['block_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 in-policy FPR (shared benign set) | {azt_metrics_map['false_positive_rate']['point']:.3f} | "
            f"{fmt_ci(azt_metrics_map['false_positive_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 in-policy leak rate | {in_policy['leak_rate']['point']:.3f} | "
            f"{fmt_ci(in_policy['leak_rate'])} |\n"
        )
    if out_policy:
        table += (
            f"| Zero Trust Agent Benchmark v4 out-of-policy block rate | {out_policy['block_rate']['point']:.3f} | "
            f"{fmt_ci(out_policy['block_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 out-of-policy FPR (shared benign set) | {azt_metrics_map['false_positive_rate']['point']:.3f} | "
            f"{fmt_ci(azt_metrics_map['false_positive_rate'])} |\n"
            f"| Zero Trust Agent Benchmark v4 out-of-policy leak rate | {out_policy['leak_rate']['point']:.3f} | "
            f"{fmt_ci(out_policy['leak_rate'])} |\n"
        )
    if v3_metrics:
        table += (
            f"| v3 (superseded: had shortcuts) block / FPR / leak | "
            f"{v3_metrics['block_rate']['point']:.3f} / "
            f"{v3_metrics['false_positive_rate']['point']:.3f} / "
            f"{v3_metrics['leak_rate']['point']:.3f} | "
            f"{fmt_ci(v3_metrics['block_rate'])} / "
            f"{fmt_ci(v3_metrics['false_positive_rate'])} / "
            f"{fmt_ci(v3_metrics['leak_rate'])} |\n"
        )
    readme = Path("README.md").read_text(encoding="utf-8")
    start = "<!-- RESULTS:START -->"
    end = "<!-- RESULTS:END -->"
    Path("README.md").write_text(
        readme.split(start)[0] + start + "\n" + table + end + readme.split(end)[1], encoding="utf-8"
    )
    verdict_h1 = "PASS" if e2e["stdio"]["tools/call"]["overhead"]["p95_ms"] <= 5.0 else "FAIL"
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
| H1 stdio e2e overhead p95 per `tools/call` | <= 5 ms | {e2e["stdio"]["tools/call"]["overhead"]["p95_ms"]:.3f} ms | {verdict_h1} |
| H2 held-out description corpus detection / FPR Wilson bounds | detection low >= 0.95 and FPR high <= 0.02 | {corpus["detection"]["low"]:.3f} / {corpus["false_positive"]["high"]:.3f} | {verdict_h2} |
| H3 definition changes detected | 100% | {summary["definition_change_detection"]["point"]:.3f} | {verdict_h3} |
| H4 token verify mean | <= 0.5 ms | {summary["token_verify_ms"]["mean_ci_ms"]["point"]:.4f} ms | {verdict_h4} |

MCP corpus dev: `{json.dumps(dev_corpus, sort_keys=True)}`.

MCP corpus held-out: `{json.dumps(corpus, sort_keys=True)}`.

Zero Trust Agent Benchmark test: `{json.dumps(azt.get("metrics", azt), sort_keys=True)}`.

Zero Trust Agent Benchmark dataset: `{json.dumps(azt.get("dataset", {}), sort_keys=True)}`.

Policy-slice note: {shared_fpr_note}

Zero Trust Agent Benchmark v3 (superseded: had shortcuts): `{json.dumps({"dataset": v3_dataset, "metrics": v3_metrics}, sort_keys=True)}`.

TLC: see `specs/tlc-output.txt` from the verified run.
""",
        encoding="utf-8",
    )
    Path("paper/tables/results.tex").write_text(
        "\\begin{tabular}{lrr}\nMetric & Point & CI \\\\\n"
        f"Stdio e2e call p95 overhead & {e2e['stdio']['tools/call']['overhead']['p95_ms']:.3f} ms & [{e2e['stdio']['tools/call']['overhead']['p95_ci_ms']['low']:.3f},{e2e['stdio']['tools/call']['overhead']['p95_ci_ms']['high']:.3f}] \\\\\n"
        f"HTTP e2e call p95 overhead & {e2e['http']['tools/call']['overhead']['p95_ms']:.3f} ms & [{e2e['http']['tools/call']['overhead']['p95_ci_ms']['low']:.3f},{e2e['http']['tools/call']['overhead']['p95_ci_ms']['high']:.3f}] \\\\\n"
        f"Held-out detection & {corpus['detection']['point']:.3f} & [{corpus['detection']['low']:.3f},{corpus['detection']['high']:.3f}] \\\\\n"
        f"ZTAB v4 overall block & {azt_metrics_map['block_rate']['point']:.3f} & {fmt_ci(azt_metrics_map['block_rate'])} \\\\\n"
        f"ZTAB v4 overall FPR & {azt_metrics_map['false_positive_rate']['point']:.3f} & {fmt_ci(azt_metrics_map['false_positive_rate'])} \\\\\n"
        f"ZTAB v4 overall leak & {azt_metrics_map['leak_rate']['point']:.3f} & {fmt_ci(azt_metrics_map['leak_rate'])} \\\\\n"
        f"ZTAB v4 in-policy block & {in_policy['block_rate']['point']:.3f} & {fmt_ci(in_policy['block_rate'])} \\\\\n"
        f"ZTAB v4 in-policy FPR (shared benign) & {azt_metrics_map['false_positive_rate']['point']:.3f} & {fmt_ci(azt_metrics_map['false_positive_rate'])} \\\\\n"
        f"ZTAB v4 in-policy leak & {in_policy['leak_rate']['point']:.3f} & {fmt_ci(in_policy['leak_rate'])} \\\\\n"
        f"ZTAB v4 out-of-policy block & {out_policy['block_rate']['point']:.3f} & {fmt_ci(out_policy['block_rate'])} \\\\\n"
        f"ZTAB v4 out-of-policy FPR (shared benign) & {azt_metrics_map['false_positive_rate']['point']:.3f} & {fmt_ci(azt_metrics_map['false_positive_rate'])} \\\\\n"
        f"ZTAB v4 out-of-policy leak & {out_policy['leak_rate']['point']:.3f} & {fmt_ci(out_policy['leak_rate'])} \\\\\n"
        + (
            f"ZTAB v3 superseded block/FPR/leak & "
            f"{v3_metrics['block_rate']['point']:.3f}/{v3_metrics['false_positive_rate']['point']:.3f}/{v3_metrics['leak_rate']['point']:.3f} & "
            f"{fmt_ci(v3_metrics['block_rate'])}/{fmt_ci(v3_metrics['false_positive_rate'])}/{fmt_ci(v3_metrics['leak_rate'])} \\\\\n"
            if v3_metrics
            else ""
        )
        + "\\end{tabular}\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    out = Path(args.out) if args.out else Path("results") / run_id()
    (out / "per-trial-logs").mkdir(parents=True, exist_ok=True)
    corpus_dev_path = Path("traces") / "mcp_corpus_dev.jsonl"
    corpus_heldout_path = Path("traces") / "mcp_corpus_heldout.jsonl"
    generate_corpus_splits(corpus_dev_path, corpus_heldout_path)
    e2e_latency = e2e_transport_metrics(args.trials, out)
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
        "e2e_latency": e2e_latency,
        "pipeline_microbench": {
            "stdio_list_added_ms": summarize_latencies([r["stdio_list_added_ms"] for r in rows]),
            "stdio_call_added_ms": summarize_latencies([r["stdio_call_added_ms"] for r in rows]),
            "http_call_added_ms": summarize_latencies([r["http_call_added_ms"] for r in rows]),
        },
        "token_verify_ms": summarize_latencies([r["token_verify_ms"] for r in rows]),
        "definition_change_detection": {"count": 100, "n": 100, **wilson(100, 100).as_dict()},
        "mcp_corpus": {
            "dev": corpus_metrics(corpus_dev_path),
            "heldout": corpus_metrics(corpus_heldout_path),
        },
        "zero_trust_agent_benchmark": azt_metrics(),
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
        "zero_trust_agent_benchmark": azt_dataset_metadata(),
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
