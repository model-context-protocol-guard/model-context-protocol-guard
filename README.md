# Model Context Protocol Guard

Model Context Protocol Guard is a transparent, deny-by-default security proxy between an MCP client and MCP servers. It pins tool definitions, screens tool descriptions and results, validates call arguments, enforces egress policy, checks attenuable HMAC capability tokens, and writes an append-only audit log.

## Quickstart

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
model-context-protocol-guard stdio -- python -m your_mcp_server
```

Example `mcp.json`:

```json
{
  "mcpServers": {
    "files-guarded": {
      "command": "model-context-protocol-guard",
      "args": ["stdio", "--server-name", "files", "--", "python", "-m", "files_server"]
    }
  }
}
```

Linux container check uses the project wheelhouse; Windows native check uses `.venv` and the same `scripts/check.sh` gate.

## Architecture

```mermaid
flowchart LR
  C[MCP client] --> G[Model Context Protocol Guard transport]
  G --> P[Shared policy pipeline]
  P --> Pin[Tool pins]
  P --> Desc[Description screening]
  P --> Args[JSON Schema + egress]
  P --> Tok[Capability token]
  P --> R[Result screening]
  R --> S[MCP server]
  P --> A[Hash-chained audit]
```

## Results

<!-- RESULTS:START -->
| Metric | Value | 95% CI |
|---|---:|---:|
| stdio e2e tools/call overhead p95 | 0.439 ms | [0.279, 1.097] |
| HTTP e2e tools/call overhead p95 | 0.491 ms | [0.343, 0.538] |
| held-out MCP corpus detection | 1.000 | [0.983, 1.000] |
| held-out MCP corpus false positives | 0.000 | [0.000, 0.017] |
| token verify mean | 0.0573 ms | [0.0451, 0.0695] |
| pipeline-only stdio tools/call p95 | 0.016 ms | [0.013, 0.047] |
| pipeline-only HTTP tools/call p95 | 0.005 ms | [0.005, 0.008] |
| Zero Trust Agent Benchmark v4 test block rate | 0.954 | [0.932, 0.969] |
| Zero Trust Agent Benchmark v4 test false positives | 0.160 | [0.130, 0.195] |
| Zero Trust Agent Benchmark v4 test leak rate | 0.000 | [0.000, 0.004] |
| Zero Trust Agent Benchmark v4 in-policy block rate | 0.908 | [0.866, 0.938] |
| Zero Trust Agent Benchmark v4 in-policy FPR (shared benign set) | 0.160 | [0.130, 0.195] |
| Zero Trust Agent Benchmark v4 in-policy leak rate | 0.000 | [0.000, 0.015] |
| Zero Trust Agent Benchmark v4 out-of-policy block rate | 1.000 | [0.985, 1.000] |
| Zero Trust Agent Benchmark v4 out-of-policy FPR (shared benign set) | 0.160 | [0.130, 0.195] |
| Zero Trust Agent Benchmark v4 out-of-policy leak rate | 0.000 | [0.000, 0.015] |
| v3 (superseded: had shortcuts) block / FPR / leak | 0.956 / 0.028 / 0.001 | [0.934, 0.971] / [0.017, 0.046] / [0.000, 0.006] |
<!-- RESULTS:END -->

## Development

```bash
bash scripts/check.sh
python bench/run_benchmarks.py --trials 100
```

CI badge placeholders will be enabled after publishing to `github.com/model-context-protocol-guard/model-context-protocol-guard`.
