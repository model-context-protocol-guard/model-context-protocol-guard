# Product requirements

Model Context Protocol Guard protects MCP clients from malicious or changed tools while staying transparent to MCP servers. The product requirements are: support stdio JSON-RPC 2.0 and Streamable HTTP MCP transports; deny unapproved tool definitions; screen descriptions, arguments, egress and results; provide attenuable per-session capability tokens; preserve an append-only audit trail; and integrate with Zero Trust Agent Benchmark without special-casing trace IDs or families.

Non-goals: hosted policy management, anonymous telemetry, and vendor-specific MCP extensions in v0.1.0.
