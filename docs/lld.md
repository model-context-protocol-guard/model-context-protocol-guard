# Low-level design

Both transports call `GuardPipeline`. `tools/list` canonicalizes `(name, description, inputSchema, annotations)` and checks `ToolPinStore`; changes after `notifications/tools/list_changed` remove approval. `tools/call` checks tool approval, optional HMAC capability token, JSON Schema draft 2020-12 validation, size limits, and recursive URL/host extraction with resolve-then-compare. Results are sanitized or blocked when control tokens or secret-shaped strings appear.

Audit records are JSONL entries containing `previous_hash`; verification recomputes the chain.
