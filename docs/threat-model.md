# Threat model

## In scope

- Malicious MCP servers poisoning tool descriptions.
- Tool definition changes after initial approval.
- Prompt/control-token injection in tool output, including the arXiv:2609.27542 observation that chat-template tokens can suppress model reasoning.
- Parser confusion from truncated or ambiguous JSON-RPC frames.
- Argument-based egress to private, link-local or metadata services.
- Capability token theft where attackers can only attenuate, not widen, caveats.

## Out of scope

Compromised client host, compromised Python runtime, and kernel/network attacks outside local DNS resolution.
