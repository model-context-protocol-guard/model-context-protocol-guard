from __future__ import annotations

import sys

from mcp_guard.jsonrpc import parse_frame, serialize_frame

TOOL = {
    "name": "echo",
    "description": "Echo user text.",
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
    "annotations": {},
}

for raw in sys.stdin.buffer:
    frame = parse_frame(raw)
    method = frame.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        result = {
            "content": [
                {
                    "type": "text",
                    "text": frame.get("params", {}).get("arguments", {}).get("text", ""),
                }
            ]
        }
    else:
        result = {}
    sys.stdout.buffer.write(
        serialize_frame({"jsonrpc": "2.0", "id": frame.get("id"), "result": result})
    )
    sys.stdout.buffer.flush()
