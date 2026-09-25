from __future__ import annotations

from pathlib import Path

from mcp_guard.audit import verify_chain
from mcp_guard.pipeline import GuardConfig, GuardPipeline

TOOL = {
    "name": "fetch",
    "description": "Fetch approved URL.",
    "inputSchema": {
        "type": "object",
        "required": ["url"],
        "properties": {"url": {"type": "string"}},
    },
    "annotations": {},
}


def test_pipeline_filters_tools_validates_args_and_audits(tmp_path: Path) -> None:
    pipe = GuardPipeline(
        GuardConfig(
            server_name="srv",
            pin_file=tmp_path / "pins.json",
            audit_file=tmp_path / "audit.jsonl",
            allowed_hosts=frozenset({"api.example.com"}),
            enforce_additional_properties_false=True,
        ),
        resolver=lambda _h: [],
    )
    allowed, pins = pipe.inspect_tools(
        [TOOL, {**TOOL, "name": "bad", "description": "<|im_start|>"}]
    )
    assert [t["name"] for t in allowed] == ["fetch"]
    assert pins["fetch"].approved
    assert pipe.validate_call("fetch", {"url": "https://api.example.com/data"}).decision == "allow"
    assert pipe.validate_call("fetch", {"url": "https://evil.example/data"}).component == "egress"
    assert (
        pipe.validate_call("fetch", {"url": "https://api.example.com", "extra": 1}).component
        == "arguments"
    )
    assert verify_chain(tmp_path / "audit.jsonl")


def test_pipeline_list_changed_blocks_modified_pin(tmp_path: Path) -> None:
    pipe = GuardPipeline(GuardConfig(server_name="srv", pin_file=tmp_path / "pins.json"))
    pipe.inspect_tools([TOOL])
    changed = dict(TOOL)
    changed["description"] = "changed after notification"
    decision = pipe.on_tools_list_changed([changed])
    assert decision.decision == "deny"
    assert pipe.validate_call("fetch", {"url": "https://api.example.com"}).decision == "deny"


def test_pipeline_sanitizes_results() -> None:
    pipe = GuardPipeline()
    result = pipe.screen_tool_result({"content": "AKIAABCDEFGHIJKLMNOP <|assistant|>"})
    assert result.decision == "allow"
    assert "SECRET-REMOVED" in result.sanitized["content"]
