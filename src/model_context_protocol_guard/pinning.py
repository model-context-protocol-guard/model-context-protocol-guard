"""Tool definition canonicalisation and pin-store enforcement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import ToolDefinition


def canonical_tool_json(tool: ToolDefinition) -> str:
    obj = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": tool.annotations,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tool_hash(tool: ToolDefinition) -> str:
    return hashlib.sha256(canonical_tool_json(tool).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class PinDecision:
    approved: bool
    reason: str
    current_hash: str
    approved_hash: str | None = None


@dataclass(slots=True)
class ToolPinStore:
    path: Path | None = None
    tofu: bool = True
    allowlist: dict[str, str] = field(default_factory=dict)
    pins: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.pins.update({str(k): str(v) for k, v in data.get("pins", {}).items()})
        self.pins.update(self.allowlist)

    def key(self, server: str, tool_name: str) -> str:
        return f"{server}:{tool_name}"

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "pins": dict(sorted(self.pins.items()))}
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def approve(self, server: str, tool: ToolDefinition) -> str:
        digest = tool_hash(tool)
        self.pins[self.key(server, tool.name)] = digest
        self._save()
        return digest

    def check(self, server: str, tool: ToolDefinition) -> PinDecision:
        digest = tool_hash(tool)
        k = self.key(server, tool.name)
        approved = self.pins.get(k)
        if approved is None:
            if self.tofu:
                self.pins[k] = digest
                self._save()
                return PinDecision(True, "tofu-pinned", digest, digest)
            return PinDecision(False, "tool definition is not approved", digest)
        if approved != digest:
            return PinDecision(False, "tool definition changed from approved pin", digest, approved)
        return PinDecision(True, "pin-match", digest, approved)

    def check_all(self, server: str, tools: list[ToolDefinition]) -> dict[str, PinDecision]:
        return {tool.name: self.check(server, tool) for tool in tools}
