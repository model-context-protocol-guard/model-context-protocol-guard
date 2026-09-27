"""Shared dataclasses for guard decisions and tool definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

DecisionValue = Literal["allow", "deny"]
ActionValue = Literal["block", "sanitize"]


@dataclass(frozen=True, slots=True)
class Finding:
    component: str
    reason: str
    severity: Literal["info", "warning", "error"] = "error"


@dataclass(frozen=True, slots=True)
class GuardDecision:
    decision: DecisionValue
    reason: str
    component: str
    findings: tuple[Finding, ...] = ()
    sanitized: Any | None = None

    @classmethod
    def allow(
        cls, reason: str = "ok", component: str = "guard", sanitized: Any | None = None
    ) -> GuardDecision:
        return cls("allow", reason, component, (), sanitized)

    @classmethod
    def deny(cls, reason: str, component: str, findings: tuple[Finding, ...] = ()) -> GuardDecision:
        return cls("deny", reason, component, findings)

    def as_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "decision": self.decision,
            "reason": self.reason,
            "component": self.component,
        }
        if self.findings:
            data["findings"] = [
                {"component": f.component, "reason": f.reason, "severity": f.severity}
                for f in self.findings
            ]
        if self.sanitized is not None:
            data["sanitized"] = self.sanitized
        return data


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, data: dict[str, Any]) -> ToolDefinition:
        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            input_schema=dict(data.get("inputSchema") or {}),
            annotations=dict(data.get("annotations") or {}),
        )

    def to_mcp(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations,
        }
