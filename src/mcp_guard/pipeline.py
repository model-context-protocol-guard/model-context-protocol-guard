"""Shared guard pipeline for stdio and Streamable HTTP transports."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema

from .audit import AuditLog
from .egress import EgressPolicy, Resolver, check_egress
from .models import Finding, GuardDecision, ToolDefinition
from .pinning import PinDecision, ToolPinStore
from .screening import ScreeningPolicy, sanitize_result, screen_description, screen_result
from .tokens import CapabilityIssuer


@dataclass(slots=True)
class GuardConfig:
    server_name: str = "default"
    pin_file: Path | None = None
    tofu: bool = True
    enforce_additional_properties_false: bool = False
    max_args_bytes: int = 64_000
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    audit_file: Path | None = None
    result_action: str = "sanitize"


@dataclass(slots=True)
class GuardPipeline:
    config: GuardConfig = field(default_factory=GuardConfig)
    pin_store: ToolPinStore | None = None
    screening_policy: ScreeningPolicy | None = None
    token_issuer: CapabilityIssuer | None = None
    resolver: Resolver | None = None
    approved_tools: dict[str, ToolDefinition] = field(default_factory=dict)
    seen_names: dict[str, str] = field(default_factory=dict)
    audit: AuditLog | None = None

    def __post_init__(self) -> None:
        if self.pin_store is None:
            self.pin_store = ToolPinStore(self.config.pin_file, tofu=self.config.tofu)
        if self.screening_policy is None:
            self.screening_policy = ScreeningPolicy(result_action=self.config.result_action)
        if self.audit is None and self.config.audit_file is not None:
            self.audit = AuditLog(self.config.audit_file)

    def inspect_tools(
        self, tools_payload: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, PinDecision]]:
        tools = [ToolDefinition.from_mcp(t) for t in tools_payload]
        pin_decisions: dict[str, PinDecision] = {}
        allowed_payload: list[dict[str, Any]] = []
        for tool in tools:
            findings = screen_description(
                self.config.server_name,
                tool.name,
                tool.description,
                seen_names=self.seen_names,
                policy=self.screening_policy,
            )
            pin_decision = (
                self.pin_store.check(self.config.server_name, tool)
                if self.pin_store
                else PinDecision(False, "pin-store-missing", "")
            )
            pin_decisions[tool.name] = pin_decision
            if findings or not pin_decision.approved:
                self._audit(
                    "tool_blocked",
                    {
                        "tool": tool.name,
                        "findings": [
                            {"component": f.component, "reason": f.reason, "severity": f.severity}
                            for f in findings
                        ],
                        "pin": {
                            "approved": pin_decision.approved,
                            "reason": pin_decision.reason,
                            "current_hash": pin_decision.current_hash,
                            "approved_hash": pin_decision.approved_hash,
                        },
                    },
                )
                self.approved_tools.pop(tool.name, None)
                continue
            self.approved_tools[tool.name] = tool
            self.seen_names[tool.name] = self.config.server_name
            allowed_payload.append(tool.to_mcp())
        return allowed_payload, pin_decisions

    def on_tools_list_changed(self, tools_payload: list[dict[str, Any]]) -> GuardDecision:
        allowed, pins = self.inspect_tools(tools_payload)
        changed = [name for name, dec in pins.items() if not dec.approved]
        if changed:
            return GuardDecision.deny(
                f"changed or unapproved tools blocked: {', '.join(changed)}", "pinning"
            )
        return GuardDecision.allow("tool list refreshed", "pinning", sanitized=allowed)

    def validate_call(
        self, tool_name: str, args: dict[str, Any], *, token: str | None = None
    ) -> GuardDecision:
        import json

        if (
            len(json.dumps(args, separators=(",", ":")).encode("utf-8"))
            > self.config.max_args_bytes
        ):
            return GuardDecision.deny("arguments exceed size limit", "arguments")
        tool = self.approved_tools.get(tool_name)
        if tool is None:
            return GuardDecision.deny("tool is not approved", "pinning")
        if self.token_issuer is not None:
            if token is None:
                return GuardDecision.deny("missing capability token", "capability")
            if not self.token_issuer.verify(
                token, server=self.config.server_name, tool=tool_name, args=args, now=time.time()
            ):
                return GuardDecision.deny("capability token rejected", "capability")
        schema = dict(tool.input_schema or {"type": "object"})
        if self.config.enforce_additional_properties_false and schema.get("type") == "object":
            schema.setdefault("additionalProperties", False)
        try:
            jsonschema.Draft202012Validator(schema).validate(args)
        except jsonschema.ValidationError as exc:
            return GuardDecision.deny(f"argument schema violation: {exc.message}", "arguments")
        egress_findings = check_egress(
            args, EgressPolicy(self.config.allowed_hosts), resolver=self.resolver
        )
        if egress_findings:
            return GuardDecision.deny(egress_findings[0].reason, "egress", egress_findings)
        self._audit("tool_call_allowed", {"tool": tool_name})
        return GuardDecision.allow("call allowed", "pipeline")

    def screen_tool_result(self, result: Any) -> GuardDecision:
        findings = screen_result(result, policy=self.screening_policy)
        if not findings:
            return GuardDecision.allow("result allowed", "result", sanitized=result)
        self._audit(
            "result_flagged",
            {
                "findings": [
                    {"component": f.component, "reason": f.reason, "severity": f.severity}
                    for f in findings
                ]
            },
        )
        if self.config.result_action == "block":
            return GuardDecision.deny(findings[0].reason, "result", findings)
        return GuardDecision.allow("result sanitized", "result", sanitized=sanitize_result(result))

    def _audit(self, event: str, data: dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(event, data)


def decision_from_findings(component: str, findings: tuple[Finding, ...]) -> GuardDecision:
    return GuardDecision.deny(findings[0].reason if findings else "denied", component, findings)
