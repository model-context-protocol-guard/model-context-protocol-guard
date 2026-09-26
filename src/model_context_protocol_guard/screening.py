"""Description and result screening rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import Finding

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}
BIDI = {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}
SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})"
)
CONTROL_TOKEN_MARKERS = (
    "<start_of_turn>",
    "<end_of_turn>",
    "<|start_header_id|>",
    "<|end_header_id|>",
    "<|eot_id|>",
)
CONTROL_TOKEN_NAMES = (
    "im_start",
    "im_end",
    "assistant",
    "system",
    "user",
    "tool",
    "channel",
    "message",
    "analysis",
    "final",
)
ASSISTANT_NAMES = ("assistant", "model", "chatbot", "coding assistant", "tool user")
ASSISTANT_DIRECTIVES = ("ignore", "follow", "obey", "must", "secretly", "instead")
CREDENTIAL_TERMS = (
    ".ssh",
    "id_rsa",
    "aws/credentials",
    "kubeconfig",
    "api_key",
    "api-key",
    "secret_key",
    "secret-key",
    "token",
    "mcpservers",
    "claude_desktop_config",
)


class _KeywordPattern:
    def __init__(self, terms: tuple[str, ...]) -> None:
        self.terms = tuple(term.lower() for term in terms)

    def search(self, text: str) -> str | None:
        lowered = text.lower()
        return next((term for term in self.terms if term in lowered), None)


class _ControlTokenPattern:
    def search(self, text: str) -> str | None:
        lowered = text.lower()
        marker = next((item for item in CONTROL_TOKEN_MARKERS if item in lowered), None)
        if marker:
            return marker
        for name in CONTROL_TOKEN_NAMES:
            if f"<|{name}" in lowered or f"<|/{name}" in lowered:
                return name
            if f"<{name}>" in lowered or f"</{name}>" in lowered:
                return name
        return None

    def sub(self, repl: str, text: str) -> str:
        updated = text
        for marker in CONTROL_TOKEN_MARKERS:
            updated = re.sub(re.escape(marker), repl, updated, flags=re.IGNORECASE)
        for name in CONTROL_TOKEN_NAMES:
            updated = re.sub(r"<\|/?" + re.escape(name) + r"[^>]*\|>", repl, updated, flags=re.I)
            updated = re.sub(r"</?" + re.escape(name) + r">", repl, updated, flags=re.I)
        return updated


CONTROL_TOKEN_RE = _ControlTokenPattern()
CREDENTIAL_RE = _KeywordPattern(CREDENTIAL_TERMS)


@dataclass(frozen=True, slots=True)
class ScreeningPolicy:
    max_description_chars: int = 4096
    result_action: str = "sanitize"
    deny_on_secret: bool = False
    blocked_tool_names: frozenset[str] = field(default_factory=frozenset)


def load_rule_file(path: str | None) -> ScreeningPolicy:
    if not path:
        return ScreeningPolicy()
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScreeningPolicy(
        max_description_chars=int(data.get("max_description_chars", 4096)),
        result_action=str(data.get("result_action", "sanitize")),
        deny_on_secret=bool(data.get("deny_on_secret", False)),
        blocked_tool_names=frozenset(str(x) for x in data.get("blocked_tool_names", [])),
    )


def _contains_any(text: str, chars: set[str]) -> bool:
    return any(ch in text for ch in chars)


def _assistant_addressed(text: str) -> bool:
    lowered = text.lower()
    for name in ASSISTANT_NAMES:
        start = lowered.find(name)
        if start == -1:
            continue
        window = lowered[start : start + len(name) + 80]
        if any(directive in window for directive in ASSISTANT_DIRECTIVES):
            return True
    return False


def screen_description(
    server: str,
    tool_name: str,
    description: str,
    *,
    seen_names: dict[str, str] | None = None,
    policy: ScreeningPolicy | None = None,
) -> tuple[Finding, ...]:
    del server
    p = policy or ScreeningPolicy()
    findings: list[Finding] = []
    if tool_name in p.blocked_tool_names:
        findings.append(Finding("description", "tool name blocked by operator policy"))
    if len(description) > p.max_description_chars:
        findings.append(Finding("description", "description exceeds configured length"))
    if _contains_any(description, ZERO_WIDTH) or _contains_any(description, BIDI):
        findings.append(Finding("description", "description contains zero-width or bidi controls"))
    if CONTROL_TOKEN_RE.search(description):
        findings.append(Finding("description", "description contains control token"))
    if _assistant_addressed(description):
        findings.append(
            Finding("description", "description appears addressed to the assistant/model")
        )
    if CREDENTIAL_RE.search(description):
        findings.append(
            Finding("description", "description mentions credentials or other MCP configuration")
        )
    if seen_names and tool_name in seen_names:
        findings.append(
            Finding("description", f"cross-server tool-name collision with {seen_names[tool_name]}")
        )
    return tuple(findings)


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_walk_strings(item))
        return out
    if isinstance(value, list | tuple):
        out = []
        for item in value:
            out.extend(_walk_strings(item))
        return out
    return []


def screen_result(result: Any, *, policy: ScreeningPolicy | None = None) -> tuple[Finding, ...]:
    p = policy or ScreeningPolicy()
    findings: list[Finding] = []
    for text in _walk_strings(result):
        if CONTROL_TOKEN_RE.search(text):
            findings.append(Finding("result", "result contains control token"))
        if SECRET_RE.search(text):
            findings.append(Finding("result", "result contains secret-shaped string"))
            if p.deny_on_secret:
                break
    return tuple(findings)


def sanitize_result(value: Any) -> Any:
    if isinstance(value, str):
        value = CONTROL_TOKEN_RE.sub("[CONTROL-TOKEN-REMOVED]", value)
        return SECRET_RE.sub("[SECRET-REMOVED]", value)
    if isinstance(value, list):
        return [sanitize_result(v) for v in value]
    if isinstance(value, dict):
        return {str(k): sanitize_result(v) for k, v in value.items()}
    return value
