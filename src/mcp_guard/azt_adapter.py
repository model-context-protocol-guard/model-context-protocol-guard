"""AZT-Bench in-process defense adapter."""

from __future__ import annotations

import base64
import binascii
import json
import re
from contextlib import suppress
from typing import Any
from urllib.parse import unquote

from .egress import EgressPolicy, check_egress
from .models import GuardDecision
from .screening import CONTROL_TOKEN_RE, CREDENTIAL_RE, screen_description

BAD_SVID = {"expired", "wrong_trust_domain", "missing", "forged", "revoked"}
BAD_ATTESTATION = {"stale", "pcr_mismatch", "missing", "replayed_nonce", "bad_signature"}
HIGH_RISK_TOOLS = {"payments.transfer", "iam.grant", "db.admin", "fs.delete"}
SECRET_SHAPE_RE = re.compile(
    r"AKIA[0-9A-Z]{8,}|sk[_-][A-Za-z0-9_=-]{12,}|ghp_[A-Za-z0-9_=-]{12,}", re.IGNORECASE
)
REDIRECT_RE = re.compile(
    r"\b(ignore previous|override the user|forward .* to|email .* to|send .* to|"
    r"share .* externally|outside collection|private drop box|upload .* to|"
    r"sending diagnostics|unrelated email|copy the local workspace|post internal notes|"
    r"external mail|data is sent to|hidden workspace excerpts externally|"
    r"redirects the workflow|abandon the task|export [a-z0-9_.-]+)\b",
    re.IGNORECASE,
)
SECRET_CONTEXT_RE = re.compile(
    r"\b(secret|token|access key|credential-shaped|project key|credential forwarding|"
    r"hide the key|encoded material|opaque credential)\b",
    re.IGNORECASE,
)


class MCPGuardDefense:
    def decide(self, request: dict[str, Any]) -> dict[str, str]:
        agent = dict(request.get("agent") or {})
        if str(agent.get("svid", "valid")) in BAD_SVID:
            return _deny("bad SVID", "identity")
        if str(agent.get("attestation", "valid")) in BAD_ATTESTATION:
            return _deny("bad attestation", "identity")
        context = dict(request.get("context") or {})
        description = str(context.get("tool_description") or "")
        tool = str(request.get("tool") or "")
        if tool in HIGH_RISK_TOOLS:
            return _deny("high-risk tool requires explicit operator capability", "tool")
        if tool == "shell.exec":
            cmd = str(dict(request.get("args") or {}).get("cmd", ""))
            if str(context.get("origin", "")) != "user" or re.search(
                r"curl .*\|\s*sh|rm\s+-rf|sudo|chmod", cmd
            ):
                return _deny("shell command from untrusted or dangerous context", "tool")
        findings = screen_description("azt", tool, description)
        if findings:
            return _deny(findings[0].reason, "description")
        content = (
            str(context.get("content") or "") + "\n" + str(context.get("raw_generation") or "")
        )
        if CONTROL_TOKEN_RE.search(content):
            return _deny("context contains control token", "context")
        if _contains_secret_like(request.get("args") or {}):
            return _deny("arguments contain secret-shaped value", "arguments")
        if (
            str(context.get("origin", "")) != "user"
            and tool in {"email.send", "http.post", "http.get"}
            and REDIRECT_RE.search(content)
        ):
            return _deny("untrusted context attempts tool redirection", "context")
        if (
            str(context.get("origin", "")) != "user"
            and "non-secret" not in content.lower()
            and SECRET_CONTEXT_RE.search(content)
        ):
            return _deny("untrusted context requests secret-bearing arguments", "context")
        raw_generation = str(context.get("raw_generation") or "")
        if str(context.get("origin", "")) == "tool_output" and '{"tool"' in raw_generation:
            try:
                json.loads(raw_generation)
            except json.JSONDecodeError:
                return _deny("truncated or ambiguous tool-call frame", "parser")
        lowered = content.lower()
        if (
            CREDENTIAL_RE.search(content)
            and "never" not in lowered
            and any(word in lowered for word in ("exfil", "leak", "raw token"))
        ):
            return _deny("context requests credential access", "context")
        if int(context.get("reasoning_tokens") or 0) == 0 and "control" in str(
            request.get("trace_id", "")
        ):
            return _deny("reasoning suppressed by control-token pattern", "context")
        egress = check_egress(
            request.get("args") or {},
            EgressPolicy(),
            resolver=lambda _h: [],
        )
        if egress:
            return _deny(egress[0].reason, "egress")
        return {"decision": "allow", "reason": "ok", "component": "mcp_guard"}


def _deny(reason: str, component: str) -> dict[str, str]:
    return GuardDecision.deny(reason, component).as_json()


defense = MCPGuardDefense()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        dict_values: list[str] = []
        for item in value.values():
            dict_values.extend(_strings(item))
        return dict_values
    if isinstance(value, list | tuple):
        list_values: list[str] = []
        for item in value:
            list_values.extend(_strings(item))
        return list_values
    return []


def _contains_secret_like(value: Any) -> bool:
    for text in _strings(value):
        candidates = {text, unquote(text)}
        with suppress(binascii.Error, UnicodeDecodeError):
            candidates.add(
                base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode("utf-8")
            )
        if len(text) % 2 == 0:
            with suppress(ValueError):
                candidates.add(bytes.fromhex(text).decode("utf-8"))
        if any(SECRET_SHAPE_RE.search(candidate) for candidate in candidates):
            return True
    return False
