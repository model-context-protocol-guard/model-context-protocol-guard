"""HMAC capability tokens with monotonic attenuation caveats."""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True, slots=True)
class Caveats:
    server: str
    tool_globs: tuple[str, ...]
    expires_at: float
    max_calls: int
    url_hosts: tuple[str, ...] = ()
    path_prefixes: tuple[str, ...] = ()
    nonce: str = field(default_factory=lambda: secrets.token_hex(8))

    def allows_tool(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pat) for pat in self.tool_globs)


@dataclass(slots=True)
class CapabilityIssuer:
    key: bytes
    call_counts: dict[str, int] = field(default_factory=dict)

    def mint(self, caveats: Caveats) -> str:
        payload = json.dumps(asdict(caveats), sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.key, payload, sha256).digest()
        return f"{_b64(payload)}.{_b64(sig)}"

    def parse(self, token: str) -> Caveats:
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload = _unb64(payload_b64)
            sig = _unb64(sig_b64)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("invalid token encoding") from exc
        expected = hmac.new(self.key, payload, sha256).digest()
        if not hmac.compare_digest(expected, sig):
            raise ValueError("capability signature verification failed")
        data = json.loads(payload)
        return Caveats(
            server=str(data["server"]),
            tool_globs=tuple(str(x) for x in data["tool_globs"]),
            expires_at=float(data["expires_at"]),
            max_calls=int(data["max_calls"]),
            url_hosts=tuple(str(x) for x in data.get("url_hosts", ())),
            path_prefixes=tuple(str(x) for x in data.get("path_prefixes", ())),
            nonce=str(data.get("nonce", "")),
        )

    def verify(
        self, token: str, *, server: str, tool: str, args: dict[str, Any], now: float | None = None
    ) -> bool:
        caveats = self.parse(token)
        if caveats.server != server or not caveats.allows_tool(tool):
            return False
        if (now if now is not None else time.time()) > caveats.expires_at:
            return False
        count = self.call_counts.get(caveats.nonce, 0)
        if count >= caveats.max_calls:
            return False
        if caveats.path_prefixes:
            for value in _string_values(args):
                if value.startswith("/") and not any(
                    value.startswith(p) for p in caveats.path_prefixes
                ):
                    return False
        self.call_counts[caveats.nonce] = count + 1
        return True


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_string_values(item))
        return out
    if isinstance(value, list | tuple):
        out = []
        for item in value:
            out.extend(_string_values(item))
        return out
    return []


def _subset_patterns(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    return all(
        any(
            p == c or (not any(ch in c for ch in "*?[") and fnmatch.fnmatchcase(c, p))
            for p in parent
        )
        for c in child
    )


def is_attenuation(parent: Caveats, child: Caveats) -> bool:
    return (
        parent.server == child.server
        and child.expires_at <= parent.expires_at
        and child.max_calls <= parent.max_calls
        and _subset_patterns(child.tool_globs, parent.tool_globs)
        and set(child.url_hosts).issubset(
            set(parent.url_hosts) if parent.url_hosts else set(child.url_hosts)
        )
        and all(
            any(prefix.startswith(parent_prefix) for parent_prefix in parent.path_prefixes)
            for prefix in child.path_prefixes
        )
    )


def attenuate(parent: Caveats, **changes: Any) -> Caveats:
    data = asdict(parent)
    data.update(changes)
    child = Caveats(
        server=str(data["server"]),
        tool_globs=tuple(data["tool_globs"]),
        expires_at=float(data["expires_at"]),
        max_calls=int(data["max_calls"]),
        url_hosts=tuple(data.get("url_hosts", ())),
        path_prefixes=tuple(data.get("path_prefixes", ())),
        nonce=secrets.token_hex(8),
    )
    if not is_attenuation(parent, child):
        raise ValueError("attenuation would widen authority")
    return child
