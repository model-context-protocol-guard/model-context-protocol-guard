"""Argument egress controls for URLs, hosts, IP literals, and encoded variants."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import unquote, urlparse

from .models import Finding

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\[[0-9a-f:]+\]", re.IGNORECASE)
B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")


class Resolver(Protocol):
    def __call__(self, host: str) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    allow_hosts: frozenset[str] = field(default_factory=frozenset)
    deny_private: bool = True
    max_decode_depth: int = 2


def _default_resolver(host: str) -> list[str]:
    try:
        return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def _walk(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_walk(item))
        return out
    if isinstance(value, list | tuple | set):
        out = []
        for item in value:
            out.extend(_walk(item))
        return out
    return []


def _decode_variants(text: str, depth: int) -> set[str]:
    seen = {text}
    frontier = {text}
    for _ in range(depth):
        next_frontier: set[str] = set()
        for item in frontier:
            pct = unquote(item)
            if pct not in seen:
                seen.add(pct)
                next_frontier.add(pct)
            for m in B64_RE.finditer(item):
                token = m.group(0)
                padded = token + "=" * (-len(token) % 4)
                try:
                    decoded = base64.b64decode(padded, validate=True).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError):
                    continue
                if decoded not in seen:
                    seen.add(decoded)
                    next_frontier.add(decoded)
        frontier = next_frontier
    return seen


def extract_hosts(args: Any, *, max_decode_depth: int = 2) -> set[str]:
    hosts: set[str] = set()
    for text in _walk(args):
        for variant in _decode_variants(text, max_decode_depth):
            for url in URL_RE.findall(variant):
                parsed = urlparse(url)
                if parsed.hostname:
                    hosts.add(parsed.hostname.strip("[]").lower())
            if "/" not in variant:
                for host in HOST_RE.findall(variant):
                    hosts.add(host.lower())
            for ip in IP_RE.findall(variant):
                hosts.add(ip.strip("[]").lower())
    return hosts


def _is_private_or_metadata(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) == "169.254.169.254"
    )


def check_egress(
    args: Any, policy: EgressPolicy, *, resolver: Resolver | None = None
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    resolve = resolver or _default_resolver
    for host in sorted(extract_hosts(args, max_decode_depth=policy.max_decode_depth)):
        if policy.allow_hosts and host not in policy.allow_hosts:
            findings.append(Finding("egress", f"host {host} is not in allowlist"))
            continue
        if policy.deny_private and _is_private_or_metadata(host):
            findings.append(Finding("egress", f"address {host} is private/link-local/metadata"))
            continue
        for address in resolve(host):
            if policy.deny_private and _is_private_or_metadata(address):
                findings.append(
                    Finding("egress", f"host {host} resolves to blocked address {address}")
                )
                break
    return tuple(findings)
