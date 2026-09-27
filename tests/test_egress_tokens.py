from __future__ import annotations

import base64
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from model_context_protocol_guard.egress import EgressPolicy, check_egress, extract_hosts
from model_context_protocol_guard.tokens import CapabilityIssuer, Caveats, attenuate, is_attenuation


def test_egress_extracts_percent_and_base64_hosts() -> None:
    encoded = base64.b64encode(b"https://169.254.169.254/latest/meta-data").decode()
    hosts = extract_hosts({"url": "https%3A%2F%2Fapi.example.com%2Fx", "blob": encoded})
    assert {"api.example.com", "169.254.169.254"}.issubset(hosts)
    findings = check_egress({"url": "http://127.0.0.1"}, EgressPolicy(), resolver=lambda _h: [])
    assert findings and "private" in findings[0].reason


def test_egress_resolve_then_compare_blocks_rebinding() -> None:
    findings = check_egress(
        {"url": "https://api.example.com"},
        EgressPolicy(frozenset({"api.example.com"})),
        resolver=lambda _h: ["10.0.0.7"],
    )
    assert findings and "resolves" in findings[0].reason


def test_capability_verify_and_tamper_detection() -> None:
    issuer = CapabilityIssuer(b"k" * 32)
    cav = Caveats("srv", ("read*",), time.time() + 60, 1, path_prefixes=("/safe",))
    token = issuer.mint(cav)
    assert issuer.verify(token, server="srv", tool="read_file", args={"path": "/safe/a"})
    assert not issuer.verify(token, server="srv", tool="read_file", args={"path": "/safe/a"})
    bad = token[:-2] + "aa"
    with pytest.raises(ValueError):
        issuer.parse(bad)


@given(
    max_calls=st.integers(min_value=1, max_value=50),
    child_calls=st.integers(min_value=1, max_value=50),
    seconds=st.floats(min_value=1, max_value=1000, allow_nan=False, allow_infinity=False),
)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_attenuation_never_widens(max_calls: int, child_calls: int, seconds: float) -> None:
    parent = Caveats("srv", ("read*",), 10_000.0, max_calls, path_prefixes=("/safe",))
    child = attenuate(
        parent,
        tool_globs=("read_file",),
        expires_at=min(parent.expires_at, seconds),
        max_calls=min(max_calls, child_calls),
        path_prefixes=("/safe/data",),
    )
    assert is_attenuation(parent, child)
    with pytest.raises(ValueError):
        attenuate(parent, max_calls=max_calls + 1)
