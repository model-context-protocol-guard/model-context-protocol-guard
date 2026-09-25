from __future__ import annotations

import pytest

from mcp_guard.jsonrpc import JsonRpcError, compare_strict_tolerant, parse_frame, serialize_frame


def test_strict_jsonrpc_roundtrip() -> None:
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert parse_frame(serialize_frame(frame)) == frame


@pytest.mark.parametrize(
    "line",
    [
        '{"jsonrpc":"2.0","method":"x"}',
        '{"jsonrpc":"2.0","method":"x"}\n{}\n',
        '{"jsonrpc":"2.0","method":"x","method":"y"}\n',
        '{"jsonrpc":"2.0","method":"x","n":NaN}\n',
    ],
)
def test_strict_rejects_ambiguous_frames(line: str) -> None:
    with pytest.raises(JsonRpcError):
        parse_frame(line)


def test_tolerant_regex_disagrees_on_truncated_payload() -> None:
    sample = '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}'
    assert compare_strict_tolerant(sample) == {
        "strict_ok": False,
        "strict_method": None,
        "tolerant_method": "tools/call",
    }
