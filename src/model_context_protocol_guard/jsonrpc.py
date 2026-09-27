"""Strict newline-delimited JSON-RPC 2.0 framing."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

_FRAME_RE = re.compile(r'\{.*?"method"\s*:\s*"(?P<method>[^"]+)".*?\}', re.DOTALL)


class JsonRpcError(ValueError):
    """Raised when a JSON-RPC frame is not strict, complete JSON."""


def _reject_constant(value: str) -> None:
    raise JsonRpcError(f"non-standard JSON constant {value!r}")


def _no_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise JsonRpcError(f"duplicate key {key!r}")
        out[key] = value
    return out


def loads_strict(data: str) -> Any:
    decoder = json.JSONDecoder(object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    try:
        obj, idx = decoder.raw_decode(data)
    except json.JSONDecodeError as exc:
        raise JsonRpcError(f"invalid JSON frame: {exc.msg}") from exc
    if data[idx:].strip():
        raise JsonRpcError("trailing data after JSON frame")
    return obj


def parse_frame(line: bytes | str, *, max_bytes: int = 1_000_000) -> dict[str, Any]:
    raw = line.decode("utf-8") if isinstance(line, bytes) else line
    if len(raw.encode("utf-8")) > max_bytes:
        raise JsonRpcError("frame exceeds size limit")
    if not raw.endswith("\n"):
        raise JsonRpcError("stdio frames must end with newline")
    obj = loads_strict(raw.rstrip("\r\n"))
    if not isinstance(obj, dict):
        raise JsonRpcError("JSON-RPC frame must be an object")
    if obj.get("jsonrpc") != "2.0":
        raise JsonRpcError("jsonrpc must be '2.0'")
    if "method" not in obj and "result" not in obj and "error" not in obj:
        raise JsonRpcError("frame is neither request nor response")
    return obj


def serialize_frame(obj: dict[str, Any]) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def tolerant_regex_method(data: str) -> str | None:
    match = _FRAME_RE.search(data)
    return match.group("method") if match else None


def compare_strict_tolerant(data: str) -> dict[str, Any]:
    tolerant = tolerant_regex_method(data)
    try:
        strict = parse_frame(data if data.endswith("\n") else data + "\n")
        strict_ok = True
        strict_method = strict.get("method")
    except JsonRpcError:
        strict_ok = False
        strict_method = None
    return {"strict_ok": strict_ok, "strict_method": strict_method, "tolerant_method": tolerant}
