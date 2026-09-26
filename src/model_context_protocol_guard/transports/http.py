"""Streamable HTTP proxy surface backed by the shared guard pipeline."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from ..pipeline import GuardPipeline

JsonHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def create_app(pipeline: GuardPipeline, upstream: JsonHandler) -> Starlette:
    async def rpc(request: Request) -> JSONResponse:
        frame = await request.json()
        if not isinstance(frame, dict):
            return JSONResponse(_error(None, -32600, "request must be object"), status_code=400)
        guarded = await _handle(frame, pipeline, upstream)
        return JSONResponse(guarded)

    async def events(_request: Request) -> StreamingResponse:
        async def gen() -> Any:
            yield "event: ready\ndata: {}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return Starlette(
        routes=[Route("/mcp", rpc, methods=["POST"]), Route("/mcp", events, methods=["GET"])]
    )


async def _handle(
    frame: dict[str, Any], pipeline: GuardPipeline, upstream: JsonHandler
) -> dict[str, Any]:
    method = frame.get("method")
    if method == "tools/call":
        params = dict(frame.get("params") or {})
        token = params.pop("capabilityToken", None)
        dec = pipeline.validate_call(
            str(params.get("name", "")), dict(params.get("arguments") or {}), token=token
        )
        if dec.decision == "deny":
            return _error(frame.get("id"), -32000, dec.reason)
        frame = dict(frame)
        frame["params"] = params
    response = await upstream(frame)
    if method == "tools/list" and isinstance(response.get("result"), dict):
        result = dict(response["result"])
        allowed, _ = pipeline.inspect_tools([dict(t) for t in result.get("tools") or []])
        result["tools"] = allowed
        response = dict(response)
        response["result"] = result
    if method == "tools/call" and "result" in response:
        dec = pipeline.screen_tool_result(response["result"])
        if dec.decision == "deny":
            return _error(frame.get("id"), -32001, dec.reason)
        response = dict(response)
        response["result"] = dec.sanitized
    return response


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
