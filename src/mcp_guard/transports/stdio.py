"""Async stdio MCP proxy for newline-delimited JSON-RPC."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from ..jsonrpc import JsonRpcError, parse_frame, serialize_frame
from ..pipeline import GuardPipeline


class StdioProxyError(RuntimeError):
    pass


class AsyncStdioProxy:
    def __init__(self, command: Sequence[str], pipeline: GuardPipeline) -> None:
        self.command = list(command)
        self.pipeline = pipeline
        self.process: asyncio.subprocess.Process | None = None

    async def __aenter__(self) -> AsyncStdioProxy:
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()

    async def request(
        self, method: str, params: dict[str, Any] | None = None, request_id: int | str = 1
    ) -> dict[str, Any]:
        frame: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            frame["params"] = params
        return await self.forward(frame)

    async def forward(self, frame: dict[str, Any]) -> dict[str, Any]:
        proc = self.process
        if proc is None or proc.stdin is None or proc.stdout is None:
            raise StdioProxyError("proxy process is not running")
        if frame.get("method") == "tools/call":
            params = dict(frame.get("params") or {})
            token = params.pop("capabilityToken", None)
            decision = self.pipeline.validate_call(
                str(params.get("name", "")), dict(params.get("arguments") or {}), token=token
            )
            if decision.decision == "deny":
                return _error(frame.get("id"), -32000, decision.reason)
            frame = dict(frame)
            frame["params"] = params
        proc.stdin.write(serialize_frame(frame))
        await proc.stdin.drain()
        line = await proc.stdout.readline()
        if not line:
            raise StdioProxyError("server closed stdout")
        try:
            response = parse_frame(line)
        except JsonRpcError as exc:
            raise StdioProxyError(str(exc)) from exc
        if frame.get("method") == "tools/list" and isinstance(response.get("result"), dict):
            result = dict(response["result"])
            tools = list(result.get("tools") or [])
            allowed, _ = self.pipeline.inspect_tools([dict(t) for t in tools])
            result["tools"] = allowed
            response = dict(response)
            response["result"] = result
        if frame.get("method") == "tools/call" and "result" in response:
            decision = self.pipeline.screen_tool_result(response["result"])
            if decision.decision == "deny":
                return _error(frame.get("id"), -32001, decision.reason)
            response = dict(response)
            response["result"] = decision.sanitized
        return response


async def relay_stdio(command: Sequence[str], pipeline: GuardPipeline) -> int:
    async with AsyncStdioProxy(command, pipeline) as proxy:
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_running_loop()
        await loop.connect_read_pipe(lambda: protocol, __import__("sys").stdin)
        writer_transport, writer_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, __import__("sys").stdout
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, loop)
        while True:
            line = await reader.readline()
            if not line:
                return 0
            try:
                frame = parse_frame(line)
                response = await proxy.forward(frame)
            except Exception as exc:
                response = _error(None, -32700, exc.__class__.__name__)
            writer.write(serialize_frame(response))
            await writer.drain()


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
