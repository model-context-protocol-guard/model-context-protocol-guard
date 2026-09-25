"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import uvicorn

from .pipeline import GuardConfig, GuardPipeline
from .transports.stdio import relay_stdio


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-guard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_stdio = sub.add_parser("stdio", help="wrap a stdio MCP server")
    p_stdio.add_argument("--pin-file", default=".mcp-guard-pins.json")
    p_stdio.add_argument("--server-name", default="default")
    p_stdio.add_argument("command", nargs=argparse.REMAINDER)
    p_http = sub.add_parser("http-demo", help="serve demo Streamable HTTP proxy")
    p_http.add_argument("--port", type=int, default=18300)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "stdio":
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise SystemExit("mcp-guard stdio requires -- <server cmd>")
        pipeline = GuardPipeline(
            GuardConfig(server_name=args.server_name, pin_file=Path(args.pin_file))
        )
        return asyncio.run(relay_stdio(command, pipeline))
    if args.cmd == "http-demo":
        from .transports.http import create_app

        async def upstream(frame: dict[str, object]) -> dict[str, object]:
            if frame.get("method") == "tools/list":
                return {"jsonrpc": "2.0", "id": frame.get("id"), "result": {"tools": []}}
            return {"jsonrpc": "2.0", "id": frame.get("id"), "result": {"content": []}}

        uvicorn.run(create_app(GuardPipeline(), upstream), host="127.0.0.1", port=args.port)
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
