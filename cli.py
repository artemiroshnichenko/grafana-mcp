#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.9.0", "httpx>=0.27", "cryptography>=42", "secretstorage>=3.3"]
# ///
"""Diagnostics and setup for the Grafana MCP server: doctor, selftest, setup."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

HERE = Path(__file__).parent


def cmd_doctor(args: argparse.Namespace) -> int:
    from client import GrafanaClient
    from auth import cookies_for_host

    api = GrafanaClient()
    print(f"url        {api.url}")
    cookies = cookies_for_host(api.host)
    print(f"cookies    {', '.join(sorted(cookies)) or 'none in local browsers'}")
    print(f"session    {'found' if api.cookie_name in cookies else 'MISSING (' + api.cookie_name + ')'}")

    async def run() -> int:
        try:
            health = await api.get("/api/health")
            print(f"version    {health.get('version')}")
            user = await api.get("/api/user")
            print(f"user       {user.get('login')}")
            found = await api.get("/api/search", params={"type": "dash-db", "limit": 1})
            print(f"api        ok, dashboards visible: {'yes' if found else 'none'}")
            return 0
        except Exception as exc:
            print(f"api        NO: {exc}")
            return 1

    return asyncio.run(run())


def cmd_selftest(args: argparse.Namespace) -> int:
    import server as srv

    async def run() -> int:
        tools = await srv.mcp.list_tools()
        print(f"tools registered: {len(tools)}")
        for tool in tools:
            print(f"  {tool.name}")
        print("\ncalling grafana_status()")
        try:
            result = await srv.mcp.call_tool("grafana_status", {})
        except Exception as exc:
            print(f"  FAILED: {exc}")
            return 1
        payload = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
        if payload is None:
            content = getattr(result, "content", result)
            payload = [getattr(b, "text", str(b)) for b in content] if isinstance(content, list) else content
        print(json.dumps(payload, indent=2, default=str)[:1500])
        return 0

    return asyncio.run(run())


def cmd_setup(args: argparse.Namespace) -> int:
    target = Path(args.project).expanduser().resolve()
    path = target / ".mcp.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    servers = data.setdefault("mcpServers", {})
    servers[args.name] = {
        "command": "uv",
        "args": ["run", "--quiet", "--script", str(HERE / "server.py")],
    }
    path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"registered '{args.name}' in {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check url, session cookie and API access").set_defaults(func=cmd_doctor)
    sub.add_parser("selftest", help="boot the MCP server and call a tool").set_defaults(func=cmd_selftest)

    p = sub.add_parser("setup", help="register the server in a project .mcp.json")
    p.add_argument("project", nargs="?", default=str(HERE.parent))
    p.add_argument("--name", default="grafana")
    p.set_defaults(func=cmd_setup)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
