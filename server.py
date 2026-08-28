#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.9.0", "httpx>=0.27", "cryptography>=42", "secretstorage>=3.3"]
# ///
"""MCP server for Grafana, authenticated by the browser session cookie."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

try:
    from mcp.server.mcpserver import MCPServer  # SDK 2.x
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

from client import GrafanaClient, GrafanaError

API = GrafanaClient()
mcp = MCPServer("grafana")


def guard_write() -> None:
    if API.readonly:
        raise GrafanaError("GRAFANA_MCP_READONLY is set: write calls are disabled")


@mcp.tool()
async def grafana_status() -> dict:
    """Grafana version, who we are logged in as, and how the session was obtained."""
    health = await API.get("/api/health")
    try:
        user = await API.get("/api/user")
        who = {"login": user.get("login"), "email": user.get("email"), "is_admin": user.get("isGrafanaAdmin")}
    except GrafanaError as exc:
        who = {"error": str(exc)}
    return {
        "url": API.url,
        "auth_source": API.auth_source,
        "readonly": API.readonly,
        "version": health.get("version"),
        "database": health.get("database"),
        "user": who,
    }


@mcp.tool()
async def search_dashboards(query: str | None = None, tag: str | None = None, limit: int = 30) -> dict:
    """Find dashboards by title fragment or tag."""
    items = await API.get(
        "/api/search", params={"query": query, "tag": tag, "type": "dash-db", "limit": limit}
    )
    return {
        "count": len(items),
        "dashboards": [
            {"uid": d.get("uid"), "title": d.get("title"), "folder": d.get("folderTitle"), "tags": d.get("tags")}
            for d in items
        ],
    }


def _panel_summary(panel: dict) -> dict:
    targets = []
    for target in panel.get("targets") or []:
        expr = target.get("expr") or target.get("rawSql") or target.get("query") or target.get("target")
        if expr:
            targets.append(str(expr)[:400])
    out = {"id": panel.get("id"), "title": panel.get("title"), "type": panel.get("type")}
    datasource = panel.get("datasource")
    if isinstance(datasource, dict):
        out["datasource"] = datasource.get("uid")
    if targets:
        out["targets"] = targets
    return out


@mcp.tool()
async def get_dashboard(uid: str) -> dict:
    """Dashboard structure: panels, their queries and variables. The raw JSON is never returned in full."""
    data = await API.get(f"/api/dashboards/uid/{uid}")
    dash = data.get("dashboard", {})
    panels = []
    for panel in dash.get("panels") or []:
        panels.append(_panel_summary(panel))
        for nested in panel.get("panels") or []:
            panels.append(_panel_summary(nested))
    return {
        "uid": dash.get("uid"),
        "title": dash.get("title"),
        "folder": (data.get("meta") or {}).get("folderTitle"),
        "refresh": dash.get("refresh"),
        "variables": [v.get("name") for v in ((dash.get("templating") or {}).get("list") or [])],
        "panel_count": len(panels),
        "panels": panels,
    }


@mcp.tool()
async def list_datasources() -> dict:
    """Datasources this account can see, with uid and type for use in query_metrics."""
    try:
        items = await API.get("/api/datasources")
        return {
            "source": "admin api",
            "datasources": [
                {"uid": d.get("uid"), "name": d.get("name"), "type": d.get("type"), "default": d.get("isDefault")}
                for d in items
            ],
        }
    except GrafanaError:
        settings = await API.get("/api/frontend/settings")
        found = settings.get("datasources") or {}
        return {
            "source": "frontend settings",
            "datasources": [
                {"uid": ds.get("uid"), "name": name, "type": ds.get("type"), "default": ds.get("isDefault")}
                for name, ds in found.items()
            ],
        }


def _summarize_frames(payload: dict, max_points: int) -> list[dict]:
    """A panel query returns thousands of points, so keep shape and a downsampled trace."""
    series = []
    for result in (payload.get("results") or {}).values():
        for frame in result.get("frames") or []:
            fields = (frame.get("schema") or {}).get("fields") or []
            values = (frame.get("data") or {}).get("values") or []
            if len(values) < 2:
                continue
            times, points = values[0], values[1]
            numeric = [p for p in points if isinstance(p, (int, float))]
            step = max(1, len(points) // max_points)
            series.append(
                {
                    "labels": (fields[1].get("labels") if len(fields) > 1 else None) or {},
                    "name": fields[1].get("name") if len(fields) > 1 else None,
                    "points": len(points),
                    "last": points[-1] if points else None,
                    "min": min(numeric) if numeric else None,
                    "max": max(numeric) if numeric else None,
                    "avg": round(sum(numeric) / len(numeric), 4) if numeric else None,
                    "sample": [[times[i], points[i]] for i in range(0, len(points), step)][:max_points],
                }
            )
    return series


@mcp.tool()
async def query_metrics(
    datasource: str,
    expr: str,
    start: str = "now-1h",
    end: str = "now",
    step_seconds: int = 60,
    instant: bool = False,
    max_points: int = 60,
) -> dict:
    """Run a PromQL or LogQL query through Grafana. `datasource` takes a name or a uid.

    Returns per-series min/max/avg/last plus a downsampled trace, not the raw points.
    """
    ds = await API.resolve_datasource(datasource)
    query: dict[str, Any] = {
        "refId": "A",
        "datasource": {"uid": ds["uid"], "type": ds["type"]},
        "expr": expr,
        "instant": instant,
        "range": not instant,
        "intervalMs": step_seconds * 1000,
        "maxDataPoints": max(max_points, 100),
    }
    payload = await API.post("/api/ds/query", json={"from": start, "to": end, "queries": [query]})
    return {
        "datasource": ds,
        "expr": expr,
        "range": {"from": start, "to": end},
        "series": _summarize_frames(payload, max_points),
    }


@mcp.tool()
async def list_alert_rules(state: str | None = None, limit: int = 50) -> dict:
    """Grafana-managed alert rules with their current state. `state` filters to firing/pending/normal."""
    data = await API.get("/api/prometheus/grafana/api/v1/rules")
    rules = []
    for group in (data.get("data") or {}).get("groups") or []:
        for rule in group.get("rules") or []:
            if state and rule.get("state") != state:
                continue
            rules.append(
                {
                    "name": rule.get("name"),
                    "state": rule.get("state"),
                    "health": rule.get("health"),
                    "folder": group.get("file"),
                    "group": group.get("name"),
                    "last_error": rule.get("lastError"),
                    "active_since": (rule.get("alerts") or [{}])[0].get("activeAt"),
                }
            )
    return {"count": len(rules), "rules": rules[:limit]}


@mcp.tool()
async def list_firing_alerts(limit: int = 50) -> dict:
    """Alerts firing right now, as the alertmanager sees them."""
    alerts = await API.get("/api/alertmanager/grafana/api/v2/alerts", params={"active": "true"})
    out = []
    for alert in alerts[:limit]:
        labels = alert.get("labels") or {}
        out.append(
            {
                "name": labels.get("alertname"),
                "labels": {k: v for k, v in labels.items() if k != "alertname"},
                "state": (alert.get("status") or {}).get("state"),
                "starts_at": alert.get("startsAt"),
                "summary": (alert.get("annotations") or {}).get("summary"),
            }
        )
    return {"count": len(out), "alerts": out}


@mcp.tool()
async def grafana_api(method: str, path: str, params: dict | None = None, body: dict | None = None) -> Any:
    """Escape hatch for any Grafana HTTP API endpoint, e.g. path="/api/annotations"."""
    method = method.upper()
    if method != "GET":
        guard_write()
    if not path.startswith("/api"):
        path = "/api/" + path.lstrip("/")
    return await API.request(method, path, params=params, **({"json": body} if body else {}))


if __name__ == "__main__":
    mcp.run()
