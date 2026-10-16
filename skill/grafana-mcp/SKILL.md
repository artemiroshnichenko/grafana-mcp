---
name: grafana-mcp
description: Investigate Grafana from the agent through the grafana-mcp server, which logs in with the browser's existing Grafana session instead of a service account. Use when the user asks what is firing, why an alert fired, what a dashboard shows, or wants a PromQL/LogQL query run against their Grafana; also when they paste a Grafana dashboard or alert link. Requires the grafana-mcp server (https://github.com/artemiroshnichenko/grafana-mcp) to be registered as an MCP server named "grafana".
---

# Grafana via grafana-mcp

The `grafana` MCP server talks to one Grafana instance (`GRAFANA_MCP_URL`) as the user who is
logged in to it in the local browser. Everything you see is what that user can see; nothing more.

## Setup check

If the `grafana_*` tools are missing, the server is not registered. Tell the user to run, from
the cloned repo:

```bash
uv run --script cli.py doctor     # url, cookies, version, identity, dashboards visible?
uv run --script cli.py setup      # registers the server in ../.mcp.json
```

then restart the agent. Do not try to install it yourself.

Call `grafana_status` first in a session. It tells you the Grafana version, who you are logged in
as, and where the session came from. If it fails with an auth error, the browser session has
expired: ask the user to open Grafana in the browser and log in, then retry. Do not ask for a
password or token.

## Which tool for which question

| Question | Start with |
| --- | --- |
| "Is anything broken?" / "what's firing?" | `list_firing_alerts` |
| "Why did alert X fire?" | `list_alert_rules` (find the rule and its state), then `query_metrics` on its expression |
| "What does dashboard X show?" | `search_dashboards`, then `get_dashboard` with the uid |
| "Run this query" | `list_datasources` to get the datasource, then `query_metrics` |
| Anything the tools above don't cover (annotations, folders, users) | `grafana_api` with a GET |

## Working rules

- `get_dashboard` returns panels with their queries and variables. Reuse a panel's query in
  `query_metrics` instead of writing PromQL from scratch; substitute dashboard variables
  (`$instance`, `$__rate_interval`) with concrete values first.
- `query_metrics` returns min/max/avg/last and a downsampled sample per series, not raw points.
  Report those numbers. For "what is it right now" pass `instant=true`. Widen `start` (e.g.
  `now-24h`) before concluding that something "never happens".
- `datasource` accepts a name or a uid. If a query returns no series, check the datasource type
  (Prometheus vs Loki) matches the language of `expr` before blaming the data.
- `grafana_api` is an escape hatch. Use GET freely. Any other method changes the user's Grafana:
  state exactly what will change and get an explicit yes first. If `GRAFANA_MCP_READONLY` is set,
  write calls fail by design; do not look for a way around it.
- Answer with the numbers and the dashboard or rule names you actually saw. Say plainly when a
  series was empty or a call failed, rather than guessing what the metric would have shown.
