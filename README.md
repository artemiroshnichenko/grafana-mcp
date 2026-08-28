# grafana-mcp

MCP server for Grafana, authenticated with the local browser's session cookie — no service account
or API token to provision, no password stored anywhere. Useful for Grafana instances behind SSO
where the only easy path in is the session you already have open in the browser.

## Install

```bash
git clone <this-repo> grafana-mcp
cd grafana-mcp
cp .env.example .env   # set GRAFANA_MCP_URL
uv run --script cli.py doctor     # url, cookies, version, who we are, dashboards visible?
uv run --script cli.py selftest   # start the MCP server, list tools, live call
uv run --script cli.py setup      # register in ../.mcp.json, then restart your MCP host
```

## Tools

| Tool | What it does |
| --- | --- |
| `grafana_status` | version, who we're logged in as, where the session came from |
| `search_dashboards` | search by title and tags |
| `get_dashboard` | panels, their queries and variables, without the giant raw JSON |
| `list_datasources` | uid and type of every datasource, falls back to frontend settings without admin rights |
| `query_metrics` | PromQL or LogQL via `/api/ds/query`, returns min/max/avg/last and a downsampled series |
| `list_alert_rules` | alert rules and their state |
| `list_firing_alerts` | what's firing right now |
| `grafana_api` | raw call to any endpoint, an escape hatch |

## Configuration

Environment variables (a `.env` file next to the code works too):

| Variable | Required | Meaning |
| --- | --- | --- |
| `GRAFANA_MCP_URL` | yes | base URL of your Grafana instance |
| `GRAFANA_MCP_TOKEN` | no | service account token, skips cookie auth entirely if set |
| `GRAFANA_MCP_COOKIE_NAME` | no | session cookie name (default `grafana_session`) |
| `GRAFANA_MCP_READONLY` | no | set to disable write calls through `grafana_api` |
| `GRAFANA_MCP_TIMEOUT` | no | HTTP timeout in seconds (default 60) |

## How the cookie is found

`auth.py` reads the session cookie straight out of the local browser's cookie store for the host
in `GRAFANA_MCP_URL`. Firefox and Chromium-family browsers (Chrome, Chromium, Brave, Edge,
Vivaldi) are supported on Linux, macOS and Windows; Safari is supported on macOS.

Log in to Grafana in the browser once, and the MCP server picks up that session on the next call.
How the Chromium encryption key is obtained differs per OS:

- **Linux** -- the key is derived from a password held in GNOME Keyring (via `secretstorage`) or
  KDE Wallet (via `kwallet-query`), cached under `~/.cache/grafana-mcp` after the first read. If
  neither keyring is reachable, cookies stored with Chromium's unencrypted-fallback password
  still decrypt.
- **macOS** -- the password comes from the login Keychain (`security find-generic-password`);
  the first lookup may prompt an "Allow access" dialog for the item.
- **Windows** -- the key is DPAPI-unwrapped from each browser's own `Local State` file. Chrome
  127+'s App-Bound Encryption (cookie prefix `v20`) wraps that key a second time through Chrome's
  elevation service, which isn't implemented here -- those specific cookies are skipped rather
  than failing the whole lookup, so upgrading past that point may mean the session cookie is no
  longer readable this way.
- **Safari (macOS)** -- cookies are read from `Cookies.binarycookies`, unencrypted. Reading the
  sandboxed path may require granting the terminal (or whatever runs the MCP server) Full Disk
  Access in System Settings. Only cookies with an explicit expiry are persisted to disk by
  Safari, so a pure session cookie (no `Expires`) won't be there until Grafana sets one that has
  one.
