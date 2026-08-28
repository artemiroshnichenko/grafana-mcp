"""Grafana HTTP API client, authenticated with the local browser's session cookie."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(Path(__file__).parent))

from auth import cookies_for_host, load_env  # noqa: E402

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"


class GrafanaError(RuntimeError):
    pass


class GrafanaClient:
    def __init__(self) -> None:
        load_env(Path(__file__).parent / ".env")
        url = os.environ.get("GRAFANA_MCP_URL")
        if not url:
            raise GrafanaError("GRAFANA_MCP_URL is not set (put it in .env or the environment)")
        self.url = url.rstrip("/")
        self.token = os.environ.get("GRAFANA_MCP_TOKEN") or None
        self.cookie_name = os.environ.get("GRAFANA_MCP_COOKIE_NAME", "grafana_session")
        self.timeout = float(os.environ.get("GRAFANA_MCP_TIMEOUT", "60"))
        self.readonly = os.environ.get("GRAFANA_MCP_READONLY", "").lower() in ("1", "true", "yes")
        self._cookies: dict[str, str] = {}
        self._source = "none"
        self._client = httpx.AsyncClient(base_url=self.url, timeout=self.timeout, follow_redirects=True)

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def auth_source(self) -> str:
        return self._source

    def _auth(self, force: bool = False) -> tuple[dict[str, str], dict[str, str]]:
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if self.token:
            self._source = "token"
            headers["Authorization"] = f"Bearer {self.token}"
            return headers, {}

        if force or not self._cookies:
            self._cookies = cookies_for_host(self.host)
            self._source = "browser"
        if self.cookie_name not in self._cookies:
            raise GrafanaError(
                f"cookie '{self.cookie_name}' for {self.host} not found"
                + (f" (present: {', '.join(sorted(self._cookies))})" if self._cookies else " (no cookies at all)")
                + f". Log in at {self.url} in the browser, then retry."
            )
        return headers, self._cookies

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        params = {k: v for k, v in (kwargs.pop("params", None) or {}).items() if v is not None}

        async def send(force: bool) -> httpx.Response:
            headers, cookies = self._auth(force=force)
            return await self._client.request(
                method, path, params=params, headers=headers, cookies=cookies or None, **kwargs
            )

        response = await send(False)
        if response.status_code in (401, 403):
            response = await send(True)

        if response.status_code >= 400:
            detail = response.text[:500]
            try:
                body = response.json()
                detail = json.dumps(body.get("message", body))[:500]
            except Exception:
                pass
            raise GrafanaError(f"{method} {path} -> {response.status_code}: {detail}")

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"text": response.text[:5000]}

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw: Any) -> Any:
        return await self.request("POST", path, **kw)

    async def resolve_datasource(self, name_or_uid: str) -> dict:
        """Grafana refers to datasources by uid, humans by name, so accept either."""
        try:
            for ds in await self.get("/api/datasources"):
                if name_or_uid in (ds.get("uid"), ds.get("name")):
                    return {"uid": ds["uid"], "type": ds["type"], "name": ds["name"]}
        except GrafanaError:
            pass

        settings = await self.get("/api/frontend/settings")
        for name, ds in (settings.get("datasources") or {}).items():
            meta = ds.get("meta") or {}
            if name_or_uid in (ds.get("uid"), name):
                return {"uid": ds.get("uid"), "type": ds.get("type") or meta.get("id"), "name": name}
        raise GrafanaError(f"datasource '{name_or_uid}' not found")
