"""Every exploitation agent sends requests through this, never through a raw
httpx client. It enforces the scope check and rate limit on every single
request, no exceptions -- this is the safety boundary for Phase 4.
"""
from __future__ import annotations

import httpx

from noctis.config.settings import Settings
from noctis.core.rate_limit import RateLimiter
from noctis.core.scope import ScopeEngine

DEFAULT_HEADERS = {"User-Agent": "Noctis/0.1 (authorized security assessment)"}


class ScopedHttpClient:
    def __init__(self, scope: ScopeEngine, settings: Settings, *, timeout: float = 15.0):
        self.scope = scope
        self._rate_limiter = RateLimiter(settings.requests_per_second)
        self._client = httpx.AsyncClient(
            headers=DEFAULT_HEADERS, follow_redirects=True, timeout=timeout
        )

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self.scope.assert_in_scope(url)
        await self._rate_limiter.wait()
        return await self._client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "ScopedHttpClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()
